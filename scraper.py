"""
CTI Pipeline – Stage 2: Article Extraction
Multi-method fallback pipeline to reliably extract clean article text.

Priority:
  1. Trafilatura  (best general-purpose extraction)
  2. Newspaper3k  (good for news sites)
  3. Readability  (Mozilla's algorithm, great for long-form)
  4. BeautifulSoup (custom heuristic scraper)
  5. Playwright   (JavaScript-rendered pages)
"""
from __future__ import annotations
import asyncio
import hashlib
import logging
import re
import time
from typing import Optional

import requests
import trafilatura
from bs4 import BeautifulSoup
from readability import Document
from tenacity import retry, stop_after_attempt, wait_exponential

from settings import (
    MIN_ARTICLE_LENGTH,
    REQUEST_TIMEOUT,
    USER_AGENT,
)
from models import ExtractedArticle, RSSArticle

logger = logging.getLogger(__name__)

BOILERPLATE_PATTERNS = [
    r"cookie\s*policy",
    r"subscribe\s*to\s*our\s*newsletter",
    r"all\s*rights\s*reserved",
    r"terms\s*of\s*service",
    r"privacy\s*policy",
    r"advertisement",
    r"sponsored\s*content",
]
_BOILERPLATE_RE = re.compile("|".join(BOILERPLATE_PATTERNS), re.IGNORECASE)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=8))
def _get_page(url: str) -> tuple[bytes, str]:
    """Fetch raw HTML bytes and detected charset."""
    headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
    resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return resp.content, resp.apparent_encoding or "utf-8"


# ── Extraction methods ────────────────────────────────────────────────────────

def _extract_trafilatura(html: bytes) -> Optional[str]:
    try:
        text = trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
            no_fallback=False,
            favor_precision=True,
        )
        return text
    except Exception as exc:
        logger.debug("Trafilatura error: %s", exc)
        return None


def _extract_newspaper(url: str) -> Optional[str]:
    try:
        from newspaper import Article
        art = Article(url)
        art.download()
        art.parse()
        return art.text if art.text else None
    except Exception as exc:
        logger.debug("Newspaper3k error: %s", exc)
        return None


def _extract_readability(html: bytes, encoding: str) -> Optional[str]:
    try:
        raw = html.decode(encoding, errors="replace")
        doc = Document(raw)
        summary_html = doc.summary()
        soup = BeautifulSoup(summary_html, "lxml")
        return soup.get_text(separator="\n", strip=True)
    except Exception as exc:
        logger.debug("Readability error: %s", exc)
        return None


def _extract_bs4(html: bytes, encoding: str) -> Optional[str]:
    """Heuristic BeautifulSoup extraction targeting common article containers."""
    try:
        soup = BeautifulSoup(html.decode(encoding, errors="replace"), "lxml")

        # Remove noise elements
        for tag in soup(["script", "style", "nav", "header", "footer",
                          "aside", "form", "noscript", "iframe", "ads",
                          ".cookie-banner", ".newsletter", ".related-articles"]):
            tag.decompose()

        # Common article selectors in priority order
        SELECTORS = [
            "article",
            '[role="main"]',
            ".article-body",
            ".post-content",
            ".entry-content",
            ".story-body",
            ".article-content",
            "#article-body",
            "main",
        ]
        for selector in SELECTORS:
            container = soup.select_one(selector)
            if container:
                text = container.get_text(separator="\n", strip=True)
                if len(text) >= MIN_ARTICLE_LENGTH:
                    return text

        # Last resort: body text
        body = soup.find("body")
        if body:
            return body.get_text(separator="\n", strip=True)
        return None
    except Exception as exc:
        logger.debug("BS4 error: %s", exc)
        return None


async def _extract_playwright(url: str) -> Optional[str]:
    """Render JavaScript-heavy pages using Playwright (async)."""
    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page    = await browser.new_page()
            await page.set_extra_http_headers({"User-Agent": USER_AGENT})
            await page.goto(url, wait_until="networkidle", timeout=45_000)
            html    = await page.content()
            await browser.close()

        # Pass rendered HTML through trafilatura
        text = trafilatura.extract(html.encode(), favor_precision=True)
        return text
    except Exception as exc:
        logger.debug("Playwright error: %s", exc)
        return None


# ── Validation ────────────────────────────────────────────────────────────────

def _validate_text(text: str) -> tuple[bool, str]:
    """
    Returns (is_valid, rejection_reason).
    A valid article has sufficient length and is not dominated by boilerplate.
    """
    if not text or len(text.strip()) < MIN_ARTICLE_LENGTH:
        return False, f"too short ({len(text.strip()) if text else 0} chars)"

    # Count boilerplate matches relative to text length
    matches = len(_BOILERPLATE_RE.findall(text))
    if matches > 5:
        return False, f"excessive boilerplate ({matches} patterns)"

    return True, ""


def _clean_text(text: str) -> str:
    """Normalise whitespace and remove repeated blank lines."""
    lines  = text.splitlines()
    cleaned = []
    blank_count = 0
    for line in lines:
        line = line.strip()
        if not line:
            blank_count += 1
            if blank_count <= 1:
                cleaned.append("")
        else:
            blank_count = 0
            cleaned.append(line)
    return "\n".join(cleaned).strip()


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ── Main extraction pipeline ──────────────────────────────────────────────────

def extract_article(article: RSSArticle) -> ExtractedArticle | None:
    """
    Run the full multi-method extraction pipeline for a single article.
    Returns None if no method succeeds or content fails validation.
    """
    url = article.url
    logger.info("Extracting: %s", url[:80])

    # Fetch the page once; reuse bytes across methods
    try:
        html, encoding = _get_page(url)
    except Exception as exc:
        logger.warning("HTTP fetch failed for %s: %s", url, exc)
        return None

    methods = [
        ("trafilatura",  lambda: _extract_trafilatura(html)),
        ("newspaper3k",  lambda: _extract_newspaper(url)),
        ("readability",  lambda: _extract_readability(html, encoding)),
        ("bs4",          lambda: _extract_bs4(html, encoding)),
    ]

    text        : Optional[str] = None
    method_used : str           = ""

    for method_name, extractor in methods:
        candidate = extractor()
        if candidate:
            valid, reason = _validate_text(candidate)
            if valid:
                text        = _clean_text(candidate)
                method_used = method_name
                logger.debug("  ✓ %s succeeded (%d chars)", method_name, len(text))
                break
            else:
                logger.debug("  ✗ %s invalid: %s", method_name, reason)

    # Playwright fallback for JS-rendered pages
    if text is None:
        logger.info("  Trying Playwright for %s", url)
        try:
            pw_text = asyncio.run(_extract_playwright(url))
        except RuntimeError:
            # Already inside an event loop (e.g. Jupyter)
            loop = asyncio.get_event_loop()
            pw_text = loop.run_until_complete(_extract_playwright(url))

        if pw_text:
            valid, reason = _validate_text(pw_text)
            if valid:
                text        = _clean_text(pw_text)
                method_used = "playwright"

    if text is None:
        logger.warning("  All extraction methods failed for %s", url)
        return None

    return ExtractedArticle(
        rss_article       = article,
        full_text         = text,
        extraction_method = method_used,
        char_count        = len(text),
        word_count        = len(text.split()),
        content_hash      = _fingerprint(text),
    )


def extract_articles(articles: list[RSSArticle]) -> list[ExtractedArticle]:
    """Batch extraction with deduplication by content fingerprint."""
    seen_hashes: set[str] = set()
    extracted: list[ExtractedArticle] = []

    for article in articles:
        result = extract_article(article)
        if result is None:
            continue
        if result.content_hash in seen_hashes:
            logger.debug("Duplicate content skipped: %s", article.url)
            continue
        seen_hashes.add(result.content_hash)
        extracted.append(result)

    logger.info(
        "Extraction complete: %d/%d articles succeeded",
        len(extracted), len(articles),
    )
    return extracted
