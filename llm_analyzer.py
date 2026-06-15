"""
CTI Pipeline – Stage A: LLM Extraction
The model does ONE thing: read article content and return raw facts as JSON.

What the LLM extracts:
  - executive_summary
  - threat_actors
  - campaigns
  - malware families
  - IOCs
  - raw behaviors (no ATT&CK IDs)

What the LLM does NOT do (handled in later stages):
  - ATT&CK mapping  →  attack_mapper.py  (ChromaDB similarity search)
  - Hunt hypotheses →  hunt_generator.py (deterministic from mapped behaviors)
"""
from __future__ import annotations
import json
import logging
import re
import time
from typing import Any

import requests as _requests
from tenacity import retry, stop_after_attempt, wait_exponential

from settings import LLM_MAX_TOKENS, LLM_MODEL, LLM_TEMPERATURE, OLLAMA_BASE_URL
from models import (
    Campaign, ConfidenceLevel, ExtractedArticle,
    IOC, IOCType, MalwareFamily, MalwareType,
    RawBehavior, ThreatActor, CTIReport,
)
from prompts import EXTRACTION_PROMPT, SYSTEM_PROMPT

logger = logging.getLogger(__name__)

# Article is chunked to this many characters before being sent to the LLM.
# Qwen3 8B context is 32K tokens (~24K chars safe); keeping to 8K means the
# model has room to think and still generate a full JSON response without
# running into num_predict limits.
MAX_CONTENT_CHARS = 8_000


# ── Ollama call ───────────────────────────────────────────────────────────────

@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=2, min=5, max=20))
def _ollama(prompt: str, model: str = LLM_MODEL) -> str:
    payload = {
        "model":  model,
        "stream": False,
        "options": {
            "temperature": LLM_TEMPERATURE,
            "num_predict": LLM_MAX_TOKENS,
            "top_p":       0.9,
        },
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
    }
    # Qwen3 reasoning mode — improves extraction accuracy with minimal extra cost
    if "qwen3" in model.lower():
        payload["think"] = False

    resp = _requests.post(
        f"{OLLAMA_BASE_URL}/api/chat",
        json=payload,
        timeout=500,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


# ── JSON extraction ───────────────────────────────────────────────────────────

def _parse_json(raw: str) -> dict:
    # Strip Qwen3 <think>…</think> reasoning block
    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

    for candidate in [
        raw,
        re.search(r"```(?:json)?\s*([\s\S]+?)```", raw),
        None,  # fallback: brace extraction
    ]:
        if candidate is None:
            start = raw.find("{")
            end   = raw.rfind("}")
            if start != -1 and end != -1:
                candidate = raw[start : end + 1]
        elif hasattr(candidate, "group"):
            candidate = candidate.group(1).strip()

        if isinstance(candidate, str):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue

    raise ValueError(f"No valid JSON found in LLM output:\n{raw[:400]}")


# ── Field coercers ────────────────────────────────────────────────────────────

def _conf(v: Any) -> ConfidenceLevel:
    return {"high": ConfidenceLevel.HIGH, "medium": ConfidenceLevel.MEDIUM,
            "low": ConfidenceLevel.LOW}.get(str(v).lower(), ConfidenceLevel.UNKNOWN)

def _mtype(v: Any) -> MalwareType:
    return {t.value.lower(): t for t in MalwareType}.get(str(v).lower(), MalwareType.UNKNOWN)

def _itype(v: Any) -> IOCType:
    return {t.value.lower(): t for t in IOCType}.get(str(v).lower(), IOCType.URL)


# ── JSON → Pydantic ───────────────────────────────────────────────────────────

def _build_report(article: ExtractedArticle, data: dict, model: str, elapsed: float) -> CTIReport:
    threat_actors = [
        ThreatActor(
            name        = ta.get("name", "Unknown"),
            aliases     = ta.get("aliases", []),
            attribution = ta.get("attribution"),
            motivation  = ta.get("motivation"),
            confidence  = _conf(ta.get("confidence")),
            evidence    = ta.get("evidence"),
        )
        for ta in (data.get("threat_actors") or [])
        if ta.get("name")
    ]

    campaigns = [
        Campaign(
            name        = c.get("name", "Unknown"),
            aliases     = c.get("aliases", []),
            description = c.get("description", ""),
            confidence  = _conf(c.get("confidence")),
            evidence    = c.get("evidence", ""),
        )
        for c in (data.get("campaigns") or [])
        if c.get("name")
    ]

    malware = [
        MalwareFamily(
            name         = m.get("name", "Unknown"),
            malware_type = _mtype(m.get("type", "")),
            description  = m.get("description"),
            confidence   = _conf(m.get("confidence")),
        )
        for m in (data.get("malware") or [])
        if m.get("name")
    ]

    iocs = [
        IOC(
            value      = i.get("value", ""),
            ioc_type   = _itype(i.get("ioc_type", "")),
            context    = i.get("context"),
            confidence = _conf(i.get("confidence")),
        )
        for i in (data.get("iocs") or [])
        if i.get("value")
    ]

    behaviors = [
        RawBehavior(
            behavior   = b.get("behavior", ""),
            category   = b.get("category", "Unknown"),
            evidence   = b.get("evidence", ""),
            artifacts  = b.get("artifacts", []),
            confidence = _conf(b.get("confidence")),
        )
        for b in (data.get("behaviors") or [])
        if b.get("behavior")
    ]

    return CTIReport(
        article           = article,
        executive_summary = data.get("executive_summary", ""),
        threat_actors     = threat_actors,
        campaigns         = campaigns,
        malware           = malware,
        iocs              = iocs,
        behaviors         = behaviors,
        model_used        = model,
        processing_time_s = round(elapsed, 2),
    )


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_article(article: ExtractedArticle, model: str = LLM_MODEL) -> CTIReport:
    """
    Stage A: send article content to the LLM, get back raw extracted facts.
    ATT&CK mapping and hunt generation happen in separate stages after this.
    """
    rss     = article.rss_article
    content = article.full_text

    # Hard truncation — keeps the model firmly within its comfort zone
    if len(content) > MAX_CONTENT_CHARS:
        content = content[:MAX_CONTENT_CHARS] + "\n\n[truncated]"

    prompt = EXTRACTION_PROMPT.format(
        title          = rss.title,
        source         = rss.source,
        published_date = rss.published_date.strftime("%Y-%m-%d"),
        content        = content,
    )

    logger.info("Analyzing [%s]: %s", model, rss.title[:70])
    t0 = time.time()

    try:
        raw     = _ollama(prompt, model=model)
        data    = _parse_json(raw)
        report  = _build_report(article, data, model, time.time() - t0)
        logger.info(
            "  → actors=%d  iocs=%d  behaviors=%d  (%.1fs)",
            len(report.threat_actors), len(report.iocs),
            len(report.behaviors), report.processing_time_s,
        )
    except Exception as exc:
        logger.error("LLM failed for '%s': %s", rss.title[:60], exc)
        report = CTIReport(
            article           = article,
            executive_summary = f"[Extraction failed: {exc}]",
            model_used        = model,
            processing_time_s = round(time.time() - t0, 2),
        )

    return report


def analyze_articles(articles: list[ExtractedArticle], model: str = LLM_MODEL) -> list[CTIReport]:
    reports = []
    for i, art in enumerate(articles, 1):
        logger.info("[%d/%d] %s", i, len(articles), art.rss_article.title[:60])
        reports.append(analyze_article(art, model=model))
    return reports
