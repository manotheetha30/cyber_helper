"""
CTI Pipeline – Stage 1: RSS Ingestion
Fetches articles published during the previous UTC day from configured feeds.
"""
from __future__ import annotations
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Generator

import feedparser
import requests
from dateutil import parser as dateutil_parser
from tenacity import retry, stop_after_attempt, wait_exponential

from settings import RSS_FEEDS, REQUEST_TIMEOUT, USER_AGENT
from models import RSSArticle

logger = logging.getLogger(__name__)


def _utc_yesterday() -> tuple[datetime, datetime]:
    """Return (start, end) of the previous UTC calendar day."""
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today - timedelta(days=1)
    yesterday_end   = today
    return yesterday_start, yesterday_end


def _parse_published(entry: feedparser.util.FeedParserDict) -> datetime | None:
    """Robustly extract a timezone-aware publication datetime from a feed entry."""
    # feedparser populates published_parsed as UTC time.struct_time
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            import calendar
            ts = calendar.timegm(entry.published_parsed)
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            pass
    # Fallback: parse the raw string
    for attr in ("published", "updated", "created"):
        raw = getattr(entry, attr, None)
        if raw:
            try:
                dt = dateutil_parser.parse(raw)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass
    return None


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def _fetch_feed(url: str) -> feedparser.util.FeedParserDict:
    """Fetch a single RSS/Atom feed with retry logic."""
    headers = {"User-Agent": USER_AGENT}
    response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return feedparser.parse(response.content)


def _is_yesterday(dt: datetime | None, start: datetime, end: datetime) -> bool:
    if dt is None:
        return False
    return start <= dt < end


def ingest_feeds(
    feeds: list[dict] | None = None,
    lookback_days: int = 1,
) -> list[RSSArticle]:
    """
    Parse all configured RSS feeds and return articles from the previous day.

    Args:
        feeds: Override feed list (defaults to settings.RSS_FEEDS).
        lookback_days: How many days back to look (default 1 = yesterday).

    Returns:
        Deduplicated list of RSSArticle objects sorted by publication date desc.
    """
    if feeds is None:
        feeds = RSS_FEEDS

    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    window_start = today - timedelta(days=lookback_days)
    window_end   = today

    seen_urls: set[str] = set()
    articles: list[RSSArticle] = []

    for feed_cfg in feeds:
        source = feed_cfg["name"]
        url    = feed_cfg["url"]
        logger.info("Fetching feed: %s", source)

        try:
            feed = _fetch_feed(url)
        except Exception as exc:
            logger.warning("Failed to fetch %s (%s): %s", source, url, exc)
            continue

        for entry in feed.entries:
            pub_dt = _parse_published(entry)

            if not _is_yesterday(pub_dt, window_start, window_end):
                continue

            article_url: str = getattr(entry, "link", "")
            if not article_url or article_url in seen_urls:
                continue

            seen_urls.add(article_url)

            article = RSSArticle(
                title          = getattr(entry, "title", "Untitled"),
                url            = article_url,
                source         = source,
                published_date = pub_dt,
                author         = getattr(entry, "author", None),
                summary        = getattr(entry, "summary", None),
            )
            articles.append(article)
            logger.debug("  + %s", article.title[:80])

        logger.info("  → %d articles from %s", sum(1 for a in articles if a.source == source), source)

    articles.sort(key=lambda a: a.published_date, reverse=True)
    logger.info("Total articles collected: %d", len(articles))
    return articles


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = ingest_feeds()
    for a in results:
        print(f"[{a.source}] {a.published_date.date()} | {a.title[:70]}")
