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

# ── Chunking configuration ────────────────────────────────────────────────────

# Each chunk is this many characters max (safe for model context)
CHUNK_SIZE = 8_000

# Overlap between chunks (for context continuity)
CHUNK_OVERLAP = 1_500

# Minimum chunk size (to avoid tiny fragments)
MIN_CHUNK_SIZE = 2_000


# ── Chunking utilities ────────────────────────────────────────────────────────

def _smart_chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """
    Split text into overlapping chunks at sentence boundaries.
    Tries to avoid breaking mid-sentence or mid-paragraph.
    
    Args:
        text: The article content to chunk
        chunk_size: Target chunk size in characters
        overlap: Overlap size between consecutive chunks
    
    Returns:
        List of overlapping text chunks
    """
    if len(text) <= chunk_size:
        return [text]
    
    # Split by sentences (rough heuristic: `. `, `! `, `? `)
    sentences = re.split(r'(?<=[.!?])\s+', text)
    
    chunks = []
    current_chunk = ""
    
    for sentence in sentences:
        # Add sentence to current chunk if it fits
        if len(current_chunk) + len(sentence) + 1 < chunk_size:
            current_chunk += (" " if current_chunk else "") + sentence
        else:
            # Current chunk is full, save it
            if current_chunk:
                chunks.append(current_chunk)
            # Start new chunk with overlap from previous
            if chunks and overlap > 0:
                # Take last `overlap` chars from previous chunk as context
                overlap_text = chunks[-1][-overlap:]
                current_chunk = overlap_text + " " + sentence
            else:
                current_chunk = sentence
    
    # Don't forget the last chunk
    if current_chunk:
        chunks.append(current_chunk)
    
    # Filter out tiny chunks (merge with previous)
    filtered = []
    for chunk in chunks:
        if len(chunk) < MIN_CHUNK_SIZE and filtered:
            # Merge with previous chunk
            filtered[-1] = filtered[-1] + " " + chunk
        else:
            filtered.append(chunk)
    
    logger.debug(f"Split article into {len(filtered)} chunks (sizes: {[len(c) for c in filtered]})")
    return filtered


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


# ── Result aggregation (for multi-chunk processing) ────────────────────────────

def _merge_reports(chunk_reports: list[dict]) -> dict:
    """
    Merge extraction results from multiple chunks into one consolidated report.
    Deduplicates behaviors and IOCs while keeping highest confidence scores.
    
    Args:
        chunk_reports: List of extraction dicts from each chunk
    
    Returns:
        Single merged extraction dict
    """
    if not chunk_reports:
        return {}
    
    if len(chunk_reports) == 1:
        return chunk_reports[0]
    
    merged = {
        "executive_summary": chunk_reports[0].get("executive_summary", ""),
        "threat_actors": [],
        "campaigns": [],
        "malware": [],
        "iocs": [],
        "behaviors": [],
    }
    
    # Deduplicate threat actors by name
    actors_seen = set()
    for report in chunk_reports:
        for actor in (report.get("threat_actors") or []):
            name = actor.get("name", "").lower()
            if name and name not in actors_seen:
                actors_seen.add(name)
                merged["threat_actors"].append(actor)
    
    # Deduplicate campaigns by name
    campaigns_seen = set()
    for report in chunk_reports:
        for campaign in (report.get("campaigns") or []):
            name = campaign.get("name", "").lower()
            if name and name not in campaigns_seen:
                campaigns_seen.add(name)
                merged["campaigns"].append(campaign)
    
    # Deduplicate malware by name
    malware_seen = set()
    for report in chunk_reports:
        for malware in (report.get("malware") or []):
            name = malware.get("name", "").lower()
            if name and name not in malware_seen:
                malware_seen.add(name)
                merged["malware"].append(malware)
    
    # Deduplicate IOCs by value
    iocs_by_value = {}
    for report in chunk_reports:
        for ioc in (report.get("iocs") or []):
            value = ioc.get("value", "").lower()
            if value:
                if value not in iocs_by_value:
                    iocs_by_value[value] = ioc
                else:
                    # Keep highest confidence
                    existing_conf = _conf(iocs_by_value[value].get("confidence", "low"))
                    new_conf = _conf(ioc.get("confidence", "low"))
                    if new_conf.value > existing_conf.value:  # HIGH > MEDIUM > LOW
                        iocs_by_value[value] = ioc
    merged["iocs"] = list(iocs_by_value.values())
    
    # Deduplicate behaviors by description (similar behaviors)
    behaviors_by_desc = {}
    for report in chunk_reports:
        for behavior in (report.get("behaviors") or []):
            desc = behavior.get("behavior", "").lower().strip()
            if desc:
                if desc not in behaviors_by_desc:
                    behaviors_by_desc[desc] = behavior
                else:
                    # Keep highest confidence
                    existing = behaviors_by_desc[desc]
                    existing_conf = _conf(existing.get("confidence", "low"))
                    new_conf = _conf(behavior.get("confidence", "low"))
                    if new_conf.value > existing_conf.value:
                        behaviors_by_desc[desc] = behavior
                    # Merge artifacts if different
                    else:
                        existing_artifacts = set(existing.get("artifacts", []))
                        new_artifacts = set(behavior.get("artifacts", []))
                        existing["artifacts"] = list(existing_artifacts | new_artifacts)
    merged["behaviors"] = list(behaviors_by_desc.values())
    
    logger.info(
        f"Merged {len(chunk_reports)} chunk reports: "
        f"actors={len(merged['threat_actors'])}, "
        f"behaviors={len(merged['behaviors'])}, "
        f"iocs={len(merged['iocs'])}"
    )
    
    return merged


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

def analyze_article(article: ExtractedArticle, model: str = LLM_MODEL, use_chunking: bool = True) -> CTIReport:
    """
    Stage A: send article content to the LLM, get back raw extracted facts.
    
    Now supports intelligent chunking for longer articles:
    - Splits article into overlapping chunks at sentence boundaries
    - Processes each chunk with context intact
    - Merges and deduplicates results
    - Much better behavior extraction for long articles!
    
    ATT&CK mapping and hunt generation happen in separate stages after this.
    
    Args:
        article: ExtractedArticle to analyze
        model: LLM model name
        use_chunking: If True, chunk long articles; if False, truncate at MAX_CONTENT
    """
    rss     = article.rss_article
    content = article.full_text

    logger.info("Analyzing [%s]: %s", model, rss.title[:70])
    t0 = time.time()

    try:
        # Decide whether to use chunking
        if use_chunking and len(content) > CHUNK_SIZE:
            chunks = _smart_chunk_text(content, chunk_size=CHUNK_SIZE, overlap=CHUNK_OVERLAP)
            logger.info(f"  Processing {len(chunks)} chunks from full article...")
            
            chunk_results = []
            for i, chunk in enumerate(chunks, 1):
                logger.debug(f"  [Chunk {i}/{len(chunks)}] {len(chunk)} chars")
                
                prompt = EXTRACTION_PROMPT.format(
                    title          = rss.title,
                    source         = rss.source,
                    published_date = rss.published_date.strftime("%Y-%m-%d"),
                    content        = chunk,
                )
                
                try:
                    raw  = _ollama(prompt, model=model)
                    data = _parse_json(raw)
                    chunk_results.append(data)
                except Exception as e:
                    logger.warning(f"  Chunk {i} failed: {e}")
                    continue
            
            if not chunk_results:
                raise ValueError("All chunks failed to extract")
            
            # Merge results from all chunks
            data = _merge_reports(chunk_results)
        
        else:
            # Original truncation behavior for short articles or if chunking disabled
            if len(content) > CHUNK_SIZE:
                logger.info(f"  Article longer than {CHUNK_SIZE} chars, truncating (chunking disabled)")
                content = content[:CHUNK_SIZE] + "\n\n[truncated]"
            
            prompt = EXTRACTION_PROMPT.format(
                title          = rss.title,
                source         = rss.source,
                published_date = rss.published_date.strftime("%Y-%m-%d"),
                content        = content,
            )
            
            raw  = _ollama(prompt, model=model)
            data = _parse_json(raw)
        
        # Build final report from merged data
        report = _build_report(article, data, model, time.time() - t0)
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


def analyze_articles(articles: list[ExtractedArticle], model: str = LLM_MODEL, use_chunking: bool = True) -> list[CTIReport]:
    """
    Analyze multiple articles.
    
    Args:
        articles: List of ExtractedArticle objects
        model: LLM model to use
        use_chunking: If True, use intelligent chunking for long articles
    
    Returns:
        List of CTIReport objects
    """
    reports = []
    for i, art in enumerate(articles, 1):
        logger.info("[%d/%d] %s", i, len(articles), art.rss_article.title[:60])
        reports.append(analyze_article(art, model=model, use_chunking=use_chunking))
    return reports
