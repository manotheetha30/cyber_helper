"""
CTI Pipeline – Stage B: ATT&CK Mapping via ChromaDB Similarity Search
No LLM involved. Each raw behavior is embedded and matched against the
indexed ATT&CK STIX dataset using cosine similarity.

Flow:
  RawBehavior.behavior + artifacts
      ↓  embed with all-MiniLM-L6-v2
      ↓  cosine search in ChromaDB
      ↓  top-K technique hits (filtered by distance threshold)
      ↓  ATTACKMapping objects attached to CTIReport
"""
from __future__ import annotations
import logging
from typing import Optional

from models import ATTACKMapping, ConfidenceLevel, CTIReport, RawBehavior
from settings import RAG_TOP_K, CHROMA_PERSIST_DIR, EMBED_MODEL

logger = logging.getLogger(__name__)

# Cosine distance thresholds → confidence bands
# ChromaDB returns distance where 0 = identical, 1 = orthogonal
_DIST_HIGH   = 0.30   # distance <= 0.30  → High confidence
_DIST_MEDIUM = 0.50   # distance <= 0.50  → Medium confidence
_DIST_MAX    = 0.65   # distance >  0.65  → rejected (too dissimilar)

_collection = None


def _get_collection():
    global _collection
    if _collection is not None:
        return _collection

    import chromadb
    from chromadb.utils import embedding_functions

    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBED_MODEL
    )
    client      = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    _collection = client.get_or_create_collection(
        name               = "mitre_attack_enterprise",
        embedding_function = ef,
        metadata           = {"hnsw:space": "cosine"},
    )

    if _collection.count() == 0:
        raise RuntimeError(
            "ATT&CK collection is empty. Run: python main.py --init-rag"
        )
    return _collection


def _dist_to_confidence(dist: float) -> ConfidenceLevel:
    if dist <= _DIST_HIGH:
        return ConfidenceLevel.HIGH
    if dist <= _DIST_MEDIUM:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def _build_query(behavior: RawBehavior) -> str:
    """
    Combine the behavior description with its artifacts and category hint
    into a single rich query string for the embedding model.
    The category acts as a tactic hint that steers the similarity search
    toward the right part of the ATT&CK matrix.
    """
    parts = [behavior.behavior]
    if behavior.category and behavior.category != "Unknown":
        parts.append(f"Tactic: {behavior.category}")
    if behavior.artifacts:
        parts.append("Artifacts: " + ", ".join(behavior.artifacts[:5]))
    return " | ".join(parts)


def map_behavior(behavior: RawBehavior, top_k: int = RAG_TOP_K) -> list[ATTACKMapping]:
    """
    Map a single RawBehavior to one or more ATT&CK techniques.
    Returns an empty list if no techniques meet the similarity threshold.
    """
    try:
        collection = _get_collection()
    except RuntimeError as exc:
        logger.warning("ATT&CK mapping skipped: %s", exc)
        return []

    query = _build_query(behavior)

    try:
        results = collection.query(
            query_texts = [query],
            n_results   = top_k,
            include     = ["metadatas", "distances"],
        )
    except Exception as exc:
        logger.warning("ChromaDB query failed: %s", exc)
        return []

    mappings: list[ATTACKMapping] = []
    metas     = results["metadatas"][0]
    distances = results["distances"][0]

    for meta, dist in zip(metas, distances):
        if dist > _DIST_MAX:
            continue  # too dissimilar — skip

        technique_id = meta.get("technique_id", "")
        if not technique_id.startswith("T"):
            continue

        # Use first tactic from the comma-separated tactics string
        tactics_str = meta.get("tactics", "Unknown")
        tactic = tactics_str.split(",")[0].strip() if tactics_str else "Unknown"

        mappings.append(
            ATTACKMapping(
                tactic            = tactic,
                technique_id      = technique_id,
                technique_name    = meta.get("technique_name", ""),
                observed_behavior = behavior.behavior,
                confidence        = _dist_to_confidence(dist),
                similarity_score  = round(1.0 - dist, 4),  # convert to similarity
            )
        )
        logger.debug(
            "  %s → %s %s (dist=%.3f)",
            behavior.behavior[:50], technique_id,
            meta.get("technique_name", ""), dist,
        )

    # Deduplicate by technique_id — keep highest similarity hit
    seen: dict[str, ATTACKMapping] = {}
    for m in mappings:
        if m.technique_id not in seen or m.similarity_score > seen[m.technique_id].similarity_score:
            seen[m.technique_id] = m

    return list(seen.values())


def map_report(report: CTIReport, top_k: int = 3) -> CTIReport:
    """
    Stage B: map all behaviors in a CTIReport to ATT&CK techniques.
    Returns a new CTIReport with attack_mappings populated.
    Mutates in place and returns self for chaining.
    """
    if not report.behaviors:
        return report

    all_mappings: list[ATTACKMapping] = []
    for behavior in report.behaviors:
        mappings = map_behavior(behavior, top_k=top_k)
        all_mappings.extend(mappings)
        if mappings:
            logger.info(
                "  %-55s → %s",
                behavior.behavior[:55],
                ", ".join(m.technique_id for m in mappings),
            )
        else:
            logger.debug("  No ATT&CK match for: %s", behavior.behavior[:60])

    # Final dedup across all behaviors — keep best similarity per technique
    deduped: dict[str, ATTACKMapping] = {}
    for m in all_mappings:
        if m.technique_id not in deduped or m.similarity_score > deduped[m.technique_id].similarity_score:
            deduped[m.technique_id] = m

    report.attack_mappings = sorted(
        deduped.values(),
        key=lambda m: m.similarity_score,
        reverse=True,
    )
    logger.info(
        "ATT&CK mapping: %d behaviors → %d unique techniques",
        len(report.behaviors), len(report.attack_mappings),
    )
    return report


def map_reports(reports: list[CTIReport]) -> list[CTIReport]:
    """Batch map all reports."""
    return [map_report(r) for r in reports]
