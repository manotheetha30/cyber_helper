from __future__ import annotations

import logging
import pickle
import requests
import numpy as np

from models import (
    ATTACKMapping,
    ConfidenceLevel,
    CTIReport,
    RawBehavior,
)

from settings import RAG_TOP_K

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Load ATT&CK embeddings
# ------------------------------------------------------------------

with open("attack_embeddings.pkl", "rb") as f:
    db = pickle.load(f)

TECHNIQUES = db["techniques"]

EMBEDDINGS = np.array(
    db["embeddings"],
    dtype=np.float32,
).squeeze(1)

logger.info(
    "Loaded %d ATT&CK techniques",
    len(TECHNIQUES),
)

# ------------------------------------------------------------------
# Confidence thresholds
# ------------------------------------------------------------------

_HIGH_SIMILARITY = 0.80
_MEDIUM_SIMILARITY = 0.60
_MIN_SIMILARITY = 0


# ------------------------------------------------------------------
# Ollama embedding helper
# ------------------------------------------------------------------

def get_embedding(text: str) -> np.ndarray:

    r = requests.post(
        "http://localhost:11434/api/embed",
        json={
            "model": "nomic-embed-text",
            "input": text,
        },
        timeout=60,
    )

    r.raise_for_status()

    emb = np.array(
        r.json()["embeddings"][0],
        dtype=np.float32,
    )

    norm = np.linalg.norm(emb)

    if norm > 0:
        emb = emb / norm

    return emb


# ------------------------------------------------------------------
# Similarity -> confidence
# ------------------------------------------------------------------

def _score_to_confidence(
    score: float,
) -> ConfidenceLevel:

    if score >= _HIGH_SIMILARITY:
        return ConfidenceLevel.HIGH

    if score >= _MEDIUM_SIMILARITY:
        return ConfidenceLevel.MEDIUM

    return ConfidenceLevel.LOW


# ------------------------------------------------------------------
# Build query text
# ------------------------------------------------------------------

def _build_query(
    behavior: RawBehavior,
) -> str:

    parts = [behavior.behavior]

    if (
        behavior.category
        and behavior.category != "Unknown"
    ):
        parts.append(
            f"Tactic: {behavior.category}"
        )

    if behavior.artifacts:
        parts.append(
            "Artifacts: "
            + ", ".join(
                behavior.artifacts[:5]
            )
        )

    return " | ".join(parts),behavior.category


# ------------------------------------------------------------------
# Map one behavior
# ------------------------------------------------------------------

def map_behavior(
    behavior: RawBehavior,
    top_k: int = RAG_TOP_K,
) -> list[ATTACKMapping]:

    query,tactic_val = _build_query(
        behavior
    )

    try:

        query_embedding = get_embedding(
            query
        )

        scores = np.dot(
            EMBEDDINGS,
            query_embedding,
        )

        top_indices = np.argsort(
            scores
        )[::-1][:top_k]

    except Exception as exc:

        logger.warning(
            "ATT&CK search failed: %s",
            exc,
        )

        return []

    # Find the best match only
    best_mapping = None
    best_similarity = _MIN_SIMILARITY

    for idx in top_indices:

        similarity = float(
            scores[idx]
        )

        if similarity < best_similarity:
            continue

        technique = TECHNIQUES[idx]

        best_mapping = ATTACKMapping(
            tactic=tactic_val,
            technique_id=technique[
                "attack_id"
            ],
            technique_name=technique[
                "name"
            ],
            observed_behavior=behavior.behavior,
            confidence=_score_to_confidence(
                similarity
            ),
            similarity_score=round(
                similarity,
                4,
            ),
        )

        logger.debug(
            "%s -> %s (%0.4f)",
            behavior.behavior[:50],
            technique["attack_id"],
            similarity,
        )

        # Return only the best match
        break

    return [
        best_mapping
    ] if best_mapping else []


# ------------------------------------------------------------------
# Map report
# ------------------------------------------------------------------

def map_report(
    report: CTIReport,
    top_k: int = 3,
) -> CTIReport:

    if not report.behaviors:
        return report

    all_mappings = []

    for behavior in report.behaviors:

        mappings = map_behavior(
            behavior,
            top_k=top_k,
        )

        all_mappings.extend(
            mappings
        )

        if mappings:

            logger.info(
                "  %-55s -> %s",
                behavior.behavior[:55],
                ", ".join(
                    m.technique_id
                    for m in mappings
                ),
            )

    deduped = {}

    for mapping in all_mappings:

        if (
            mapping.technique_id
            not in deduped
            or
            mapping.similarity_score
            >
            deduped[
                mapping.technique_id
            ].similarity_score
        ):
            deduped[
                mapping.technique_id
            ] = mapping

    report.attack_mappings = sorted(
        deduped.values(),
        key=lambda x:
            x.similarity_score,
        reverse=True,
    )

    logger.info(
        "ATT&CK mapping: %d behaviors -> %d techniques",
        len(report.behaviors),
        len(
            report.attack_mappings
        ),
    )

    return report


# ------------------------------------------------------------------
# Batch mapping
# ------------------------------------------------------------------

def map_reports(
    reports: list[CTIReport],
) -> list[CTIReport]:

    return [
        map_report(r)
        for r in reports
    ]