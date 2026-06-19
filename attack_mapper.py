from __future__ import annotations
import logging
import pickle
from sentence_transformers import SentenceTransformer
import requests
import numpy as np
from models import (
    ATTACKMapping,
    ConfidenceLevel,
    CTIReport,
    RawBehavior,
)

logger = logging.getLogger(__name__)
model = SentenceTransformer(
    "./e5_attack_mapper"
)
# ------------------------------------------------------------------
# Load ATT&CK embeddings
# ------------------------------------------------------------------

with open("attack_embeddings_transformer.pkl", "rb") as f:
    data = pickle.load(f)
TECHNIQUES_IDS = data["ids"]
TECHNIQUES_METADATA=data["metadata"]
EMBEDDINGS = data["embeddings"]

logger.info(
    "Loaded %d ATT&CK techniques",
    len(TECHNIQUES_IDS),
)


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

def map_behavior(behavior: RawBehavior) -> list[ATTACKMapping]:

    query,tactic_val = _build_query(
        behavior
    )

    try:

        query_embedding =model.encode(
        f"query: {query}",
        normalize_embeddings=True
    )
        scores = EMBEDDINGS @ query_embedding
        top_k = np.argsort(scores)[::-1][0]
    except Exception as exc:

        logger.warning(
            "ATT&CK search failed: %s",
            exc,
        )

        return []
    technique = TECHNIQUES_METADATA[top_k]

    best_mapping = ATTACKMapping(
        tactic=technique["tactic"],
        technique_id=technique[
            "attack_id"
        ],
        technique_name=technique[
            "name"
        ],
        observed_behavior=behavior.behavior
    )

    logger.debug(
        "%s -> %s (%0.4f)",
        behavior.behavior[:50],
        technique["attack_id"]
    )

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
            behavior
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


    report.attack_mappings = all_mappings
    

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