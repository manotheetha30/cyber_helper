"""
CTI Pipeline – ATT&CK STIX Ingestion into ChromaDB
Run once (or when ATT&CK is updated):  python main.py --init-rag

This module is ingestion-only. Querying is done in attack_mapper.py.
"""
from __future__ import annotations
import json
import logging
from pathlib import Path

import requests

from settings import ATTACK_STIX_URL, CHROMA_PERSIST_DIR, EMBED_MODEL

logger = logging.getLogger(__name__)
COLLECTION_NAME = "mitre_attack_enterprise"


def _get_collection(force_new: bool = False):
    import chromadb
    from chromadb.utils import embedding_functions

    ef     = embedding_functions.SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL)
    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)

    if force_new:
        try:
            client.delete_collection(COLLECTION_NAME)
        except Exception:
            pass

    return client.get_or_create_collection(
        name               = COLLECTION_NAME,
        embedding_function = ef,
        metadata           = {"hnsw:space": "cosine"},
    )


def _parse_stix(stix_data: dict) -> list[dict]:
    tactic_map: dict[str, str] = {}
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "x-mitre-tactic":
            short = obj.get("x_mitre_shortname", "")
            name  = obj.get("name", "")
            if short and name:
                tactic_map[short] = name

    techniques = []
    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        technique_id = ""
        technique_url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id  = ref.get("external_id", "")
                technique_url = ref.get("url", "")
                break

        if not technique_id.startswith("T"):
            continue

        tactics = [
            tactic_map.get(p["phase_name"], p["phase_name"])
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        name         = obj.get("name", "")
        description  = obj.get("description", "")[:1000]
        platforms    = ", ".join(obj.get("x_mitre_platforms", []))
        data_sources = ", ".join(obj.get("x_mitre_data_sources", []))

        # Rich document text — this is what gets embedded for similarity search.
        # Including data_sources improves retrieval for behavior queries that
        # mention specific log types or artifacts.
        doc_text = (
            f"Technique: {technique_id} — {name}\n"
            f"Tactics: {', '.join(tactics)}\n"
            f"Platforms: {platforms}\n"
            f"Data Sources: {data_sources}\n"
            f"Description: {description}"
        )

        techniques.append({
            "id":             technique_id,
            "document":       doc_text,
            "technique_id":   technique_id,
            "technique_name": name,
            "tactics":        ", ".join(tactics),
            "description":    description[:500],
            "data_sources":   data_sources,
            "url":            technique_url,
        })

    logger.info("Parsed %d techniques from STIX", len(techniques))
    return techniques


def ingest_attack_stix(force_reload: bool = False) -> None:
    """Download and ingest ATT&CK STIX into ChromaDB."""
    collection = _get_collection(force_new=force_reload)

    if not force_reload and collection.count() > 0:
        logger.info("ATT&CK collection already has %d docs — skipping ingest.", collection.count())
        return

    stix_cache = Path(CHROMA_PERSIST_DIR) / "attack_stix.json"
    stix_cache.parent.mkdir(parents=True, exist_ok=True)

    if not stix_cache.exists() or force_reload:
        logger.info("Downloading ATT&CK STIX from GitHub...")
        resp = requests.get(ATTACK_STIX_URL, timeout=120)
        resp.raise_for_status()
        stix_cache.write_bytes(resp.content)
        logger.info("Cached STIX at %s", stix_cache)

    stix_data  = json.loads(stix_cache.read_text())
    techniques = _parse_stix(stix_data)

    if not techniques:
        raise RuntimeError("No techniques parsed — check STIX file.")

    batch_size = 100
    for i in range(0, len(techniques), batch_size):
        batch = techniques[i : i + batch_size]
        collection.upsert(
            ids       = [t["id"] for t in batch],
            documents = [t["document"] for t in batch],
            metadatas = [
                {
                    "technique_id":   t["technique_id"],
                    "technique_name": t["technique_name"],
                    "tactics":        t["tactics"],
                    "description":    t["description"],
                    "data_sources":   t["data_sources"],
                    "url":            t["url"],
                }
                for t in batch
            ],
        )
        logger.debug("Upserted batch %d–%d", i, i + len(batch))

    logger.info("Ingestion complete — %d techniques indexed.", collection.count())
