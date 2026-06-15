"""
CTI Pipeline – Report Generator
Renders the final CTIReport (with all three stages complete) into Markdown + CSV.
"""
from __future__ import annotations
import csv
import logging
from datetime import datetime
from pathlib import Path

from settings import REPORT_DIR
from models import CTIReport, HuntHypothesis

logger = logging.getLogger(__name__)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    sep  = "| " + " | ".join("---" for _ in headers) + " |"
    head = "| " + " | ".join(headers) + " |"
    body = ["| " + " | ".join(str(c).replace("|", "\\|")[:120] for c in row) + " |"
            for row in rows]
    return "\n".join([head, sep] + body)


def render_report(report: CTIReport) -> str:
    rss  = report.article.rss_article
    now  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        f"# CTI Report: {rss.title}",
        "",
        f"| Field | Value |",
        f"| --- | --- |",
        f"| Source | {rss.source} |",
        f"| Published | {rss.published_date.strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| URL | [{rss.url}]({rss.url}) |",
        f"| Report Generated | {now} |",
        f"| Model | {report.model_used} |",
        f"| LLM Processing Time | {report.processing_time_s}s |",
        "",
        "---",
        "",
    ]

    # ── Executive Summary ─────────────────────────────────────────────────────
    lines += ["## Executive Summary", "", report.executive_summary or "_None generated._", ""]

    # ── Threat Actors ─────────────────────────────────────────────────────────
    lines += ["## Threat Actors", ""]
    if report.threat_actors:
        for ta in report.threat_actors:
            lines += [
                f"### {ta.name}",
                f"- **Aliases:** {', '.join(ta.aliases) or '—'}",
                f"- **Attribution:** {ta.attribution or '—'}",
                f"- **Motivation:** {ta.motivation or '—'}",
                f"- **Confidence:** {ta.confidence.value}",
                f"- **Evidence:** {ta.evidence or '—'}",
                "",
            ]
    else:
        lines += ["_None identified._", ""]

    # ── Campaigns ─────────────────────────────────────────────────────────────
    if report.campaigns:
        lines += ["## Campaigns", ""]
        for c in report.campaigns:
            lines += [
                f"### {c.name}",
                f"- **Aliases:** {', '.join(c.aliases) or '—'}",
                f"- **Confidence:** {c.confidence.value}",
                f"- **Description:** {c.description or '—'}",
                f"- **Evidence:** {c.evidence or '—'}",
                "",
            ]

    # ── Malware ───────────────────────────────────────────────────────────────
    lines += ["## Malware", ""]
    if report.malware:
        for mw in report.malware:
            lines += [
                f"### {mw.name} ({mw.malware_type.value})",
                f"- **Aliases:** {', '.join(mw.aliases) or '—'}",
                f"- **Confidence:** {mw.confidence.value}",
                f"- **Description:** {mw.description or '—'}",
                "",
            ]
    else:
        lines += ["_None identified._", ""]

    # ── IOCs ──────────────────────────────────────────────────────────────────
    lines += ["## Indicators of Compromise", ""]
    if report.iocs:
        lines += [
            _table(
                ["IOC Value", "Type", "Confidence", "Context"],
                [[i.value, i.ioc_type.value, i.confidence.value, i.context or "—"]
                 for i in report.iocs],
            ), "",
        ]
    else:
        lines += ["_None extracted._", ""]

    # ── Behaviors (raw LLM output) ────────────────────────────────────────────
    lines += ["## Observed Behaviors", ""]
    if report.behaviors:
        for i, b in enumerate(report.behaviors, 1):
            artifacts = ", ".join(b.artifacts) if b.artifacts else "—"
            lines += [
                f"**{i}. {b.behavior}**",
                f"- Category: {b.category}  |  Confidence: {b.confidence.value}",
                f"- Evidence: _{b.evidence}_",
                f"- Artifacts: `{artifacts}`",
                "",
            ]
    else:
        lines += ["_None extracted._", ""]

    # ── ATT&CK Mapping (Stage B) ──────────────────────────────────────────────
    lines += ["## MITRE ATT&CK Mapping", ""]
    if report.attack_mappings:
        lines += [
            _table(
                ["Tactic", "Technique ID", "Technique Name", "Observed Behavior", "Confidence", "Similarity"],
                [
                    [
                        m.tactic,
                        f"`{m.technique_id}`",
                        m.technique_name,
                        m.observed_behavior[:70],
                        m.confidence.value,
                        f"{m.similarity_score:.2f}",
                    ]
                    for m in report.attack_mappings
                ],
            ), "",
        ]
    else:
        lines += ["_No techniques mapped — either no behaviors were extracted or similarity was below threshold._", ""]

    # ── Hunt Hypotheses (Stage C) ─────────────────────────────────────────────
    lines += ["## Threat Hunt Hypotheses", ""]
    if report.hunt_hypotheses:
        for i, hh in enumerate(report.hunt_hypotheses, 1):
            badge     = "✅ Huntable" if hh.huntable else "⚠️ Needs Validation"
            techs     = ", ".join(f"`{t}`" for t in hh.mitre_techniques)
            sources   = "\n".join(f"  - {ds.value}" for ds in hh.data_sources)
            telemetry = "\n".join(f"  - {t}" for t in hh.required_telemetry)
            lines += [
                f"### Hypothesis {i} — {badge}",
                f"> {hh.hypothesis}",
                "",
                f"**Evidence:** {hh.evidence}",
                f"**Techniques:** {techs}",
                f"**Reason:** {hh.huntability_reason}",
                "",
                "**Data Sources:**",
                sources,
                "",
                "**Required Telemetry:**",
                telemetry,
                "",
            ]
            if hh.detection_query:
                lines += ["**Sigma Detection Stub:**", "```yaml", hh.detection_query, "```", ""]
    else:
        lines += ["_No hypotheses generated._", ""]

    # ── Huntability Table ─────────────────────────────────────────────────────
    if report.hunt_hypotheses:
        lines += ["## Huntability Assessment", ""]
        lines += [
            _table(
                ["Hypothesis (truncated)", "Huntable", "Technique(s)", "Reason"],
                [
                    [
                        hh.hypothesis[:60] + "…",
                        "✅" if hh.huntable else "⚠️",
                        ", ".join(hh.mitre_techniques),
                        hh.huntability_reason[:80],
                    ]
                    for hh in report.hunt_hypotheses
                ],
            ), "",
        ]

    lines += ["---", f"*Generated by CTI Pipeline | {now}*"]
    return "\n".join(lines)


def save_report_file(report: CTIReport, output_dir: Path | None = None) -> Path:
    output_dir = Path(output_dir or REPORT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    date_str = report.article.rss_article.published_date.strftime("%Y-%m-%d")
    title    = report.article.rss_article.title[:50]
    safe     = "".join(c if c.isalnum() or c in "- " else "_" for c in title).strip()
    path     = output_dir / f"{date_str}_{safe.replace(' ', '_')}.md"

    path.write_text(render_report(report), encoding="utf-8")
    logger.info("Report written: %s", path)
    return path


def save_all_reports(reports: list[CTIReport], output_dir: Path | None = None) -> list[Path]:
    paths = []
    for r in reports:
        try:
            paths.append(save_report_file(r, output_dir))
        except Exception as exc:
            logger.error("Failed to write report: %s", exc)
    return paths


def export_ioc_csv(reports: list[CTIReport], output_dir: Path | None = None) -> Path:
    output_dir = Path(output_dir or REPORT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{datetime.utcnow().strftime('%Y-%m-%d')}_iocs.csv"

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["value", "type", "confidence", "context", "source", "url"])
        w.writeheader()
        for r in reports:
            rss = r.article.rss_article
            for ioc in r.iocs:
                w.writerow({
                    "value":      ioc.value,
                    "type":       ioc.ioc_type.value,
                    "confidence": ioc.confidence.value,
                    "context":    ioc.context or "",
                    "source":     rss.source,
                    "url":        rss.url,
                })

    total = sum(len(r.iocs) for r in reports)
    logger.info("IOC CSV: %s (%d IOCs)", path, total)
    return path
