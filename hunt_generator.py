"""
CTI Pipeline – Stage C: Threat Hunt Hypothesis Generation
One hypothesis per tactic — all techniques and behaviors under that tactic
are consolidated into a single, richer hunting hypothesis.

Example:
  Tactic: Execution
    T1059.001 — PowerShell used to download payload
    T1059.003 — cmd.exe spawned by Word macro
    T1204.002 — User opened malicious attachment
  → ONE hypothesis covering all three, with combined artifacts + telemetry
"""
from __future__ import annotations
import logging
from collections import defaultdict

from models import (
    ATTACKMapping, CTIReport, DataSource,
    HuntHypothesis, RawBehavior, ConfidenceLevel,
)

logger = logging.getLogger(__name__)


# ── Lookup tables ─────────────────────────────────────────────────────────────

_TACTIC_SOURCES: dict[str, list[DataSource]] = {
    "Initial Access":       [DataSource.EMAIL_GATEWAY, DataSource.FIREWALL_LOGS, DataSource.PROXY_LOGS],
    "Execution":            [DataSource.SYSMON, DataSource.EDR, DataSource.WINDOWS_EVENT_LOGS],
    "Persistence":          [DataSource.SYSMON, DataSource.WINDOWS_EVENT_LOGS, DataSource.EDR],
    "Privilege Escalation": [DataSource.WINDOWS_EVENT_LOGS, DataSource.EDR, DataSource.SYSMON],
    "Defense Evasion":      [DataSource.EDR, DataSource.SYSMON, DataSource.WINDOWS_EVENT_LOGS],
    "Credential Access":    [DataSource.WINDOWS_EVENT_LOGS, DataSource.EDR, DataSource.SYSMON],
    "Discovery":            [DataSource.SYSMON, DataSource.WINDOWS_EVENT_LOGS, DataSource.EDR],
    "Lateral Movement":     [DataSource.WINDOWS_EVENT_LOGS, DataSource.FIREWALL_LOGS, DataSource.EDR],
    "Collection":           [DataSource.EDR, DataSource.SYSMON, DataSource.PROCESS_LOGS],
    "Command and Control":  [DataSource.FIREWALL_LOGS, DataSource.DNS_LOGS, DataSource.PROXY_LOGS],
    "Exfiltration":         [DataSource.PROXY_LOGS, DataSource.FIREWALL_LOGS, DataSource.PCAP],
    "Impact":               [DataSource.EDR, DataSource.WINDOWS_EVENT_LOGS, DataSource.SYSMON],
}

_TACTIC_TELEMETRY: dict[str, list[str]] = {
    "Initial Access":       ["Email gateway alerts", "Firewall inbound deny logs"],
    "Execution":            ["Sysmon Event ID 1 (process create)", "Windows Event ID 4688"],
    "Persistence":          ["Sysmon Event ID 13 (registry set)", "Windows Event ID 4698 (scheduled task)"],
    "Privilege Escalation": ["Windows Event ID 4672 (special logon)", "Windows Event ID 4673"],
    "Defense Evasion":      ["Sysmon Event ID 7 (image load)", "Windows Event ID 4663 (object access)"],
    "Credential Access":    ["Windows Event ID 4624/4625 (logon)", "Sysmon Event ID 10 (process access)"],
    "Discovery":            ["Sysmon Event ID 1 (net/whoami/ipconfig)", "Windows Event ID 4688"],
    "Lateral Movement":     ["Windows Event ID 4624 type 3 (network logon)", "Windows Event ID 4648"],
    "Collection":           ["Sysmon Event ID 11 (file create)", "EDR file access events"],
    "Command and Control":  ["DNS query logs", "Proxy logs (unusual destinations/beaconing)"],
    "Exfiltration":         ["Proxy POST volume anomalies", "Firewall large outbound transfers"],
    "Impact":               ["Windows Event ID 7045 (service install)", "EDR process termination events"],
}

# Per-technique Sigma stubs — used for the highest-confidence technique in each tactic
_SIGMA_STUBS: dict[str, str] = {
    "T1059.001": (
        "title: Suspicious PowerShell Execution\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n"
        "    CommandLine|contains:\n"
        "      - '-EncodedCommand'\n      - 'IEX'\n      - 'Invoke-Expression'\n      - 'DownloadString'\n"
        "  condition: selection"
    ),
    "T1059.003": (
        "title: Suspicious CMD Execution\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    Image|endswith: '\\\\cmd.exe'\n"
        "    CommandLine|contains:\n      - 'certutil'\n      - 'bitsadmin'\n      - '/c '\n"
        "  condition: selection"
    ),
    "T1055": (
        "title: Process Injection\n"
        "logsource:\n  category: process_access\n  product: windows\n"
        "detection:\n  selection:\n    GrantedAccess|contains:\n      - '0x1f0fff'\n      - '0x1fffff'\n"
        "  condition: selection"
    ),
    "T1003.001": (
        "title: LSASS Memory Access\n"
        "logsource:\n  category: process_access\n  product: windows\n"
        "detection:\n  selection:\n    TargetImage|endswith: '\\\\lsass.exe'\n"
        "    GrantedAccess|contains:\n      - '0x1410'\n      - '0x1010'\n"
        "  condition: selection"
    ),
    "T1566.001": (
        "title: Office Child Process Spawned (Phishing)\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    ParentImage|endswith:\n      - '\\\\winword.exe'\n      - '\\\\excel.exe'\n"
        "    Image|endswith:\n      - '\\\\powershell.exe'\n      - '\\\\cmd.exe'\n      - '\\\\wscript.exe'\n"
        "  condition: selection"
    ),
    "T1190": (
        "title: Exploit Public-Facing Application\n"
        "logsource:\n  category: webserver\n"
        "detection:\n  selection:\n    sc-status:\n      - 500\n      - 400\n"
        "    cs-uri-query|contains:\n      - '../'\n      - 'cmd='\n      - 'exec('\n"
        "  condition: selection"
    ),
    "T1071.001": (
        "title: Suspicious HTTP C2 Communication\n"
        "logsource:\n  category: proxy\n"
        "detection:\n  selection:\n    c-useragent|contains:\n      - 'curl'\n      - 'python-requests'\n"
        "    cs-method: POST\n  condition: selection"
    ),
    "T1078": (
        "title: Valid Account Used from Unusual Location\n"
        "logsource:\n  category: authentication\n  product: windows\n"
        "detection:\n  selection:\n    EventID: 4624\n    LogonType: 10\n"
        "  condition: selection"
    ),
    "T1486": (
        "title: Mass File Encryption (Ransomware)\n"
        "logsource:\n  category: file_event\n  product: windows\n"
        "detection:\n  selection:\n    TargetFilename|endswith:\n"
        "      - '.encrypted'\n      - '.locked'\n      - '.ransom'\n"
        "  condition: selection"
    ),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _behaviors_for_tactic(
    tactic:    str,
    mappings:  list[ATTACKMapping],
    behaviors: list[RawBehavior],
) -> list[RawBehavior]:
    """Return the RawBehaviors whose observed_behavior text matches any mapping in this tactic."""
    tactic_behaviors = {m.observed_behavior for m in mappings if m.tactic == tactic}
    matched = [b for b in behaviors if b.behavior in tactic_behaviors]
    # Fallback: include behaviors whose category matches the tactic name
    if not matched:
        matched = [b for b in behaviors if b.category.lower() in tactic.lower()]
    return matched


def _best_sigma(technique_ids: list[str]) -> str | None:
    """Return the Sigma stub for the highest-priority technique in the list."""
    for tid in technique_ids:
        if tid in _SIGMA_STUBS:
            return _SIGMA_STUBS[tid]
        parent = tid.split(".")[0]
        if parent in _SIGMA_STUBS:
            return _SIGMA_STUBS[parent]
    return None


def _tactic_confidence(mappings: list[ATTACKMapping]) -> ConfidenceLevel:
    """Overall confidence = highest confidence among the tactic's mappings."""
    order = [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW, ConfidenceLevel.UNKNOWN]
    for level in order:
        if any(m.confidence == level for m in mappings):
            return level
    return ConfidenceLevel.UNKNOWN


# ── Core builder ──────────────────────────────────────────────────────────────

def _build_tactic_hypothesis(
    tactic:    str,
    mappings:  list[ATTACKMapping],   # all mappings for this tactic
    behaviors: list[RawBehavior],     # all raw behaviors from the article
) -> HuntHypothesis:
    """
    Build ONE hypothesis that covers all techniques observed under a tactic.
    """
    # Sort mappings by similarity score descending — best match leads
    mappings = sorted(mappings, key=lambda m: m.similarity_score, reverse=True)

    technique_ids   = [m.technique_id   for m in mappings]
    technique_names = [m.technique_name for m in mappings]
    observed        = [m.observed_behavior for m in mappings]

    # Collect artifacts from all matching behaviors
    tactic_behaviors = _behaviors_for_tactic(tactic, mappings, behaviors)
    all_artifacts: list[str] = []
    evidence_parts: list[str] = []
    for b in tactic_behaviors:
        all_artifacts.extend(b.artifacts)
        if b.evidence:
            evidence_parts.append(b.evidence)

    # Deduplicate artifacts, keep order
    seen: set[str] = set()
    unique_artifacts = [a for a in all_artifacts if not (a in seen or seen.add(a))]  # type: ignore[func-returns-value]

    # Data sources and telemetry from the tactic lookup table
    data_sources = _TACTIC_SOURCES.get(tactic, [DataSource.EDR, DataSource.SYSMON])
    telemetry    = list(_TACTIC_TELEMETRY.get(tactic, ["EDR process events", "System logs"]))

    # Add artifact-level telemetry hints
    if unique_artifacts:
        telemetry = [f"Search for artifact: {a}" for a in unique_artifacts[:3]] + telemetry

    # ── Hypothesis statement ──────────────────────────────────────────────────
    tech_summary = ", ".join(
        f"{tid} ({name})" for tid, name in zip(technique_ids[:3], technique_names[:3])
    )
    if len(technique_ids) > 3:
        tech_summary += f" and {len(technique_ids) - 3} more"

    hypothesis = (
        f"Adversary activity consistent with the {tactic} tactic may be present. "
        f"Observed techniques: {tech_summary}. "
    )
    if unique_artifacts:
        hypothesis += f"Look for artifacts: {', '.join(unique_artifacts[:4])}."
    else:
        hypothesis += f"Observed behavior: {observed[0][:100]}."

    # ── Evidence ──────────────────────────────────────────────────────────────
    evidence = " | ".join(evidence_parts[:3]) if evidence_parts else " | ".join(observed[:2])

    # ── Huntability ───────────────────────────────────────────────────────────
    overall_confidence = _tactic_confidence(mappings)
    huntable = overall_confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM)

    if huntable and unique_artifacts:
        reason = (
            f"{len(technique_ids)} technique(s) mapped under {tactic} with "
            f"{overall_confidence.value} confidence; {len(unique_artifacts)} observable "
            f"artifact(s) identified."
        )
    elif huntable:
        reason = (
            f"{len(technique_ids)} technique(s) mapped under {tactic} with "
            f"{overall_confidence.value} confidence; no specific artifacts — "
            "hunt requires baseline tuning."
        )
    else:
        reason = (
            f"Low similarity score for {tactic} mappings — "
            "validate ATT&CK mapping before operationalising."
        )

    # ── Sigma stub (best technique in this tactic) ────────────────────────────
    detection_query = _best_sigma(technique_ids)

    return HuntHypothesis(
        hypothesis          = hypothesis,
        evidence            = evidence,
        mitre_techniques    = technique_ids,
        data_sources        = data_sources,
        huntable            = huntable,
        huntability_reason  = reason,
        required_telemetry  = telemetry[:6],
        detection_query     = detection_query,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def generate_hypotheses(report: CTIReport) -> CTIReport:
    """
    Stage C: one hypothesis per tactic, consolidating all techniques
    and behaviors observed under that tactic.
    """
    if not report.attack_mappings:
        logger.debug(
            "No ATT&CK mappings — skipping hunt generation for '%s'",
            report.article.rss_article.title[:60],
        )
        return report

    # Group mappings by tactic
    by_tactic: dict[str, list[ATTACKMapping]] = defaultdict(list)
    for m in report.attack_mappings:
        tactic = m.tactic or "Unknown"
        by_tactic[tactic].append(m)

    hypotheses: list[HuntHypothesis] = []
    for tactic, tactic_mappings in by_tactic.items():
        h = _build_tactic_hypothesis(tactic, tactic_mappings, report.behaviors)
        hypotheses.append(h)
        logger.info(
            "  [%s] %d technique(s) → hypothesis huntable=%s",
            tactic, len(tactic_mappings), h.huntable,
        )

    huntable_count = sum(1 for h in hypotheses if h.huntable)
    logger.info(
        "Hunt generation: %d tactic(s) → %d hypotheses (%d huntable) for '%s'",
        len(by_tactic), len(hypotheses), huntable_count,
        report.article.rss_article.title[:50],
    )

    report.hunt_hypotheses = hypotheses
    return report


def generate_all_hypotheses(reports: list[CTIReport]) -> list[CTIReport]:
    return [generate_hypotheses(r) for r in reports]
