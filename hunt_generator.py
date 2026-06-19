"""
CTI Pipeline – Stage C: Threat Hunt Hypothesis Generation
One hypothesis per tactic — all techniques and behaviors under that tactic
are consolidated into a single, richer hunting hypothesis.

THREAT-ACTOR-CENTRIC: Hypotheses describe what an attacker would do and why.
Tactics covered (MITRE ATT&CK v15+):
  - Reconnaissance, Resource Development, Initial Access, Execution, Persistence
  - Privilege Escalation, Stealth, Defense Impairment, Credential Access
  - Discovery, Lateral Movement, Collection, Command and Control
  - Exfiltration, Impact

Example:
  Tactic: Execution
    T1059.001 — PowerShell used to download payload
    T1059.003 — cmd.exe spawned by Word macro
    T1204.002 — User opened malicious attachment
  → ONE hypothesis: "If a threat actor has compromised a system, they may use 
    PowerShell and command-line execution to execute malicious code or commands. 
    Observable indicators include payloads and macro spawning. This aligns with 
    ATT&CK technique(s): T1059.001, T1059.003, T1204.002."
"""
from __future__ import annotations
from collections import defaultdict

from models import (
    ATTACKMapping, CTIReport, DataSource,
    HuntHypothesis, RawBehavior, ConfidenceLevel,
)



# ── Lookup tables ─────────────────────────────────────────────────────────────

_TACTIC_SOURCES: dict[str, list[DataSource]] = {
    "Reconnaissance":       [DataSource.PROXY_LOGS, DataSource.FIREWALL_LOGS, DataSource.DNS_LOGS],
    "Resource Development": [DataSource.PROXY_LOGS, DataSource.DNS_LOGS, DataSource.FIREWALL_LOGS],
    "Initial Access":       [DataSource.EMAIL_GATEWAY, DataSource.FIREWALL_LOGS, DataSource.PROXY_LOGS],
    "Execution":            [DataSource.SYSMON, DataSource.EDR, DataSource.WINDOWS_EVENT_LOGS],
    "Persistence":          [DataSource.SYSMON, DataSource.WINDOWS_EVENT_LOGS, DataSource.EDR],
    "Privilege Escalation": [DataSource.WINDOWS_EVENT_LOGS, DataSource.EDR, DataSource.SYSMON],
    "Stealth":              [DataSource.EDR, DataSource.SYSMON, DataSource.WINDOWS_EVENT_LOGS],
    "Defense Impairment":   [DataSource.EDR, DataSource.WINDOWS_EVENT_LOGS, DataSource.SYSMON],
    "Credential Access":    [DataSource.WINDOWS_EVENT_LOGS, DataSource.EDR, DataSource.SYSMON],
    "Discovery":            [DataSource.SYSMON, DataSource.WINDOWS_EVENT_LOGS, DataSource.EDR],
    "Lateral Movement":     [DataSource.WINDOWS_EVENT_LOGS, DataSource.FIREWALL_LOGS, DataSource.EDR],
    "Collection":           [DataSource.EDR, DataSource.SYSMON, DataSource.PROCESS_LOGS],
    "Command and Control":  [DataSource.FIREWALL_LOGS, DataSource.DNS_LOGS, DataSource.PROXY_LOGS],
    "Exfiltration":         [DataSource.PROXY_LOGS, DataSource.FIREWALL_LOGS, DataSource.PCAP],
    "Impact":               [DataSource.EDR, DataSource.WINDOWS_EVENT_LOGS, DataSource.SYSMON],
}

_TACTIC_TELEMETRY: dict[str, list[str]] = {
    "Reconnaissance":       ["Proxy HTTP requests (footprinting)", "DNS queries to target infrastructure", "Network traffic analysis"],
    "Resource Development": ["C2 infrastructure registration logs", "Malware development artifacts", "Domain registration patterns"],
    "Initial Access":       ["Email gateway alerts", "Firewall inbound deny logs", "Web server logs (exploit attempts)"],
    "Execution":            ["Sysmon Event ID 1 (process create)", "Windows Event ID 4688", "EDR process execution events"],
    "Persistence":          ["Sysmon Event ID 13 (registry set)", "Windows Event ID 4698 (scheduled task)", "File modification events"],
    "Privilege Escalation": ["Windows Event ID 4672 (special logon)", "Windows Event ID 4673", "EDR privilege elevation events"],
    "Stealth":              ["Sysmon Event ID 7 (image load)", "Windows Event ID 4663 (object access)", "EDR evasion detection"],
    "Defense Impairment":   ["Windows Event ID 4720 (firewall changes)", "EDR tool disable events", "Log deletion patterns"],
    "Credential Access":    ["Windows Event ID 4624/4625 (logon)", "Sysmon Event ID 10 (process access)", "LSASS access events"],
    "Discovery":            ["Sysmon Event ID 1 (net/whoami/ipconfig)", "Windows Event ID 4688", "Registry query events"],
    "Lateral Movement":     ["Windows Event ID 4624 type 3 (network logon)", "Windows Event ID 4648", "Remote service usage"],
    "Collection":           ["Sysmon Event ID 11 (file create)", "EDR file access events", "Clipboard monitoring"],
    "Command and Control":  ["DNS query logs", "Proxy logs (unusual destinations/beaconing)", "Network flow analysis"],
    "Exfiltration":         ["Proxy POST volume anomalies", "Firewall large outbound transfers", "DNS tunneling patterns"],
    "Impact":               ["Windows Event ID 7045 (service install)", "EDR process termination events", "File encryption alerts"],
}

# Map tactic to threat actor intent/motivation
_TACTIC_INTENT: dict[str, str] = {
    "Reconnaissance":       "gather intelligence about the target organization and systems",
    "Resource Development": "acquire and develop tools, infrastructure, and capabilities for attack",
    "Initial Access":       "gain initial entry into the network",
    "Execution":            "execute malicious code or commands",
    "Persistence":          "maintain long-term access to the system",
    "Privilege Escalation": "escalate privileges to gain higher-level access",
    "Stealth":              "evade detection and remain undetected on the system",
    "Defense Impairment":   "disable or bypass security controls and defenses",
    "Credential Access":    "steal credentials and authentication tokens",
    "Discovery":            "discover system configuration and network topology",
    "Lateral Movement":     "move laterally across the network",
    "Collection":           "collect sensitive data and files",
    "Command and Control":  "establish a command and control channel",
    "Exfiltration":         "exfiltrate stolen data from the network",
    "Impact":               "disrupt or compromise system availability",
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




def _build_behavior_phrase(observed_behaviors: list[str]) -> str:
    """
    Combine observed behaviors into a readable phrase.
    Example: ["PowerShell used to download", "cmd.exe spawned"] -> 
             "PowerShell and command-line execution"
    """
    if not observed_behaviors:
        return "suspicious activity"
    
    # Take first behavior and make it a noun phrase
    behavior = observed_behaviors[0].lower()
    
    # Clean up common patterns
    if "recon" in behavior or "scan" in behavior or "enum" in behavior:
        return "reconnaissance activity"
    elif "powershell" in behavior:
        return "PowerShell execution"
    elif "cmd" in behavior or "command" in behavior:
        return "command-line execution"
    elif "process" in behavior:
        return "process execution"
    elif "registry" in behavior:
        return "registry modification"
    elif "file" in behavior:
        return "file operations"
    elif "network" in behavior or "communication" in behavior:
        return "network communication"
    elif "credential" in behavior or "password" in behavior:
        return "credential theft"
    elif "encryption" in behavior:
        return "file encryption"
    elif "disable" in behavior or "bypass" in behavior or "firewall" in behavior:
        return "security control bypass"
    elif "evad" in behavior or "hide" in behavior:
        return "evasion technique"
    elif "infra" in behavior or "domain" in behavior or "c2" in behavior:
        return "infrastructure development"
    else:
        # Fallback: use first 50 chars
        return behavior[:50]


# ── Core builder ──────────────────────────────────────────────────────────────

def _build_tactic_hypothesis(
    tactic:    str,
    mappings:  list[ATTACKMapping],   # all mappings for this tactic
    behaviors: list[RawBehavior],     # all raw behaviors from the article
) -> HuntHypothesis:
    """
    Build ONE hypothesis that covers all techniques observed under a tactic.
    Hypothesis is threat-actor-centric: explains what an attacker would do and why.
    """
    # Sort mappings by similarity score descending — best match leads

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

    # ── Threat-Actor-Centric Hypothesis Statement ─────────────────────────────
    # Build behavior phrase from observed behaviors
    behavior_phrase = _build_behavior_phrase(observed)
    
    # Get threat actor intent for this tactic
    intent = _TACTIC_INTENT.get(tactic, f"conduct {tactic.lower()} activities")
    
    # Build narrative hypothesis
    hypothesis = (
        f"If a threat actor has compromised a system, they may use {behavior_phrase} to {intent}. "
    )
    
    # Add indicators from artifacts
    if unique_artifacts:
        artifact_str = ", ".join(unique_artifacts[:3])
        if len(unique_artifacts) > 3:
            artifact_str += f", and {len(unique_artifacts) - 3} more"
        hypothesis += f"Observable indicators include: {artifact_str}. "
    
    # Add technique reference
    tech_str = ", ".join(technique_ids[:3])
    if len(technique_ids) > 3:
        tech_str += f", and {len(technique_ids) - 3} more"
    hypothesis += f"This aligns with ATT&CK technique(s): {tech_str}."

    # ── Evidence ──────────────────────────────────────────────────────────────
    evidence = " | ".join(evidence_parts[:3]) if evidence_parts else " | ".join(observed[:2])
    # ── Sigma stub (best technique in this tactic) ────────────────────────────
    detection_query = _best_sigma(technique_ids)

    return HuntHypothesis(
        hypothesis          = hypothesis,
        evidence            = evidence,
        mitre_techniques    = technique_ids,
        data_sources        = data_sources,
        required_telemetry  = telemetry[:6],
        detection_query     = detection_query,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def generate_hypotheses(report: CTIReport) -> CTIReport:
    """
    Stage C: one hypothesis per tactic, consolidating all techniques
    and behaviors observed under that tactic.
    
    THREAT-ACTOR-CENTRIC: Each hypothesis describes what an attacker would do
    and why, making it more intuitive for threat hunters.
    """
    if not report.attack_mappings:
    
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

    report.hunt_hypotheses = hypotheses
    return report


def generate_all_hypotheses(reports: list[CTIReport]) -> list[CTIReport]:
    return [generate_hypotheses(r) for r in reports]