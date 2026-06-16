# CTI Report: Google exposes China espionage group that’s been lurking in networks undetected since 2023

| Field | Value |
| --- | --- |
| Source | CyberScoop |
| Published | 2026-06-15 20:11 UTC |
| URL | [https://cyberscoop.com/google-unc6508-china-espionage-threat/](https://cyberscoop.com/google-unc6508-china-espionage-threat/) |
| Report Generated | 2026-06-16 13:39 UTC |
| Model | qwen3:8b |
| LLM Processing Time | 237.28s |

---

## Executive Summary

Google uncovered a Chinese state-sponsored espionage group, UNC6508, that has been operating stealthily in networks since 2023, targeting organizations in the U.S. and Canada. The group used a custom backdoor called INFINITERED to steal credentials and data from medical research institutions and other critical sectors.

## Threat Actors

### UNC6508
- **Aliases:** —
- **Attribution:** Chinese state-sponsored
- **Motivation:** Steal data with national security implications
- **Confidence:** High
- **Evidence:** Google Threat Intelligence Group confirmed the group's activities and attributed them to China's government.

## Campaigns

### UNC6508 Campaign
- **Aliases:** —
- **Confidence:** High
- **Description:** A long-term espionage campaign targeting medical research, government, and private organizations using a custom backdoor to steal credentials and data.
- **Evidence:** Google confirmed multiple victims compromised with INFINITERED, and the campaign has been active since September 2023.

## Malware

### INFINITERED (Backdoor)
- **Aliases:** —
- **Confidence:** High
- **Description:** A custom backdoor deployed by UNC6508 to steal administrative credentials after exploiting REDCap servers.

## Indicators of Compromise

| IOC Value | Type | Confidence | Context |
| --- | --- | --- | --- |
| REDCap | Domain | High | The threat group exploited externally facing REDCap servers to deploy the INFINITERED backdoor. |
| Gmail account | Email | High | The threat group used a Gmail account to exfiltrate data, which was disabled by Google. |

## Observed Behaviors

**1. The threat group exploited externally facing REDCap servers to deploy the INFINITERED backdoor.**
- Category: Initial Access  |  Confidence: High
- Evidence: _Google said it confirmed multiple victims compromised with INFINITERED, a custom backdoor the threat group deployed on targeted networks to steal administrative credentials after it exploited externally facing REDCap servers._
- Artifacts: `REDCap`

**2. The threat group used a custom backdoor to steal administrative credentials.**
- Category: Credential Access  |  Confidence: High
- Evidence: _Google said it confirmed multiple victims compromised with INFINITERED, a custom backdoor the threat group deployed on targeted networks to steal administrative credentials after it exploited externally facing REDCap servers._
- Artifacts: `INFINITERED`

**3. The threat group abused domain compliance rules to steal data without relying on malware or living-off-the-land tools.**
- Category: Collection  |  Confidence: High
- Evidence: _Researchers said the threat group abused domain compliance rules to steal data, a technique that doesn’t rely on malware or living-off-the-land tools, and routed traffic through U.S.-based IPs to blend in with legitimate traffic._
- Artifacts: `—`

**4. The threat group exfiltrated data using a Gmail account.**
- Category: Exfiltration  |  Confidence: High
- Evidence: _Google said it disrupted some of UNC6508’s known infrastructure by disabling a Gmail account it used to exfiltrate data._
- Artifacts: `Gmail account`

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior | Confidence | Similarity |
| --- | --- | --- | --- | --- | --- |
| Credential Access | `T1212` | Exploitation for Credential Access | The threat group used a custom backdoor to steal administrative creden | High | 0.81 |
| Credential Access | `T1589.001` | Credentials | The threat group used a custom backdoor to steal administrative creden | Medium | 0.79 |
| Credential Access | `T1003` | OS Credential Dumping | The threat group used a custom backdoor to steal administrative creden | Medium | 0.78 |
| Exfiltration | `T1586.002` | Email Accounts | The threat group exfiltrated data using a Gmail account. | Medium | 0.78 |
| Collection | `T1583.001` | Domains | The threat group abused domain compliance rules to steal data without  | Medium | 0.78 |
| Collection | `T1069.002` | Domain Groups | The threat group abused domain compliance rules to steal data without  | Medium | 0.77 |
| Exfiltration | `T1585.002` | Email Accounts | The threat group exfiltrated data using a Gmail account. | Medium | 0.77 |
| Collection | `T1590.001` | Domain Properties | The threat group abused domain compliance rules to steal data without  | Medium | 0.77 |
| Exfiltration | `T1087` | Account Discovery | The threat group exfiltrated data using a Gmail account. | Medium | 0.75 |
| Initial Access | `T1668` | Exclusive Control | The threat group exploited externally facing REDCap servers to deploy  | Medium | 0.73 |
| Initial Access | `T1108` | Redundant Access | The threat group exploited externally facing REDCap servers to deploy  | Medium | 0.72 |
| Initial Access | `T1525` | Implant Internal Image | The threat group exploited externally facing REDCap servers to deploy  | Medium | 0.72 |

## Threat Hunt Hypotheses

### Hypothesis 1 — ✅ Huntable
> Adversary activity consistent with the Credential Access tactic may be present. Observed techniques: T1212 (Exploitation for Credential Access), T1589.001 (Credentials), T1003 (OS Credential Dumping). Look for artifacts: INFINITERED.

**Evidence:** Google said it confirmed multiple victims compromised with INFINITERED, a custom backdoor the threat group deployed on targeted networks to steal administrative credentials after it exploited externally facing REDCap servers.
**Techniques:** `T1212`, `T1589.001`, `T1003`
**Reason:** 3 technique(s) mapped under Credential Access with High confidence; 1 observable artifact(s) identified.

**Data Sources:**
  - Windows Event Logs
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for artifact: INFINITERED
  - Windows Event ID 4624/4625 (logon)
  - Sysmon Event ID 10 (process access)

### Hypothesis 2 — ✅ Huntable
> Adversary activity consistent with the Exfiltration tactic may be present. Observed techniques: T1586.002 (Email Accounts), T1585.002 (Email Accounts), T1087 (Account Discovery). Look for artifacts: Gmail account.

**Evidence:** Google said it disrupted some of UNC6508’s known infrastructure by disabling a Gmail account it used to exfiltrate data.
**Techniques:** `T1586.002`, `T1585.002`, `T1087`
**Reason:** 3 technique(s) mapped under Exfiltration with Medium confidence; 1 observable artifact(s) identified.

**Data Sources:**
  - Proxy Logs
  - Firewall Logs
  - PCAP / Network Capture

**Required Telemetry:**
  - Search for artifact: Gmail account
  - Proxy POST volume anomalies
  - Firewall large outbound transfers

### Hypothesis 3 — ✅ Huntable
> Adversary activity consistent with the Collection tactic may be present. Observed techniques: T1583.001 (Domains), T1069.002 (Domain Groups), T1590.001 (Domain Properties). Observed behavior: The threat group abused domain compliance rules to steal data without relying on malware or living-o.

**Evidence:** Researchers said the threat group abused domain compliance rules to steal data, a technique that doesn’t rely on malware or living-off-the-land tools, and routed traffic through U.S.-based IPs to blend in with legitimate traffic.
**Techniques:** `T1583.001`, `T1069.002`, `T1590.001`
**Reason:** 3 technique(s) mapped under Collection with Medium confidence; no specific artifacts — hunt requires baseline tuning.

**Data Sources:**
  - EDR
  - Sysmon
  - Process Execution Logs

**Required Telemetry:**
  - Sysmon Event ID 11 (file create)
  - EDR file access events

### Hypothesis 4 — ✅ Huntable
> Adversary activity consistent with the Initial Access tactic may be present. Observed techniques: T1668 (Exclusive Control), T1108 (Redundant Access), T1525 (Implant Internal Image). Look for artifacts: REDCap.

**Evidence:** Google said it confirmed multiple victims compromised with INFINITERED, a custom backdoor the threat group deployed on targeted networks to steal administrative credentials after it exploited externally facing REDCap servers.
**Techniques:** `T1668`, `T1108`, `T1525`
**Reason:** 3 technique(s) mapped under Initial Access with Medium confidence; 1 observable artifact(s) identified.

**Data Sources:**
  - Email Gateway Logs
  - Firewall Logs
  - Proxy Logs

**Required Telemetry:**
  - Search for artifact: REDCap
  - Email gateway alerts
  - Firewall inbound deny logs

## Huntability Assessment

| Hypothesis (truncated) | Huntable | Technique(s) | Reason |
| --- | --- | --- | --- |
| Adversary activity consistent with the Credential Access tac… | ✅ | T1212, T1589.001, T1003 | 3 technique(s) mapped under Credential Access with High confidence; 1 observable |
| Adversary activity consistent with the Exfiltration tactic m… | ✅ | T1586.002, T1585.002, T1087 | 3 technique(s) mapped under Exfiltration with Medium confidence; 1 observable ar |
| Adversary activity consistent with the Collection tactic may… | ✅ | T1583.001, T1069.002, T1590.001 | 3 technique(s) mapped under Collection with Medium confidence; no specific artif |
| Adversary activity consistent with the Initial Access tactic… | ✅ | T1668, T1108, T1525 | 3 technique(s) mapped under Initial Access with Medium confidence; 1 observable  |

---
*Generated by CTI Pipeline | 2026-06-16 13:39 UTC*