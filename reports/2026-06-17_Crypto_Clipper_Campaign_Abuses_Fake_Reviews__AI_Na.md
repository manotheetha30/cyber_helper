# CTI Report: Crypto Clipper Campaign Abuses Fake Reviews, AI Narrators, and VirusTotal Comments

| Field | Value |
| --- | --- |
| Source | The Hacker News |
| Published | 2026-06-17 18:14 UTC |
| URL | [https://thehackernews.com/2026/06/crypto-clipper-campaign-abuses-fake.html](https://thehackernews.com/2026/06/crypto-clipper-campaign-abuses-fake.html) |
| Report Generated | 2026-06-18 13:59 UTC |
| Model | qwen3:8b |
| LLM Processing Time | 216.7s |

---

## Executive Summary

An unknown threat actor launched the Crypto Clipper campaign, distributing a Rust-based cryptocurrency clipboard hijacker through fake reviews, AI narrators, and manipulated platforms like VirusTotal and SourceForge. The malware targets cryptocurrency users by stealing wallet addresses.

## Threat Actors

### Unknown Threat Actor
- **Aliases:** —
- **Motivation:** Targeting cryptocurrency users and gamblers for financial gain
- **Confidence:** High
- **Evidence:** Check Point Research identified the actor through their use of fake reviews, coordinated activity on VirusTotal, and promotion on multiple platforms.

## Campaigns

### Crypto Clipper Campaign
- **Aliases:** —
- **Confidence:** High
- **Description:** A campaign distributing a cryptocurrency clipboard hijacker through fake reputation building and cross-platform promotion.
- **Evidence:** Check Point Research detailed the campaign's use of fake reviews, AI narrators, and manipulated download counts on platforms like SourceForge.

## Malware

### Crypto Clipper (Infostealer)
- **Aliases:** —
- **Confidence:** High
- **Description:** A Rust-based malware targeting Windows and macOS systems that monitors the clipboard for cryptocurrency wallet addresses and replaces them with attacker-controlled addresses.

## Indicators of Compromise

| IOC Value | Type | Confidence | Context |
| --- | --- | --- | --- |
| sourceforge.net | Domain | High | Promotion of malware through a SourceForge project |
| github.com | Domain | High | Use of GitHub accounts for cross-promotion |
| youtube.com | Domain | High | Promotion through a YouTube channel with over 91,000 subscribers |
| einpresswire.com | Domain | High | Use of press release distribution service for marketing |
| usatoday.com | Domain | High | Syndication of press release across USA TODAY Network |

## Observed Behaviors

**1. The threat actor used fake reviews and coordinated activity on VirusTotal to misclassify malicious files as safe.**
- Category: Reconnaissance  
- Evidence: _The threat actor operated a cluster of accounts on VirusTotal to misclassify malicious files as safe through upvotes and positive comments._
- Artifacts: `VirusTotal, fake reviews`

**2. The threat actor promoted malware through fake GitHub repositories with artificially inflated download counts.**
- Category: Resource Development  
- Evidence: _The threat actor operated at least six GitHub accounts to cross-promote and distribute their malware, with one repository having 146 stars and 62 forks._
- Artifacts: `GitHub, repository, stars, forks`

**3. The threat actor used a dedicated YouTube channel with AI-generated narrators and positive comments to promote the malware.**
- Category: Resource Development  
- Evidence: _The YouTube channel featured AI-generated narrators and positive comments to reinforce the illusion of popularity and trustworthiness._
- Artifacts: `YouTube, AI-generated narrators, positive comments`

**4. The threat actor used a press release distribution service to market their tool's capabilities.**
- Category: Resource Development  
- Evidence: _The threat actor used a press release distribution service like EIN Presswire to market their tool's purported capabilities._
- Artifacts: `EIN Presswire, press release`

**5. The malware continuously monitors the clipboard for cryptocurrency wallet address patterns and replaces them with attacker-controlled addresses.**
- Category: Exfiltration  
- Evidence: _The Rust-based clipper targets both Windows and macOS systems, and continuously monitors the clipboard for content that matches a cryptocurrency wallet address pattern. When a match is found, the malware substitutes the wallet address with an attacker-controlled address pulled from a hard-coded list._
- Artifacts: `clipboard monitoring, wallet address substitution, hard-coded list`

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior |
| --- | --- | --- | --- |
| Stealth | `T1036` | Masquerading | The threat actor used fake reviews and coordinated activity on VirusTo |
| Execution | `T1204.005` | User Execution: Malicious Library | The threat actor promoted malware through fake GitHub repositories wit |
| Resource Development | `T1683` | Generate Content | The threat actor used a dedicated YouTube channel with AI-generated na |
| Resource Development | `T1608` | Stage Capabilities | The threat actor used a press release distribution service to market t |
| Reconnaissance | `T1595.001` | Active Scanning: Scanning IP Blocks | The malware continuously monitors the clipboard for cryptocurrency wal |

## Threat Hunt Hypotheses

### Hypothesis 1
> If a threat actor has compromised a system, they may use file operations to evade detection and remain undetected on the system. Observable indicators include: VirusTotal, fake reviews. This aligns with ATT&CK technique(s): T1036.

**Evidence:** The threat actor operated a cluster of accounts on VirusTotal to misclassify malicious files as safe through upvotes and positive comments.
**Techniques:** `T1036`

**Data Sources:**
  - EDR
  - Sysmon
  - Windows Event Logs

**Required Telemetry:**
  - Search for artifact: VirusTotal
  - Search for artifact: fake reviews
  - Sysmon Event ID 7 (image load)
  - Windows Event ID 4663 (object access)
  - EDR evasion detection

### Hypothesis 2
> If a threat actor has compromised a system, they may use the threat actor promoted malware through fake git to execute malicious code or commands. Observable indicators include: GitHub, repository, stars, and 1 more. This aligns with ATT&CK technique(s): T1204.005.

**Evidence:** The threat actor operated at least six GitHub accounts to cross-promote and distribute their malware, with one repository having 146 stars and 62 forks.
**Techniques:** `T1204.005`

**Data Sources:**
  - Sysmon
  - EDR
  - Windows Event Logs

**Required Telemetry:**
  - Search for artifact: GitHub
  - Search for artifact: repository
  - Search for artifact: stars
  - Sysmon Event ID 1 (process create)
  - Windows Event ID 4688
  - EDR process execution events

### Hypothesis 3
> If a threat actor has compromised a system, they may use the threat actor used a dedicated youtube channel  to acquire and develop tools, infrastructure, and capabilities for attack. Observable indicators include: YouTube, AI-generated narrators, positive comments, and 2 more. This aligns with ATT&CK technique(s): T1683, T1608.

**Evidence:** The YouTube channel featured AI-generated narrators and positive comments to reinforce the illusion of popularity and trustworthiness. | The threat actor used a press release distribution service like EIN Presswire to market their tool's purported capabilities.
**Techniques:** `T1683`, `T1608`

**Data Sources:**
  - Proxy Logs
  - DNS Logs
  - Firewall Logs

**Required Telemetry:**
  - Search for artifact: YouTube
  - Search for artifact: AI-generated narrators
  - Search for artifact: positive comments
  - C2 infrastructure registration logs
  - Malware development artifacts
  - Domain registration patterns

### Hypothesis 4
> If a threat actor has compromised a system, they may use the malware continuously monitors the clipboard fo to gather intelligence about the target organization and systems. Observable indicators include: clipboard monitoring, wallet address substitution, hard-coded list. This aligns with ATT&CK technique(s): T1595.001.

**Evidence:** The Rust-based clipper targets both Windows and macOS systems, and continuously monitors the clipboard for content that matches a cryptocurrency wallet address pattern. When a match is found, the malware substitutes the wallet address with an attacker-controlled address pulled from a hard-coded list.
**Techniques:** `T1595.001`

**Data Sources:**
  - Proxy Logs
  - Firewall Logs
  - DNS Logs

**Required Telemetry:**
  - Search for artifact: clipboard monitoring
  - Search for artifact: wallet address substitution
  - Search for artifact: hard-coded list
  - Proxy HTTP requests (footprinting)
  - DNS queries to target infrastructure
  - Network traffic analysis

---
*Generated by CTI Pipeline | 2026-06-18 13:59 UTC*