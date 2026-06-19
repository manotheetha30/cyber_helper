# CTI Report: ShapedPlugin update flow hacked to infect WordPress sites

| Field | Value |
| --- | --- |
| Source | BleepingComputer |
| Published | 2026-06-18 12:55 UTC |
| URL | [https://www.bleepingcomputer.com/news/security/shapedplugin-update-flow-hacked-to-infect-wordpress-sites/](https://www.bleepingcomputer.com/news/security/shapedplugin-update-flow-hacked-to-infect-wordpress-sites/) |
| Report Generated | 2026-06-19 07:53 UTC |
| Model | qwen3:8b |
| LLM Processing Time | 470.89s |

---

## Executive Summary

ShapedPlugin's supply chain was compromised, distributing a backdoor via infected plugin updates. The malware steals credentials, grants remote file-writing access, and impersonates WooCommerce components. The breach affected three paid plugins and was confirmed by Wordfence analysis.

## Threat Actors

_None identified._

## Campaigns

### ShapedPlugin Supply Chain Compromise
- **Aliases:** —
- **Confidence:** High
- **Description:** Attackers injected a backdoor into ShapedPlugin's Pro builds via the build pipeline, distributing malicious updates to customers.
- **Evidence:** Wordfence analysis confirmed file modifications, timestamp patterns, and Git build references in infected packages.

## Malware

### LicenseLoader.php (Backdoor)
- **Aliases:** —
- **Confidence:** High
- **Description:** Malicious loader file that activates via WordPress admin panel, contacts C2 server, downloads second-stage backdoor, and installs fake plugins.

## Indicators of Compromise

| IOC Value | Type | Confidence | Context |
| --- | --- | --- | --- |
| Product Slider Pro <3.5.4 | Filename | High | Affected plugin version |
| Real Testimonials Pro 3.2.5 | Filename | High | Affected plugin version |
| Smart Post Show Pro <4.0.2 | Filename | High | Affected plugin version |
| CVE-2026-10735 | CVE | High | Assigned CVE for the incident |
| CVE-2026-49777 | CVE | High | Duplicate CVE submitted for the incident |
| LicenseLoader.php | Filename | High | Malicious loader file |

## Observed Behaviors

**1. Malware activates via WordPress admin panel access**
- Category: Execution  
- Evidence: _The infected plugins contain a malicious loader file (LicenseLoader.php) that activates when a WordPress administrator accesses the website’s admin panel._
- Artifacts: `LicenseLoader.php`

**2. Establishes command-and-control communication**
- Category: Command and Control  
- Evidence: _The loader contacts the command-and-control (C2) server, downloads the second-stage (backdoor), and reports to the attacker._
- Artifacts: `C2 server`

**3. Installs fake plugins to impersonate WooCommerce components**
- Category: Persistence  
- Evidence: _The loader installs the backdoor as a fake plugin (woocommerce-subscription or woocommerce-notification)._
- Artifacts: `woocommerce-subscription, woocommerce-notification`

**4. Steals WordPress credentials and sensitive data**
- Category: Credential Access  
- Evidence: _The fake plugin attempts to steal WordPress login credentials, 2FA secrets, database credentials, and SMTP/email service credentials._
- Artifacts: `wp-config.php, SMTP/email service credentials`

**5. Exfiltrates WooCommerce order data**
- Category: Exfiltration  
- Evidence: _The fake plugin steals WooCommerce order data from the past three months, including payment method information._
- Artifacts: `WooCommerce order data`

**6. Self-deletes to erase evidence**
- Category: Stealth  
- Evidence: _The loader self-deletes after completing its operations to erase evidence._
- Artifacts: `—`

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior |
| --- | --- | --- | --- |
| Privilege Escalation | `T1546.003` | Event Triggered Execution: Windows Management Instrumentation Event Subscription | Malware activates via WordPress admin panel access |
| Command and Control | `T1102.003` | Web Service: One-Way Communication | Establishes command-and-control communication |
| Command and Control | `T1001.003` | Data Obfuscation: Protocol or Service Impersonation | Installs fake plugins to impersonate WooCommerce components |
| Credential Access | `T1110.004` | Brute Force: Credential Stuffing | Steals WordPress credentials and sensitive data |
| Collection | `T1560` | Archive Collected Data | Exfiltrates WooCommerce order data |
| Stealth | `T1070.009` | Indicator Removal: Clear Persistence | Self-deletes to erase evidence |

## Threat Hunt Hypotheses

### Hypothesis 1
> If a threat actor has compromised a system, they may use malware activates via wordpress admin panel access to escalate privileges to gain higher-level access. Observable indicators include: LicenseLoader.php. This aligns with ATT&CK technique(s): T1546.003.

**Evidence:** The infected plugins contain a malicious loader file (LicenseLoader.php) that activates when a WordPress administrator accesses the website’s admin panel.
**Techniques:** `T1546.003`

**Data Sources:**
  - Windows Event Logs
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for artifact: LicenseLoader.php
  - Windows Event ID 4672 (special logon)
  - Windows Event ID 4673
  - EDR privilege elevation events

### Hypothesis 2
> If a threat actor has compromised a system, they may use command-line execution to establish a command and control channel. Observable indicators include: C2 server, woocommerce-subscription, woocommerce-notification. This aligns with ATT&CK technique(s): T1102.003, T1001.003.

**Evidence:** The loader contacts the command-and-control (C2) server, downloads the second-stage (backdoor), and reports to the attacker. | The loader installs the backdoor as a fake plugin (woocommerce-subscription or woocommerce-notification).
**Techniques:** `T1102.003`, `T1001.003`

**Data Sources:**
  - Firewall Logs
  - DNS Logs
  - Proxy Logs

**Required Telemetry:**
  - Search for artifact: C2 server
  - Search for artifact: woocommerce-subscription
  - Search for artifact: woocommerce-notification
  - DNS query logs
  - Proxy logs (unusual destinations/beaconing)
  - Network flow analysis

### Hypothesis 3
> If a threat actor has compromised a system, they may use credential theft to steal credentials and authentication tokens. Observable indicators include: wp-config.php, SMTP/email service credentials. This aligns with ATT&CK technique(s): T1110.004.

**Evidence:** The fake plugin attempts to steal WordPress login credentials, 2FA secrets, database credentials, and SMTP/email service credentials.
**Techniques:** `T1110.004`

**Data Sources:**
  - Windows Event Logs
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for artifact: wp-config.php
  - Search for artifact: SMTP/email service credentials
  - Windows Event ID 4624/4625 (logon)
  - Sysmon Event ID 10 (process access)
  - LSASS access events

### Hypothesis 4
> If a threat actor has compromised a system, they may use exfiltrates woocommerce order data to collect sensitive data and files. Observable indicators include: WooCommerce order data. This aligns with ATT&CK technique(s): T1560.

**Evidence:** The fake plugin steals WooCommerce order data from the past three months, including payment method information.
**Techniques:** `T1560`

**Data Sources:**
  - EDR
  - Sysmon
  - Process Execution Logs

**Required Telemetry:**
  - Search for artifact: WooCommerce order data
  - Sysmon Event ID 11 (file create)
  - EDR file access events
  - Clipboard monitoring

### Hypothesis 5
> If a threat actor has compromised a system, they may use self-deletes to erase evidence to evade detection and remain undetected on the system. This aligns with ATT&CK technique(s): T1070.009.

**Evidence:** The loader self-deletes after completing its operations to erase evidence.
**Techniques:** `T1070.009`

**Data Sources:**
  - EDR
  - Sysmon
  - Windows Event Logs

**Required Telemetry:**
  - Sysmon Event ID 7 (image load)
  - Windows Event ID 4663 (object access)
  - EDR evasion detection

---
*Generated by CTI Pipeline | 2026-06-19 07:53 UTC*