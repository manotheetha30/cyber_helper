# CTI Report: FBI disrupts massive AI-powered phishing service using a million URLs

| Field | Value |
| --- | --- |
| Source | BleepingComputer |
| Published | 2026-06-14 14:36 UTC |
| URL | [https://www.bleepingcomputer.com/news/security/fbi-disrupts-massive-ai-powered-phishing-service-using-a-million-urls/](https://www.bleepingcomputer.com/news/security/fbi-disrupts-massive-ai-powered-phishing-service-using-a-million-urls/) |
| Report Generated | 2026-06-15 03:26 UTC |
| Model | qwen3:8b |
| LLM Processing Time | 193.86s |

---

## Executive Summary

The FBI, in collaboration with Google and Black Lotus Labs, dismantled a large-scale Chinese phishing-as-a-service operation called Outsider Enterprise, which used AI and distributed phishing kits to steal credit card data and passwords. The operation impacted hundreds of thousands of users globally and led to over 3.8 million credit card records being stolen, causing $1.9 billion in losses.

## Threat Actors

### Outsider Enterprise
- **Aliases:** —
- **Attribution:** Chinese-based
- **Motivation:** Financial gain through phishing scams
- **Confidence:** High
- **Evidence:** The FBI and Google attributed the operation to a Chinese-based threat actor.

## Campaigns

### Outsider Enterprise
- **Aliases:** —
- **Confidence:** High
- **Description:** A phishing-as-a-service operation that used AI and distributed phishing kits to impersonate trusted brands via SMS messages sent through AT&T, T-Mobile, and Verizon.
- **Evidence:** The FBI and Google identified the operation as a large-scale phishing-as-a-service operation.

## Malware

_None identified._

## Indicators of Compromise

| IOC Value | Type | Confidence | Context |
| --- | --- | --- | --- |
| outsiderenterprise.com | Domain | High | Phishing service domain |
| usdt | URL | High | Seized cryptocurrency from payment wallets |
| Telegram bot | URL | High | Linked to phishing service infrastructure |
| Android users | URL | High | Targeted by phishing campaigns |

## Observed Behaviors

**1. Phishing kits were distributed to criminals to launch fake text campaigns impersonating trusted brands.**
- Category: Initial Access  |  Confidence: High
- Evidence: _The cybercrime operation used AI and distributed phishing kits for campaigns impersonating various trusted brands in texts sent through AT&T, T-Mobile, and Verizon._
- Artifacts: `phishing kits, SMS messages, Telegram bot`

**2. Phishing domains were redirected to an FBI splash page after being seized.**
- Category: Impact  |  Confidence: High
- Evidence: _Thousands of phishing domains that the threat actor registered at U.S. providers are now redirecting to an FBI splash page._
- Artifacts: `phishing domains, FBI splash page`

**3. The FBI and partners seized administration servers, a Shopify storefront, and a payment wallet account.**
- Category: Impact  |  Confidence: High
- Evidence: _During the technical takedown, the FBI and partners seized multiple administration servers, a Shopify e-commerce storefront, and an account the threat actor used to test the phishing service._
- Artifacts: `administration servers, Shopify storefront, payment wallet account`

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior | Confidence | Similarity |
| --- | --- | --- | --- | --- | --- |
| Initial Access | `T1566` | Phishing | Phishing kits were distributed to criminals to launch fake text campai | Medium | 0.63 |
| Reconnaissance | `T1598` | Phishing for Information | Phishing kits were distributed to criminals to launch fake text campai | Medium | 0.61 |
| Reconnaissance | `T1598.003` | Spearphishing Link | Phishing kits were distributed to criminals to launch fake text campai | Medium | 0.58 |
| Resource Development | `T1583.001` | Domains | Phishing domains were redirected to an FBI splash page after being sei | Medium | 0.51 |
| Reconnaissance | `T1593` | Search Open Websites/Domains | Phishing domains were redirected to an FBI splash page after being sei | Medium | 0.51 |
| Impact | `T1657` | Financial Theft | The FBI and partners seized administration servers, a Shopify storefro | Low | 0.50 |
| Initial Access | `T1195` | Supply Chain Compromise | The FBI and partners seized administration servers, a Shopify storefro | Low | 0.45 |
| Reconnaissance | `T1589.001` | Credentials | The FBI and partners seized administration servers, a Shopify storefro | Low | 0.45 |

## Threat Hunt Hypotheses

### Hypothesis 1 — ✅ Huntable
> Adversaries may be using Phishing (T1566) in the environment. Evidence: Phishing kits were distributed to criminals to launch fake text campaigns impersonating trusted brands.. Look for artifacts: phishing kits, SMS messages, Telegram bot.

**Evidence:** The cybercrime operation used AI and distributed phishing kits for campaigns impersonating various trusted brands in texts sent through AT&T, T-Mobile, and Verizon.
**Techniques:** `T1566`
**Reason:** Observable artifacts exist and Email Gateway Logs telemetry is available for detection.

**Data Sources:**
  - Email Gateway Logs
  - Firewall Logs
  - Proxy Logs

**Required Telemetry:**
  - Search for: phishing kits
  - Search for: SMS messages
  - Search for: Telegram bot
  - Email gateway alerts
  - Firewall inbound deny logs

### Hypothesis 2 — ✅ Huntable
> Adversaries may be using Phishing for Information (T1598) in the environment. Evidence: Phishing kits were distributed to criminals to launch fake text campaigns impersonating trusted brands.. Look for artifacts: phishing kits, SMS messages, Telegram bot.

**Evidence:** The cybercrime operation used AI and distributed phishing kits for campaigns impersonating various trusted brands in texts sent through AT&T, T-Mobile, and Verizon.
**Techniques:** `T1598`
**Reason:** Observable artifacts exist and EDR telemetry is available for detection.

**Data Sources:**
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for: phishing kits
  - Search for: SMS messages
  - Search for: Telegram bot
  - EDR process events
  - System logs

### Hypothesis 3 — ✅ Huntable
> Adversaries may be using Spearphishing Link (T1598.003) in the environment. Evidence: Phishing kits were distributed to criminals to launch fake text campaigns impersonating trusted brands.. Look for artifacts: phishing kits, SMS messages, Telegram bot.

**Evidence:** The cybercrime operation used AI and distributed phishing kits for campaigns impersonating various trusted brands in texts sent through AT&T, T-Mobile, and Verizon.
**Techniques:** `T1598.003`
**Reason:** Observable artifacts exist and EDR telemetry is available for detection.

**Data Sources:**
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for: phishing kits
  - Search for: SMS messages
  - Search for: Telegram bot
  - EDR process events
  - System logs

### Hypothesis 4 — ✅ Huntable
> Adversaries may be using Domains (T1583.001) in the environment. Evidence: Phishing domains were redirected to an FBI splash page after being seized.. Look for artifacts: phishing domains, FBI splash page.

**Evidence:** Thousands of phishing domains that the threat actor registered at U.S. providers are now redirecting to an FBI splash page.
**Techniques:** `T1583.001`
**Reason:** Observable artifacts exist and EDR telemetry is available for detection.

**Data Sources:**
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for: phishing domains
  - Search for: FBI splash page
  - EDR process events
  - System logs

### Hypothesis 5 — ✅ Huntable
> Adversaries may be using Search Open Websites/Domains (T1593) in the environment. Evidence: Phishing domains were redirected to an FBI splash page after being seized.. Look for artifacts: phishing domains, FBI splash page.

**Evidence:** Thousands of phishing domains that the threat actor registered at U.S. providers are now redirecting to an FBI splash page.
**Techniques:** `T1593`
**Reason:** Observable artifacts exist and EDR telemetry is available for detection.

**Data Sources:**
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for: phishing domains
  - Search for: FBI splash page
  - EDR process events
  - System logs

### Hypothesis 6 — ⚠️ Needs Validation
> Adversaries may be using Financial Theft (T1657) in the environment. Evidence: The FBI and partners seized administration servers, a Shopify storefront, and a payment wallet account.. Look for artifacts: administration servers, Shopify storefront, payment wallet account.

**Evidence:** During the technical takedown, the FBI and partners seized multiple administration servers, a Shopify e-commerce storefront, and an account the threat actor used to test the phishing service.
**Techniques:** `T1657`
**Reason:** Low similarity score — ATT&CK mapping needs analyst validation before operationalising as a hunt.

**Data Sources:**
  - EDR
  - Windows Event Logs
  - Sysmon

**Required Telemetry:**
  - Search for: administration servers
  - Search for: Shopify storefront
  - Search for: payment wallet account
  - Windows Event ID 7045 (service install)
  - EDR process termination events

### Hypothesis 7 — ⚠️ Needs Validation
> Adversaries may be using Supply Chain Compromise (T1195) in the environment. Evidence: The FBI and partners seized administration servers, a Shopify storefront, and a payment wallet account.. Look for artifacts: administration servers, Shopify storefront, payment wallet account.

**Evidence:** During the technical takedown, the FBI and partners seized multiple administration servers, a Shopify e-commerce storefront, and an account the threat actor used to test the phishing service.
**Techniques:** `T1195`
**Reason:** Low similarity score — ATT&CK mapping needs analyst validation before operationalising as a hunt.

**Data Sources:**
  - Email Gateway Logs
  - Firewall Logs
  - Proxy Logs

**Required Telemetry:**
  - Search for: administration servers
  - Search for: Shopify storefront
  - Search for: payment wallet account
  - Email gateway alerts
  - Firewall inbound deny logs

### Hypothesis 8 — ⚠️ Needs Validation
> Adversaries may be using Credentials (T1589.001) in the environment. Evidence: The FBI and partners seized administration servers, a Shopify storefront, and a payment wallet account.. Look for artifacts: administration servers, Shopify storefront, payment wallet account.

**Evidence:** During the technical takedown, the FBI and partners seized multiple administration servers, a Shopify e-commerce storefront, and an account the threat actor used to test the phishing service.
**Techniques:** `T1589.001`
**Reason:** Low similarity score — ATT&CK mapping needs analyst validation before operationalising as a hunt.

**Data Sources:**
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for: administration servers
  - Search for: Shopify storefront
  - Search for: payment wallet account
  - EDR process events
  - System logs

## Huntability Assessment

| Hypothesis (truncated) | Huntable | Technique(s) | Reason |
| --- | --- | --- | --- |
| Adversaries may be using Phishing (T1566) in the environment… | ✅ | T1566 | Observable artifacts exist and Email Gateway Logs telemetry is available for det |
| Adversaries may be using Phishing for Information (T1598) in… | ✅ | T1598 | Observable artifacts exist and EDR telemetry is available for detection. |
| Adversaries may be using Spearphishing Link (T1598.003) in t… | ✅ | T1598.003 | Observable artifacts exist and EDR telemetry is available for detection. |
| Adversaries may be using Domains (T1583.001) in the environm… | ✅ | T1583.001 | Observable artifacts exist and EDR telemetry is available for detection. |
| Adversaries may be using Search Open Websites/Domains (T1593… | ✅ | T1593 | Observable artifacts exist and EDR telemetry is available for detection. |
| Adversaries may be using Financial Theft (T1657) in the envi… | ⚠️ | T1657 | Low similarity score — ATT&CK mapping needs analyst validation before operationa |
| Adversaries may be using Supply Chain Compromise (T1195) in … | ⚠️ | T1195 | Low similarity score — ATT&CK mapping needs analyst validation before operationa |
| Adversaries may be using Credentials (T1589.001) in the envi… | ⚠️ | T1589.001 | Low similarity score — ATT&CK mapping needs analyst validation before operationa |

---
*Generated by CTI Pipeline | 2026-06-15 03:26 UTC*