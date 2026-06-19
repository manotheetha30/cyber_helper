"""
CTI Pipeline – Pydantic data models
Clean, minimal, strictly aligned with what the LLM actually returns.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    HIGH    = "High"
    MEDIUM  = "Medium"
    LOW     = "Low"
    UNKNOWN = "Unknown"


class MalwareType(str, Enum):
    RANSOMWARE  = "Ransomware"
    INFOSTEALER = "Infostealer"
    BACKDOOR    = "Backdoor"
    LOADER      = "Loader"
    RAT         = "RAT"
    WIPER       = "Wiper"
    DROPPER     = "Dropper"
    BOTNET      = "Botnet"
    ROOTKIT     = "Rootkit"
    UNKNOWN     = "Unknown"


class IOCType(str, Enum):
    IP       = "IP Address"
    DOMAIN   = "Domain"
    MALWARE  = "Malware Name"
    URL      = "URL"
    EMAIL    = "Email"
    MD5      = "MD5"
    SHA1     = "SHA1"
    SHA256   = "SHA256"
    SHA512   = "SHA512"
    FILENAME = "Filename"
    REGISTRY = "Registry Key"
    CVE      = "CVE"


class DataSource(str, Enum):
    WINDOWS_EVENT_LOGS = "Windows Event Logs"
    SYSMON             = "Sysmon"
    EDR                = "EDR"
    PROXY_LOGS         = "Proxy Logs"
    DNS_LOGS           = "DNS Logs"
    EMAIL_GATEWAY      = "Email Gateway Logs"
    FIREWALL_LOGS      = "Firewall Logs"
    PCAP               = "PCAP / Network Capture"
    CLOUD_TRAIL        = "AWS CloudTrail / Cloud Audit"
    PROCESS_LOGS       = "Process Execution Logs"


# ── Feed / Extraction ─────────────────────────────────────────────────────────

class RSSArticle(BaseModel):
    title:          str
    url:            str
    source:         str
    published_date: datetime
    author:         Optional[str] = None
    summary:        Optional[str] = None


class ExtractedArticle(BaseModel):
    rss_article:       RSSArticle
    full_text:         str
    extraction_method: str
    char_count:        int
    word_count:        int
    content_hash:      str
    extracted_at:      datetime = Field(default_factory=datetime.utcnow)


# ── LLM extraction outputs (Stage A) ─────────────────────────────────────────

class ThreatActor(BaseModel):
    name:        str
    aliases:     list[str]       = []
    motivation:  Optional[str]   = None
    confidence:  ConfidenceLevel = ConfidenceLevel.UNKNOWN
    evidence:    Optional[str]   = None


class Campaign(BaseModel):
    name:        str
    aliases:     list[str]       = []
    description: str             = ""
    confidence:  ConfidenceLevel = ConfidenceLevel.MEDIUM
    evidence:    str             = ""


class MalwareFamily(BaseModel):
    name:         str
    malware_type: MalwareType   = MalwareType.UNKNOWN
    aliases:      list[str]     = []
    description:  Optional[str] = None
    confidence:   ConfidenceLevel = ConfidenceLevel.UNKNOWN


class IOC(BaseModel):
    value:      str
    ioc_type:   IOCType
    context:    Optional[str]   = None
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM


class RawBehavior(BaseModel):
    """A single adversary behavior extracted by the LLM — no ATT&CK mapping yet."""
    behavior:  str                          # what the attacker did
    category:  str             = "Unknown"  # rough tactic hint
    evidence:  str                          # article quote/paraphrase
    artifacts: list[str]       = []         # observable items (filenames, cmds…)
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM


# ── ATT&CK mapping (Stage B — pure RAG, no LLM) ──────────────────────────────

class ATTACKMapping(BaseModel):
    tactic:            str
    technique_id:      str   # e.g. T1059.001
    technique_name:    str
    observed_behavior: str


# ── Hunt hypothesis (Stage C — deterministic) ────────────────────────────────

class HuntHypothesis(BaseModel):
    hypothesis:         str
    evidence:           str
    mitre_techniques:   list[str]       = []
    data_sources:       list[DataSource] = []
    required_telemetry: list[str]       = []
    detection_query:    Optional[str]   = None


# ── Final per-article report ──────────────────────────────────────────────────

class CTIReport(BaseModel):
    article:            ExtractedArticle
    executive_summary:  str                    = ""
    threat_actors:      list[ThreatActor]      = []
    campaigns:          list[Campaign]         = []
    malware:            list[MalwareFamily]    = []
    iocs:               list[IOC]              = []
    behaviors:          list[RawBehavior]      = []
    attack_mappings:    list[ATTACKMapping]    = []
    hunt_hypotheses:    list[HuntHypothesis]   = []
    model_used:         str                    = ""
    processing_time_s:  float                  = 0.0
    generated_at:       datetime = Field(default_factory=datetime.utcnow)
