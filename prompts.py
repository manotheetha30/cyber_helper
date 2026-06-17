"""
CTI Pipeline – LLM Prompt Templates

DESIGN PRINCIPLE:
  The LLM does ONE job: read article content and extract raw observable facts.
  It does NOT map to ATT&CK. It does NOT generate hunt hypotheses. It does NOT
  score huntability. All of that happens in separate deterministic stages.

  This keeps the prompt short, the output schema tiny, and the model fast.
"""

SYSTEM_PROMPT = """\
You are a Cyber Threat Intelligence analyst. Your only job is to read a \
cybersecurity article and extract raw observable facts into JSON.

Rules:
- Extract ONLY what is explicitly stated in the article and don't repeatedly extract the same behavior which may be mentioned more than once.
- Never invent actors, malware, IOCs, or behaviors.
- IOCs are IP addresses, file hashes, domain names,urls,malware names,mac addresses, host addresses,etc.
- For behaviors: extract atomic adversary ACTIONS, not outcomes.
  GOOD: "PowerShell used to download payload", "Registry Run key modified"
  BAD:  "Attackers compromised systems", "Malware infected devices"
- If a field has no data, use an empty array [].
- Output ONLY valid JSON. No markdown, no explanation."""


# One focused prompt — just the article content and a minimal schema.
# The {content} placeholder is the ONLY variable; metadata is added as a
# two-line header so the model has context without bloating the schema.
EXTRACTION_PROMPT = """\
Article: {title}
Source:  {source} | {published_date}

{content}

---
Extract and return ONLY this JSON (no other text):

{{
  "executive_summary": "<2-3 sentences summarising the incident, threat actors, malware, and behaviors>",

  "threat_actors": [
    {{"name": "", "aliases": [], "motivation": "", "confidence": "High|Medium|Low", "evidence": ""}}
  ],

  "campaigns": [
    {{"name": "", "aliases": [], "description": "", "confidence": "High|Medium|Low", "evidence": ""}}
  ],

  "malware": [
    {{"name": "", "type": "Ransomware|Infostealer|Backdoor|Loader|RAT|Wiper|Dropper|Botnet|Rootkit|Unknown", "description": "", "confidence": "High|Medium|Low"}}
  ],

  "iocs": [
    {{"value": "", "ioc_type": "IP Address|Domain|Malware Name|URL|Email|MD5|SHA1|SHA256|SHA512|Filename|Registry Key|CVE", "context": "", "confidence": "High|Medium|Low"}}
  ],

  "behaviors": [
    {{
      "behavior": "<one sentence: what the attacker did>",
      "category": "Initial Access|Reconnaissance|Resource Development|Execution|Persistence|Privilege Escalation|Stealth|Defense Impairment|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact|Unknown",
      "evidence": "<direct quote or close paraphrase from article>",
      "artifacts": ["<filename>", "<command>", "<registry key>", "..."],
      "confidence": "High|Medium|Low"
    }}
  ]
}}"""
