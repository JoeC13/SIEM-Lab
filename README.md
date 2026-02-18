# SIEM Lab: Malicious Email Attachment Investigation

## 🎯 Objective
Investigate a real-world-style SIEM alert triggered by a **malicious attachment** delivered via email, walk through the detection, analysis, containment, and reporting process as a Security Analyst / SOC investigator.

This lab demonstrates a typical phishing → malware delivery → initial access chain commonly seen in enterprise environments.

## 🛠️ Scenario

**Alert received in SIEM:**
- Rule name: `Suspicious Malicious Attachment Detected - Known MalDoc Patterns`
- Severity: High
- Timestamp: 2025-11-12 09:47:22 UTC
- Email sender: spoofed internal-looking domain (procurement@internal-corp[.]co → actually external)
- Subject: `Urgent: Updated Vendor Payment Instructions – Action Required`
- Attachment: `PAYMENT_2025_11_INVOICE_478293.docm` (detected by EDR/Sandbox as malicious)
- Detection signatures: Office macro execution + suspicious network callback to 185.117.118[.]x / 91.149.239[.]x
- Affected user: finance-user-23@company.local

## 🔍 Investigation Steps Performed

1. Alert triage & validation
2. Email header & envelope analysis (SPF/DKIM/DMARC failure)
3. Attachment static analysis
   - File type verification (OLE compound file)
   - Macro code extraction & deobfuscation
4. Dynamic analysis / sandbox detonation (observables collected)
5. Network IOC hunting (DNS queries, HTTP requests, C2 patterns)
6. Endpoint forensics (process tree, parent-child relationships, file creation)
7. User activity timeline correlation
8. Containment & remediation actions taken
9. Root cause & lessons learned

## 📊 Key Findings

- Delivery vector: Spear-phishing email with weaponized Word document (.docm)
- Initial execution: VBA macro → PowerShell stager → shellcode injection
- C2 communication: HTTPS to dynamic resolution domains via DGA-like pattern
- Payload: Information stealer + secondary downloader (most likely AsyncRAT / AgentTesla variant family)
- Scope: Single user compromise (no lateral movement observed in this case)

## 🧰 Tools & Platforms Used

| Category            | Tools / Platforms used                                 |
|---------------------|--------------------------------------------------------|
| SIEM                | Splunk / Microsoft Sentinel / Elastic SIEM             |
| Email analysis      | MX Toolbox, MessageHeader Analyzer, VirusTotal        |
| Document analysis   | olevba, officeparser, ViperMonkey, olevba + manual review |
| Sandbox             | Hybrid Analysis, Any.Run, Triage, Joe Sandbox          |
| Network analysis    | Wireshark, Zeek logs, DNS logs, Suricata               |
| Endpoint visibility | CrowdStrike Falcon, Microsoft Defender for Endpoint, Carbon Black |
| IOC hunting         | VirusTotal Intelligence, GreyNoise, AbuseIPDB, OTX     |

## 📁 Repository Contents
