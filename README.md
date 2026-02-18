# SIEM Lab: Malicious Email Attachment Investigation

## Objective
Investigate a real-world-style SIEM alert triggered by a **malicious attachment** delivered via email, walk through the detection, analysis, containment, and reporting process as a Security Analyst / SOC investigator.

This lab demonstrates a typical phishing → malware delivery → initial access chain commonly seen in enterprise environments.

## 🛠️ Scenario

**Alert received in SIEM:**
- Rule name: `SOC114 - Malicious Attachment Detected - Phishing ALert`
- Severity: High
- Event Time: 2021-01-31 15:48:22 UTC
- Email sender: spoofed internal-looking domain accounting@cmail.carleton.ca
- - Subject: `Urgent: Updated Vendor Payment Instructions – Action Required`
- Attachment: `https://download.cyberlearn.academy/download/download?url=https://files-ld.s3.us-east-2.amazonaws.com/c9ad9506bcccfaa987ff9fc11b91698d.zip` (detected by EDR/Sandbox as malicious)
- Affected user: richard@letsdefend.io
