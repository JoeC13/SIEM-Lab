# LetsDefend Phishing Lab - Internal to Internal Email Compromise

This repository documents a cybersecurity lab investigation from LetsDefend.io. The scenario involves detecting and investigating a **phishing email** sent internally from a dormant/compromised endpoint.

The key finding: Malicious SMTP activity originating from a workstation that had **no legitimate user logins for ~4 months**, indicating persistence and post-compromise abuse.

## Incident Overview

**Alert Rule:** SOC120 - Phishing Mail Detected - Internal to Internal  
**Event ID:** 52  
**Timestamp:** February 07, 2021, 04:24 AM  
**Email Details:**
- From: `john@letsdefend.io`
- To: `susie@letsdefend.io`
- Subject: `Meeting`
- Source IP: `172.16.17.82`
- Hostname: `JohnComputer`
- Device Action: Allowed

## Investigation Summary

### Red Flag Discovered
- Last legitimate user login to the endpoint (`JohnComputer`): **October 10, 2020 at 18:53**
- Malicious email sent: **February 07, 2021**
- **Gap:** ~4 months of inactivity followed by sudden outbound SMTP traffic

This timeline mismatch is a **classic indicator of compromise**:
- Dormant/stale workstation likely used for persistence
- Attacker abusing internal SMTP relay (port 25) for phishing, spam, or C2
- No recent user interaction required → suggests backdoor, scheduled task, rogue service, etc.

### Step-by-Step Investigation (as performed in lab)

1. **Email Security Review**  
   Queried SIEM / Email Security → confirmed internal email with suspicious rule match.
   
   <img src="https://i.imgur.com/ryM0fCz.png" />

3. **Log Management Check**  
   Traced source IP `172.16.17.82` in central logs → identified as origin of SMTP connection.

4. **Endpoint Security Lookup**  
   Queried EDR/Endpoint tool → Hostname: `JohnComputer`  
   Last login: October 10, 2020 → no activity since.

5. **Timeline Correlation**  
   Compared login history vs. email send time → **major anomaly detected**.

6. **Containment**  
   Isolated the endpoint to prevent further abuse.

7. **Disposition**  
   **True Positive** – Confirmed malicious activity from compromised dormant host.

## Indicators of Compromise (IoCs)

| Type              | Value                     | Notes                                      |
|-------------------|---------------------------|--------------------------------------------|
| IP Address        | 172.16.17.82             | Compromised workstation                    |
| Hostname          | JohnComputer             | Dormant since Oct 2020                     |
| Email Account     | john@letsdefend.io       | Spoofed / abused for internal phishing     |
| Behavioral        | SMTP outbound after 4-month dormancy | Strong persistence indicator               |
| Temporal Anomaly  | Activity Feb 2021 after last login Oct 2020 | Key detection pivot                        |

## Remediation & Lessons Learned

### Immediate Actions Taken/Recommended
- Endpoint containment & forensic preservation
- Credential reset for `john@letsdefend.io`
- Hunt for persistence artifacts (scheduled tasks, services, registry, WMI)
- Review internal SMTP relay logs for additional abuse
- Scan/reset credentials for other dormant accounts

### Key Takeaways
- Dormant endpoints are prime targets for persistence and lateral movement.
- Internal-to-internal phishing can bypass many external-focused defenses.
- Alert on SMTP from hosts with no recent logon events.
- Regular stale account/host cleanup is critical.


Feel free to fork, adapt, or use this as a template for your own blue-team lab write-ups.

Happy defending!
