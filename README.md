# malicious-email-attachment-analysis
SOC-style investigation of a malicious email with a weaponized document attachment, including header analysis, Microsoft Exchange infrastructure identification, attachment extraction, hash-based malware analysis, and VirusTotal threat intelligence correlation.

---

## Malicious Email Attachment Analysis (SOC Project)

## Overview

This project demonstrates a SOC-style investigation of a malicious email delivering a macro-enabled document attachment.  
The objective is to analyze the email headers, identify the sending infrastructure, extract and analyze the attachment, and determine whether the email should be released or blocked.

---

## Objectives

- Analyze email headers to identify sender identity and mail infrastructure
- Identify the email service provider using Received, DKIM, and IP ownership
- Extract and inspect malicious attachments using emldump
- Perform hash-based malware analysis
- Correlate findings with VirusTotal threat intelligence
- Make a final release or block decision from a SOC perspective

---

## Tools & Techniques

- Email header analysis
- Microsoft Exchange infrastructure identification
- emldump.py attachment extraction
- SHA-256 hash analysis
- VirusTotal threat intelligence
- Malware classification and verdict determination

---

## Email Header Analysis Summary

| Field | Value |
|------|------|
| Delivery Date | Tue, 14 May 2024 23:31:08 +0000 |
| Subject | You're Invited! |
| Recipient | emily.nguyen@glbllogistics.co |
| Sender Display Name | Adam Barry |
| Sender Email | abarry@live.com |
| Message-ID | SA1PR14MB737384979FDD1178FD956584C1E32@SA1PR14MB7373.namprd14.prod.outlook.com |

---

## Email Infrastructure Identification

**Identified Provider:** Microsoft (Exchange Online)

**Evidence supporting this conclusion:**
- `Received` headers reference `outbound.protection.outlook.com`
- DKIM signature domain (`d=live.com`) signed by Microsoft infrastructure
- IP / ASN ownership corresponds to Microsoft
- SPF validation confirms authorized sending infrastructure

**Conclusion:**  
The email was sent using **Microsoft Exchange Online**, confirmed through mail server hostnames, DKIM signing, and IP ownership analysis.

---

## Attachment Analysis

- **Attachment index (emldump):** 5
- **Filename:** `AR_Wedding_RSVP.docm`
- **File type:** Macro-enabled Word document
- **SHA-256 hash:**
41c3dd4e9f794d53c212398891931760de469321e4c5d04be719d5485ed8f53e

yaml
Copy code

---

## Malware Threat Intelligence

The attachment hash was submitted to VirusTotal for reputation analysis.

**VirusTotal Result:**
- **Popular threat label:** `downloader.autdwnlrner/w97m`

This classification indicates a malicious document capable of acting as a malware downloader.

---

## Indicators of Compromise (IOCs)

**Attachment Filename**
AR_Wedding_RSVP.docm

markdown
Copy code

**SHA-256 Hash**
41c3dd4e9f794d53c212398891931760de469321e4c5d04be719d5485ed8f53e

markdown
Copy code

**Sender Email**
abarry@live.com

yaml
Copy code

---

## Final Verdict

**Malicious – Email should NOT be released to the user's inbox.**

The presence of a macro-enabled document with a confirmed malware classification represents a high risk to the organization.

---

## Recommended SOC Actions

- Block the attachment hash at email and endpoint security layers
- Quarantine similar emails across the organization
- Monitor for execution indicators related to macro-enabled documents
- Add identified IOCs to SIEM and threat intelligence feeds
- Educate users on malicious document attachment risks

---

## Evidence Handling Note

The original malicious email file (.eml) was analyzed in a controlled lab environment.  
To prevent accidental execution of malicious content and protect sensitive data, the raw email file is not included in this repository.  
All relevant artifacts, screenshots, and supporting evidence are documented in the linked investigation issue.

---

## Disclaimer

This project was conducted in a controlled lab environment for educational and demonstration purposes only.
