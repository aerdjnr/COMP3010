# BOTSv3 SOC Report

## Contents

- [Introduction](#introduction)
- [Installation & Data Preparation](#installation--data-preparation)
- [SOC Roles](#soc-roles)
- [BOTSv3 Analysis](#botsv3-analysis)
  - [200](#200)
  - [201](#201)
  - [202](#202)
  - [203](#203)
  - [204](#204)
  - [205](#205)
  - [215](#215)
- [Conclusion](#conclusion)
- [Appendix](#appendix)

---

## Introduction

This investigation is taken from the perspective of a Security Operations Centre (SOC) which is responsible for monitoring, detecting, and responding to threats across an organisations network architecture. It is an essential form of security revolved around visibility, leveraging assets and processes which aims to identify malicious activity, assess risk, and manage incident response in line with an organisation’s security objectives.

The report is structured around the **Boss of the SOC v3 (BOTSv3)** dataset, with references to the BOTSv3 questions to evaluate the simulated attack and provide possible solutions against further attempts.

### Objectives

- Assess the effectiveness of Splunk's SIEM capability against a simulated attack.
- Understand and map the attack using the BOTSv3 questions as a roadmap alongside the Cyber Kill Chain (CKC) methodology.
- Reflect on SOC processes, escalation paths, and strategic incident handling.

### Assumptions

- A single attack campaign is taking place.
- All logs are complete and untampered.
- Situational evidence may be used beyond direct BOTSv3 context clues.

---

## Installation & Data Preparation

A small form factor (SFF) system with a multi-core CPU, NVMe storage, and sufficient RAM was used to support sustained indexing and search workloads. Proxmox VE was selected to host the Splunk instance as an isolated SOC analysis environment, enabling snapshot-based recovery and reproducibility.

Splunk was deployed on an Ubuntu Desktop VM to reduce overhead compared to Windows while still allowing efficient analyst interaction through a web-based interface. Ubuntu was cross-referenced with official Splunk compatibility documentation.

Splunk Enterprise **10.0.2** was selected to align with modern SOC workflows. A standalone deployment was used, as distributed components would add unnecessary complexity. Add-ons were intentionally limited to preserve analytical clarity and derive evidence directly from raw SPL queries.

---

## SOC Roles

### Tier 1 SOC Analyst

- Continuous log and alert monitoring
- Triage alerts and identify false positives
- Document events in ticketing systems
- Escalate verified threats to Tier 2

### Tier 2 SOC Analyst

- Deep investigation of escalated events
- Scope determination and threat intelligence analysis
- Lead containment and recovery efforts
- Escalate high-impact incidents to Tier 3

### Tier 3 SOC Analyst

- Handle major incidents
- Perform or oversee vulnerability assessments and penetration testing
- Recommend security tooling and monitoring improvements

---

## BOTSv3 Analysis

### 200

**List IAM users that accessed AWS services**

```spl
index="botsv3" sourcetype="*aws*" *iam*
```

```spl
index="botsv3" sourcetype="aws:cloudtrail" *iam*
```

```spl
index="botsv3" sourcetype="aws:cloudtrail"
| stats count BY userIdentity.type
```

```spl
index="botsv3" sourcetype="aws:cloudtrail" userIdentity.type="IAMUser"
| stats count BY userIdentity.userName
```

Identified IAM users:
- bstoll
- btun
- splunk_access
- web_admin

---

### 201

**Detect AWS API activity without MFA**

```spl
index="botsv3" sourcetype="aws:cloudtrail" *mfa*
```

```spl
index="botsv3" sourcetype="aws:cloudtrail"
| stats count BY eventType
```

```spl
index="botsv3" sourcetype="aws:cloudtrail" eventType="AwsApiCall"
```

Field used:
```
userIdentity.sessionContext.attributes.mfaAuthenticated
```

---

### 202

**Processor number used on web servers**

```spl
index="botsv3" *amd* OR *intel*
| stats count BY sourcetype
```

```spl
index="botsv3" sourcetype="hardware"
```

CPU Type: **E5-2676**

---

### 203

**Event ID enabling public S3 bucket access**

```spl
index="botsv3" sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
```

Event ID:
```
Ab45689d-69cd-41e7-8705-5350402cf7ac
```

---

### 204

**Public S3 bucket name**

Bucket name: **frothleywebcode**

---

### 205

**File uploaded while bucket was public**

File name: **OPEN_BUCKET_PLEASE_FIX.txt**

---

### 215

**FQDN of endpoint with different Windows edition**

FQDN: **BSTOLL-L.froth.ly**

---

## Conclusion

The BOTSv3 analysis revealed multiple security weaknesses, most notably a delay in remediating a publicly exposed S3 bucket. Improvements should focus on real-time alerting, faster response times, stricter access controls, and MFA enforcement.

---

## Appendix

Cyber Kill Chain®, Lockheed Martin  
https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
