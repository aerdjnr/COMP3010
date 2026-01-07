# BOTSv3 SOC Report

Unlisted YouTube video:()

## Contents

- [Introduction](#introduction)
- [Installation & Data Preparation](#installation--data-preparation)
- [SOC Roles](#soc-roles)
- [BOTSv3 Analysis](#botsv3-analysis)
  - [Q1](#Q1)
  - [Q2](#Q2)
  - [Q3](#Q3)
  - [Q4](#Q4)
  - [Q5](#Q5)
  - [Q6](#Q6)
  - [Q7](#Q7)
  - [Q8](#Q8)
- [Conclusion](#conclusion)
- [Appendix](#appendix)

---

## Introduction

This investigation is taken from the perspective of a Security Operations Centre (SOC) which is responsible for monitoring, detecting, and responding to threats across an organisations network architecture. It is an essential form of security revolved around visibility, leveraging assets and processes which aims to identify malicious activity, assess risk, and manage incident response in line with an organisation’s security objectives.

The report is structured around the **Boss of the SOC v3 (BOTSv3)** dataset, with references to the BOTSv3 questions to evaluate the simulated attack and provide possible solutions against further attempts.

### Objectives

- Assess the effectiveness of Splunk's SIEM capability against a simulated attack.
- Understand and map the attack using the BOTSv3 questions as a roadmap alongside the Cyber Kill Chain (CKC) methodology\[1\].
- Reflect on SOC processes, escalation paths, and strategic incident handling.

### Assumptions

- A single attack campaign is taking place.
- All logs are complete and untampered.
- Situational evidence may be used beyond direct BOTSv3 context clues.

---

## Installation & Data Preparation

Starting with the initial hardware, I went with a small form factor (SFF) computer with multi-core CPU, NVMe storage, and RAM – all of which was allocated to support sustained indexing and search workloads. 
As for the operating system, Proxmox VE was used to treat the Splunk instance as an isolated, quick-to-recover SOC analysis platform, allowing for improved environment reproducibility through snapshots – beneficial given the defined scope.

The Splunk instance was deployed in an Ubuntu Desktop VM due to the lower resource overhead with an OS such as Windows 10/11, but with a more efficient analyst interaction over a server-only OS (such as ubuntu server) due to the presence of a web-based management/search panel which is preferred for a single-user post-incident analysis.
Without the presence of a graphical environment, additional configuration would be present without improving analytical outcomes in this context. The Ubuntu version was cross referenced with official Splunk documentation to ensure compatibility.

As for the Splunk instance, Enterprise 10.0.2 (latest stable release available at the time of the report) was chosen to ensure SPL functionality and to align with modern SOC workflows. A standalone deployment method was selected due to the nature of the task, with index and search capabilities located on a single instance being best suited to the investigative focus; a distributed deployment would serve no additional purpose and only increase complexity and resource overhead. 
I deliberately limited the use of add-ons to preserve analytical clarity and reduce the risk of misinterpretation and instead derive evidence directly from SPL queries of the raw dataset. 

Collectively, these design choices focus on single-user post-incident analysis over likeness with an enterprise scale, live SOC environment. In such a setting, a distributed Splunk deployment would typically be used, with forwarders (with an OS such as Ubuntu Server) collecting and collating logs to centralised indexers, alongside granular role-based access control (such as by tier of SOC analyst, engineers, and admins).
Dedicated search heads would then provide the interface for which SOC analysts may conduct investigations via the Splunk web interface. In such a context, dashboards would be utilised for live monitoring, reporting, and communication – prioritising operational visibility and response coordination, which I do not need in this instance.


---

## SOC Roles

Throughout the BOTSv3 analysis, I will make references to SOC roles, and their processes/escalation procedures\[2\],\[3\]. The following is a breakdown of the main roles involved:

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

### Q1

**List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly’s AWS environment**

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

![Q1 Final Evidence Piece](Evidence/CourseworkQuestions/Q1_F200_4.png)
Identified IAM users:
- bstoll
- btun
- splunk_access
- web_admin

---

### Q2

**What field would you use to alert that AWS API activity has occurred without MFA (Multi-Factor Authentication)?**

```spl
index="botsv3" sourcetype="aws:cloudtrail"
```

```spl
index="botsv3" sourcetype="aws:cloudtrail"
| stats count BY eventType
```

```spl
index="botsv3" sourcetype="aws:cloudtrail" eventType="AwsApiCall"
```

![Q2 Final Evidence Piece](Evidence/CourseworkQuestions/Q2_F201_1.png)

Field used:
userIdentity.sessionContext.attributes.mfaAuthenticated



---

### Q3

**What is the processor number used on the web servers?**

```spl
index="botsv3" *amd* OR *intel*
| stats count BY sourcetype
```

```spl
index="botsv3" sourcetype="hardware"
```
![Q3 Final Evidence Piece](Evidence/CourseworkQuestions/Q3_F202_2.png)

CPU Type: 
E5-2676

---

### Q4

**Bud Accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access?**

```spl
index="botsv3" *bucket* 
| stats count BY sourcetype
```

```spl
index="botsv3" sourcetype="aws:cloudtrail" 
| stats count BY eventName
```

```spl
index="botsv3" sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
```
![Q4 Final Evidence Piece](Evidence/CourseworkQuestions/Q4_F203_4.png)

Event ID:
Ab45689d-69cd-41e7-8705-5350402cf7ac

---

### Q5

**What is Bud's username?**

From Q1, there were 2 users bstoll and btun, using the query

```spl
Index=“botsv3” bstoll
```
Yielded an smtp event containing a "receiver" field with both of their full names in:

![Q5 Final Evidence Piece](Evidence/CourseworkQuestions/Q5_F200_5.png)

Bud Stoll's username:
bstoll

---

### Q6

**What is the name of the S3 bucket that was made publicly accessible?**

```spl
index="botsv3" sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
```
Using the same query from Q4, we can see a subfield in "requestParameters" called bucketName:
![Q6 Evidence Piece](Evidence/CourseworkQuestions/Q6_F204_1.png)

Bucket name:
frothleywebcode

---

### Q7

**What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible?**

```spl
index="botsv3" sourcetype="*aws*” *bucket* 
| stats count BY sourcetype
```

```spl
Index=”botsv3” sourcetype=“aws:s3:accesslogs”
| reverse
```
After searching through the logs starting from the exact timestamp of the moment the bucket was made public, at 14:02:44PM, a PUT API request was made with the file name “OPEN_BUCKET_PLEASE_FIX.txt”

![Q7 Final Evidence Piece](Evidence/CourseworkQuestions/Q7_F205_2.png)

File name:
OPEN_BUCKET_PLEASE_FIX.txt

---

### Q8

**What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?**

```spl
index="botsv3" *window*
```

```spl
index=”botsv3” sourcetype=“WinHostMon”
```

```spl
index=”botsv3” sourcetype=“WinHostMon” source=”operatingsystem”
```

```spl
Index=”botsv3” sourcetype=”WinHostMon” source=”operatingsystem”
| stats count BY host OS
```

```spl
index=“botsv3” “bstoll-l”
```
The first result of the final query identified the FQDN within the "ComputerName"

![Q8 Evidence Piece](Evidence/CourseworkQuestions/Q8_F215_5.png)

FQDN:
BSTOLL-L.froth.ly

---

## Conclusion

Through this analysis of the BOTSv3 dataset, there is a collection of evidence that highlights several critical security weaknesses across both defensive and reactive controls.  A key finding was the approximately 56-minute delay in remediating the publicly exposed S3 bucket, which indicates flaws in Frothly’s reactive security posture. 

In a compliant, live SOC environment, an incident of this severity would be expected to trigger near-immediate alerting and response mechanisms, reducing the exposure window significantly, possibly preventing the upload of a .txt file from an unauthorised user which occurred approximately 2 minutes later.

However, the ability to collect and analyse a high level of enriched data following the incident demonstrates a degree of maturity in Frothly’s incident response and logging capabilities. These findings can be leveraged proactively to inform targeted vulnerability assessments and strengthen security controls moving forward. 

Specific improvements should focus on enhancing real-time alerting, reducing response times, stricter access controls, and the enforcement of MFA. By addressing these areas Frothly can improve its overall resilience and reduce the likelihood and impact of similar incidents in the future.

---

## Appendix

\[1\]	‘Cyber Kill Chain®’, Lockheed Martin. [Online]. Available: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

\[2\]	‘Security Operations Center (SOC) Roles and Responsibilities’, Palo Alto Networks. \[Online\]. Available: https://www.paloaltonetworks.com/cyberpedia/soc-roles-and-responsibilities

\[3\]	C. Kidd, ‘What Is a SOC? Security Operations Centers: A Complete Overview’, Splunk. \[Online\]. Available: https://www.splunk.com/en_us/blog/learn/soc-security-operation-center.html

