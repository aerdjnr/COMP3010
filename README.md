# COMP3010 BOTSv3 Analysis



Note: The "Research" field is a separate investigation into the SPL of Splunk and some interesting data (which are out of the scope of this report)



Video Presentation: ()



#### Introduction



This investigation is taken from the perspective of a Security Operations Centre (SOC) which is responsible for monitoring, detecting, and responding to threats across an organisations network architecture. It is an essential form of security revolved around visibility, leveraging assets and processes which aims to identify malicious activity, assess risk, and manage incident response inline with an organisations security objectives.

The report is structured around the "Boss of the SOC v3" BOTSv3 dataset, with references to the BOTSv3 questions to evaluate the simulated attack and provide possible solutions against further attempts.



The primary objectives are as follows:

* Assess the effectiveness of Splunk's SIEM capability against a simulated attack
* Understand and map the attack using the BOTSv3 questions as a roadmap alongside the Cyber Kill Chain (CKC) methodology
* Reflect on SOC processes, escalation paths, and strategic incident handling, comparing available toolsets and providing recommended improvements for the SOC



Assumptions:

* There is a single attack campaign taking place, and that all evidence found is directly attributable to this campaign
* Analysis of logs occurs post-incident, all logs are complete, and have not been tampered with or altered.
* Where applicable, situational evidence may be incorporated to support the investigation using queries or techniques that aren't directly gained through context clues within the BOTSv3 questions



**200 - List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment.**



Initial query
```spl
index="botsv3" sourcetype="*aws*" *iam*
```
Identified sourcetype "aws:cloudtrail" as most common found, with a field labelled "userIdentity.type" tied to each event:

[200 Evidence Piece](Evidence/200Level/200SPL\_Refined.png)


**201 - What field would you use to alert that AWS API activity has occurred without MFA (Multi-Factor Authentication)?**


Initial query
```spl
index="botsv3" sourcetype="aws:cloudtrail" *MFA*
```

No immediate evidence, but scrubbing through an event showed the field
"userIdentity.sessionContext.attributes.mfaAuthenticated":

[201 Evidence Piece](Evidence/200Level/201_)

Through many variates of SPL(to ensure that syntax was not the reason for any missing values) there only seemed to be the value "false" which indicates that no MFA has been implemented. As a tier 2 SOC analyst, processes and escalations would be as follows:
* Identify the scope, which has already been performed (all IAM users do not have MFA implemented.
* Validate the data, if needed, cross referencing with other data to back up the claim
* Risk assessment, identifying that a lack of MFA is a security risk
* Escalate to tier 3 for policy enforcement
* Set an alert for future events of this manner

