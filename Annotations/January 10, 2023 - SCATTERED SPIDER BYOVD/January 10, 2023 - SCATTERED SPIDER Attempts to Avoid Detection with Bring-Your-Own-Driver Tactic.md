# SCATTERED SPIDER Attempts to Avoid Detection with Bring-Your-Own-Driver Tactic

- **Source :** crowdstrike
- **URL :** https://www.crowdstrike.com/en-us/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/
- **Date :** January 10, 2023

---

# SCATTERED SPIDER Exploits Windows Security Deficiencies with Bring-Your-Own-Vulnerable-Driver Tactic in Attempt to Bypass Endpoint Security

January 10, 2023

• [ CrowdStrike Intelligence Team](/en-us/blog/author.crowdstrike-intelligence-team/ "Posts by CrowdStrike Intelligence Team") • [Threat Hunting & Intel](/en-us/blog/category.counter-adversary-operations/ "Threat Hunting & Intel")


  * In December 2022, CrowdStrike [reported on a campaign](/en-us/blog/analysis-of-intrusion-campaign-targeting-telecom-and-bpo-companies/) by SCATTERED SPIDER, targeting organizations within the telecom and business process outsourcing (BPO) sectors with an end objective of gaining access to mobile carrier networks.
  * In the weeks since that post, the CrowdStrike Falcon® platform prevented a novel attempt by SCATTERED SPIDER to deploy a malicious kernel driver through a vulnerability (CVE-2015-2291) in the Intel Ethernet diagnostics driver.
  * The activity exploits a well known and pervasive deficiency in Windows security that enables adversaries to bypass Windows kernel protections with the Bring-Your-Own-Vulnerable-Driver tactic. 
  * CrowdStrike Services has observed the actor attempting to bypass other endpoint tools including Microsoft Defender for Endpoint, Palo Alto Networks Cortex XDR and SentinelOne using more traditional defense evasion techniques targeting Windows registry hives.



## Introduction

In December, CrowdStrike reported that beginning in June 2022, the CrowdStrike Services, CrowdStrike® Falcon OverWatch™ and CrowdStrike Intelligence teams observed an increase in the targeting of telco and BPO industries. CrowdStrike Intelligence attributed this campaign with low confidence to the SCATTERED SPIDER eCrime adversary.

SCATTERED SPIDER (aka Roasted 0ktapus, UNC3944) leverages a combination of credential phishing and social engineering to capture one-time-password (OTP) codes or overwhelms targets using multifactor authentication (MFA) notification fatigue tactics. Having obtained access, the adversary avoids using unique malware, instead favoring a wide range of legitimate remote management tools to maintain persistent access.

In the weeks since [that blog post](/en-us/blog/analysis-of-intrusion-campaign-targeting-telecom-and-bpo-companies/), the Falcon platform detected a novel attempt by this adversary to deploy a malicious kernel driver through a vulnerability (CVE-2015-2291) in the Intel Ethernet diagnostics driver for Windows (`iqvw64.sys`).

## Microsoft Windows Security Deficiencies Leave Devices Vulnerable

This vulnerability has been used by adversaries for several years to deploy malicious drivers into the Windows kernel. This technique is known as “Bring Your Own Vulnerable Driver” (BYOVD) and is a tactic that has persisted due to a gap in Windows security.

In an attempt to limit the amount of capabilities that malware can gain access to on a Windows system, starting with 64-bit Windows Vista, Windows does not allow unsigned kernel-mode drivers to run by default. BYOVD “makes it easy for an attacker with administrative control [to bypass Windows kernel protections](https://arstechnica.com/information-technology/2022/10/how-a-microsoft-blunder-opened-millions-of-pcs-to-potent-malware-attacks.html),” allowing an adversary to install a legitimately signed but malicious driver to execute an attack. Publicly available tools, such as KDMapper, allow adversaries to easily take advantage of BYOVD to map non-signed drivers into memory.

In 2021, [Microsoft stated](https://www.microsoft.com/en-us/security/blog/2021/12/08/improve-kernel-security-with-the-new-microsoft-vulnerable-and-malicious-driver-reporting-center/) that “Increasingly, adversaries are leveraging legitimate drivers in the ecosystem and their security vulnerabilities to run malware,” and that “drivers with confirmed security vulnerabilities will be blocked on Windows 10 devices in the ecosystem using Microsoft Defender for Endpoint attack surface reduction (ASR) and Microsoft Windows Defender Application Control (WDAC) technologies to protect devices against exploits involving vulnerable drivers to gain access to the kernel.”

However, as noted by multiple security researchers (e.g., [here](https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/amp/), [here](https://eclypsium.com/2019/08/10/screwed-drivers-signed-sealed-delivered/) and [here](https://www.welivesecurity.com/2022/01/11/signed-kernel-drivers-unguarded-gateway-windows-core/)) over the past two years, the issue continues to persist as Microsoft fails to block vulnerable drivers by default.

In this instance, the adversary attempted to load a malicious driver that was prevented from running and quarantined by CrowdStrike Falcon® Prevent machine learning (ML) and identified by Falcon OverWatch. This driver is designed to use the privileged driver space provided by the vulnerable Intel driver to overwrite specific routines in the CrowdStrike Falcon sensor driver with adversary-created trampoline code. While this was prevented by the Falcon sensor and immediately escalated to the customer with human analysis, a series of recommendations to protect Microsoft kernel memory can be found in the "Recommendations" section below.

In the past months, CrowdStrike Services has observed the actor attempting to bypass other endpoint tools including Microsoft Defender for Endpoint, Palo Alto Networks Cortex XDR and SentinelOne.

## Technical Analysis

CrowdStrike has identified various versions of a malicious driver that are signed by different certificates and authorities — including stolen certificates originally issued to NVIDIA and Global Software LLC, as well as a self-signed test certificate. The intent of the adversary is to disable the endpoint security products visibility and prevention capabilities so the actor can further their actions on objectives.

Versions of the sample are small, 64-bit Windows kernel drivers with less than 35 relatively simple functions.

An example driver with SHA256 hash

`b6e82a4e6d8b715588bf4252f896e40b766ef981d941d0968f29a3a444f68fef` has its build time set to `1970-01-01 00:01:35 UTC`. It contains various status messages and calls to `DbgPrintEx()`, as a means to provide status messages to the threat actor. The file is signed using a certificate with the following parameters:

serial: `31 11 00 fb 8d ee 5e 09 37 6b 69 a8 f6 23 e0 ee`

issued to: `Global Software, LLC`

valid from: `2018-05-14` valid to: `2021-06-18`

The same certificate has been observed signing other malicious files dating back to at least 2018, suggesting that other threat actors have copies of it.

The driver walks the list of loaded kernel modules, searching for `csagent.sys` (the CrowdStrike Falcon kernel component), and scans the identified module for a hard-coded pattern of 64 bytes. In addition to the search pattern, the scanning function retrieves the mask string "`xxxxxxxxxxxxxxxxxxx??xxxxxxxxxxxxxxxxxxxxxxxxxxxx??xx`" as an argument that masks out bytes corresponding to absolute memory addresses. These change when the driver code is mapped to a different base address, and should therefore be excluded. The mask string is only 61 bytes long, 3 bytes shorter than the code pattern, possibly due to incomplete adjustments.

A second sample with SHA256 hash `e23283e75ed2bdabf6c703236f5518b4ca37d32f78d3d65b073496c12c643cfe` has a PE build timestamp of `2022-12-23 15:11:27 UTC` that matches the signing date. This file is digitally signed with what appears to be a test certificate with the following parameters:

serial: `23 43 9d 9d d3 2a a7 b2 4b bb 6e 31 64 fb 47 53`

``issued to: `WDKTestCert guid0,133162475712847553`

valid from: `2022-12-23`

valid to: `2032-12-23`

This sample is intended to be loaded using BYOVD techniques and hence does not require a verifiable digital signature. No other files signed with this test certificate were available at the time of analysis.

Upon startup, the driver decrypts a hard-coded string of targeted security products using a basic XOR loop:

`for i in len(name): name _^= i % 56 + 49_`

The malicious driver then finds the target driver using the same method and patches it, in memory, at hard-coded offsets. The patching routine operates on a list where each element represents a hook structure that contains a pointer to the target function, a pointer to the malware routine and trampoline code to invoke that routine. The installed malware routines signal success to the Falcon sensor in every case even though the routines perform no operation.

While the outlined activity appears to target specific industries, organizations of all types should apply the lessons learned to harden defenses against such threats. CrowdStrike recommends that organizations employ a rigorous, defense-in-depth approach that monitors endpoints, cloud workloads, identities and networks to defend against advanced, persistent adversaries. The holistic deployment of security tooling paired with a high operational tempo in responding to alerts and incidents are critical to success.

## Recommendations

The described activity will be prevented and quarantined by the Falcon platform if configured as outlined in our prevention policy [best practices recommendations](https://supportportal.crowdstrike.com/s/article/Prevention-Policy-Best-Practice-Guidelines).

### Prevention Policy Settings

With regard to the malicious activity detailed here, in particular confirm the Windows prevention policy settings listed are set as follows:

  * Sensor Tampering Protection enabled
  * Cloud Anti-malware Prevention slider at Moderate or higher
  * Sensor Anti-malware Prevention slider at Moderate or higher
  * Suspicious Processes enabled
  * Suspicious Kernel Drivers enabled



The complete list of our best practices recommendations for prevention policies may be found in the support portal here: [Prevention Policy Best Practice Guidelines](https://supportportal.crowdstrike.com/s/article/Prevention-Policy-Best-Practice-Guidelines)

### Mitigate CVE-2015-2291

CrowdStrike customers should ensure they have the ability to locate and patch the vulnerable Intel Ethernet Driver specified in CVE-2015-2291. Prioritizing the patching of vulnerable drivers can help mitigate this and similar attack vectors involving signed driver abuse.

CrowdStrike Falcon® Spotlight customers can search for the presence of this driver by navigating to: Spotlight > Vulnerabilities. [US-1](https://falcon.crowdstrike.com/spotlight-v2/vulnerabilities/group-by/cve?filter=cve.id%3A%27CVE-2015-2291%27) | [US-2](https://falcon.us-2.crowdstrike.com/spotlight-v2/vulnerabilities/group-by/cve?filter=cve.id%3A%27CVE-2015-2291%27) | [EU](https://falcon.eu-1.crowdstrike.com/spotlight-v2/vulnerabilities/group-by/cve?filter=cve.id%3A%27CVE-2015-2291%27) | [Gov](https://falcon.laggar.gcw.crowdstrike.com/spotlight-v2/vulnerabilities/group-by/cve?filter=cve.id%3A%27CVE-2015-2291%27)

### Evaluate Enabling Microsoft Memory Integrity Capabilities

Due to the inherent flaws in Microsoft protection of kernel memory permitting these types of BYOVD attacks, additional functionality has been incorporated into modern Windows Operating Systems. [Hypervisor-Protected Code Integrity (HVCI)](https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard), a component of Virtualization-Based Security (VBS) is designed to prevent users with elevated privilege from being able to read and write to kernel memory. The protections were implemented in order to address the security flaw of not enforcing kernel memory protections.

While CrowdStrike has not identified any issues with the Falcon platform running in environments with these features enabled, there have been intermittent reports of performance issues in various other environments tied to specific applications and some processors. CrowdStrike Falcon® Insight XDR customers can view the status of HVCI by navigating to: Host setup and management > Zero Trust Assessment.

__

_[![](https://www.crowdstrike.com/content/dam/crowdstrike/www/en-us/wp/2023/01/Picture1-edited.png)](/content/dam/crowdstrike/www/en-us/wp/2023/01/Picture1-edited.png)(Click to enlarge)_

__

### Enable Traffic Inspection for CrowdStrike Falcon Identity Threat Protection

As the adversary is largely leveraging valid accounts as the initial access vector, additional scrutiny of legitimate login activity and two-factor authentication approvals from unexpected assets, accounts or locations are highly recommended.

_[![](https://www.crowdstrike.com/content/dam/crowdstrike/www/en-us/wp/2023/01/Picture2.png)](/content/dam/crowdstrike/www/en-us/wp/2023/01/Picture2.png)(Click to enlarge)_

#### Additional Resources

  * _[Request a free trial](/en-us/free-trial-guide/) of the industry-leading CrowdStrike Falcon platform. _
  * _Read about adversaries tracked by CrowdStrike in 2022 in the[ 2023 CrowdStrike Global Threat Report](/en-us/global-threat-report/) and in the [2023 Threat Hunting Report](/en-us/resources/reports/threat-hunting-report/)._
  * _Request a free[ CrowdStrike Intelligence threat briefing](https://go.crowdstrike.com/threat-intelligence-briefing.html?utm_campaign=threatintelligence&utm_content=us&utm_medium=sem&utm_source=goog&utm_term=cyber%20threat%20intelligence&_bt=465670942471&_bk=cyber%20threat%20intelligence&_bm=e&_bn=g&_bg=108022039334&gclid=EAIaIQobChMIqsSdwZ-j7AIV9R6tBh23rQErEAAYASAAEgKc8fD_BwE&_ga=2.145914102.359113952.1606756854-1198667695.1606243810) and learn how to stop adversaries targeting your organization._
  * _Learn how[ CrowdStrike Services](/en-us/services/) can help your organization prepare to defend against sophisticated threats, respond and recover from incidents with speed and precision, and fortify your cybersecurity practices._
  * _[Watch an introductory video](https://www.youtube.com/watch?v=oAGUHgtf7c8) on the CrowdStrike Falcon console and [register for an on-demand demo](https://go.crowdstrike.com/product-demo-platform.html) of the market-leading CrowdStrike Falcon platform in action._



[ ](https://www.linkedin.com/shareArticle) [ ](https://twitter.com/share)

* * *

#### Related Content

[ ![PhantomRaven: An LLM-Generated Information Stealer Developed for Bug Bounty Hunting](https://assets.crowdstrike.com/is/image/crowdstrikeinc/Blog-InfoStealer?wid=2048&hei=1349&fmt=png-alpha&qlt=95,0&resMode=sharp2&op_usm=3.0,0.3,2,0) Threat Hunting & Intel | Sep 15, 2026  PhantomRaven: An LLM-Generated Information Stealer Developed for Bug Bounty Hunting ](/en-us/blog/phantomraven-llm-generated-information-stealer-for-bug-bounty-hunting/) [ ![Peer Pressure: Inside the Sality Botnet Disruption Operation](https://assets.crowdstrike.com/is/image/crowdstrikeinc/Blog-FalCon-Sality?wid=1060&hei=698&fmt=png-alpha&qlt=95,0&resMode=sharp2&op_usm=3.0,0.3,2,0) Threat Hunting & Intel | Sep 01, 2026  Peer Pressure: Inside the Sality Botnet Disruption Operation ](/en-us/blog/inside-sality-botnet-disruption-operation/) [ ![CrowdStrike 2026 Threat Hunting Report: Exploitation Window Closes as AI Use Accelerates](https://assets.crowdstrike.com/is/image/crowdstrikeinc/Blog-THR-2026?wid=1060&hei=698&fmt=png-alpha&qlt=95,0&resMode=sharp2&op_usm=3.0,0.3,2,0) Threat Hunting & Intel | Aug 03, 2026  CrowdStrike 2026 Threat Hunting Report: Exploitation Window Closes as AI Use Accelerates ](/en-us/blog/crowdstrike-2026-threat-hunting-report/)