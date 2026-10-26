# STARDUST CHOLLIMA Likely Compromises Axios npm Package

- **Source :** crowdstrike
- **URL :** https://www.crowdstrike.com/en-us/blog/stardust-chollima-likely-compromises-axios-npm-package/
- **Date :** April 01, 2026

---

# STARDUST CHOLLIMA Likely Compromises Axios npm Package

April 01, 2026

• [ Counter Adversary Operations](/en-us/blog/author.counter-adversary-operations/ "Posts by Counter Adversary Operations") • [Threat Hunting & Intel](/en-us/blog/category.counter-adversary-operations/ "Threat Hunting & Intel")


On March 31, 2026, a threat actor used stolen maintainer credentials to compromise the widely used HTTP client library Axios Node Package Manager (npm) package and deploy platform-specific _ZshBucket_ variants. CrowdStrike Counter Adversary Operations attributes this activity to [STARDUST CHOLLIMA](https://www.crowdstrike.com/en-us/adversaries/stardust-chollima/) with moderate confidence based on the adversary’s deployment of updated variants of _ZshBucket_ (malware uniquely attributed to STARDUST CHOLLIMA) and overlaps with known STARDUST CHOLLIMA infrastructure. 

_ZshBucket_ can be used to target Linux, macOS, and Windows systems; previously, only macOS variants of _ZshBucket_ had been observed. The observed macOS variant in this case extensively reuses code from previous instances, including function names. All variants retain characteristics of previous instances, including how it profiles the user and host of the operating system, and how it sends the collected information.

The adversary made the following significant updates to the functionality and messaging protocol in the _ZshBucket_ instance deployed in this incident compared to previous variants:

  * Implemented a common JSON-based messaging protocol for all platform-specific instances
  * Implemented commands that enable the operator to inject binary payloads, execute arbitrary scripts and commands, enumerate the file system, and remotely terminate the implant; these commands replace previous instances’ simple download and execute functionality



## Related Infrastructure

The domain `sfrclak[.]com` — hosted at `142.11.206[.]73` and later used as a command-and-control (C2) address — shares a host services banner hash (`c373706b3456c36e8baa0a3ee5aed358c1fe07cba04f65790c90f029971e378a`) with two additional IP addresses: `23.254.203[.]244` and `23.254.167.216`. The IP address `23.254.203[.]244` is a known STARDUST CHOLLIMA IP address first observed in December 2025, and `23.254.167[.]216` was previously used as a C2 server for [FAMOUS CHOLLIMA](https://www.crowdstrike.com/en-us/adversaries/famous-chollima/)’s InvisibleFerret malware in May 2025. The domain is also registered on the Hostwinds hosting provider, consistent with STARDUST CHOLLIMA’s previously observed operations.

## Assessment

CrowdStrike Intelligence attributes this activity to STARDUST CHOLLIMA with moderate confidence based on the use of an updated _ZshBucket_ instance — malware uniquely attributed to STARDUST CHOLLIMA — as well as infrastructure overlaps with STARDUST CHOLLIMA’s previous operations. However, the infrastructure also overlaps with FAMOUS CHOLLIMA operations, precluding a higher confidence assessment. 

DPRK-nexus adversaries frequently share infrastructure, and FAMOUS CHOLLIMA has historically deployed DPRK-associated tooling and has extensively abused npm repositories in their operations. As such, FAMOUS CHOLLIMA could be responsible for this incident. However, the updated _ZshBucket_ variants deployed in this supply chain compromise are more technically advanced than the malware FAMOUS CHOLLIMA typically uses, and this incident is more likely attributable to STARDUST CHOLLIMA. 

The intended targets of this compromise are unclear. The Axios npm package is a commonly used HTTP client library that is downloaded more than 100,000 times per week. STARDUST CHOLLIMA’s operations prioritize currency generation and regularly target cryptocurrency holders, and the adversary has also conducted widespread supply chain compromises impacting fintech companies’ npm and PyPi repositories. Based on these factors, CrowdStrike Counter Adversary Operations assesses the adversary’s motivation probably aligns with this currency generation objective. 

Since the end of Q4 2025, STARDUST CHOLLIMA’s operational tempo has surged and has continued at this pace. This supply chain attack leveraging updated _ZshBucket_ variants is further evidence that the adversary intends to scale their operations in the near term.

#### Additional Resources

  * _Dive deeper into topics like this at[Fal.Con 2026](https://www.crowdstrike.com/en-us/events/fal-con/las-vegas/?utm_medium=evt&utm_source=blog&utm_campaign=fal-con-26&utm_term=crwdblogs&utm_language=en-us) with expert-led sessions, hands-on training, and real-world insights._
  * _Read the[CrowdStrike 2026 Global Threat Report](https://www.crowdstrike.com/en-us/global-threat-report/) for the latest insights on adversaries, tradecraft, and activity._
  * _Visit the[Counter Adversary Operations](https://www.crowdstrike.com/en-us/platform/threat-intelligence/) webpage to learn about CrowdStrike’s threat intelligence and hunting solutions._



[ ](https://www.linkedin.com/shareArticle) [ ](https://twitter.com/share)

* * *

#### Related Content

[ ![PhantomRaven: An LLM-Generated Information Stealer Developed for Bug Bounty Hunting](https://assets.crowdstrike.com/is/image/crowdstrikeinc/Blog-InfoStealer?wid=2048&hei=1349&fmt=png-alpha&qlt=95,0&resMode=sharp2&op_usm=3.0,0.3,2,0) Threat Hunting & Intel | Sep 15, 2026  PhantomRaven: An LLM-Generated Information Stealer Developed for Bug Bounty Hunting ](/en-us/blog/phantomraven-llm-generated-information-stealer-for-bug-bounty-hunting/) [ ![Peer Pressure: Inside the Sality Botnet Disruption Operation](https://assets.crowdstrike.com/is/image/crowdstrikeinc/Blog-FalCon-Sality?wid=1060&hei=698&fmt=png-alpha&qlt=95,0&resMode=sharp2&op_usm=3.0,0.3,2,0) Threat Hunting & Intel | Sep 01, 2026  Peer Pressure: Inside the Sality Botnet Disruption Operation ](/en-us/blog/inside-sality-botnet-disruption-operation/) [ ![CrowdStrike 2026 Threat Hunting Report: Exploitation Window Closes as AI Use Accelerates](https://assets.crowdstrike.com/is/image/crowdstrikeinc/Blog-THR-2026?wid=1060&hei=698&fmt=png-alpha&qlt=95,0&resMode=sharp2&op_usm=3.0,0.3,2,0) Threat Hunting & Intel | Aug 03, 2026  CrowdStrike 2026 Threat Hunting Report: Exploitation Window Closes as AI Use Accelerates ](/en-us/blog/crowdstrike-2026-threat-hunting-report/)