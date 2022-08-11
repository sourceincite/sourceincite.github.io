---
layout: page
title: Research
isroot: True
order: 5
permalink: /research/
---

The following links are some of my past information security research. Not all.

* [Advisories](/advisories)
* [Exploits](/exploits)

### Tools:

---
* [Bridgit](https://github.com/stevenseeley/bridgit)

   This was a tool I developed to discover [src-2018-0027](https://srcincite.io/advisories/src-2018-0027) and re-discover/exploit [ZDI-18-332](https://www.zerodayinitiative.com/advisories/ZDI-18-332/).

### Competitions:

---

- [Pwn2Own Miami 2022 - Second place with 4 successful wins](https://www.zerodayinitiative.com/blog/2022/4/14/pwn2own-miami-2022-results)

   [Chris Anastasio](https://twitter.com/mufinnnnnnn) and I came back to defend our title and we found multiple vulnerabilities targeting several ICS applications. Unfortunately we didn't win, but we had heaps of fun!

- [Pwn2Own Vancouver 2021 - Partial win against Microsoft Exchange Server](https://youtu.be/6FYfUv1pwAg?t=5778)

   I found a remote code execution vulnerability that could have been triggered during a [MiTM](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) attack which scored a partial win.

- [Pwn2Own Miami 2020 - Master of Pwn](https://www.zerodayinitiative.com/blog/2020/1/21/pwn2own-miami-2020-schedule-and-live-results)

   In preperation for this competition, [Chris Anastasio](https://twitter.com/mufinnnnnnn) and I found multiple vulnerabilities and developed exploits targeting several ICS applications that allowed us to win the competition!

### Presentations:

---
Some past presentations that I have shared.

* [BlackHat :: USA :: 2022 - IAM Whoever I Say IAM Infiltrating Identity Providers Using 0Click Exploits](/assets/iam-who-i-say-iam.pdf)

   In this presentation I discuss the various vulnerabilities I discovered when auditing VMWare Workspace ONE Access and how they were exploited creatively.
   
* [Defcon 29 :: USA :: 2021 - Don't Date to Exploit :: An Attack Surface Tour of SharePoint Server](/assets/yuhao-weng-steven-seeley-zhiniang-peng-dont-dare-to-exploit-an-attack-surface-tour-of-sharepoint-server.pdf)

   In this presentation Yuhao, Zhiniang and I discuss the various vulnerabilities we discovered when auditing Microsoft SharePoint Server and reveal some of the hidden attack surfaces.

* [Internet Security Conference :: China :: 2020 - Out of Hand :: Attacks Against PHP Environments](/assets/out-of-hand-attacks-against-php-environments.pdf)

   In this presentation I discuss a few interesting primitives in the current PHP environment. The first allows an attacker to achieve an information disclosure using TypeError and the second is how an external entity injection (XXE) vulnerability can be leveraged for deserialization of untrusted data.
   
* [BlueHatIL :: Israel :: 2019 - Postscript Pat and His Black and White Hat](/assets/postscript-pat-and-his-black-and-white-hat.pdf)

   I discussed how I developed a postscript fuzzer to target Adobe's postscript engine and uncover many zeroday vulnerabilities.

* [BSides :: Mexico :: 2018 - Foxes Among Us](/assets/Foxes-Among-Us-Steven-Seeley-bsidescdmx-2018.pdf)

   I discussed how I found a use-after-free vulnerability and chained it together with an uninitialized object vulnerability to achieve reliable exploitation bypassing several operating system mitigations.

* [Hack in The Box :: Netherlands :: 2017 - I got 99 trends and a # is all of them](/assets/steven-seeley-and-roberto-suggi-liverani-i-got-99-trends-and-a-shell-is-all-of-them.pdf)

   Roberto and I discussed how we found over 200+ Remote Code Execution vulnerabilities within Trend Micro Software.

* [Hack in The Box :: Netherlands :: 2012 - Ghost in the allocator](/assets/D2T2-Steven-Seeley-Ghost-In-the-Allocator.pdf)

   Here I demonstrated a new technique/variation for exploitation against the Windows 7 heap manager that abuses the allocation offset mechanism. Additionally, I also presented a likely attack technique against the consumer preview version of the Windows 8 heap manager.

* [Ruxcon :: Australia :: 2012 - How to catch a chameleon](/assets/How-to-catch-a-chameleon-StevenSeeley-Ruxcon-2012.pdf)

   This presentation was about the introduction of a plugin for Immunity Debugger that I developed called [heaper](https://github.com/stevenseeley/heaper) that is designed to not only detect a corrupted heap state before out-of-bounds memory access, but was also designed to detect exploitable conditions in past Windows operating systems.

### Other blog posts I have written:

---
* [The Synology Improbability](https://www.offensive-security.com/offsec/the-synology-improbability/)
* [Auditing the Auditor](https://www.offensive-security.com/vulndev/auditing-the-auditor/)

### Media:

---
Some mentions of my work that are publically available.

* [Inside the World's Highest-Stakes Industrial Hacking Contest](https://www.wired.com/story/pwn2own-industrial-hacking-contest/)
* [Critics Hit Out at Cisco After Security Researcher Finds 120+ Vulnerabilities in a Single Product](https://www.cbronline.com/data-centre/cisco-data-center-network-manager/)
* [One Mans Patch is Another Mans Treasure. A Tale of a Failed HPE Patch](https://www.zerodayinitiative.com/blog/2018/2/6/one-mans-patch-is-another-mans-treasure-a-tale-of-a-failed-hpe-patch)
* [Exploiting Untrusted Objects Through Deserialization: Analyzing 1 of 100+ HPE Bug Submissions](https://www.thezdi.com/blog/2017/12/01/exploiting-untrusted-objects-through-deserialization-analyzing-1-of-100-hpe-bug-submissions)
* [Busting Myths in Foxit Reader](https://www.thezdi.com/blog/2017/8/17/busting-myths-in-foxit-reader)
* [Hackers Tear Apart Trend Micro, Find 200 Vulnerabilities In Just 6 Months](https://www.forbes.com/sites/thomasbrewster/2017/01/25/trend-micro-security-exposed-200-flaws-hacked/)