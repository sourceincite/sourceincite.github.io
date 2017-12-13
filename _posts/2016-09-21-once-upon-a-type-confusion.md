---
layout: post
title: "Once Upon a Type Confusion"
date: 2016-09-21 12:34:15 -0600
categories: blog
excerpt_separator: <!--more-->
---

<img class="excel" alt="Microsoft Office Excel" src="/assets/images/excel.png">
Last week, Microsoft released the MS16–107 to patch CVE-2016-3363, which is a `Type Confusion` vulnerability within Microsoft Excel 2007, 2010, 2013 and 2016 both 32 and 64 bit versions. This post will show you how I determined the vulnerability class and some lightweight technical details around the vulnerability.

<!--more-->

After minimising the Proof of Concept and visualising the structures in [offviz][offviz], we can see the differences:

{% include image.html
            img="assets/images/type-confusion-sample.png"
            title="The original sample"
            caption="The original sample" %}

{% include image.html
            img="assets/images/type-confusion-trigger.png"
            title="The trigger sample"
            caption="The trigger sample" %}

Within a BIFFRecord structure, there are several BIFFRecord_General structures that are defined. Following a set number of BIFFRecord_General structures defined in the BIFFRecord, the code blindly assumes that the next structure is a EOF Record. More details about the specification can be found in OpenOffice’s version of [Microsoft Excel File Format][excelfileformat] document.

The trigger occurs in the protected mode (brokered process) of Microsoft Excel, so we are going to have to enable child debugging within windbg.
Running the Proof of Concept yields in the following crash dump:

{% highlight text %}
(6ec.9a0): Break instruction exception — code 80000003 (first chance)
eax=7ffd5000 ebx=00000000 ecx=00000000 edx=776bebb3 esi=00000000 edi=00000000
eip=77653c4c esp=045afe3c ebp=045afe68 iopl=0 nv up ei pl zr na pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000246
ntdll!DbgBreakPoint:
77653c4c cc int 3
0:009> .childdbg 1
Processes created by the current process will not be debugged
0:009> g
...
(2dc.ce8): Break instruction exception - code 80000003 (first chance)
eax=00000000 ebx=00000000 ecx=0020f59c edx=77666bf4 esi=fffffffe edi=00000000
eip=776c0541 esp=0020f5b8 ebp=0020f5e4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!LdrpDoDebuggerBreak+0x2c:
776c0541 cc              int     3
1:025> g
...
(2dc.ce8): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0ae04c98 ebx=0ae04de8 ecx=0a3c0fa0 edx=00000301 esi=00000007 edi=001ff748
eip=2fd22c77 esp=001ff728 ebp=001ff764 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
Excel!Ordinal40+0x322c77:
2fd22c77 8b5164          mov     edx,dword ptr [ecx+64h] ds:0023:0a3c1004=????????
{% endhighlight %}

We can see that initially it is an out-of-bounds read in @ecx. Lets go ahead and dump @ecx to get an understanding for its size and structure.

{% highlight text %}
1:025> !heap -p -a @ecx
 address 0a3c0fa0 found in
 _DPH_HEAP_ROOT @ 1211000
 in busy allocation ( DPH_HEAP_BLOCK: UserAddr UserSize — VirtAddr VirtSize)
 a243000: a3c0fa0 60 — a3c0000 2000
 73218e89 verifier!AVrfDebugPageHeapAllocate+0x00000229
 776e616e ntdll!RtlDebugAllocateHeap+0x00000030
 776aa08b ntdll!RtlpAllocateHeap+0x000000c4
 77675920 ntdll!RtlAllocateHeap+0x0000023a
 62f06cca mso!Ordinal149+0x000078e0
 2fb29b51 Excel!Ordinal40+0x00129b51
 2fb29af7 Excel!Ordinal40+0x00129af7
 2fb61228 Excel!Ordinal40+0x00161228
 2fb5f32e Excel!Ordinal40+0x0015f32e
 2fb35b78 Excel!Ordinal40+0x00135b78
 2fb34e64 Excel!Ordinal40+0x00134e64
 7728c4f7 USER32!InternalCallWinProc+0x00000023
 77285faf USER32!UserCallWinProcCheckWow+0x000000e0
 77284f1b USER32!DispatchClientMessage+0x000000e6
 7727e992 USER32!__fnINLPCREATESTRUCT+0x0000008b
 77666b2e ntdll!KiUserCallbackDispatcher+0x0000002e
 7727ec5c USER32!_CreateWindowEx+0x00000201
 7727ecb7 USER32!CreateWindowExW+0x00000033
 2fb2337d Excel!Ordinal40+0x0012337d
 2fb34cbe Excel!Ordinal40+0x00134cbe
 2fb5f248 Excel!Ordinal40+0x0015f248
 2fc8cdfe Excel!Ordinal40+0x0028cdfe
 305bc671 Excel!MdCallBack12+0x0023e0f6
 302c1482 Excel!Ordinal40+0x008c1482
 302b6ceb Excel!Ordinal40+0x008b6ceb
 302ccea6 Excel!Ordinal40+0x008ccea6
 302d1708 Excel!Ordinal40+0x008d1708
 302d2067 Excel!Ordinal40+0x008d2067
 302d29d2 Excel!Ordinal40+0x008d29d2
 302d2e11 Excel!Ordinal40+0x008d2e11
 2fb8a514 Excel!Ordinal40+0x0018a514
 30248977 Excel!Ordinal40+0x00848977
1:025> dds @ecx
0a3c0fa0 00000000
0a3c0fa4 00000005
0a3c0fa8 08c8ae70
0a3c0fac 08c60880
0a3c0fb0 00000000
0a3c0fb4 00000011
0a3c0fb8 00000014
0a3c0fbc 00000000
0a3c0fc0 00000000
0a3c0fc4 00000000
0a3c0fc8 00000000
0a3c0fcc 00000000
0a3c0fd0 00000001
0a3c0fd4 00000000
0a3c0fd8 ffffffff
0a3c0fdc ffffffff
0a3c0fe0 ffffffff
0a3c0fe4 ffffffff
0a3c0fe8 00000000
0a3c0fec 2faf7980 Excel!Ordinal40+0xf7980
0a3c0ff0 00000000
0a3c0ff4 0a3c0fa0
0a3c0ff8 00000000
0a3c0ffc 00000000
0a3c1000 ????????
0a3c1004 ????????
0a3c1008 ????????
0a3c100c ????????
0a3c1010 ????????
0a3c1014 ????????
0a3c1018 ????????
0a3c101c ????????
{% endhighlight %}

We can see that the heap buffer is of size 0x60 bytes. Now, we can set a breakpoint at the @eip where the access violation is occurring and run the sample.xls file to see if there is a change in the heap buffer structure are size.

{% highlight text %}
Breakpoint 0 hit
eax=21aa8c98 ebx=21aa8de8 ecx=2a97cf70 edx=00000301 esi=00000007 edi=001d1e58
eip=2f7f2c77 esp=001d1e38 ebp=001d1e74 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200202
EXCEL!Ordinal40+0x322c77:
2f7f2c77 8b5164          mov     edx,dword ptr [ecx+64h] ds:0023:2a97cfd4=00000000
0:000> !heap -p -a @ecx
    address 2a97cf70 found in
    _DPH_HEAP_ROOT @ 11e1000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                                21a03854:         2a97cf70               90 -         2a97c000             2000
    6d8c8e89 verifier!AVrfDebugPageHeapAllocate+0x00000229
    776e616e ntdll!RtlDebugAllocateHeap+0x00000030
    776aa08b ntdll!RtlpAllocateHeap+0x000000c4
    77675920 ntdll!RtlAllocateHeap+0x0000023a
    642a6cca mso!Ordinal149+0x000078e0
    2f5f9b51 EXCEL!Ordinal40+0x00129b51
    2f5f9af7 EXCEL!Ordinal40+0x00129af7
    2f631228 EXCEL!Ordinal40+0x00161228
    2f7f7a89 EXCEL!Ordinal40+0x00327a89
    2f6346cc EXCEL!Ordinal40+0x001646cc
    2f634610 EXCEL!Ordinal40+0x00164610
    2f7e95c4 EXCEL!Ordinal40+0x003195c4
    2f8b14a5 EXCEL!Ordinal40+0x003e14a5
    3008e072 EXCEL!MdCallBack12+0x0023faf7
    2fd91482 EXCEL!Ordinal40+0x008c1482
    2fd86ceb EXCEL!Ordinal40+0x008b6ceb
    2fd9cea6 EXCEL!Ordinal40+0x008ccea6
    2fda1708 EXCEL!Ordinal40+0x008d1708
    2fda2067 EXCEL!Ordinal40+0x008d2067
    2fdb2011 EXCEL!Ordinal40+0x008e2011
    64088fea mso!Ordinal766+0x0000264e
    64089622 mso!Ordinal6107+0x00000584
    6406be75 mso!Ordinal9839+0x00000ff0
    6406c77d mso!Ordinal3502+0x000003b7
    63b4f77b mso!Ordinal6326+0x00003cc5
    64088f77 mso!Ordinal766+0x000025db
    6374b5b2 mso!Ordinal4178+0x000011d3
    6374b2e8 mso!Ordinal4178+0x00000f09
    6374a48a mso!Ordinal4178+0x000000ab
    2f6d6a5a EXCEL!Ordinal40+0x00206a5a
    2f657776 EXCEL!Ordinal40+0x00187776
    2f5f133c EXCEL!Ordinal40+0x0012133c
0:000> dds @ecx l24
2a97cf70  2b500fa0
2a97cf74  00000002
2a97cf78  21890e70
2a97cf7c  2b4fedc8
2a97cf80  00000002
2a97cf84  00000011
2a97cf88  00000014
2a97cf8c  00000000
2a97cf90  00000000
2a97cf94  00000000
2a97cf98  00000000
2a97cf9c  00000000
2a97cfa0  00000001
2a97cfa4  00000000
2a97cfa8  00000005
2a97cfac  00000006
2a97cfb0  00000007
2a97cfb4  00000000
2a97cfb8  00000000
2a97cfbc  2f5c7980 EXCEL!Ordinal40+0xf7980
2a97cfc0  00000000
2a97cfc4  2a97cf70
2a97cfc8  00000000
2a97cfcc  00000000
2a97cfd0  00000001
2a97cfd4  00000000
2a97cfd8  00000000
2a97cfdc  00000000
2a97cfe0  00000000
2a97cfe4  00000000
2a97cfe8  00000000
2a97cfec  00000000
2a97cff0  00000000
2a97cff4  00000000
2a97cff8  00000000
2a97cffc  23416f28
{% endhighlight %}

We can see that this time, the heap chunk size is 0x90 and that at our +0x64 dereference location, it is set to null. This indicates that the code is suppose to be operating on a heap chunk of size 0x90, yet in our crashing Proof of Concept, we can see it is using a chunk of size 0x60 with a different structure.

What is not shown here, is that both the trigger and the sample files, when hitting this breakpoint, have the exact same callstacks. This is important as it is possible that the same location, can operate on different object types and sizes (although unlikley).

Now, at +0x0 and +0x8c of the valid chunk, we can see other heap chunk pointers that could be used by subsequent functions to achieve Remote Code Execution via a code flow redirection.

Additionally, after analysing the vulnerability in IDA, an alternate approach to exploitation was discovered. We see the crashing @eip is located in sub_30322AF2.

{% highlight text %}
.text:30322C77 loc_30322C77:                  
.text:30322C77 mov edx, [ecx+64h]              ; control @edx
.text:30322C7A mov ecx, [ecx+68h]              ; control @ecx
.text:30322C7D sub [esp+38h+var_20_taint], edx ; taint var 0x20
.text:30322C81 sub [esp+38h+var_1C_taint], ecx ; taint var 0x1c
{% endhighlight %}

Now, a few blocks down with multiple pathways from our crashing @eip we see some dword writes, the first of which, we control the value being written:

{% highlight text %}
.text:30322D00 loc_30322D00: 
.text:30322D00 mov edi, [ebp+arg_0]              ; des
.text:30322D03 add edi, 18h                      ; des offset +0x18
.text:30322D06 lea esi, [esp+38h+var_20_taint]   ; src
.text:30322D0A movsd                             ; write dword
{% endhighlight %}

This all looks a bit clearer in windbg:

{% highlight text %}
30272d00 8b7d08 mov edi,dword ptr [ebp+8]
30272d03 83c718 add edi,18h
30272d06 8d742418 lea esi,[esp+18h]
30272d0a a5 movs dword ptr es:[edi],dword ptr [esi]
{% endhighlight %}

Essentially crushing this 0x00000007 value with a controlled value in an alternate heap chunk:

{% highlight text %}
1:025> dd poi(ebp+8)+18 L1
0ade2df0 00000007
{% endhighlight %}

### Conclusion

Whilst in context, exploiting such a vulnerability would be very hard, type confusion vulnerabilities often give attackers several opportunities to achieve relative reads/writes or direct control flow highjacking.

In this case, we had the ability to tamper with data in an alternate chunk, thus, potentially influencing the control of execution when code is operating on that heap chunk. Many more opportunities for exploitation are likely to exist for this vulnerability and type confusions are excellent primitives for an attacker.

The advisory can be found [here][advisory] along with a PoC [here][poc].

[offviz]: http://go.microsoft.com/fwlink/?LinkId=158791&usg=AFQjCNF_MQ5K2mj3WmG0gT55Q8Ym5rmPbQ&sig2=V8eCC2WwA1JBk_NxQVq5Vg
[excelfileformat]: https://www.openoffice.org/sc/excelfileformat.pdf
[advisory]: https://srcincite.io/advisories/src-2016-0038/
[poc]: https://github.com/sourceincite/poc/blob/master/SRC-2016-0038.xls
