---
layout: post
title: The Implied Security of memmove()
date: 2016-10-25 12:34:15 -0600
categories: blog
excerpt_separator: <!--more-->
---

<p class="cn" markdown="1">tl;dr; Calls to memmove(); that use a source buffer that is smaller than the destination buffer can be at times exploitable if the size value is bit aligned, is mapped in memory and that the original source buffer is also mapped in memory.</p>

<!--more-->

<p class="cn" markdown="1">So, the other day I was debugging a vulnerability I had found and trying to understand the issue by performing a root cause analysis (RCA). I was, all up in windbg doing my thing, setting break points and getting all crazy. I ended up with the following breakpoint when messing in the windbg.</p>

{% highlight text %}
bp msvcrt!memmove ".if (poi(@esp+8)==0) {.printf \"calling memmove(0x%x, 0x%x, 0x%x);\\n\", poi(@esp+4), poi(@esp+8), poi(@esp+c);} .else {gc}"
{% endhighlight %}

<p class="cn" markdown="1">So this breakpoint will only break into the debugger if a call to memmove has the second argument set to null. Checking my windbg log, I see the following: `calling memmove(0x1613fe8, 0x0, 0x0161aa10);`</p>

<p class="cn" markdown="1">Everyone knows that the memmove prototype across architectures is:
`void *memmove( void *dest, const void *src, size_t count );`</p>

<p class="cn" markdown="1">So naturally, I attempt to investigate the situation.</p>

{% highlight text %}
1:001> !address 0x0161aa10
 ProcessParametrs 001812b0 in range 00180000 0018a000
 Environment 00180810 in range 00180000 0018a000
    015b0000 : 015b0000 - 00073000
                    Type     00020000 MEM_PRIVATE
                    Protect  00000004 PAGE_READWRITE
                    State    00001000 MEM_COMMIT
                    Usage    RegionUsageHeap
                    Handle   00530000
1:001> !heap -p -a 0x0161aa10
    address 0161aa10 found in
    _HEAP @ 530000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        01613fe0 0f48 0000  [00]   01613fe8    07a28 - (busy)
1:001> !address 0x1613fe8
 ProcessParametrs 001812b0 in range 00180000 0018a000
 Environment 00180810 in range 00180000 0018a000
    015b0000 : 015b0000 - 00073000
                    Type     00020000 MEM_PRIVATE
                    Protect  00000004 PAGE_READWRITE
                    State    00001000 MEM_COMMIT
                    Usage    RegionUsageHeap
                    Handle   00530000
1:001> !heap -p -a 0x1613fe8
    address 01613fe8 found in
    _HEAP @ 530000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        01613fe0 0f48 0000  [00]   01613fe8    07a28 - (busy)
{% endhighlight %}

<p class="cn" markdown="1">As it turns out, the size value is actually a mapped heap chunk! To make it worse (or better), the least significant bytes are always mapped to offset 0xaa10, which I can control based on allocation size in the target. It looks like the developer of my target got his/her parameters mixed up! My guess is that the second and third arguments should have switched: `calling memmove(0x1613fe8, 0x0161aa10, 0x0);`</p>

<p class="cn" markdown="1">Anyway, when I continued execution, I was surprised to see the following output:</p>

{% highlight text %}
1:001> g
(1c38.1260): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0161aa10 ebx=00000000 ecx=00586a84 edx=00000000 esi=0161aa0c edi=02c2e9f4
eip=7687c120 esp=00129ba0 ebp=00129ba8 iopl=0         nv dn ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010612
msvcrt!memmove+0x1e0:
7687c120 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
1:001> dd @esi L1
0161aa0c  41414141
1:001> dd @edi L1
02c2e9f4  ????????
1:001> !address @edi
 ProcessParametrs 001812b0 in range 00180000 0018a000
 Environment 00180810 in range 00180000 0018a000
    01a33000 : 01a33000 - 0e5cd000
                    Type     00000000 
                    Protect  00000001 PAGE_NOACCESS
                    State    00010000 MEM_FREE
                    Usage    RegionUsageFree
1:001> !heap -p -a @esi
    address 0161aa0c found in
    _HEAP @ 530000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        01613fe0 0f48 0000  [00]   01613fe8    07a28 - (busy)
{% endhighlight %}

<p class="cn" markdown="1">An Out-of-Bounds write on unmapped memory? How could this be? Well as it turns out, the copy operation is doing a [backwards copy][backwardscopy]. To find that out I dove into the Microsoft’s implementation of memmove within the 32bit architecture. I used the following DLL: C:\Windows\System32\msvcrt.dll v7.0.7601.1744 (latest at the time of writing).</p>

{% highlight c %}
void *__cdecl memmove(void *Dst, const void *Src, size_t Size)
{
  const void *v3;
  void *v4;
  size_t v5;
  void *result;
  int v7;
  int v8;
  unsigned int v9;
  signed int v10;
  unsigned int v11;

  v3 = Src;
  v4 = Dst;
  if ( Dst <= Src || Dst >= (char *)Src + Size )      // passed the check size dst > src (0x0) and dst < src+size
  {
    ...
  }
  v7 = (int)((char *)Src + Size - 4);                 // set the src buffer based on size value - 0x4
  v8 = (int)((char *)Dst + Size - 4);                 // set the dst buffer based on size value - 0x4
  if ( !(v8 & 3) )                                    // check if dst is bit aligned to the cpu
  {
    v9 = Size >> 2;
    v10 = Size & 3;
    if ( Size >> 2 < 8 )                              // jump if (size / 4) is < 0x8 (which, it wont be if its a large value)
    {
LABEL_36:
      switch ( -v9 )
      {
        case 0u:
          break;
      }
    }
    else                                              // else, we are here
    {
      qmemcpy((void *)v8, (const void *)v7, 4 * v9);  // out of bounds copy
      ...
    }
{% endhighlight %}

<p class="cn" markdown="1">As you can see, its very similar to [OS X’s implementation][appleimplimentation] or [GNU’s implementation][niximplimentation]. So the same situation would happen on Linux or Mac OS X under 32 bit implementations. What you will notice here is that there is no sanity check on the source buffer whatsoever inside memmove. The source buffer is NULL? No worries, continue execution. However, do note that if NULL is not mapped, then an access violation will occur since the backwards copy performs a -- instead of a ++. Thanks to [@badd1e][badd1enull] for pointing this out.</p>

<p class="cn" markdown="1">Depending on how you are targeting your exploitation, an access violation might be ok as you can potentially use the initial out-of-bounds write to target an `unhandled exception function pointer`.</p>

<p class="cn" markdown="1">Regarding exploitation, the following is needed:</p>

<div class="cn" markdown="1">
* ~~(void *)0x0 as the source buffer.~~ Actually, as long as the src buffer is smaller than the dst buffer, this is still possible.
* You will likely need whatever the src value is, to be mapped in memory. If it is null, then the null page will need to be mapped to survive the copy operation.
* A bit aligned size value, in my case it was 32bits or 4 bytes
* The destination + size to point to a mapped and writable location in memory.
* The size value to be a valid pointer to controlled data, rare indeed.
</div>

### Summary

<p class="cn" markdown="1">Now I know what a lot of you neckbeards are going to say, that developers should be careful about the parameters parsed to mem* functions. But the simple matter is, is that a simple check for a source buffer that is not mapped would have made this particular vulnerability un-exploitable.</p>
<p class="cn" markdown="1">Whilst this is a very bizarre corner case, it goes to show that the lack of sanity checking for the sake of speed can cause all sorts of undesired effects, potentially leading to an exploitable condition.</p>
<p class="cn" markdown="1">Since I can relatively control the size value (based on the allocation bucket) and the source buffer passed into memmove() is always NULL, I can trigger a relative wild write at a semi-controlled location. Sure, not the most amazing primitive, but when the application is installed and running as SYSTEM on 99% of enterprise applications, hackers become motivated.</p>
<p class="cn" markdown="1">A big thanks goes out to [@rohitwas][rohitwas] for his validation of my insanity and [@badd1e][badd1e] for pointing out that the src buffer (be it null or not), needs to be mapped in memory!</p>

<div class="cn" markdown="1">
[rohitwas]: https://twitter.com/rohitwas
[badd1e]: https://twitter.com/badd1e
[badd1enull]: https://twitter.com/badd1e/status/792032651179794432
[niximplimentation]: https://sourceware.org/git/?p=glibc.git;a=blob;f=string/memmove.c#l44
[appleimplimentation]: https://opensource.apple.com/source/BerkeleyDB/BerkeleyDB-6/db/clib/memmove.c
[backwardscopy]: http://stackoverflow.com/questions/22158053/memmove-vs-copying-backwards
</div>
