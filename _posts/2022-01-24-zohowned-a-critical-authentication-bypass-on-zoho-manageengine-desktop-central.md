---
layout: post
title: "ZohOwned :: A Critical Authentication Bypass on Zoho ManageEngine Desktop Central"
date: 2022-01-20 09:00:00 -0500
categories: blog
---

![Desktop Central](/assets/images/zohowned-a-critical-authentication-bypass-on-zoho-manageengine-desktop-central/logo.png "Desktop Central")

On December 3, 2021, [Zoho released a security advisory](https://www.manageengine.com/products/desktop-central/cve-2021-44515-authentication-bypass-filter-configuration.html) under [CVE-2021-44515](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44515) for an authentication bypass in its ManageEngine Desktop Central and Desktop Central MSP products. On December 17, 2021, the FBI published a [flash alert](https://www.ic3.gov/Media/News/2021/211220.pdf) for CVE-2021-44515, including technical details and indicators of compromise (IOCs) used by threat actors. Shortly after, [William Vu](https://twitter.com/wvuuuuuuuuuuuuu) published an [Attackerkb](https://attackerkb.com/topics/rJw4DFI2RQ/cve-2021-44515/rapid7-analysis) entry after doing some static analysis. Meanwhile during the whole of December, I was on holidays!

<!--more-->

Why did this matter? Well, as it turns out I was sitting on a few bugs I had found in Desktop Central when I audited it [back in December 2019](https://srcincite.io/pocs/src-2020-0011.py.txt). One of them, being an authentication bypass and after reading the FBI report I quickly relized we were dealing with the same zeroday!

At the time, I could only exploit the bug to trigger a directory traversal and write a zip file onto the target system (the same bug that was used in the wild). Since I didn't have any vector for exploitation and I already had [CVE-2020-10189](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10189) handy, I decided to leave it alone and include it as part of my [Full Stack Web Attack](/training/) training within module-5 (A zero-day hunt in ManageEngine Desktop Central). I even hinted to a *partial* authentication bypass to some students! ;->

So after coming back from holidays, I decided to give the bug some justice and understand/improve on the attack that the threat actors pulled off. First though, what is it we are dealing with here?

## StateFilter Arbitrary Forward Authentication Bypass Vulnerability

Inside of the `web.xml` file we find the following entry:

```xml
<filter>
  <filter-name>StateFilter</filter-name>
  <filter-class>com.adventnet.client.view.web.StateFilter</filter-class>
</filter>

<filter-mapping>
  <filter-name>StateFilter</filter-name>
  <url-pattern>/STATE_ID/*</url-pattern>
</filter-mapping>
```

Filters are triggered pre-authenticated and often used to validate clientside data such as csrf tokens, sessions, etc. Let's check the `doFilter` method:

```java
/*     */   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
/*     */     try {
/*  41 */       Long startTime = new Long(System.currentTimeMillis());
/*  42 */       request.setAttribute("TIME_TO_LOAD_START_TIME", startTime);
/*  43 */       logger.log(Level.FINEST, "doFilter called for {0} ", ((HttpServletRequest)request).getRequestURI());
/*  44 */       StateParserGenerator.processState((HttpServletRequest)request, (HttpServletResponse)response); // 1
/*  45 */       String forwardPath = ((HttpServletRequest)request).getRequestURI();
/*  46 */       if (!WebClientUtil.isRestful((HttpServletRequest)request) || forwardPath.indexOf("STATE_ID") != -1) { // 8 
/*     */         
/*  48 */         String path = getForwardPath((HttpServletRequest)request); // 9
/*  49 */         RequestDispatcher rd = request.getRequestDispatcher(path); // 10
/*  50 */         rd.forward(request, response); // 11
/*     */       }
/*     */       //...
```

At *[1]* the code calls `stateParserGenerator.processState` with the attacker controlled request:

```java
/*     */   public static void processState(HttpServletRequest request, HttpServletResponse response) throws Exception {
/* 288 */     if (StateAPI.prevStateDataRef.get() != null) {
/*     */       return;
/*     */     }
/*     */     
/* 292 */     Cookie[] cookiesList = request.getCookies();
/* 293 */     if (cookiesList == null)
/*     */     {
/* 295 */       throw new ClientException(2, null);
/*     */     }
/*     */ 
/*     */     
/* 299 */     TreeSet set = new TreeSet(new StateUtils.CookieComparator()); // 2
/* 300 */     String contextPath = request.getContextPath();
/* 301 */     contextPath = (contextPath == null || contextPath.trim().length() == 0) ? "/" : contextPath;
/*     */     
/* 303 */     String sessionIdName = request.getServletContext().getSessionCookieConfig().getName();
/* 304 */     sessionIdName = (sessionIdName != null) ? sessionIdName : "JSESSIONID";
/*     */     
/* 306 */     for (int i = 0; i < cookiesList.length; i++) {
/*     */       //...
/* 316 */       String cookieName = cookie.getName();
/*     */       //...    
/* 334 */       if (cookieName.startsWith("_")) {
/*     */         
/* 336 */         cookiesList[i].setPath(contextPath);
/* 337 */         response.addCookie(cookiesList[i]);
/*     */       }
/* 339 */       else if (cookieName.startsWith("STATE_COOKIE")) {
/*     */         
/* 341 */         set.add(cookiesList[i]); // 3
/*     */       }
/*     */     //...
/* 369 */     if (set.size() == 0) { // 4
/*     */       
/* 371 */       request.setAttribute("STATE_MAP", NULLOBJ);
/* 372 */       if (!WebClientUtil.isRestful(request))
/*     */       {
/* 374 */         throw new ClientException(2, null);
/*     */       }
/*     */       return;
/*     */     }
/* 378 */     Iterator iterator = set.iterator();
/* 379 */     StringBuffer cookieValue = new StringBuffer();
/* 380 */     while (iterator.hasNext()) {
/* 381 */       Cookie currentCookie = (Cookie)iterator.next();
/* 382 */       String value = currentCookie.getValue();
/* 383 */       cookieValue.append(value);
/*     */     } 
/* 385 */     request.setAttribute("PREVCLIENTSTATE", cookieValue.toString());
/* 386 */     Map state = parseState(cookieValue.toString()); // 5
/*     */     //...
/* 388 */     Iterator ite = state.keySet().iterator();
/* 389 */     while (ite.hasNext()) {
/*     */       
/* 391 */       String uniqueId = (String)ite.next();
/* 392 */       Map viewMap = (Map)state.get(uniqueId);
/* 393 */       refIdVsId.put(viewMap.get("ID") + "", uniqueId);
/*     */     } 
/* 395 */     StateAPI.prevStateDataRef.set((state != null) ? state : NULLOBJ);
/* 396 */     if (state != null) {
/*     */       
/* 398 */       if (!WebClientUtil.isRestful(request)) {
/*     */         
/* 400 */         long urlTime = getTimeFromUrl(request.getRequestURI());
/* 401 */         long reqTime = Long.parseLong((String)StateAPI.getRequestState("_TIME")); // 6
/* 402 */         ((Map)state.get("_REQS")).put("_ISBROWSERREFRESH", String.valueOf((urlTime != reqTime && !StateAPI.isSubRequest(request)))); // 7
/*     */       }
```

In order to survive `StateParserGenerator.processState`, the attacker will need to populate the `TreeSet` at *[2]* with a `STATE_COOKIE` at *[3]* so that they don't crash and burn at *[4]*. Also, the attacker needs to use `StateParserGenerator.processState` method at *[5]* to craft a special `state` map containing values to survive *[6]* and *[7]*. There is no way to return null from `StateParserGenerator.parseState`, I already thought of that!

Once the attacker can proceed past `StateParserGenerator.processState`, they can set `forwardPath` at *[8]* with the provided URI and subsequently set `path` at *[9]*

```java
/*     */   private String getForwardPath(HttpServletRequest request) {
/*  88 */     String path = request.getContextPath() + "/STATE_ID/";
/*  89 */     String forwardPath = request.getRequestURI();
/*  90 */     if (!forwardPath.startsWith(path))
/*     */     {
/*  92 */       return forwardPath;
/*     */     }
/*  94 */     int index = forwardPath.indexOf('/', path.length());
/*  95 */     if (WebClientUtil.isRestful(request)) {
/*     */       
/*  97 */       forwardPath = forwardPath.substring(path.length() - 1);
/*     */ 
/*     */     
/*     */     }
/* 101 */     else if (index > 0) {
/*     */       
/* 103 */       forwardPath = forwardPath.substring(index);
/*     */     } 
/*     */ 
/*     */     
/* 107 */     return forwardPath;
/*     */   }
```

Now, the code at *[10]* and *[11]* of the `StateFilter.doFilter` method forwards the incoming request and bypasses any further filters or interceptors within the filter chain. The fact that the forward happens inside of a filter is very powerful, it means that any HTTP verb can be used to reach dangerous API.

## AgentLogUploadServlet Directory Traversal Remote Code Execution Vulnerability 

This particular bug was patched in earlier versions before the `StateFilter` arbitrary forward was patched. As always, we start in the `web.xml` file:

```xml
<servlet>
  <servlet-name>AgentLogUploadServlet</servlet-name>
  <servlet-class>com.adventnet.sym.webclient.statusupdate.AgentLogUploadServlet</servlet-class>
</servlet>

<servlet-mapping>
  <servlet-name>AgentLogUploadServlet</servlet-name>
  <url-pattern>/agentLogUploader</url-pattern>
</servlet-mapping>
```

As the threat actors discovered, it was possible to reach this servlet using the `StateFilter` arbitrary forward:

```java
/*     */   public void doPost(HttpServletRequest request, HttpServletResponse response) {
/*  35 */     reader = null;
/*  36 */     PrintWriter printWriter = null;
/*     */     try {
/*  38 */       computerName = request.getParameter("computerName"); // 1
/*  39 */       String domName = request.getParameter("domainName");
/*  40 */       String customerIdStr = request.getParameter("customerId");
/*  41 */       String resourceidStr = request.getParameter("resourceid");
/*  42 */       String logType = request.getParameter("logType");
/*  43 */       String fileName = request.getParameter("filename"); // 2
/*     */       //... 
/*  66 */       if (managedResourceID != null || branchId != null) {
/*     */         //... 
/*  73 */         String localDirToStore = baseDir + File.separator + wanDir + File.separator + customerIdStr + File.separator + domName + File.separator + computerName; // 3  
/*     */         //... 
/*  84 */         fileName = fileName.toLowerCase();
/*     */         
/*  86 */         if (fileName != null && FileUploadUtil.hasVulnerabilityInFileName(fileName, "zip|7z|gz")) { // 4
/*  87 */           this.logger.log(Level.WARNING, "AgentLogUploadServlet : Going to reject the file upload {0}", fileName);
/*  88 */           response.sendError(403, "Request Refused");
/*     */           
/*     */           return;
/*     */         } 
/*  92 */         String absoluteFileName = localDirToStore + File.separator + fileName; // 5
/*     */         
/*  94 */         this.logger.log(Level.WARNING, "absolute File Name {0} ", new Object[] { fileName });
/*     */ 
/*     */         
/*  97 */         in = null;
/*  98 */         fout = null;
/*     */         try {
/* 100 */           in = request.getInputStream();
/* 101 */           fout = new FileOutputStream(absoluteFileName);
/*     */           
/* 103 */           byte[] bytes = new byte[10000]; int i;
/* 104 */           while ((i = in.read(bytes)) != -1) {
/* 105 */             fout.write(bytes, 0, i); // 6
/*     */           }
/* 107 */           fout.flush();
/* 108 */         } catch (Exception e1) {
/* 109 */           e1.printStackTrace();
/*     */         } finally {
/* 111 */           if (fout != null) {
/* 112 */             fout.close();
/*     */           }
/* 114 */           if (in != null) {
/* 115 */             in.close();
/*     */           }
/*     */         } 
```

At *[1]* and *[2]* the code gets the `computerName` and `filename` parameters from the incoming request and then at *[3]* the code builds a path using the controlled `computerName`. Then at *[4]* the code calls `FileUploadUtil.hasVulnerabilityInFileName` using `zip|7z|gz` as a filter:

```java
/*     */   public static boolean hasVulnerabilityInFileName(String fileName, String allowedFileExt) {
/* 227 */     if (isContainDirectoryTraversal(fileName) || isCompletePath(fileName) || !isValidFileExtension(fileName, allowedFileExt)) {
/* 228 */       return true;
/*     */     }
/* 230 */     return false;
/*     */   }
```

The code checks that the file extension is either zip, 7z or gz with a check for a traversal but there is no check for a traversal in the `localDirToStore` at *[5]* which is later used for a controlled write at *[6]*. 

### Patches

Zoho patched the arbitrary forward by adding the URI pattern to a secured context, meaning that authentication is required which was verified on version `10.1.2137.3`

```
<security-constraint>
 <web-resource-collection>
     <web-resource-name>Secured Core Context</web-resource-name>
     ...
+     <url-pattern>/STATE_ID/*</url-pattern>
 </web-resource-collection>
```

Zoho also patched the directory traversal in `AgentLogUploadServlet` somewhere between May - November 2021. The additional check in the `doPost` protecting `computerName` which was verified on version `10.1.2137.2`:

```java
/*  67 */       if ((domName != null && FileUploadUtil.hasVulnerabilityInFileName(domName)) || (computerName != null && FileUploadUtil.hasVulnerabilityInFileName(computerName)) || (customerIdStr != null && FileUploadUtil.hasVulnerabilityInFileName(customerIdStr)) || (branchId != null && FileUploadUtil.hasVulnerabilityInFileName(branchId)) || 
/*  68 */         !SoMUtil.getInstance().isValidDomainName(domName) || !SoMUtil.getInstance().isValidComputerName(computerName) || !branchId.matches(regex) || !resourceidStr.matches(regex) || !customerIdStr.matches(regex)) {
/*     */         
/*  70 */         this.logger.log(Level.WARNING, "AgentLogUploadServlet : Going to reject the file upload {0} for  computer  {1}  under domain {2} and branch office {4} of customer id {3} ", new Object[] { fileName, computerName, domName, customerIdStr, branchId });
/*  71 */         response.sendError(403, "Request Refused");
/*     */         
/*     */         return;
/*     */       }
```

## Exploitation

At the time of discovery, I couldn't leverage this bug and after reading the FBI report, it becomes evident that the threat actors wrote a zip file into the `C:\Program Files\DesktopCentral_Server\lib` directory and either waited for the server to restart or forced a restart.

![Loading a zip from the lib directory](/assets/images/zohowned-a-critical-authentication-bypass-on-zoho-manageengine-desktop-central/libload.png "Loading a zip from the lib directory") 

In fact, it can be *any* extension and it clearly not mentioned in the [Tomcat documentation](https://tomcat.apache.org/tomcat-7.0-doc/class-loader-howto.html)! This inturn loaded a malicious jar file (hidden as a zip file) which overwrote core classes. When those classes were loaded from the server/process upon a restart, then their code would execute.

The threat actors also used the `/fos/statuscheck` endpoint which safety returned the string `OK` if the server was up.

![Checking the status of the server](/assets/images/zohowned-a-critical-authentication-bypass-on-zoho-manageengine-desktop-central/status.png "Checking the status of the server") 

```java
/*    */   private void processRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
/*    */     try {
/* 33 */       String slaveId = ServletUtil.Param.optionalValue(request, "slaveId");
/* 34 */       if (MonitorPool.isEnabled())
/*    */       {
/* 36 */         if (slaveId != null)
/*    */         {
/* 38 */           MonitorPool.getInst().getOrCreate(slaveId).updateLastAccessTime();
/*    */         }
/*    */       }
/* 41 */       ServletUtil.Write.text(response, "ok");
/*    */     }
/*    */   //...
/*    */   }
/*    */ }
```

With that, I decided to look into the code to find locations to where the process and/or server could be restarted with an API that was reachable from the `StateFilter` arbitrary forward but I was unsuccessful in this attempt.

## Attack chain limitations

There are 4 main limitations with the attack chain used by the threat actors:

1. The `StateFilter` arbitrary forward is *only* a partial authentication bypass. It's possible to reach the servlet endpoints, but not possible to reach any of the REST api or struts ActionForward classes. This is a significate weakness in the attack.

2. The `AgentLogUploadServlet` directory traversal only gave an attacker the ability to write a 7z, zip, or gz file.

3. The `AgentLogUploadServlet` directory traversal was patched in an earlier version than the `StateFilter` arbitrary forward, meaning there are versions where the chain was broken

4. The attack chain required the server to be restarted which, AFAIK was not possible to be directly controlled by the threat actor.

## Bypassing all limitations

I finally managed to find a better way to (ab)use the `StateFilter` arbitrary forward by reaching the `ChangeAmazonPasswordServlet`. At first I ignored this servlet because I thought, what's the point of changing an Amazon password anyway.

```java
/*    */ public class ChangeAmazonPasswordServlet
/*    */   extends HttpServlet
/*    */ {
/* 23 */   private Logger logger = Logger.getLogger(ChangeAmazonPasswordServlet.class.getName());
/*    */ 
/*    */ 
/*    */   
/*    */   protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
/* 28 */     String loginName = request.getParameter("loginName");
/*    */     
/*    */     try {
/* 31 */       String productCode = ProductUrlLoader.getInstance().getValue("productcode");
/*    */       
/* 33 */       String newUserPassword = request.getParameter("newUserPassword");
/*    */       
/* 35 */       SYMClientUtil.changeDefaultAwsPassword(loginName, newUserPassword); // 1
``` 

At *[1]* the code calls `SYMClientUtil.changeDefaultAwsPassword` using the attacker supplied `loginName` and `newUserPassword`:

```java
/*     */   public static void changeDefaultAwsPassword(String loginName, String newPasswd) throws Exception {
/*     */     try {
/* 139 */       String serviceName = getServiceName(loginName);
/*     */       
/* 141 */       DMUserHandler.addOrUpdateAPIKeyForLoginId(DMUserHandler.getLoginIdForUser(loginName));
/*     */       
/* 143 */       AuthUtil.changePassword(loginName, serviceName, newPasswd); // 2
/* 144 */       SyMUtil.updateSyMParameter("IS_PASSWORD_CHANGED", "true");
/* 145 */       SyMUtil.updateServerParameter("IS_AMAZON_DEFAULT_PASSWORD_CHANGED", "true");
/*     */     }
```

When I saw *[2]* I got very suspicious because I saw `AuthUtil.changePassword`. When I was auditing previously, I remember seeing that function used for other password reset functionality so I decided to do a quick xref on it:

![Other functions that call changePassword](/assets/images/zohowned-a-critical-authentication-bypass-on-zoho-manageengine-desktop-central/changePassword.png "Other functions that call changePassword") 

*Could this code change the admin password from an unauthenticated context?*

![Changing the admin password unauthenticated](/assets/images/zohowned-a-critical-authentication-bypass-on-zoho-manageengine-desktop-central/haxed.png "Changing the admin password unauthenticated")

Now that we have changed the password we can login and access any agents within Desktop Central to gain remote code execution against them:

![Accessing agents that are connected to Desktop Central](/assets/images/zohowned-a-critical-authentication-bypass-on-zoho-manageengine-desktop-central/agent-access.png "Accessing agents that are connected to Desktop Central")

![Popping a SYSTEM shell over the web interface](/assets/images/zohowned-a-critical-authentication-bypass-on-zoho-manageengine-desktop-central/agent-shell.png "Popping a SYSTEM shell over the web interface")

This exploit chain impacts all versions up to `10.1.2137.2`. It's still possible to reset the admin password and/or trigger the `StateFilter` arbitrary forward using a **guest** account in the [latest version](/advisories/src-2022-0002/) at the time of writing, because I have a habit of not reporting vulnerabilities to Zoho, oh no!

![Changing the admin password as a guest user on the latest version (10.1.2138.1)](/assets/images/zohowned-a-critical-authentication-bypass-on-zoho-manageengine-desktop-central/haxed-as-guest.png "Changing the admin password as a guest user on the latest version (10.1.2138.1)")

The only limitation to this atatck is that changing the administrators password is pretty overt, and will likley reveal that a compromise took place.

## Conclusion

Threat actors, up your game! If you are stuck on a bug, come back to it with a fresh mind even if its been years. As a professional engineer, you develop your skillset slowly and sometimes it's important to check code that doesn't seem relevant. 

This is not the first time [I have written](/blog/2020/04/17/strike-three-symlinking-your-way-to-unauthenticated-access-against-cisco-ucs-director.html#authentication-bypass) about arbitrary forward vulnerabilities that lead to authentication bypass and it's likley that threat actors are reading this very blog.

A big thanks goes to William Vu for listening to me live debug this application and allowing me to ask him many questions along the way.

## References

- [https://attackerkb.com/topics/rJw4DFI2RQ/cve-2021-44515/rapid7-analysis](https://attackerkb.com/topics/rJw4DFI2RQ/cve-2021-44515/rapid7-analysis)
- [https://pitstop.manageengine.com/portal/en/community/topic/an-authentication-bypass-vulnerability-identified-and-fixed-in-desktop-central-and-desktop-central-msp](https://pitstop.manageengine.com/portal/en/community/topic/an-authentication-bypass-vulnerability-identified-and-fixed-in-desktop-central-and-desktop-central-msp)
- [https://www.ic3.gov/Media/News/2021/211220.pdf](https://www.ic3.gov/Media/News/2021/211220.pdf)