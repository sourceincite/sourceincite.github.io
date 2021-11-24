---
layout: post
title: "Unlocking the Vault :: Unauthenticated Remote Code Execution against CommVault Command Center"
date: 2021-11-22 09:00:00 -0500
categories: blog
---

When [Justin Kennedy](https://twitter.com/jstnkndy) and [Brandon Perry](https://twitter.com/BrandonPrry) asked me if I was interested in performing a little audit together, I couldn't resist. Although time was limited, I decided to jump on board because true hacking collaboration is a rare commoditity these days.

<!--more-->

We decided to target the [CommVault Command Center Interface](https://documentation.commvault.com/commvault/v11/article?p=103135.htm) and to quote CommVault:

> The Command Center is a web-based user interface for administration tasks that provides default configuration values and streamlined procedures for routine data protection and recovery tasks. You can use the Command Center to set up your data protection environment, to identify content that you want to protect, and to initiate and monitor backups and restores.

This is an interesting target because:

1. It's a product that incorporates [several components](https://documentation.commvault.com/commvault/v11/article?p=111918.htm) (CommCell Console, Command Center, Web Console, CommServe Server, etc).
1. There was a serious lack of decent vulnerabilities in CommVault. The only recent bug I could dig up was [CVE-2020-25780](https://kb.commvault.com/article/63264) which was a post authenticated directory traversal with a disclosure impact and no proof of concept.
2. There is a mix of technologies from C# to Java which made it quite attractive to audit.

After some time, we managed to chain 3 bugs (disclosed as two bugs - [ZDI-21-1328](https://www.zerodayinitiative.com/advisories/ZDI-21-1328/) and [ZDI-21-1331](https://www.zerodayinitiative.com/advisories/ZDI-21-1331/)) to achieve unauthenticated remote code execution as SYSTEM against a target CommVault node.

## CVAuthHttpModule OnEnter Partial Authentication Bypass

Inside of the `CVInfoMgmtService.dll` file the `CVAuthHttpModule.OnEnter` method is the authentication check for the `CVSearchService` web service:

```c#
private void OnEnter(object sender, EventArgs e)
{
    bool flag = true;
    this.reject = true;
    string empty = string.Empty;
    bool flag2 = true;
    this._token = "";
    this._sw = Stopwatch.StartNew();
    this._request = "";
    try
    {
        string[] array = CVAuthHttpModule.readHeader();
        string text = array[0]; // 1
        string text2 = array[1];
        string text3 = array[2];
        string text4 = array[3];
        bool flag3 = this.IsRestWebService(); // 2
        ...
        bool flag11 = !string.IsNullOrEmpty(text) && !flag3 && NonSecureOperations.canByPassCheck(text); // 3
        if (flag11)
        {
            flag = false;
            this.reject = false;
        ...
```

At *[1]* the `text` is coming from the cookie header and at *[2]* the code checks that the request is for the `CVSearchService.svc` service then we can see the `NonSecureOperations.canByPassCheck` at *[3]*.

```c#
public static bool canByPassCheck(string messageName)
{
    string item = dmConf.encodePass(messageName); // 4
    return NonSecureOperations.list.Contains(item); // 5
}
```

The `dmConf.encodePass` call at *[4]*:

```c#
// DM2WebLib.dmConf
// Token: 0x060000E8 RID: 232 RVA: 0x00006C10 File Offset: 0x00004E10
public static string encodePass(string dataTobeEncoded)
{
	string text = string.Empty;
	bool flag = string.IsNullOrEmpty(dataTobeEncoded);
	string result;
	if (flag)
	{
		result = dataTobeEncoded;
	}
	else
	{
		try
		{
			byte[] inArray = new byte[dataTobeEncoded.Length];
			inArray = Encoding.UTF8.GetBytes(dataTobeEncoded);
			text = Convert.ToBase64String(inArray);
		}
		catch (Exception ex)
		{
			throw new Exception(string.Format("Error in base64Encode. Exception Message:[{0}], Data to be decoded:[{1}] ", ex.Message, dataTobeEncoded));
		}
		result = text;
	}
	return result;
}
```

...and the `NonSecureOperations` constructor at *[5]*:

```c#
static NonSecureOperations()
{
    NonSecureOperations.list = new ArrayList();
    NonSecureOperations.list.Add("TG9naW4uR2V0TG9nb25MaXN0");
    NonSecureOperations.list.Add("TG9naW4uTG9naW4=");
    NonSecureOperations.list.Add("Q0kuR2V0RE1TZXR0aW5n");
    NonSecureOperations.list.Add("TG9naW4=");
    NonSecureOperations.list.Add("Q0kuR2V0RE1TZXR0aW5ncw==");
    NonSecureOperations.list.Add("UmV0cmlldmVJdGVt");
    NonSecureOperations.list.Add("U2VhcmNoLkdldFBhbmVsQ29sdW1uQ29uZmln");
    NonSecureOperations.list.Add("RGF0YVNlcnZpY2UuUG9wdWxhdGVEYXRh");
    NonSecureOperations.list.Add("Z2V0T2VtSWQ=");
    NonSecureOperations.list.Add("TG9naW4uV2ViQ2xpZW50TG9naW4=");
    NonSecureOperations.list.Add("Z2V0R2xvYmFsUGFyYW0=");
}
```

1. Login.GetLogonList
2. Login.Login
3. CI.GetDMSetting
4. Login
5. CI.GetDMSettings
6. RetrieveItem
7. Search.GetPanelColumnConfig
8. DataService.PopulateData
9. getOemId
10. Login.WebClientLogin
11. getGlobalParam

This just encodes the cookie as base64 and checks it against a list of hardcoded strings. So I just set the first one as `Login.GetLogonList` which matches on `TG9naW4uR2V0TG9nb25MaXN0`. Now the `this.reject` is set to false and we can bypass the auth for this web service!

## CVSearchSvc downLoadFile File Disclosure

As it turns out, there is a file disclosure vulnerability in the API for this service. Let's check the `CVSearchSvc` class:

```c#
public byte[] downLoadFile(string path)
{
    DownLoad downLoad = new DownLoad();
    return downLoad.downLoadFile(path); // 4
}
```

At *[4]* the code calls `com.commvault.biz.restore.DownLoad.downLoadFile` with the attacker controlled `path`:

```c#
public byte[] downLoadFile(string path)
{
    bool flag = string.IsNullOrEmpty(path);
    byte[] result;
    if (flag)
    {
        result = null;
    }
    else
    {
        bool flag2 = !File.Exists(path);
        if (flag2)
        {
            result = null;
        }
        else
        {
            FileInfo fileInfo = new FileInfo(path);
            long length = fileInfo.Length;
            FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Read);
            BinaryReader binaryReader = new BinaryReader(fileStream);
            byte[] array = binaryReader.ReadBytes((int)length);
            binaryReader.Close();
            fileStream.Close();
            result = array;
        }
    }
    return result;
}
```

Which opens the attacker supplied file path for reading and returns the contents of the file. This can be a binary file because the response is base64 encoded and returned to the attacker. 

## Exploitation

At this point we essentially had an unauthenticated file read vulnerability. How were we going to leverage this for remote code execution or an authentication bypass? It was a limited file read as we could only read files with the permissions of the network service account. Due to this, we couldn't open files that already had an open file handle in another process. It was grim.

![For the better right](/assets/images/unlocking-the-vault/right.jpg "Surely we're safe, right?")

A few days later, Brandon came up with a clever exploitation strategy. When he was configuring and testing the email server, he noticed that when he tried to reset the password for the `SystemCreatedAdmin` account, it would throw an error into the `c:/Program Files/Commvault/ContentStore/Log Files/WebServer.log` file:

```
4424  3     05/13 17:00:37 3   ###  - Processing [POST] request : /user/Password/ForgotRequest : Headers :[Content-Type=application/x-www-form-urlencoded][Expect=100-continue][Host=127.0.0.1:81][Content-Length=50][locale=en_US][LookupNames=false][client-location=192.168.1.152][CVRequestRouted=true][MS-ASPNETCORE-TOKEN=cba64f3f-885a-4d1e-bcfe-cbda5c6e5e19][X-Original-Proto=http][trace-id=wse7e5af76c93c][X-Original-For=127.0.0.1:51285] : Parameters : (empty) : AdditionalInfo[ClientIP[192.168.1.152] ConsoleType[Unknown] Operation[CV.WebServer.Controllers.UserController.ForgotPasswordRequest (CVWebControllerClient)] isTokenSupplied?[False] Username[]]
4424  3     05/13 17:00:38 3   ### SetTinyWebConsoleTinyUrl - Error sending reset password email with tinyURL : http://WIN-9BHJU583I26:80/webconsole/gtl.do?gid=sqmyEqVeOftkV
4424  3     05/13 17:00:43 3   ### SendResetPasswordEmail - Reset password email set successfully to: 
4424  3     05/13 17:00:43 3   ### Invoke - POST /user/Password/ForgotRequest : HTTP code 'OK'
```

This occured because the default god mode user `SystemCreatedAdmin` didn't have an email account linked by design and so the developers thought it would be convenient to drop the password reset token into the log file. With our file disclosure vulnerability we could leak this log file and disclose the password reset token (`sqmyEqVeOftkV` in this case) so that we could reset the `SystemCreatedAdmin` password and gain access to the Command Center. 

Once this was achieved, we found that we could execute workflows with, low and behold, a default workflow that allowed for a command to be executed as SYSTEM!

![Unlocking the CommVault](/assets/images/unlocking-the-vault/poc.png "Achieving unauthenticated remote code execution!") 

We have [released a proof of concept](/pocs/cve-2021-{34993,34996}.py.txt) for your defending pleasure.

## Conclusion

These aren't the only issues we discovered, but only the ones we had time to focus on and submit since they were the highest impact. Sure enough, KP Choubey also discovered [ZDI-21-1332](https://www.zerodayinitiative.com/advisories/ZDI-21-1332/) when analyzing our bugs.