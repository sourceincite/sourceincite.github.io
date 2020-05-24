---
layout: training
title: Training
permalink: /training/
---

<script>
// Set the date we're counting down to
var countDownDate = new Date("Aug 3, 2020 09:00:00").getTime();

// Update the count down every 1 second
var x = setInterval(function() {

  // Get today's date and time
  var now = new Date().getTime();

  // Find the distance between now and the count down date
  var distance = countDownDate - now;

  // Time calculations for days, hours, minutes and seconds
  var days = Math.floor(distance / (1000 * 60 * 60 * 24));
  var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
  var seconds = Math.floor((distance % (1000 * 60)) / 1000);

  // Display the result in the element with id="demo"
  document.getElementById("demo").innerHTML = "<p class='cn'>It's " + days + " days " + hours + " hours "
  + minutes + " minutes and " + seconds + " seconds until the next training!</p>";

  // If the count down is finished, write some text
  if (distance < 0) {
    clearInterval(x);
    document.getElementById("demo").innerHTML = "EXPIRED";
  }
}, 1000);
</script>

## Full Stack Web Attack

---

<p id="demo"></p>

<p class="cn" markdown="1">**Full Stack Web Attack** is *not* an entry-level course. It's designed to push you beyond what you thought was possible and set you on the path to develop your own workflow for offensive zero-day web research.</p>
{% include imageright.html
            img="assets/images/training.png"
            style="width:50%;height:50%;float:right;"
            %}
<p class="cn" markdown="1">This course is developed for web penetration testers, bug hunters and developers that want to make a switch to server-side web security research or see how serious adversaries will attack their web based code.</p>

<p class="cn" markdown="1">Students are expected to know how to use [Burp Suite](https://portswigger.net/burp) and have a basic understanding of common web attacks as well as perform basic scripting using common languages such as python, PHP and JavaScript. Each of the vulnerabilities presented have either been mirrored from real zero-day or are n-day bugs that have been discovered by the author with a focus on not just exploitation, but also on the discovery.</p>

<p class="cn" markdown="1">So if you want to learn how to exploit web technologies without client interaction for maximum impact, that is, remote code execution then this is the course for you.</p>

<p class="cn" markdown="1">Leave your OWASP Top Ten and CSP bypasses at the door.</p>

### <a id="structure"></a> Course Structure

<div markdown="1" class="cn">
- Duration: 4 days
- Language: English
- Hours: 9am - 5pm*
- Lunch break: 12.30pm for 1 hour
- Coffee break: 10.30am for 10 minutes
- Coffee break: 3.15pm for 10 minutes
</div>

<p class="cn" markdown="1">* The day to day hours maybe extended at the descretion of the trainer and students.</p>

### <a id="where"></a> When and Where

<p class="cn" markdown="1">We have three (3) public trainings for Full Stack Web Attack in 2020. **Please note that syllabus may change anytime, so an accurate syllabus can be found [here](/training/#syllabus).**</p>

#### USA:

<p class="cn" markdown="1">We are offering two (2) trainings in the USA as part of an agreement with the [Center for Cyber Security Training](https://ccsecuritytraining.com/center-for-cyber-security-training-signs-exclusive-partnership-with-leading-training-provider-source-incite/).</p>

<div markdown="1" class="cn">
- Registration: [https://ccsecuritytraining.com/registration/](https://ccsecuritytraining.com/registration/)
- Details: [https://ccsecuritytraining.com/training/source-incites-full-stack-web-attack/](https://ccsecuritytraining.com/training/source-incites-full-stack-web-attack/)
</div>

<p markdown="1" class="cn">**East Coast**</p>

<div markdown="1" class="cn">
- Location: 10480 Little Patuxent Pkwy #700 Columbia, MD 21044
- Date: **February the 24th - 27th 2020**
</div>

<p markdown="1" class="cn">**West Coast**</p>

<div markdown="1" class="cn">
- Location: 33 New Montgomery Street San Francisco, CA 94105
- Date: **December the 1st - 4th 2020**
</div>

### Certification

```java
javax.servlet.ServletException: java.lang.NullPointerException
    com.source.incite.FullStackWebAttack.certification(FullStackWebAttack.java:38) 
    org.apache.struts.action.RequestProcessor.processActionPerform(RequestProcessor.java:425) 
    org.apache.struts.action.RequestProcessor.process(RequestProcessor.java:228) 
    org.apache.struts.action.ActionServlet.process(ActionServlet.java:1913) 
    org.apache.struts.action.ActionServlet.doPost(ActionServlet.java:462) 
```

<p class="cn" markdown="1">We apologise in advance but we do not offer any certifications.</p>

### Instructor

<p class="cn" markdown="1">Steven Seeley ([@steventseeley](https://twitter.com/steventseeley)) is an internationally recognized security researcher and trainer. For the last four years, Steven has reached platinum status with the [ZDI](https://www.zerodayinitiative.com/about/benefits/) and has literally found over a thousand high impact vulnerabilities, some of which can be found under the [advisories](/advisories/) section.</p>

### Student Requirements

<div markdown="1" class="cn">
- At least basic scripting skills (moderate or advanced skills are *prefered*)
- At least a basic understanding of various web technologies such as HTTP(S), proxies and browsers
</div>

### Hardware Requirements

<div markdown="1" class="cn">
- A 64bit Host operating system
- 16 Gb RAM minimum
- VMWare Workstation/Fusion
- 100 Gb Hard disk free minimum
- Wired and Wireless network support
- USB 3.0 support
</div>

### <a id="syllabus"></a> Syllabus *

<p class="cn" markdown="1">*** This syllabus is subject to change at the discretion of the instructor.**</p>

<div markdown="1" class="cn">

#### Day 0x01

*Introduction*

- PHP & Java language fundamentals
- Debugging PHP & Java applications
- Module overview and required background knowledge
- Auditing for zero-day vulnerabilities

*PHP*

- Loose typing
- Logic authentication bypasses
- Code injection
- Filter bypass via code reuse
- Patch bypass

### Day 0x02

*Java*

- Java Remote Method Invocation (RMI)
  - Java Remote Method Protocol (JRMP)
- Java naming and directory interface (JNDI) injection
  - Remote class loading
  - Deserialization 101 (using existing gadget chains)

*PHP*

- Introduction to object instantiation
- Introduction to protocol wrappers
- External entity (XXE) injection
  - Regular file disclosure
  - Blind out-of-band attacks
    - Error based exfiltration using entity overwrites
    - Exfiltration using protocols

### Day 0x03

*PHP*

- Patch analysis and bypass
- Introduction to object injection
- Magic methods
  - Customized serialization
  - Phar deserialization
  - Property oriented programming (POP)
  - Custom gadget chain creation
- Information disclosure
- Phar planting
- Building a 7 stage exploit chain for Remote Code Execution

### Day 0x04

*PHP*

- Blacklist bypasses (zero-day vulnerability analysis and exploitation)

*Java*

- Introduction to reflection
- Expression language injection
- Bypassing URI filters
- URI forward authentication bypasses (zero-day technique)
- Deserialization 102 (custom gadget chains)
  - Trampoline gadgets
  - Exploiting reflection
  - Whitelist (ab)use
- A zero-day bug hunt in a real target

</div>

### Testimonials

> <p class="cn" markdown="1">*"I recommend @steventseeley's Full Stack Web Attack from @sourceincite. I know it's going to be offered a few times next year, you should take it! It's training unlike anything else. I am excited to put my newly found skills to work. Awesome stuff!"*</p>

<p class="cn" markdown="1">- [@awhitehatter](https://twitter.com/awhitehatter/status/1180120923816386561)</p>

> <p class="cn" markdown="1">*"Just finished an amazing training course with @steventseeley - Full Stack Web Attack @sourceincite. I highly recommend it if you wanna take your php, java, and general web exploitation skills to the next level."*</p>

<p class="cn" markdown="1">- [@kiqueNissim](https://twitter.com/kiqueNissim/status/1179908013601251328)</p>

> <p class="cn" markdown="1">*"It was a great course, I think is one of the best I ever had, I liked how Steven always explained each exercise very well and clarified any doubts. Essentially I'm very happy to have taken this course and I will recommend it to my collegues for the next year. Thanks Steven!"*</p>

<p class="cn" markdown="1">- Anonymous</p>

> <p class="cn" markdown="1">*"GREAT course man! thank you SO much!"*</p>

<p class="cn" markdown="1">- Anonymous</p>

> <p class="cn" markdown="1">*"try harder, thanks mr_m3"*</p>

<p class="cn" markdown="1">- Anonymous</p>

> <p class="cn" markdown="1">*"It was very inspiring to see your strategy, way of thinking and searching through code. That is even more valuable than the vulnerabilities themselves. It was possibly one of the most challenging trainings, I took, in a good way."*</p>

<p class="cn" markdown="1">- Anonymous</p>

#### FAQ

<p class="cn" markdown="1">*Why are you only offering 3 public trainings this year?*</p>

<p class="cn" markdown="1">**Our primary business is vulnerability research and exploitation. Course content is derived from such research and in order to provide a training that covers *bleeding edge attack techniques* the instructor needs to continually improve their skills.**</p>

<p class="cn" markdown="1">*Why are you not offering a training in Mexico?*</p>

<p class="cn" markdown="1">**This year we are offering two (2) trainings in the USA and believe this services the American market. However, if demand increases, we may offer a Mexican based training for 2020.**</p>

<p class="cn" markdown="1">*Can I get a discount?*</p>

<p class="cn" markdown="1">**No.**</p>

<p class="cn" markdown="1">*Do you offer private trainings?*</p>

<p class="cn" markdown="1">**Yes, on a case by case basis. For private trainings in the USA please contact the [Center for Cyber Security Training](https://ccsecuritytraining.com/contact-us/). For all other countries please contact [training@](mailto:training@srcincite.io).**</p>

#### Additional Material

<p class="cn" markdown="1">The madness doesn't stop. Preconfigured environments will be provided for additional work after class ends for the rediscovery and exploitation of n-day vulnerabilities.</p>
