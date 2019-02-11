---
layout: training
title: Training
permalink: /training/
---

<style type="text/css">
.countdown {
  width: 100%;
  float: left;
  margin: 20px auto;
}
</style>

<script>
function countdown(dateEnd) {
  var timer, days, hours, minutes, seconds;
  dateEnd = new Date(dateEnd);
  dateEnd = dateEnd.getTime();
  if ( isNaN(dateEnd) ) {
    return;
  }
  timer = setInterval(calculate, 1000);
  function calculate() {
    var dateStart = new Date();
    var dateStart = new Date(dateStart.getUTCFullYear(),
                             dateStart.getUTCMonth(),
                             dateStart.getUTCDate(),
                             dateStart.getUTCHours(),
                             dateStart.getUTCMinutes(),
                             dateStart.getUTCSeconds());
    var timeRemaining = parseInt((dateEnd - dateStart.getTime()) / 1000)
    if ( timeRemaining >= 0 ) {
      days    = parseInt(timeRemaining / 86400);
      timeRemaining   = (timeRemaining % 86400);
      hours   = parseInt(timeRemaining / 3600);
      timeRemaining   = (timeRemaining % 3600);
      minutes = parseInt(timeRemaining / 60);
      timeRemaining   = (timeRemaining % 60);
      seconds = parseInt(timeRemaining);
      document.getElementById("days").innerHTML    = parseInt(days, 10);
      document.getElementById("hours").innerHTML   = ("0" + hours).slice(-2);
      document.getElementById("minutes").innerHTML = ("0" + minutes).slice(-2);
      document.getElementById("seconds").innerHTML = ("0" + seconds).slice(-2);
    } else {
      return;
    }
  }
  function display(days, hours, minutes, seconds) {}
}
countdown('10/1/2019 09:00:00 AM');
</script>

## Full Stack Web Attack

---

<div class="countdown">
  <p class="cn">
    It's
    <span id="days"></span>
    days,
    <span id="hours"></span>
    hours,
    <span id="minutes"></span>
    minutes,
    <span id="seconds"></span>
    and seconds until the training begins!
  </p>
</div>

<p class="cn" markdown="1">**Full Stack Web Attack** is *not* an entry-level course. It's designed to push you beyond what you thought was possible and set you on the path to develop your own workflow for offensive zero-day web research.</p>
{% include imageright.html
            img="assets/images/hax.jpg"
            style="width:30%;height:30%"
            %}
<p class="cn" markdown="1">This course is developed for web penetration testers, bug hunters and developers that want to make a switch to server-side web security research or see how serious adversaries will attack their web based code.</p>

<p class="cn" markdown="1">Students are expected to know how to use [Burp Suite](https://portswigger.net/burp) and have a basic understanding of common web attacks as well as perform basic scripting using common languages such as python, PHP and JavaScript. Each of the vulnerabilities presented have either been mirrored from real zero-day or are n-day bugs that have been discovered by the author with a focus on not just exploitation, but also on the discovery.</p>

<p class="cn" markdown="1">So if you want to learn how to exploit web technologies without client interaction for maximum impact, that is, remote code execution then this is the course for you.</p>

<p class="cn" markdown="1">Leave your OWASP Top Ten and CSP bypasses at the door.</p>

#### <a name="where"></a> When and Where

<p class="cn" markdown="1">The 3 day training course will take place on October the 1st, 2nd and 3rd of 2019 at [the room](https://theroom.mx/) in Polanco, Mexico City.</p>

```
Av. Homero s/n frente al 1730, entre Jaime Balmes y Luis Vives.
Planta baja de Corporativo Polanco.
Miguel Hidalgo
Los Morales Polanco
CP 11510 Ciudad de México.
```

<p class="cn" markdown="1">You can use [Google Maps](https://www.google.com/maps/place/The+Room+Polanco+-+El+lugar+de+tus+eventos/@19.436942,-99.20973,16z/data=!4m5!3m4!1s0x0:0xf355886c37a4fd72!8m2!3d19.4369424!4d-99.2097305?hl=en-US) for the exact location of the venue. When coming via an Uber or taxi, just state you would like to go to **Avenida Homero numero un mil siete centos trenta en polcano, se llama The Room**. Don't worry if you don't speak a little Spanish, the hotel concierges all speak English.</p>

#### <a name="hotel"></a> Hotels and Accomodation

<p class="cn" markdown="1">The two hotels we recommend are approximately 10 minute’s drive with an Uber or taxi. The cost of ride to and from the venue should be approximately $5 USD. Walking is possible, but it will take approximately 25 - 30 minutes.</p>

<div class="cn" markdown="1">
- [The W Hotel](https://www.marriott.com/reservation/rateListMenu.mi?defaultTab=prepay)
- [The Intercontinental](https://www.ihg.com/intercontinental/hotels/us/en/mexico/mexha/hoteldetail)
</div>

#### Certification

```java
javax.servlet.ServletException: java.lang.NullPointerException
    com.source.incite.FullStackWebAttack.certification(FullStackWebAttack.java:38) 
    org.apache.struts.action.RequestProcessor.processActionPerform(RequestProcessor.java:425) 
    org.apache.struts.action.RequestProcessor.process(RequestProcessor.java:228) 
    org.apache.struts.action.ActionServlet.process(ActionServlet.java:1913) 
    org.apache.struts.action.ActionServlet.doPost(ActionServlet.java:462) 
```

#### Tickets

<p class="cn" markdown="1">Tickets can be purchased [here](https://www.eventbrite.com/e/full-stack-web-attack-fswa-training-course-2019-tickets-55039278965). Please note that the course is limited to maximum of 20 seats to ensure a high quality deliverable.</p>

#### Instructor

<p class="cn" markdown="1">Steven Seeley ([@steventseeley](https://twitter.com/steventseeley)) is an internationally recognized security researcher and trainer. For the last three years, Steven has reached platinum status with the [ZDI](https://www.zerodayinitiative.com/about/benefits/) and has literally found over a thousand high impact vulnerabilities, some of which can be found under the [advisories](/advisories/) section.</p>

#### Student Requirements

<div markdown="1" class="cn">
- At least basic scripting skills
- At least a basic understanding of various web technologies such as HTTP(S), proxies and browsers
</div>

#### Hardware Requirements

<div markdown="1" class="cn">
- A 64bit Host operating system
- 16 Gb RAM minimum
- VMWare Workstation/Fusion
- 60 Gb Hard disk free minimum
- Wired and Wireless network support
- USB 3.0 support
</div>

#### Syllabus *

<div markdown="1" class="cn">

- Introduction
  - PHP & Java language fundamentals
  - Debugging PHP & Java applications
  - Auditing for zero-day vulnerabilities

</div>

<div markdown="1" class="cn">

- Java/PHP Authentication Bypass
  - Bypassing URI filters
  - Leveraging unauthenticated redirection
  - Type juggling security boundaries
  - Pass the hash login

</div>

<div markdown="1" class="cn">

- High Impact Information Disclosure
  - File disclosure
  - SQL injection
  - External entity injection

</div>

<div markdown="1" class="cn">

- Remote Code Execution
  - Java deserialization
  - Directory traversal
  - PHP object instantiation
  - PHP object injection

</div>

<p class="cn" markdown="1">* This syllabus is subject to change at the discretion of the instructor</p>

#### Additional Material

<p class="cn" markdown="1">The madness doesn't stop. Preconfigured environments will be provided for additional work after class ends for the rediscovery and exploitation of n-day vulnerabilities.</p>