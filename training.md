---
layout: training
title: Training
permalink: /training/
---

## Full Stack Web Attack

---

**Full Stack Web Attack** is *not* an entry-level course. It's designed to push you beyond what you thought was possible and set you on the path to develop your own workflow for offensive zero-day web research.

![Full chain exploit development is taught in class](/assets/images/training/msf.png "Full chain exploit development is taught in class"){: style="float: right"}

This course is developed for web penetration testers, bug hunters and developers that want to make a switch to server-side web security research or see how serious adversaries will attack their web based code.

Students are expected to know how to use [Burp Suite](https://portswigger.net/burp) and have a basic understanding of common web attacks as well as perform basic scripting using common languages such as python, PHP and JavaScript. Each of the vulnerabilities presented have either been mirrored from real zero-day or are n-day bugs that have been discovered by the author with a focus on not just exploitation, but also on the discovery.

So if you want to learn how to exploit web technologies without client interaction for maximum impact, that is, remote code execution then this is the course for you.

Leave your OWASP Top Ten and CSP bypasses at the door.

## Table of Contents

- [Course Structure](#course-structure)
- [When and Where](#when-and-where)
- [Certification](#certification)
- [Instructor](#instructor)
- [Student Requirements](#student-requirements)
- [Hardware Requirements](#hardware-requirements)
- [Syllabus](#syllabus)
- [Testimonials](#testimonials)
- [FAQ](#faq)
- [Additional Material](#additional-material)

### Course Structure

- Duration: 4 days
- Language: English
- Hours: 9am - 5pm*
- Lunch break: 12.30pm for 1 hour
- Coffee break: 10.30am for 10 minutes
- Coffee break: 3.15pm for 10 minutes

\* The day to day hours maybe extended at the descretion of the trainer and students.

### When and Where

Currently we are not hosting any trainings for 2020.

### Certification

```java
javax.servlet.ServletException: java.lang.NullPointerException
    com.source.incite.FullStackWebAttack.certification(FullStackWebAttack.java:38) 
    org.apache.struts.action.RequestProcessor.processActionPerform(RequestProcessor.java:425) 
    org.apache.struts.action.RequestProcessor.process(RequestProcessor.java:228) 
    org.apache.struts.action.ActionServlet.process(ActionServlet.java:1913) 
    org.apache.struts.action.ActionServlet.doPost(ActionServlet.java:462) 
```

We apologise in advance but we do not offer any certifications.

### Instructor

Steven Seeley ([@steventseeley](https://twitter.com/steventseeley)) is an internationally recognized security researcher and trainer. For the last four years, Steven has reached platinum status with the [ZDI](https://www.zerodayinitiative.com/about/benefits/) and has literally found over a thousand high impact vulnerabilities, some of which can be found under the [advisories](/advisories/) section.

In 2020, [Chris and Steven won the Pwn2Own ICS competition](https://www.youtube.com/watch?v=Frd1LVgjXas) held in Miami and currently Steven focuses on cloud security research.

### Student Requirements

- At least basic scripting skills (moderate or advanced skills are *prefered*)
- At least a basic understanding of various web technologies such as HTTP(S), proxies and browsers

### Hardware Requirements

- A 64bit Host operating system
- 16 Gb RAM minimum
- VMWare Workstation or Fusion
- 200 Gb hard disk free minimum, this can be from an external drive
- Wired and wireless networking support
- USB 3.0 support

### Syllabus

*** This syllabus is subject to change at the discretion of the instructor.**

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

### Testimonials

> *"I recommend @steventseeley's Full Stack Web Attack from @sourceincite. I know it's going to be offered a few times next year, you should take it! It's training unlike anything else. I am excited to put my newly found skills to work. Awesome stuff!"*

- [@awhitehatter](https://twitter.com/awhitehatter/status/1180120923816386561)

> *"Just finished an amazing training course with @steventseeley - Full Stack Web Attack @sourceincite. I highly recommend it if you wanna take your php, java, and general web exploitation skills to the next level."*

- [@kiqueNissim](https://twitter.com/kiqueNissim/status/1179908013601251328)

> *"It was a great course, I think is one of the best I ever had, I liked how Steven always explained each exercise very well and clarified any doubts. Essentially I'm very happy to have taken this course and I will recommend it to my collegues for the next year. Thanks Steven!"*

- Anonymous

> *"GREAT course man! thank you SO much!"*

- Anonymous

> *"try harder, thanks mr_m3"*

- Anonymous

> *"It was very inspiring to see your strategy, way of thinking and searching through code. That is even more valuable than the vulnerabilities themselves. It was possibly one of the most challenging trainings, I took, in a good way."*

- Anonymous

### FAQ

*Why are you only offering X number of public trainings this year?*

**Our primary business is vulnerability research and exploitation. Course content is derived from such research and in order to provide a training that covers *bleeding edge attack techniques* the instructor needs to continually improve their skills.**

*Is this class offered online?*

**Unfortunately we are not offering this class online and we are not planning to in the future. This training is offered live because we love building relationships with the students and love watching that moment of realization where a student recognizes a level of empowerment they never thought possible.**

*Can I get a discount?*

**No.**

*Do you offer private trainings?*

**Yes, on a case by case basis. Please contact [training@](mailto:training@srcincite.io).**

### Additional Material

The madness doesn't stop. Preconfigured environments will be provided for additional work after class ends for the rediscovery and exploitation of n-day vulnerabilities.

[ret2toc](#table-of-contents)