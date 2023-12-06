---
layout: training
title: Training syllabus
permalink: /training/syllabus/java
---

## Full Stack Web Attack (Java Edition) - Syllabus

---

*Please note:* **This syllabus is subject to change at the discretion of the instructor.**

#### Day 1

*Introduction*

- Java Language Fundamentals
- Debugging Java Applications

*Framework Overview*

- Spring MVC
- Struts v1/2

*Java Deserialization Primer*

- Serializable vs Externalizable
- Unmarshalling vs Deserialization
- Reflection in theory and practice
- Pivot gadgets

*JNDI Injection*

- RMI and JRMP overview
- Remote class loading
- Exception Handling Deserialization
- Local Object Factory exploitation

*Analyzing the Struts Framework*

- Action Mappings
- Dynamic Method Invocation
- Interceptor Stacks
- Case studies: 
  - Do I even exist? - Analyzing an edge-case RCE vulnerability
  - Devil in the details - Analyzing a TOCTOU framework vulnerability

### Day 2

*JDBC Injection*

- Common drivers and their exploitation primitives
- Exploiting the MySQL Driver via Deserialization
- Discovering your own driver primitives

*Authentication Bypasses*

- Auditing Servlet Filters
- Auditing Interceptors
- Common authentication bypass patterns

*Java deserialization for Security Researchers*

- Building upon Ysoserial
- Custom gadget chain creation
- Chaining vulnerabilities

* Server-side template injection*

- Analyzing and exploiting CVE-2022-XXXXX

*Java Bean Validation - Attacking Custom Validators*

- Analyzing and exploiting CVE-2022-XXXXX