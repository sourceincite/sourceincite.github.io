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

- Java language fundamentals
- Debugging Java applications

*Framework Overview*

- Spring MVC
- Struts v1/2

*Authentication Bypasses*

- Auditing Servlet Filters
- Auditing Interceptors
- Common authentication bypass patterns

*Java deserialization primer*

- Serializable interface
- Externalizable interface
- Unmarshalling vs Deserialization, whats the difference?
- Understanding Reflection
- Reflection in practice

*Java deserialization exploitation*

- Pivot gadgets
- Building upon ysoserial
- Custom gadget chain creation

### Day 2

*JNDI Injection*

- RMI and JRMP overview
- Remote class loading
- DGC deserialization
- Local object exploitation
- Application specific exploitation

*Analyzing the Struts Framework*

- Action Mappings
- Dynamic Method Invocation
- Interceptor Stacks
- Case study: Do I even exist? - Analyzing an edge-case RCE vulnerability
- Case study: Devil in the details - Analyzing a TOCTOU framework vulnerability

### Day 3

*JDBC Injection*

- Common drivers and their exploitation primitives
- Discovering your own driver primitives

*Server-side template injection*

- Analyzing and exploiting CVE-2022-22954

*Java Bean Validation - Attacking Custom Validators*

- Analyzing and exploiting CVE-2022-31700