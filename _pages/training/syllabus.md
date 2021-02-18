---
layout: training
title: Training syllabus
permalink: /training/syllabus/
---

## Full Stack Web Attack - Syllabus

---

*Please note:* **This syllabus is subject to change at the discretion of the instructor.**

#### Day 1

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

### Day 2

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

### Day 3

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

### Day 4

*PHP*

- Blocklist bypasses (zero-day vulnerability analysis and exploitation)

*Java*

- Introduction to reflection
- Expression language injection
- Bypassing URI filters
- URI forward authentication bypasses (zero-day technique)
- Deserialization 102 (custom gadget chains)
  - Trampoline gadgets
  - Exploiting reflection
  - Allowlist flexability (ab)use
- A zero-day bug hunt in a real target