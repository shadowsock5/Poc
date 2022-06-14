- [tomcat常用漏洞汇总](https://saucer-man.com/information_security/507.html)
- [tomcat容器url解析特性研究](https://xz.aliyun.com/t/10799)

### [CVE-2020-9484] Tomcat Session 反序列化漏洞


#### 影响范围
Apache Tomcat 10.x < 10.0.0-M5
Apache Tomcat 9.x < 9.0.35
Apache Tomcat 8.x < 8.5.55
Apache Tomcat 7.x < 7.0.104


- https://romnenko.medium.com/apache-tomcat-deserialization-of-untrusted-data-rce-cve-2020-9484-afc9a12492c4
- https://github.com/masahiro331/CVE-2020-9484
- https://y4er.com/post/cve-2020-9484-tomcat-session-rce/
- https://www.cnblogs.com/potatsoSec/p/12931427.html


### [CVE-2021-25329]

- [CVE-2021-25329: Apache Tomcat Incomplete fix for CVE-2020-9484](https://seclists.org/oss-sec/2021/q1/184)
- http://blog.nsfocus.net/cve-2021-25329/

### [CVE-2020-13935] WebSocket Vulnerability in Apache Tomcat

- https://github.com/RedTeamPentesting/CVE-2020-13935

### [CVE-2020-13943] HTTP/2 Request Smuggling
受影响组件：
```
org.apache.tomcat.embed:tomcat-embed-core
```

参考：
- https://security.snyk.io/vuln/SNYK-JAVA-ORGAPACHETOMCATEMBED-1017119
- https://github.com/apache/tomcat/commit/1bbc650cbc3f08d85a1ec6d803c47ae53a84f3bb

其他各种漏洞参考：
https://snyk.io/vuln/maven:org.apache.tomcat.embed%3Atomcat-embed-core

### [CVE-2020-11996] HTTP/2 拒绝服务攻击漏洞
> A specially crafted sequence of HTTP/2 requests sent to Apache Tomcat 10.0.0-M1 to 10.0.0-M5, 9.0.0.M1 to 9.0.35 and 8.5.0 to 8.5.55 could trigger high CPU usage for several seconds. If a sufficient number of such requests were made on concurrent HTTP/2 connections, the server could become unresponsive.

https://github.com/rusakovichma/tomcat-embed-core-9.0.31-CVE-2020-11996/blob/master/test/org/apache/coyote/http2/TestHttp2Section_5_1.java

### tomcat-jmxproxy

https://github.com/4ra1n/tomcat-jmxproxy-rce-exp
