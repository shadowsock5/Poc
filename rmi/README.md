## Ref

- [针对RMI服务的九重攻击](https://xz.aliyun.com/t/7930)
- [RMI-反序列化](https://xz.aliyun.com/t/6660)
- [RMI 利用分析](https://mp.weixin.qq.com/s/5xHPCklm3IyBn7vc5_OiUA)
- [CVE-2017-3241 Java RMI Registry.bind()反序列化漏洞](http://www.code2sec.com/cve-2017-3241-java-rmi-registrybindfan-xu-lie-hua-lou-dong.html)
- https://github.com/A-D-Team/attackRmi
- https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/
- https://www.usd.de/en/presentation-black-hat-usa-2021/
- https://itnext.io/java-rmi-for-pentesters-part-two-reconnaissance-attack-against-non-jmx-registries-187a6561314d
- https://medium.com/m/global-identity?redirectUrl=https%3A%2F%2Fitnext.io%2Fjava-rmi-for-pentesters-structure-recon-and-communication-non-jmx-registries-a10d5c996a79

### Remote Method Guesser
修改ysoserial的路径，两种方法：
- 修改配置文件：https://github.com/qtc-de/remote-method-guesser/blob/master/src/config.properties#L63
- 设置参数：--yso /opt/ysoserial.jar

### rmiscout
- https://github.com/BishopFox/rmiscout
- https://bishopfox.com/blog/brute-forcing-rmi-iiop-with-rmiscout
