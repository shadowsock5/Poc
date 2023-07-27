
```
getString:845, ResultSetImpl (com.mysql.cj.jdbc.result)
populateMapWithSessionStatusValues:85, ServerStatusDiffInterceptor (com.mysql.cj.jdbc.interceptors)
preProcess:97, ServerStatusDiffInterceptor (com.mysql.cj.jdbc.interceptors)
preProcess:76, NoSubInterceptorWrapper (com.mysql.cj)
invokeQueryInterceptorsPre:1048, NativeProtocol (com.mysql.cj.protocol.a)
sendQueryPacket:931, NativeProtocol (com.mysql.cj.protocol.a)
sendQueryString:892, NativeProtocol (com.mysql.cj.protocol.a)
execSQL:1073, NativeSession (com.mysql.cj)
setAutoCommit:2054, ConnectionImpl (com.mysql.cj.jdbc)
handleAutoCommitDefaults:1381, ConnectionImpl (com.mysql.cj.jdbc)
initializePropsFromServer:1326, ConnectionImpl (com.mysql.cj.jdbc)
connectOneTryOnly:967, ConnectionImpl (com.mysql.cj.jdbc)
createNewIO:826, ConnectionImpl (com.mysql.cj.jdbc)
<init>:456, ConnectionImpl (com.mysql.cj.jdbc)
getInstance:246, ConnectionImpl (com.mysql.cj.jdbc)
connect:198, NonRegisteringDriver (com.mysql.cj.jdbc)
getConnection:664, DriverManager (java.sql)
getConnection:247, DriverManager (java.sql)
main:17, TestJdbcController (org.jeecg.modules.demo.test.controller)
```

jdbc后门，用于放在传jdbc驱动的地方，Class.forName的时候就可以RCE。

Ref:
- https://su18.org/post/jdbc-connection-url-attack/#jdbc
- https://github.com/su18/JDBC-Attack/blob/main/mysql-attack/src/main/java/org/su18/jdbc/attack/mysql/serverstatus/Attack8x.java
- https://github.com/fnmsd/MySQL_Fake_Server
- [由CVE-2022-21724引申jdbc漏洞](https://mp.weixin.qq.com/s/pYWbpyW8DHXGvqsJurbc6A)
- https://pyn3rd.github.io/2022/06/06/Make-JDBC-Attacks-Brillian-Again-I/
- https://pyn3rd.github.io/2022/06/02/Make-JDBC-Attacks-Brilliant-Again/
- [jdbc后门](https://github.com/airman604/jdbc-backdoor)
