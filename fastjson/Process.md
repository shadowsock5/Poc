```
JSON.parseObject(text)
=> JSON.parse(text)
=> JSON.parse(text, ParserConfig.getGlobalInstance(), DEFAULT_PARSER_FEATURE);    // ParserConfig.getGlobalInstance()是拿到ParserConfig的静态实例，而这个实例在ParserConfig的static代码块中已经被初始化了
   => DefaultJSONParser(text, config, features)#parse
   => DefaultJSONParser#parseObject   
   
   
```
 
 
先拿到class对象：如果不支持autoType的话，这里就直接抛异常了；
```java
                    if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {
                        typeName = lexer.scanSymbol(this.symbolTable, '"');
                        if (!lexer.isEnabled(Feature.IgnoreAutoType)) {
                            strValue = null;
                            Class clazz;
                            if (object != null && object.getClass().getName().equals(typeName)) {
                                clazz = object.getClass();
                            } else {
                                clazz = this.config.checkAutoType(typeName, (Class)null, lexer.getFeatures());
                            }
```

拿到class对象之后对其进行判断，
- clazz.isEnum()
- clazz.isArray()
- clazz != Set.class && clazz != HashSet.class && clazz != Collection.class && clazz != List.class && clazz != ArrayList.class
- Collection.class.isAssignableFrom(clazz)
- Map.class.isAssignableFrom(clazz)
- Throwable.class.isAssignableFrom(clazz)
- PropertyProcessable.class.isAssignableFrom(clazz)


都不是，则创建这个类的的BeanDeserializer：
```java
derializer = this.createJavaBeanDeserializer(clazz, (Type)type);
```

然后判断这个类有没有public的构造方法。
注：这里getModifiers拿到的是int型，值为1则代表public。参考：https://stackoverflow.com/questions/30666487/how-does-the-getmodifiers-method-calculate-the-value-for-multiple-modifiers

```java
superClass = JavaBeanInfo.getBuilderClass(clazz, jsonType);

                do {
                    if (!Modifier.isPublic(superClass.getModifiers())) {
                        asmEnable = false;
                        break;
                    }

                    superClass = superClass.getSuperclass();
                } while(superClass != Object.class && superClass != null);
```
可见如果没有，则直接break了。

然后是拿到这个class的父类
```java
superClass = superClass.getSuperclass();
```

我们这里的class是org.apache.shiro.realm.jndi.JndiRealmFactory，所以拿到的它的父类是org.apache.shiro.jndi.JndiLocator。
这里是一个while循环，循环判断的条件是父类存在，且不为Object。意思是只要还有父类，就继续找父类。
而且，只要父类的构造器不是public，也会break。



检查名字，是否是ASCII字符：
```java
asmEnable = ASMUtils.checkName(clazz.getSimpleName());

    public static boolean checkName(String name) {
        for(int i = 0; i < name.length(); ++i) {
            char c = name.charAt(i);
            if (c < 1 || c > 127 || c == '.') {
                return false;
            }
        }

        return true;
    }
```

再看
```java
            if (clazz.isInterface()) {
                asmEnable = false;
            }

            beanInfo = JavaBeanInfo.build(clazz, type, this.propertyNamingStrategy);
```

进行build这个class，在build的逻辑中，拿到它的属性，
```java
Field[] declaredFields = clazz.getDeclaredFields();
```
这里只有
```java
Collection<String> jndiNames = null;
```
然后拿到它的所有方法，包括父类的所有方法。
```java
Method[] methods = clazz.getMethods();
```
以及构造器：
```java
Constructor[] constructors = clazz.getDeclaredConstructors();
```
如果只有一个构造器，则直接拿到默认的构造器：
```java
        if (!kotlin || constructors.length == 1) {
            if (builderClass == null) {
                defaultConstructor = getDefaultConstructor(clazz, constructors);
            } else {
                defaultConstructor = getDefaultConstructor(builderClass, builderClass.getDeclaredConstructors());
            }
        }
```

然后判断这个类是不是接口或者抽象类：
```java
boolean isInterfaceOrAbstract = clazz.isInterface() || Modifier.isAbstract(clazz.getModifiers());
```
如果默认构造器为空，或者是接口/抽象类，进行另一个逻辑（暂时不看）
```java
if (defaultConstructor == null && builderClass == null || isInterfaceOrAbstract) 
```
继续往下：
如果默认构造器不为空，
```java
            if (defaultConstructor != null) {
                TypeUtils.setAccessible(defaultConstructor);
            }
```


com\alibaba\fastjson\parser\deserializer\JavaBeanDeserializer.java
```java
object = createInstance(parser, type);
```
创建这个类型的实例。


com\alibaba\fastjson\parser\deserializer\DefaultFieldDeserializer.java
```java
value = fieldValueDeserilizer.deserialze(parser, fieldType, fieldInfo.name);
```
解析对象的属性值。


调用`setjndiNames`方法：
```java
setValue(object, value);
```


poc里的
```json
"Realms":[""]
```
则先对应到`org.apache.shiro.realm.Realm`，由于它是Interface，所以进入这个之前没深入的逻辑：
```java
if ((defaultConstructor == null && builderClass == null) || isInterfaceOrAbstract)
```

com\alibaba\fastjson\util\JavaBeanInfo.java
判断方法名是否以get开头，并且get后面的第一个字符是大写。
```java
if (builderClass == null && methodName.startsWith("get") && Character.isUpperCase(methodName.charAt(3)))
```
如果有参数，则不选择：
```java
                if (method.getParameterTypes().length != 0) {
                    continue;
                }
```

com\alibaba\fastjson\parser\ParserConfig.java
由于是接口，所以拿到的BeanInfo没啥东西，只知道它的类型是什么：
```java
JavaBeanInfo beanInfo = JavaBeanInfo.build(clazz, type, propertyNamingStrategy);
```

