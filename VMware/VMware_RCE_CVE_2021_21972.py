#!/usr/bin/env python
#coding=utf-8

import random
import json
from string import ascii_letters
import time
import traceback
import socket

# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip
from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase, logger
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


'''
CVE-2021-21972
'''
class vCenter_RCE_POC(POCBase):
    vulID = 'VMWare-vCenter-unauth-RCE'
    appName = 'VMWare vCenter'
    appVersion = '''version = 6.5, 6.7, 7.0'''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.OTHER
    vulDate = '2021-03-01'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2021-03-01'  # 编写 PoC 的日期
    updateDate = '2021-03-01'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://swarm.ptsecurity.com/unauth-rce-vmware/', 'https://www.exploit-db.com/exploits/49602']  # 漏洞地址来源,0day不用写
    name = 'VMware vCenter未授权RCE漏洞'  # PoC 名称
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


        target_url = "{0}/ui/vropspluginui/rest/services/uploadova".format(vul_url)
        
        try:
            resp = req.get(target_url, verify=False)
        except Exception as e:
            print(e)
            raise e
        


        if resp.status_code == 405:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            return self.save_output(result)

        logger.info(resp)
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
register_poc(vCenter_RCE_POC)
