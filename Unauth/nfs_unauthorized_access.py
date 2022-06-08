#!/usr/bin/env python
#coding=utf-8

import traceback
import base64
import socket
import binascii

# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


class NFS_POC(POCBase):
    vulID = 'NFS-unauthorized-access'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    appName = 'NFS'
    appVersion = ''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE

    vulDate = '2020-04-14'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-04-14'  # 编写 PoC 的日期
    updateDate = '2020-04-14'  # PoC 更新的时间,默认和编写时间一样
    references = ['http://wp.blkstone.me/2019/11/ubuntu-nfs-unauth-access/']  # 漏洞地址来源,0day不用写
    name = 'NFS未授权访问漏洞'  # PoC 名称
    cvss = u"中危"


    def _verify(self):
        result={}

        vul_url = self.url
        target_url = vul_url

        # 传入True参数，得到host和port，参考：https://github.com/knownsec/pocsuite3/blob/0f68c1cef3804c5d43be6cfd11c2298f3d77f0ad/pocsuite3/lib/utils/__init__.py
        host, port = url2ip(target_url, True)  

        socket.setdefaulttimeout(5)   # 默认timeout时间
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            sock.connect((host, port))

            # NFS NULL Call
            NFS_NULL_Call = b'8000002831ec45220000000000000002000186a3000000040000000000000000000000000000000000000000'
            bNFS_NULL_Call = bytes.fromhex(NFS_NULL_Call.decode())

            #NFS_NULL_Call2 = base64.b64decode('gAAAKDHsRSIAAAAAAAAAAgABhqMAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAA=')

            # 发送请求
            #sock.send(NFS_NULL_Call2)
            sock.send(bNFS_NULL_Call)


            # 接收响应
            hello = sock.recv(1024)

            # NFS NULL Reply
            NFS_NULL_Reply = binascii.b2a_hex(hello)

            NFS_XID = NFS_NULL_Reply[8:16]
            print(NFS_XID)


            print("[*] NFS NULL Reply: {0}".format(NFS_NULL_Reply))

            # 如果响应内容中有"31ec4522"（这个是XID，是请求中带的，如果响应中有则认为存在NFS协议）则认为存在漏洞
            if NFS_XID.decode() == '31ec4522':
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target_url
                return self.save_output(result)
    
            return self.save_output(result)
        except socket.error as msg:
            print('[*] Could not connect to the target NFS service. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1])
            traceback.print_stack(msg)

    #漏洞攻击
    def _attack(self):
        return self._verify()



    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register_poc(NFS_POC)