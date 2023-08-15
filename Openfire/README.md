
参考：
- https://github.com/vulhub/vulhub/blob/master/openfire/CVE-2023-32315/README.zh-cn.md

### 环境搭建

```bash
wget https://github.com/igniterealtime/Openfire/releases/download/v4.7.3/openfire_4_7_3.tar.gz
tar zxf openfire_4_7_3.tar.gz
cd bin
chmod +x ./openfire.sh
./openfire.sh start -debug
```
即可监听在5005端口进行调试。

