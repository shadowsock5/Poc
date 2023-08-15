
参考：
- https://github.com/vulhub/vulhub/blob/master/openfire/CVE-2023-32315/README.zh-cn.md

### 环境搭建

```bash
sudo docker pull vulhub/openfire:4.7.4
sudo docker run -p 9090:9090 --name openfire-4.7.4 f16b082dca65
```
启动之后发现监听了这个多端口：
```
root@bb3db75888ae:/mnt/openfire# netstat -plnt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9090            0.0.0.0:*               LISTEN      1/java              
tcp        0      0 0.0.0.0:5223            0.0.0.0:*               LISTEN      1/java              
tcp        0      0 0.0.0.0:5222            0.0.0.0:*               LISTEN      1/java              
tcp        0      0 0.0.0.0:5276            0.0.0.0:*               LISTEN      1/java              
tcp        0      0 0.0.0.0:5275            0.0.0.0:*               LISTEN      1/java              
tcp        0      0 0.0.0.0:5269            0.0.0.0:*               LISTEN      1/java              
tcp        0      0 0.0.0.0:5270            0.0.0.0:*               LISTEN      1/java              
tcp        0      0 0.0.0.0:5263            0.0.0.0:*               LISTEN      1/java              
tcp        0      0 0.0.0.0:5262            0.0.0.0:*               LISTEN      1/java              
tcp        0      0 0.0.0.0:7777            0.0.0.0:*               LISTEN      1/java              
tcp        0      0 0.0.0.0:7070            0.0.0.0:*               LISTEN      1/java
```
这里给出了一些端口映射：
https://download.igniterealtime.org/openfire/docs/latest/documentation/working-with-openfire.html
再给它加上调试：
```
docker run -e "JAVA_OPTS=-Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=n" -p 8000:8000/tcp -p 3478:3478/tcp -p 3479:3479/tcp -p 5222:5222/tcp -p 5223:5223/tcp -p 5229:5229/tcp -p 5262:5262/tcp -p 5263:5263/tcp -p 5275:5275/tcp -p 5276:5276/tcp -p 7070:7070/tcp -p 7443:7443/tcp -p 7777:7777/tcp -p 9090:9090/tcp -p 9091:9091/tcp -p 5005:5005/tcp  --name openfire-4.7.4 f16b082dca65
```
