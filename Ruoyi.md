### Ruoyi内存马
- https://github.com/lz2y/yaml-payload-for-ruoyi




### Ruoyi相关资料
- https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=ruoyi
- [某依后台RCE分析](https://xz.aliyun.com/t/10687)
- [某依rce黑名单多种bypass方法分析](https://xz.aliyun.com/t/10957)
- [定时任务功能点绕过黑白名单执行任意sql语句](https://xz.aliyun.com/t/11336)
- [RuoYi 可用内存马](https://xz.aliyun.com/t/10651)


### Ruoyi运行
![image](https://user-images.githubusercontent.com/30398606/173298801-3752ba2d-3a69-45ea-a108-eec580f90331.png)


```
mvn clean package

sudo runuser -l ruoyi -c "java -jar /home/cqq/repos/RuoYi-Vue/ruoyi-admin/target/ruoyi-admin.jar"
```
https://gitee.com/y_project/RuoYi-Vue
