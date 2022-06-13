### Ruoyi内存马
- https://github.com/lz2y/yaml-payload-for-ruoyi




### Ruoyi相关资料
- https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=ruoyi
- [某依后台RCE分析](https://xz.aliyun.com/t/10687)
- [某依rce黑名单多种bypass方法分析](https://xz.aliyun.com/t/10957)
- [定时任务功能点绕过黑白名单执行任意sql语句](https://xz.aliyun.com/t/11336)
- [RuoYi 可用内存马](https://xz.aliyun.com/t/10651)


### Ruoyi配置/运行

```
mysql> grant all privileges on ry.* to ruoyi@localhost;
mysql> create database ry;
mysql> use ry;
mysql> source /home/cqq/repos/RuoYi-Vue/sql/ry_20210908.sql;
mysql> source /home/cqq/repos/RuoYi-Vue/sql/quartz.sql;
```
![image](https://user-images.githubusercontent.com/30398606/173298801-3752ba2d-3a69-45ea-a108-eec580f90331.png)

需要本地开启redis：
```
sudo apt install redis-server
sudo systemctl start redis-server
```
编译：
```
mvn clean package

sudo runuser -l ruoyi -c "java -jar /home/cqq/repos/RuoYi-Vue/ruoyi-admin/target/ruoyi-admin.jar"
```
https://gitee.com/y_project/RuoYi-Vue


运行之后的控制台：
![image](https://user-images.githubusercontent.com/30398606/173300011-254feedf-41b9-42af-98e5-ecfa290fd069.png)


