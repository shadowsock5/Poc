## Confluence环境搭建

### 配置数据库
```bash
sudo service postgresql start
sudo su postgres
psql
create user confluence with password 'confluence';
create database confluence_5_8_15 owner confluence;
grant all privileges on database confluence_5_8_15 to confluence;
\q
```

### 安装
```bash
# 下载特定Confluence版本
wget https://product-downloads.atlassian.com/software/confluence/downloads/atlassian-confluence-5.8.15.zip
unzip -q atlassian-confluence-5.8.15.zip
cd atlassian-confluence-5.8.15
# vi confluence/WEB-INF/classes/confluence-init.properties
```
### 修改home目录
```
sed -i "s/\# confluence.home=\/var\/data\/confluence\//confluence.home=\/home\/77\/confluenceHome5.8.15/g" confluence/WEB-INF/classes/confluence-init.properties
```
### 增加调试参数
```
sed -i "s/export CATALINA_OPTS/CATALINA_OPTS=\"-Xrunjdwp:transport=dt_socket,suspend=n,server=y,address=12346 ${CATALINA_OPTS}\"  \# for debug\nexport CATALINA_OPTS/g" bin/setenv.sh
```
或者
```
JVM_SUPPORT_RECOMMENDED_ARGS="-Xrunjdwp:transport=dt_socket,suspend=n,server=y,address=8346"    # for debug
```
### Tomcat启动调试
```
.\bin\catalina.bat jpda start
```
启动之前需要在`bin\catalina.bat`中修改调试端口。修改`JPDA_ADDRESS`即可。


### 启动/停止Confluence
```
bin/start-confluence.sh
bin/stop-confluence.sh
```

### jars
- synchrony-proxy/WEB-INF/lib/
- lib/
- confluence/WEB-INF/packages/
- confluence/WEB-INF/osgi-framework-bundles/
- confluence/WEB-INF/lib/
- confluence/WEB-INF/atlassian-bundled-plugins-setup/
- confluence/WEB-INF/atlassian-bundled-plugins/
- bin/
