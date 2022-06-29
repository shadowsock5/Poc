### Image containing all Flowable UI apps running on Tomcat (with a in memory H2 database). 
- https://hub.docker.com/r/flowable/all-in-one


还可以使用这个：
- https://hub.docker.com/r/flowable/flowable-idm
- https://hub.docker.com/r/flowable/flowable-admin


```
sudo docker run -p192.168.17.129:8080:8080 flowable/flowable-idm

sudo docker run -p192.168.17.129:9988:9988 -e FLOWABLE_COMMON_APP_IDM-URL=http://192.168.17.129:8080/flowable-idm -e FLOWABLE_COMMON_APP_IDM-ADMIN_USER=admin -e FLOWABLE_COMMON_APP_IDM-ADMIN_PASSWORD=test flowable/flowable-admin
```
