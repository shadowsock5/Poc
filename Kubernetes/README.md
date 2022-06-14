每一个 Node 节点都有一个 kubelet 服务，kubelet 监听了 10250，10248，10255 等端口。

其中 10250 端口是 kubelet 与 apiserver 进行通信的主要端口，通过该端口 kubelet 可以知道自己当前应该处理的任务，该端口在最新版 Kubernetes 是有鉴权的，但在开启了接受匿名请求的情况下，不带鉴权信息的请求也可以使用 10250 提供的能力
```

kube-apiserver: 6443, 8080

kubectl proxy: 8080, 8081

kubelet: 10250, 10255, 4149

dashboard: 30000

docker api: 2375

etcd: 2379, 2380

kube-controller-manager: 10252

kube-proxy: 10256, 31442

kube-scheduler: 10251

weave: 6781, 6782, 6783

kubeflow-dashboard: 8080

```

Ref:
- https://github.com/teamssix/awesome-cloud-security
- https://github.com/neargle/my-re0-k8s-security#3-%E5%8D%95%E5%AE%B9%E5%99%A8%E7%8E%AF%E5%A2%83%E5%86%85%E7%9A%84%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86
