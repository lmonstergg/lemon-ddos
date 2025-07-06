#!/bin/bash

# 简化版Ubuntu网络性能优化脚本
# 仅优化网络参数和提高资源限制
# 用法: sudo ./optimize_network.sh

# 检查是否以root运行
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

echo "====================================="
echo " Ubuntu Network Optimization "
echo "====================================="

# 1. 优化网络参数
echo "Optimizing network parameters..."
sysctl -w net.core.wmem_max=12582912
sysctl -w net.core.rmem_max=12582912
sysctl -w net.core.netdev_max_backlog=500000
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65536
sysctl -w net.ipv4.tcp_synack_retries=1
sysctl -w net.ipv4.tcp_syncookies=0
sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# 2. 提高资源限制
echo "Increasing resource limits..."
echo "* soft nofile 1000000" >> /etc/security/limits.conf
echo "* hard nofile 1000000" >> /etc/security/limits.conf
ulimit -n 1000000

# 3. 清理防火墙规则（可选）
read -p "Clear firewall rules? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Clearing firewall rules..."
    iptables -F
    iptables -t nat -F
    iptables -X
    iptables -t nat -X
    ufw disable > /dev/null 2>&1
fi

echo "-------------------------------------"
echo " Optimization complete!"
echo " Important changes:"
echo "   - Increased network buffers"
echo "   - Raised file descriptor limit to 1,000,000"
echo "   - Cleared firewall rules (if selected)"
echo "====================================="
