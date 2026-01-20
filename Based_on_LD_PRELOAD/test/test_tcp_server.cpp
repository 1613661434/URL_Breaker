#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define SERVER_IP "127.0.0.1" // 本地测试IP
#define SERVER_PORT 8888      // 测试端口（避开80/8080等常用端口）
int server_fd;                // 服务器socket，用于信号关闭

// 信号处理
void sig_handler(int sig)
{
    close(server_fd);
    printf("\n✅ 测试服务器已关闭\n");
    exit(0);
}

int main()
{
    // 注册退出信号
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 创建服务器socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket 创建失败");
        return -1;
    }

    // 端口复用
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    // 绑定地址和端口
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind 失败");
        close(server_fd);
        return -1;
    }

    // 监听端口
    if (listen(server_fd, 5) < 0)
    {
        perror("listen 失败");
        close(server_fd);
        return -1;
    }

    printf("🚀 测试服务器已启动：%s:%d（等待连接...）\n", SERVER_IP, SERVER_PORT);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0)
    {
        perror("accept 失败");
    }

    // 打印客户端信息并关闭连接
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("✅ 收到客户端连接：%s:%d\n", client_ip, ntohs(client_addr.sin_port));
    close(client_fd);

    close(server_fd);
    return 0;
}