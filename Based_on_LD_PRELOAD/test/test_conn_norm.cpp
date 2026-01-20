#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

// 非黑名单目标：本地测试服务器
const char* IP = "127.0.0.1";
const int PORT = 8888;

int main()
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket 创建失败");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, IP, &addr.sin_addr) <= 0)
    {
        perror("无效的地址");
        close(sockfd);
        return -1;
    }

    printf("🔍 尝试连接非黑名单地址：%s:%d\n", IP, PORT);
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror("❌ 非黑名单连接失败（异常！）");
        close(sockfd);
        return -1;
    }

    printf("✅ 非黑名单连接成功（符合预期）\n");
    close(sockfd);
    return 0;
}