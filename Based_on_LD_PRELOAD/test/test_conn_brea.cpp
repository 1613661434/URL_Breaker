#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

// 黑名单目标
const char* IP = "1.1.1.1";
const int PORT = 80;

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

    printf("🔍 尝试连接黑名单地址：%s:%d\n", IP, PORT);
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        if (errno == ECONNREFUSED)
        {
            printf("✅ 黑名单连接被拒绝（拦截器生效，符合预期）\n");
        }
        else
        {
            perror("❌ 黑名单连接失败（非拦截器原因，异常！）");
        }
        close(sockfd);
        return 0; // 拦截成功返回0（正常）
    }

    printf("❌ 黑名单连接成功（拦截器失效，异常！）\n");
    close(sockfd);
    return -1;
}