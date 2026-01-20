#include "url_breaker.h"
#include <signal.h>

// 全局对象（用于信号处理）
URLBreaker g_breaker;

// 信号处理函数（Ctrl+C：清空规则+停止线程+清理内核日志）
void sigHandler(int sig)
{
    if (sig == SIGINT)
    {
        std::cout << "\nReceived SIGINT, processing cleanup..." << std::endl;

        // 1. 停止实时监控线程
        g_breaker.stopMonitorThread();

        // 2. 清空iptables规则
        g_breaker.clearIptablesRules();

        // 3. 清理内核日志（根据配置）
        if (g_breaker.getCleanKernelLog())
        {
            std::cout << "Cleaning kernel logs (buffer + files)..." << std::endl;
            // 清空dmesg缓冲区
            g_breaker.execCmd("sudo dmesg -c");
            // 截断系统日志文件（避免删除，影响系统）
            g_breaker.execCmd("sudo > /var/log/kern.log");
            g_breaker.execCmd("sudo > /var/log/syslog");
            std::cout << "Kernel logs cleaned successfully (buffer truncated + files emptied)!" << std::endl;
        }
        else
        {
            std::cout << "Skip cleaning kernel logs (disabled in config)!" << std::endl;
        }

        std::cout << "Cleanup finished, exiting..." << std::endl;
        exit(0);
    }
}

int main(int argc, char* argv[])
{
    // 检查权限（必须root运行）
    if (getuid() != 0)
    {
        std::cerr << "Error: Must run as root (sudo)!" << std::endl;
        return -1;
    }

    // 检查参数（传入XML配置路径）
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <config_xml_path>" << std::endl;
        return -1;
    }

    // 加载XML配置
    if (!g_breaker.loadConfig(argv[1]))
    {
        std::cerr << "Load config failed!" << std::endl;
        return -1;
    }

    // 注册信号处理（Ctrl+C退出时清理资源）
    signal(SIGINT, sigHandler);

    // 启动实时监控线程（核心：实时捕获拦截事件）
    if (!g_breaker.startMonitorThread())
    {
        std::cerr << "Start monitor thread failed!" << std::endl;
        return -1;
    }

    // 主逻辑：监控时段变化，加载/清空规则（每分钟检查一次）
    bool last_in_intercept = false;
    while (true)
    {
        bool curr_in_intercept = g_breaker.isInInterceptTime();
        if (curr_in_intercept != last_in_intercept)
        {
            if (curr_in_intercept)
            {
                std::cout << "Enter intercept time, loading rules..." << std::endl;
                g_breaker.loadIptablesRules();
            }
            else
            {
                std::cout << "Exit intercept time, clearing rules..." << std::endl;
                g_breaker.clearIptablesRules();
            }
            last_in_intercept = curr_in_intercept;
        }
        // 休眠60秒，降低CPU占用
        sleep(60);
    }

    return 0;
}