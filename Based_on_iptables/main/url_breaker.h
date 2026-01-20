#ifndef URL_BREAKER_H
#define URL_BREAKER_H 1

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ctime>
#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>
#include <tinyxml2.h>
#include <pthread.h>
#include <atomic>
#include <utility>
#include <sstream>
#include <set>
#include <cstdlib>

// 时间段规则结构体
struct TimeRule
{
    std::string start; // 开始时间（如 "09:00"）
    std::string end;   // 结束时间（如 "18:00"）
};

// 黑名单项结构体
struct BlackItem
{
    std::string ip; // 目标IP
    int port;       // 目标端口（0=所有端口）
};

// 全局配置结构体
struct GlobalConfig
{
    std::string log_path;  // 日志路径
    std::string ipt_chain; // iptables自定义链名
    bool persist_rule;     // 是否持久化规则
    bool clean_kernel_log; // Ctrl+C时是否清理内核日志（默认false）
};

// 解析内核日志字段的结构体
struct KernelLogInfo
{
    std::string proto;  // 协议（TCP/UDP/ICMP）
    std::string dst_ip; // 目标IP
    int spt;            // 源端口（TCP/UDP）
    int icmp_id;        // ICMP ID（对应ping进程PID）
};

// 核心类
class URLBreaker
{
private:
    GlobalConfig global_cfg;
    std::vector<TimeRule> time_rules;
    std::vector<BlackItem> black_list;
    // 线程安全相关
    pthread_t monitor_thread;
    std::atomic<bool> is_running;
    pthread_mutex_t log_mutex;
    pthread_mutex_t processed_logs_mutex;
    std::set<std::string> processed_logs;

    // 私有方法：安全转换字符串到int
    int safe_stoi(const std::string& s, int default_val = 0);
    // 私有方法：解析时间字符串为小时+分钟
    bool parseTimeStr(const std::string& time_str, int& hour, int& min);
    // 私有方法：获取当前程序进程名
    std::string getProcessName();
    // 私有方法：实时监控内核日志的线程函数
    static void* monitorKernelLog(void* arg);
    // 私有方法：处理单条内核日志
    void processKernelLogLine(const std::string& line);
    // 私有方法：解析内核日志行
    bool parseKernelLogLine(const std::string& line, KernelLogInfo& log_info);
    // 私有方法：查询发起进程
    std::pair<std::string, std::string> getInitiatorProcess(const KernelLogInfo& log_info);

public:
    // 构造函数
    URLBreaker() : is_running(false)
    {
        pthread_mutex_init(&log_mutex, nullptr);
        pthread_mutex_init(&processed_logs_mutex, nullptr);
        // 默认配置
        global_cfg.log_path = "/var/log/url_breaker.log";
        global_cfg.ipt_chain = "URL_BREAKER";
        global_cfg.persist_rule = false;
        global_cfg.clean_kernel_log = false;
    }
    // 析构函数
    ~URLBreaker()
    {
        pthread_mutex_destroy(&log_mutex);
        pthread_mutex_destroy(&processed_logs_mutex);
    }

    // 加载XML配置
    bool loadConfig(const std::string& xml_path);
    // 判断当前时间是否在拦截时段内（仅判断当天时间段）
    bool isInInterceptTime();
    // 加载iptables规则
    bool loadIptablesRules();
    // 清空iptables规则
    bool clearIptablesRules();
    // 记录日志（重载）
    void writeLog(const std::string& target_ip, int port, const std::string& result);
    void writeLog(const std::string& target_ip, int port, const std::string& result,
                  const std::string& proc_name, const std::string& pid);
    // 记录时间规则日志
    void writeLog_timeRules();
    // 持久化规则
    bool persistIptablesRules();
    // 启动/停止监控线程
    bool startMonitorThread();
    void stopMonitorThread();
    // Getter
    bool getCleanKernelLog() const
    {
        return global_cfg.clean_kernel_log;
    }
    // 执行系统命令并返回结果
    std::string execCmd(const std::string& cmd);
};

#endif // !URL_BREAKER_H