#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ol_public.h"
#include "ol_net/ol_InetAddr.h" // 引入OL网络地址封装类
#include "ol_string.h"          // 引入OL字符串处理工具类
#include <atomic>
#include <cstdarg>
#include <dlfcn.h>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <cstdlib>
#include <cstring>

// 兼容老系统宏定义
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

using namespace ol;
using namespace std;

// ===================== 全局配置 =====================
// 黑名单条目结构（复用InetAddr简化IP/端口管理）
typedef struct
{
    InetAddr addr;  // OL封装的IP+端口（核心）
    string url;     // 原始URL（可选，如www.xxx.com）
    string mask;    // IP掩码（扩展预留）
    bool is_domain; // 是否是域名（非IP）
} BlacklistEntry;

// 拦截时间段（内部存储HHMM数值，外部交互用00:00格式）
typedef struct
{
    int start_time; // 开始时间（如0900=09:00）
    int end_time;   // 结束时间（如1800=18:00）
} TimeRange;

// 全局变量
vector<BlacklistEntry> g_Blacklist;    // IP/URL黑名单
vector<string> g_WhitelistProcs;       // 进程白名单
TimeRange g_InterceptTime = {0, 2400}; // 默认全天拦截（00:00-24:00）
atomic_bool g_bConfigLoaded(false);
clogfile g_log;
const string g_configPath = "/home/mysql/Projects/URL_Breaker/main/config.xml";
const string g_logPath = "/home/mysql/Projects/URL_Breaker/main/url_breaker.log";
const int MAX_BLACKLIST = 100;

// 原子初始化状态
atomic<bool> g_InitState(false);

// ================================== <工具函数> ==================================
/**
 * @brief 获取当前进程绝对路径
 */
string get_current_proc_path()
{
    char buf[PATH_MAX] = {0};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    return (len > 0) ? string(buf, len) : "unknown_proc";
}

/**
 * @brief 将HHMM格式数字转换为HH:MM字符串（如0900→09:00，2400→24:00）
 * @param hhmm 内部存储的HHMM数值
 * @return 格式化后的时间字符串
 */
static string hhmm_to_str(int hhmm)
{
    // 严格限制小时/分钟范围，避免数值异常导致格式溢出
    int hour = hhmm / 100;
    int min = hhmm % 100;

    // 强制约束合法范围（小时0-24，分钟0-59）
    hour = (hour < 0) ? 0 : (hour > 24) ? 24
                                        : hour;
    min = (min < 0) ? 0 : (min > 59) ? 59
                                     : min;

    // 扩大缓冲区至16字节
    char buf[16] = {0};
    snprintf(buf, sizeof(buf), "%02d:%02d", hour, min);
    return string(buf);
}

/**
 * @brief 解析HH:MM格式字符串为HHMM数值（结合OL库清理空白）
 * @param time_str 如"09:30"、"23:59"、"24:00"（允许包含首尾空白）
 * @param hhmm_out 输出解析后的HHMM数值
 * @return 成功返回true，失败返回false
 */
static bool str_to_hhmm(const string& time_str, int& hhmm_out)
{
    // 使用OL库清理首尾空白
    string clean_str = time_str;
    deleteLRchr(clean_str);

    // 校验格式（必须包含:，且长度符合）
    size_t colon_pos = clean_str.find(':');
    if (colon_pos == string::npos || colon_pos < 1 || colon_pos > 2 || clean_str.length() > 5)
    {
        return false;
    }

    // 拆分小时和分钟（使用OL库清理拆分后的字符串）
    string hour_str = clean_str.substr(0, colon_pos);
    string min_str = clean_str.substr(colon_pos + 1);
    deleteLRchr(hour_str);
    deleteLRchr(min_str);

    // 转换为数字并校验范围
    char* end_ptr = nullptr;
    long hour = strtol(hour_str.c_str(), &end_ptr, 10);
    if (*end_ptr != '\0' || hour < 0 || hour > 24) return false;

    long min = strtol(min_str.c_str(), &end_ptr, 10);
    if (*end_ptr != '\0' || min < 0 || min > 59) return false;

    // 特殊处理24:00（转换为2400）
    if (hour == 24 && min != 0) return false;

    // 计算HHMM数值
    hhmm_out = static_cast<int>(hour * 100 + min);
    return true;
}

/**
 * @brief 解析当前时间为HHMM格式（如09:05→905）
 */
static int get_current_hhmm()
{
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    return t->tm_hour * 100 + t->tm_min;
}

/**
 * @brief 判断当前时间是否在拦截时间段内
 */
static bool is_in_intercept_time()
{
    int current = get_current_hhmm();
    int start = g_InterceptTime.start_time;
    int end = g_InterceptTime.end_time;

    // 处理跨天场景（如23:00-02:00 → 2300-0200）
    return (start > end) ? (current >= start || current <= end) : (current >= start && current <= end);
}

/**
 * @brief 解析URL/域名为IP地址（用于构造InetAddr）
 * @param target URL/域名（如www.xxx.com）
 * @param ip_out 输出解析后的IP字符串
 * @param family_out 输出地址族（AF_INET/AF_INET6）
 * @return 成功返回true，失败返回false
 */
static bool resolve_url_to_ip(const string& target, string& ip_out, sa_family_t& family_out)
{
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // 同时支持IPv4/IPv6
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(target.c_str(), NULL, &hints, &res) != 0)
    {
        return false;
    }

    // 优先取第一个有效IP
    for (p = res; p != NULL; p = p->ai_next)
    {
        if (p->ai_family == AF_INET)
        {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            char ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip));
            ip_out = ip;
            family_out = AF_INET;
            freeaddrinfo(res);
            return true;
        }
        else if (p->ai_family == AF_INET6)
        {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            char ip[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, sizeof(ip));
            ip_out = ip;
            family_out = AF_INET6;
            freeaddrinfo(res);
            return true;
        }
    }

    freeaddrinfo(res);
    return false;
}

/**
 * @brief 解析URL/域名为多个IP地址
 * @param target URL/域名
 * @param ips_out 输出解析后的IP列表
 * @return 成功解析出至少一个IP返回true
 */
static bool resolve_url_to_ips(const string& target, vector<string>& ips_out)
{
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(target.c_str(), NULL, &hints, &res) != 0)
    {
        return false;
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        char ip[INET6_ADDRSTRLEN] = {0};
        if (p->ai_family == AF_INET)
        {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip));
            ips_out.push_back(ip);
        }
        else if (p->ai_family == AF_INET6)
        {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, sizeof(ip));
            ips_out.push_back(ip);
        }
    }

    freeaddrinfo(res);
    return !ips_out.empty();
}

/**
 * @brief 轻量版IP合法性判断（只判断是否是纯IP，不引入复杂逻辑）
 * @param str 待判断字符串
 * @return 是合法IP返回true，否则false
 */
static bool is_valid_ip(const string& str)
{
    // IPv4判断（仅数字和.，且.的数量合法）
    int dot_count = 0;
    for (char c : str)
    {
        if (!isdigit(c) && c != '.') return false;
        if (c == '.') dot_count++;
    }
    if (dot_count == 3) return true;

    // IPv6简单判断（包含:且有数字/字母）
    bool has_colon = false;
    for (char c : str)
    {
        if (!isdigit(c) && !isalpha(c) && c != ':' && c != '.') return false;
        if (c == ':') has_colon = true;
    }
    return has_colon;
}

/**
 * @brief 判断进程是否在白名单
 */
static bool is_proc_whitelisted()
{
    string proc_path = get_current_proc_path();
    if (proc_path.empty()) return false;

    // 兼容/usr/bin → /bin路径简化
    string simplified_proc = proc_path;
    if (simplified_proc.find("/usr/bin/") == 0)
    {
        simplified_proc.replace(0, 4, "/bin");
    }

    for (const auto& white_proc : g_WhitelistProcs)
    {
        string simplified_white = white_proc;
        if (simplified_white.find("/usr/bin/") == 0)
        {
            simplified_white.replace(0, 4, "/bin");
        }
        if (proc_path == white_proc || simplified_proc == simplified_white)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief 检查目标地址是否命中黑名单（支持域名动态匹配）
 * @param target_addr 目标地址
 * @return 命中返回true，否则false
 */
static bool is_blocked(const InetAddr& target_addr)
{
    // 不在拦截时间段 → 直接放行
    if (!is_in_intercept_time()) return false;

    string target_ip = target_addr.getIp();
    uint16_t target_port = target_addr.getPort();

    for (const auto& entry : g_Blacklist)
    {
        // 1. 先检查IP:端口直接匹配（包括通配符）
        bool port_match = (entry.addr.getPort() == 0) ||
                          (entry.addr.getPort() == target_port);

        if (port_match)
        {
            const char* entry_ip = entry.addr.getIp();

            // 通配符匹配
            if (strcmp(entry_ip, "*") == 0)
                return true;

            // IP完全匹配
            if (strcmp(entry_ip, target_ip.c_str()) == 0)
                return true;
        }

        // 2. 如果是域名，尝试实时解析匹配
        if (entry.is_domain && !entry.url.empty())
        {
            // 检查端口是否匹配
            bool port_match_domain = (entry.addr.getPort() == 0) ||
                                     (entry.addr.getPort() == target_port);

            if (port_match_domain)
            {
                // 实时解析域名
                vector<string> resolved_ips;
                if (resolve_url_to_ips(entry.url, resolved_ips))
                {
                    for (const auto& resolved_ip : resolved_ips)
                    {
                        if (resolved_ip == target_ip)
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }

    return false;
}

/**
 * @brief 记录拦截/放行日志（参考示例风格，强化可读性）
 */
static void log_operation(const InetAddr& target_addr, const string& target_url,
                          const string& proc, const string& op_type, bool success)
{
    if (success)
    {
        g_log.write("✅ 拦截非白名单进程[%s]%s访问黑名单地址[%s]（原始URL：%s）\n",
                    proc.c_str(), op_type.c_str(), target_addr.getAddrStr().c_str(),
                    target_url.empty() ? "无" : target_url.c_str());
    }
    else
    {
        g_log.write("ℹ️ 放行进程[%s]%s访问地址[%s]（原始URL：%s）\n",
                    proc.c_str(), op_type.c_str(), target_addr.getAddrStr().c_str(),
                    target_url.empty() ? "无" : target_url.c_str());
    }
}
// ================================== </工具函数> ==================================

// ================================== <配置加载> ==================================
static void load_config()
{
    bool expected = false;
    // 使用compare_exchange_strong确保配置只加载一次
    if (!g_bConfigLoaded.compare_exchange_strong(expected, true))
    {
        return;
    }

    // 初始化日志
    g_log.open(g_logPath, ios::app, false, true);
    g_log.write("========== 开始加载URL拦截配置 ==========\n");
    g_log.write("配置文件路径：%s\n", g_configPath.c_str());

    // 读取XML配置
    cifile ifile;
    if (!ifile.open(g_configPath))
    {
        g_log.write("❌ 配置文件不存在，使用默认配置（拦截时间段：%s-%s）\n",
                    hhmm_to_str(g_InterceptTime.start_time).c_str(),
                    hhmm_to_str(g_InterceptTime.end_time).c_str());
        return;
    }

    string buf;
    int blacklist_count = 0, whitelist_count = 0;
    while (ifile.readline(buf))
    {
        string load;
        char* line = (char*)buf.c_str();

        // 使用OL库清理首尾空白（替代原trim函数）
        deleteLRchr(line);

        // 跳过注释和空行
        if (*line == '#' || *line == '\0') continue;

        // 解析拦截开始时间（XML读入00:00格式字符串，自动清理空白）
        if (getByXml(buf, "StartInterceptTime", load))
        {
            int parsed_time = 0;
            if (str_to_hhmm(load, parsed_time))
            {
                g_InterceptTime.start_time = parsed_time;
                g_log.write("✅ 加载拦截开始时间：%s\n", hhmm_to_str(parsed_time).c_str());
            }
            else
            {
                g_log.write("❌ 无效的开始时间格式[%s]，使用默认值%s\n",
                            load.c_str(), hhmm_to_str(g_InterceptTime.start_time).c_str());
            }
        }
        // 解析拦截结束时间（XML读入00:00格式字符串，自动清理空白）
        else if (getByXml(buf, "EndInterceptTime", load))
        {
            int parsed_time = 0;
            if (str_to_hhmm(load, parsed_time))
            {
                g_InterceptTime.end_time = parsed_time;
                g_log.write("✅ 加载拦截结束时间：%s\n", hhmm_to_str(parsed_time).c_str());
            }
            else
            {
                g_log.write("❌ 无效的结束时间格式[%s]，使用默认值%s\n",
                            load.c_str(), hhmm_to_str(g_InterceptTime.end_time).c_str());
            }
        }

        // 解析进程白名单（清理空白后存储）
        else if (getByXml(buf, "WhitelistProc", load))
        {
            deleteLRchr(load); // 清理首尾空白
            if (!load.empty())
            {
                g_WhitelistProcs.push_back(load);
                g_log.write("✅ 加载白名单进程：%s\n", load.c_str());
                whitelist_count++;
            }
        }

        // 解析黑名单（IP:端口 / URL:端口，清理空白）
        else if (getByXml(buf, "BlacklistEntry", load))
        {
            deleteLRchr(load); // 清理首尾空白
            if (load.empty() || blacklist_count >= MAX_BLACKLIST) continue;

            // 分割目标（IP/URL）和端口
            size_t colon_pos = load.find(':');
            if (colon_pos == string::npos) continue;

            string target_str = load.substr(0, colon_pos);
            string port_str = load.substr(colon_pos + 1);

            // 清理目标和端口字符串的空白
            deleteLRchr(target_str);
            deleteLRchr(port_str);

            // 解析端口（支持*通配，记录显示用字符串）
            uint16_t port = 0;
            string port_display = "*"; // 日志显示用
            if (port_str != "*")
            {
                long port_val = strtol(port_str.c_str(), nullptr, 10);
                if (port_val < 1 || port_val > 65535)
                {
                    g_log.write("❌ 无效端口：%s，跳过该条目\n", port_str.c_str());
                    continue;
                }
                port = static_cast<uint16_t>(port_val);
                port_display = port_str; // 用原始端口字符串显示
            }

            // 构造黑名单条目
            BlacklistEntry entry;
            entry.url = target_str;
            entry.mask = "";

            // 处理通配符*
            if (target_str == "*")
            {
                // 通配所有IP，默认构造IPv4的0.0.0.0:端口
                entry.addr = InetAddr("0.0.0.0", port);
                entry.is_domain = false;
                g_log.write("✅ 加载黑名单：*:%s（通配所有IP）\n", port_display.c_str());
                g_Blacklist.push_back(entry);
                blacklist_count++;
                continue;
            }

            // 处理合法IP地址（直接构造InetAddr）
            if (is_valid_ip(target_str))
            {
                try
                {
                    entry.addr = InetAddr(target_str, port);
                    entry.is_domain = false;
                    g_log.write("✅ 加载黑名单：%s:%s\n",
                                target_str.c_str(), port_display.c_str());
                    g_Blacklist.push_back(entry);
                    blacklist_count++;
                }
                catch (const invalid_argument& e)
                {
                    g_log.write("❌ 无效IP地址：%s，跳过该条目\n", target_str.c_str());
                    continue;
                }
            }
            // 处理URL/域名（标记为域名，动态解析）
            else
            {
                // 对于域名，我们将其标记为域名类型，并记录端口
                // 同时解析一次域名，获取主IP用于日志显示
                string resolved_ip;
                sa_family_t family;
                if (resolve_url_to_ip(target_str, resolved_ip, family))
                {
                    try
                    {
                        entry.addr = InetAddr(resolved_ip, port);
                        entry.is_domain = true;
                        g_log.write("✅ 加载域名黑名单：%s:%s（域名：%s）\n",
                                    resolved_ip.c_str(), port_display.c_str(), target_str.c_str());
                        g_Blacklist.push_back(entry);
                        blacklist_count++;
                    }
                    catch (const invalid_argument& e)
                    {
                        g_log.write("❌ 解析后的IP无效：%s，跳过该条目\n", resolved_ip.c_str());
                        continue;
                    }
                }
                else
                {
                    g_log.write("❌ 无法解析域名：%s，跳过该条目\n", target_str.c_str());
                    continue;
                }
            }
        }
    }

    // 配置加载完成
    g_log.write("========== 配置加载完成 ==========\n");
    g_log.write("黑名单条目数：%d\n", blacklist_count);
    g_log.write("白名单进程数：%d\n", whitelist_count);
    g_log.write("拦截时间段：%s - %s\n",
                hhmm_to_str(g_InterceptTime.start_time).c_str(),
                hhmm_to_str(g_InterceptTime.end_time).c_str());
    g_log.write("==================================\n");
}
// ================================== </配置加载> ==================================

// ================================== <系统调用劫持> ==================================
/**
 * @brief 劫持connect函数（核心拦截逻辑）
 */
typedef int (*orig_connect_t)(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
orig_connect_t orig_connect = nullptr;

extern "C" int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
    // 懒加载配置，确保只加载一次
    load_config();

    // 初始化原函数（这里不需要compare_exchange，因为dlsym可以安全地多次调用）
    if (!orig_connect)
    {
        orig_connect = (orig_connect_t)dlsym(RTLD_NEXT, "connect");
        if (!orig_connect)
        {
            // 注意：这里不能使用g_log，因为可能还没初始化
            const char* error = dlerror();
            write(STDERR_FILENO, "❌ 获取原connect函数失败：", 35);
            if (error) write(STDERR_FILENO, error, strlen(error));
            write(STDERR_FILENO, "\n", 1);
            errno = EINVAL;
            return -1;
        }
    }

    // 白名单进程 → 直接放行
    if (is_proc_whitelisted())
    {
        g_log.write("ℹ️ 放行白名单进程[%s]访问\n", get_current_proc_path());
        return orig_connect(sockfd, addr, addrlen);
    }

    // 非IP协议（如Unix域套接字）→ 放行
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
    {
        return orig_connect(sockfd, addr, addrlen);
    }

    // 用InetAddr封装目标地址（简化IP/端口提取）
    InetAddr target_addr(addr, addrlen);
    string proc_path = get_current_proc_path();

    // 检查是否命中黑名单（支持域名动态匹配）
    bool blocked = is_blocked(target_addr);

    // 找到匹配的黑名单条目（用于日志显示）
    string matched_url = "";
    if (blocked)
    {
        // 查找匹配的黑名单条目，获取原始URL用于日志
        for (const auto& entry : g_Blacklist)
        {
            if (entry.is_domain)
            {
                vector<string> resolved_ips;
                if (resolve_url_to_ips(entry.url, resolved_ips))
                {
                    for (const auto& ip : resolved_ips)
                    {
                        if (ip == target_addr.getIp() &&
                            (entry.addr.getPort() == 0 || entry.addr.getPort() == target_addr.getPort()))
                        {
                            matched_url = entry.url;
                            break;
                        }
                    }
                }
            }
            else
            {
                // 对于IP条目，检查是否匹配
                bool ip_match = (strcmp(entry.addr.getIp(), "*") == 0) ||
                                (strcmp(entry.addr.getIp(), target_addr.getIp()) == 0);
                bool port_match = (entry.addr.getPort() == 0) ||
                                  (entry.addr.getPort() == target_addr.getPort());

                if (ip_match && port_match)
                {
                    matched_url = entry.url;
                    break;
                }
            }
            if (!matched_url.empty()) break;
        }

        log_operation(target_addr, matched_url, proc_path, "connect", true);
        errno = ECONNREFUSED;
        return -1;
    }

    // 放行并记录日志
    log_operation(target_addr, "", proc_path, "connect", false);
    return orig_connect(sockfd, addr, addrlen);
}

/**
 * @brief 劫持connectat函数（兼容新系统）
 */
typedef int (*orig_connectat_t)(int dirfd, int sockfd, const struct sockaddr* addr, socklen_t addrlen, int flags);
orig_connectat_t orig_connectat = nullptr;

extern "C" int connectat(int dirfd, int sockfd, const struct sockaddr* addr, socklen_t addrlen, int flags)
{
    load_config();

    if (!orig_connectat)
    {
        orig_connectat = (orig_connectat_t)dlsym(RTLD_NEXT, "connectat");
        if (!orig_connectat)
        {
            const char* error = dlerror();
            write(STDERR_FILENO, "❌ 获取原connectat函数失败：", 39);
            if (error) write(STDERR_FILENO, error, strlen(error));
            write(STDERR_FILENO, "\n", 1);
            errno = EINVAL;
            return -1;
        }
    }

    if (is_proc_whitelisted())
    {
        g_log.write("ℹ️ 放行白名单进程[%s]访问\n", get_current_proc_path());
        return orig_connectat(dirfd, sockfd, addr, addrlen, flags);
    }

    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
    {
        return orig_connectat(dirfd, sockfd, addr, addrlen, flags);
    }

    InetAddr target_addr(addr, addrlen);
    string proc_path = get_current_proc_path();

    bool blocked = is_blocked(target_addr);

    // 查找匹配的黑名单条目
    string matched_url = "";
    if (blocked)
    {
        for (const auto& entry : g_Blacklist)
        {
            if (entry.is_domain)
            {
                vector<string> resolved_ips;
                if (resolve_url_to_ips(entry.url, resolved_ips))
                {
                    for (const auto& ip : resolved_ips)
                    {
                        if (ip == target_addr.getIp() &&
                            (entry.addr.getPort() == 0 || entry.addr.getPort() == target_addr.getPort()))
                        {
                            matched_url = entry.url;
                            break;
                        }
                    }
                }
            }
            else
            {
                bool ip_match = (strcmp(entry.addr.getIp(), "*") == 0) ||
                                (strcmp(entry.addr.getIp(), target_addr.getIp()) == 0);
                bool port_match = (entry.addr.getPort() == 0) ||
                                  (entry.addr.getPort() == target_addr.getPort());

                if (ip_match && port_match)
                {
                    matched_url = entry.url;
                    break;
                }
            }
            if (!matched_url.empty()) break;
        }

        log_operation(target_addr, matched_url, proc_path, "connectat", true);
        errno = ECONNREFUSED;
        return -1;
    }

    log_operation(target_addr, "", proc_path, "connectat", false);
    return orig_connectat(dirfd, sockfd, addr, addrlen, flags);
}
// ================================== </系统调用劫持> ==================================