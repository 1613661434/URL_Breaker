#include "url_breaker.h"
#include <algorithm>
#include <sys/types.h>
#include <pwd.h>
#include <cstring>
#include <unistd.h>

// #define DEBUG

// 安全转换字符串到int
int URLBreaker::safe_stoi(const std::string& s, int default_val)
{
    if (s.empty()) return default_val;
    char* end;
    long val = strtol(s.c_str(), &end, 10);
    if (*end != '\0') return default_val;
    return static_cast<int>(val);
}

// 解析时间字符串
bool URLBreaker::parseTimeStr(const std::string& time_str, int& hour, int& min)
{
    if (time_str.empty()) return false;
    size_t colon = time_str.find(':');
    if (colon == std::string::npos || colon == 0 || colon == time_str.size() - 1)
    {
        return false;
    }
    hour = safe_stoi(time_str.substr(0, colon), -1);
    min = safe_stoi(time_str.substr(colon + 1), -1);
    return (hour >= 0 && hour <= 24) && (min >= 0 && min <= 60);
}

// 执行系统命令
std::string URLBreaker::execCmd(const std::string& cmd)
{
    if (cmd.empty()) return "";
    char buffer[1024] = {0};
    std::string result = "";

    // 用popen执行，设置超时
    FILE* pipe = popen(("timeout 1 " + cmd).c_str(), "r");
    if (!pipe) return "";

    // 循环读取输出
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        result += buffer;
        memset(buffer, 0, sizeof(buffer)); // 清空缓冲区
    }
    pclose(pipe);

    // 清理特殊字符
    result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
    result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());
    result.erase(std::remove(result.begin(), result.end(), '\0'), result.end());

    return result;
}

// 获取当前程序进程名
std::string URLBreaker::getProcessName()
{
    char buf[256] = {0};
    snprintf(buf, sizeof(buf), "/proc/%d/comm", getpid());
    std::ifstream comm_file(buf);
    std::string name;
    if (comm_file.is_open())
    {
        getline(comm_file, name);
        comm_file.close();
    }
    return name.empty() ? "unknown" : name;
}

// 加载XML配置
bool URLBreaker::loadConfig(const std::string& xml_path)
{
    tinyxml2::XMLDocument doc;
    tinyxml2::XMLError err = doc.LoadFile(xml_path.c_str());
    if (err != tinyxml2::XML_SUCCESS)
    {
        std::cerr << "Load XML failed: " << xml_path << " (err: " << err << ")" << std::endl;
        return false;
    }

    // 解析根节点
    tinyxml2::XMLElement* root_elem = doc.FirstChildElement("URLBreakerConfig");
    if (!root_elem)
    {
        std::cerr << "XML root 'URLBreakerConfig' not found!" << std::endl;
        return false;
    }

    // 解析全局配置
    tinyxml2::XMLElement* global_elem = root_elem->FirstChildElement("Global");
    if (global_elem)
    {
        // 日志路径
        tinyxml2::XMLElement* log_path_elem = global_elem->FirstChildElement("LogPath");
        if (log_path_elem && log_path_elem->GetText())
        {
            global_cfg.log_path = log_path_elem->GetText();
        }
        // iptables链名
        tinyxml2::XMLElement* ipt_chain_elem = global_elem->FirstChildElement("IptablesChain");
        if (ipt_chain_elem && ipt_chain_elem->GetText())
        {
            global_cfg.ipt_chain = ipt_chain_elem->GetText();
        }
        // 持久化规则
        tinyxml2::XMLElement* persist_rule_elem = global_elem->FirstChildElement("PersistRule");
        if (persist_rule_elem && persist_rule_elem->GetText())
        {
            global_cfg.persist_rule = (std::string(persist_rule_elem->GetText()) == "true");
        }
        // 清理内核日志
        tinyxml2::XMLElement* clean_log_elem = global_elem->FirstChildElement("CleanKernelLog");
        if (clean_log_elem && clean_log_elem->GetText())
        {
            global_cfg.clean_kernel_log = (std::string(clean_log_elem->GetText()) == "true");
        }
    }

    // 解析时间段规则
    tinyxml2::XMLElement* time_rules_elem = root_elem->FirstChildElement("TimeRules");
    if (time_rules_elem)
    {
        tinyxml2::XMLElement* time_rule_elem = time_rules_elem->FirstChildElement("TimeRule");
        while (time_rule_elem)
        {
            TimeRule tr;
            // 开始时间
            tinyxml2::XMLElement* start_elem = time_rule_elem->FirstChildElement("Start");
            if (start_elem && start_elem->GetText())
            {
                tr.start = start_elem->GetText();
            }
            // 结束时间
            tinyxml2::XMLElement* end_elem = time_rule_elem->FirstChildElement("End");
            if (end_elem && end_elem->GetText())
            {
                tr.end = end_elem->GetText();
            }
            // 有效规则才添加
            if (!tr.start.empty() && !tr.end.empty())
            {
                time_rules.push_back(tr);
            }
            time_rule_elem = time_rule_elem->NextSiblingElement("TimeRule");
        }
        writeLog_timeRules();
    }

    // 解析黑名单
    tinyxml2::XMLElement* black_list_elem = root_elem->FirstChildElement("BlackList");
    if (black_list_elem)
    {
        tinyxml2::XMLElement* item_elem = black_list_elem->FirstChildElement("Item");
        while (item_elem)
        {
            const char* item_text = item_elem->GetText();
            if (!item_text)
            {
                item_elem = item_elem->NextSiblingElement("Item");
                continue;
            }
            std::string item = item_text;
            size_t colon = item.find(':');
            if (colon != std::string::npos && colon > 0 && colon < item.size() - 1)
            {
                BlackItem bi;
                bi.ip = item.substr(0, colon);
                bi.port = safe_stoi(item.substr(colon + 1), 0);
                black_list.push_back(bi);
            }
            item_elem = item_elem->NextSiblingElement("Item");
        }
    }

    return true;
}

// 判断当前是否在拦截时段
bool URLBreaker::isInInterceptTime()
{
    time_t now = time(nullptr);
    tm* tm_now = localtime(&now);
    if (!tm_now) return false; // 空指针保护

    int curr_hour = tm_now->tm_hour;
    int curr_min = tm_now->tm_min;
    int curr_total = curr_hour * 60 + curr_min;

    for (const auto& tr : time_rules)
    {
        int start_h, start_m, end_h, end_m;
        if (!parseTimeStr(tr.start, start_h, start_m)) continue;
        if (!parseTimeStr(tr.end, end_h, end_m)) continue;

        int start_total = start_h * 60 + start_m;
        int end_total = end_h * 60 + end_m;

        // 时间段判断（支持跨天，如23:00-02:00）
        if (start_total <= end_total)
        {
            // 正常时段（如09:00-18:00）
            if (curr_total >= start_total && curr_total <= end_total)
            {
                return true;
            }
        }
        else
        {
            // 跨天时段（如23:00-02:00）
            if (curr_total >= start_total || curr_total <= end_total)
            {
                return true;
            }
        }
    }
    return false;
}

// 加载iptables规则
bool URLBreaker::loadIptablesRules()
{
    // 创建自定义链
    std::string cmd_create_chain = "sudo iptables -N " + global_cfg.ipt_chain + " 2>/dev/null";
    execCmd(cmd_create_chain);

    // 清空已有规则
    clearIptablesRules();

    // 遍历黑名单添加规则
    for (const auto& bi : black_list)
    {
        std::string log_prefix = "\"URL_BREAKER: \" ";
        std::string cmd_tcp_log, cmd_tcp_drop;
        std::string cmd_udp_log, cmd_udp_drop;
        std::string cmd_icmp_log, cmd_icmp_drop;

        if (bi.port == 0)
        {
            // 所有端口
            cmd_tcp_log = "sudo iptables -A " + global_cfg.ipt_chain + " -p tcp -d " + bi.ip + " -j LOG --log-prefix " + log_prefix + "--log-level info 2>/dev/null";
            cmd_tcp_drop = "sudo iptables -A " + global_cfg.ipt_chain + " -p tcp -d " + bi.ip + " -j DROP 2>/dev/null";
            cmd_udp_log = "sudo iptables -A " + global_cfg.ipt_chain + " -p udp -d " + bi.ip + " -j LOG --log-prefix " + log_prefix + "--log-level info 2>/dev/null";
            cmd_udp_drop = "sudo iptables -A " + global_cfg.ipt_chain + " -p udp -d " + bi.ip + " -j DROP 2>/dev/null";
            cmd_icmp_log = "sudo iptables -A " + global_cfg.ipt_chain + " -p icmp -d " + bi.ip + " -j LOG --log-prefix " + log_prefix + "--log-level info 2>/dev/null";
            cmd_icmp_drop = "sudo iptables -A " + global_cfg.ipt_chain + " -p icmp -d " + bi.ip + " -j DROP 2>/dev/null";
        }
        else
        {
            // 指定端口
            cmd_tcp_log = "sudo iptables -A " + global_cfg.ipt_chain + " -p tcp -d " + bi.ip + " --dport " + std::to_string(bi.port) + " -j LOG --log-prefix " + log_prefix + "--log-level info 2>/dev/null";
            cmd_tcp_drop = "sudo iptables -A " + global_cfg.ipt_chain + " -p tcp -d " + bi.ip + " --dport " + std::to_string(bi.port) + " -j DROP 2>/dev/null";
            cmd_udp_log = "sudo iptables -A " + global_cfg.ipt_chain + " -p udp -d " + bi.ip + " --dport " + std::to_string(bi.port) + " -j LOG --log-prefix " + log_prefix + "--log-level info 2>/dev/null";
            cmd_udp_drop = "sudo iptables -A " + global_cfg.ipt_chain + " -p udp -d " + bi.ip + " --dport " + std::to_string(bi.port) + " -j DROP 2>/dev/null";
            cmd_icmp_log = "sudo iptables -A " + global_cfg.ipt_chain + " -p icmp -d " + bi.ip + " -j LOG --log-prefix " + log_prefix + "--log-level info 2>/dev/null";
            cmd_icmp_drop = "sudo iptables -A " + global_cfg.ipt_chain + " -p icmp -d " + bi.ip + " -j DROP 2>/dev/null";
        }

        // 执行规则
        execCmd(cmd_tcp_log);
        execCmd(cmd_tcp_drop);
        execCmd(cmd_udp_log);
        execCmd(cmd_udp_drop);
        execCmd(cmd_icmp_log);
        execCmd(cmd_icmp_drop);

        // 记录日志
        writeLog(bi.ip, bi.port, "拦截成功（TCP/UDP/ICMP）");
    }

    // 挂到OUTPUT链
    std::string cmd_detach_chain = "sudo iptables -D OUTPUT -j " + global_cfg.ipt_chain + " 2>/dev/null";
    execCmd(cmd_detach_chain);
    std::string cmd_attach_chain = "sudo iptables -I OUTPUT 1 -j " + global_cfg.ipt_chain + " 2>/dev/null";
    execCmd(cmd_attach_chain);

    // 持久化规则
    if (global_cfg.persist_rule)
    {
        persistIptablesRules();
    }

    return true;
}

// 清空iptables规则
bool URLBreaker::clearIptablesRules()
{
    std::string cmd = "sudo iptables -F " + global_cfg.ipt_chain + " 2>/dev/null";
    std::string result = execCmd(cmd);
    if (result.empty())
    {
        for (const auto& bi : black_list)
        {
            writeLog(bi.ip, bi.port, "规则已清空");
        }
        return true;
    }
    else
    {
        writeLog("未知IP", 0, "清空规则失败：" + result);
        return false;
    }
}

// 记录日志（重载1）
void URLBreaker::writeLog(const std::string& target_ip, int port, const std::string& result)
{
    std::string curr_proc = getProcessName();
    std::string curr_pid = std::to_string(getpid());
    writeLog(target_ip, port, result, curr_proc, curr_pid);
}

// 记录日志（重载2）
void URLBreaker::writeLog(const std::string& target_ip, int port, const std::string& result,
                          const std::string& proc_name, const std::string& pid)
{
    pthread_mutex_lock(&log_mutex);

    // 生成时间戳
    time_t now = time(nullptr);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // 拼接日志
    std::string proc_label = (proc_name == getProcessName()) ? "进程" : "发起进程";
    std::string log_content = "[" + std::string(time_buf) + "] " + proc_label + "：" + proc_name + "(" + pid + ") " + "目标IP：" + target_ip + (port == 0 ? ":所有端口" : ":" + std::to_string(port)) + " " + "执行结果：" + result + "\n";

    // 写入日志文件
    std::ofstream log_file(global_cfg.log_path, std::ios::app);
    if (log_file.is_open())
    {
        log_file << log_content;
        log_file.close();
    }
    else
    {
        std::cerr << "Open log failed: " << global_cfg.log_path << std::endl;
    }

    pthread_mutex_unlock(&log_mutex);
}

// 记录时间规则日志
void URLBreaker::writeLog_timeRules()
{
    pthread_mutex_lock(&log_mutex);

    // 生成时间戳
    time_t now = time(nullptr);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // 拼接日志
    std::ostringstream oss;
    for (size_t i = 0; i < time_rules.size(); ++i)
    {
        oss << "[" + std::string(time_buf) + "] " << "加载时间规则[" << i + 1 << "]:" << time_rules[i].start << "-" << time_rules[i].end << "\n";
    }

    // 写入日志文件
    std::ofstream log_file(global_cfg.log_path, std::ios::app);
    if (log_file.is_open())
    {
        log_file << oss.str();
        log_file.close();
    }
    else
    {
        std::cerr << "Open log failed: " << global_cfg.log_path << std::endl;
    }

    pthread_mutex_unlock(&log_mutex);
}

// 持久化iptables规则
bool URLBreaker::persistIptablesRules()
{
    execCmd("sudo mkdir -p /etc/sysconfig 2>/dev/null");
    std::string cmd = "sudo iptables-save > /etc/sysconfig/iptables 2>/dev/null";
    std::string result = execCmd(cmd);

    if (result.empty())
    {
        writeLog("全局", 0, "规则已持久化");
        return true;
    }
    else
    {
        writeLog("全局", 0, "规则持久化失败：" + result);
        return false;
    }
}

// 解析内核日志行
bool URLBreaker::parseKernelLogLine(const std::string& line, KernelLogInfo& log_info)
{
    log_info.proto = "";
    log_info.dst_ip = "";
    log_info.spt = -1;
    log_info.icmp_id = -1;

    // 提取PROTO
    size_t proto_pos = line.find("PROTO=");
    if (proto_pos == std::string::npos) return false;
    size_t proto_end = line.find(' ', proto_pos + 6);
    if (proto_end == std::string::npos) proto_end = line.size();
    log_info.proto = line.substr(proto_pos + 6, proto_end - (proto_pos + 6));

    // 提取DST
    size_t dst_pos = line.find("DST=");
    if (dst_pos == std::string::npos) return false;
    size_t dst_end = line.find(' ', dst_pos + 4);
    if (dst_end == std::string::npos) dst_end = line.size();
    log_info.dst_ip = line.substr(dst_pos + 4, dst_end - (dst_pos + 4));

    // 提取SPT（TCP/UDP，兼容不同格式）
    if (log_info.proto == "TCP" || log_info.proto == "UDP")
    {
        size_t spt_pos = line.find("SPT=");
        if (spt_pos != std::string::npos)
        {
            size_t spt_end = line.find(' ', spt_pos + 4);
            if (spt_end == std::string::npos) spt_end = line.size();
            log_info.spt = safe_stoi(line.substr(spt_pos + 4, spt_end - (spt_pos + 4)), -1);
        }
    }

    // 提取ICMP ID（兼容ID=和icmp_id=两种格式）
    if (log_info.proto == "ICMP")
    {
        size_t icmp_id_pos = line.find("ID=");
        // 兼容ICMP ID的另类格式
        if (icmp_id_pos == std::string::npos) icmp_id_pos = line.find("icmp_id=");
        if (icmp_id_pos != std::string::npos)
        {
            int offset = (icmp_id_pos == line.find("ID=")) ? 3 : 8;
            size_t icmp_id_end = line.find(' ', icmp_id_pos + offset);
            if (icmp_id_end == std::string::npos) icmp_id_end = line.size();
            log_info.icmp_id = safe_stoi(line.substr(icmp_id_pos + offset, icmp_id_end - (icmp_id_pos + offset)), -1);
        }
    }

    return true;
}

// 查询发起进程
std::pair<std::string, std::string> URLBreaker::getInitiatorProcess(const KernelLogInfo& log_info)
{
    std::string pid = "unknown";
    std::string proc_name = "unknown";

    // ========== TCP/UDP 进程查询 ==========
    if (log_info.proto == "TCP" || log_info.proto == "UDP")
    {
        if (log_info.spt <= 0) return {proc_name, pid};

        // 命令：netstat -tulnp | grep 源端口 | 提取PID和进程名（root权限必能查到）
        std::string cmd = "netstat -tulnp 2>/dev/null | grep -E ':" + std::to_string(log_info.spt) + "\\b' | grep -v 'LISTEN' | awk '{print $7}' | head -1";
        std::string result = execCmd(cmd);

        if (!result.empty())
        {
            // 清理输出（移除换行/回车/空格）
            result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
            result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());
            result.erase(std::remove(result.begin(), result.end(), ' '), result.end());

            // 分割 PID/进程名（格式：pid/name）
            size_t slash_pos = result.find('/');
            if (slash_pos != std::string::npos && slash_pos > 0)
            {
                pid = result.substr(0, slash_pos);
                if (slash_pos < result.size() - 1)
                {
                    proc_name = result.substr(slash_pos + 1);
                }
            }
        }

        // 用lsof再次尝试（如果netstat失败）
        if (pid == "unknown")
        {
            cmd = "lsof -i " + log_info.proto + ":" + std::to_string(log_info.spt) + " 2>/dev/null | grep -v 'COMMAND' | awk '{print $2,$1}' | head -1";
            result = execCmd(cmd);
            if (!result.empty())
            {
                std::istringstream iss(result);
                iss >> pid >> proc_name;
            }
        }
    }

    // ========== ICMP 进程查询 ==========
    else if (log_info.proto == "ICMP")
    {
        // ICMP TYPE=8 是ping请求，TYPE=0是响应
        if (log_info.icmp_id <= 0 || log_info.dst_ip.empty())
        {
            proc_name = "ping（未知PID）";
            pid = "unknown";
            return {proc_name, pid};
        }

        // 命令：列出所有ping进程，检查其目标IP是否匹配
        std::string cmd = "ps -ef 2>/dev/null | grep 'ping ' | grep -v 'grep'";
        std::string result = execCmd(cmd);

        if (!result.empty())
        {
            std::istringstream iss(result);
            std::string line;
            while (std::getline(iss, line))
            {
                // 检查ping命令行是否包含目标IP
                if (line.find(log_info.dst_ip) != std::string::npos)
                {
                    // 提取PID（第2列）和进程名（第8列）
                    std::istringstream line_iss(line);
                    std::string uid, ppid, ppid_str, comm;
                    line_iss >> uid >> pid >> ppid_str; // 跳过uid，取pid
                    // 提取ping参数后的进程名（实际是ping）
                    proc_name = "ping";
                    break;
                }
            }
        }

        // 若未匹配到，标注为ping
        if (pid == "unknown")
        {
            proc_name = "ping";
            pid = "unknown";
        }
    }

    // ========== 最终兜底处理 ==========
    if (pid.empty() || pid == "0" || pid == "-1") pid = "unknown";
    if (proc_name.empty() || proc_name == "?") proc_name = "unknown";

    return {proc_name, pid};
}

// 处理单条内核日志（去重）
void URLBreaker::processKernelLogLine(const std::string& line)
{
    if (line.find("URL_BREAKER:") == std::string::npos) return;

    // 去重
    pthread_mutex_lock(&processed_logs_mutex);
    if (processed_logs.count(line) > 0)
    {
        pthread_mutex_unlock(&processed_logs_mutex);
        return;
    }
    processed_logs.insert(line);
    pthread_mutex_unlock(&processed_logs_mutex);

    // 解析日志
    KernelLogInfo log_info;
    if (!parseKernelLogLine(line, log_info)) return;

    // 匹配黑名单
    for (const auto& bi : black_list)
    {
        if (log_info.dst_ip == bi.ip)
        {
            std::pair<std::string, std::string> info = getInitiatorProcess(log_info);
            writeLog(bi.ip, bi.port, "拦截成功 实时拦截事件：" + line, info.first, info.second);
            break;
        }
    }
}

// 监控内核日志线程
void* URLBreaker::monitorKernelLog(void* arg)
{
    URLBreaker* breaker = static_cast<URLBreaker*>(arg);
    if (!breaker) return nullptr;

    // 清空历史日志
    breaker->execCmd("dmesg -c");

    // 实时监控
    FILE* pipe = popen("LC_ALL=C dmesg -w | grep --line-buffered \"URL_BREAKER:\"", "r");
    if (!pipe)
    {
        breaker->writeLog("全局", 0, "监控线程启动失败：无法打开dmesg");
        return nullptr;
    }

    char buffer[512];
    while (breaker->is_running.load())
    {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr)
        {
            std::string line(buffer);
            // 清理字符
            line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
            line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
            line.erase(std::remove(line.begin(), line.end(), '\0'), line.end());
            // 处理日志
            breaker->processKernelLogLine(line);
        }
        usleep(1000);
    }

    pclose(pipe);
    return nullptr;
}

// 启动监控线程
bool URLBreaker::startMonitorThread()
{
    if (is_running.load()) return true;
    is_running.store(true);

    int ret = pthread_create(&monitor_thread, nullptr, monitorKernelLog, this);
    if (ret != 0)
    {
        is_running.store(false);
        writeLog("全局", 0, "启动监控线程失败：" + std::string(strerror(ret)));
        return false;
    }

    pthread_detach(monitor_thread);
    writeLog("全局", 0, "实时监控线程已启动");
    return true;
}

// 停止监控线程
void URLBreaker::stopMonitorThread()
{
    if (!is_running.load()) return;
    is_running.store(false);
    pthread_cancel(monitor_thread);
    writeLog("全局", 0, "实时监控线程已停止");
}