# URL拦截者

* 中文名：URL拦截者
* 英文名：URL_Breaker

## 需求

1. 用户自定义的拦截时间段，可以多段时间段（24小时制）
2. 用户自定义不可访问的黑名单（ 含IP: 端口）；
3. 拦截所有对黑名单中IP的访问请求（仅在设定拦截时间段内生效）
4. 保存日志信息：时间戳，发起进程，目标IP/URL，执行结果（拦截成功/拦截失败）
5. 只在类UNIX平台使用

## 依赖

基于LD_PRELOAD的依赖个人开发的OL库：[https://github.com/1613661434/OL](https://github.com/1613661434/OL)
基于iptables的依赖tinyxml2库

## 注意事项

OL库关于XML是简单实现，就是依据标签来查找的，所以不支持注释等等功能，而且是一行一行读取

## 编译

基于LD_PRELOAD的记得自己改下**配置路径和日志路径**
```cpp
const string g_configPath = "";
const string g_logPath = "";
```

```bash
make
```


## 测试（基于LD_PRELOAD）

```bash
make test
```

## 使用

### 基于LD_PRELOAD：

通过LD_PRELOAD注入动态库

```bash
source export.sh
```

取消注入

```bash
source unset.sh
```

### 基于iptables：

```bash
sh start.sh
```