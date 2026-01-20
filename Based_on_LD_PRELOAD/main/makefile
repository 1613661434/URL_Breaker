# URL拦截者编译配置
CXX = g++
# 编译选项：
CXXFLAGS = -Wall -fPIC -std=c++17 -O2 -pthread -I./ol/include
# 动态库链接参数：
LDFLAGS = -shared -fPIC -Wl,--whole-archive ./ol/lib/libol.a -Wl,--no-whole-archive -ldl -pthread

# 目标文件：
SO_FILE = url_breaker.so

# 测试文件路径
TEST_DIR = ../test

# 编译规则
all: $(SO_FILE) $(TEST_DIR)/test_conn_norm $(TEST_DIR)/test_conn_brea $(TEST_DIR)/test_conn_brea_whi $(TEST_DIR)/test_tcp_server

# 动态库编译
$(SO_FILE): URL_Breaker.o
	$(CXX) $(LDFLAGS) -o $@ $^
	@echo "✅ 动态库编译完成：$@"

URL_Breaker.o: URL_Breaker.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# 非白名单进程访问非黑名单URL测试程序
$(TEST_DIR)/test_conn_norm: $(TEST_DIR)/test_conn_norm.cpp
	$(CXX) -std=c++17 -o $@ $< -pthread
	@echo "✅ 非白名单进程访问非黑名单URL测试程序编译完成：$@"

# 非白名单进程访问黑名单URL测试程序
$(TEST_DIR)/test_conn_brea: $(TEST_DIR)/test_conn_brea.cpp
	$(CXX) -std=c++17 -o $@ $< -pthread
	@echo "✅ 非白名单进程访问黑名单URL测试程序：$@"

# 白名单进程访问黑名单URL测试程序
$(TEST_DIR)/test_conn_brea_whi: $(TEST_DIR)/test_conn_brea_whi.cpp
	$(CXX) -std=c++17 -o $@ $< -pthread
	@echo "✅ 白名单进程访问黑名单URL测试程序：$@"

# TCP测试服务器程序
$(TEST_DIR)/test_tcp_server: $(TEST_DIR)/test_tcp_server.cpp
	$(CXX) -std=c++17 -o $@ $< -pthread
	@echo "✅ 测试服务器程序编译完成：$@"

# 测试目标
test: all
	@echo "========================================"
	@echo "🔍 第一步：启动本地TCP测试服务器"
	# 启动服务器并记录PID
	$(TEST_DIR)/test_tcp_server & sleep 2

	@echo "========================================"
	@echo "🔍 第二步：测试非白名单进程访问非黑名单URL（test_conn_norm）"
	LD_PRELOAD=./$(SO_FILE) $(TEST_DIR)/test_conn_norm

	@echo "========================================"
	@echo "🔍 第三步：测试非白名单进程访问黑名单URL（test_conn_brea）"
	LD_PRELOAD=./$(SO_FILE) $(TEST_DIR)/test_conn_brea

	@echo "========================================"
	@echo "🔍 第四步：测试白名单进程访问黑名单URL（test_conn_brea_whi）"
	LD_PRELOAD=./$(SO_FILE) $(TEST_DIR)/test_conn_brea_whi

	@echo "========================================"
	@echo "🔍 第五步：查看拦截日志"
	@tail -20 url_breaker.log || echo "日志文件暂未生成"

# 清理规则
clean:
	rm -f *.o *.so $(TEST_DIR)/test_conn_norm $(TEST_DIR)/test_conn_brea $(TEST_DIR)/test_conn_brea_whi $(TEST_DIR)/test_tcp_server
	rm -f ./url_breaker.log
	@echo "✅ 清理完成"