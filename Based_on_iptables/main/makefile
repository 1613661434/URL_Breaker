# Makefile for URLBreaker (兼容Ubuntu 16.04 + GCC 5.4)
CC = g++
CFLAGS = -std=c++11 -Wall -O2
LIBS = -ltinyxml2 -lpthread
TARGET = url_breaker
SRCS = main.cpp url_breaker.cpp
LOG_FILE = /home/ol/URL_Breaker/3/url_breaker.log

all: $(TARGET)

# 编译生成可执行文件
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)
	@echo "Compile success! Run with: sudo ./$(TARGET) ./url_breaker.xml"

# 清理编译产物

.PHONY:clean log deps

clean:
	rm -f $(TARGET)
	@echo "Cleanup done!"

# 查看日志
log:
	tail -f $(LOG_FILE)

# 安装依赖
deps:
	sudo apt update && sudo apt install -y libtinyxml2-dev net-tools lsof iproute2