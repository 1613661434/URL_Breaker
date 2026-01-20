/*
 *  程序名：procctl.cpp(Process Control)，此程序是服务程序的调度模块。
 *  创建子进程后关闭父进程：第一次 fork() 后父进程退出，子进程成为守护进程。
 *  创建子进程的子进程：守护进程中循环调用 fork() 创建任务子进程。
 *  调度逻辑：
 *  1.任务子进程执行目标程序。
 *  2.守护进程通过 wait() 监控任务结束。
 *  3.休眠 timetvl 秒后重复上述过程。
 *  作者：ol
 */
#include <cstdio>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        printf("Using:./procctl timetvl program argv ...\n");
        printf("Example:/PROJECT/tools/bin/procctl 10 /usr/bin/tar zcvf /tmp/tmp.tgz /usr/include\n");
        printf("Example:/PROJECT/tools/bin/procctl 60 /PROJECT/idc/bin/crtsurfdata /PROJECT/idc/ini/stcode.ini /tmp/idc/surfdata /log/idc/crtsurfdata.log csv,xml,json\n");

        printf("本程序是服务程序的调度程序，周期性启动服务程序或shell脚本。\n");
        printf("timetvl 运行周期，单位：秒。\n");
        printf("        被调度的程序运行结束后，在timetvl秒后会被procctl重新启动。\n");
        printf("        如果被调度的程序是周期性的任务，timetvl设置为运行周期。\n");
        printf("        如果被调度的程序是常驻内存的服务程序，timetvl设置小于5秒。\n");
        printf("program 被调度的程序名，必须使用全路径。\n");
        printf("...     被调度的程序的参数。\n");
        printf("注意，本程序不会被kill杀死，但可以用kill -9强行杀死。\n\n");

        return -1;
    }

    // 关闭信号和I/O，本程序不希望被打扰。
    // 注意: 1）为了防调度程序被误杀，不处理退出信号；
    //       2）如果忽略和信号和关闭了I/O，将影响被调度的程序（也会忽略和信号和关闭了I/O）。
    //          why？因为被调度的程序取代了子进程，子进程会继承父进程的信号处理方式和I/O。
    for (int i = 0; i < 64; ++i) signal(i, SIG_IGN);
    for (int i = 0; i < 3; ++i) close(i);

    // 生成子进程，父进程退出，让程序运行在后台，由系统1号进程托管，不受shell的控制。
    if (fork() != 0) exit(0);

    // 把子进程退出的信号SIGCHLD恢复为默认行为，让父进程可以调用wait()函数等待子进程退出。
    signal(SIGCHLD, SIG_DFL);

    // 定义一个和argv一样大的指针数组，存放被调度程序名及其参数。
    char* prov[argc];
    for (int i = 2; i < argc; ++i) prov[i - 2] = argv[i];

    prov[argc - 2] = nullptr; // 空表示参数已结束。

    while (true)
    {
        if (fork() == 0)
        {
            // 子进程运行被调度的程序。
            execv(argv[2], prov);
            exit(0); // 如果被调度的程序运行失败，才会执行这行代码。
        }
        else
        {
            // 父进程等待子进程终止（被调度的程序运行结束）。
            // int status;
            // wait(&status);           // wait()函数会阻塞，直到被调度的程序终止。
            wait(nullptr);        // wait()函数会阻塞，直到被调度的程序终止。
            sleep(atoi(argv[1])); // 休眠timetvl秒，然后回到循环。
        }
    }
}