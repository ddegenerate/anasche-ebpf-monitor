#ifndef __ANASCHE_H
#define __ANASCHE_H

struct event {
    unsigned int pid;
    unsigned long long que_time; // 排队时间
    char comm[16];               // 进程名
};

#endif 
