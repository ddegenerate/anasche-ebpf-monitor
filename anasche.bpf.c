#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "anasche.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define MAX_ENTRIES	10240
//记录入队时间戳
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);
	__type(value, u64);
} start SEC(".maps");
//用环形缓冲区向用户态传PID,time等
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 分配 256KB 的内存作为缓冲区
} ring SEC(".maps");
//关注三个事件
//sched_wakeup 进程从睡眠态被唤醒
//sched_wakeup_new 当一个新创建的进程准备好运行
//sched_switch cpu从一个进程切换到另一个进程时触发
const volatile unsigned long long min_duration_ns = 0;

SEC("raw_tp/sched_wakeup") //原始跟踪点程序，挂载到sched_wakeup这一个跟踪点   相较于普通的tracepoint，带raw的不作任何打包，减小性能损耗，因为这个触发很频繁
int BPF_PROG(handle_sched_wakeup,struct task_struct *p)    //对应的上下文格式去vmlinux.h文件里面对应查，因为是void *ctx，所以这里直接用PROG宏
{
    u32 sw_pid=BPF_CORE_READ(p,pid);//安全读取进程指针中的进程id
	if(!sw_pid)
		return 0;
	u64 sw_time=bpf_ktime_get_ns(); //获取当前系统时间，精确到ns
	bpf_map_update_elem(&start,&sw_pid,&sw_time,BPF_ANY);  //对应存进哈希表中，键为进程id，值为唤醒时间
	return 0;
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new,struct task_struct *p)
{
	u32 swn_pid=BPF_CORE_READ(p,pid);
    if(!swn_pid)
		return 0;
	u64 swn_time=bpf_ktime_get_ns(); 
	bpf_map_update_elem(&start,&swn_pid,&swn_time,BPF_ANY); //基本一模一样写了一遍
	return 0;
}

SEC("raw_tp/sched_switch")  //raw原始版本直接不打包传过来，所以都用PROG宏
int BPF_PROG(handle_sched_switch,bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)//后面的一堆参数typedef void (*btf_trace_sched_switch)(void *, bool, struct task_struct *, struct task_struct *, unsigned int);
{
	if(prev_state==0)  //之前的进程被抢占
	{
		u32 prev_pid=BPF_CORE_READ(prev,pid);
		if(!prev_pid)
		    return 0;
		u64 swich_prev_time=bpf_ktime_get_ns();
		bpf_map_update_elem(&start,&prev_pid,&swich_prev_time,BPF_ANY);   //被抢占的进程以及抢占时间存进哈希表
	}
    u32 next_pid=BPF_CORE_READ(next,pid); //读要进来的进程pid
	u64 *pre_pro_time=bpf_map_lookup_elem(&start,&next_pid);//去查找之前排队的时间 注意查找返回的是指针
	if(!pre_pro_time)
	    return 0;
	u64 now_pro_time=bpf_ktime_get_ns();
	u64 que_time=now_pro_time-(*pre_pro_time);   //计算出队列等待时间
	if (que_time < 0)
	    goto cleanup;
	struct event *e;//要传输的结构体指针
	e=bpf_ringbuf_reserve(&ring,sizeof(*e),0); //在环形缓冲区申请一片空间
	if(e)//申请成功把pid，quetime，command等东西往环形缓冲区里面存
	{
		e->pid=next_pid;
		e->que_time=que_time;
		bpf_probe_read_kernel_str(&e->comm,sizeof(e->comm),next->comm);
		bpf_ringbuf_submit(e,0);
	}
	cleanup:
	    bpf_map_delete_elem(&start,&next_pid); //存完之后把哈希表释放
		return 0;
}