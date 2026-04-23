#include <stdio.h>
#include <argp.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
//内核和用户态共享的数据结构协议
#include "anasche.h"
#include "anasche.skel.h" //bpftool 自动生成
//加入argp解析
//配置本，有目标进程名及id和持续时间
static struct env
{
	bool verbose;
	int target_pid;
	char target_commd[16];
	int duration_time;
} env;
//常规的-version和-help等内容
const char *argp_program_version = "anasche 1.1";
const char *argp_program_bug_address = "<ZY2502205@buaa.edu.cn>";
const char argp_program_doc[] =
"进程调度性能检测工具\n"
"\n"
"可以追踪每个进程或指定单独某个进程的队列等待时间\n"
"终端可视化窗口左侧会显示进程调度时间直方图，右侧显示实时日志，同时对应目录下会自动导出csv数据\n"
"导出数据格式为'timestamp,pid,comm,delay_us'\n"
"\n"
"用法: ./anasche [-d <运行时间>] [-v] [-p <特定进程id>] [-n <特定进程名字>]\n";
//配置文档
static const struct argp_option opts[] =
{
	{"verbose", 'v', NULL, 0, "方便开发者看的详细日志"},
	{"pid",'p',"process_id",0,"追踪特定的进程id"},
	{"name",'n',"command_name",0,"追踪特定的进程名字"},
	{"duration",'d',"dura_time",0,"指定运行多长时间后自动退出"},
	{},
};
//解析函数
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch(key)
	{
		case 'p':
			env.target_pid=strtol(arg,NULL,10); //默认arg是字符串，把字符串转10进制整数
			break;
		case 'n':
			snprintf(env.target_commd,sizeof(env.target_commd),"%s",arg);  //复制字符串
			break;
		case 'd':
			env.duration_time=strtol(arg,NULL,10);
			break;
		case 'v':
			env.verbose=true;
			break;
		case ARGP_KEY_ARG:
			argp_usage(state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
//总控
static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};
//详细信息过滤
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose) 
		return 0;
	return vfprintf(stderr, format, args);  
}
static volatile bool exiting = false;
static void sig_handler(int sig)
{
	exiting = true;
}
//收到ringbuffer后的处理逻辑
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e=data; //定义结构体准备接收数据
	//进程名过滤放用户态来做
	if (env.target_commd[0] != '\0' && strncmp(e->comm, env.target_commd, 16) != 0)  //目标command不为0且接手过来的command不是要的command，直接return 0
	{
        return 0;
    }
	time_t now=time(NULL); //获取当前时间戳
	printf("%ld,%u,%s,%llu\n",now,e->pid,e->comm,e->que_time/1000); //当前时间，进程id，进程名，排队时间，前面是ns，这里除以1000转成us
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct anasche_bpf *skel;
	int err;
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL); 
	if (err)
		return err;
	libbpf_set_print(libbpf_print_fn);
	struct rlimit rlim= 
	
	{
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
	//绑定ctrl+c的退出信号
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	if (env.duration_time > 0)
	{
        signal(SIGALRM, sig_handler); // 拦截闹钟信号
        alarm(env.duration_time);          // 定下指定秒数的闹钟
    }
	//打开BPFskel
	skel = anasche_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	skel->rodata->targ_pid = env.target_pid;
	//加载验证
	err = anasche_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	//挂载到追踪点
	err = anasche_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	//设置ringbuffer的监听
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ring), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	//打印csv表头
	printf("timestamp,pid,comm,que_time_us\n");
    fflush(stdout);
	//死循环拉数据
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		//捕获ctrl c
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}
cleanup:
	ring_buffer__free(rb);
	anasche_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
