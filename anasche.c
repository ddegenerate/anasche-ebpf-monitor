#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
//内核和用户态共享的数据结构协议
#include "anasche.h"
#include "anasche.skel.h" //bpftool 自动生成

static volatile bool exiting = false;
static void sig_handler(int sig)
{
	exiting = true;
}
//收到ringbuffer后的处理逻辑
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e=data; //定义结构体准备接收数据
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
	struct rlimit rlim= 
	{
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
	//绑定ctrl+c的退出信号
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	//打开BPFskel
	skel = anasche_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
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
