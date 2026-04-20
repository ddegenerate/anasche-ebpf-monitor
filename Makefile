# 定义基础变量，方便以后改名
APP = anasche
BPF_C = $(APP).bpf.c
BPF_OBJ = $(APP).bpf.o
USER_C = $(APP).c
SKEL_H = $(APP).skel.h

# 默认的终极目标
all: $(APP)

# 第一步：把内核 C 代码编译成 eBPF 字节码 (.o)
$(BPF_OBJ): $(BPF_C) anasche.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c $(BPF_C) -o $(BPF_OBJ)

# 第二步：用 bpftool 读取 .o 文件，自动生成包含骨架代码的头文件 (.skel.h)
$(SKEL_H): $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $(SKEL_H)

# 第三步：编译用户态 C 代码，并链接 libbpf 库，生成最终的可执行文件
$(APP): $(USER_C) $(SKEL_H) anasche.h
	gcc -g -O2 -Wall $(USER_C) -o $(APP) -lbpf -lelf -lz

# 清理编译产生的临时文件
clean:
	rm -f $(APP) $(BPF_OBJ) $(SKEL_H)