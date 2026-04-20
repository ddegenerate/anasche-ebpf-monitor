# anasche: eBPF-based Process Scheduling Latency Monitor

`anasche` 是基于 libbpf (CO-RE) 的进程调度延迟（排队时间）监控与分析工具。

提供一键运行的监控脚本和可视化看板，可作为一个研究 Linux 内核调度行为的小工具，适用于不同多核调度算法的性能评估、高并发场景下的延迟抖动分析以及自定义调度策略的底层数据抓取。

---

## 设计思路

进程的调度延迟（Scheduling Latency）或排队时间，指的是一个进程从具备运行条件（Runnable）到真正 CPU 调度执行（Running）之间所经历的时间。

为了捕获这一时间差，`anasche` 的核心逻辑分为三个阶段：

### 1. 状态追踪：捕获入队时刻
在内核态使用了 `raw_tp` (Raw Tracepoint) 的程序类型，而不是常用的 `tracepoint`。由于调度器事件触发极其频繁，`raw_tp` 省略了参数打包的过程，虽然后续拿信息比较麻烦，但是能够最大程度减少探针自身的性能开销。

工具监听了两个进程进入就绪队列的事件
* **`raw_tp/sched_wakeup`**: 当一个睡眠中的进程被唤醒时触发。
* **`raw_tp/sched_wakeup_new`**: 当一个新进程被创建并准备好运行时触发。
* **抢占逻辑**: 在进程切换时，如果前一个进程（`prev`）是因为时间片耗尽等原因被抢占，它会重新回到就绪队列，重新开始排队。

在这三种情况下，eBPF 程序会安全读取进程的 PID，并通过 `bpf_ktime_get_ns()` 获取当前纳秒级时间戳，将其存入类型为 `BPF_MAP_TYPE_HASH` 的 BPF Map 中（键为 PID，值为入队时间）。

### 2. 延迟计算：捕获运行时刻
真正发生上下文切换时，会触发 `raw_tp/sched_switch` 事件，对这个事件也进行监听。
在这里，探针会获取即将执行的新进程的 PID，并去之前的 Hash Map 中查找它对应的入队时间。
* **等待时间计算**: `队列等待时间 = 当前时间戳 - 入队时间戳`。
* **数据清理**: 计算完成后，通过 `bpf_map_delete_elem` 将该 PID 从 Hash Map 中释放。

### 3. 内核态至用户态的通信
为了防止数据回传阻塞内核调度，分配了一块 256KB 的环形缓冲区。
eBPF 探针将计算好的等待时间、PID 以及进程名打包成事件结构体，通过异步提交。用户态程序持续轮询并拉取数据。

### 4. 数据处理与可视化
为了兼顾实时观测与后续科研作图：
* **C**: 扮演数据管道的角色，将收到的二进制数据格式化为标准的 `timestamp,pid,comm,que_time_us` 以CSV格式输出，后续可用origin或MATLAB进行作图。
<img width="305" height="224" alt="image" src="https://github.com/user-attachments/assets/167ffc74-92e7-49a0-8c3e-f2d80697dcc5" />

* **Python**: 拦截标准输入流，对微秒值进行统计，使用 `rich` 库渲染出 us 到 ms 区间的多维直方图 TUI 面板，实现调度性能诊断，同时在另一侧不断实时更新PID，command，队列时间日志。
<img width="1561" height="346" alt="image" src="https://github.com/user-attachments/assets/326092fd-8731-496f-8ef8-166cb6cebe2b" />

---

## 环境

* **libbpf环境配置**: 主要参考链接https://github.com/libbpf/libbpf/tree/a6d7530cb7dff87ac1e64a540e63b67ddde2e0f9
                      参见其中libbpf/README.md细节
* **运行环境**: Python 3.x, `rich` 库 (`pip install rich`)

## 开始

**1. 编译与运行**

到对应文件目录下，执行以下命令进行编译：
```bash
Bash
make
```
使用 make 编译完成后，接着执行以下命令：
```bash
Bash
sudo ./anasche | python3 dash.py
```
这里有的时候可能会因为可视化启动太快导致覆盖终端，来不及输入sudo的密码，若出现这种情况可以先原地sudo ls，输入一次密码，这样短时间内就不用再sudo，或者直接以root运行
