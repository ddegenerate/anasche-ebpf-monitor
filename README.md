# anasche: eBPF-based Process Scheduling Latency Monitor

`anasche` 是基于 libbpf (CO-RE) 的进程调度延迟（排队时间）监控与分析工具。

提供一键运行的监控脚本和可视化看板，可作为一个研究 Linux 内核调度行为的小工具，适用于不同多核调度算法的性能评估、高并发场景下的延迟抖动分析以及自定义调度策略的底层数据抓取。

---

## 设计思路

进程的调度延迟（Scheduling Latency）或排队时间，指的是一个进程从具备运行条件（Runnable）到真正 CPU 调度执行（Running）之间所经历的时间。

为了捕获这一时间差，`anasche` 的核心逻辑分为三个阶段：

### 1. 状态追踪：捕获入队时刻
在内核态使用了 `raw_tp` (Raw Tracepoint) 的程序类型，而不是常用的 `tracepoint`。由于调度器事件触发极其频繁，`raw_tp` 省略了参数打包的过程，虽然后续拿信息比较麻烦，但是能够最大程度减少探针自身的性能开销。

工具监听了两个进程进入就绪队列的事件：
* **`raw_tp/sched_wakeup`**: 当一个睡眠中的进程被唤醒时触发。
* **`raw_tp/sched_wakeup_new`**: 当一个新进程被创建并准备好运行时触发。
* **抢占逻辑**: 在进程切换时，如果前一个进程（`prev`）是因为时间片耗尽等原因被抢占，它会重新回到就绪队列，重新开始排队。

在这三种情况下，eBPF 程序会安全读取进程的 PID，并通过 `bpf_ktime_get_ns()` 获取当前纳秒级时间戳，将其存入类型为 `BPF_MAP_TYPE_HASH` 的 BPF Map 中（键为 PID，值为入队时间）。

### 2. 延迟计算：捕获运行时刻
真正发生上下文切换时，会触发 `raw_tp/sched_switch` 事件，对这个事件也进行监听。
在这里，探针会获取即将执行的新进程的 PID，并去之前的 Hash Map 中查找它对应的入队时间。
* **等待时间计算**: `队列等待时间 = 当前时间戳 - 入队时间戳`。
* **数据清理**: 计算完成后，通过 `bpf_map_delete_elem` 将该 PID 从 Hash Map 中释放。
* **v1.1 修复**: 修复了原来 CPU 从空闲进程（PID 0）切换到其他进程时会忽略切换进程的问题，确保所有进程切换都被正确追踪。

### 3. 内核态至用户态的通信
为了防止数据回传阻塞内核调度，分配了一块 256KB 的环形缓冲区。
eBPF 探针将计算好的等待时间、PID 以及进程名打包成事件结构体，通过异步提交。用户态程序持续轮询并拉取数据。

### 4. 数据处理与可视化
为了兼顾实时观测与后续科研作图：
* **C**: 扮演数据管道的角色，将收到的二进制数据格式化为标准的 `timestamp,pid,comm,que_time_us` 以 CSV 格式输出，后续可用 Origin 或 MATLAB 进行作图。
  
  <img width="305" height="224" alt="image" src="https://github.com/user-attachments/assets/167ffc74-92e7-49a0-8c3e-f2d80697dcc5" />

* **Python**: 拦截标准输入流，对微秒值进行统计，使用 `rich` 库渲染出 us 到 ms 区间的多维直方图 TUI 面板，实现调度性能诊断，同时在另一侧不断实时更新 PID、command、队列时间日志。
  
  **v1.1 增强**: 直方图新增统计进程数的百分比占比，更直观地观察不同延迟区间的分布比例。
  
<img width="1374" height="352" alt="image" src="https://github.com/user-attachments/assets/dc1ec24f-11e3-42ac-9b69-d8d8f0750d62" />


---

## 环境

* **libbpf 环境配置**: 主要参考链接 https://github.com/libbpf/libbpf/tree/a6d7530cb7dff87ac1e64a540e63b67ddde2e0f9，参见其中 `libbpf/README.md` 细节
* **运行环境**: Python 3.x, `rich` 库 (`pip install rich`)

---

## 命令行参数 (v1.1 新增)

`anasche` 现在支持通过 `argp` 解析命令行参数，提供更灵活的使用方式：

| 参数 | 说明 |
|------|------|
| `-h, --help` | 显示帮助信息 |
| `-p, --pid <pid>` | 只追踪指定 PID 的进程（可多次使用） |
| `-n, --name <name>` | 只追踪指定名称的进程（可多次使用） |
| `-d, --duration <seconds>` | 设置程序运行时间（秒），超时后自动退出 |
| `-v, --verbose` | 方便开发者查看的详细日志 |

**使用示例：**

```bash
# 查看帮助
sudo ./anasche -h

# 只追踪 PID 为 1234 的进程
sudo ./anasche -p 1234 | python3 dash.py

# 只追踪名为 "mysql" 和 "nginx" 的进程
sudo ./anasche -n mysql -n nginx | python3 dash.py

# 同时追踪特定 PID 和特定名称
sudo ./anasche -p 1234 -n redis | python3 dash.py

# 运行 60 秒后自动退出
sudo ./anasche -d 60 | python3 dash.py

# 组合使用：追踪特定进程，运行 30 秒
sudo ./anasche -p 5678 -d 30 | python3 dash.py

# 开启详细日志模式
sudo ./anasche -v | python3 dash.py
```
<img width="750" height="464" alt="image" src="https://github.com/user-attachments/assets/75a7abd0-5a5f-47fe-950e-6fa49f8b67a0" />

---

## 开始

**1. 编译与运行**

进入对应文件目录，执行以下命令进行编译：

```bash
make
```

编译完成后，使用管道将 `anasche` 的输出传递给可视化脚本：

```bash
sudo ./anasche | python3 dash.py
```

> **注意**: 有时因为可视化启动太快导致终端被覆盖，来不及输入 sudo 密码。若出现此情况，可以先执行 `sudo ls` 输入一次密码（短时间内无需再 sudo），或直接以 root 用户运行。

**2. 带参数运行示例**

```bash
# 只追踪指定进程，运行 10 秒
sudo ./anasche -n chromium -d 10 | python3 dash.py

# 查看原始 CSV 输出（不启动可视化）
sudo ./anasche -d 5
```

---

## 输出格式

`anasche` 默认输出 CSV 格式数据到标准输出，每行包含四个字段：

```
timestamp,pid,comm,que_time_us
1734567890123456789,1234,myproc,125.32
```

- `timestamp`: 纳秒级时间戳
- `pid`: 进程 ID
- `comm`: 进程名称
- `que_time_us`: 调度队列等待时间（微秒）

---

## 版本历史

### v1.1 (当前版本)
- 修复 CPU 从空闲进程（PID 0）切换到其他进程时忽略切换进程的问题
- 优化可视化直方图显示，新增统计进程数的百分比占比
- 新增 `argp` 命令行参数解析
- 支持追踪特定 PID 或特定进程名称
- 支持自定义程序运行时间

### v1.0
- 初始版本，基础调度延迟监控功能
- CSV 输出与 Rich 可视化面板
