# anasche: eBPF-based Process Scheduling Latency Monitor

`anasche` 是基于 libbpf (CO-RE) 的进程调度延迟（排队时间）监控与分析工具。

提供一键运行的监控脚本和实时可视化看板，可作为研究 Linux 内核调度行为的工具，适用于：

- 多核调度算法的性能评估
- 高并发场景下的延迟抖动分析
- 自定义调度策略的底层数据采集
- 特定进程的调度性能诊断

**核心特性：**

- 基于 Raw Tracepoint 的低开销监控
- 支持按 PID 或进程名过滤（内核态过滤，零开销）
- 实时 TUI 可视化 + CSV 数据导出
- CO-RE 技术支持跨内核版本运行

---

## 设计思路

进程的调度延迟（Scheduling Latency）或排队时间，指的是一个进程从具备运行条件（Runnable）到真正 CPU 调度执行（Running）之间所经历的时间。

为了捕获这一时间差，`anasche` 的核心逻辑分为三个阶段：

### 1. 状态追踪：捕获入队时刻

在内核态使用了 `raw_tp` (Raw Tracepoint) 的程序类型，而不是常用的 `tracepoint`。由于调度器事件触发极其频繁，`raw_tp` 省略了参数打包的过程，虽然后续拿信息比较麻烦，但是能够最大程度减少探针自身的性能开销。

工具监听了三种进程进入就绪队列的场景：

- **`raw_tp/sched_wakeup`**: 当一个睡眠中的进程被唤醒时触发
- **`raw_tp/sched_wakeup_new`**: 当一个新进程被创建并准备好运行时触发
- **抢占逻辑**: 在 `sched_switch` 事件中，如果前一个进程（`prev`）的状态为 `TASK_RUNNING`（即被抢占而非主动睡眠），它会重新回到就绪队列，需要重新记录入队时间

在这三种情况下，eBPF 程序会：

1. 使用 `BPF_CORE_READ` 安全读取进程的 PID 和进程名
2. 通过 `should_trace()` 函数进行内核态过滤（支持按 PID 或进程名过滤）
3. 调用 `bpf_ktime_get_ns()` 获取当前纳秒级时间戳
4. 将入队时间存入 `BPF_MAP_TYPE_HASH` 类型的 Map（键为 PID，值为入队时间戳）

**内核态过滤机制**：引入统一的过滤函数 `should_trace()`，在三个事件处理路径中复用。当用户通过 `-p` 或 `-n` 参数指定目标进程时，内核态会直接过滤不相关进程，避免无意义的 Map 写入和 Ringbuf 传输，实现零开销过滤。

**CO-RE 跨版本兼容**：实现了 `get_task_state()` 函数，通过 `bpf_core_field_exists` 检测内核是否使用 `__state` 字段（Linux 5.14+），自动适配新旧内核的 `task_struct` 结构体差异，保证在不同内核版本上均可正确判断进程是否为 TASK_RUNNING 抢占状态。

### 2. 延迟计算：捕获运行时刻

真正发生上下文切换时，会触发 `raw_tp/sched_switch` 事件。在这个事件处理函数中：

1. **处理被抢占的进程**：检查前一个进程（`prev`）的状态，如果为 `TASK_RUNNING`（被抢占），且通过 `should_trace()` 过滤，则更新其入队时间
2. **计算等待时间**：获取即将执行的新进程（`next`）的 PID，从 Hash Map 中查找其入队时间戳，计算 `队列等待时间 = 当前时间戳 - 入队时间戳`
3. **数据清理**：计算完成后，通过 `bpf_map_delete_elem` 将该 PID 从 Hash Map 中删除，释放空间

**关键修复**：正确处理了 CPU 从空闲进程（PID 0）切换到其他进程的场景，确保所有进程切换都被正确追踪。

### 3. 内核态至用户态的通信

使用 `BPF_MAP_TYPE_RINGBUF` 环形缓冲区（256KB）进行异步数据传输，防止数据回传阻塞内核调度。

eBPF 探针将计算好的调度延迟数据打包成 `event` 结构体（包含 PID、进程名、排队时间），通过 `bpf_ringbuf_reserve` 和 `bpf_ringbuf_submit` 异步提交。用户态程序通过 `ring_buffer__poll` 持续轮询并拉取数据。

### 4. 数据处理与可视化

为了兼顾实时观测与后续科研作图，采用双层架构：

- **C 程序 (anasche)**：作为数据管道，接收 eBPF 探针传来的二进制数据，格式化为标准的 CSV 格式输出到标准输出：`timestamp,pid,comm,que_time_us`。CSV 数据可用 Origin、MATLAB 或 Python 进行后续分析和作图。

  <img width="305" height="224" alt="image" src="https://github.com/user-attachments/assets/167ffc74-92e7-49a0-8c3e-f2d80697dcc5" />

- **Python 脚本 (dash.py)**：从标准输入读取 CSV 数据流，使用 `rich` 库渲染实时 TUI 面板：
  - **左侧**：调度延迟分布直方图（10 个区间，从 < 5 us 到 > 5 ms），显示绝对计数和百分比占比
  - **右侧**：最近 15 条调度事件的实时日志（时间、PID、进程名、延迟）
  - **自动保存**：所有原始数据自动保存到带时间戳的 CSV 文件（`anasche_data_YYYYMMDD_HHMMSS.csv`）

  <img width="1374" height="352" alt="image" src="https://github.com/user-attachments/assets/dc1ec24f-11e3-42ac-9b69-d8d8f0750d62" />


---

## 环境要求

- **内核版本**：Linux 5.8+ (推荐 5.14+ 以获得更好的 CO-RE 支持)
- **libbpf**：需要安装 libbpf 开发库
  - 参考配置：<https://github.com/libbpf/libbpf>
  - 详见其中 `libbpf/README.md`
- **编译工具**：gcc, make, clang, llvm (用于编译 eBPF 程序)
- **Python 环境**：Python 3.x + `rich` 库

  ```bash
  pip install rich
  ```

- **权限**：需要 root 权限运行（加载 eBPF 程序需要 CAP_BPF 或 CAP_SYS_ADMIN）

---

## 命令行参数

`anasche` 支持通过命令行参数进行灵活配置：

| 参数 | 说明 |
|------|------|
| `-h, --help` | 显示帮助信息 |
| `-p, --pid <pid>` | 只追踪指定 PID 的进程（内核态过滤） |
| `-n, --name <name>` | 只追踪指定名称的进程（最多 15 字符，内核态过滤） |
| `-d, --duration <seconds>` | 设置程序运行时间（秒），超时后自动退出 |
| `-v, --verbose` | 显示详细的 libbpf 调试日志 |

**使用示例：**

```bash
# 查看帮助
sudo ./anasche -h

# 只追踪 PID 为 1234 的进程
sudo ./anasche -p 1234 | python3 dash.py

# 只追踪名为 "mysql" 的进程
sudo ./anasche -n mysql | python3 dash.py

# 运行 60 秒后自动退出
sudo ./anasche -d 60 | python3 dash.py

# 组合使用：追踪特定进程，运行 30 秒
sudo ./anasche -p 5678 -d 30 | python3 dash.py

# 开启详细日志模式
sudo ./anasche -v | python3 dash.py
```

<img width="750" height="464" alt="image" src="https://github.com/user-attachments/assets/75a7abd0-5a5f-47fe-950e-6fa49f8b67a0" />

---

## 快速开始

### 1. 编译

进入项目目录，执行以下命令进行编译：

```bash
make
```

编译过程会：

- 使用 `clang` 编译 eBPF 内核态代码（`anasche.bpf.c` → `anasche.bpf.o`）
- 使用 `bpftool` 生成 skeleton 头文件（`anasche.skel.h`）
- 使用 `gcc` 编译用户态程序（`anasche.c` → `anasche`）

### 2. 运行

使用管道将 `anasche` 的 CSV 输出传递给可视化脚本：

```bash
sudo ./anasche | python3 dash.py
```

> **注意**：
>
> - 需要 root 权限加载 eBPF 程序
> - 如果可视化启动太快导致终端被覆盖，来不及输入 sudo 密码，可以先执行 `sudo ls` 输入一次密码（短时间内无需再 sudo），或直接以 root 用户运行

### 3. 带参数运行示例

```bash
# 只追踪指定进程，运行 10 秒
sudo ./anasche -n chromium -d 10 | python3 dash.py

# 查看原始 CSV 输出（不启动可视化）
sudo ./anasche -d 5

# 追踪特定 PID，开启详细日志
sudo ./anasche -p 1234 -v | python3 dash.py
```

---

## 输出格式

`anasche` 默认输出 CSV 格式数据到标准输出，每行包含四个字段：

```csv
timestamp,pid,comm,que_time_us
1734567890,1234,myproc,125
```

字段说明：

- `timestamp`: Unix 时间戳（秒）
- `pid`: 进程 ID
- `comm`: 进程名称（最多 15 字符）
- `que_time_us`: 调度队列等待时间（微秒，原始纳秒值除以 1000）

---

## 项目结构

```text
anasche-ebpf-monitor/
├── anasche.bpf.c       # eBPF 内核态代码（探针逻辑）
├── anasche.c           # 用户态 C 程序（数据接收与 CSV 输出）
├── anasche.h           # 内核态与用户态共享的数据结构定义
├── dash.py             # Python 可视化脚本（TUI 面板）
├── vmlinux.h           # 内核数据结构定义（bpftool 生成）
├── Makefile            # 编译脚本
└── README.md           # 项目文档
```

---

## 技术亮点

### 1. 低开销监控

- 使用 Raw Tracepoint 而非普通 Tracepoint，省略参数打包过程
- 内核态过滤机制，避免无效数据传输到用户态
- 环形缓冲区异步传输，不阻塞内核调度路径

### 2. CO-RE (Compile Once, Run Everywhere)

- 使用 `BPF_CORE_READ` 宏进行安全的内核数据结构访问
- 通过 `bpf_core_field_exists` 自动适配不同内核版本的结构体差异
- 无需为每个内核版本重新编译，一次编译即可在不同内核上运行

### 3. 精确的调度延迟测量

- 纳秒级时间戳精度（`bpf_ktime_get_ns()`）
- 正确处理三种入队场景：唤醒、新进程创建、抢占
- 修复了空闲进程切换时的追踪遗漏问题

### 4. 灵活的过滤机制

- 支持按 PID 过滤（`-p` 参数）
- 支持按进程名过滤（`-n` 参数，使用 Hash Map 白名单）
- 过滤逻辑在内核态执行，零用户态开销

---

## 版本历史

### v1.1 (当前版本)

**核心修复：**

- 修复 CPU 从空闲进程（PID 0）切换到其他进程时忽略切换进程的问题

**新增功能：**

- 新增 CO-RE 兼容的 `task_struct` 状态字段读取（`get_task_state()`），自动适配 Linux 5.14+ 的 `__state` 字段
- 新增内核态进程名过滤机制（`target_comms` BPF Map + `should_trace()` 统一过滤函数）
- 新增 `argp` 命令行参数解析，支持 `-p`、`-n`、`-d`、`-v` 参数
- 抢占路径中应用目标过滤，仅对用户关心的进程更新入队时间

**可视化优化：**

- 直方图新增统计进程数的百分比占比显示
- 自动生成带时间戳的 CSV 数据文件

### v1.0

- 初始版本，基础调度延迟监控功能
- CSV 输出与 Rich 可视化面板

---

## 常见问题

**Q: 为什么需要 root 权限？**

A: 加载 eBPF 程序需要 `CAP_BPF` 或 `CAP_SYS_ADMIN` 权限，通常需要 root 用户或使用 `sudo`。

**Q: 支持哪些内核版本？**

A: 理论上支持 Linux 5.8+，推荐 5.14+ 以获得更好的 CO-RE 支持。工具会自动适配不同内核版本的结构体差异。

**Q: 如何减少性能开销？**

A: 使用 `-p` 或 `-n` 参数进行内核态过滤，只追踪关心的进程，可以显著降低开销。

**Q: CSV 数据保存在哪里？**

A: 当使用 `dash.py` 可视化时，数据会自动保存到当前目录下的 `anasche_data_YYYYMMDD_HHMMSS.csv` 文件。如果只运行 `anasche` 而不使用 `dash.py`，数据只会输出到标准输出。

**Q: 可以同时追踪多个进程吗？**

A: 当前版本 `-p` 参数只支持单个 PID，但 `-n` 参数支持追踪所有同名进程（例如多个 `nginx` 工作进程）。如果不指定任何过滤参数，会追踪系统中所有进程。

---

## 许可证

Dual BSD/GPL

---

## 联系方式

- 作者邮箱：<ZY2502205@buaa.edu.cn>
- 问题反馈：请在 GitHub Issues 中提交
