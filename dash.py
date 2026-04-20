import sys
import time
from datetime import datetime
from collections import deque
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text

# ---- 1. 数据与文件配置 ----
# 存储最近的 15 条调度记录
recent_events = deque(maxlen=15)

# 细化的 1ms - 10ms 统计区间（针对科研实测优化）
buckets = {
    "< 5 us": 0,
    "5 - 10 us": 0,
    "10 - 30 us": 0,
    "30 - 50 us": 0,
    "50 - 100 us": 0,
    "100 - 300 us": 0,
    "300 - 500 us": 0,
    "500 us - 1 ms": 0,
    "1 - 5 ms": 0,
    "> 5 ms": 0
}

stats = {"total": 0, "max_delay": 0}
# 自动创建实验数据文件
LOG_FILE_NAME = f"anasche_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

def categorize(delay_us):
    """根据高精度微秒值进行分桶"""
    if delay_us < 5: return "< 5 us"
    elif delay_us < 10: return "5 - 10 us"
    elif delay_us < 30: return "10 - 30 us"
    elif delay_us < 50: return "30 - 50 us"
    elif delay_us < 100: return "50 - 100 us"
    elif delay_us < 300: return "100 - 300 us"
    elif delay_us < 500: return "300 - 500 us"
    elif delay_us < 1000: return "500 us - 1 ms"
    elif delay_us < 5000: return "1 - 5 ms"
    else: return "> 5 ms"

def generate_layout():
    """实时渲染 TUI 布局"""
    # --- 左侧：高精度直方图 ---
    hist_table = Table(show_header=False, box=None, expand=True)
    hist_table.add_column("Bucket", style="cyan", justify="right", width=15)
    hist_table.add_column("Bar", style="blue")
    hist_table.add_column("Count", justify="left", width=10)

    # 找出除了长尾桶之外的最大值，避免长尾数据压平其他柱子
    normal_values = list(buckets.values())[:-1]
    max_count = max(normal_values) if any(normal_values) else (buckets["> 5 ms"] or 1)
    
    max_bar_width = 40 
    fractional_blocks = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"]

    for b_name, count in buckets.items():
        proportion = count / max_count
        total_eighths = int(proportion * max_bar_width * 8)
        full_blocks = min(total_eighths // 8, max_bar_width)
        remainder = total_eighths % 8 if full_blocks < max_bar_width else 0
        
        bar_string = "█" * full_blocks + fractional_blocks[remainder]
        
        # 毫秒级变色逻辑：1-4ms 黄色，5ms+ 红色
        color = "green" if any(x in b_name for x in ["< 5 us","5 - 10 us","10 - 30 us", "30 - 50 us"]) else ("red" if any(x in b_name for x in ["1 - 5 ms", "> 5 ms"]) else "yellow")
        bar = f"[{color}]{bar_string}[/]"
        hist_table.add_row(b_name, bar, str(count))

    # --- 右侧：实时日志 ---
    log_table = Table(show_header=True, header_style="bold magenta", expand=True)
    log_table.add_column("Time", width=10)
    log_table.add_column("PID", justify="right", style="dim", width=8)
    log_table.add_column("COMM", style="cyan")
    log_table.add_column("Delay(us)", justify="right", style="bold")

    for ev in reversed(recent_events):
        d_val = ev['delay']
        d_str = f"[red]{d_val}[/]" if d_val > 5000 else (f"[yellow]{d_val}[/]" if d_val > 1000 else f"[green]{d_val}[/]")
        log_table.add_row(ev['time'], ev['pid'], ev['comm'], d_str)

    layout = Layout()
    layout.split_column(Layout(name="header", size=3), Layout(name="main"))
    layout["main"].split_row(
        Layout(Panel(hist_table, title="[bold white]调度延迟分布[/]"), ratio=1),
        Layout(Panel(log_table, title="[bold white]实时日志[/]"), ratio=1)
    )
    
    status_msg = f" 🟢 正在记录至: {LOG_FILE_NAME} | 总数: {stats['total']}"
    layout["header"].update(Panel(Text(status_msg, style="bold white on blue", justify="center")))
    return layout

# ---- 2. 运行主循环 ----
if __name__ == "__main__":
    # 打开文件并写入 CSV 头
    with open(LOG_FILE_NAME, "w") as f:
        f.write("timestamp,pid,comm,delay_us\n")
        
        with Live(generate_layout(), refresh_per_second=10, screen=True) as live:
            try:
                for line in sys.stdin:
                    line = line.strip()
                    if not line or "timestamp" in line: continue
                    
                    # 写入原始数据到文件
                    f.write(line + "\n")
                    f.flush()

                    try:
                        parts = line.split(',')
                        if len(parts) != 4: continue
                        
                        ts, pid, comm, delay_us = int(parts[0]), parts[1], parts[2], int(parts[3])
                        time_str = datetime.fromtimestamp(ts).strftime('%H:%M:%S')

                        stats['total'] += 1
                        if delay_us > stats['max_delay']: stats['max_delay'] = delay_us
                        
                        buckets[categorize(delay_us)] += 1
                        recent_events.append({"time": time_str, "pid": pid, "comm": comm, "delay": delay_us})
                        live.update(generate_layout())

                    except (ValueError, IndexError):
                        pass
            except KeyboardInterrupt:
                pass