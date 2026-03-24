# lsdriver 驱动说明（以当前源码为准）

> 仅供技术研究与学习，严禁用于非法用途。作者不承担任何违法责任。

交流群：
TG:https://t.me/+ArHIx-Km9jkxNjZl  
QQ:1092055800

---

## 1. 项目定位

`lsdriver` 是一个基于共享内存协议的内核模块，当前代码实现了以下能力：

1. 进程内存读写（`op_r` / `op_w`）
2. 进程内存布局枚举（`op_m`）
3. 虚拟触摸注入（`op_init_touch` / `op_down` / `op_move` / `op_up`）
4. ARM64 硬件断点管理与命中记录（`op_set_process_hwbp` / `op_remove_process_hwbp` / `op_brps_weps_info`）
5. 内核工作线程退出控制（`op_kexit`）

注意：当前驱动通信方式是“用户进程共享内存 + 内核线程轮询”，没有 `ioctl`/`netlink`/`procfs` 命令接口。

---

## 2. 代码结构

`lsdriver/` 目录下核心文件：

- `lsdriver.c`：模块入口、连接线程、调度线程、进程退出监听、模块/线程隐藏逻辑
- `io_struct.h`：共享内存协议定义（操作码、请求结构、返回结构）
- `physical.h`：进程内存读写与内存布局枚举实现
- `virtual_input.h`：虚拟触摸注入实现
- `hwbp.h`：ARM64 用户态硬件断点实现
- `export_fun.h`：`kallsyms_lookup_name` 获取与 CFI/KCFI 兼容调用封装
- `Makefile`：模块编译参数

---

## 3. 运行架构

模块初始化后会启动两个内核线程：

1. `ConnectThreadFunction`
2. `DispatchThreadFunction`

### 3.1 连接线程（Connect）

行为：

1. 周期遍历进程列表，查找 `task->comm == "LS"` 的进程。
2. 对固定用户地址 `0x2025827000` 执行 `get_user_pages_remote`，把请求结构体所在页 pin 住。
3. 通过 `vmap` 把这些页映射成内核可访问虚拟地址，赋给全局 `req`。
4. 设置 `ProcessExit=1`，并设置 `req->user=1` 通知用户侧“连接完成”。

内核版本分支：

- 5.10 / 5.15 / 6.1 / 6.5 / 6.12 通过条件编译适配了 `get_user_pages_remote` 参数签名差异。

### 3.2 调度线程（Dispatch）

行为：

1. 仅在 `ProcessExit=1` 时处理请求。
2. 通过 `atomic_read(req->kernel)` 判断是否有请求待处理。
3. 通过 `atomic_xchg(&req->kernel, 0)` 抢占请求处理权。
4. 按 `req->op` 分发到内存读写、内存枚举、虚拟触摸、硬件断点等函数。
5. 处理完成后 `atomic_set(&req->user, 1)` 通知用户侧结果可读。

轮询策略：

- 前 `5000` 轮 `cpu_relax()` 忙等，追求低延迟响应。
- 后续 `usleep_range(50, 100)`，降低空闲功耗。

---

## 4. 共享内存协议

协议结构定义在 `io_struct.h` 的 `struct req_obj`。

### 4.1 同步字段

- `kernel`：用户侧置 1，表示内核有待处理请求
- `user`：内核侧置 1，表示用户可读取结果

### 4.2 主要请求字段

- `op`：操作码（`enum sm_req_op`）
- `status`：返回状态 / 返回长度
- `pid`, `target_addr`, `size`, `user_buffer[0x1000]`：读写参数与数据缓冲
- `mem_info`：内存布局枚举结果
- `bt`, `bs`, `len_bytes`, `bp_info`：硬件断点参数/结果
- `POSITION_X`, `POSITION_Y`, `x`, `y`：触摸初始化返回与触摸坐标

### 4.3 操作码

- `op_o`：空调用
- `op_r`：读内存
- `op_w`：写内存
- `op_m`：枚举内存布局
- `op_down` / `op_move` / `op_up`：触摸按下/移动/抬起
- `op_init_touch`：初始化触摸
- `op_brps_weps_info`：读取 CPU 断点资源数量
- `op_set_process_hwbp`：设置硬件断点
- `op_remove_process_hwbp`：删除硬件断点
- `op_kexit`：结束内核线程循环

---

## 5. 内存读写实现（`physical.h`）

代码中保留两套“物理读写后端”：

1. PTE 重映射（方案 1）
2. 线性映射读写（方案 2）

当前默认路径是：**手动页表翻译 VA->PA + 线性映射读写物理内存**。

### 5.1 进程读写主流程

入口函数：

- `read_process_memory(...)`
- `write_process_memory(...)`
- 实际都走 `_process_memory_rw(...)`

关键优化：

1. `mm_struct` 缓存：`s_last_pid` / `s_last_mm`
2. 软件页缓存：`s_last_vpage_base` / `s_last_ppage_base`
3. 按页循环处理，自动拆分跨页访问

地址翻译：

- 当前实际启用：`walk_translate_va_to_pa(...)`
- 保留但未启用：`mmu_translate_va_to_pa(...)`（AT 指令 + TTBR0 切换方案）

物理读写：

- 当前实际启用：`linear_read_physical` / `linear_write_physical`
- 保留但未启用：`pte_read_physical` / `pte_write_physical`

返回值语义：

- 成功：返回成功处理的字节数
- 失败：返回负错误码（如 `-EFAULT`、`-EINVAL`）

### 5.2 进程内存布局枚举（`enum_process_memory`）

`memory_info` 输出两类数据：

1. `modules[]`：模块段信息（含 index/prot/start/end）
2. `regions[]`：可扫描私有 RW 区域（`rw-p`）

模块采集规则（当前代码）：

- 仅收集路径前缀命中 `/data/` 的文件映射
- 额外支持把匿名且紧邻前一模块段的可写区段识别为 BSS（`index=-1`）
- 兼容 BSS 只有 `-w-p` 的情况

扫描区过滤规则（当前代码）：

- 排除路径前缀：`/dev/`, `/system/`, `/vendor/`, `/apex/`
- 排除关键词：`.oat`, `.art`, `.odex`, `.vdex`, `.dex`, `.ttf`, `dalvik`, `gralloc`, `ashmem`
- 排除匿名栈区、`[vvar]/[vdso]/[vsyscall]`

后处理算法（当前实现）：

1. 物理地址排序
2. 体积聚类选主干（16MB 断层阈值）
3. 过滤远端诱饵并保留尾部 BSS 豁免
4. 拓扑重标记（RO/RX/RW/BSS）
5. `prot` 规范化（含 BSS `-w-` 修正为 RW）
6. 相邻同类段拉链式合并
7. 最终 index 连续化（BSS 保持 `-1`）

---

## 6. 虚拟触摸实现（`virtual_input.h`）

核心常量：

- `TARGET_SLOT_IDX = 9`
- `PHYSICAL_SLOTS = 9`
- `TOTAL_SLOTS = 10`

核心思路：

1. 劫持 `input_dev->mt`，分配新 `input_mt`，保留至少 10 个 slot 存储空间。
2. 对物理驱动暴露 `num_slots=9`，让其只处理 `0..8`。
3. 对系统上报 `ABS_MT_SLOT` 范围到 `10`（0..9）。
4. 发送虚拟触摸时瞬时把 `num_slots` 切到 10，写入 slot 9 后再切回 9。
5. 手动维护 `BTN_TOUCH` / `BTN_TOOL_FINGER` / `BTN_TOOL_DOUBLETAP`。

关键实现点：

- 关闭 `INPUT_MT_POINTER`，防止按键状态抖动
- 发送过程 `local_irq_save/restore` 降低真实中断打断导致的帧污染
- 自动伪造 `TOUCH_MAJOR/WIDTH_MAJOR/PRESSURE`（设备支持时）
- `v_touch_destroy()` 恢复原始 `mt` 并释放劫持资源

---

## 7. 硬件断点实现（`hwbp.h`）

能力：

1. 获取当前 CPU BRP/WRP 资源数量（读 `id_aa64dfr0_el1`）
2. 给目标进程线程设置用户态硬件断点（R/W/RW/X）
3. 删除已注册断点
4. 记录命中 PC、命中次数、寄存器快照

实现要点：

- 通过 `register_user_hw_breakpoint` / `unregister_hw_breakpoint` 动态解析符号地址
- `sample_hbp_handler()` 在回调中记录/回放寄存器，并调用 `emulate_insn(regs)` 步过指令
- 断点事件维护在全局链表 `bp_event_list`

---

## 8. 模块可见性处理（`lsdriver.c`）

初始化时会执行隐藏逻辑：

1. 从 `vmap_area_list` 和 `vmap_area_root` 摘除自身映射节点
2. 从 `THIS_MODULE->list` 摘除（`/proc/modules` 不可见）
3. 删除 `mkobj.kobj`（`/sys/module` 不可见）
4. 清理模块依赖 holder 链接
5. 工作线程从 `task->tasks` 链表摘除

另外，注册了 `do_exit` 的 kprobe：

- 主线程退出时（`thread_group_leader`）若进程名包含 `ls`/`LS`，执行状态清理（重置连接状态、触摸销毁等）。

---

## 9. 编译说明

### 9.1 直接编译模块（通用）

在目标内核源码树执行：

```bash
make -C <KDIR> M=$PWD/lsdriver ARCH=arm64 LLVM=1 modules
```

### 9.2 模块 Makefile 当前关键参数

- `obj-m += lsdriver.o`
- `ccflags-y += -O3`
- `ccflags-y += -Wno-error`
- `ccflags-y += -fno-stack-protector`
- `ccflags-y += -fomit-frame-pointer`
- `ccflags-y += -funroll-loops`
- `ccflags-y += -fstrict-aliasing`
- `ccflags-y += -ffunction-sections -fdata-sections`

### 9.3 仓库内已有产物（`lsdriver/`）

- `android12-5.10lsdriver.ko`
- `android13-5.10lsdriver.ko`
- `android13-5.15lsdriver.ko`
- `android14-6.1lsdriver.ko`
- `android15-6.6lsdriver.ko`
- `android16-6.12lsdriver.ko`

---

## 10. 使用前提与限制（按当前代码）

1. 用户进程名必须是 `LS`（连接线程硬编码匹配）。
2. 共享内存虚拟地址固定为 `0x2025827000`。
3. 单次读写缓冲 `user_buffer` 固定 `0x1000` 字节。
4. 模块初始化后立即做隐藏处理，常规 `rmmod` 流程不适合作为回收路径。
5. 触摸和断点逻辑依赖 ARM64 输入子系统/硬件断点能力，不同设备内核行为可能有差异。

---

## 11. 后续维护建议

如果你后续继续改驱动代码，建议 README 同步关注这几块：

1. `enum sm_req_op` 变更（协议兼容）
2. `req_obj` 结构变更（用户态同步）
3. 连接条件（进程名、共享地址、握手机制）
4. 内存读写后端切换（PTE vs 线性映射）
5. 触摸/断点能力开关与版本适配分支

