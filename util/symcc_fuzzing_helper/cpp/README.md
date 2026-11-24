# C++17 fuzzing helper

独立的 C++17 版本，与上级目录中的 Rust 版本并存。可执行文件名为
`symcc_fuzzing_helper_cpp`，不会替换原程序、CLion 配置或已有 fuzzing 数据。
当前实现面向 Linux（使用 POSIX 进程接口和 `pipe2`）。

## 构建和运行

不依赖 LLVM/Z3 开发包，独立构建：

```bash
cmake -S util/symcc_fuzzing_helper/cpp -B build-helper-cpp -DCMAKE_BUILD_TYPE=Debug
cmake --build build-helper-cpp
```

也可给项目原有 CMake 配置增加 `-DBUILD_FUZZING_HELPER_CPP=ON`，然后构建
`symcc_fuzzing_helper_cpp` 目标。该选项默认关闭。安装使用 `cmake --install`，
Rust 版的 `cargo install` 流程不变。

```bash
./build-helper-cpp/symcc_fuzzing_helper_cpp \
  -o /absolute/path/to/afl_out -a afl-secondary -n symcc-cpp-test -j 4 -v \
  -- /absolute/path/to/symcc-tcpdump -e -r @@
```

请使用新的实例名称，不要复用已有 Rust 实例目录。CLion 可增加一个 CMake
Application 配置指向新目标，保持现有 helper 的参数和工作目录，另取实例名。
两个 AFL Shell 配置无需修改；原 Cargo 配置保留。

## 协调器与并行执行

`-j N`、`--jobs N` 或 `--jobs=N` 指定并行 worker 数量，默认 `1`。
一个 helper 进程充当协调器，为最多 N 个 worker 分配 AFL 输入；每个 worker
启动独立的 SymCC 目标进程并验证生成的样本。worker 完成后立即领取下一个输入，
无需等待其他 worker；协调器同时记录已完成和正在执行的输入，防止重复分配。
选择输入时保持原有优先级。通过 Linux inotify 监听队列文件写入完成和移入事件，
新输入到达时立即唤醒协调器；每 5 秒额外扫描一次，兼容通知不可用或事件丢失。
协调器检查任务完成状态的最大轮询间隔仍为 50ms。

`-j 1` 保持实例根目录下的 `.cur_input` 和 `bitmap`。`-j N`（N > 1）使用
`workers/0/` 到 `workers/N-1/` 分别保存各 worker 的 `.cur_input` 和 `bitmap`，
每次执行另有独立的临时输出目录。输入文件、stdin 和 `afl-showmap` 验证均可并行。
QSYM bitmap 由运行时读取并重写，不能让多个目标同时写同一个文件；因此各 worker
保留自己的持久 bitmap，worker 之间可能重复求解。所有 worker 的验证覆盖率统一
按位合并，只有新增覆盖率样本进入共享 queue；合并、样本编号和统计更新均有锁保护。
崩溃样本保持原有双份归档行为。

收到 SIGINT（Ctrl+C）或 SIGTERM 时，协调器停止分配任务，终止各次执行的进程组，
回收进程并清理临时目录，最后写入已完成执行的统计。worker 发生启动、文件或验证
错误时，协调器取消其他任务并以非零退出码报告错误。统计中的执行时间是各 worker
耗时之和，并行运行时可能超过实际经过的时间。不支持续跑，重新启动须另取实例名。

支持 `pidfd_open` 的 Linux 内核使用 pidfd 通知等待子进程退出，避免短时间运行的
`afl-showmap` 每次额外等待一轮 20ms 轮询。等待期间最多每 100ms 检查停止标志，
保留进程组取消与回收；内核或权限不支持 pidfd 时回退到原来的 20ms 轮询。

当前项目的现有 AFL 输出可以直接使用，例如在项目根目录执行：

```bash
./build-helper-cpp/symcc_fuzzing_helper_cpp \
  -o "$PWD/fuzz-run/afl_out" -a afl-secondary -n symcc-cpp-parallel-01 -j 4 -v \
  -- "$PWD/symcc_build/tcpdump/tcpdump" -e -r @@
```

CLion 的现有 C++ helper 配置可增加 `-j 4`，并将 `-n` 改为未使用过的实例名。

## 验证

构建后运行 `ctest --test-dir build-helper-cpp --output-on-failure`。
有 Python 3 时，CTest 自动注册集成测试，使用可控目标和 showmap 替身验证：并发
上限与实际重叠执行、输入和 bitmap 隔离、跨 worker 覆盖率去重、样本连续编号、
崩溃与超时分类、忙碌 worker 期间动态补位、stdin 串行兼容、异常取消及信号退出。
另验证空闲队列通过写入完成和原子移入及时唤醒，以及验证进程等待期间的取消回收。
测试不需要 LLVM、Z3 或 AFL。

## 保持的行为

- 读取指定 AFL 实例的 `fuzzer_stats` 和 `queue`，识别 `-Q`。
- 按 `+cov`、`orig:`、更小文件、更大文件名顺序选择未处理输入。
- 仅替换第一个独立 `@@`，支持文件与 stdin 两种输入方式。
- 通过 `timeout -k 5 90` 执行目标，继承环境并设置原有 `SYMCC_*` 变量。
- 使用 `afl-showmap -t 5000 -m none -b -o ...` 验证，按 0/1/2 分类。
- 加载 65536 字节验证位图并按位合并；QSYM 的持久 bitmap 仍由运行时管理。
- 保持共享 queue/crashes/hangs、stats 及样本命名格式。
- 崩溃样本双份保存；showmap 超时样本忽略；SymCC killed 时归档原始输入。
- 队列变化时唤醒，并每 5 秒补充扫描；协调器定期检查是否超过 60 个整数秒并写累计统计。
- 解析最后一条有效 SMT 求解耗时；保持非零退出码不一定算 killed 的原有规则。
- 已有实例目录拒绝续跑；临时目录在正常返回或异常展开时清理。

进程管道同时写 stdin、读 stderr，避免原版先写后读可能导致的死锁。
命令直接通过 argv 执行，不经过 shell。正常日志保留关键结果文字和 Rust 模块名；
日志布局、帮助文字和异常诊断不保证逐字相同。支持 `-v` 和常用 `RUST_LOG`
模块过滤；日志正则使用 C++ ECMAScript 语法，与 Rust 正则的高级语法不完全相同。
非法配置返回明确错误，而非模拟 Rust panic。`fuzzer_stats` 中的命令仍按空白拆分，
保留原版对包含空格的 AFL 目标命令还原能力的限制。

不支持续跑、可变验证位图或自动重试。
