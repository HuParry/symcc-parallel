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
  -o /absolute/path/to/afl_out -a afl-secondary -n symcc-cpp-test -v \
  -- /absolute/path/to/symcc-tcpdump -e -r @@
```

请使用新的实例名称，不要复用已有 Rust 实例目录。CLion 可增加一个 CMake
Application 配置指向新目标，保持现有 helper 的参数和工作目录，另取实例名。
两个 AFL Shell 配置无需修改；原 Cargo 配置保留。

## 保持的行为

- 读取指定 AFL 实例的 `fuzzer_stats` 和 `queue`，识别 `-Q`。
- 按 `+cov`、`orig:`、更小文件、更大文件名顺序选择未处理输入。
- 仅替换第一个独立 `@@`，支持文件与 stdin 两种输入方式。
- 通过 `timeout -k 5 90` 执行目标，继承环境并设置原有 `SYMCC_*` 变量。
- 使用 `afl-showmap -t 5000 -m none -b -o ...` 验证，按 0/1/2 分类。
- 加载 65536 字节验证位图并按位合并；QSYM 的持久 bitmap 仍由运行时管理。
- 保持 queue/crashes/hangs、`.cur_input`、`bitmap`、`stats` 及样本命名格式。
- 崩溃样本双份保存；showmap 超时样本忽略；SymCC killed 时归档原始输入。
- 无输入时等待 5 秒；每轮结束检查是否超过 60 个整数秒并写累计统计。
- 解析最后一条有效 SMT 求解耗时；保持非零退出码不一定算 killed 的原有规则。
- 已有实例目录拒绝续跑；临时目录在正常返回或异常展开时清理。

进程管道同时写 stdin、读 stderr，避免原版先写后读可能导致的死锁。
命令直接通过 argv 执行，不经过 shell。正常日志保留关键结果文字和 Rust 模块名；
日志布局、帮助文字和异常诊断不保证逐字相同。支持 `-v` 和常用 `RUST_LOG`
模块过滤；日志正则使用 C++ ECMAScript 语法，与 Rust 正则的高级语法不完全相同。
非法配置返回明确错误，而非模拟 Rust panic。`fuzzer_stats` 中的命令仍按空白拆分，
保留原版对包含空格的 AFL 目标命令还原能力的限制。

这次迁移不增加续跑、多输入并发、可变位图或自动重试等新策略。
