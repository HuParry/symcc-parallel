// This file is part of SymCC.
//
// SymCC is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// SymCC. If not, see <https://www.gnu.org/licenses/>.

mod symcc;

use anyhow::{Context, Result};
use clap::{self, StructOpt};
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use symcc::{AflConfig, AflMap, AflShowmapResult, SymCC, TestcaseDir};
use tempfile::tempdir;

const STATS_INTERVAL_SEC: u64 = 60;

// TODO extend timeout when idle? Possibly reprocess previously timed-out
// inputs.

#[derive(Debug, StructOpt)]
#[clap(about = "Make SymCC collaborate with AFL.")]
struct CLI {
    /// The name of the fuzzer to work with
    #[clap(short = 'a')]
    fuzzer_name: String,

    /// The AFL output directory
    #[clap(short = 'o')]
    output_dir: PathBuf,

    /// Name to use for SymCC
    #[clap(short = 'n')]
    name: String,

    /// Enable verbose logging
    #[clap(short = 'v')]
    verbose: bool,

    /// Program under test
    command: Vec<String>,
}

/// Execution statistics.
#[derive(Debug, Default)]
// 累计执行统计，仅用于观察效率，不参与选样本和剪枝。
struct Stats {
    /// Number of successful executions.
    total_count: u32,

    /// Time spent in successful executions of SymCC.
    total_time: Duration,

    /// Time spent in the solver as part of successfully running SymCC.
    solver_time: Option<Duration>,

    /// Number of failed executions.
    failed_count: u32,

    /// Time spent in failed SymCC executions.
    failed_time: Duration,
}

impl Stats {
    fn add_execution(&mut self, result: &symcc::SymCCResult) {
        if result.killed {
            self.failed_count += 1;
            self.failed_time += result.time;
        } else {
            self.total_count += 1;
            self.total_time += result.time;
            self.solver_time = match (self.solver_time, result.solver_time) {
                (None, None) => None,
                (Some(t), None) => Some(t), // no queries in this execution
                (None, Some(t)) => Some(t),
                (Some(a), Some(b)) => Some(a + b),
            };
        }
    }

    fn log(&self, out: &mut impl Write) -> Result<()> {
        writeln!(out, "Successful executions: {}", self.total_count)?;
        writeln!(
            out,
            "Time in successful executions: {}ms",
            self.total_time.as_millis()
        )?;

        if self.total_count > 0 {
            writeln!(
                out,
                "Avg time per successful execution: {}ms",
                (self.total_time / self.total_count).as_millis()
            )?;
        }

        if let Some(st) = self.solver_time {
            writeln!(
                out,
                "Solver time (successful executions): {}ms",
                st.as_millis()
            )?;

            if self.total_time.as_secs() > 0 {
                let solver_share =
                    st.as_millis() as f64 / self.total_time.as_millis() as f64 * 100_f64;
                writeln!(
                    out,
                    "Solver time share (successful executions): {:.2}% (-> {:.2}% in execution)",
                    solver_share,
                    100_f64 - solver_share
                )?;
                writeln!(
                    out,
                    "Avg solver time per successful execution: {}ms",
                    (st / self.total_count).as_millis()
                )?;
            }
        }

        writeln!(out, "Failed executions: {}", self.failed_count)?;
        writeln!(
            out,
            "Time spent on failed executions: {}ms",
            self.failed_time.as_millis()
        )?;

        if self.failed_count > 0 {
            writeln!(
                out,
                "Avg time in failed executions: {}ms",
                (self.failed_time / self.failed_count).as_millis()
            )?;
        }

        writeln!(
            out,
            "--------------------------------------------------------------------------------"
        )?;

        Ok(())
    }
}

/// Mutable run-time state.
///
/// This is a collection of the state we update during execution.
// 运行中维护的状态：覆盖图、已处理输入、输出目录和统计。
struct State {
    /// The cumulative coverage of all test cases generated so far.
    current_bitmap: AflMap,

    /// The AFL test cases that have been analyzed so far.
    processed_files: HashSet<PathBuf>,

    /// The place to put new and useful test cases.
    queue: TestcaseDir,

    /// The place for new test cases that time out.
    hangs: TestcaseDir,

    /// The place for new test cases that crash.
    crashes: TestcaseDir,

    /// Run-time statistics.
    stats: Stats,

    /// When did we last output the statistics?
    last_stats_output: Instant,

    /// Write statistics to this file.
    stats_file: File,
}

impl State {
    /// Initialize the run-time environment in the given output directory.
    ///
    /// This involves creating the output directory and all required
    /// subdirectories.
    // 创建实例输出目录和各子目录，并初始化内存状态。
    fn initialize(output_dir: impl AsRef<Path>) -> Result<Self> {
        let symcc_dir = output_dir.as_ref();

        fs::create_dir(&symcc_dir).with_context(|| {
            format!("Failed to create SymCC's directory {}", symcc_dir.display())
        })?;
        let symcc_queue =
            TestcaseDir::new(symcc_dir.join("queue")).context("Failed to create SymCC's queue")?;
        let symcc_hangs = TestcaseDir::new(symcc_dir.join("hangs"))?;
        let symcc_crashes = TestcaseDir::new(symcc_dir.join("crashes"))?;
        let stats_file = File::create(symcc_dir.join("stats"))?;

        Ok(State {
            current_bitmap: AflMap::new(),
            processed_files: HashSet::new(),
            queue: symcc_queue,
            hangs: symcc_hangs,
            crashes: symcc_crashes,
            stats: Default::default(), // Is this bad style?
            last_stats_output: Instant::now(),
            stats_file,
        })
    }

    /// Run a single input through SymCC and process the new test cases it
    /// generates.
    fn test_input(
        &mut self,
        input: impl AsRef<Path>,
        symcc: &SymCC,
        afl_config: &AflConfig,
    ) -> Result<()> {
        log::info!("Running on input {}", input.as_ref().display());

        // 本轮生成样本存放在临时目录中，处理结束后自动清理。
        let tmp_dir = tempdir()
            .context("Failed to create a temporary directory for this execution of SymCC")?;

        let mut num_interesting = 0u64;
        let mut num_total = 0u64;

        // 运行 SymCC 生成样本，再逐个用 AFL 插桩目标验证。
        let symcc_result = symcc
            .run(&input, tmp_dir.path().join("output"))
            .context("Failed to run SymCC")?;
        for new_test in symcc_result.test_cases.iter() {
            let res = process_new_testcase(&new_test, &input, &tmp_dir, &afl_config, self)?;

            num_total += 1;
            if res == TestcaseResult::New {
                log::debug!("Test case is interesting");
                num_interesting += 1;
            }
        }

        log::info!(
            "Generated {} test cases ({} new)",
            num_total,
            num_interesting
        );

        // SymCC 被终止时，将本轮原始输入归档到 hangs。
        if symcc_result.killed {
            log::info!(
                "The target process was killed (probably timeout or out of memory); \
                 archiving to {}",
                self.hangs.path.display()
            );
            symcc::copy_testcase(&input, &mut self.hangs, &input)
                .context("Failed to archive the test case")?;
        }

        // 处理完成后记录输入路径，避免重复分析。
        self.processed_files.insert(input.as_ref().to_path_buf());
        self.stats.add_execution(&symcc_result);
        Ok(())
    }
}

fn main() -> Result<()> {
    let options = CLI::parse();
    env_logger::builder()
        .filter_level(if options.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init();

    if !options.output_dir.is_dir() {
        log::error!(
            "The directory {} does not exist!",
            options.output_dir.display()
        );
        return Ok(());
    }

    // afl_queue 是AFL保存测试用例的目录，symcc_fuzzing_helper需要从这个目录中获取AFL生成的测试用例
    let afl_queue = options.output_dir.join(&options.fuzzer_name).join("queue");
    if !afl_queue.is_dir() {
        log::error!("The AFL queue {} does not exist!", afl_queue.display());
        return Ok(());
    }

    // symcc实例的工作目录，symcc_fuzzing_helper会在这个目录中保存symcc生成的测试用例
    let symcc_dir = options.output_dir.join(&options.name);
    if symcc_dir.is_dir() {
        log::error!(
            "{} already exists; we do not currently support resuming",
            symcc_dir.display()
        );
        return Ok(());
    }

    // 根据Symcc工作目录和命令行参数创建SymCC配置对象
    let symcc = SymCC::new(symcc_dir.clone(), &options.command);
    log::debug!("\nSymCC configuration: {:?}", &symcc);
    // 读取AFL的配置文件，获取AFL的运行参数。
    let afl_config = AflConfig::load(options.output_dir.join(&options.fuzzer_name))?;
    log::debug!("\nAFL configuration: {:?}", &afl_config);
    // 创建state对象，初始化SymCC的工作目录和统计信息文件。mut表示允许修改变量。
    let mut state = State::initialize(symcc_dir)?;

    loop {
        match afl_config
            .best_new_testcase(&state.processed_files)  // 挑选最优的未处理测试用例
            // 函数会返回None、Some(PathBuf)或者Err，match根据结果选择对应分支进行处理
            .context("Failed to check for new test cases")?
        {
            None => {
                log::debug!("Waiting for new test cases...");
                thread::sleep(Duration::from_secs(5));  // 如果没有新的测试用例，等待5秒后继续检查
            }
            Some(input) => state.test_input(&input, &symcc, &afl_config)?,
            // 找到新的测试用例，调用test_input函数处理它，input是测试用例的路径。
        }

        // 如果距离上次输出统计信息已经超过60秒，则输出当前的统计信息。
        if state.last_stats_output.elapsed().as_secs() > STATS_INTERVAL_SEC {
            if let Err(e) = state.stats.log(&mut state.stats_file) {
                log::error!("Failed to log run-time statistics: {}", e);
            }
            state.last_stats_output = Instant::now();
        }
    }
}

/// The possible outcomes of test-case evaluation.
#[derive(Debug, PartialEq, Eq)]
enum TestcaseResult {
    Uninteresting,
    New,
    Hang,
    Crash,
}

/// Check if the given test case provides new coverage, crashes, or times out;
/// copy it to the corresponding location.
fn process_new_testcase(
    testcase: impl AsRef<Path>,
    parent: impl AsRef<Path>,
    tmp_dir: impl AsRef<Path>,
    afl_config: &AflConfig,
    state: &mut State,
) -> Result<TestcaseResult> {
    log::debug!("Processing test case {}", testcase.as_ref().display());

    let testcase_bitmap_path = tmp_dir.as_ref().join("testcase_bitmap");
    match afl_config
        .run_showmap(&testcase_bitmap_path, &testcase)
        .with_context(|| {
            format!(
                "Failed to check whether test case {} is interesting",
                &testcase.as_ref().display()
            )
        })? {
        // 相对于 helper 的累计覆盖图有新增位时，将样本保存到 queue。
        AflShowmapResult::Success(testcase_bitmap) => {
            let interesting = state.current_bitmap.merge(&testcase_bitmap);
            if interesting {
                symcc::copy_testcase(&testcase, &mut state.queue, parent).with_context(|| {
                    format!(
                        "Failed to enqueue the new test case {}",
                        testcase.as_ref().display()
                    )
                })?;

                Ok(TestcaseResult::New)
            } else {
                Ok(TestcaseResult::Uninteresting)
            }
        }
        // 验证时超时或执行失败的生成样本直接忽略。
        AflShowmapResult::Hang => {
            log::info!(
                "Ignoring new test case {} because afl-showmap timed out on it",
                testcase.as_ref().display()
            );
            Ok(TestcaseResult::Hang)
        }
        // 崩溃样本同时归档到 crashes 和 queue，供 AFL 同步导入。
        AflShowmapResult::Crash => {
            log::info!(
                "Test case {} crashes afl-showmap; it is probably interesting",
                testcase.as_ref().display()
            );
            symcc::copy_testcase(&testcase, &mut state.crashes, &parent)?;
            symcc::copy_testcase(&testcase, &mut state.queue, &parent).with_context(|| {
                format!(
                    "Failed to enqueue the new test case {}",
                    testcase.as_ref().display()
                )
            })?;
            Ok(TestcaseResult::Crash)
        }
    }
}
