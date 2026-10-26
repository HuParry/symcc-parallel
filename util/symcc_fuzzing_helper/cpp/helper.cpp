// SPDX-License-Identifier: GPL-3.0-or-later
#include "helper.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <future>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <poll.h>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <sys/inotify.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

extern char **environ;

namespace helper {
namespace {
bool verbose = false;
static_assert(std::atomic<bool>::is_always_lock_free,
              "Signal handling requires a lock-free stop flag");
std::atomic<bool> stopRequested{false};
std::mutex logMutex;
std::map<std::string, int> logFilters;
std::optional<std::regex> logPattern;
int logLevel(const std::string &name) {
  if (name == "off")
    return 0;
  if (name == "error" || name == "ERROR")
    return 1;
  if (name == "warn" || name == "WARN")
    return 2;
  if (name == "info" || name == "INFO")
    return 3;
  if (name == "debug" || name == "DEBUG")
    return 4;
  if (name == "trace" || name == "TRACE")
    return 5;
  return -1;
}
[[noreturn]] void fail(const std::string &message) {
  throw std::runtime_error(message);
}
void systemCheck(bool condition, const std::string &message) {
  if (!condition)
    fail(message + ": " + std::strerror(errno));
}
void createDirectory(const fs::path &path) {
  if (!fs::create_directory(path))
    fail("Directory already exists: " + path.string());
}
bool contains(const std::vector<std::string> &args, const std::string &arg) {
  return std::find(args.begin(), args.end(), arg) != args.end();
}
std::vector<std::string> insertInput(std::vector<std::string> args,
                                     const fs::path &path) {
  auto it = std::find(args.begin(), args.end(), "@@");
  if (it != args.end())
    *it = path.string();
  return args;
}
std::string describe(const std::vector<std::string> &args) {
  std::ostringstream out;
  for (const auto &arg : args)
    out << std::quoted(arg) << ' ';
  return out.str();
}

// 所有文件描述符和临时目录都由作用域管理，异常返回也会释放。
class Fd {
  int value_ = -1;

public:
  explicit Fd(int value = -1) : value_(value) {}
  ~Fd() { reset(); }
  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;
  int get() const { return value_; }
  void reset(int value = -1) {
    if (value_ >= 0)
      ::close(value_);
    value_ = value;
  }
};

// Wake idle workers when AFL finishes publishing an input. Keep the periodic
// scan as a fallback for unavailable watches, lost events and queue replacement.
class QueueWatch {
  Fd fd_;

public:
  explicit QueueWatch(const fs::path &queue)
      : fd_(::inotify_init1(IN_NONBLOCK | IN_CLOEXEC)) {
    if (fd_.get() >= 0 &&
        ::inotify_add_watch(fd_.get(), queue.c_str(),
                            IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE_SELF |
                                IN_MOVE_SELF) < 0)
      fd_.reset();
    if (fd_.get() < 0)
      log("WARN", "Queue notifications unavailable; using periodic scans");
  }

  bool changed() {
    bool changed = false;
    alignas(inotify_event) std::array<char, 4096> buffer;
    while (fd_.get() >= 0) {
      auto bytes = ::read(fd_.get(), buffer.data(), buffer.size());
      if (bytes < 0 && errno == EINTR)
        continue;
      if (bytes < 0 && errno == EAGAIN)
        break;
      if (bytes <= 0) {
        fd_.reset();
        break;
      }
      changed = true;
      for (size_t offset = 0; offset < static_cast<size_t>(bytes);) {
        const auto *event = reinterpret_cast<const inotify_event *>(
            buffer.data() + offset);
        if (event->mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF))
          fd_.reset();
        offset += sizeof(inotify_event) + event->len;
      }
    }
    return changed;
  }

  void wait() const {
    pollfd descriptor{fd_.get(), POLLIN, 0};
    // Also check completed futures and the stop flag at least every 50ms.
    int ready = ::poll(&descriptor, 1, 50);
    systemCheck(ready >= 0 || errno == EINTR, "Failed to wait for queue updates");
  }
};

class TempDir {
public:
  fs::path path;
  TempDir() {
    auto pattern = (fs::temp_directory_path() / "symcc-helper-XXXXXX").string();
    std::vector<char> buffer(pattern.begin(), pattern.end());
    buffer.push_back(0);
    char *created = ::mkdtemp(buffer.data());
    systemCheck(created != nullptr, "Failed to create temporary directory");
    path = created;
  }
  ~TempDir() {
    std::error_code error;
    fs::remove_all(path, error);
  }
};
struct ProcessResult {
  int status;
  std::string stderrOutput;
};

// fork 前准备参数和环境；子进程只做描述符重定向和 exec，命令不经过 shell。
ProcessResult runProcess(const std::vector<std::string> &args,
                         const std::map<std::string, std::string> &overrides,
                         const std::optional<fs::path> &input,
                         bool captureStderr) {
  if (args.empty() || args.front().empty())
    fail("Empty executable command");
  std::vector<std::string> envStrings;
  for (char **entry = environ; *entry; ++entry) {
    std::string text(*entry);
    if (!overrides.count(text.substr(0, text.find('='))))
      envStrings.push_back(text);
  }
  for (const auto &entry : overrides)
    envStrings.push_back(entry.first + "=" + entry.second);
  std::vector<char *> env, argv;
  for (auto &entry : envStrings)
    env.push_back(entry.data());
  env.push_back(nullptr);
  for (const auto &arg : args)
    argv.push_back(const_cast<char *>(arg.c_str()));
  argv.push_back(nullptr);
  std::vector<std::string> candidates;
  if (args.front().find('/') != std::string::npos)
    candidates.push_back(args.front());
  else {
    const char *path = std::getenv("PATH");
    std::string search = path ? path : "/bin:/usr/bin";
    size_t start = 0;
    do {
      auto end = search.find(':', start);
      auto part = search.substr(start, end - start);
      candidates.push_back((part.empty() ? std::string(".") : part) + "/" +
                           args.front());
      if (end == std::string::npos)
        break;
      start = end + 1;
    } while (true);
  }
  Fd nullFd(::open("/dev/null", O_RDWR | O_CLOEXEC));
  systemCheck(nullFd.get() >= 0, "Failed to open /dev/null");
  Fd inputFile;
  if (input) {
    inputFile.reset(::open(input->c_str(), O_RDONLY | O_CLOEXEC));
    systemCheck(inputFile.get() >= 0,
                "Failed to read input " + input->string());
  }
  Fd inRead, inWrite, errRead, errWrite, execRead, execWrite;
  auto makePipe = [](Fd &read, Fd &write) {
    int descriptors[2];
    systemCheck(::pipe2(descriptors, O_CLOEXEC) == 0, "Failed to create pipe");
    read.reset(descriptors[0]);
    write.reset(descriptors[1]);
  };
  if (input)
    makePipe(inRead, inWrite);
  if (captureStderr)
    makePipe(errRead, errWrite);
  makePipe(execRead, execWrite);
  log("DEBUG", "Running command: " + describe(args),
      "symcc_fuzzing_helper::symcc");
  pid_t pid = ::fork();
  systemCheck(pid >= 0, "Failed to fork");
  if (pid == 0) {
    auto childError = [&](int error) {
      const char *bytes = reinterpret_cast<const char *>(&error);
      size_t remaining = sizeof(error);
      while (remaining) {
        ssize_t written = ::write(execWrite.get(), bytes, remaining);
        if (written < 0 && errno == EINTR)
          continue;
        if (written <= 0)
          break;
        remaining -= static_cast<size_t>(written);
        bytes += written;
      }
      ::_exit(127);
    };
    // Isolate each invocation so cancellation also stops target descendants.
    if (::setpgid(0, 0) < 0)
      childError(errno);
    if (::dup2(input ? inRead.get() : nullFd.get(), STDIN_FILENO) < 0 ||
        ::dup2(nullFd.get(), STDOUT_FILENO) < 0 ||
        ::dup2(captureStderr ? errWrite.get() : nullFd.get(), STDERR_FILENO) <
            0)
      childError(errno);
    // Rust Command 默认让子进程使用正常的 SIGPIPE 语义。
    ::signal(SIGPIPE, SIG_DFL);
    ::signal(SIGINT, SIG_DFL);
    ::signal(SIGTERM, SIG_DFL);
    int savedError = ENOENT;
    for (const auto &candidate : candidates) {
      ::execve(candidate.c_str(), argv.data(), env.data());
      if (errno == EACCES)
        savedError = EACCES;
      else if (errno != ENOENT && errno != ENOTDIR)
        childError(errno);
    }
    childError(savedError);
  }
  // 即使中途发生读写错误，也必须回收子进程。
  struct Reaper {
    pid_t pid;
    ~Reaper() {
      if (pid > 0) {
        ::kill(-pid, SIGKILL);
        ::kill(pid, SIGKILL);
        while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
        }
      }
    }
  } reaper{pid};
  Fd childExit;
#ifdef SYS_pidfd_open
  // A pidfd becomes readable on exit, without taking SIGCHLD away from other
  // worker threads. Older kernels and restricted environments use the fallback.
  childExit.reset(static_cast<int>(::syscall(SYS_pidfd_open, pid, 0)));
#endif
  inRead.reset();
  errWrite.reset();
  execWrite.reset();
  int execError = 0;
  ssize_t execBytes;
  do {
    execBytes = ::read(execRead.get(), &execError, sizeof(execError));
  } while (execBytes < 0 && errno == EINTR);
  systemCheck(execBytes >= 0, "Failed to read child launch status");
  if (execBytes > 0)
    fail("Failed to execute " + args.front() + ": " + std::strerror(execError));
  execRead.reset();
  auto nonblocking = [](int fd) {
    if (fd < 0)
      return;
    int flags = ::fcntl(fd, F_GETFL);
    systemCheck(flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0,
                "Failed to configure pipe");
  };
  nonblocking(inWrite.get());
  nonblocking(errRead.get());
  std::string output;
  std::array<char, 65536> inputBuffer{}, outputBuffer{};
  size_t length = 0, offset = 0;
  // 同时供给 stdin 和排空 stderr，避免大输入与大量日志互相堵塞管道。
  while (inWrite.get() >= 0 || errRead.get() >= 0) {
    if (stopping())
      fail("Execution interrupted");
    if (inWrite.get() >= 0 && offset == length) {
      ssize_t bytes;
      do {
        bytes = ::read(inputFile.get(), inputBuffer.data(), inputBuffer.size());
      } while (bytes < 0 && errno == EINTR);
      systemCheck(bytes >= 0, "Failed to read input");
      length = static_cast<size_t>(bytes);
      offset = 0;
      if (!length)
        inWrite.reset(); // EOF 必须关闭管道，目标才能结束读取。
    }
    pollfd descriptors[2] = {{inWrite.get(), POLLOUT, 0},
                             {errRead.get(), POLLIN, 0}};
    if (descriptors[0].fd < 0 && descriptors[1].fd < 0)
      break;
    int ready;
    do {
      ready = ::poll(descriptors, 2, 100);
    } while (ready < 0 && errno == EINTR && !stopping());
    if (stopping())
      fail("Execution interrupted");
    systemCheck(ready >= 0, "Failed to poll child pipes");
    if (descriptors[0].revents & (POLLOUT | POLLERR | POLLHUP)) {
      ssize_t bytes =
          ::write(inWrite.get(), inputBuffer.data() + offset, length - offset);
      if (bytes > 0)
        offset += static_cast<size_t>(bytes);
      else if (bytes < 0 && errno == EPIPE)
        inWrite.reset(); // A target may finish without consuming all stdin.
      else if (bytes < 0 && errno != EINTR && errno != EAGAIN)
        fail("Failed to pipe the test input: " +
             std::string(std::strerror(errno)));
    }
    if (descriptors[1].revents & (POLLIN | POLLERR | POLLHUP)) {
      ssize_t bytes =
          ::read(errRead.get(), outputBuffer.data(), outputBuffer.size());
      if (bytes > 0)
        output.append(outputBuffer.data(), static_cast<size_t>(bytes));
      else if (bytes == 0)
        errRead.reset();
      else if (errno != EINTR && errno != EAGAIN)
        fail("Failed to capture stderr");
    }
  }
  int status;
  pid_t waited;
  for (;;) {
    if (stopping())
      fail("Execution interrupted");
    waited = ::waitpid(pid, &status, WNOHANG);
    if (waited == pid)
      break;
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (childExit.get() >= 0) {
      pollfd descriptor{childExit.get(), POLLIN, 0};
      // The timeout bounds cancellation latency; exit wakes poll immediately.
      int ready = ::poll(&descriptor, 1, 100);
      systemCheck(ready >= 0 || errno == EINTR, "Failed to wait for child exit");
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }
  systemCheck(waited == pid, "Failed to wait for child");
  reaper.pid = -1;
  return {status, std::move(output)};
}

std::optional<Duration> parseSolverTimeImpl(const std::string &output) {
  static const std::regex pattern("\"solving_time\": ([0-9]+)");
  std::optional<Duration> last;
  std::istringstream lines(output);
  std::string line;
  while (std::getline(lines, line)) {
    auto start = line.find_first_not_of(" \t\r\n");
    if (start == std::string::npos ||
        line.compare(start, 11, "[STAT] SMT:") != 0)
      continue;
    std::smatch match;
    if (std::regex_search(line, match, pattern)) {
      try {
        auto micros = std::stoull(match[1].str());
        if (micros <= static_cast<uint64_t>(Duration::max().count() / 1000))
          last = std::chrono::microseconds(micros);
      } catch (const std::exception &) {
      }
    }
  }
  return last;
}
struct Score {
  bool valid = false, coverage = false, seed = false;
  uintmax_t size = 0;
  std::string name;
  bool operator<(const Score &other) const {
    if (valid != other.valid)
      return !valid;
    if (coverage != other.coverage)
      return !coverage;
    if (seed != other.seed)
      return !seed;
    if (size != other.size)
      return size > other.size;
    return name < other.name;
  }
};
Score score(const fs::path &path) {
  std::error_code error;
  auto size = fs::file_size(path, error);
  if (error) {
    log("WARN", "Failed to score " + path.string() + ": " + error.message(),
        "symcc_fuzzing_helper::symcc");
    return {};
  }
  auto name = path.filename().native();
  return {true,
          name.size() >= 4 && name.compare(name.size() - 4, 4, "+cov") == 0,
          name.find("orig:") != std::string::npos, size, name};
}
} // namespace

std::optional<Duration> parseSolverTime(const std::string &output) {
  return parseSolverTimeImpl(output);
}

void requestStop() { stopRequested.store(true, std::memory_order_relaxed); }
bool stopping() { return stopRequested.load(std::memory_order_relaxed); }

void setVerbose(bool enabled) {
  verbose = enabled;
  logFilters.clear();
  logPattern.reset();
  // 与 env_logger 的调用顺序一致：-v 决定全局级别，RUST_LOG
  // 的模块规则可覆盖它。
  const char *setting = std::getenv("RUST_LOG");
  if (!setting)
    return;
  std::string spec(setting);
  auto slash = spec.find('/');
  if (slash != std::string::npos) {
    try {
      logPattern.emplace(spec.substr(slash + 1));
    } catch (const std::regex_error &) {
      std::cerr << "Ignoring invalid RUST_LOG regex\n";
    }
    spec.resize(slash);
  }
  std::istringstream directives(spec);
  std::string directive;
  while (std::getline(directives, directive, ',')) {
    auto first = directive.find_first_not_of(" \t");
    if (first == std::string::npos)
      continue;
    directive =
        directive.substr(first, directive.find_last_not_of(" \t") - first + 1);
    auto equals = directive.find('=');
    if (equals == std::string::npos) {
      if (logLevel(directive) < 0)
        logFilters[directive] = 5;
    } else {
      auto level = logLevel(directive.substr(equals + 1));
      if (equals > 0 && level >= 0)
        logFilters[directive.substr(0, equals)] = level;
    }
  }
}
void log(const std::string &level, const std::string &message,
         const std::string &target) {
  int threshold = verbose ? 4 : 3;
  size_t longest = 0;
  for (const auto &filter : logFilters) {
    if (target.compare(0, filter.first.size(), filter.first) == 0 &&
        filter.first.size() >= longest) {
      threshold = filter.second;
      longest = filter.first.size();
    }
  }
  if (logLevel(level) > threshold ||
      (logPattern && !std::regex_search(message, *logPattern)))
    return;
  auto now = std::time(nullptr);
  std::tm utc{};
  ::gmtime_r(&now, &utc);
  std::lock_guard<std::mutex> lock(logMutex);
  std::cerr << '[' << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ") << ' ' << level
            << ' ' << target << "] " << message << '\n';
}
Options parseOptions(int argc, char **argv) {
  Options options;
  bool haveOutput = false, haveFuzzer = false, haveName = false,
       haveJobs = false;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--") {
      for (++i; i < argc; ++i)
        options.command.emplace_back(argv[i]);
      break;
    }
    if (arg == "-h" || arg == "--help") {
      std::cout << "Make SymCC collaborate with AFL.\nUsage: "
                   "symcc_fuzzing_helper_cpp -o DIR -a FUZZER -n NAME "
                   "[-j JOBS] [-v] -- PROGRAM [ARGS...]\n"
                   "  -j, --jobs JOBS  Concurrent SymCC workers (default: 1)\n";
      std::exit(0);
    }
    if (arg == "-V" || arg == "--version") {
      std::cout << "symcc_fuzzing_helper_cpp 0.1.0\n";
      std::exit(0);
    }
    if (arg == "--jobs")
      arg = "-j";
    else if (arg.compare(0, 7, "--jobs=") == 0)
      arg = "-j" + arg.substr(7);
    if (arg.size() > 1 && arg[0] == '-') {
      for (size_t j = 1; j < arg.size(); ++j) {
        char key = arg[j];
        if (key == 'v') {
          options.verbose = true;
          continue;
        }
        if (key != 'o' && key != 'a' && key != 'n' && key != 'j')
          fail("Unknown option: " + arg);
        std::string value;
        const bool attached = j + 1 < arg.size();
        if (attached)
          value = arg.substr(j + 1);
        else {
          if (++i >= argc)
            fail("Missing value for " + arg);
          value = argv[i];
        }
        if (attached && !value.empty() && value[0] == '=')
          value.erase(0, 1);
        if (key == 'o') {
          if (haveOutput)
            fail("Duplicate -o");
          options.output = value;
          haveOutput = true;
        }
        if (key == 'a') {
          if (haveFuzzer)
            fail("Duplicate -a");
          options.fuzzer = value;
          haveFuzzer = true;
        }
        if (key == 'n') {
          if (haveName)
            fail("Duplicate -n");
          options.name = value;
          haveName = true;
        }
        if (key == 'j') {
          if (haveJobs)
            fail("Duplicate -j/--jobs");
          if (value.empty() ||
              value.find_first_not_of("0123456789") != std::string::npos)
            fail("Jobs must be a positive integer");
          unsigned long long jobs;
          try {
            jobs = std::stoull(value);
          } catch (const std::exception &) {
            fail("Jobs must be a positive integer within unsigned range");
          }
          if (jobs == 0 || jobs > std::numeric_limits<unsigned>::max())
            fail("Jobs must be a positive integer within unsigned range");
          options.jobs = static_cast<unsigned>(jobs);
          haveJobs = true;
        }
        break;
      }
    } else {
      for (; i < argc; ++i)
        options.command.emplace_back(argv[i]);
      break;
    }
  }
  if (!haveOutput || !haveFuzzer || !haveName)
    fail("Required options: -o DIR -a FUZZER -n NAME");
  if (options.command.empty())
    fail("Missing target command after --");
  return options;
}

AflMap AflMap::load(const fs::path &path) {
  if (fs::file_size(path) != 65536)
    fail("Coverage map must contain exactly 65536 bytes: " + path.string());
  std::ifstream input(path, std::ios::binary);
  AflMap result;
  if (!input.read(reinterpret_cast<char *>(result.data.data()),
                  result.data.size()))
    fail("Failed to read AFL bitmap " + path.string());
  return result;
}
bool AflMap::merge(const AflMap &other) {
  bool interesting = false;
  for (size_t i = 0; i < data.size(); ++i) {
    if ((data[i] | other.data[i]) != data[i]) {
      data[i] |= other.data[i];
      interesting = true;
    }
  }
  return interesting;
}
TestcaseDir::TestcaseDir(fs::path directory) : path(std::move(directory)) {
  createDirectory(path);
}
void copyTestcase(const fs::path &testcase, TestcaseDir &target,
                  const fs::path &parent) {
  auto name = parent.filename().string();
  if (name.compare(0, 3, "id:") != 0 || name.size() < 9)
    fail("Invalid AFL parent name: " + name);
  std::ostringstream filename;
  filename << "id:" << std::setfill('0') << std::setw(6) << target.nextId
           << ",src:" << name.substr(3, 6);
  auto destination = target.path / filename.str();
  log("DEBUG", "Creating test case " + destination.string(),
      "symcc_fuzzing_helper::symcc");
  fs::copy_file(testcase, destination, fs::copy_options::overwrite_existing);
  ++target.nextId;
}
AflConfig AflConfig::load(const fs::path &directory) {
  std::ifstream stats(directory / "fuzzer_stats");
  if (!stats)
    fail("Failed to open fuzzer_stats in " + directory.string());
  std::string line, command;
  while (std::getline(stats, line)) {
    if (line.compare(0, 12, "command_line") == 0) {
      auto colon = line.find(':');
      if (colon == std::string::npos)
        fail("Invalid AFL command_line format");
      command = line.substr(colon + 1);
      break;
    }
  }
  std::istringstream stream(command);
  std::vector<std::string> args;
  for (std::string arg; stream >> arg;)
    args.push_back(arg);
  if (args.empty())
    fail("Missing AFL command_line");
  AflConfig result;
  result.showmap_ = fs::path(args.front()).parent_path() / "afl-showmap";
  auto separator = std::find(args.begin(), args.end(), "--");
  if (separator == args.end())
    fail("AFL command_line must contain -- before the target");
  result.command_.assign(separator, args.end());
  result.stdin_ = !contains(result.command_, "@@");
  result.qemu_ = contains(args, "-Q");
  result.queue_ = directory / "queue";
  log("DEBUG", "AFL configuration: " + result.showmap_.string() + " " +
                   describe(result.command_));
  return result;
}
std::optional<fs::path>
AflConfig::bestNewTestcase(const std::unordered_set<fs::path> &seen,
                           const std::unordered_set<fs::path> &inFlight) const {
  std::optional<fs::path> best;
  Score bestScore;
  // AFL 可同时创建文件；文件评分失败时按最低优先级处理。
  std::vector<fs::path> entries;
  for (const auto &entry : fs::directory_iterator(queue_))
    entries.push_back(entry.path());
  for (const auto &path : entries) {
    std::error_code error;
    if (!fs::is_regular_file(path, error) || seen.count(path) ||
        inFlight.count(path))
      continue;
    auto candidate = score(path);
    if (!best || !(candidate < bestScore)) {
      best = path;
      bestScore = std::move(candidate);
    }
  }
  return best;
}
ShowmapResult AflConfig::runShowmap(const fs::path &bitmap,
                                    const fs::path &testcase) const {
  std::vector<std::string> args{showmap_.string()};
  if (qemu_)
    args.push_back("-Q");
  for (const auto *arg : {"-t", "5000", "-m", "none", "-b", "-o"})
    args.emplace_back(arg);
  args.push_back(bitmap.string());
  auto target = insertInput(command_, testcase);
  args.insert(args.end(), target.begin(), target.end());
  auto result = runProcess(
      args, {}, stdin_ ? std::optional<fs::path>(testcase) : std::nullopt,
      false);
  if (!WIFEXITED(result.status))
    fail("afl-showmap terminated by signal");
  int code = WEXITSTATUS(result.status);
  log("DEBUG", "afl-showmap returned " + std::to_string(code),
      "symcc_fuzzing_helper::symcc");
  if (code == 0)
    return {Outcome::Success, AflMap::load(bitmap)};
  if (code == 1)
    return {Outcome::Hang, std::nullopt};
  if (code == 2)
    return {Outcome::Crash, std::nullopt};
  fail("Unexpected return code " + std::to_string(code) + " from afl-showmap");
}
SymCC::SymCC(const fs::path &directory, const std::vector<std::string> &command)
    : input_(directory / ".cur_input"), bitmap_(directory / "bitmap"),
      command_(insertInput(command, input_)), stdin_(!contains(command, "@@")) {
  log("DEBUG", "SymCC configuration: " + describe(command_));
}
SymCCResult SymCC::run(const fs::path &input, const fs::path &output) const {
  fs::copy_file(input, input_, fs::copy_options::overwrite_existing);
  createDirectory(output);
  std::vector<std::string> args{"timeout", "-k", "5", "90"};
  args.insert(args.end(), command_.begin(), command_.end());
  std::map<std::string, std::string> env{
      {"SYMCC_ENABLE_LINEARIZATION", "1"},
      {"SYMCC_AFL_COVERAGE_MAP", bitmap_.string()},
      {"SYMCC_OUTPUT_DIR", output.string()}};
  if (!stdin_)
    env["SYMCC_INPUT_FILE"] = input_.string();
  auto start = Clock::now();
  auto process = runProcess(
      args, env, stdin_ ? std::optional<fs::path>(input_) : std::nullopt, true);
  auto elapsed = std::chrono::duration_cast<Duration>(Clock::now() - start);
  bool killed;
  if (WIFEXITED(process.status)) {
    int code = WEXITSTATUS(process.status);
    log("DEBUG", "SymCC returned code " + std::to_string(code),
        "symcc_fuzzing_helper::symcc");
    killed = code == 124; // 与 Rust 版相同：其他非零退出码不自动算 killed。
  } else {
    killed = WIFSIGNALED(process.status);
    if (killed)
      log("WARN",
          "SymCC received signal " + std::to_string(WTERMSIG(process.status)),
          "symcc_fuzzing_helper::symcc");
  }
  std::vector<fs::path> tests;
  for (const auto &entry : fs::directory_iterator(output))
    tests.push_back(entry.path());
  auto solver = parseSolverTime(process.stderrOutput);
  if (solver && *solver > elapsed) {
    log("WARN", "Backend reported inaccurate solver time!",
        "symcc_fuzzing_helper::symcc");
    solver = elapsed;
  }
  return {std::move(tests), killed, elapsed, solver};
}
void Stats::add(const SymCCResult &result) {
  if (result.killed) {
    ++failedCount;
    failedTime += result.time;
  } else {
    ++count;
    time += result.time;
    if (result.solverTime)
      solverTime = solverTime.value_or(Duration{}) + *result.solverTime;
  }
}
void Stats::write(std::ostream &out) const {
  auto millis = [](Duration duration) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration)
        .count();
  };
  out << "Successful executions: " << count << '\n'
      << "Time in successful executions: " << millis(time) << "ms\n";
  if (count)
    out << "Avg time per successful execution: " << millis(time / count)
        << "ms\n";
  if (solverTime) {
    out << "Solver time (successful executions): " << millis(*solverTime)
        << "ms\n";
    if (std::chrono::duration_cast<std::chrono::seconds>(time).count() > 0) {
      double share = static_cast<double>(millis(*solverTime)) /
                     static_cast<double>(millis(time)) * 100;
      out << std::fixed << std::setprecision(2)
          << "Solver time share (successful executions): " << share << "% (-> "
          << 100 - share << "% in execution)\n"
          << "Avg solver time per successful execution: "
          << millis(*solverTime / count) << "ms\n";
    }
  }
  out << "Failed executions: " << failedCount << '\n'
      << "Time spent on failed executions: " << millis(failedTime) << "ms\n";
  if (failedCount)
    out << "Avg time in failed executions: " << millis(failedTime / failedCount)
        << "ms\n";
  out << "---------------------------------------------------------------------"
         "-----------\n";
  out.flush();
  if (!out)
    fail("Failed to write run-time statistics");
}
// 与 Rust File 相同，统计文件不应通过 exec 泄漏给目标或 afl-showmap。
StatsFile::StatsFile(const fs::path &path)
    : fd_(::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                 0666)) {
  systemCheck(fd_ >= 0, "Failed to create statistics file " + path.string());
}
StatsFile::~StatsFile() { ::close(fd_); }
void StatsFile::append(const std::string &text) {
  size_t offset = 0;
  while (offset < text.size()) {
    auto written = ::write(fd_, text.data() + offset, text.size() - offset);
    if (written < 0 && errno == EINTR)
      continue;
    systemCheck(written > 0, "Failed to write statistics file");
    offset += static_cast<size_t>(written);
  }
}
State::State(const fs::path &directory)
    : queue_((createDirectory(directory), directory / "queue")),
      hangs_(directory / "hangs"), crashes_(directory / "crashes"),
      statsFile_(directory / "stats") {}
void State::testInput(const fs::path &input, const SymCC &symcc,
                      const AflConfig &afl) {
  log("INFO", "Running on input " + input.string());
  TempDir temporary;
  auto result = symcc.run(input, temporary.path / "output");
  uint64_t interesting = 0;
  for (const auto &testcase : result.testcases) {
    if (stopping())
      fail("Execution interrupted");
    log("DEBUG", "Processing test case " + testcase.string());
    auto checked = afl.runShowmap(temporary.path / "testcase_bitmap", testcase);
    // Merge coverage and allocate output IDs atomically across all workers.
    std::lock_guard<std::mutex> lock(mutex_);
    switch (checked.outcome) {
    case Outcome::Success:
      if (coverage_.merge(*checked.map)) {
        copyTestcase(testcase, queue_, input);
        ++interesting;
      }
      break;
    case Outcome::Hang:
      log("INFO", "Ignoring new test case " + testcase.string() +
                      " because afl-showmap timed out on it");
      break;
    case Outcome::Crash:
      log("INFO", "Test case " + testcase.string() +
                      " crashes afl-showmap; it is probably interesting");
      copyTestcase(testcase, crashes_, input);
      copyTestcase(testcase, queue_, input);
      break;
    default:
      fail("Invalid showmap outcome");
    }
  }
  log("INFO", "Generated " + std::to_string(result.testcases.size()) +
                  " test cases (" + std::to_string(interesting) + " new)");
  std::lock_guard<std::mutex> lock(mutex_);
  if (result.killed) {
    log("INFO",
        "The target process was killed; archiving to " + hangs_.path.string());
    copyTestcase(input, hangs_, input);
  }
  stats_.add(result);
}
void State::maybeWriteStats(bool force) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() -
                                                                  lastStats_);
  if (!force && elapsed.count() <= 60)
    return;
  try {
    std::ostringstream output;
    stats_.write(output);
    statsFile_.append(output.str());
  } catch (const std::exception &error) {
    log("ERROR", error.what());
  }
  lastStats_ = Clock::now();
}

Coordinator::Coordinator(const Options &options)
    : directory_(fs::absolute(options.output / options.name)),
      command_(options.command), jobs_(options.jobs),
      afl_(AflConfig::load(options.output / options.fuzzer)),
      state_(directory_) {
  if (!jobs_)
    fail("Jobs must be positive");
}

void Coordinator::run() {
  struct Worker {
    SymCC symcc;
    std::optional<fs::path> input;
    std::future<void> task;
    Worker(const fs::path &directory, const std::vector<std::string> &command)
        : symcc(directory, command) {}
  };
  std::vector<std::unique_ptr<Worker>> workers;
  for (unsigned i = 0; i < jobs_; ++i) {
    auto workspace = directory_;
    if (jobs_ > 1) {
      workspace /= "workers";
      if (i == 0)
        createDirectory(workspace);
      workspace /= std::to_string(i);
      createDirectory(workspace);
    }
    workers.push_back(std::make_unique<Worker>(workspace, command_));
  }
  QueueWatch incoming(afl_.queueDirectory());
  log("INFO",
      "Coordinator started with " + std::to_string(jobs_) + " SymCC worker(s)");

  // Only the coordinator accesses these sets. Reserve an input before launch
  // and move it to processed only after successful completion of the whole job.
  std::unordered_set<fs::path> inFlight;
  auto nextScan = Clock::now();
  try {
    while (!stopping()) {
      for (auto &worker : workers) {
        if (!worker->task.valid())
          continue;
        auto status = worker->task.wait_for(std::chrono::seconds(0));
        if (status != std::future_status::ready)
          continue;
        // Worker failures are reported by the coordinator.
        worker->task.get();
        state_.processed.insert(*worker->input);
        inFlight.erase(*worker->input);
        worker->input.reset();
        nextScan = Clock::now();
      }
      if (incoming.changed())
        nextScan = Clock::now();
      if (Clock::now() >= nextScan) {
        for (size_t i = 0; i < workers.size(); ++i) {
          auto &worker = workers[i];
          if (worker->input || stopping())
            continue;
          auto input = afl_.bestNewTestcase(state_.processed, inFlight);
          if (!input)
            break;
          inFlight.insert(*input);
          worker->input = *input;
          log("DEBUG", "Dispatching " + input->string() + " to worker " +
                           std::to_string(i));
          worker->task = std::async(
              std::launch::async, [this, slot = worker.get(), input = *input] {
                state_.testInput(input, slot->symcc, afl_);
              });
        }
        nextScan = Clock::now() + std::chrono::seconds(5);
      }
      state_.maybeWriteStats();
      incoming.wait();
    }
  } catch (...) {
    // Cancel siblings before future destruction joins them.
    requestStop();
    for (auto &worker : workers)
      if (worker->task.valid())
        worker->task.wait();
    state_.maybeWriteStats(true);
    throw;
  }
  for (auto &worker : workers) {
    if (!worker->task.valid())
      continue;
    try {
      worker->task.get();
    } catch (const std::exception &error) {
      log("DEBUG", "Worker stopped: " + std::string(error.what()));
    }
  }
  state_.maybeWriteStats(true);
  log("INFO", "Coordinator stopped; all workers have been reaped");
}
} // namespace helper
