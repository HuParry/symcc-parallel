// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace helper {
namespace fs = std::filesystem;
using Duration = std::chrono::nanoseconds;
using Clock = std::chrono::steady_clock;

struct Options {
  fs::path output;
  std::string fuzzer, name;
  bool verbose = false;
  unsigned jobs = 1;
  std::vector<std::string> command;
};
Options parseOptions(int argc, char **argv);
void setVerbose(bool enabled);
void requestStop();
bool stopping();
void log(const std::string &level, const std::string &message,
         const std::string &target = "symcc_fuzzing_helper");
std::optional<Duration> parseSolverTime(const std::string &output);

struct AflMap {
  std::array<uint8_t, 65536> data{};
  static AflMap load(const fs::path &path);
  bool merge(const AflMap &other);
};

struct TestcaseDir {
  fs::path path;
  uint64_t nextId = 0;
  explicit TestcaseDir(fs::path directory);
};
void copyTestcase(const fs::path &testcase, TestcaseDir &target,
                  const fs::path &parent);

enum class Outcome { Success, Hang, Crash };
struct ShowmapResult {
  Outcome outcome;
  std::optional<AflMap> map;
};

class AflConfig {
  fs::path showmap_, queue_;
  std::vector<std::string> command_;
  bool stdin_ = false, qemu_ = false;

public:
  static AflConfig load(const fs::path &directory);
  const fs::path &queueDirectory() const { return queue_; }
  std::optional<fs::path>
  bestNewTestcase(const std::unordered_set<fs::path> &seen,
                  const std::unordered_set<fs::path> &inFlight) const;
  ShowmapResult runShowmap(const fs::path &bitmap,
                           const fs::path &testcase) const;
};

struct SymCCResult {
  std::vector<fs::path> testcases;
  bool killed;
  Duration time;
  std::optional<Duration> solverTime;
};
class SymCC {
  fs::path input_, bitmap_;
  std::vector<std::string> command_;
  bool stdin_;

public:
  SymCC(const fs::path &directory, const std::vector<std::string> &command);
  SymCCResult run(const fs::path &input, const fs::path &output) const;
};

struct Stats {
  uint32_t count = 0, failedCount = 0;
  Duration time{}, failedTime{};
  std::optional<Duration> solverTime;
  void add(const SymCCResult &result);
  void write(std::ostream &out) const;
};

class StatsFile {
  int fd_;

public:
  explicit StatsFile(const fs::path &path);
  ~StatsFile();
  StatsFile(const StatsFile &) = delete;
  StatsFile &operator=(const StatsFile &) = delete;
  void append(const std::string &text);
};

class State {
  // Workers only hold this lock while publishing results, never during exec.
  std::mutex mutex_;
  AflMap coverage_;
  TestcaseDir queue_, hangs_, crashes_;
  Stats stats_;
  StatsFile statsFile_;
  Clock::time_point lastStats_ = Clock::now();

public:
  // Only accessed by the coordinator; running inputs are tracked separately.
  std::unordered_set<fs::path> processed;
  explicit State(const fs::path &directory);
  void testInput(const fs::path &input, const SymCC &symcc,
                 const AflConfig &afl);
  void maybeWriteStats(bool force = false);
};

// One coordinator dispatches distinct inputs to a bounded number of workers.
// Each worker owns its input file and persistent runtime bitmap.
class Coordinator {
  fs::path directory_;
  std::vector<std::string> command_;
  unsigned jobs_;
  AflConfig afl_;
  State state_;

public:
  explicit Coordinator(const Options &options);
  void run();
};
} // namespace helper
