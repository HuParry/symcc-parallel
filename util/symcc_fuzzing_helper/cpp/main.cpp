// SPDX-License-Identifier: GPL-3.0-or-later
#include "helper.h"

#include <csignal>
#include <iostream>

namespace {
void stop(int) { helper::requestStop(); }
} // namespace

int main(int argc, char **argv) {
  try {
    auto options = helper::parseOptions(argc, argv);
    helper::setVerbose(options.verbose);
    // 管道提前关闭时由写入错误处理，避免 helper 被 SIGPIPE 直接终止。
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, stop);
    std::signal(SIGTERM, stop);
    if (!helper::fs::is_directory(options.output)) {
      helper::log("ERROR", "The directory " + options.output.string() +
                               " does not exist!");
      return 0;
    }
    auto aflDirectory = options.output / options.fuzzer;
    if (!helper::fs::is_directory(aflDirectory / "queue")) {
      helper::log("ERROR", "The AFL queue " +
                               (aflDirectory / "queue").string() +
                               " does not exist!");
      return 0;
    }
    auto directory = options.output / options.name;
    if (helper::fs::is_directory(directory)) {
      helper::log("ERROR",
                  directory.string() +
                      " already exists; we do not currently support resuming");
      return 0;
    }
    helper::Coordinator coordinator(options);
    coordinator.run();
  } catch (const std::exception &error) {
    std::cerr << "Error: " << error.what() << '\n';
    return 1;
  }
}
