#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the real helper's process boundary without requiring AFL or Z3."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


def wait_until(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("Timed out waiting for helper progress")


def fake_target(args):
    root = Path(os.environ["HELPER_TEST_ROOT"])
    data = Path(args[0]).read_bytes() if args else sys.stdin.buffer.read()
    name = data.decode()
    bitmap = Path(os.environ["SYMCC_AFL_COVERAGE_MAP"])
    marker = root / ("started-" + name)
    staging = root / ("pending-" + name)
    staging.write_text(json.dumps({
        "pid": os.getpid(), "bitmap": str(bitmap),
        "input": os.environ.get("SYMCC_INPUT_FILE"),
        "previous": bitmap.read_text() if bitmap.exists() else None,
    }))
    staging.replace(marker)
    if name == "slow":
        wait_until(lambda: (root / "release-slow").exists())
    else:
        wait_until(lambda: (root / "release").exists())
    if args:
        assert Path(args[0]).read_bytes() == data, "Worker input was overwritten"
    bitmap.write_text(name)
    output = Path(os.environ["SYMCC_OUTPUT_DIR"])
    (output / "same").write_bytes(b"same")
    (output / "unique").write_bytes(data)
    (output / "crash").write_bytes(b"crash")
    (output / "hang").write_bytes(b"hang")
    print('[STAT] SMT: {"solving_time": 100}', file=sys.stderr)


def fake_showmap(args):
    root = Path(os.environ["HELPER_TEST_ROOT"])
    separator = args.index("--")
    target = args[separator + 1:]
    data = Path(target[-1]).read_bytes() if len(target) > 1 else sys.stdin.buffer.read()
    (root / ("checked-" + str(os.getpid()))).write_bytes(data)
    wait_until(lambda: (root / "release-map").exists())
    if (root / "bad-showmap").exists():
        return 3
    if data == b"hang":
        return 1
    if data == b"crash":
        return 2
    bitmap = bytearray(65536)
    bitmap[sum(data)] = 1
    Path(args[args.index("-o") + 1]).write_bytes(bitmap)
    return 0


class Integration(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="symcc-parallel-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.afl = self.root / "afl"
        (self.afl / "queue").mkdir(parents=True)
        wrapper = self.root / "afl-showmap"
        wrapper.write_text(
            "#!" + sys.executable + "\nimport runpy, sys\n"
            "sys.argv = [" + repr(__file__) + ", '--fake-showmap'] + sys.argv[1:]\n"
            "runpy.run_path(" + repr(__file__) + ", run_name='__main__')\n")
        wrapper.chmod(0o755)
        self.process = None

    def seed(self, index, name):
        (self.afl / "queue" / ("id:%06d,orig:%s" % (index, name))).write_text(name)

    def start(self, jobs=2, stdin=False):
        (self.afl / "fuzzer_stats").write_text(
            "command_line : " + str(self.root / "afl-fuzz") +
            " -- target" + ("" if stdin else " @@") + "\n")
        env = dict(os.environ, HELPER_TEST_ROOT=str(self.root))
        env.pop("RUST_LOG", None)
        env.pop("SYMCC_INPUT_FILE", None)
        self.log = (self.root / "helper.log").open("w")
        self.addCleanup(self.log.close)
        self.process = subprocess.Popen(
            [BINARY, "-o", str(self.root), "-a", "afl", "-n", "symcc",
             "--jobs=" + str(jobs), "-v", "--", sys.executable, __file__,
             "--fake-target"] + ([] if stdin else ["@@"]),
            env=env, stdout=subprocess.DEVNULL, stderr=self.log)
        self.addCleanup(self.cleanup_process)

    def cleanup_process(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def wait(self, predicate):
        try:
            wait_until(predicate)
        except AssertionError:
            self.fail((self.root / "helper.log").read_text())

    def release(self, name="release"):
        (self.root / name).touch()

    def finish(self, count):
        self.wait(lambda: (self.root / "helper.log").read_text().count(
            "Generated 4 test cases") == count)
        self.process.send_signal(signal.SIGTERM)
        self.assertEqual(self.process.wait(timeout=5), 0)
        stats = (self.root / "symcc" / "stats").read_text()
        self.assertIn("Successful executions: " + str(count) + "\n", stats)
        self.assertIn("Failed executions: 0\n", stats)

    def test_parallel_file_inputs_and_global_coverage(self):
        for index, name in enumerate(["alpha", "beta", "gamma", "delta"]):
            self.seed(index, name)
        self.start()
        self.wait(lambda: len(list(self.root.glob("started-*"))) == 2)
        time.sleep(0.2)
        self.assertEqual(len(list(self.root.glob("started-*"))), 2)
        first = [json.loads(p.read_text()) for p in self.root.glob("started-*")]
        self.assertEqual(len({p["bitmap"] for p in first}), 2)
        self.assertEqual(len({p["input"] for p in first}), 2)
        self.release()
        # Two validations must also overlap, outside the shared-state lock.
        self.wait(lambda: len(list(self.root.glob("checked-*"))) == 2)
        self.release("release-map")
        self.finish(4)
        records = [json.loads(p.read_text()) for p in self.root.glob("started-*")]
        self.assertEqual(len(records), 4)
        self.assertTrue(any(p["previous"] is not None for p in records))
        queue = list((self.root / "symcc" / "queue").iterdir())
        crashes = list((self.root / "symcc" / "crashes").iterdir())
        self.assertEqual(len(queue), 9)  # 1 common + 4 unique + 4 crashes
        self.assertEqual(len(crashes), 4)
        self.assertEqual(len(list((self.root / "symcc" / "hangs").iterdir())), 0)
        self.assertEqual(sorted(int(p.name[3:9]) for p in queue), list(range(9)))
        self.assertEqual(sum(p.read_bytes() == b"same" for p in queue), 1)
        self.assertEqual({p.name[14:20] for p in crashes},
                         {"000000", "000001", "000002", "000003"})

    def test_refill_while_another_worker_is_busy(self):
        self.seed(0, "slow")
        self.seed(1, "fast")
        self.start()
        self.wait(lambda: len(list(self.root.glob("started-*"))) == 2)
        self.release()
        self.release("release-map")
        self.seed(2, "new")
        self.wait(lambda: (self.root / "started-new").exists())
        self.assertFalse((self.root / "release-slow").exists())
        self.release("release-slow")
        self.finish(3)

    def test_idle_queue_wakes_on_close_and_rename(self):
        self.start(jobs=1)
        self.release()
        self.release("release-map")
        self.wait(lambda: "Coordinator started" in
                  (self.root / "helper.log").read_text())
        for index, name in enumerate(["closed", "renamed"]):
            # Let the previous scan finish with an empty queue. A newly
            # published file must not wait for the five-second fallback scan.
            time.sleep(0.2)
            if index == 0:
                self.seed(index, name)
            else:
                staging = self.root / "staged-input"
                staging.write_text(name)
                staging.rename(self.afl / "queue" /
                               ("id:%06d,orig:%s" % (index, name)))
            try:
                wait_until(lambda: (self.root / ("started-" + name)).exists(),
                           timeout=2)
            except AssertionError:
                self.fail((self.root / "helper.log").read_text())
            self.wait(lambda: (self.root / "helper.log").read_text().count(
                "Generated 4 test cases") == index + 1)
        self.finish(2)

    def test_serial_stdin_compatibility(self):
        self.seed(0, "alpha")
        self.seed(1, "beta")
        self.start(jobs=1, stdin=True)
        self.wait(lambda: len(list(self.root.glob("started-*"))) == 1)
        self.release()
        self.release("release-map")
        self.finish(2)
        records = [json.loads(p.read_text()) for p in self.root.glob("started-*")]
        self.assertTrue(all(p["input"] is None for p in records))
        self.assertTrue((self.root / "symcc" / ".cur_input").is_file())
        self.assertTrue((self.root / "symcc" / "bitmap").is_file())

    def test_stop_reaps_active_targets(self):
        self.seed(0, "alpha")
        self.seed(1, "beta")
        self.start()
        self.wait(lambda: len(list(self.root.glob("started-*"))) == 2)
        pids = [json.loads(p.read_text())["pid"]
                for p in self.root.glob("started-*")]
        self.process.send_signal(signal.SIGINT)
        self.assertEqual(self.process.wait(timeout=5), 0)
        for pid in pids:
            # A descendant may briefly remain a zombie until init reaps it.
            status = Path("/proc") / str(pid) / "stat"
            self.assertTrue(not status.exists() or status.read_text().split()[2] == "Z")

    def test_stop_reaps_active_showmap(self):
        self.seed(0, "alpha")
        self.start(jobs=1)
        self.release()
        self.wait(lambda: len(list(self.root.glob("checked-*"))) == 1)
        marker = next(self.root.glob("checked-*"))
        pid = int(marker.name.split("-", 1)[1])
        self.process.send_signal(signal.SIGTERM)
        self.assertEqual(self.process.wait(timeout=5), 0)
        status = Path("/proc") / str(pid) / "stat"
        self.assertTrue(not status.exists() or status.read_text().split()[2] == "Z")

    def test_worker_failure_cancels_siblings(self):
        self.seed(0, "slow")
        self.seed(1, "fast")
        self.start()
        self.wait(lambda: len(list(self.root.glob("started-*"))) == 2)
        self.release()
        self.release("bad-showmap")
        self.release("release-map")
        self.assertEqual(self.process.wait(timeout=5), 1)
        self.assertIn("Unexpected return code 3", (self.root / "helper.log").read_text())

    def test_invalid_jobs(self):
        for args in (["-j", "0"], ["--jobs=-1"], ["-jabc"],
                     ["--jobs=4294967296"], ["-j2", "--jobs=3"],
                     ["--jobs="], ["-j"]):
            result = subprocess.run([BINARY] + args, capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 1, args)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--fake-target":
        fake_target(sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == "--fake-showmap":
        sys.exit(fake_showmap(sys.argv[2:]))
    else:
        BINARY = str(Path(sys.argv.pop(1)).resolve())
        unittest.main()
