#!/usr/bin/env python3
"""Compile once; run >=3 warm, fresh-process offline acceptance measurements.

Artifacts contain private capture paths and configuration: keep the output local.
No cold-cache claim is made. CPU/heap profiling is a separate optional process.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import statistics
import subprocess
import time


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_metrics(path):
    for line in path.read_text().splitlines():
        if re.match(r"^BenchmarkOfflineAcceptance-\d+\s+1\s+", line):
            columns = line.split()[2:]
            if len(columns) % 2:
                raise ValueError("incomplete benchmark metric pairs")
            return {
                columns[i + 1]: float(columns[i]) for i in range(0, len(columns), 2)
            }
    raise ValueError("acceptance benchmark did not emit completed metrics")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--profile", action="store_true")
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("at least three unprofiled runs are required")
    capture = args.capture.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    patch = subprocess.check_output(["git", "diff", "HEAD", "--binary"])
    (output / "baseline.patch").write_bytes(patch)
    untracked = (
        subprocess.check_output(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"]
        )
        .decode()
        .split("\0")
    )
    metadata = {
        "revision": command("git", "rev-parse", "HEAD"),
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "untracked_sha256": {
            p: sha256(p) for p in untracked if p and Path(p).is_file()
        },
        "go": command("go", "version"),
        "build_tags": "all",
        "runner_sha256": sha256(Path(__file__)),
        "host": platform.uname()._asdict(),
        "cpu_count": os.cpu_count(),
        "capture": str(capture),
        "capture_bytes": capture.stat().st_size,
        "capture_sha256": sha256(capture),
        "cache": "warm: sequential complete read before each process; no drop_caches",
        "persistent_reuse": "unavailable; new temporary dataset for each process",
        "cold_cache": "unverified",
        "rlimit_as": resource.getrlimit(resource.RLIMIT_AS),
        "rlimit_nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
        "environment": {
            k: os.environ.get(k, "default")
            for k in ("GOMAXPROCS", "GOGC", "GOMEMLIMIT", "LIPPYCAT_BENCH_BPF")
        },
        "rss": "wait4 per-child maximum RSS (KiB on Linux), whole fresh benchmark process",
        "disk": "benchmark sampled accounted index/scratch/query peak; export output separate; filesystem allocation peak unavailable",
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    binary = output / "offline-acceptance.test"
    env = dict(
        os.environ,
        GOCACHE="/tmp/lippycat-go-cache",
        LOG_LEVEL="ERROR",
        LIPPYCAT_BENCH_PCAP=str(capture),
    )
    subprocess.run(
        ["go", "test", "-c", "-tags", "all", "-o", str(binary), "./internal/pkg/tui"],
        check=True,
        env=env,
    )
    metadata["benchmark_binary_sha256"] = sha256(binary)
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    base = [
        str(binary),
        "-test.run=^$",
        "-test.bench=^BenchmarkOfflineAcceptance$",
        "-test.benchtime=1x",
        "-test.benchmem",
        "-test.timeout=10m",
    ]
    runs = []
    for run in range(args.runs + int(args.profile)):
        profiled = run == args.runs
        label = "profile" if profiled else f"warm-{run + 1}"
        # Reading the original source also fixes the declared cache preparation.
        if sha256(capture) != metadata["capture_sha256"]:
            raise RuntimeError("capture changed during measurement")
        cmd = base.copy()
        if profiled:
            cmd += [
                f"-test.cpuprofile={output}/cpu.pprof",
                f"-test.memprofile={output}/heap.pprof",
            ]
        started = time.monotonic()
        with (output / f"{label}.log").open("w") as log:
            child = subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            (output / f"{label}.resources.json").write_text(
                json.dumps(
                    {
                        "max_rss": usage.ru_maxrss,
                        "rss_unit": "bytes" if platform.system() == "Darwin" else "KiB",
                        "user_seconds": usage.ru_utime,
                        "system_seconds": usage.ru_stime,
                        "minor_faults": usage.ru_minflt,
                        "major_faults": usage.ru_majflt,
                    },
                    indent=2,
                )
                + "\n"
            )
            if child.returncode:
                raise subprocess.CalledProcessError(child.returncode, cmd)
        runs.append(
            {
                "label": label,
                "profiled": profiled,
                "process_seconds": time.monotonic() - started,
                "command": cmd,
                "metrics": read_metrics(output / f"{label}.log"),
            }
        )
        (output / "runs.json").write_text(json.dumps(runs, indent=2) + "\n")
        print(f"completed {label}", flush=True)
    unprofiled = [run["metrics"] for run in runs if not run["profiled"]]
    if any(sample.keys() != unprofiled[0].keys() for sample in unprofiled):
        raise ValueError("acceptance metric set changed between runs")
    summary = {
        "runs": len(unprofiled),
        "median": {
            key: statistics.median(sample[key] for sample in unprofiled)
            for key in sorted(unprofiled[0])
        },
        "note": "Unprofiled fresh-process medians only; raw samples in runs.json.",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
