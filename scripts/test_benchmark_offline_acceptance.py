"""Regression checks for the offline acceptance result reader and summary."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "offline_acceptance", Path(__file__).with_name("benchmark-offline-acceptance.py")
)
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class AcceptanceResultsTest(unittest.TestCase):
    def test_go_benchmark_names_with_one_or_multiple_processors(self):
        for suffix in ("", "-32"):
            with self.subTest(
                suffix=suffix
            ), tempfile.TemporaryDirectory() as directory:
                log = Path(directory) / "benchmark.log"
                log.write_text(
                    "goos: linux\n"
                    f"BenchmarkOfflineAcceptance{suffix}\t1\t100 ns/op\t42 packets\n"
                    "PASS\n"
                )
                self.assertEqual(
                    acceptance.read_metrics(log), {"ns/op": 100, "packets": 42}
                )

    def test_fresh_process_percentiles_exclude_profile(self):
        runs = [
            {"profiled": False, "metrics": {"latency-ns": value}}
            for value in (30, 10, 20)
        ]
        runs.append({"profiled": True, "metrics": {"latency-ns": 1000}})
        summary = acceptance.summarize_runs(runs)
        self.assertEqual(summary["runs"], 3)
        self.assertEqual(summary["median"], {"latency-ns": 20})
        self.assertEqual(summary["p95"], {"latency-ns": 30})

    def test_p95_uses_nearest_rank_for_larger_run_counts(self):
        runs = [
            {"profiled": False, "metrics": {"latency-ns": value}}
            for value in range(1, 21)
        ]
        self.assertEqual(acceptance.summarize_runs(runs)["p95"], {"latency-ns": 19})

    def test_mismatched_metric_sets_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "metric set changed"):
            acceptance.summarize_runs(
                [
                    {"profiled": False, "metrics": {"latency-ns": 10}},
                    {"profiled": False, "metrics": {"packets": 42}},
                ]
            )


if __name__ == "__main__":
    unittest.main()
