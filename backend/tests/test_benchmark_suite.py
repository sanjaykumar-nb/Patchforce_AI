"""
PatchForge AI - Phase 21 Benchmark Suite Unit Tests
===================================================
Validates that the 50-case benchmark suite executes and achieves >= 95% Precision,
>= 90% Recall, and zero false positives on safe code patterns.
"""

import pytest
from benchmark.benchmark_suite import run_benchmark_suite, generate_50_benchmark_cases


def test_benchmark_suite_generation():
    cases = generate_50_benchmark_cases()
    assert len(cases) == 50
    vulnerable_count = sum(1 for c in cases if c.is_vulnerable)
    safe_count = sum(1 for c in cases if not c.is_vulnerable)
    assert vulnerable_count == 33
    assert safe_count == 17


def test_benchmark_suite_metrics_evaluation():
    report = run_benchmark_suite()
    assert report["total_cases"] == 50
    assert report["accuracy"] >= 95.0
    assert report["precision"] >= 95.0
    assert report["recall"] >= 90.0
    assert report["false_positives"] == 0
    assert report["avg_time_ms"] < 20.0
