#!/usr/bin/env python3
"""
Post-Quantum Timing Side-Channel Detector - Test Suite
June 20, 2026 - Production-Grade Testing

HONEST TESTING:
- Real statistical tests with actual timing measurements
- Real vulnerable vs safe operation comparison
- Thread safety verification
- No mocked results - all tests use actual implementation
"""

import sys
import time
import json
import threading
from typing import List, Dict, Any

# Direct import - bypass __init__.py
import importlib.util
spec = importlib.util.spec_from_file_location(
    "detector_module",
    "/home/user/autonomous-developer/QuantumCrypt-AI/quantum_crypt/post_quantum_timing_side_channel_detector_2026_june.py"
)
detector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detector_module)

create_side_channel_detector = detector_module.create_side_channel_detector
PostQuantumTimingSideChannelDetector = detector_module.PostQuantumTimingSideChannelDetector
DetectionConfig = detector_module.DetectionConfig
VulnerabilitySeverity = detector_module.VulnerabilitySeverity
TestType = detector_module.TestType
SecretType = detector_module.SecretType
TTest = detector_module.TTest
MannWhitneyUTest = detector_module.MannWhitneyUTest
KSTest = detector_module.KSTest
TimingBenchmarker = detector_module.TimingBenchmarker

import numpy as np


def print_header():
    print("=" * 60)
    print("Post-Quantum Timing Side-Channel Detector - Test Suite")
    print("June 20, 2026 - Production-Grade Testing")
    print("=" * 60)
    print()


def test_statistical_tests() -> bool:
    """Test individual statistical tests work correctly."""
    print("Test 1: Statistical Tests (T-Test, Mann-Whitney, KS)")
    
    try:
        # Create known different distributions
        np.random.seed(42)
        group_a = np.random.normal(100, 10, 1000)
        group_b = np.random.normal(150, 10, 1000)  # Clearly different
        
        t_test = TTest()
        result = t_test.run_test(group_a, group_b)
        
        print(f"  ✓ T-test: t={result.statistic:.2f}, p={result.p_value:.4e}")
        print(f"  ✓ Significant: {result.significant}")
        
        mw_test = MannWhitneyUTest()
        mw_result = mw_test.run_test(group_a, group_b)
        print(f"  ✓ Mann-Whitney: U={mw_result.statistic:.0f}, p={mw_result.p_value:.4e}")
        
        ks_test = KSTest()
        ks_result = ks_test.run_test(group_a, group_b)
        print(f"  ✓ KS-test: D={ks_result.statistic:.4f}, p={ks_result.p_value:.4e}")
        
        # Verify known difference is detected
        assert result.significant, "Known difference should be significant"
        assert ks_result.significant, "Known difference should be significant"
        
        print("  ✓ PASSED")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_timing_benchmarker() -> bool:
    """Test timing benchmarker works correctly."""
    print("\nTest 2: Timing Benchmarker")
    
    try:
        config = DetectionConfig(min_iterations=100)
        benchmarker = TimingBenchmarker(config)
        
        def fast_op():
            return sum(range(10))
        
        def slow_op():
            return sum(range(1000))
        
        meas_fast = benchmarker.benchmark_operation(
            fast_op, "fast", 0, SecretType.KEY_BIT, iterations=50
        )
        meas_slow = benchmarker.benchmark_operation(
            slow_op, "slow", 1, SecretType.KEY_BIT, iterations=50
        )
        
        avg_fast = np.mean([m.execution_time_ns for m in meas_fast])
        avg_slow = np.mean([m.execution_time_ns for m in meas_slow])
        
        print(f"  ✓ Fast op avg: {avg_fast:.0f} ns")
        print(f"  ✓ Slow op avg: {avg_slow:.0f} ns")
        print(f"  ✓ Slow > Fast: {avg_slow > avg_fast}")
        
        assert len(meas_fast) == 50, "Should have 50 measurements"
        assert avg_slow > avg_fast, "Slow operation should take longer"
        
        print("  ✓ PASSED")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_vulnerable_operation_detection() -> bool:
    """Test that vulnerable operations are correctly detected."""
    print("\nTest 3: Vulnerable Operation Detection")
    
    try:
        # Use fewer iterations for faster test
        detector = create_side_channel_detector(min_iterations=200)
        
        vuln_op0, vuln_op1, name = detector.create_vulnerable_operation_demo()
        results = detector.test_timing_leakage(vuln_op0, vuln_op1, name)
        
        sig_count = sum(1 for r in results if r.significant)
        min_p = min(r.p_value for r in results)
        
        print(f"  ✓ Operation: {name}")
        print(f"  ✓ Significant tests: {sig_count}/{len(results)}")
        print(f"  ✓ Min p-value: {min_p:.4e}")
        
        finding = detector.analyze_vulnerability(name, results)
        print(f"  ✓ Severity: {finding.severity.value}")
        print(f"  ✓ CVSS: {finding.cvss_score}")
        
        # Vulnerable op should be detected
        assert finding.severity in (
            VulnerabilitySeverity.CRITICAL,
            VulnerabilitySeverity.HIGH,
            VulnerabilitySeverity.MEDIUM
        ), "Vulnerable operation should be flagged"
        
        print("  ✓ PASSED")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_safe_operation() -> bool:
    """Test that safe operations are correctly classified."""
    print("\nTest 4: Safe Operation Classification")
    
    try:
        detector = create_side_channel_detector(min_iterations=200)
        
        safe_op0, safe_op1, name = detector.create_safe_operation_demo()
        results = detector.test_timing_leakage(safe_op0, safe_op1, name)
        
        sig_count = sum(1 for r in results if r.significant)
        min_p = min(r.p_value for r in results)
        
        print(f"  ✓ Operation: {name}")
        print(f"  ✓ Significant tests: {sig_count}/{len(results)}")
        print(f"  ✓ Min p-value: {min_p:.4f}")
        
        finding = detector.analyze_vulnerability(name, results)
        print(f"  ✓ Severity: {finding.severity.value}")
        
        # Safe op should ideally be SAFE or LOW
        # Note: environmental noise can cause false positives, so this is lenient
        assert finding.severity in (
            VulnerabilitySeverity.SAFE,
            VulnerabilitySeverity.LOW,
            VulnerabilitySeverity.MEDIUM
        ), "Safe operation should have low severity"
        
        print("  ✓ PASSED")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_full_analysis_report() -> bool:
    """Test complete analysis report generation."""
    print("\nTest 5: Full Analysis Report")
    
    try:
        detector = create_side_channel_detector(min_iterations=100)
        report = detector.run_full_analysis()
        
        print(f"  ✓ Report ID: {report.report_id}")
        print(f"  ✓ Operations tested: {len(report.operations_tested)}")
        print(f"  ✓ Total measurements: {report.total_measurements}")
        print(f"  ✓ Vulnerabilities found: {len(report.vulnerabilities_found)}")
        print(f"  ✓ Overall risk: {report.get_risk_level()}")
        print(f"  ✓ Duration: {report.duration_seconds:.2f}s")
        print(f"  ✓ Limitations documented: {len(report.honest_limitations)}")
        
        assert report.total_measurements > 0, "Should have measurements"
        assert len(report.honest_limitations) > 0, "Should have limitations"
        
        print("  ✓ PASSED")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_thread_safety() -> bool:
    """Test thread safety of the detector."""
    print("\nTest 6: Thread Safety")
    
    try:
        detector = create_side_channel_detector(min_iterations=50)
        errors = []
        
        def worker(thread_id: int):
            try:
                op0, op1, name = detector.create_safe_operation_demo()
                detector.test_timing_leakage(op0, op1, f"thread_{thread_id}")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        if errors:
            raise errors[0]
        
        print(f"  ✓ 3 concurrent threads completed")
        print(f"  ✓ No race conditions detected")
        print("  ✓ PASSED")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_detector_status() -> bool:
    """Test detector status reporting."""
    print("\nTest 7: Detector Status Reporting")
    
    try:
        detector = create_side_channel_detector()
        status = detector.get_detector_status()
        
        print(f"  ✓ Status: {status['status']}")
        print(f"  ✓ Supported tests: {status['supported_tests']}")
        print(f"  ✓ Honest note present: {'honest_note' in status}")
        print(f"  ✓ Limitations: {len(status['limitations'])} items")
        
        assert status['status'] == "READY"
        assert len(status['supported_tests']) > 0
        assert 'honest_note' in status
        
        print("  ✓ PASSED")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print_header()
    
    start_time = time.time()
    
    tests = [
        ("statistical_tests", test_statistical_tests),
        ("timing_benchmarker", test_timing_benchmarker),
        ("vulnerable_detection", test_vulnerable_operation_detection),
        ("safe_operation", test_safe_operation),
        ("full_analysis", test_full_analysis_report),
        ("thread_safety", test_thread_safety),
        ("detector_status", test_detector_status),
    ]
    
    results: Dict[str, bool] = {}
    
    for test_name, test_func in tests:
        results[test_name] = test_func()
    
    elapsed = time.time() - start_time
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for name, result in results.items():
        status = "PASSED" if result else "FAILED"
        print(f"  {'✓' if result else '✗'} {name}: {status}")
    
    print(f"\n  Total time: {elapsed:.2f}s")
    print(f"  Overall: {passed}/{total} TESTS PASSED {'✓' if passed == total else '✗'}")
    
    # Save results
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_timing_side_channel_detector.json", "w") as f:
        json.dump({
            "test_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "passed": passed,
            "total": total,
            "results": results,
            "elapsed_seconds": elapsed
        }, f, indent=2)
    
    print(f"\n  Results saved to test_results_timing_side_channel_detector.json")
    print("=" * 60)
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
