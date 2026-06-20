"""
Test suite for Post-Quantum Random Number Health Monitor
Real production-grade tests
"""

import sys
import os
import json
import tempfile

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_random_number_health_monitor_2026_june import (
    StatisticalRandomnessTests,
    RandomNumberHealthMonitor,
    RandomnessTestResult,
    HealthReport,
    validate_post_quantum_key_material
)


def test_frequency_test():
    """Test frequency (monobit) test"""
    # Good random data
    good_data = os.urandom(512)
    result = StatisticalRandomnessTests.frequency_test(good_data)
    
    assert isinstance(result, RandomnessTestResult)
    assert result.test_name == "frequency_monobit"
    assert 0 <= result.p_value <= 1
    print("✓ test_frequency_test PASSED")


def test_runs_test():
    """Test runs test"""
    good_data = os.urandom(512)
    result = StatisticalRandomnessTests.runs_test(good_data)
    
    assert isinstance(result, RandomnessTestResult)
    assert result.test_name == "runs"
    assert "observed_runs" in result.details
    print("✓ test_runs_test PASSED")


def test_chi_square_test():
    """Test chi-square uniformity test"""
    good_data = os.urandom(1024)
    result = StatisticalRandomnessTests.chi_square_test(good_data)
    
    assert isinstance(result, RandomnessTestResult)
    assert result.test_name == "chi_square_uniformity"
    assert "chi_square_statistic" in result.details
    print("✓ test_chi_square_test PASSED")


def test_autocorrelation_test():
    """Test autocorrelation test"""
    good_data = os.urandom(512)
    result = StatisticalRandomnessTests.autocorrelation_test(good_data, lag=1)
    
    assert isinstance(result, RandomnessTestResult)
    assert "lag1" in result.test_name
    print("✓ test_autocorrelation_test PASSED")


def test_entropy_estimate():
    """Test entropy estimation"""
    good_data = os.urandom(1024)
    shannon, min_entropy = StatisticalRandomnessTests.entropy_estimate(good_data)
    
    assert 0 <= shannon <= 8
    assert 0 <= min_entropy <= 8
    # Good random data should have high entropy
    assert shannon > 7.5  # Real entropy check
    print("✓ test_entropy_estimate PASSED")


def test_longest_run_test():
    """Test longest run test"""
    good_data = os.urandom(512)
    result = StatisticalRandomnessTests.longest_run_test(good_data)
    
    assert isinstance(result, RandomnessTestResult)
    assert result.test_name == "longest_run"
    print("✓ test_longest_run_test PASSED")


def test_bad_data_detection():
    """Test that non-random data is correctly detected"""
    # Create obviously non-random data
    bad_data = b'\x00' * 512  # All zeros
    result = StatisticalRandomnessTests.frequency_test(bad_data)
    
    # Should fail or have very low score
    assert result.passed == False or result.score < 0.5
    print("✓ test_bad_data_detection PASSED")


def test_monitor_initialization():
    """Test health monitor initialization"""
    monitor = RandomNumberHealthMonitor(sample_size=2048)
    
    assert monitor.sample_size == 2048
    assert len(monitor.test_history) == 0
    print("✓ test_monitor_initialization PASSED")


def test_generate_sample():
    """Test sample generation"""
    monitor = RandomNumberHealthMonitor(sample_size=1024)
    
    sample_system = monitor.generate_sample("system")
    sample_urandom = monitor.generate_sample("urandom")
    sample_mixed = monitor.generate_sample("mixed")
    
    assert len(sample_system) == 1024
    assert len(sample_urandom) == 1024
    assert len(sample_mixed) == 1024
    print("✓ test_generate_sample PASSED")


def test_full_test_suite():
    """Test complete test suite execution"""
    monitor = RandomNumberHealthMonitor(sample_size=4096)
    
    report = monitor.run_full_test_suite()
    
    assert isinstance(report, HealthReport)
    assert len(report.test_results) >= 6  # 6 tests
    assert report.overall_health_score > 0
    assert report.status in ["HEALTHY", "WARNING", "CRITICAL", "FAILED"]
    assert len(report.recommendations) > 0
    assert report.entropy_estimate > 0
    print("✓ test_full_test_suite PASSED")


def test_system_rng_health():
    """Verify system RNG passes health checks (real validation)"""
    monitor = RandomNumberHealthMonitor(sample_size=8192)
    report = monitor.run_full_test_suite()
    
    # System CSPRNG should be healthy
    passed_tests = sum(1 for t in report.test_results if t.passed)
    total_tests = len(report.test_results)
    
    # Should pass most tests
    assert passed_tests >= total_tests * 0.7
    assert report.entropy_estimate > 7.7  # High entropy
    print(f"✓ test_system_rng_health PASSED ({passed_tests}/{total_tests} tests passed)")


def test_trend_analysis():
    """Test historical trend analysis"""
    monitor = RandomNumberHealthMonitor(sample_size=2048)
    
    # Run several tests
    for _ in range(5):
        monitor.run_full_test_suite()
    
    trends = monitor.get_trend_analysis()
    
    assert "total_tests" in trends
    assert "score_trend" in trends
    assert "status_distribution" in trends
    assert trends["total_tests"] == 5
    print("✓ test_trend_analysis PASSED")


def test_report_export():
    """Test report export functionality"""
    monitor = RandomNumberHealthMonitor(sample_size=2048)
    report = monitor.run_full_test_suite()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        filepath = f.name
    
    try:
        success = monitor.export_report(report, filepath)
        assert success
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        assert "report_id" in data
        assert "status" in data
        assert "test_results" in data
        print("✓ test_report_export PASSED")
    finally:
        os.unlink(filepath)


def test_continuous_monitoring():
    """Test continuous monitoring mode"""
    monitor = RandomNumberHealthMonitor(sample_size=1024)
    
    reports = monitor.continuous_monitoring(iterations=3)
    
    assert len(reports) == 3
    assert all(isinstance(r, HealthReport) for r in reports)
    print("✓ test_continuous_monitoring PASSED")


def test_pq_key_validation():
    """Test post-quantum key material validation"""
    # Use larger sample for reliable entropy estimation
    good_key = os.urandom(512)  # Larger sample for accurate entropy
    result = validate_post_quantum_key_material(good_key)
    
    assert "valid_for_pq_crypto" in result
    assert "health_status" in result
    assert "entropy_bits_per_byte" in result
    assert result["entropy_bits_per_byte"] > 7.0
    print("✓ test_pq_key_validation PASSED")


def test_bad_key_validation():
    """Test that weak key material is rejected"""
    bad_key = b'\x00' * 32  # All zeros - very bad
    result = validate_post_quantum_key_material(bad_key)
    
    # Should not be valid for PQ crypto
    assert result["valid_for_pq_crypto"] == False or result["health_status"] != "HEALTHY"
    print("✓ test_bad_key_validation PASSED")


def test_insufficient_data_handling():
    """Test edge case: insufficient data"""
    small_data = b'\x00' * 10
    result = StatisticalRandomnessTests.frequency_test(small_data)
    
    assert result.passed == False
    assert "error" in result.details
    print("✓ test_insufficient_data_handling PASSED")


def test_empty_data():
    """Test edge case: empty data"""
    shannon, min_entropy = StatisticalRandomnessTests.entropy_estimate(b'')
    
    assert shannon == 0.0
    assert min_entropy == 0.0
    print("✓ test_empty_data PASSED")


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Post-Quantum Random Number Health Monitor - Test Suite")
    print("=" * 60)
    print()
    
    tests = [
        test_frequency_test,
        test_runs_test,
        test_chi_square_test,
        test_autocorrelation_test,
        test_entropy_estimate,
        test_longest_run_test,
        test_bad_data_detection,
        test_monitor_initialization,
        test_generate_sample,
        test_full_test_suite,
        test_system_rng_health,
        test_trend_analysis,
        test_report_export,
        test_continuous_monitoring,
        test_pq_key_validation,
        test_bad_key_validation,
        test_insufficient_data_handling,
        test_empty_data
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            failures.append((test.__name__, str(e)))
            print(f"✗ {test.__name__} FAILED: {e}")
    
    print()
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failures:
        print("\nFailures:")
        for name, error in failures:
            print(f"  - {name}: {error}")
    
    # Save results
    results = {
        'test_timestamp': __import__('datetime').datetime.utcnow().isoformat(),
        'total_tests': len(tests),
        'passed': passed,
        'failed': failed,
        'pass_rate': f"{(passed/len(tests)*100):.1f}%"
    }
    
    with open('test_results_post_quantum_random_number_health_monitor.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_post_quantum_random_number_health_monitor.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
