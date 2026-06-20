"""
Test Suite for Post-Quantum Cryptographic Randomness Health Monitor
Production-Grade Tests - June 21, 2026
"""
import pytest
import json
import os
from datetime import datetime
from quantum_crypt.post_quantum_cryptographic_randomness_health_monitor_2026_june import (
    CryptographicRandomnessHealthMonitor,
    HealthStatus,
    TestResult
)


class TestCryptographicRandomnessHealthMonitor:
    """Test suite for randomness health monitor."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.monitor = CryptographicRandomnessHealthMonitor(window_size=50)
        
        # Good random data from system CSPRNG
        self.good_random = os.urandom(1024)
        
        # Bad non-random data for testing
        self.bad_random_all_zeros = b'\x00' * 1024
        self.bad_random_all_ones = b'\xff' * 1024
        self.bad_random_repeating = b'ABCD' * 256
    
    def test_shannon_entropy_calculation(self):
        """Test real Shannon entropy calculation."""
        # Good random should have high entropy (~7.9-8.0 bits per byte)
        entropy, _ = self.monitor._calculate_shannon_entropy(self.good_random)
        assert 7.5 <= entropy <= 8.0
        
        # All zeros should have 0 entropy
        entropy_zero, _ = self.monitor._calculate_shannon_entropy(self.bad_random_all_zeros)
        assert entropy_zero == 0.0
        
        # Repeating pattern should have low entropy
        entropy_repeat, _ = self.monitor._calculate_shannon_entropy(self.bad_random_repeating)
        assert entropy_repeat < 5.0
    
    def test_min_entropy_calculation(self):
        """Test min-entropy calculation."""
        # Good random should have reasonable min-entropy
        min_entropy = self.monitor._calculate_min_entropy(self.good_random)
        assert min_entropy > 4.0
        
        # All zeros should have 0 min-entropy
        min_entropy_zero = self.monitor._calculate_min_entropy(self.bad_random_all_zeros)
        assert min_entropy_zero == 0.0
    
    def test_frequency_monobit_test(self):
        """Test frequency (monobit) test."""
        # Good random should pass
        result = self.monitor._frequency_test(self.good_random)
        assert result.test_name == "frequency_monobit"
        # System CSPRNG should pass or at least not fail catastrophically
        assert result.result in [TestResult.PASS, TestResult.WARNING]
        assert 0 <= result.p_value <= 1.0
        
        # All zeros should FAIL
        result_bad = self.monitor._frequency_test(self.bad_random_all_zeros)
        assert result_bad.result == TestResult.FAIL
        assert result_bad.score < 50.0
    
    def test_runs_test(self):
        """Test runs test for randomness."""
        # Good random should pass
        result = self.monitor._runs_test(self.good_random)
        assert result.test_name == "runs_test"
        
        # Constant data should fail runs test
        result_bad = self.monitor._runs_test(self.bad_random_all_zeros)
        assert result_bad.result == TestResult.FAIL
    
    def test_chi_square_test(self):
        """Test chi-square uniformity test."""
        # Good random should have reasonable chi-square
        result = self.monitor._chi_square_test(self.good_random)
        assert result.test_name == "chi_square_uniformity"
        
        # All zeros should FAIL badly
        result_bad = self.monitor._chi_square_test(self.bad_random_all_zeros)
        assert result_bad.result == TestResult.FAIL
        assert result_bad.score < 50.0
    
    def test_longest_run_test(self):
        """Test longest run detection."""
        # Good random should pass
        result = self.monitor._longest_run_test(self.good_random)
        assert result.test_name == "longest_run"
        
        # All zeros - extremely long run should FAIL
        result_bad = self.monitor._longest_run_test(self.bad_random_all_zeros)
        assert result_bad.result == TestResult.FAIL
        assert result_bad.details['longest_run_0'] > 100
    
    def test_serial_correlation_test(self):
        """Test serial correlation detection."""
        # Good random should have low correlation
        result = self.monitor._serial_correlation_test(self.good_random)
        assert result.test_name == "serial_correlation"
        # Correlation should be near 0 for good random
        assert abs(result.details['correlation_coefficient']) < 0.2
        
        # Constant data has perfect correlation
        result_bad = self.monitor._serial_correlation_test(self.bad_random_all_zeros)
        assert result_bad.result != TestResult.PASS
    
    def test_pattern_analysis(self):
        """Test pattern analysis."""
        # Good random should have few patterns
        patterns_good = self.monitor._analyze_patterns(self.good_random)
        assert len(patterns_good.suspicious_patterns) <= 1
        
        # Bad data should detect patterns
        patterns_bad = self.monitor._analyze_patterns(self.bad_random_all_zeros)
        assert "long_zero_sequence" in patterns_bad.suspicious_patterns
        assert patterns_bad.longest_run_zeros > 100
    
    def test_analyze_randomness_good_data(self):
        """Test full analysis with good random data."""
        report = self.monitor.analyze_randomness(
            sample_id="test_good_001",
            random_data=self.good_random,
            source="system_csprng"
        )
        
        # Verify report structure
        assert report.report_id == "report_test_good_001"
        assert report.total_bytes_analyzed >= 1024
        assert len(report.statistical_tests) == 5
        
        # System CSPRNG should get good health score
        assert report.overall_health_score >= 60.0
        assert report.health_status in [
            HealthStatus.EXCELLENT,
            HealthStatus.GOOD,
            HealthStatus.ACCEPTABLE
        ]
        
        # Entropy should be high
        assert report.entropy_analysis.shannon_entropy >= 7.0
        assert report.entropy_analysis.entropy_per_bit >= 0.85
    
    def test_analyze_randomness_bad_data(self):
        """Test full analysis with bad non-random data."""
        report = self.monitor.analyze_randomness(
            sample_id="test_bad_001",
            random_data=self.bad_random_all_zeros,
            source="bad_source"
        )
        
        # Bad data should get low score
        assert report.overall_health_score < 50.0
        assert report.health_status in [
            HealthStatus.DEGRADED,
            HealthStatus.CRITICAL,
            HealthStatus.FAILED
        ]
        
        # Should have alerts
        assert len(report.alerts) > 0
        
        # Should have critical recommendations
        critical_recs = [r for r in report.recommendations if r['priority'] == 'CRITICAL']
        assert len(critical_recs) > 0
    
    def test_health_status_scoring(self):
        """Test health status classification."""
        score_excellent, status_excellent = self.monitor._calculate_overall_health([])
        # Empty list gives failed status
        assert status_excellent == HealthStatus.FAILED
    
    def test_input_validation(self):
        """Test input validation."""
        # Too small sample should raise error
        with pytest.raises(ValueError, match="Minimum 16 bytes"):
            self.monitor.analyze_randomness(
                sample_id="test_small",
                random_data=b'short'
            )
    
    def test_sliding_window_history(self):
        """Test sliding window history tracking."""
        # Process multiple samples
        for i in range(10):
            self.monitor.analyze_randomness(
                sample_id=f"window_test_{i}",
                random_data=os.urandom(256)
            )
        
        metrics = self.monitor.get_metrics()
        assert metrics['total_samples_processed'] == 10
        assert metrics['total_bytes_processed'] == 10 * 256
    
    def test_trend_analysis(self):
        """Test trend analysis over multiple samples."""
        # Process several samples to build history
        for i in range(8):
            self.monitor.analyze_randomness(
                sample_id=f"trend_test_{i}",
                random_data=os.urandom(512)
            )
        
        report = self.monitor.analyze_randomness(
            sample_id="trend_test_final",
            random_data=os.urandom(512)
        )
        
        assert 'trend' in report.trend_analysis
        assert report.trend_analysis['trend'] in ['STABLE', 'IMPROVING', 'DEGRADING']
        assert 'rolling_average' in report.trend_analysis
        assert 'std_deviation' in report.trend_analysis
    
    def test_recommendations_generation(self):
        """Test recommendations generation."""
        # Bad data should give critical recommendations
        report_bad = self.monitor.analyze_randomness(
            sample_id="rec_test_bad",
            random_data=self.bad_random_all_zeros
        )
        
        assert len(report_bad.recommendations) > 0
        
        # Good data should give positive recommendations
        report_good = self.monitor.analyze_randomness(
            sample_id="rec_test_good",
            random_data=self.good_random
        )
        
        assert len(report_good.recommendations) > 0
    
    def test_export_report_json(self):
        """Test JSON export functionality."""
        report = self.monitor.analyze_randomness(
            sample_id="json_test",
            random_data=self.good_random
        )
        
        json_output = self.monitor.export_report_json(report)
        parsed = json.loads(json_output)
        
        assert parsed['report_id'] == "report_json_test"
        assert 'overall_health_score' in parsed
        assert 'health_status' in parsed
        assert 'statistical_tests' in parsed
        assert 'entropy' in parsed
        assert 'alerts' in parsed
    
    def test_get_system_random_sample(self):
        """Test system CSPRNG sampling."""
        sample = self.monitor.get_system_random_sample(256)
        assert len(sample) == 256
        assert isinstance(sample, bytes)
        
        # Sample should be random
        entropy, _ = self.monitor._calculate_shannon_entropy(sample)
        assert entropy > 7.0
    
    def test_alerts_generation(self):
        """Test alert generation for failed tests."""
        report = self.monitor.analyze_randomness(
            sample_id="alert_test",
            random_data=self.bad_random_all_zeros
        )
        
        # Should have HIGH severity alerts for failures
        high_alerts = [a for a in report.alerts if a['severity'] == 'HIGH']
        assert len(high_alerts) > 0


def run_tests_and_save_results():
    """Run tests and save results to JSON."""
    import time
    
    start_time = time.time()
    
    test = TestCryptographicRandomnessHealthMonitor()
    test.setup_method()
    
    results = {
        'test_timestamp': datetime.utcnow().isoformat() + "Z",
        'module': 'post_quantum_cryptographic_randomness_health_monitor',
        'tests_passed': 0,
        'tests_failed': 0,
        'failures': [],
        'execution_time_ms': 0
    }
    
    test_functions = [
        ('shannon_entropy_calculation', test.test_shannon_entropy_calculation),
        ('min_entropy_calculation', test.test_min_entropy_calculation),
        ('frequency_monobit_test', test.test_frequency_monobit_test),
        ('runs_test', test.test_runs_test),
        ('chi_square_test', test.test_chi_square_test),
        ('longest_run_test', test.test_longest_run_test),
        ('serial_correlation_test', test.test_serial_correlation_test),
        ('pattern_analysis', test.test_pattern_analysis),
        ('analyze_randomness_good_data', test.test_analyze_randomness_good_data),
        ('analyze_randomness_bad_data', test.test_analyze_randomness_bad_data),
        ('health_status_scoring', test.test_health_status_scoring),
        ('input_validation', test.test_input_validation),
        ('sliding_window_history', test.test_sliding_window_history),
        ('trend_analysis', test.test_trend_analysis),
        ('recommendations_generation', test.test_recommendations_generation),
        ('export_report_json', test.test_export_report_json),
        ('get_system_random_sample', test.test_get_system_random_sample),
        ('alerts_generation', test.test_alerts_generation),
    ]
    
    for test_name, test_func in test_functions:
        try:
            test_func()
            results['tests_passed'] += 1
            print(f"✓ {test_name}")
        except Exception as e:
            results['tests_failed'] += 1
            results['failures'].append({
                'test': test_name,
                'error': str(e)
            })
            print(f"✗ {test_name}: {e}")
    
    results['execution_time_ms'] = round((time.time() - start_time) * 1000, 2)
    
    # Save results
    with open('test_results_cryptographic_randomness_health_monitor_2026_june.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n=== TEST SUMMARY ===")
    print(f"Passed: {results['tests_passed']}")
    print(f"Failed: {results['tests_failed']}")
    print(f"Time: {results['execution_time_ms']}ms")
    
    return results


if __name__ == "__main__":
    run_tests_and_save_results()
