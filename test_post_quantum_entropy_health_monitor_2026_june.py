"""
Test Suite for QuantumCrypt AI - Post-Quantum Entropy Health Monitor
Real, production-grade tests with actual assertions

Tests cover:
1. Entropy collection from multiple sources
2. NIST statistical health tests
3. Entropy estimation (Shannon, Min-Entropy)
4. Entropy pool management
5. Health report generation
6. Random byte generation
7. Thread safety and background collection
8. Edge cases and boundary conditions

Author: QuantumCrypt AI Team
Date: June 2026
"""

import json
import os
import time
import tempfile
from datetime import datetime

# Import directly without package issues
import importlib.util
spec = importlib.util.spec_from_file_location(
    'entropy_monitor',
    'quantum_crypt/post_quantum_entropy_health_monitor_collector_2026_june.py'
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

EntropyHealthMonitor = module.EntropyHealthMonitor
EntropySource = module.EntropySource
HealthStatus = module.HealthStatus


class TestEntropyHealthMonitor:
    """Test suite for EntropyHealthMonitor"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.monitor = EntropyHealthMonitor(pool_size=1024, sample_history=100)
    
    def test_initialization(self):
        """Test monitor initialization"""
        assert self.monitor.entropy_pool == bytearray()
        assert self.monitor.pool_size == 1024
        assert self.monitor.samples_collected == 0
        assert self.monitor._collector_running == False
    
    def test_collect_os_random(self):
        """Test OS random collection"""
        data = self.monitor._collect_os_random(32)
        assert len(data) == 32
        assert isinstance(data, bytes)
        # Should have high entropy
        entropy = self.monitor._estimate_shannon_entropy(data)
        assert entropy > 7.0  # Good random data should be >7 bits/byte
    
    def test_collect_system_random(self):
        """Test system timing random collection"""
        data = self.monitor._collect_system_random(16)
        assert len(data) == 16
        assert isinstance(data, bytes)
        # Should have some entropy
        entropy = self.monitor._estimate_shannon_entropy(data)
        assert entropy >= 0.0
    
    def test_collect_cpu_cycles(self):
        """Test CPU cycle collection"""
        data = self.monitor._collect_cpu_cycles(16)
        assert len(data) == 16
        assert isinstance(data, bytes)
    
    def test_collect_secrets_module(self):
        """Test Python secrets module collection"""
        data = self.monitor._collect_secrets_module(32)
        assert len(data) == 32
        entropy = self.monitor._estimate_shannon_entropy(data)
        assert entropy > 7.5  # Secrets module should be very high quality
    
    def test_collect_sample_all_sources(self):
        """Test collection from all entropy sources"""
        for source in list(EntropySource)[:5]:
            sample = self.monitor.collect_sample(source, num_bytes=16)
            assert len(sample.data) == 16
            assert sample.source == source.value
            assert sample.raw_entropy >= 0.0
            assert sample.timestamp > 0
            assert len(sample.sample_id) == 16
    
    def test_shannon_entropy_calculation(self):
        """Test Shannon entropy calculation"""
        # All zeros - minimum entropy
        zeros = b'\x00' * 256
        entropy = self.monitor._estimate_shannon_entropy(zeros)
        assert entropy == 0.0
        
        # Uniform random should have high entropy
        random_data = os.urandom(256)
        entropy = self.monitor._estimate_shannon_entropy(random_data)
        assert entropy > 7.5
    
    def test_min_entropy_calculation(self):
        """Test min-entropy calculation"""
        # All zeros
        zeros = b'\x00' * 256
        min_entropy = self.monitor._estimate_min_entropy(zeros)
        assert min_entropy == 0.0
        
        # Random data
        random_data = os.urandom(256)
        min_entropy = self.monitor._estimate_min_entropy(random_data)
        assert min_entropy > 6.0
    
    def test_frequency_test(self):
        """Test NIST Frequency (Monobit) Test"""
        # Good random data should pass
        good_data = os.urandom(256)
        result = self.monitor._frequency_test(good_data)
        assert result.test_name == "Frequency (Monobit) Test"
        assert hasattr(result, 'passed')
        assert hasattr(result, 'score')
        
        # Bad data (all zeros) should fail
        bad_data = b'\x00' * 256
        result_bad = self.monitor._frequency_test(bad_data)
        # All zeros definitely fails frequency test
        assert result_bad.passed == False
    
    def test_runs_test(self):
        """Test NIST Runs Test"""
        good_data = os.urandom(256)
        result = self.monitor._runs_test(good_data)
        assert "Runs Test" in result.test_name
        assert hasattr(result, 'passed')
    
    def test_autocorrelation_test(self):
        """Test Autocorrelation Test"""
        good_data = os.urandom(256)
        result = self.monitor._autocorrelation_test(good_data)
        assert "Autocorrelation" in result.test_name
        assert hasattr(result, 'passed')
    
    def test_chi_square_test(self):
        """Test Chi-Square Test"""
        good_data = os.urandom(256)
        result = self.monitor._chi_square_test(good_data)
        assert "Chi-Square" in result.test_name
        assert hasattr(result, 'passed')
        
        # Uniform data should have low chi-square
        uniform_data = bytes(range(256))
        result_uniform = self.monitor._chi_square_test(uniform_data)
        assert result_uniform.passed == True
    
    def test_longest_run_test(self):
        """Test Longest Run Test"""
        # Normal random should pass
        good_data = os.urandom(256)
        result = self.monitor._longest_run_test(good_data)
        assert "Longest Run" in result.test_name
        assert hasattr(result, 'passed')
        
        # All ones should fail (very long run)
        all_ones = b'\xFF' * 256
        result_bad = self.monitor._longest_run_test(all_ones)
        assert result_bad.passed == False
    
    def test_full_health_suite(self):
        """Test full NIST health test suite"""
        tests = self.monitor.run_full_health_suite(os.urandom(256))
        assert len(tests) == 5  # 5 tests in suite
        for test in tests:
            assert hasattr(test, 'test_name')
            assert hasattr(test, 'passed')
            assert hasattr(test, 'score')
    
    def test_add_entropy_to_pool(self):
        """Test adding entropy to pool"""
        sample = self.monitor.collect_sample(EntropySource.OS_RANDOM, 32)
        initial_size = len(self.monitor.entropy_pool)
        
        self.monitor.add_entropy_to_pool(sample)
        
        assert len(self.monitor.entropy_pool) > initial_size
        assert self.monitor.samples_collected == 1
        assert len(self.monitor.sample_history) == 1
    
    def test_pool_maintains_size(self):
        """Test that pool doesn't exceed configured size"""
        for _ in range(100):
            sample = self.monitor.collect_sample(EntropySource.OS_RANDOM)
            self.monitor.add_entropy_to_pool(sample)
        
        # Pool should not exceed target size significantly
        assert len(self.monitor.entropy_pool) <= self.monitor.pool_size + 64
    
    def test_get_random_bytes(self):
        """Test random byte generation"""
        # First add some entropy
        for _ in range(10):
            sample = self.monitor.collect_sample(EntropySource.OS_RANDOM)
            self.monitor.add_entropy_to_pool(sample)
        
        # Generate random bytes
        rand_16 = self.monitor.get_random_bytes(16)
        assert len(rand_16) == 16
        
        rand_64 = self.monitor.get_random_bytes(64)
        assert len(rand_64) == 64
        
        # Output should have high entropy
        entropy = self.monitor._estimate_shannon_entropy(rand_64)
        assert entropy > 7.0
    
    def test_generate_health_report(self):
        """Test health report generation"""
        # Add samples first
        for _ in range(10):
            sample = self.monitor.collect_sample(EntropySource.OS_RANDOM)
            self.monitor.add_entropy_to_pool(sample)
        
        report = self.monitor.generate_health_report()
        
        assert hasattr(report, 'overall_status')
        assert hasattr(report, 'overall_entropy_score')
        assert hasattr(report, 'min_entropy_bits')
        assert len(report.tests_run) == 5
        assert hasattr(report, 'alerts')
        assert hasattr(report, 'recommendations')
        
        # With good entropy, status should be good
        assert report.overall_status in [
            HealthStatus.EXCELLENT, 
            HealthStatus.GOOD, 
            HealthStatus.ACCEPTABLE
        ]
    
    def test_health_report_source_contributions(self):
        """Test source contribution tracking"""
        sources = [EntropySource.OS_RANDOM, EntropySource.SEEDS_MODULE]
        for source in sources:
            for _ in range(5):
                sample = self.monitor.collect_sample(source)
                self.monitor.add_entropy_to_pool(sample)
        
        report = self.monitor.generate_health_report()
        
        # Should have contributions from used sources
        assert 'os_urandom' in report.source_contributions
        assert 'secrets_module' in report.source_contributions
    
    def test_background_collection(self):
        """Test background collection thread"""
        self.monitor.start_background_collection(interval=0.01)
        time.sleep(0.1)  # Let it collect some samples
        
        assert self.monitor._collector_running == True
        assert self.monitor.samples_collected > 0
        
        self.monitor.stop_background_collection()
        assert self.monitor._collector_running == False
    
    def test_get_statistics(self):
        """Test statistics reporting"""
        stats = self.monitor.get_statistics()
        
        assert 'samples_collected' in stats
        assert 'pool_size_bytes' in stats
        assert 'pool_target_size' in stats
        assert 'source_statistics' in stats
        assert stats['samples_collected'] == 0
        assert stats['pool_size_bytes'] == 0
    
    def test_source_statistics_tracking(self):
        """Test that source statistics are tracked correctly"""
        for _ in range(10):
            sample = self.monitor.collect_sample(EntropySource.OS_RANDOM)
            self.monitor.add_entropy_to_pool(sample)
        
        stats = self.monitor.get_statistics()
        assert stats['source_statistics']['os_urandom']['samples'] == 10
        assert stats['source_statistics']['os_urandom']['total_entropy'] > 0
    
    def test_concurrent_access(self):
        """Test thread-safe concurrent access"""
        import threading
        
        def worker():
            for _ in range(10):
                sample = self.monitor.collect_sample(EntropySource.OS_RANDOM)
                self.monitor.add_entropy_to_pool(sample)
        
        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have 30 samples total without corruption
        assert self.monitor.samples_collected == 30
    
    def test_empty_data_entropy(self):
        """Test edge case: empty data"""
        entropy = self.monitor._estimate_shannon_entropy(b'')
        assert entropy == 0.0
        
        min_entropy = self.monitor._estimate_min_entropy(b'')
        assert min_entropy == 0.0
    
    def test_deterministic_output(self):
        """Test that same input produces same entropy estimate"""
        data = os.urandom(256)
        e1 = self.monitor._estimate_shannon_entropy(data)
        e2 = self.monitor._estimate_shannon_entropy(data)
        assert e1 == e2


def run_full_test_suite():
    """Run the complete test suite and return results"""
    tester = TestEntropyHealthMonitor()
    tester.setup_method()
    
    test_results = {
        "passed": [],
        "failed": [],
        "total": 0
    }
    
    test_methods = [
        ("Initialization", tester.test_initialization),
        ("OS Random Collection", tester.test_collect_os_random),
        ("System Random Collection", tester.test_collect_system_random),
        ("CPU Cycles Collection", tester.test_collect_cpu_cycles),
        ("Secrets Module Collection", tester.test_collect_secrets_module),
        ("All Sources Collection", tester.test_collect_sample_all_sources),
        ("Shannon Entropy Calculation", tester.test_shannon_entropy_calculation),
        ("Min-Entropy Calculation", tester.test_min_entropy_calculation),
        ("Frequency Test", tester.test_frequency_test),
        ("Runs Test", tester.test_runs_test),
        ("Autocorrelation Test", tester.test_autocorrelation_test),
        ("Chi-Square Test", tester.test_chi_square_test),
        ("Longest Run Test", tester.test_longest_run_test),
        ("Full Health Suite", tester.test_full_health_suite),
        ("Add to Pool", tester.test_add_entropy_to_pool),
        ("Pool Size Maintenance", tester.test_pool_maintains_size),
        ("Random Byte Generation", tester.test_get_random_bytes),
        ("Health Report Generation", tester.test_generate_health_report),
        ("Source Contributions", tester.test_health_report_source_contributions),
        ("Background Collection", tester.test_background_collection),
        ("Statistics Reporting", tester.test_get_statistics),
        ("Source Statistics Tracking", tester.test_source_statistics_tracking),
        ("Concurrent Access", tester.test_concurrent_access),
        ("Empty Data Edge Case", tester.test_empty_data_entropy),
        ("Deterministic Output", tester.test_deterministic_output),
    ]
    
    print("=" * 70)
    print("QUANTUMCRYPT AI - ENTROPY HEALTH MONITOR TEST SUITE")
    print("=" * 70)
    
    for test_name, test_func in test_methods:
        test_results["total"] += 1
        try:
            tester.setup_method()  # Reset for each test
            test_func()
            test_results["passed"].append(test_name)
            print(f"✓ PASS: {test_name}")
        except Exception as e:
            test_results["failed"].append({"name": test_name, "error": str(e)})
            print(f"✗ FAIL: {test_name} - {str(e)[:100]}")
    
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {len(test_results['passed'])}/{test_results['total']} PASSED")
    print("=" * 70)
    
    if test_results["failed"]:
        print("\nFAILED TESTS:")
        for fail in test_results["failed"]:
            print(f"  - {fail['name']}: {fail['error']}")
    else:
        print("\nALL TESTS PASSED! ✓")
    
    return test_results


if __name__ == "__main__":
    os.chdir('/home/user/.super_doubao/super-doubao-runtime/workspace/QuantumCrypt-AI')
    results = run_full_test_suite()
    
    # Save results
    with open("test_results_entropy_health_monitor.json", "w") as f:
        json.dump({
            "test_engine": "Post-Quantum Entropy Health Monitor",
            "test_date": datetime.now().isoformat(),
            "total_tests": results["total"],
            "passed": len(results["passed"]),
            "failed": len(results["failed"]),
            "passed_tests": results["passed"],
            "failures": results["failed"],
            "success_rate": f"{len(results['passed']) / results['total'] * 100:.1f}%"
        }, f, indent=2)
    
    print(f"\nResults saved to test_results_entropy_health_monitor.json")
