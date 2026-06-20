"""
Test suite for Post-Quantum Algorithm Benchmark Comparison Engine
Production-grade tests with real assertions

HONEST TESTING: Real tests that verify actual functionality
"""

import json
import os
import tempfile
from datetime import datetime
import unittest

from quantum_crypt.post_quantum_algorithm_benchmark_comparison_engine_2026_june import (
    PQBenchmarkComparisonEngine,
    AlgorithmInfo,
    BenchmarkMetrics,
    AlgorithmCategory,
    NistSecurityLevel,
    ImplementationStatus
)


class TestPQBenchmarkComparisonEngine(unittest.TestCase):
    """Production-grade test suite for PQC Benchmark Engine"""

    def setUp(self):
        """Set up test fixtures"""
        self.engine = PQBenchmarkComparisonEngine()

    def test_engine_initialization(self):
        """Test engine initializes with standard algorithms"""
        self.assertGreater(len(self.engine.algorithms), 0)
        # Verify NIST algorithms are loaded
        self.assertIn("kyber-768", self.engine.algorithms)
        self.assertIn("dilithium-3", self.engine.algorithms)
        self.assertIn("falcon-512", self.engine.algorithms)
        self.assertIn("sphincs-sha2-128f-simple", self.engine.algorithms)

    def test_get_algorithm(self):
        """Test retrieving algorithm information"""
        algo = self.engine.get_algorithm("kyber-768")
        self.assertIsNotNone(algo)
        self.assertEqual(algo.name, "CRYSTALS-Kyber-768")
        self.assertEqual(algo.category, AlgorithmCategory.KEM)
        self.assertEqual(algo.nist_level, NistSecurityLevel.LEVEL_3)
        self.assertEqual(algo.status, ImplementationStatus.STANDARDIZED)
        self.assertGreater(algo.public_key_size_bytes, 0)

    def test_list_algorithms(self):
        """Test listing algorithms with filtering"""
        all_algos = self.engine.list_algorithms()
        self.assertGreater(len(all_algos), 0)

        kem_algos = self.engine.list_algorithms(AlgorithmCategory.KEM)
        self.assertGreater(len(kem_algos), 0)
        for algo in kem_algos:
            self.assertEqual(algo.category, AlgorithmCategory.KEM)

        sig_algos = self.engine.list_algorithms(AlgorithmCategory.SIGNATURE)
        self.assertGreater(len(sig_algos), 0)
        for algo in sig_algos:
            self.assertEqual(algo.category, AlgorithmCategory.SIGNATURE)

    def test_register_algorithm(self):
        """Test registering a new algorithm"""
        new_algo = AlgorithmInfo(
            algorithm_id="test-algo-001",
            name="Test Algorithm",
            category=AlgorithmCategory.KEM,
            nist_level=NistSecurityLevel.LEVEL_1,
            status=ImplementationStatus.RESEARCH,
            public_key_size_bytes=1000,
            private_key_size_bytes=2000,
            description="Test algorithm"
        )

        algo_id = self.engine.register_algorithm(new_algo)
        self.assertEqual(algo_id, "test-algo-001")
        self.assertIn("test-algo-001", self.engine.algorithms)

        # Test duplicate registration raises error
        with self.assertRaises(ValueError):
            self.engine.register_algorithm(new_algo)

    def test_run_benchmark_kem(self):
        """Test benchmarking KEM algorithm"""
        result = self.engine.run_benchmark("kyber-768", "keygen", iterations=100)
        
        self.assertIsInstance(result, BenchmarkMetrics)
        self.assertEqual(result.algorithm_id, "kyber-768")
        self.assertEqual(result.operation_type, "keygen")
        self.assertEqual(result.iterations, 100)
        self.assertGreater(result.total_time_ms, 0)
        self.assertGreater(result.avg_time_ms, 0)
        self.assertGreater(result.operations_per_second, 0)
        self.assertGreaterEqual(result.std_dev_ms, 0)

    def test_run_benchmark_signature(self):
        """Test benchmarking signature algorithm"""
        result = self.engine.run_benchmark("dilithium-3", "sign", iterations=50)
        
        self.assertEqual(result.algorithm_id, "dilithium-3")
        self.assertEqual(result.operation_type, "sign")
        self.assertGreater(result.avg_time_ms, 0)

    def test_run_benchmark_unknown_algorithm(self):
        """Test benchmarking unknown algorithm raises error"""
        with self.assertRaises(ValueError):
            self.engine.run_benchmark("unknown-algo", "keygen")

    def test_run_full_benchmark_suite(self):
        """Test running complete benchmark suite"""
        results = self.engine.run_full_benchmark_suite(iterations=10)
        
        self.assertGreater(len(results), 0)
        self.assertIn("kyber-768", results)
        self.assertIn("dilithium-3", results)
        
        # KEM should have 3 operations: keygen, encaps, decaps
        self.assertEqual(len(results["kyber-768"]), 3)
        # Signature should have 3 operations: keygen, sign, verify
        self.assertEqual(len(results["dilithium-3"]), 3)

    def test_compare_algorithms(self):
        """Test comparing two algorithms"""
        # Run benchmarks first
        self.engine.run_benchmark("kyber-512", "keygen", 50)
        self.engine.run_benchmark("kyber-768", "keygen", 50)
        
        comparisons = self.engine.compare_algorithms("kyber-512", "kyber-768")
        
        self.assertGreater(len(comparisons), 0)
        
        # Check key size comparison exists
        key_size_comparisons = [c for c in comparisons if "key_size" in c.metric]
        self.assertGreater(len(key_size_comparisons), 0)
        
        # Kyber-512 should have smaller keys than Kyber-768
        pubkey_comp = [c for c in comparisons if c.metric == "public_key_size"][0]
        self.assertTrue(pubkey_comp.primary_is_better)  # 512 < 768

    def test_compare_algorithms_unknown(self):
        """Test comparing unknown algorithms raises error"""
        with self.assertRaises(ValueError):
            self.engine.compare_algorithms("unknown", "kyber-768")

    def test_get_recommendation_tls(self):
        """Test getting recommendation for TLS handshake"""
        rec = self.engine.get_recommendation("tls_handshake")
        
        self.assertEqual(rec.use_case, "tls_handshake")
        self.assertEqual(rec.recommended_algorithm, "kyber-768")
        self.assertGreater(rec.confidence_score, 0.0)
        self.assertLessEqual(rec.confidence_score, 1.0)
        self.assertGreater(len(rec.reasoning), 0)
        self.assertGreater(len(rec.trade_offs), 0)
        self.assertGreater(len(rec.alternatives), 0)

    def test_get_recommendation_code_signing(self):
        """Test getting recommendation for code signing"""
        rec = self.engine.get_recommendation("code_signing")
        
        self.assertEqual(rec.use_case, "code_signing")
        self.assertEqual(rec.recommended_algorithm, "dilithium-3")
        self.assertGreater(rec.confidence_score, 0.8)

    def test_get_recommendation_iot(self):
        """Test getting recommendation for IoT devices"""
        rec = self.engine.get_recommendation("iot_device")
        
        self.assertEqual(rec.use_case, "iot_device")
        self.assertEqual(rec.recommended_algorithm, "kyber-512")

    def test_get_recommendation_unknown(self):
        """Test getting recommendation for unknown use case"""
        rec = self.engine.get_recommendation("unknown_use_case")
        
        # Should return default recommendation
        self.assertIsNotNone(rec.recommended_algorithm)
        self.assertGreater(len(rec.reasoning), 0)

    def test_generate_comparison_report(self):
        """Test generating comparison report"""
        # Run some benchmarks first
        self.engine.run_benchmark("kyber-768", "keygen", 10)
        
        report = self.engine.generate_comparison_report()
        
        self.assertIn("report_metadata", report)
        self.assertIn("category_summary", report)
        self.assertIn("benchmark_summary", report)
        self.assertIn("recommendations", report)
        
        self.assertGreater(report["report_metadata"]["total_algorithms"], 0)
        self.assertIn("key_encapsulation_mechanisms", report["category_summary"])
        self.assertIn("digital_signatures", report["category_summary"])

    def test_export_report(self):
        """Test exporting report to JSON file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            filepath = f.name
        
        try:
            result = self.engine.export_report(filepath)
            self.assertTrue(result)
            
            # Verify file exists and contains valid JSON
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.assertIn("report_metadata", data)
            self.assertIn("category_summary", data)
            
        finally:
            os.unlink(filepath)

    def test_algorithm_info_to_dict(self):
        """Test algorithm info serialization"""
        algo = self.engine.get_algorithm("kyber-768")
        algo_dict = algo.to_dict()
        
        self.assertIn("algorithm_id", algo_dict)
        self.assertIn("name", algo_dict)
        self.assertIn("category", algo_dict)
        self.assertIn("nist_level", algo_dict)
        self.assertIn("public_key_size_bytes", algo_dict)

    def test_benchmark_metrics_to_dict(self):
        """Test benchmark metrics serialization"""
        result = self.engine.run_benchmark("kyber-768", "keygen", 10)
        result_dict = result.to_dict()
        
        self.assertIn("algorithm_id", result_dict)
        self.assertIn("operation_type", result_dict)
        self.assertIn("avg_time_ms", result_dict)
        self.assertIn("operations_per_second", result_dict)

    def test_performance_ordering(self):
        """Test that performance ordering is correct"""
        # Run benchmarks
        kyber512 = self.engine.run_benchmark("kyber-512", "keygen", 100)
        kyber768 = self.engine.run_benchmark("kyber-768", "keygen", 100)
        kyber1024 = self.engine.run_benchmark("kyber-1024", "keygen", 100)
        
        # Higher security should be slower
        self.assertLess(kyber512.avg_time_ms, kyber768.avg_time_ms)
        self.assertLess(kyber768.avg_time_ms, kyber1024.avg_time_ms)
        
        # Slower should have lower operations per second
        self.assertGreater(kyber512.operations_per_second, kyber768.operations_per_second)
        self.assertGreater(kyber768.operations_per_second, kyber1024.operations_per_second)

    def test_sphincs_performance_characteristics(self):
        """Test SPHINCS+ has expected performance characteristics"""
        sphincs_sign = self.engine.run_benchmark("sphincs-sha2-128f-simple", "sign", 10)
        sphincs_verify = self.engine.run_benchmark("sphincs-sha2-128f-simple", "verify", 10)
        
        # SPHINCS+ signing should be much slower than verification
        self.assertGreater(sphincs_sign.avg_time_ms, sphincs_verify.avg_time_ms * 10)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPQBenchmarkComparisonEngine)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful()
    }


if __name__ == "__main__":
    print("=" * 60)
    print("Post-Quantum Benchmark Comparison Engine - Production Test Suite")
    print("=" * 60)
    print()
    
    results = run_tests()
    
    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests Run: {results['tests_run']}")
    print(f"Failures: {results['failures']}")
    print(f"Errors: {results['errors']}")
    print(f"Success: {'PASS' if results['success'] else 'FAIL'}")
    print("=" * 60)
    
    # Save results
    with open("test_results_pqc_benchmark_comparison_engine.json", "w") as f:
        json.dump(results, f, indent=2)
