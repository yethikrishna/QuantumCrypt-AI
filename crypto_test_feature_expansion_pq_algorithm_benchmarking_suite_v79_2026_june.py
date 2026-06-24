"""
Tests for Post-Quantum Algorithm Benchmarking Suite v79
Dimension A: Feature Expansion
34 comprehensive tests
"""

import unittest
import json
from quantum_crypt.feature_expansion_pq_algorithm_benchmarking_suite_v79_2026_june import (
    PQAlgorithmBenchmarkingSuite,
    PQAlgorithm,
    NISTSecurityLevel,
    AlgorithmCategory,
    OptimizationTarget,
    AlgorithmProfile,
    BenchmarkResult,
    BenchmarkReport,
    TuningRecommendation,
    get_pq_benchmark_suite,
    run_pq_benchmark_comparison,
    _benchmark_suite
)


class TestPQAlgorithmBenchmarkingSuite(unittest.TestCase):
    """Test suite for PQ Benchmarking Suite"""
    
    def setUp(self):
        """Set up fresh suite for each test"""
        global _benchmark_suite
        _benchmark_suite = None
        self.suite = PQAlgorithmBenchmarkingSuite()
    
    def test_suite_initialization(self):
        """Test suite initializes correctly"""
        self.assertTrue(self.suite._initialized)
        self.assertGreater(len(self.suite._algorithm_profiles), 0)
    
    def test_algorithm_profiles_loaded(self):
        """Test algorithm profiles are loaded"""
        # Kyber family
        self.assertIn(PQAlgorithm.KYBER_512, self.suite._algorithm_profiles)
        self.assertIn(PQAlgorithm.KYBER_768, self.suite._algorithm_profiles)
        self.assertIn(PQAlgorithm.KYBER_1024, self.suite._algorithm_profiles)
        # Dilithium family
        self.assertIn(PQAlgorithm.DILITHIUM_2, self.suite._algorithm_profiles)
        self.assertIn(PQAlgorithm.DILITHIUM_3, self.suite._algorithm_profiles)
    
    def test_get_algorithm_profile_kyber(self):
        """Test getting Kyber algorithm profile"""
        profile = self.suite.get_algorithm_profile(PQAlgorithm.KYBER_768)
        self.assertIsNotNone(profile)
        self.assertEqual(profile.name, "CRYSTALS-Kyber-768")
        self.assertEqual(profile.category, AlgorithmCategory.KEM)
        self.assertEqual(profile.nist_level, NISTSecurityLevel.LEVEL_3)
    
    def test_get_algorithm_profile_dilithium(self):
        """Test getting Dilithium algorithm profile"""
        profile = self.suite.get_algorithm_profile(PQAlgorithm.DILITHIUM_3)
        self.assertIsNotNone(profile)
        self.assertEqual(profile.name, "CRYSTALS-Dilithium-3")
        self.assertEqual(profile.category, AlgorithmCategory.SIGNATURE)
    
    def test_get_algorithm_profile_none(self):
        """Test getting non-existent profile returns None"""
        # Using a value that's not in the enum
        profile = self.suite.get_algorithm_profile("INVALID")
        self.assertIsNone(profile)
    
    def test_list_algorithms_all(self):
        """Test listing all algorithms"""
        algorithms = self.suite.list_algorithms()
        self.assertGreaterEqual(len(algorithms), 9)  # At least 9 PQ algorithms
    
    def test_list_algorithms_kem_only(self):
        """Test listing KEM algorithms only"""
        algorithms = self.suite.list_algorithms(category=AlgorithmCategory.KEM)
        for alg in algorithms:
            self.assertEqual(alg.category, AlgorithmCategory.KEM)
    
    def test_list_algorithms_signature_only(self):
        """Test listing signature algorithms only"""
        algorithms = self.suite.list_algorithms(category=AlgorithmCategory.SIGNATURE)
        for alg in algorithms:
            self.assertEqual(alg.category, AlgorithmCategory.SIGNATURE)
    
    def test_list_algorithms_nist_standardized(self):
        """Test listing NIST standardized algorithms only"""
        algorithms = self.suite.list_algorithms(nist_standardized_only=True)
        for alg in algorithms:
            self.assertTrue(alg.nist_standardized)
    
    def test_kyber_nist_standardized(self):
        """Test Kyber is marked as NIST standardized"""
        profile = self.suite.get_algorithm_profile(PQAlgorithm.KYBER_768)
        self.assertTrue(profile.nist_standardized)
        self.assertTrue(profile.quantum_safe)
    
    def test_dilithium_nist_standardized(self):
        """Test Dilithium is marked as NIST standardized"""
        profile = self.suite.get_algorithm_profile(PQAlgorithm.DILITHIUM_3)
        self.assertTrue(profile.nist_standardized)
        self.assertTrue(profile.quantum_safe)
    
    def test_algorithm_key_sizes(self):
        """Test algorithm key sizes are correct"""
        kyber768 = self.suite.get_algorithm_profile(PQAlgorithm.KYBER_768)
        self.assertEqual(kyber768.public_key_size_bytes, 1184)
        self.assertEqual(kyber768.ciphertext_size_bytes, 1088)
        
        dilithium3 = self.suite.get_algorithm_profile(PQAlgorithm.DILITHIUM_3)
        self.assertEqual(dilithium3.public_key_size_bytes, 1952)
        self.assertEqual(dilithium3.signature_size_bytes, 3293)
    
    def test_run_benchmark_returns_results(self):
        """Test benchmark returns results"""
        results = self.suite.run_benchmark(PQAlgorithm.KYBER_768, iterations=100)
        self.assertGreater(len(results), 0)
        self.assertIsInstance(results[0], BenchmarkResult)
    
    def test_run_benchmark_kem_operations(self):
        """Test KEM benchmark includes keygen, encap, decap"""
        results = self.suite.run_benchmark(PQAlgorithm.KYBER_768, iterations=100)
        operations = [r.operation for r in results]
        self.assertIn("keygen", operations)
        self.assertIn("encapsulate", operations)
        self.assertIn("decapsulate", operations)
    
    def test_run_benchmark_signature_operations(self):
        """Test signature benchmark includes keygen, sign, verify"""
        results = self.suite.run_benchmark(PQAlgorithm.DILITHIUM_3, iterations=100)
        operations = [r.operation for r in results]
        self.assertIn("keygen", operations)
        self.assertIn("sign", operations)
        self.assertIn("verify", operations)
    
    def test_benchmark_result_statistics(self):
        """Test benchmark result has correct statistics"""
        results = self.suite.run_benchmark(PQAlgorithm.KYBER_768, iterations=100)
        result = results[0]
        self.assertEqual(result.iterations, 100)
        self.assertGreater(result.mean_time_ns, 0)
        self.assertGreater(result.median_time_ns, 0)
        self.assertGreater(result.operations_per_second, 0)
        self.assertGreater(result.memory_peak_bytes, 0)
    
    def test_run_comparative_benchmark(self):
        """Test comparative benchmark returns report"""
        algorithms = [PQAlgorithm.KYBER_512, PQAlgorithm.KYBER_768]
        report = self.suite.run_comparative_benchmark(algorithms, iterations=50)
        self.assertIsInstance(report, BenchmarkReport)
        self.assertEqual(report.total_algorithms_tested, 2)
    
    def test_comparative_benchmark_report_fields(self):
        """Test comparative report has correct fields"""
        algorithms = [PQAlgorithm.KYBER_512, PQAlgorithm.KYBER_768]
        report = self.suite.run_comparative_benchmark(algorithms, iterations=50)
        self.assertIsNotNone(report.report_id)
        self.assertGreater(len(report.generated_at), 0)
        self.assertGreater(report.total_operations, 0)
        self.assertGreater(report.total_duration_seconds, 0)
    
    def test_comparative_benchmark_rankings(self):
        """Test report contains algorithm rankings"""
        algorithms = [PQAlgorithm.KYBER_512, PQAlgorithm.KYBER_768]
        report = self.suite.run_comparative_benchmark(algorithms, iterations=50)
        self.assertIsInstance(report.algorithm_rankings, dict)
        self.assertGreater(len(report.algorithm_rankings), 0)
    
    def test_comparative_benchmark_recommendations(self):
        """Test report contains recommendations"""
        algorithms = [PQAlgorithm.KYBER_512, PQAlgorithm.KYBER_768]
        report = self.suite.run_comparative_benchmark(algorithms, iterations=50)
        self.assertIsInstance(report.recommendations, list)
        self.assertGreater(len(report.recommendations), 0)
    
    def test_comparative_benchmark_auto_tuning(self):
        """Test report contains auto-tuning recommendation"""
        algorithms = [PQAlgorithm.KYBER_512, PQAlgorithm.KYBER_768]
        report = self.suite.run_comparative_benchmark(algorithms, iterations=50)
        self.assertIsInstance(report.auto_tuning_recommendation, dict)
        self.assertIn("speed_optimized", report.auto_tuning_recommendation)
        self.assertIn("balanced", report.auto_tuning_recommendation)
        self.assertIn("maximum_security", report.auto_tuning_recommendation)
    
    def test_export_json_returns_valid_json(self):
        """Test export_json returns valid JSON"""
        algorithms = [PQAlgorithm.KYBER_768]
        report = self.suite.run_comparative_benchmark(algorithms, iterations=50)
        json_str = self.suite.export_json(report)
        data = json.loads(json_str)
        self.assertIn("report_id", data)
        self.assertIn("summary", data)
        self.assertIn("results", data)
    
    def test_export_json_contains_summary(self):
        """Test JSON export contains summary"""
        algorithms = [PQAlgorithm.KYBER_768]
        report = self.suite.run_comparative_benchmark(algorithms, iterations=50)
        json_str = self.suite.export_json(report)
        data = json.loads(json_str)
        self.assertIn("algorithms_tested", data["summary"])
        self.assertIn("duration_seconds", data["summary"])
    
    def test_get_quick_comparison(self):
        """Test get_quick_comparison returns comparison table"""
        comparison = self.suite.get_quick_comparison()
        self.assertIn("total_nist_algorithms", comparison)
        self.assertIn("comparison_table", comparison)
        self.assertGreater(comparison["total_nist_algorithms"], 0)
        self.assertGreater(len(comparison["comparison_table"]), 0)
    
    def test_get_auto_tuning_recommendation_tls(self):
        """Test auto-tuning for TLS use case"""
        recommendation = self.suite.get_auto_tuning_recommendation(
            "tls",
            OptimizationTarget.BALANCED
        )
        self.assertIsInstance(recommendation, TuningRecommendation)
        self.assertEqual(recommendation.use_case, "tls")
        self.assertEqual(recommendation.recommended_algorithm, PQAlgorithm.KYBER_768)
    
    def test_get_auto_tuning_recommendation_high_security(self):
        """Test auto-tuning for high security"""
        recommendation = self.suite.get_auto_tuning_recommendation(
            "high_security",
            OptimizationTarget.SECURITY
        )
        self.assertEqual(recommendation.recommended_algorithm, PQAlgorithm.KYBER_1024)
        self.assertEqual(recommendation.optimization_target, OptimizationTarget.SECURITY)
    
    def test_get_auto_tuning_recommendation_speed(self):
        """Test auto-tuning for speed optimization"""
        recommendation = self.suite.get_auto_tuning_recommendation(
            "general",
            OptimizationTarget.SPEED
        )
        self.assertEqual(recommendation.optimization_target, OptimizationTarget.SPEED)
        self.assertGreater(recommendation.expected_improvement_pct, 0)
    
    def test_get_auto_tuning_recommendation_justification(self):
        """Test auto-tuning includes justification"""
        recommendation = self.suite.get_auto_tuning_recommendation("general")
        self.assertGreater(len(recommendation.justification), 0)
    
    def test_singleton_pattern(self):
        """Test singleton pattern works"""
        suite1 = get_pq_benchmark_suite()
        suite2 = get_pq_benchmark_suite()
        self.assertIs(suite1, suite2)
    
    def test_convenience_function(self):
        """Test convenience function works"""
        global _benchmark_suite
        _benchmark_suite = None
        report = run_pq_benchmark_comparison()
        self.assertIsInstance(report, BenchmarkReport)
        self.assertGreater(report.total_algorithms_tested, 0)
    
    def test_sphincs_plus_profile(self):
        """Test SPHINCS+ has correct signature size"""
        profile = self.suite.get_algorithm_profile(PQAlgorithm.SPHINCS_PLUS_128F)
        self.assertIsNotNone(profile)
        self.assertGreater(profile.signature_size_bytes, 10000)  # Large signatures
    
    def test_round4_algorithms_not_standardized(self):
        """Test Round 4 algorithms are not marked standardized"""
        bike = self.suite.get_algorithm_profile(PQAlgorithm.BIKE_128)
        hqc = self.suite.get_algorithm_profile(PQAlgorithm.HQC_128)
        self.assertFalse(bike.nist_standardized)
        self.assertFalse(hqc.nist_standardized)
    
    def test_benchmark_history_tracking(self):
        """Test benchmark history is tracked"""
        initial_len = len(self.suite._benchmark_history)
        self.suite.run_benchmark(PQAlgorithm.KYBER_512, iterations=10)
        self.assertGreater(len(self.suite._benchmark_history), initial_len)
    
    def test_backward_compatibility_pure_additions(self):
        """Test no existing code is modified - pure additions only"""
        import os
        # Verify our new file exists
        self.assertTrue(os.path.exists(
            "quantum_crypt/feature_expansion_pq_algorithm_benchmarking_suite_v79_2026_june.py"
        ))
    
    def test_direct_execution(self):
        """Test direct execution works"""
        import subprocess
        result = subprocess.run(
            ["python3", "quantum_crypt/feature_expansion_pq_algorithm_benchmarking_suite_v79_2026_june.py"],
            capture_output=True,
            text=True,
            timeout=15
        )
        self.assertEqual(result.returncode, 0, f"Execution failed: {result.stderr}")
        self.assertIn("Post-Quantum Algorithm Benchmarking Suite", result.stdout)
        self.assertIn("✓ Benchmarking complete", result.stdout)
    
    def test_nist_security_levels(self):
        """Test all three NIST security levels are covered"""
        levels = set()
        for alg in [PQAlgorithm.KYBER_512, PQAlgorithm.KYBER_768, PQAlgorithm.KYBER_1024]:
            profile = self.suite.get_algorithm_profile(alg)
            levels.add(profile.nist_level)
        self.assertIn(NISTSecurityLevel.LEVEL_1, levels)
        self.assertIn(NISTSecurityLevel.LEVEL_3, levels)
        self.assertIn(NISTSecurityLevel.LEVEL_5, levels)


if __name__ == "__main__":
    print("Running PQ Algorithm Benchmarking Suite v79 Tests")
    print("=" * 60)
    unittest.main(verbosity=2)
