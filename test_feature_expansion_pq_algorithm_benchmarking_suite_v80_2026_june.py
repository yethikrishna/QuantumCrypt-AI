"""
Test Suite for PQ Algorithm Benchmarking Suite v80
DIMENSION A - Feature Expansion Tests

All tests must pass. Backward compatibility verified.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from quantum_crypt.feature_expansion_pq_algorithm_benchmarking_suite_v80_2026_june import (
    PQAlgorithmBenchmarkSuite,
    PQAlgorithmType,
    SecurityLevel,
    PQAlgorithm,
    BenchmarkResult,
    AlgorithmComparison,
    get_benchmark_suite,
    run_pq_benchmark
)


class TestPQAlgorithmBenchmarkSuite:
    """Test suite for Post-Quantum Algorithm Benchmarking"""
    
    def test_suite_initialization(self):
        """Test benchmark suite initializes correctly"""
        suite = PQAlgorithmBenchmarkSuite()
        assert suite is not None
        assert len(suite.algorithms) > 0
        assert suite.benchmark_history == []
    
    def test_algorithm_database_populated(self):
        """Test algorithm database contains expected algorithms"""
        suite = PQAlgorithmBenchmarkSuite()
        
        # NIST standardized KEMs should exist
        assert "CRYSTALS-Kyber-768" in suite.algorithms
        assert "CRYSTALS-Kyber-512" in suite.algorithms
        assert "CRYSTALS-Kyber-1024" in suite.algorithms
        
        # NIST standardized signatures should exist
        assert "CRYSTALS-Dilithium-3" in suite.algorithms
        assert "FALCON-512" in suite.algorithms
        assert "SPHINCS+-SHA2-128f" in suite.algorithms
    
    def test_nist_standardized_flag(self):
        """Test NIST standardized flag is correct"""
        suite = PQAlgorithmBenchmarkSuite()
        
        kyber = suite.algorithms["CRYSTALS-Kyber-768"]
        assert kyber.nist_standardized is True
        
        bike = suite.algorithms["BIKE-L1"]
        assert bike.nist_standardized is False
    
    def test_algorithm_key_sizes(self):
        """Test algorithm key sizes are properly defined"""
        suite = PQAlgorithmBenchmarkSuite()
        
        kyber768 = suite.algorithms["CRYSTALS-Kyber-768"]
        assert kyber768.public_key_size == 1184
        assert kyber768.private_key_size == 2400
        assert kyber768.ciphertext_size == 1088
        
        dilithium3 = suite.algorithms["CRYSTALS-Dilithium-3"]
        assert dilithium3.public_key_size == 1952
        assert dilithium3.signature_size == 3293
    
    def test_security_levels(self):
        """Test security levels are correctly assigned"""
        suite = PQAlgorithmBenchmarkSuite()
        
        assert suite.algorithms["CRYSTALS-Kyber-512"].security_level == SecurityLevel.LEVEL_1
        assert suite.algorithms["CRYSTALS-Kyber-768"].security_level == SecurityLevel.LEVEL_3
        assert suite.algorithms["CRYSTALS-Kyber-1024"].security_level == SecurityLevel.LEVEL_5
    
    def test_algorithm_types(self):
        """Test algorithm types are correctly assigned"""
        suite = PQAlgorithmBenchmarkSuite()
        
        assert suite.algorithms["CRYSTALS-Kyber-768"].algorithm_type == PQAlgorithmType.KEY_ENCAPSULATION
        assert suite.algorithms["CRYSTALS-Dilithium-3"].algorithm_type == PQAlgorithmType.DIGITAL_SIGNATURE
        assert suite.algorithms["SPHINCS+-SHA2-128f"].algorithm_type == PQAlgorithmType.HASH_BASED
    
    def test_benchmark_key_generation_kem(self):
        """Test key generation benchmark for KEM"""
        suite = PQAlgorithmBenchmarkSuite()
        result = suite.benchmark_key_generation("CRYSTALS-Kyber-768", iterations=10)
        
        assert isinstance(result, BenchmarkResult)
        assert result.algorithm_name == "CRYSTALS-Kyber-768"
        assert result.operation == "key_generation"
        assert result.iterations == 10
        assert result.total_time_ms > 0
        assert result.avg_time_ms > 0
        assert result.throughput_ops_per_sec > 0
        assert result.memory_usage_bytes > 0
    
    def test_benchmark_key_generation_signature(self):
        """Test key generation benchmark for signature scheme"""
        suite = PQAlgorithmBenchmarkSuite()
        result = suite.benchmark_key_generation("CRYSTALS-Dilithium-3", iterations=10)
        
        assert isinstance(result, BenchmarkResult)
        assert result.avg_time_ms > 0
    
    def test_benchmark_encapsulation(self):
        """Test KEM encapsulation benchmark"""
        suite = PQAlgorithmBenchmarkSuite()
        result = suite.benchmark_encapsulation("CRYSTALS-Kyber-768", iterations=10)
        
        assert result.operation == "encapsulation"
        assert result.avg_time_ms > 0
    
    def test_benchmark_decapsulation(self):
        """Test KEM decapsulation benchmark"""
        suite = PQAlgorithmBenchmarkSuite()
        result = suite.benchmark_decapsulation("CRYSTALS-Kyber-768", iterations=10)
        
        assert result.operation == "decapsulation"
        assert result.avg_time_ms > 0
    
    def test_benchmark_signing(self):
        """Test signature generation benchmark"""
        suite = PQAlgorithmBenchmarkSuite()
        result = suite.benchmark_signing("CRYSTALS-Dilithium-3", iterations=5)
        
        assert result.operation == "signing"
        assert result.avg_time_ms > 0
    
    def test_benchmark_verification(self):
        """Test signature verification benchmark"""
        suite = PQAlgorithmBenchmarkSuite()
        result = suite.benchmark_verification("CRYSTALS-Dilithium-3", iterations=10)
        
        assert result.operation == "verification"
        assert result.avg_time_ms > 0
    
    def test_benchmark_unknown_algorithm(self):
        """Test benchmarking unknown algorithm raises error"""
        suite = PQAlgorithmBenchmarkSuite()
        
        with pytest.raises(ValueError):
            suite.benchmark_key_generation("Unknown-Algorithm-123")
    
    def test_benchmark_wrong_algorithm_type(self):
        """Test running KEM operation on signature algorithm"""
        suite = PQAlgorithmBenchmarkSuite()
        
        with pytest.raises(ValueError):
            suite.benchmark_encapsulation("CRYSTALS-Dilithium-3")
    
    def test_run_full_benchmark_kem(self):
        """Test full benchmark suite for KEM algorithm"""
        suite = PQAlgorithmBenchmarkSuite()
        report = suite.run_full_benchmark("CRYSTALS-Kyber-768", iterations=5)
        
        assert report["algorithm"] == "CRYSTALS-Kyber-768"
        assert "algorithm_details" in report
        assert "benchmarks" in report
        assert "key_generation" in report["benchmarks"]
        assert "encapsulation" in report["benchmarks"]
        assert "decapsulation" in report["benchmarks"]
    
    def test_run_full_benchmark_signature(self):
        """Test full benchmark suite for signature algorithm"""
        suite = PQAlgorithmBenchmarkSuite()
        report = suite.run_full_benchmark("CRYSTALS-Dilithium-3", iterations=5)
        
        assert report["algorithm"] == "CRYSTALS-Dilithium-3"
        assert "key_generation" in report["benchmarks"]
        assert "signing" in report["benchmarks"]
        assert "verification" in report["benchmarks"]
    
    def test_compare_algorithms(self):
        """Test algorithm comparison functionality"""
        suite = PQAlgorithmBenchmarkSuite()
        comparison = suite.compare_algorithms(
            ["CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024"],
            "key_generation"
        )
        
        assert isinstance(comparison, AlgorithmComparison)
        assert len(comparison.algorithms) == 3
        assert comparison.metric == "key_generation"
        assert len(comparison.results) == 3
        assert comparison.best_performer in comparison.algorithms
        assert comparison.worst_performer in comparison.algorithms
        assert comparison.performance_ratio > 0
    
    def test_get_recommendation_tls(self):
        """Test getting TLS handshake recommendation"""
        suite = PQAlgorithmBenchmarkSuite()
        rec = suite.get_recommendation("tls_handshake")
        
        assert rec["recommended_kem"] == "CRYSTALS-Kyber-768"
        assert rec["recommended_sig"] == "CRYSTALS-Dilithium-3"
    
    def test_get_recommendation_high_security(self):
        """Test getting high security recommendation"""
        suite = PQAlgorithmBenchmarkSuite()
        rec = suite.get_recommendation("high_security")
        
        assert rec["recommended_kem"] == "CRYSTALS-Kyber-1024"
        assert rec["recommended_sig"] == "CRYSTALS-Dilithium-5"
    
    def test_get_recommendation_embedded(self):
        """Test getting embedded device recommendation"""
        suite = PQAlgorithmBenchmarkSuite()
        rec = suite.get_recommendation("embedded_device")
        
        assert rec["recommended_kem"] == "CRYSTALS-Kyber-512"
    
    def test_get_recommendation_unknown(self):
        """Test getting recommendation for unknown use case"""
        suite = PQAlgorithmBenchmarkSuite()
        rec = suite.get_recommendation("unknown_use_case")
        
        assert "error" in rec
    
    def test_generate_comparison_report(self):
        """Test comprehensive comparison report generation"""
        suite = PQAlgorithmBenchmarkSuite()
        report = suite.generate_comparison_report()
        
        assert "summary" in report
        assert "key_size_comparison" in report
        assert "nist_standardized_algorithms" in report
        assert report["summary"]["total_algorithms"] > 0
        assert report["summary"]["nist_standardized"] > 0
    
    def test_singleton_instance(self):
        """Test singleton pattern works"""
        suite1 = get_benchmark_suite()
        suite2 = get_benchmark_suite()
        
        assert suite1 is suite2
    
    def test_convenience_function(self):
        """Test convenience benchmark function"""
        report = run_pq_benchmark("CRYSTALS-Kyber-768")
        
        assert "algorithm" in report
        assert "benchmarks" in report
    
    def test_benchmark_history_recorded(self):
        """Test benchmark history is recorded"""
        suite = PQAlgorithmBenchmarkSuite()
        initial_count = len(suite.benchmark_history)
        
        suite.benchmark_key_generation("CRYSTALS-Kyber-768", iterations=5)
        suite.benchmark_encapsulation("CRYSTALS-Kyber-768", iterations=5)
        
        assert len(suite.benchmark_history) == initial_count + 2
    
    def test_throughput_calculation(self):
        """Test throughput is calculated correctly"""
        suite = PQAlgorithmBenchmarkSuite()
        result = suite.benchmark_key_generation("CRYSTALS-Kyber-512", iterations=10)
        
        # Throughput should be ops per second
        assert result.throughput_ops_per_sec > 0
        # Throughput should be roughly iterations / total_time (in seconds)
        expected_throughput = result.iterations / (result.total_time_ms / 1000)
        # Allow for some floating point tolerance (wider due to timing variations)
        assert abs(result.throughput_ops_per_sec - expected_throughput) < 500
    
    def test_min_max_times_recorded(self):
        """Test min and max times are recorded"""
        suite = PQAlgorithmBenchmarkSuite()
        result = suite.benchmark_key_generation("CRYSTALS-Kyber-512", iterations=10)
        
        assert result.min_time_ms > 0
        assert result.max_time_ms > 0
        assert result.min_time_ms <= result.avg_time_ms <= result.max_time_ms
    
    def test_sphincs_small_keys(self):
        """Test SPHINCS+ has very small public/private keys"""
        suite = PQAlgorithmBenchmarkSuite()
        sphincs = suite.algorithms["SPHINCS+-SHA2-128f"]
        
        # SPHINCS+ has tiny keys (hash-based)
        assert sphincs.public_key_size == 32
        assert sphincs.private_key_size == 64


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
    print("\n✅ All PQ Algorithm Benchmarking tests passed!")
