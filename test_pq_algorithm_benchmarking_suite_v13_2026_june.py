"""
Tests for Post-Quantum Algorithm Benchmarking Suite v13 - QuantumCrypt-AI
Dimension A - Feature Expansion
"""

import pytest
import threading
import tempfile
import os
import json
from datetime import datetime
from quantum_crypt.pq_algorithm_benchmarking_suite_v13_2026_june import (
    PQBenchmarkSuite,
    AlgorithmImplementation,
    BenchmarkResult,
    AlgorithmCategory,
    NISTSecurityLevel,
    BenchmarkMetric,
    ComparisonRank
)


class TestAlgorithmImplementation:
    """Test AlgorithmImplementation data class"""

    def test_algorithm_creation(self):
        """Test basic algorithm creation"""
        alg = AlgorithmImplementation(
            name="Test-KEM-128",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            nist_level=NISTSecurityLevel.LEVEL_1,
            version="1.0.0",
            description="Test KEM algorithm",
            is_standardized=True
        )
        assert alg.name == "Test-KEM-128"
        assert alg.category == AlgorithmCategory.KEY_ENCAPSULATION
        assert alg.nist_level == NISTSecurityLevel.LEVEL_1
        assert alg.is_standardized is True


class TestPQBenchmarkSuiteBasics:
    """Test basic PQBenchmarkSuite functionality"""

    def test_suite_initialization(self):
        """Test suite initializes with standard algorithms"""
        suite = PQBenchmarkSuite()
        summary = suite.get_summary()
        assert summary["total_algorithms"] > 0
        assert summary["benchmarked_algorithms"] == 0

    def test_standard_algorithms_registered(self):
        """Test NIST standard algorithms are pre-registered"""
        suite = PQBenchmarkSuite()
        algs = suite.get_algorithms()
        
        # Kyber KEMs should be present
        assert "CRYSTALS-Kyber-512" in algs
        assert "CRYSTALS-Kyber-768" in algs
        assert "CRYSTALS-Kyber-1024" in algs
        
        # Dilithium signatures should be present
        assert "CRYSTALS-Dilithium-2" in algs
        assert "CRYSTALS-Dilithium-3" in algs
        assert "CRYSTALS-Dilithium-5" in algs
        
        # Classical algorithms for comparison
        assert "RSA-2048" in algs
        assert "ECC-P256" in algs

    def test_register_custom_algorithm(self):
        """Test registering custom algorithm"""
        suite = PQBenchmarkSuite()
        initial = suite.get_summary()["total_algorithms"]
        
        custom_alg = AlgorithmImplementation(
            name="CUSTOM-PQ-ALG",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            nist_level=NISTSecurityLevel.LEVEL_3,
            description="Custom PQ algorithm"
        )
        suite.register_algorithm(custom_alg)
        
        summary = suite.get_summary()
        assert summary["total_algorithms"] == initial + 1
        assert "CUSTOM-PQ-ALG" in suite.get_algorithms()

    def test_filter_algorithms_by_category(self):
        """Test filtering algorithms by category"""
        suite = PQBenchmarkSuite()
        
        kems = suite.get_algorithms(category=AlgorithmCategory.KEY_ENCAPSULATION)
        sigs = suite.get_algorithms(category=AlgorithmCategory.DIGITAL_SIGNATURE)
        
        assert len(kems) > 0
        assert len(sigs) > 0
        assert set(kems).isdisjoint(set(sigs))

    def test_filter_algorithms_by_security_level(self):
        """Test filtering algorithms by NIST security level"""
        suite = PQBenchmarkSuite()
        
        level1 = suite.get_algorithms(nist_level=NISTSecurityLevel.LEVEL_1)
        level5 = suite.get_algorithms(nist_level=NISTSecurityLevel.LEVEL_5)
        
        assert len(level1) > 0
        assert len(level5) > 0


class TestBenchmarkExecution:
    """Test benchmark execution"""

    def test_benchmark_key_generation(self):
        """Test key generation benchmarking"""
        suite = PQBenchmarkSuite(measurement_iterations=100)
        
        result = suite.benchmark_key_generation("CRYSTALS-Kyber-512")
        
        assert result is not None
        assert result.algorithm == "CRYSTALS-Kyber-512"
        assert result.metric == BenchmarkMetric.KEY_GEN_TIME
        assert result.mean > 0
        assert result.sample_count == 100
        assert result.warmup_done is True

    def test_benchmark_nonexistent_algorithm(self):
        """Test benchmarking non-existent algorithm"""
        suite = PQBenchmarkSuite()
        result = suite.benchmark_key_generation("NONEXISTENT-ALG")
        assert result is None

    def test_benchmark_all(self):
        """Test benchmarking all algorithms"""
        suite = PQBenchmarkSuite(measurement_iterations=50)
        
        counts = suite.benchmark_all()
        
        assert counts["completed"] > 0
        assert counts["failed"] == 0
        
        summary = suite.get_summary()
        assert summary["benchmarked_algorithms"] > 0

    def test_benchmark_statistics(self):
        """Test benchmark statistics calculation"""
        suite = PQBenchmarkSuite(measurement_iterations=100)
        
        result = suite.benchmark_key_generation("CRYSTALS-Kyber-768")
        
        # All statistics should be computed
        assert result.mean > 0
        assert result.median > 0
        assert result.min > 0
        assert result.max > 0
        assert result.p95 >= result.median
        assert result.p99 >= result.p95
        assert result.std_dev >= 0

    def test_algorithm_sizes(self):
        """Test algorithm size retrieval"""
        suite = PQBenchmarkSuite()
        
        sizes = suite.get_algorithm_sizes("CRYSTALS-Kyber-512")
        
        assert "pk" in sizes
        assert "sk" in sizes
        assert "ct" in sizes
        assert sizes["pk"] > 0
        assert sizes["sk"] > 0


class TestRankingAndComparison:
    """Test algorithm ranking and comparison"""

    def test_rank_algorithms_by_performance(self):
        """Test ranking algorithms by performance"""
        suite = PQBenchmarkSuite(measurement_iterations=50)
        suite.benchmark_all()
        
        rank = suite.rank_algorithms(BenchmarkMetric.KEY_GEN_TIME)
        
        assert rank.metric == BenchmarkMetric.KEY_GEN_TIME
        assert len(rank.rankings) > 0
        
        # Should be sorted fastest to slowest
        values = [v for _, v in rank.rankings]
        assert values == sorted(values)

    def test_rank_filtered_by_category(self):
        """Test ranking filtered by category"""
        suite = PQBenchmarkSuite(measurement_iterations=50)
        suite.benchmark_all()
        
        rank = suite.rank_algorithms(
            BenchmarkMetric.KEY_GEN_TIME,
            category=AlgorithmCategory.KEY_ENCAPSULATION
        )
        
        # All ranked should be KEMs
        kem_names = suite.get_algorithms(category=AlgorithmCategory.KEY_ENCAPSULATION)
        for alg_name, _ in rank.rankings:
            assert alg_name in kem_names


class TestRegressionDetection:
    """Test performance regression detection"""

    def test_set_and_compare_baseline(self):
        """Test baseline setting and regression detection"""
        suite = PQBenchmarkSuite(measurement_iterations=50)
        suite.benchmark_key_generation("CRYSTALS-Kyber-512")
        
        # Set baseline
        suite.set_baseline()
        
        # No regression should be detected immediately
        is_regression, change = suite.detect_regression(
            "CRYSTALS-Kyber-512",
            BenchmarkMetric.KEY_GEN_TIME,
            threshold_pct=10.0
        )
        assert is_regression is False
        assert abs(change) < 1.0  # Should be ~0% change

    def test_regression_no_baseline(self):
        """Test regression detection without baseline"""
        suite = PQBenchmarkSuite()
        suite.benchmark_key_generation("CRYSTALS-Kyber-512")
        
        # No baseline set yet
        is_regression, change = suite.detect_regression(
            "CRYSTALS-Kyber-512",
            BenchmarkMetric.KEY_GEN_TIME
        )
        assert is_regression is False
        assert change == 0.0


class TestReportGeneration:
    """Test benchmark report generation"""

    def test_generate_json_report(self):
        """Test generating JSON benchmark report"""
        suite = PQBenchmarkSuite(measurement_iterations=50)
        suite.benchmark_all()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            filepath = f.name
        
        try:
            result = suite.generate_report(filepath)
            assert result is True
            
            # Verify file exists and is valid JSON
            assert os.path.exists(filepath)
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            assert "generated_at" in data
            assert "benchmark_config" in data
            assert "results" in data
            assert "rankings" in data
            
        finally:
            if os.path.exists(filepath):
                os.unlink(filepath)

    def test_summary_statistics(self):
        """Test summary statistics"""
        suite = PQBenchmarkSuite()
        summary = suite.get_summary()
        
        assert "total_algorithms" in summary
        assert "benchmarked_algorithms" in summary
        assert "by_category" in summary
        assert "by_security_level" in summary
        assert "kem" in summary["by_category"]
        assert "signature" in summary["by_category"]


class TestThreadSafety:
    """Test thread-safe concurrent benchmarking"""

    def test_concurrent_benchmarking(self):
        """Test concurrent benchmarking from multiple threads"""
        suite = PQBenchmarkSuite(measurement_iterations=50)
        errors = []
        
        def worker():
            try:
                for alg_name in ["CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "ECC-P256"]:
                    suite.benchmark_key_generation(alg_name)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0, f"Concurrent errors: {errors}"

    def test_concurrent_benchmark_and_rank(self):
        """Test concurrent benchmarking and ranking"""
        suite = PQBenchmarkSuite(measurement_iterations=30)
        errors = []
        
        def benchmarker():
            try:
                suite.benchmark_key_generation("CRYSTALS-Kyber-512")
            except Exception as e:
                errors.append(e)
        
        def ranker():
            try:
                suite.rank_algorithms(BenchmarkMetric.KEY_GEN_TIME)
            except Exception as e:
                errors.append(e)
        
        threads = []
        for _ in range(3):
            threads.append(threading.Thread(target=benchmarker))
            threads.append(threading.Thread(target=ranker))
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0, f"Concurrent benchmark/rank errors: {errors}"


class TestBenchmarkResultSerialization:
    """Test BenchmarkResult serialization"""

    def test_result_to_dict(self):
        """Test result serialization to dict"""
        result = BenchmarkResult(
            algorithm="TEST-ALG",
            metric=BenchmarkMetric.KEY_GEN_TIME,
            mean=0.123,
            median=0.12,
            min=0.1,
            max=0.15,
            std_dev=0.01,
            p95=0.14,
            p99=0.145,
            sample_count=1000,
            timestamp=datetime.now()
        )
        
        data = result.to_dict()
        
        assert data["algorithm"] == "TEST-ALG"
        assert data["metric"] == BenchmarkMetric.KEY_GEN_TIME.value
        assert data["mean"] == 0.123
        assert data["sample_count"] == 1000
        assert "timestamp" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
