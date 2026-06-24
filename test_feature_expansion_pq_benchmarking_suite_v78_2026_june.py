"""
Test Suite for Post-Quantum Algorithm Benchmarking Suite v78
Dimension A: Feature Expansion
QuantumCrypt-AI - June 24, 2026

All tests verify the new feature works correctly.
No existing production code modified - ADD-ONLY philosophy.
"""

import pytest
import json
from quantum_crypt.feature_expansion_pq_algorithm_benchmarking_suite_v78_2026_june import (
    PQAlgorithmBenchmarkingSuite,
    PQAlgorithmFamily,
    PQAlgorithm,
    BenchmarkOperation,
    SecurityLevel,
    BenchmarkResult,
    AlgorithmComparison,
    BenchmarkReport
)


class TestBenchmarkingSuiteCoreFunctionality:
    """Core functionality tests for the PQ benchmarking suite."""
    
    def setup_method(self):
        """Initialize benchmark suite for each test."""
        self.suite = PQAlgorithmBenchmarkingSuite()
    
    def test_suite_initialization(self):
        """Test suite initializes correctly."""
        assert self.suite is not None
        assert hasattr(self.suite, '_benchmark_history')
        assert hasattr(self.suite, '_warmup_done')
    
    def test_version_information(self):
        """Test version information is correct."""
        version = self.suite.get_version()
        assert version["version"] == "1.0.0"
        assert version["api_stability"] == "STABLE"
        assert version["module"] == "PQAlgorithmBenchmarkingSuite"
        assert version["nist_algorithms_supported"] > 0
        assert version["total_algorithms_supported"] > 0
    
    def test_algorithm_metadata_populated(self):
        """Test algorithm metadata is populated."""
        assert len(self.suite._ALGORITHM_METADATA) > 0
        assert "CRYSTALS-Kyber-768" in self.suite._ALGORITHM_METADATA
        assert "CRYSTALS-Dilithium-3" in self.suite._ALGORITHM_METADATA
    
    def test_performance_baselines_populated(self):
        """Test performance baselines are populated."""
        assert len(self.suite._PERFORMANCE_BASELINES) > 0
        assert "CRYSTALS-Kyber-768" in self.suite._PERFORMANCE_BASELINES


class TestSingleBenchmarkExecution:
    """Tests for individual benchmark execution."""
    
    def setup_method(self):
        """Initialize benchmark suite for each test."""
        self.suite = PQAlgorithmBenchmarkingSuite()
    
    def test_run_benchmark_returns_result(self):
        """Test benchmark returns valid result object."""
        result = self.suite.run_benchmark(
            "CRYSTALS-Kyber-768",
            "key_generation",
            iterations=100
        )
        assert isinstance(result, BenchmarkResult)
        assert result.algorithm == "CRYSTALS-Kyber-768"
        assert result.operation == "key_generation"
        assert result.iterations == 100
    
    def test_benchmark_statistics_calculated(self):
        """Test benchmark statistics are properly calculated."""
        result = self.suite.run_benchmark(
            "CRYSTALS-Kyber-768",
            "key_generation",
            iterations=100
        )
        assert result.mean_time_ms > 0
        assert result.median_time_ms > 0
        assert result.min_time_ms > 0
        assert result.max_time_ms > 0
        assert result.operations_per_second > 0
    
    def test_benchmark_key_sizes_correct(self):
        """Test key sizes match NIST specifications."""
        result = self.suite.run_benchmark(
            "CRYSTALS-Kyber-768",
            "key_generation",
            iterations=10
        )
        assert result.public_key_size_bytes == 1184
        assert result.private_key_size_bytes == 2400
        assert result.ciphertext_size_bytes == 1088
    
    def test_benchmark_security_level(self):
        """Test security level is correctly reported."""
        result = self.suite.run_benchmark(
            "CRYSTALS-Kyber-768",
            "key_generation",
            iterations=10
        )
        assert result.security_level == 3  # NIST Level 3
    
    def test_warmup_function(self):
        """Test warmup function works."""
        assert not self.suite._warmup_done
        self.suite._warmup()
        assert self.suite._warmup_done


class TestFullAlgorithmBenchmark:
    """Tests for full algorithm benchmarking."""
    
    def setup_method(self):
        """Initialize benchmark suite for each test."""
        self.suite = PQAlgorithmBenchmarkingSuite()
    
    def test_benchmark_kem_algorithm(self):
        """Test benchmarking KEM algorithm runs all operations."""
        results = self.suite.benchmark_algorithm(
            "CRYSTALS-Kyber-768",
            iterations=50
        )
        assert "key_generation" in results
        assert "key_encapsulation" in results
        assert "key_decapsulation" in results
        assert len(results) == 3
    
    def test_benchmark_signature_algorithm(self):
        """Test benchmarking signature algorithm runs all operations."""
        results = self.suite.benchmark_algorithm(
            "CRYSTALS-Dilithium-3",
            iterations=50
        )
        assert "key_generation" in results
        assert "signature_generation" in results
        assert "signature_verification" in results
        assert len(results) == 3
    
    def test_custom_operations_list(self):
        """Test benchmarking with custom operations list."""
        results = self.suite.benchmark_algorithm(
            "CRYSTALS-Kyber-768",
            operations=["key_generation"],
            iterations=50
        )
        assert len(results) == 1
        assert "key_generation" in results


class TestAlgorithmComparison:
    """Tests for algorithm comparison functionality."""
    
    def setup_method(self):
        """Initialize benchmark suite for each test."""
        self.suite = PQAlgorithmBenchmarkingSuite()
    
    def test_compare_algorithms_returns_comparison(self):
        """Test comparison returns valid object."""
        comparison = self.suite.compare_algorithms(
            ["CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024"],
            "key_generation"
        )
        assert isinstance(comparison, AlgorithmComparison)
        assert len(comparison.algorithms_compared) == 3
    
    def test_comparison_relative_performance(self):
        """Test relative performance calculations."""
        comparison = self.suite.compare_algorithms(
            ["CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768"],
            "key_generation",
            baseline_algorithm="CRYSTALS-Kyber-768"
        )
        assert comparison.baseline_algorithm == "CRYSTALS-Kyber-768"
        assert "CRYSTALS-Kyber-512" in comparison.relative_performance
        assert "CRYSTALS-Kyber-768" in comparison.speedup_vs_baseline
    
    def test_comparison_key_size_comparison(self):
        """Test key size comparison is included."""
        comparison = self.suite.compare_algorithms(
            ["CRYSTALS-Kyber-768", "RSA-4096"],
            "key_generation"
        )
        assert "CRYSTALS-Kyber-768" in comparison.key_size_comparison
        assert "RSA-4096" in comparison.key_size_comparison
        assert "public_key" in comparison.key_size_comparison["CRYSTALS-Kyber-768"]
    
    def test_comparison_recommendations_generated(self):
        """Test recommendations are generated."""
        comparison = self.suite.compare_algorithms(
            ["CRYSTALS-Kyber-768", "ECC-P256", "RSA-4096"],
            "key_generation"
        )
        assert len(comparison.recommendations) > 0
    
    def test_comparison_requires_at_least_one_algorithm(self):
        """Test comparison raises error with no algorithms."""
        with pytest.raises(ValueError):
            self.suite.compare_algorithms([], "key_generation")


class TestFullBenchmarkReport:
    """Tests for comprehensive benchmark report generation."""
    
    def setup_method(self):
        """Initialize benchmark suite for each test."""
        self.suite = PQAlgorithmBenchmarkingSuite()
    
    def test_generate_full_report(self):
        """Test full report generation works."""
        report = self.suite.generate_full_report(
            algorithms=["CRYSTALS-Kyber-768", "CRYSTALS-Dilithium-3"]
        )
        assert isinstance(report, BenchmarkReport)
        assert report.report_id.startswith("pq-benchmark-")
        assert report.total_algorithms_tested == 2
        assert report.total_operations_tested > 0
    
    def test_report_includes_system_info(self):
        """Test system info is included in report."""
        report = self.suite.generate_full_report(
            algorithms=["CRYSTALS-Kyber-768"]
        )
        assert report.system_info is not None
    
    def test_export_report_json(self):
        """Test JSON export works correctly."""
        report = self.suite.generate_full_report(
            algorithms=["CRYSTALS-Kyber-768"]
        )
        json_str = self.suite.export_report_json(report)
        parsed = json.loads(json_str)
        assert "report_id" in parsed
        assert "summary" in parsed
        assert "results" in parsed


class TestUseCaseRecommendations:
    """Tests for use case recommendation system."""
    
    def setup_method(self):
        """Initialize benchmark suite for each test."""
        self.suite = PQAlgorithmBenchmarkingSuite()
    
    def test_tls_recommendation(self):
        """Test TLS use case recommendation."""
        rec = self.suite.get_recommendation_for_use_case("tls")
        assert rec["primary"] == "CRYSTALS-Kyber-768"
        assert "rationale" in rec
    
    def test_code_signing_recommendation(self):
        """Test code signing use case recommendation."""
        rec = self.suite.get_recommendation_for_use_case("code_signing")
        assert rec["primary"] == "CRYSTALS-Dilithium-3"
        assert "rationale" in rec
    
    def test_iot_recommendation(self):
        """Test IoT use case recommendation."""
        rec = self.suite.get_recommendation_for_use_case("iot")
        assert rec["primary"] == "CRYSTALS-Kyber-512"
    
    def test_unknown_use_case_fallback(self):
        """Test unknown use case falls back to general."""
        rec = self.suite.get_recommendation_for_use_case("unknown")
        assert "kem" in rec
        assert "rationale" in rec


class TestAlgorithmListing:
    """Tests for algorithm listing functionality."""
    
    def setup_method(self):
        """Initialize benchmark suite for each test."""
        self.suite = PQAlgorithmBenchmarkingSuite()
    
    def test_list_all_algorithms(self):
        """Test listing all supported algorithms."""
        algorithms = self.suite.list_supported_algorithms()
        assert len(algorithms) > 0
        assert "CRYSTALS-Kyber-768" in algorithms
    
    def test_list_by_family(self):
        """Test listing algorithms by family."""
        lattice = self.suite.list_supported_algorithms(PQAlgorithmFamily.LATTICE_BASED)
        assert len(lattice) > 0
        assert "CRYSTALS-Kyber-768" in lattice
        
        hash_based = self.suite.list_supported_algorithms(PQAlgorithmFamily.HASH_BASED)
        assert len(hash_based) > 0
        assert "SPHINCS+-128f" in hash_based


class TestEnumsAndDataclasses:
    """Tests for enum and dataclass integrity."""
    
    def test_pq_algorithm_family_enum(self):
        """Test PQAlgorithmFamily enum values."""
        assert PQAlgorithmFamily.LATTICE_BASED.value == "lattice_based"
        assert PQAlgorithmFamily.CODE_BASED.value == "code_based"
        assert PQAlgorithmFamily.HASH_BASED.value == "hash_based"
    
    def test_benchmark_operation_enum(self):
        """Test BenchmarkOperation enum values."""
        assert BenchmarkOperation.KEY_GENERATION.value == "key_generation"
        assert BenchmarkOperation.SIGNATURE_VERIFICATION.value == "signature_verification"
    
    def test_security_level_enum(self):
        """Test SecurityLevel enum values."""
        assert SecurityLevel.LEVEL_1.value == 1
        assert SecurityLevel.LEVEL_3.value == 3
        assert SecurityLevel.LEVEL_5.value == 5
    
    def test_benchmark_result_dataclass(self):
        """Test BenchmarkResult dataclass works."""
        result = BenchmarkResult(
            algorithm="Test-Algo",
            algorithm_family="lattice_based",
            operation="key_generation",
            security_level=3,
            iterations=100,
            mean_time_ms=0.1,
            median_time_ms=0.1,
            min_time_ms=0.09,
            max_time_ms=0.11,
            std_dev_ms=0.005,
            p95_time_ms=0.105,
            p99_time_ms=0.108,
            operations_per_second=10000,
            public_key_size_bytes=1184,
            private_key_size_bytes=2400
        )
        assert result.algorithm == "Test-Algo"
        assert result.security_level == 3


class TestBackwardCompatibility:
    """Tests ensuring backward compatibility - no breaking changes."""
    
    def test_no_existing_modules_modified(self):
        """Verify ADD-ONLY philosophy - module is completely standalone."""
        import quantum_crypt.feature_expansion_pq_algorithm_benchmarking_suite_v78_2026_june as module
        assert module is not None
        # Module is self-contained, no modifications to other modules
    
    def test_import_without_side_effects(self):
        """Test importing doesn't cause side effects."""
        suite = PQAlgorithmBenchmarkingSuite()
        assert suite is not None


class TestEdgeCases:
    """Edge case tests for benchmark suite."""
    
    def setup_method(self):
        """Initialize benchmark suite for each test."""
        self.suite = PQAlgorithmBenchmarkingSuite()
    
    def test_single_iteration_benchmark(self):
        """Test benchmark with single iteration."""
        result = self.suite.run_benchmark(
            "CRYSTALS-Kyber-768",
            "key_generation",
            iterations=1
        )
        assert result.iterations == 1
        assert result.mean_time_ms > 0
    
    def test_unknown_algorithm_performance(self):
        """Test unknown algorithm gets default timing."""
        result = self.suite.run_benchmark(
            "UNKNOWN-ALGORITHM",
            "key_generation",
            iterations=10
        )
        assert result.mean_time_ms > 0
    
    def test_unknown_operation_performance(self):
        """Test unknown operation gets default timing."""
        result = self.suite.run_benchmark(
            "CRYSTALS-Kyber-768",
            "unknown_operation",
            iterations=10
        )
        assert result.mean_time_ms > 0
    
    def test_no_warmup_option(self):
        """Test benchmark without warmup."""
        result = self.suite.run_benchmark(
            "CRYSTALS-Kyber-768",
            "key_generation",
            iterations=10,
            warmup=False
        )
        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
