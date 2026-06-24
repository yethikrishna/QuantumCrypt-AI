"""
Test Suite for Post-Quantum Algorithm Benchmarking Suite v77
DIMENSION A - Feature Expansion
Tests cover: basic functionality, edge cases, integration, and error paths.
All existing tests must continue to pass.
"""

import pytest
import json

from quantum_crypt.feature_expansion_pq_algorithm_benchmarking_suite_v77_2026_june import (
    PQAlgorithmBenchmarkingSuite,
    PQAlgorithm,
    SecurityLevel,
    BenchmarkMetric,
    BenchmarkResult,
    AlgorithmComparison,
    pq_benchmark_suite
)


class TestPQAlgorithmEnum:
    """Test PQ Algorithm enumeration"""
    
    def test_kem_algorithms_exist(self):
        """Test KEM algorithms are defined"""
        kem_algs = [
            PQAlgorithm.CRYSTALS_KYBER,
            PQAlgorithm.NTRU_HPS,
            PQAlgorithm.SABER,
            PQAlgorithm.CLASSIC_MCELIECE,
            PQAlgorithm.BIKE,
            PQAlgorithm.HQC
        ]
        for alg in kem_algs:
            assert alg in PQAlgorithm
    
    def test_signature_algorithms_exist(self):
        """Test signature algorithms are defined"""
        sig_algs = [
            PQAlgorithm.CRYSTALS_DILITHIUM,
            PQAlgorithm.FALCON,
            PQAlgorithm.SPHINCS
        ]
        for alg in sig_algs:
            assert alg in PQAlgorithm
    
    def test_algorithm_count(self):
        """Test correct number of algorithms"""
        assert len(PQAlgorithm) >= 10  # At least 10 PQ algorithms


class TestSecurityLevelEnum:
    """Test NIST Security Level enumeration"""
    
    def test_security_levels_exist(self):
        """Test all NIST security levels are present"""
        assert SecurityLevel.LEVEL_1.value == "NIST-1"
        assert SecurityLevel.LEVEL_3.value == "NIST-3"
        assert SecurityLevel.LEVEL_5.value == "NIST-5"


class TestBenchmarkMetricEnum:
    """Test Benchmark Metric enumeration"""
    
    def test_time_metrics_exist(self):
        """Test timing metrics are defined"""
        time_metrics = [
            BenchmarkMetric.KEYGEN_TIME,
            BenchmarkMetric.ENCAPS_TIME,
            BenchmarkMetric.DECAPS_TIME,
            BenchmarkMetric.SIGN_TIME,
            BenchmarkMetric.VERIFY_TIME
        ]
        for metric in time_metrics:
            assert metric in BenchmarkMetric
    
    def test_size_metrics_exist(self):
        """Test size metrics are defined"""
        size_metrics = [
            BenchmarkMetric.PUBLIC_KEY_SIZE,
            BenchmarkMetric.PRIVATE_KEY_SIZE,
            BenchmarkMetric.CIPHERTEXT_SIZE,
            BenchmarkMetric.SIGNATURE_SIZE
        ]
        for metric in size_metrics:
            assert metric in BenchmarkMetric


class TestBenchmarkingSuiteInitialization:
    """Test benchmarking suite initialization"""
    
    def test_suite_initialization(self):
        """Test suite initializes properly"""
        suite = PQAlgorithmBenchmarkingSuite()
        assert len(suite._algorithm_properties) > 0
        assert len(suite._benchmark_cache) == 0
    
    def test_singleton_instance(self):
        """Test singleton instance is available"""
        assert pq_benchmark_suite is not None
        assert isinstance(pq_benchmark_suite, PQAlgorithmBenchmarkingSuite)


class TestSingleAlgorithmBenchmark:
    """Test single algorithm benchmarking"""
    
    def test_benchmark_kyber(self):
        """Test benchmarking CRYSTALS-Kyber (NIST standard)"""
        suite = PQAlgorithmBenchmarkingSuite()
        result = suite.benchmark_algorithm(PQAlgorithm.CRYSTALS_KYBER)
        
        assert result.algorithm == PQAlgorithm.CRYSTALS_KYBER
        assert result.security_level == SecurityLevel.LEVEL_1
        assert len(result.metrics) > 0
        assert BenchmarkMetric.KEYGEN_TIME in result.metrics
        assert BenchmarkMetric.PUBLIC_KEY_SIZE in result.metrics
        assert result.iterations == 100
        assert result.warmup_iterations == 3
    
    def test_benchmark_dilithium(self):
        """Test benchmarking CRYSTALS-Dilithium"""
        suite = PQAlgorithmBenchmarkingSuite()
        result = suite.benchmark_algorithm(
            PQAlgorithm.CRYSTALS_DILITHIUM,
            security_level=SecurityLevel.LEVEL_3
        )
        
        assert result.algorithm == PQAlgorithm.CRYSTALS_DILITHIUM
        assert result.security_level == SecurityLevel.LEVEL_3
    
    def test_benchmark_mceliece_warnings(self):
        """Test Classic McEliece has appropriate warnings"""
        suite = PQAlgorithmBenchmarkingSuite()
        result = suite.benchmark_algorithm(PQAlgorithm.CLASSIC_MCELIECE)
        
        assert any("WARNING" in note for note in result.notes)
        assert any("large public key" in note.lower() for note in result.notes)
        assert any("slow key generation" in note.lower() for note in result.notes)
    
    def test_benchmark_sphincs_warnings(self):
        """Test SPHINCS+ has appropriate warnings"""
        suite = PQAlgorithmBenchmarkingSuite()
        result = suite.benchmark_algorithm(PQAlgorithm.SPHINCS)
        
        assert any("WARNING" in note for note in result.notes)
        assert any("slow signing" in note.lower() for note in result.notes)
    
    def test_benchmark_custom_iterations(self):
        """Test custom iteration count"""
        suite = PQAlgorithmBenchmarkingSuite()
        result = suite.benchmark_algorithm(
            PQAlgorithm.NTRU_HPS,
            iterations=50,
            warmup_iterations=5
        )
        
        assert result.iterations == 50
        assert result.warmup_iterations == 5
    
    def test_benchmark_caching(self):
        """Test benchmark result caching"""
        suite = PQAlgorithmBenchmarkingSuite()
        result1 = suite.benchmark_algorithm(PQAlgorithm.CRYSTALS_KYBER, iterations=25)
        result2 = suite.benchmark_algorithm(PQAlgorithm.CRYSTALS_KYBER, iterations=25)
        
        assert result1 is result2  # Same object from cache
    
    def test_benchmark_no_cache(self):
        """Test benchmark without caching"""
        suite = PQAlgorithmBenchmarkingSuite()
        result1 = suite.benchmark_algorithm(
            PQAlgorithm.SABER,
            iterations=10,
            use_cache=False
        )
        result2 = suite.benchmark_algorithm(
            PQAlgorithm.SABER,
            iterations=10,
            use_cache=False
        )
        
        # Different objects, but same algorithm
        assert result1 is not result2
        assert result1.algorithm == result2.algorithm


class TestAlgorithmComparison:
    """Test algorithm comparison functionality"""
    
    def test_compare_kem_algorithms(self):
        """Test comparing multiple KEM algorithms"""
        suite = PQAlgorithmBenchmarkingSuite()
        comparison = suite.compare_algorithms([
            PQAlgorithm.CRYSTALS_KYBER,
            PQAlgorithm.NTRU_HPS,
            PQAlgorithm.SABER
        ])
        
        assert len(comparison.algorithms) == 3
        assert len(comparison.comparison_metrics) > 0
        assert len(comparison.recommendations) > 0
    
    def test_compare_signature_algorithms(self):
        """Test comparing signature algorithms"""
        suite = PQAlgorithmBenchmarkingSuite()
        comparison = suite.compare_algorithms([
            PQAlgorithm.CRYSTALS_DILITHIUM,
            PQAlgorithm.FALCON,
            PQAlgorithm.SPHINCS
        ])
        
        assert len(comparison.algorithms) == 3
        assert any("BEST SIGNATURE" in r for r in comparison.recommendations)
    
    def test_comparison_normalized_scores(self):
        """Test comparison metrics are normalized 0-100"""
        suite = PQAlgorithmBenchmarkingSuite()
        comparison = suite.compare_algorithms([
            PQAlgorithm.CRYSTALS_KYBER,
            PQAlgorithm.NTRU_HPS
        ])
        
        for metric, scores in comparison.comparison_metrics.items():
            for alg, score in scores.items():
                assert 0 <= score <= 100
    
    def test_nist_selected_recommendation(self):
        """Test NIST-selected algorithms are highlighted"""
        suite = PQAlgorithmBenchmarkingSuite()
        comparison = suite.compare_algorithms([
            PQAlgorithm.CRYSTALS_KYBER,
            PQAlgorithm.SABER
        ])
        
        assert any("NIST STANDARDIZED" in r for r in comparison.recommendations)


class TestAlgorithmInformation:
    """Test algorithm information retrieval"""
    
    def test_get_kyber_info(self):
        """Test getting Kyber algorithm info"""
        suite = PQAlgorithmBenchmarkingSuite()
        info = suite.get_algorithm_info(PQAlgorithm.CRYSTALS_KYBER)
        
        assert info is not None
        assert info["algorithm"] == "CRYSTALS-Kyber"
        assert info["type"] == "KEM"
        assert info["nist_selected"] is True
        assert info["patent_free"] is True
    
    def test_get_dilithium_info(self):
        """Test getting Dilithium algorithm info"""
        suite = PQAlgorithmBenchmarkingSuite()
        info = suite.get_algorithm_info(PQAlgorithm.CRYSTALS_DILITHIUM)
        
        assert info is not None
        assert info["type"] == "Signature"
        assert info["nist_selected"] is True
    
    def test_list_kem_algorithms(self):
        """Test listing KEM algorithms"""
        suite = PQAlgorithmBenchmarkingSuite()
        kems = suite.list_algorithms_by_type("KEM")
        
        assert len(kems) >= 5
        assert PQAlgorithm.CRYSTALS_KYBER in kems
        assert PQAlgorithm.NTRU_HPS in kems
    
    def test_list_signature_algorithms(self):
        """Test listing signature algorithms"""
        suite = PQAlgorithmBenchmarkingSuite()
        sigs = suite.list_algorithms_by_type("Signature")
        
        assert len(sigs) >= 3
        assert PQAlgorithm.CRYSTALS_DILITHIUM in sigs
        assert PQAlgorithm.FALCON in sigs


class TestAlgorithmRecommendation:
    """Test algorithm recommendation engine"""
    
    def test_recommend_tls_use_case(self):
        """Test recommendation for TLS use case"""
        suite = PQAlgorithmBenchmarkingSuite()
        rec = suite.recommend_algorithm("tls")
        
        assert rec["kem"] == PQAlgorithm.CRYSTALS_KYBER
        assert rec["signature"] == PQAlgorithm.CRYSTALS_DILITHIUM
        assert "NIST-selected" in rec["rationale"]
    
    def test_recommend_signing_use_case(self):
        """Test recommendation for signing use case"""
        suite = PQAlgorithmBenchmarkingSuite()
        rec = suite.recommend_algorithm("signing")
        
        assert rec["signature"] == PQAlgorithm.FALCON
    
    def test_recommend_embedded_use_case(self):
        """Test recommendation for embedded use case"""
        suite = PQAlgorithmBenchmarkingSuite()
        rec = suite.recommend_algorithm("embedded")
        
        assert rec["kem"] == PQAlgorithm.NTRU_HPS
    
    def test_recommend_high_security_use_case(self):
        """Test recommendation for high-security use case"""
        suite = PQAlgorithmBenchmarkingSuite()
        rec = suite.recommend_algorithm("high_security")
        
        assert rec["kem"] == PQAlgorithm.CLASSIC_MCELIECE
    
    def test_recommend_general_use_case(self):
        """Test recommendation for general use case"""
        suite = PQAlgorithmBenchmarkingSuite()
        rec = suite.recommend_algorithm("general")
        
        assert rec["kem"] == PQAlgorithm.CRYSTALS_KYBER
    
    def test_recommend_unknown_use_case(self):
        """Test unknown use case falls back to general"""
        suite = PQAlgorithmBenchmarkingSuite()
        rec = suite.recommend_algorithm("unknown_use_case_xyz")
        
        assert rec["kem"] == PQAlgorithm.CRYSTALS_KYBER
    
    def test_recommend_with_constraints(self):
        """Test recommendation with constraints"""
        suite = PQAlgorithmBenchmarkingSuite()
        rec = suite.recommend_algorithm(
            "tls",
            constraints={"max_key_size": 2000, "max_latency_ms": 1.0}
        )
        
        assert "constraints_applied" in rec
        assert rec["constraints_applied"]["max_key_size"] == 2000


class TestReportExport:
    """Test benchmark report export functionality"""
    
    def test_export_json_format(self):
        """Test JSON report export"""
        suite = PQAlgorithmBenchmarkingSuite()
        results = [
            suite.benchmark_algorithm(PQAlgorithm.CRYSTALS_KYBER),
            suite.benchmark_algorithm(PQAlgorithm.CRYSTALS_DILITHIUM),
        ]
        json_output = suite.export_benchmark_report(results, format="json")
        
        # Should be valid JSON
        parsed = json.loads(json_output)
        assert "benchmark_summary" in parsed
        assert "results" in parsed
        assert parsed["benchmark_summary"]["total_algorithms"] == 2
        assert len(parsed["results"]) == 2
    
    def test_export_contains_metrics(self):
        """Test exported report contains metrics"""
        suite = PQAlgorithmBenchmarkingSuite()
        results = [suite.benchmark_algorithm(PQAlgorithm.CRYSTALS_KYBER)]
        json_output = suite.export_benchmark_report(results, format="json")
        
        parsed = json.loads(json_output)
        assert "metrics" in parsed["results"][0]
        assert "algorithm" in parsed["results"][0]
        assert "notes" in parsed["results"][0]


class TestPerformanceCharacteristics:
    """Test algorithm performance characteristics"""
    
    def test_mceliece_slow_keygen(self):
        """Test Classic McEliece has significantly slower keygen"""
        suite = PQAlgorithmBenchmarkingSuite()
        kyber = suite.benchmark_algorithm(PQAlgorithm.CRYSTALS_KYBER)
        mceliece = suite.benchmark_algorithm(PQAlgorithm.CLASSIC_MCELIECE)
        
        # McEliece keygen should be orders of magnitude slower
        kyber_keygen = kyber.metrics.get(BenchmarkMetric.KEYGEN_TIME, 0)
        mceliece_keygen = mceliece.metrics.get(BenchmarkMetric.KEYGEN_TIME, 0)
        
        assert mceliece_keygen > kyber_keygen * 100
    
    def test_sphincs_tiny_keys(self):
        """Test SPHINCS+ has extremely small public keys"""
        suite = PQAlgorithmBenchmarkingSuite()
        sphincs = suite.benchmark_algorithm(PQAlgorithm.SPHINCS)
        dilithium = suite.benchmark_algorithm(
            PQAlgorithm.CRYSTALS_DILITHIUM,
            security_level=SecurityLevel.LEVEL_3
        )
        
        sphincs_key = sphincs.metrics.get(BenchmarkMetric.PUBLIC_KEY_SIZE, 999999)
        dilithium_key = dilithium.metrics.get(BenchmarkMetric.PUBLIC_KEY_SIZE, 0)
        
        # SPHINCS+ has tiny keys (32 bytes vs 1312 bytes for Dilithium)
        assert sphincs_key < dilithium_key
        assert sphincs_key == 32  # SPHINCS+ public key is only 32 bytes


class TestNonNistAlgorithmNotes:
    """Test non-NIST algorithms have appropriate notes"""
    
    def test_saber_not_nist_note(self):
        """Test SABER has non-NIST note"""
        suite = PQAlgorithmBenchmarkingSuite()
        result = suite.benchmark_algorithm(PQAlgorithm.SABER)
        assert any("Not NIST-selected" in note for note in result.notes)
    
    def test_bike_not_nist_note(self):
        """Test BIKE has non-NIST note"""
        suite = PQAlgorithmBenchmarkingSuite()
        result = suite.benchmark_algorithm(PQAlgorithm.BIKE)
        assert any("Not NIST-selected" in note for note in result.notes)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
