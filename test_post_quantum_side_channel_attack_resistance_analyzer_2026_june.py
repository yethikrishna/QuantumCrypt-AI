#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Side-Channel Attack Resistance Analyzer
June 21, 2026 - Production Tests
Tests all side-channel analysis functionality
"""
import sys
import json
import hashlib

sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_side_channel_attack_resistance_analyzer_2026_june import (
    PostQuantumSideChannelAnalyzer,
    SideChannelType,
    PQAlgorithm,
    ResistanceLevel,
    SideChannelFinding,
    TimingAnalysisResult,
    PowerAnalysisResult,
    CacheAnalysisResult,
    ResistanceScore,
    SideChannelAnalysisReport,
    create_side_channel_analyzer,
    verify_side_channel_analyzer
)


def run_all_tests():
    """Run all test cases and generate report"""
    test_results = []
    total_passed = 0
    total_failed = 0
    
    print("=" * 70)
    print("Post-Quantum Side-Channel Attack Resistance Analyzer Tests")
    print("June 21, 2026 - Production Test Suite")
    print("=" * 70)
    
    # Test 1: Basic Verification
    print("\n[TEST 1] Self-Verification")
    try:
        result = verify_side_channel_analyzer()
        assert result == True, "Self-verification should pass"
        print("  ✓ Self-verification passed")
        
        test_results.append({"test": "Self-Verification", "status": "PASSED"})
        total_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "Self-Verification", "status": "FAILED", "error": str(e)})
        total_failed += 1
    
    # Test 2: Factory Function
    print("\n[TEST 2] Factory Function")
    try:
        analyzer = create_side_channel_analyzer(num_samples=500)
        assert isinstance(analyzer, PostQuantumSideChannelAnalyzer)
        assert analyzer.num_timing_samples == 500
        print("  ✓ Factory creates configured instance")
        
        test_results.append({"test": "Factory Function", "status": "PASSED"})
        total_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "Factory Function", "status": "FAILED", "error": str(e)})
        total_failed += 1
    
    # Test 3: Timing Analysis
    print("\n[TEST 3] Timing Attack Resistance Analysis")
    try:
        analyzer = create_side_channel_analyzer(num_samples=200)
        
        def hash_operation(x):
            return hashlib.sha512(x).digest()
        
        test_inputs = [b"input1", b"input2", b"input3", b"input4"]
        result = analyzer.analyze_timing_resistance(hash_operation, test_inputs, "sha512")
        
        assert isinstance(result, TimingAnalysisResult)
        assert result.timing_variance >= 0.0
        assert result.timing_stddev >= 0.0
        assert result.coefficient_of_variation >= 0.0
        assert isinstance(result.is_constant_time, bool)
        
        print(f"  ✓ Timing variance: {result.timing_variance:.2f}")
        print(f"  ✓ Coefficient of variation: {result.coefficient_of_variation:.6f}")
        print(f"  ✓ Is constant-time: {result.is_constant_time}")
        
        test_results.append({"test": "Timing Analysis", "status": "PASSED"})
        total_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "Timing Analysis", "status": "FAILED", "error": str(e)})
        total_failed += 1
    
    # Test 4: Power Analysis Resistance
    print("\n[TEST 4] Power Analysis (SPA/DPA) Resistance")
    try:
        analyzer = create_side_channel_analyzer()
        
        # Test multiple algorithms
        algorithms = [PQAlgorithm.CRYSTALS_KYBER, PQAlgorithm.SPHINCS, PQAlgorithm.FALCON]
        
        for alg in algorithms:
            result = analyzer.analyze_power_resistance(alg)
            assert isinstance(result, PowerAnalysisResult)
            assert isinstance(result.spa_vulnerable, bool)
            assert isinstance(result.dpa_vulnerable, bool)
            assert 0.0 <= result.hamming_weight_leakage <= 1.0
            assert 0.0 <= result.masking_effectiveness <= 1.0
            
            print(f"  ✓ {alg.value}: SPA={result.spa_vulnerable}, DPA={result.dpa_vulnerable}")
        
        test_results.append({"test": "Power Analysis", "status": "PASSED"})
        total_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "Power Analysis", "status": "FAILED", "error": str(e)})
        total_failed += 1
    
    # Test 5: Cache-Timing Analysis
    print("\n[TEST 5] Cache-Timing Attack Analysis")
    try:
        analyzer = create_side_channel_analyzer()
        
        result = analyzer.analyze_cache_resistance(PQAlgorithm.CRYSTALS_KYBER)
        
        assert isinstance(result, CacheAnalysisResult)
        assert isinstance(result.cache_timing_vulnerable, bool)
        assert 0.0 <= result.flush_reload_risk <= 1.0
        assert 0.0 <= result.prime_probe_risk <= 1.0
        
        print(f"  ✓ Cache vulnerable: {result.cache_timing_vulnerable}")
        print(f"  ✓ Flush+Reload risk: {result.flush_reload_risk:.2%}")
        print(f"  ✓ Prime+Probe risk: {result.prime_probe_risk:.2%}")
        
        test_results.append({"test": "Cache Analysis", "status": "PASSED"})
        total_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "Cache Analysis", "status": "FAILED", "error": str(e)})
        total_failed += 1
    
    # Test 6: Full Algorithm Analysis Report
    print("\n[TEST 6] Complete Algorithm Analysis Report")
    try:
        analyzer = create_side_channel_analyzer(num_samples=100)
        
        report = analyzer.analyze_algorithm(
            PQAlgorithm.CRYSTALS_DILITHIUM,
            implementation_details={"version": "3.1", "masking": "first_order"}
        )
        
        assert isinstance(report, SideChannelAnalysisReport)
        assert report.algorithm == PQAlgorithm.CRYSTALS_DILITHIUM
        assert isinstance(report.resistance_score, ResistanceScore)
        assert 0.0 <= report.resistance_score.overall_score <= 10.0
        assert isinstance(report.findings, list)
        assert isinstance(report.mitigation_recommendations, list)
        
        print(f"  ✓ Algorithm: {report.algorithm.value}")
        print(f"  ✓ Overall Score: {report.resistance_score.overall_score}/10.0")
        print(f"  ✓ Resistance Level: {report.resistance_score.resistance_level.value}")
        print(f"  ✓ Findings: {len(report.findings)} vulnerabilities")
        print(f"  ✓ Recommendations: {len(report.mitigation_recommendations)} mitigations")
        
        test_results.append({"test": "Full Analysis Report", "status": "PASSED"})
        total_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "Full Analysis Report", "status": "FAILED", "error": str(e)})
        total_failed += 1
    
    # Test 7: Resistance Score Calculation
    print("\n[TEST 7] Resistance Score Calculation")
    try:
        analyzer = create_side_channel_analyzer()
        
        # Create dummy results for scoring
        timing_result = TimingAnalysisResult(
            operation="test", timing_variance=100.0, timing_stddev=10.0,
            coefficient_of_variation=0.005, is_constant_time=True,
            secret_dependent_branches=[], secret_dependent_lookups=[]
        )
        
        power_result = PowerAnalysisResult(
            spa_vulnerable=False, dpa_vulnerable=False, hamming_weight_leakage=0.1,
            key_dependent_operations=[], masking_effectiveness=0.9
        )
        
        cache_result = CacheAnalysisResult(
            cache_timing_vulnerable=False, secret_dependent_access=[],
            cache_line_conflicts=[], flush_reload_risk=0.1, prime_probe_risk=0.1
        )
        
        score = analyzer.calculate_resistance_score(
            PQAlgorithm.SPHINCS, timing_result, power_result, cache_result
        )
        
        assert isinstance(score, ResistanceScore)
        assert 0.0 <= score.overall_score <= 10.0
        assert 0.0 <= score.timing_score <= 10.0
        assert 0.0 <= score.power_analysis_score <= 10.0
        assert 0.0 <= score.cache_timing_score <= 10.0
        assert isinstance(score.resistance_level, ResistanceLevel)
        
        print(f"  ✓ Overall: {score.overall_score}")
        print(f"  ✓ Timing: {score.timing_score}, Power: {score.power_analysis_score}")
        print(f"  ✓ Cache: {score.cache_timing_score}, EM: {score.em_leakage_score}")
        print(f"  ✓ Level: {score.resistance_level.value}")
        
        test_results.append({"test": "Resistance Scoring", "status": "PASSED"})
        total_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "Resistance Scoring", "status": "FAILED", "error": str(e)})
        total_failed += 1
    
    # Test 8: Algorithm Comparison
    print("\n[TEST 8] Multi-Algorithm Comparison")
    try:
        analyzer = create_side_channel_analyzer()
        
        algorithms = [
            PQAlgorithm.CRYSTALS_KYBER,
            PQAlgorithm.CRYSTALS_DILITHIUM,
            PQAlgorithm.SPHINCS,
            PQAlgorithm.FALCON,
            PQAlgorithm.NTRU
        ]
        
        comparison = analyzer.compare_algorithms(algorithms)
        
        assert "comparison" in comparison
        assert "ranked" in comparison
        assert len(comparison["ranked"]) == len(algorithms)
        
        print("  ✓ Algorithm ranking (best to worst):")
        for i, (alg, scores) in enumerate(comparison["ranked"], 1):
            print(f"    {i}. {alg}: {scores['overall_score']}/10 ({scores['resistance_level']})")
        
        test_results.append({"test": "Algorithm Comparison", "status": "PASSED"})
        total_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "Algorithm Comparison", "status": "FAILED", "error": str(e)})
        total_failed += 1
    
    # Test 9: Findings and Mitigations Generation
    print("\n[TEST 9] Findings & Mitigations Generation")
    try:
        analyzer = create_side_channel_analyzer()
        
        timing_result = TimingAnalysisResult(
            operation="test_op", timing_variance=1000.0, timing_stddev=31.6,
            coefficient_of_variation=0.08, is_constant_time=False,
            secret_dependent_branches=["branch_A"], secret_dependent_lookups=["lookup_B"]
        )
        
        power_result = PowerAnalysisResult(
            spa_vulnerable=True, dpa_vulnerable=True, hamming_weight_leakage=0.5,
            key_dependent_operations=["key_op1"], masking_effectiveness=0.5
        )
        
        cache_result = CacheAnalysisResult(
            cache_timing_vulnerable=True, secret_dependent_access=["access1"],
            cache_line_conflicts=["conflict1"], flush_reload_risk=0.6, prime_probe_risk=0.5
        )
        
        findings = analyzer.generate_findings(
            PQAlgorithm.FALCON, timing_result, power_result, cache_result
        )
        
        assert len(findings) > 0
        assert all(isinstance(f, SideChannelFinding) for f in findings)
        
        score = ResistanceScore(
            overall_score=4.5, timing_score=5.0, power_analysis_score=4.0,
            cache_timing_score=4.5, em_leakage_score=4.5, fault_resistance_score=5.0,
            resistance_level=ResistanceLevel.WEAK
        )
        
        mitigations = analyzer.generate_mitigations(findings, score)
        
        assert len(mitigations) > 0
        assert all(isinstance(m, str) for m in mitigations)
        
        print(f"  ✓ Generated {len(findings)} vulnerability findings")
        print(f"  ✓ Generated {len(mitigations)} mitigation recommendations")
        
        test_results.append({"test": "Findings & Mitigations", "status": "PASSED"})
        total_passed += 1
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "Findings & Mitigations", "status": "FAILED", "error": str(e)})
        total_failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total Tests: {len(test_results)}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")
    print(f"Success Rate: {(total_passed/len(test_results))*100:.1f}%")
    
    # Save results
    report = {
        "test_date": "2026-06-21",
        "module": "post_quantum_side_channel_attack_resistance_analyzer_2026_june",
        "total_tests": len(test_results),
        "passed": total_passed,
        "failed": total_failed,
        "success_rate": total_passed / len(test_results),
        "results": test_results
    }
    
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_side_channel_analyzer.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nTest report saved to test_results_side_channel_analyzer.json")
    
    return total_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
