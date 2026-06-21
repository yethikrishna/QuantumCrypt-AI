#!/usr/bin/env python3
"""
Test suite for Post-Quantum EM Side-Channel Analysis Validator
Production-grade tests with real assertions
"""

import sys
import time
import json
import secrets

sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_em_side_channel_analysis_validator_2026_june import (
    EMLeakageResult,
    EMRadiationSample,
    LatticeOperationAnalyzer,
    EMCorrelationAttackSimulator,
    EMSideChannelValidator
)


def test_lattice_analyzer_basic():
    """Test Lattice Operation Analyzer basic functionality"""
    print("Testing Lattice Operation Analyzer...")
    
    analyzer = LatticeOperationAnalyzer()
    
    # Test polynomial multiplication emission
    coeffs = [secrets.randbelow(3329) - 1665 for _ in range(64)]
    samples = analyzer.simulate_polynomial_mult_emission(coeffs)
    
    assert len(samples) == 64, "Should have 64 samples"
    assert all(s.operation == "polynomial_mult" for s in samples), "All should be polynomial mult"
    assert all(0 <= s.hamming_weight <= 16 for s in samples), "HW should be valid"
    assert all(s.simulated_em_amplitude >= 0 for s in samples), "EM amplitude non-negative"
    
    print("  ✓ Lattice Analyzer basic tests passed")
    return True


def test_ntt_emission_simulation():
    """Test NTT emission simulation"""
    print("Testing NTT Emission Simulation...")
    
    analyzer = LatticeOperationAnalyzer()
    
    # Small NTT for testing
    samples = analyzer.simulate_ntt_emission(n=64)
    
    assert len(samples) > 0, "Should generate NTT samples"
    assert all(s.operation == "ntt_butterfly" for s in samples), "All should be NTT butterfly"
    
    # Test correlation analysis
    analysis = analyzer.analyze_em_correlation(samples)
    
    assert "hw_em_correlation" in analysis, "Should have correlation metric"
    assert 0 <= analysis["hw_em_correlation"] <= 1.0, "Correlation should be in [0,1]"
    assert analysis["sample_count"] == len(samples), "Sample count should match"
    
    print("  ✓ NTT Emission Simulation tests passed")
    return True


def test_gaussian_sampling_emission():
    """Test Gaussian sampling emission simulation"""
    print("Testing Gaussian Sampling Emission...")
    
    analyzer = LatticeOperationAnalyzer()
    
    samples = analyzer.simulate_gaussian_sampling_emission(sample_count=50)
    
    assert len(samples) > 0, "Should generate sampling samples"
    assert any("gaussian_sampling" in s.operation for s in samples), "Should have sampling ops"
    
    analysis = analyzer.analyze_em_correlation(samples)
    
    assert "mean_em_amplitude" in analysis, "Should have mean amplitude"
    assert analysis["mean_em_amplitude"] > 0, "Mean amplitude should be positive"
    
    print("  ✓ Gaussian Sampling Emission tests passed")
    return True


def test_em_correlation_analysis():
    """Test EM correlation analysis"""
    print("Testing EM Correlation Analysis...")
    
    analyzer = LatticeOperationAnalyzer()
    
    # Create controlled samples for correlation test
    coeffs = list(range(100))  # Linear progression
    samples = analyzer.simulate_polynomial_mult_emission(coeffs)
    
    analysis = analyzer.analyze_em_correlation(samples)
    
    # Correlation should be measurable
    assert 0 <= analysis["hw_em_correlation"] <= 1.0, "Correlation bounds check"
    assert "frequency_distribution" in analysis, "Should have frequency distribution"
    assert "operation_distribution" in analysis, "Should have operation distribution"
    
    print("  ✓ EM Correlation Analysis tests passed")
    return True


def test_cpa_attack_simulator():
    """Test CPA Attack Simulator"""
    print("Testing CPA Attack Simulator...")
    
    simulator = EMCorrelationAttackSimulator()
    
    # Test trace generation
    trace = simulator.generate_trace(0xAB, secrets.token_bytes(32))
    
    assert "hypothesis" in trace, "Should have hypothesis"
    assert "intermediate_hw" in trace, "Should have intermediate HW"
    assert "trace" in trace, "Should have trace points"
    assert len(trace["trace"]) == 50, "Should have 50 trace points"
    
    # Test attack simulation
    result = simulator.run_cpa_attack_simulation(true_secret=0xCD, num_traces=100)
    
    assert "attack_success" in result, "Should have attack success flag"
    assert "resistance_score" in result, "Should have resistance score"
    assert 0 <= result["resistance_score"] <= 1.0, "Resistance score bounds"
    assert result["traces_used"] == 100, "Trace count should match"
    
    print("  ✓ CPA Attack Simulator tests passed")
    return True


def test_polynomial_multiplication_validation():
    """Test polynomial multiplication validation"""
    print("Testing Polynomial Multiplication Validation...")
    
    validator = EMSideChannelValidator()
    
    result = validator.validate_polynomial_multiplication(poly_size=128)
    
    assert isinstance(result, EMLeakageResult), "Should return EMLeakageResult"
    assert result.test_name == "polynomial_multiplication_em_leakage"
    assert 0 <= result.correlation_score <= 1.0, "Correlation score bounds"
    assert result.leakage_severity in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert len(result.countermeasures_recommended) > 0, "Should have recommendations"
    
    print("  ✓ Polynomial Multiplication Validation tests passed")
    return True


def test_ntt_validation():
    """Test NTT operation validation"""
    print("Testing NTT Operation Validation...")
    
    validator = EMSideChannelValidator()
    
    result = validator.validate_ntt_operation(n=128)
    
    assert isinstance(result, EMLeakageResult)
    assert result.test_name == "ntt_operation_em_leakage"
    assert "adjusted_correlation" in result.details, "Should have adjusted correlation"
    
    print("  ✓ NTT Operation Validation tests passed")
    return True


def test_gaussian_sampling_validation():
    """Test Gaussian sampling validation"""
    print("Testing Gaussian Sampling Validation...")
    
    validator = EMSideChannelValidator()
    
    result = validator.validate_gaussian_sampling(samples=100)
    
    assert isinstance(result, EMLeakageResult)
    assert result.test_name == "gaussian_sampling_em_leakage"
    assert "sampling_penalty_applied" in result.details
    
    print("  ✓ Gaussian Sampling Validation tests passed")
    return True


def test_cpa_resistance_validation():
    """Test CEMA resistance validation"""
    print("Testing CEMA Resistance Validation...")
    
    validator = EMSideChannelValidator()
    
    result = validator.validate_cpa_resistance(secret=0x5A, traces=200)
    
    assert isinstance(result, EMLeakageResult)
    assert result.test_name == "correlation_em_analysis_resistance"
    assert "attack_success" in result.details
    assert "resistance_score" in result.details
    
    print("  ✓ CEMA Resistance Validation tests passed")
    return True


def test_full_em_validation_suite():
    """Test complete EM validation suite"""
    print("Testing Full EM Validation Suite...")
    
    validator = EMSideChannelValidator()
    
    result = validator.run_full_em_validation(algorithm_name="KYBER-768_TEST")
    
    assert "validator_version" in result
    assert "overall_em_resistance_score" in result
    assert 0 <= result["overall_em_resistance_score"] <= 1.0
    assert "average_leakage_correlation" in result
    assert "tests_with_leakage" in result
    assert "critical_vulnerabilities" in result
    assert "detailed_results" in result
    assert len(result["detailed_results"]) == 4, "Should have 4 test results"
    assert "all_recommendations" in result
    
    # Verify all tests ran
    test_names = [r["test"] for r in result["detailed_results"]]
    assert "polynomial_multiplication_em_leakage" in test_names
    assert "ntt_operation_em_leakage" in test_names
    assert "gaussian_sampling_em_leakage" in test_names
    assert "correlation_em_analysis_resistance" in test_names
    
    print("  ✓ Full EM Validation Suite tests passed")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("Post-Quantum EM Side-Channel Validator - Test Suite")
    print("=" * 70)
    
    tests = [
        test_lattice_analyzer_basic,
        test_ntt_emission_simulation,
        test_gaussian_sampling_emission,
        test_em_correlation_analysis,
        test_cpa_attack_simulator,
        test_polynomial_multiplication_validation,
        test_ntt_validation,
        test_gaussian_sampling_validation,
        test_cpa_resistance_validation,
        test_full_em_validation_suite
    ]
    
    results = []
    start_time = time.time()
    
    for test_func in tests:
        try:
            result = test_func()
            results.append((test_func.__name__, result, None))
        except Exception as e:
            results.append((test_func.__name__, False, str(e)))
            print(f"  ✗ FAILED: {e}")
    
    elapsed = time.time() - start_time
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, r, _ in results if r)
    total = len(results)
    
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}")
    print(f"Total time: {elapsed:.3f}s")
    
    print("\nDetailed results:")
    for name, result, error in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
        if error:
            print(f"       Error: {error}")
    
    # Save test results
    test_results = {
        "test_version": "em_side_channel_2026_june_v1",
        "timestamp": time.time(),
        "total_tests": total,
        "passed": passed,
        "failed": total - passed,
        "elapsed_seconds": round(elapsed, 3),
        "results": [{"name": n, "passed": r, "error": e} for n, r, e in results]
    }
    
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_post_quantum_em_side_channel_2026_june.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to JSON file")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
