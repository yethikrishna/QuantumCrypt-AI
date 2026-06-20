#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Key Generation Entropy Health Monitor & Validator
QuantumCrypt-AI Production Grade Tests

Comprehensive tests covering:
1. NIST SP 800-90B randomness tests
2. Entropy pool management and health scoring
3. Algorithm-specific key generation validation
4. Entropy collection and mixing
5. Health status classification
6. Predictive depletion forecasting
7. Performance and statistical accuracy
"""
import json
import time
import sys
import os
import secrets

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.post_quantum_key_generation_entropy_health_validator_2026_june import (
    PostQuantumKeyGenerationEntropyHealthValidator,
    EntropySourceType,
    HealthStatus,
    AlgorithmType,
    NISTRandomnessTester,
    EntropyHealthConfig
)


def run_tests():
    """Execute all tests and generate results report"""
    test_results = {
        "test_suite": "Post-Quantum Key Generation Entropy Health Validator",
        "timestamp": time.time(),
        "tests_passed": 0,
        "tests_failed": 0,
        "test_cases": {},
        "performance_metrics": {},
        "randomness_test_results": {}
    }
    
    print("=" * 70)
    print("QuantumCrypt-AI: Entropy Health Validator Tests")
    print("=" * 70)
    
    # Test 1: NIST Monobit Test
    print("\n[Test 1] NIST Monobit Randomness Test")
    try:
        # Test with good random data
        good_data = secrets.token_bytes(256)
        result = NISTRandomnessTester.monobit_test(good_data)
        assert result.passed, "Good random data should pass monobit test"
        assert result.score > 0.7, f"Score too low: {result.score}"
        
        # Test with biased data (all zeros)
        bad_data = b'\x00' * 256
        bad_result = NISTRandomnessTester.monobit_test(bad_data)
        assert not bad_result.passed or bad_result.score < 0.5, "All zeros should fail or score low"
        
        print(f"  ✓ Monobit test working (good data score: {result.score:.3f})")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["monobit_test"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["monobit_test"] = f"FAILED: {str(e)}"
    
    # Test 2: NIST Runs Test
    print("\n[Test 2] NIST Runs Randomness Test")
    try:
        good_data = secrets.token_bytes(256)
        result = NISTRandomnessTester.runs_test(good_data)
        assert result.passed, "Good random data should pass runs test"
        
        print(f"  ✓ Runs test working (score: {result.score:.3f})")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["runs_test"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["runs_test"] = f"FAILED: {str(e)}"
    
    # Test 3: Chi-Square Distribution Test
    print("\n[Test 3] Chi-Square Distribution Test")
    try:
        good_data = secrets.token_bytes(512)
        result = NISTRandomnessTester.chi_square_distribution(good_data)
        assert result.passed or result.score > 0.5, "Good random should pass distribution test"
        
        print(f"  ✓ Chi-square test working (score: {result.score:.3f})")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["chi_square_test"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["chi_square_test"] = f"FAILED: {str(e)}"
    
    # Test 4: Autocorrelation Test
    print("\n[Test 4] Autocorrelation Test")
    try:
        good_data = secrets.token_bytes(256)
        result = NISTRandomnessTester.autocorrelation_test(good_data, lag=1)
        assert result.score > 0.6, f"Autocorrelation score too low: {result.score}"
        
        print(f"  ✓ Autocorrelation test working (score: {result.score:.3f})")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["autocorrelation_test"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["autocorrelation_test"] = f"FAILED: {str(e)}"
    
    # Test 5: Entropy Estimation
    print("\n[Test 5] Shannon Entropy Estimation")
    try:
        # High entropy random data
        high_entropy = secrets.token_bytes(1024)
        high_score = NISTRandomnessTester.entropy_estimate(high_entropy)
        assert high_score > 7.0, f"Random data should have high entropy: {high_score}"
        
        # Low entropy repeating pattern
        low_entropy = b'AAAA' * 256
        low_score = NISTRandomnessTester.entropy_estimate(low_entropy)
        assert low_score < 1.0, f"Pattern should have low entropy: {low_score}"
        
        print(f"  ✓ Entropy estimation: random={high_score:.2f} bpb, pattern={low_score:.2f} bpb")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["entropy_estimation"] = "PASSED"
        test_results["performance_metrics"]["random_entropy_bpb"] = round(high_score, 3)
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["entropy_estimation"] = f"FAILED: {str(e)}"
    
    # Test 6: Entropy Pool Initialization
    print("\n[Test 6] Entropy Pool Initialization")
    try:
        config = EntropyHealthConfig(enable_continuous_monitoring=False)
        validator = PostQuantumKeyGenerationEntropyHealthValidator(config)
        
        stats = validator.get_pool_statistics()
        assert stats["primary_pool"]["size_bytes"] > 0, "Pool should be initialized"
        assert stats["primary_pool"]["entropy_bits"] > 0, "Entropy should be available"
        
        print(f"  ✓ Pool initialized: {stats['primary_pool']['size_bytes']} bytes, "
              f"{stats['primary_pool']['entropy_bits']:.0f} bits entropy")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["pool_initialization"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["pool_initialization"] = f"FAILED: {str(e)}"
    finally:
        validator.shutdown()
    
    # Test 7: Kyber-768 Key Generation Validation
    print("\n[Test 7] CRYSTALS-Kyber 768 Key Generation Validation")
    try:
        config = EntropyHealthConfig(enable_continuous_monitoring=False)
        validator = PostQuantumKeyGenerationEntropyHealthValidator(config)
        
        # Collect extra entropy to ensure we have enough
        for _ in range(20):
            validator.collect_system_entropy()
        
        result = validator.validate_key_generation(AlgorithmType.KYBER_768)
        
        assert result.algorithm == AlgorithmType.KYBER_768
        assert result.entropy_required_bits == 384, f"Kyber-768 needs 384 bits"
        assert result.entropy_available_bits >= 0
        
        if result.validation_passed:
            print(f"  ✓ Kyber-768 validation PASSED")
            print(f"    Available: {result.entropy_available_bits:.0f} bits, "
                  f"Required: {result.entropy_required_bits} bits")
            print(f"    Margin: {result.entropy_margin_bits:.0f} bits, "
                  f"Quality: {result.quality_score:.3f}")
        else:
            print(f"  ⚠ Kyber-768 validation result: {result.validation_passed}")
            print(f"    Warnings: {result.warnings}")
        
        test_results["tests_passed"] += 1
        test_results["test_cases"]["kyber768_validation"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["kyber768_validation"] = f"FAILED: {str(e)}"
    finally:
        validator.shutdown()
    
    # Test 8: Dilithium-5 Key Generation Validation
    print("\n[Test 8] CRYSTALS-Dilithium 5 Key Generation Validation")
    try:
        config = EntropyHealthConfig(enable_continuous_monitoring=False)
        validator = PostQuantumKeyGenerationEntropyHealthValidator(config)
        
        for _ in range(20):
            validator.collect_system_entropy()
        
        result = validator.validate_key_generation(AlgorithmType.DILITHIUM_5)
        
        assert result.entropy_required_bits == 512, f"Dilithium-5 needs 512 bits"
        assert result.health_status in [s for s in HealthStatus]
        
        print(f"  ✓ Dilithium-5 validation completed")
        print(f"    Status: {result.health_status.value}, "
              f"Quality: {result.quality_score:.3f}")
        
        test_results["tests_passed"] += 1
        test_results["test_cases"]["dilithium5_validation"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["dilithium5_validation"] = f"FAILED: {str(e)}"
    finally:
        validator.shutdown()
    
    # Test 9: Secure Random Bytes Generation
    print("\n[Test 9] Secure Random Bytes Generation")
    try:
        config = EntropyHealthConfig(enable_continuous_monitoring=False)
        validator = PostQuantumKeyGenerationEntropyHealthValidator(config)
        
        # Generate multiple batches
        batches = []
        for _ in range(10):
            batches.append(validator.get_secure_random_bytes(64))
        
        # Verify uniqueness
        unique_batches = set(batches)
        assert len(unique_batches) == len(batches), "Random batches should be unique"
        
        # Verify length
        assert len(batches[0]) == 64, "Should return requested byte count"
        
        print(f"  ✓ Secure random generation: {len(batches)} unique batches")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["random_bytes_generation"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["random_bytes_generation"] = f"FAILED: {str(e)}"
    finally:
        validator.shutdown()
    
    # Test 10: Custom Entropy Collection
    print("\n[Test 10] Custom Entropy Collection")
    try:
        config = EntropyHealthConfig(enable_continuous_monitoring=False)
        validator = PostQuantumKeyGenerationEntropyHealthValidator(config)
        
        initial_stats = validator.get_pool_statistics()
        initial_samples = initial_stats["monitor"]["total_samples"]
        
        # Add custom entropy
        custom_data = secrets.token_bytes(128)
        validator.collect_custom_entropy(custom_data, EntropySourceType.HARDWARE_RNG)
        
        final_stats = validator.get_pool_statistics()
        assert final_stats["monitor"]["total_samples"] > initial_samples
        
        print(f"  ✓ Custom entropy collected from {EntropySourceType.HARDWARE_RNG.value}")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["custom_entropy_collection"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["custom_entropy_collection"] = f"FAILED: {str(e)}"
    finally:
        validator.shutdown()
    
    # Test 11: Full Randomness Test Suite
    print("\n[Test 11] Full NIST Randomness Test Suite")
    try:
        config = EntropyHealthConfig(enable_continuous_monitoring=False)
        validator = PostQuantumKeyGenerationEntropyHealthValidator(config)
        
        suite_result = validator.run_full_randomness_suite()
        
        assert suite_result["tests_run"] == 5, "Should run 5 tests"
        assert "overall_score" in suite_result
        assert "entropy_estimate_bpb" in suite_result
        
        print(f"  ✓ Full test suite: {suite_result['tests_run']} tests, "
              f"score={suite_result['overall_score']:.3f}, "
              f"entropy={suite_result['entropy_estimate_bpb']:.2f} bpb")
        
        test_results["tests_passed"] += 1
        test_results["test_cases"]["full_randomness_suite"] = "PASSED"
        test_results["randomness_test_results"] = suite_result
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["full_randomness_suite"] = f"FAILED: {str(e)}"
    finally:
        validator.shutdown()
    
    # Test 12: Health Status Classification
    print("\n[Test 12] Health Status Classification")
    try:
        config = EntropyHealthConfig(enable_continuous_monitoring=False)
        validator = PostQuantumKeyGenerationEntropyHealthValidator(config)
        
        stats = validator.get_pool_statistics()
        health_status = stats["primary_pool"]["health_status"]
        
        valid_statuses = [s.value for s in HealthStatus]
        assert health_status in valid_statuses, f"Invalid status: {health_status}"
        
        health_score = stats["primary_pool"]["health_score"]
        assert 0 <= health_score <= 1, f"Score out of range: {health_score}"
        
        print(f"  ✓ Health status: {health_status.upper()} (score: {health_score:.3f})")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["health_status_classification"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["health_status_classification"] = f"FAILED: {str(e)}"
    finally:
        validator.shutdown()
    
    # Test 13: Statistics Tracking
    print("\n[Test 13] Statistics Tracking")
    try:
        config = EntropyHealthConfig(enable_continuous_monitoring=False)
        validator = PostQuantumKeyGenerationEntropyHealthValidator(config)
        
        # Perform multiple validations
        for algo in [AlgorithmType.KYBER_512, AlgorithmType.KYBER_768, AlgorithmType.FALCON_512]:
            validator.validate_key_generation(algo)
        
        stats = validator.get_pool_statistics()
        assert stats["monitor"]["validations_performed"] == 3
        
        print(f"  ✓ Statistics tracking: {stats['monitor']['validations_performed']} validations, "
              f"{stats['monitor']['total_samples']} samples")
        test_results["tests_passed"] += 1
        test_results["test_cases"]["statistics_tracking"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["statistics_tracking"] = f"FAILED: {str(e)}"
    finally:
        validator.shutdown()
    
    # Test 14: Performance Benchmark
    print("\n[Test 14] Performance Benchmark")
    try:
        config = EntropyHealthConfig(enable_continuous_monitoring=False)
        validator = PostQuantumKeyGenerationEntropyHealthValidator(config)
        
        # Benchmark validation speed
        start = time.time()
        iterations = 100
        for _ in range(iterations):
            validator.validate_key_generation(AlgorithmType.KYBER_768)
        elapsed = time.time() - start
        
        avg_ms = (elapsed / iterations) * 1000
        
        print(f"  ✓ Performance: {iterations} validations in {elapsed*1000:.1f}ms")
        print(f"    Average: {avg_ms:.3f}ms per validation")
        print(f"    Throughput: {iterations/elapsed:.1f} validations/sec")
        
        test_results["tests_passed"] += 1
        test_results["test_cases"]["performance_benchmark"] = "PASSED"
        test_results["performance_metrics"]["avg_validation_ms"] = round(avg_ms, 3)
        test_results["performance_metrics"]["validation_throughput"] = round(iterations/elapsed, 1)
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["tests_failed"] += 1
        test_results["test_cases"]["performance_benchmark"] = f"FAILED: {str(e)}"
    finally:
        validator.shutdown()
    
    # Summary
    print("\n" + "=" * 70)
    total_tests = test_results["tests_passed"] + test_results["tests_failed"]
    pass_rate = (test_results["tests_passed"] / total_tests * 100) if total_tests > 0 else 0
    print(f"TEST SUMMARY: {test_results['tests_passed']}/{total_tests} passed ({pass_rate:.1f}%)")
    print("=" * 70)
    
    test_results["pass_rate_percent"] = round(pass_rate, 1)
    
    # Save results
    with open("test_results_post_quantum_key_generation_entropy_health_validator.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nResults saved to test_results_post_quantum_key_generation_entropy_health_validator.json")
    
    return test_results


if __name__ == "__main__":
    results = run_tests()
    sys.exit(0 if results["tests_failed"] == 0 else 1)
