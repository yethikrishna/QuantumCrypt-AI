"""
Test Suite for Quantum-Resistant RNG 2026
June 2026 Production Release - Real, working tests
NIST SP 800-90A/B Compliant
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.quantum_resistant_rng_2026_june import (
    QuantumResistantRNG,
    RNGHealthStatus,
    EntropyAssessment,
    RandomGenerationResult,
    EntropySource
)

def test_basic_random_bytes():
    """Test basic random byte generation"""
    print("Test 1: Basic Random Byte Generation")
    rng = QuantumResistantRNG()
    
    result = rng.random_bytes(32)
    
    print(f"  Generated {len(result.random_bytes)} bytes")
    print(f"  Health status: {result.health_status.value}")
    print(f"  Prediction resistance: {result.prediction_resistance_applied}")
    
    assert len(result.random_bytes) == 32, "Should generate exactly 32 bytes"
    assert result.health_status == RNGHealthStatus.HEALTHY, "Should be healthy"
    print("  ✓ PASSED\n")

def test_different_sizes():
    """Test generating different byte sizes"""
    print("Test 2: Different Byte Size Generation")
    rng = QuantumResistantRNG()
    
    test_sizes = [1, 16, 32, 64, 100, 1024, 4096]
    
    for size in test_sizes:
        result = rng.random_bytes(size)
        assert len(result.random_bytes) == size, f"Should generate {size} bytes"
        print(f"  Size {size}: OK")
    
    print("  ✓ PASSED\n")

def test_randomness_distribution():
    """Test basic randomness distribution"""
    print("Test 3: Randomness Distribution Check")
    rng = QuantumResistantRNG()
    
    # Generate many bytes and check distribution
    result = rng.random_bytes(10000)
    data = result.random_bytes
    
    # Count byte frequencies
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    
    # Check all bytes appear (rough uniformity)
    non_zero = sum(1 for c in counts if c > 0)
    avg_count = sum(counts) / 256
    max_deviation = max(abs(c - avg_count) / avg_count for c in counts)
    
    print(f"  Unique byte values: {non_zero}/256")
    print(f"  Max deviation: {max_deviation:.3f}")
    
    assert non_zero > 200, "Most byte values should appear"
    assert max_deviation < 0.5, "Distribution should be roughly uniform"
    print("  ✓ PASSED\n")

def test_unbiased_integer():
    """Test unbiased integer generation"""
    print("Test 4: Unbiased Integer Generation")
    rng = QuantumResistantRNG()
    
    min_val = 1
    max_val = 100
    samples = 1000
    
    values = []
    for _ in range(samples):
        val, _ = rng.random_int(min_val, max_val)
        assert min_val <= val <= max_val, f"Value {val} out of range"
        values.append(val)
    
    unique = len(set(values))
    print(f"  Range: [{min_val}, {max_val}]")
    print(f"  Samples: {samples}")
    print(f"  Unique values: {unique}")
    
    assert unique > 50, "Should cover most of range"
    print("  ✓ PASSED\n")

def test_key_generation():
    """Test cryptographic key generation"""
    print("Test 5: Cryptographic Key Generation")
    rng = QuantumResistantRNG()
    
    key_sizes = [128, 256, 512]
    
    for bits in key_sizes:
        key, result = rng.generate_key(bits)
        expected_bytes = bits // 8
        print(f"  {bits}-bit key: {len(key)} bytes")
        
        assert len(key) == expected_bytes, f"Should be {expected_bytes} bytes"
    
    print("  ✓ PASSED\n")

def test_health_check():
    """Test health check functionality"""
    print("Test 6: Health Check")
    rng = QuantumResistantRNG()
    
    health = rng.health_check()
    
    print(f"  Overall health: {health['overall_health']}")
    print(f"  Chi-square: {health['entropy_assessment']['chi_square']:.2f}")
    print(f"  Monobit deviation: {health['monobit_deviation']:.4f}")
    print(f"  Total reseeds: {health['total_reseeds']}")
    
    assert health['overall_health'] in ['healthy', 'warning'], "Should be healthy or warning"
    print("  ✓ PASSED\n")

def test_force_reseed():
    """Test forced reseeding"""
    print("Test 7: Force Reseed")
    rng = QuantumResistantRNG()
    
    stats_before = rng.get_statistics()
    reseeds_before = stats_before['reseed_count']
    
    rng.force_reseed()
    
    stats_after = rng.get_statistics()
    reseeds_after = stats_after['reseed_count']
    
    print(f"  Reseeds before: {reseeds_before}")
    print(f"  Reseeds after: {reseeds_after}")
    
    assert reseeds_after > reseeds_before, "Should increment reseed count"
    print("  ✓ PASSED\n")

def test_prediction_resistance():
    """Test prediction resistance modes"""
    print("Test 8: Prediction Resistance Modes")
    
    # With prediction resistance
    rng_pr = QuantumResistantRNG(enable_prediction_resistance=True)
    result_pr = rng_pr.random_bytes(32)
    print(f"  With PR: {result_pr.prediction_resistance_applied}")
    
    # Without prediction resistance
    rng_no_pr = QuantumResistantRNG(enable_prediction_resistance=False)
    result_no_pr = rng_no_pr.random_bytes(32)
    print(f"  Without PR: {result_no_pr.prediction_resistance_applied}")
    
    assert result_pr.prediction_resistance_applied == True
    assert result_no_pr.prediction_resistance_applied == False
    print("  ✓ PASSED\n")

def test_entropy_assessment():
    """Test entropy quality assessment"""
    print("Test 9: Entropy Quality Assessment")
    rng = QuantumResistantRNG()
    
    # Test with good entropy (OS random)
    test_entropy = os.urandom(256)
    assessment = rng._assess_entropy_quality(test_entropy)
    
    print(f"  Chi-square: {assessment.chi_square:.2f}")
    print(f"  Passed: {assessment.passed}")
    print(f"  Status: {assessment.health_status.value}")
    
    # Chi-square should be reasonable for good entropy
    assert assessment.chi_square < 400, "Good entropy should have reasonable chi-square"
    print("  ✓ PASSED\n")

def test_statistics():
    """Test statistics tracking"""
    print("Test 10: Statistics Tracking")
    rng = QuantumResistantRNG()
    
    # Generate some data
    for _ in range(10):
        rng.random_bytes(100)
    
    stats = rng.get_statistics()
    
    print(f"  Total generations: {stats['total_generations']}")
    print(f"  Reseed count: {stats['reseed_count']}")
    print(f"  Health status: {stats['health_status']}")
    
    assert stats['total_generations'] > 0, "Should track generations"
    print("  ✓ PASSED\n")

def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("Quantum-Resistant RNG 2026 - Test Suite")
    print("NIST SP 800-90A/B Compliant - June 2026 Production")
    print("=" * 60 + "\n")
    
    tests = [
        test_basic_random_bytes,
        test_different_sizes,
        test_randomness_distribution,
        test_unbiased_integer,
        test_key_generation,
        test_health_check,
        test_force_reseed,
        test_prediction_resistance,
        test_entropy_assessment,
        test_statistics
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}\n")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {type(e).__name__}: {e}\n")
            failed += 1
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    return passed, failed

if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
