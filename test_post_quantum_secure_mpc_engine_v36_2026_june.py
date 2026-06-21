#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure MPC Engine v36
Real working tests with actual cryptographic assertions
"""

import json
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_mpc_engine_v36_2026_june import (
    PostQuantumSecureMPCEngineV36,
    Share,
    MPCOperationResult,
    SecurityLevel,
    SideChannelResistantRNG,
    ConstantTimeMath,
)


def test_rng_basic():
    """Test side-channel resistant RNG"""
    print("Test 1: Side-Channel Resistant RNG")
    
    rng = SideChannelResistantRNG(SecurityLevel.HIGH)
    
    # Test random int generation
    values = [rng.random_int(1000) for _ in range(100)]
    for v in values:
        assert 0 <= v < 1000, f"Value {v} out of range [0, 1000)"
    
    # Verify distribution is somewhat uniform (basic sanity check)
    unique_values = len(set(values))
    assert unique_values > 50, f"Should have good distribution, got only {unique_values} unique"
    
    print(f"  ✓ Generated 100 values, {unique_values} unique")
    print("  ✓ RNG works correctly with side-channel protection")
    
    return True


def test_constant_time_math():
    """Test constant-time math operations"""
    print("\nTest 2: Constant-Time Math Operations")
    
    # Test modular inverse
    prime = 2**256 - 189
    for a in [7, 42, 12345, 999999]:
        inv = ConstantTimeMath.ct_mod_inverse(a, prime)
        result = (a * inv) % prime
        assert result == 1, f"Modular inverse failed for {a}: (a * inv) % p = {result}"
        print(f"  ✓ Modular inverse: {a} * {inv} mod p = 1")
    
    # Test constant-time select
    assert ConstantTimeMath.ct_select(True, 100, 200) == 100
    assert ConstantTimeMath.ct_select(False, 100, 200) == 200
    print("  ✓ Constant-time selection works")
    
    return True


def test_mpc_engine_initialization():
    """Test MPC engine initialization"""
    print("\nTest 3: MPC Engine Initialization")
    
    # Test valid configurations
    engine = PostQuantumSecureMPCEngineV36(
        threshold=3,
        total_shares=5,
        security_level=SecurityLevel.HIGH
    )
    
    params = engine.get_security_parameters()
    assert params['threshold'] == 3
    assert params['total_shares'] == 5
    assert params['security_level'] == 'HIGH'
    assert params['version'] == 'v36'
    
    print(f"  ✓ Engine initialized: t={params['threshold']}, n={params['total_shares']}")
    print(f"  ✓ Security: {params['security_bits']} bits, prime: {params['prime_size']} bits")
    
    # Test invalid threshold
    try:
        PostQuantumSecureMPCEngineV36(threshold=1, total_shares=5)
        assert False, "Should have raised ValueError for threshold < 2"
    except ValueError:
        print("  ✓ Correctly rejects threshold < 2")
    
    # Test threshold > total_shares
    try:
        PostQuantumSecureMPCEngineV36(threshold=10, total_shares=5)
        assert False, "Should have raised ValueError"
    except ValueError:
        print("  ✓ Correctly rejects threshold > total_shares")
    
    return True


def test_secret_sharing_basic():
    """Test basic secret splitting and reconstruction"""
    print("\nTest 4: Basic Secret Sharing (3-of-5)")
    
    engine = PostQuantumSecureMPCEngineV36(
        threshold=3,
        total_shares=5,
        security_level=SecurityLevel.HIGH
    )
    
    original_secret = 123456789
    
    # Split secret
    shares = engine.split_secret(original_secret)
    assert len(shares) == 5, f"Should have 5 shares, got {len(shares)}"
    
    # Verify all shares have correct structure
    for i, share in enumerate(shares, 1):
        assert share.index == i, f"Share index should be {i}"
        assert share.commitment, "Share should have commitment"
        assert engine.verify_share(share), "Share should pass verification"
    
    print(f"  ✓ Secret split into {len(shares)} shares")
    print("  ✓ All shares pass integrity verification")
    
    # Reconstruct with exactly threshold shares
    reconstruction_result = engine.reconstruct_secret(shares[:3])
    assert reconstruction_result.threshold_met == True
    assert reconstruction_result.verification_passed == True
    assert reconstruction_result.result == original_secret, \
        f"Reconstructed {reconstruction_result.result} != original {original_secret}"
    
    print(f"  ✓ Reconstructed with 3 shares: {reconstruction_result.result}")
    
    # Reconstruct with more than threshold
    result_all = engine.reconstruct_secret(shares)
    assert result_all.result == original_secret
    print(f"  ✓ Reconstructed with all 5 shares: {result_all.result}")
    
    return True


def test_threshold_enforcement():
    """Test that threshold is properly enforced"""
    print("\nTest 5: Threshold Enforcement")
    
    engine = PostQuantumSecureMPCEngineV36(
        threshold=3,
        total_shares=5,
        security_level=SecurityLevel.MEDIUM
    )
    
    secret = 987654321
    shares = engine.split_secret(secret)
    
    # Try to reconstruct with only 2 shares (below threshold)
    result = engine.reconstruct_secret(shares[:2])
    assert result.threshold_met == False, "Should fail threshold check"
    assert result.result == 0, "Should return 0 when threshold not met"
    
    print("  ✓ Correctly fails with 2 shares (below threshold 3)")
    print(f"  ✓ threshold_met = {result.threshold_met}")
    
    # Now with exactly threshold
    result_ok = engine.reconstruct_secret(shares[:3])
    assert result_ok.threshold_met == True
    assert result_ok.result == secret
    
    print("  ✓ Succeeds with 3 shares (meets threshold)")
    
    return True


def test_share_integrity_verification():
    """Test share integrity verification"""
    print("\nTest 6: Share Integrity Verification")
    
    engine = PostQuantumSecureMPCEngineV36(threshold=2, total_shares=3)
    shares = engine.split_secret(42)
    
    # Original shares should verify
    for share in shares:
        assert engine.verify_share(share) == True
    
    print("  ✓ All original shares verify correctly")
    
    # Tamper with a share
    tampered_share = Share(
        index=shares[0].index,
        value=999999,  # Tampered value
        prime=shares[0].prime,
        commitment=shares[0].commitment,
        share_id=shares[0].share_id
    )
    
    assert engine.verify_share(tampered_share) == False, "Tampered share should fail verification"
    print("  ✓ Tampered share correctly fails verification")
    
    # Reconstruction with tampered share should show verification failed
    result = engine.reconstruct_secret([tampered_share, shares[1]])
    assert result.verification_passed == False
    print("  ✓ Reconstruction correctly reports verification failure")
    
    return True


def test_homomorphic_addition():
    """Test homomorphic addition on shares"""
    print("\nTest 7: Homomorphic Addition")
    
    engine = PostQuantumSecureMPCEngineV36(threshold=2, total_shares=4)
    
    secret_a = 1000
    secret_b = 2000
    
    shares_a = engine.split_secret(secret_a)
    shares_b = engine.split_secret(secret_b)
    
    # Add shares homomorphically
    sum_shares = engine.secure_add(shares_a, shares_b)
    
    # Reconstruct sum
    result = engine.reconstruct_secret(sum_shares[:2])
    
    expected = (secret_a + secret_b) % engine.prime
    assert result.result == expected, f"Expected {expected}, got {result.result}"
    
    print(f"  ✓ {secret_a} + {secret_b} = {result.result}")
    print("  ✓ Homomorphic addition works correctly")
    
    return True


def test_scalar_multiplication():
    """Test scalar multiplication on shares"""
    print("\nTest 8: Scalar Multiplication")
    
    engine = PostQuantumSecureMPCEngineV36(threshold=2, total_shares=3)
    
    secret = 500
    constant = 7
    
    shares = engine.split_secret(secret)
    product_shares = engine.secure_multiply_constant(shares, constant)
    
    result = engine.reconstruct_secret(product_shares[:2])
    
    expected = (secret * constant) % engine.prime
    assert result.result == expected, f"Expected {expected}, got {result.result}"
    
    print(f"  ✓ {secret} * {constant} = {result.result}")
    print("  ✓ Homomorphic scalar multiplication works")
    
    return True


def test_different_share_combinations():
    """Test reconstruction with different share combinations"""
    print("\nTest 9: Different Share Combinations")
    
    engine = PostQuantumSecureMPCEngineV36(threshold=3, total_shares=6)
    secret = 12345
    shares = engine.split_secret(secret)
    
    # Test different combinations
    combinations = [
        [0, 1, 2],      # First 3
        [1, 3, 5],      # Spread out
        [2, 4, 5],      # Last 3
        [0, 2, 4, 5],   # 4 shares
    ]
    
    for combo in combinations:
        selected_shares = [shares[i] for i in combo]
        result = engine.reconstruct_secret(selected_shares)
        assert result.result == secret, f"Combo {combo} failed: {result.result} != {secret}"
        print(f"  ✓ Combo {combo}: reconstructed correctly")
    
    print("  ✓ All share combinations produce correct result")
    
    return True


def test_secure_comparison():
    """Test secure comparison operation"""
    print("\nTest 10: Secure Comparison")
    
    engine = PostQuantumSecureMPCEngineV36(threshold=2, total_shares=3)
    
    # Test a > b
    shares_100 = engine.split_secret(100)
    shares_50 = engine.split_secret(50)
    
    result = engine.secure_compare(shares_100[:2], shares_50[:2])
    assert result.result == 1, "100 > 50 should return 1"
    assert result.threshold_met == True
    print(f"  ✓ 100 > 50 = {result.result} (correct)")
    
    # Test a < b
    result2 = engine.secure_compare(shares_50[:2], shares_100[:2])
    assert result2.result == 0, "50 > 100 should return 0"
    print(f"  ✓ 50 > 100 = {result2.result} (correct)")
    
    return True


def test_random_shares_generation():
    """Test verifiable random shares generation"""
    print("\nTest 11: Random Shares Generation")
    
    engine = PostQuantumSecureMPCEngineV36(threshold=2, total_shares=3)
    
    # Generate multiple random secret shares
    results = []
    for _ in range(5):
        shares = engine.generate_verifiable_random_shares()
        result = engine.reconstruct_secret(shares[:2])
        results.append(result.result)
        assert result.verification_passed == True
        print(f"  ✓ Random secret: {result.result}")
    
    # Should have different values (with high probability)
    unique_random = len(set(results))
    assert unique_random >= 3, f"Should have diverse random values, got only {unique_random}"
    print(f"  ✓ Generated {unique_random} unique random secrets")
    
    return True


def test_zeroize_security():
    """Test zeroize functionality"""
    print("\nTest 12: Zeroize Security")
    
    engine = PostQuantumSecureMPCEngineV36(threshold=2, total_shares=3)
    
    # Perform some operations
    shares = engine.split_secret(42)
    engine.reconstruct_secret(shares[:2])
    
    # Zeroize
    engine.zeroize()
    
    # Verification key should be zeros
    assert all(b == 0 for b in engine.verification_key)
    assert len(engine.rng._entropy_pool) == 0
    
    print("  ✓ Verification key zeroized")
    print("  ✓ Entropy pool cleared")
    print("  ✓ Forward security maintained")
    
    return True


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("Post-Quantum Secure MPC Engine v36 - Test Suite")
    print("=" * 60)
    
    tests = [
        test_rng_basic,
        test_constant_time_math,
        test_mpc_engine_initialization,
        test_secret_sharing_basic,
        test_threshold_enforcement,
        test_share_integrity_verification,
        test_homomorphic_addition,
        test_scalar_multiplication,
        test_different_share_combinations,
        test_secure_comparison,
        test_random_shares_generation,
        test_zeroize_security,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            failed += 1
            print(f"  ✗ FAILED: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} passed, {failed} failed")
    print("=" * 60)
    
    # Save test results
    results = {
        "test_suite": "post_quantum_secure_mpc_engine_v36",
        "version": "v36",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": f"{(passed/len(tests)*100):.1f}%",
        "timestamp": __import__('datetime').datetime.utcnow().isoformat()
    }
    
    with open("test_results_post_quantum_secure_mpc_engine_v36_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to test_results_post_quantum_secure_mpc_engine_v36_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
