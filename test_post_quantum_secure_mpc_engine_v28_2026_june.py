#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Multi-Party Computation Engine v28
Production-grade tests with comprehensive security coverage
"""

import json
import time
import sys
import os

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_mpc_engine_v28_2026_june import (
    PostQuantumSecureMPCEngineV28,
    SecurityLevel,
    SecureRandom,
    SideChannelResistantOps,
    VerifiableShamirSecretSharing,
    AdditiveSecretSharing,
    SecretShare
)


def test_secure_random_generation():
    """Test cryptographically secure random generation"""
    print("Testing SecureRandom...")
    
    # Test random int generation
    rand1 = SecureRandom.random_int(256)
    rand2 = SecureRandom.random_int(256)
    assert rand1 != rand2, "Random numbers should be different"
    assert rand1.bit_length() <= 256, "Should respect bit length"
    
    # Test random range
    ranged = SecureRandom.random_int_range(100, 200)
    assert 100 <= ranged < 200, "Should be within range"
    
    # Test random bytes
    bytes_val = SecureRandom.random_bytes(32)
    assert len(bytes_val) == 32, "Should return correct byte count"
    
    print("  ✓ SecureRandom tests passed")
    return True


def test_side_channel_operations():
    """Test side-channel resistant operations"""
    print("Testing SideChannelResistantOps...")
    
    # Test constant time compare
    assert SideChannelResistantOps.constant_time_compare(b"test", b"test") == True
    assert SideChannelResistantOps.constant_time_compare(b"test", b"other") == False
    
    # Test constant time int compare
    assert SideChannelResistantOps.constant_time_int_compare(42, 42) == True
    assert SideChannelResistantOps.constant_time_int_compare(42, 99) == False
    
    # Test secure zero memory
    buffer = bytearray(b"sensitive data")
    SideChannelResistantOps.secure_zero_memory(buffer)
    assert all(b == 0 for b in buffer), "Memory should be zeroed"
    
    print("  ✓ SideChannelResistantOps tests passed")
    return True


def test_shamir_secret_sharing_basic():
    """Test basic Shamir secret sharing functionality"""
    print("Testing Shamir Secret Sharing...")
    
    vsss = VerifiableShamirSecretSharing(SecurityLevel.HIGH)
    
    # Test splitting and reconstruction
    secret = 123456789
    shares = vsss.split_secret(secret, 5, 3)
    
    assert len(shares) == 5, "Should create 5 shares"
    assert all(isinstance(s, SecretShare) for s in shares), "All should be SecretShare"
    
    # Reconstruct with threshold shares
    reconstructed, verified = vsss.reconstruct_secret(shares[:3])
    assert reconstructed == secret, f"Should reconstruct correctly, got {reconstructed} vs {secret}"
    assert verified == True, "Integrity should verify"
    
    # Reconstruct with more than threshold
    reconstructed2, verified2 = vsss.reconstruct_secret(shares)
    assert reconstructed2 == secret, "Should reconstruct with all shares"
    
    print("  ✓ Shamir Secret Sharing basic tests passed")
    return True


def test_shamir_threshold_enforcement():
    """Test threshold enforcement in Shamir sharing"""
    print("Testing Shamir threshold enforcement...")
    
    vsss = VerifiableShamirSecretSharing(SecurityLevel.HIGH)
    
    secret = 9876543210123456789
    shares = vsss.split_secret(secret, 5, 4)  # 4-of-5
    
    # With insufficient shares (2 < 4), should NOT reconstruct correctly
    reconstructed, _ = vsss.reconstruct_secret(shares[:2])
    assert reconstructed != secret, "Insufficient shares should NOT reconstruct correctly"
    
    # With exactly threshold
    reconstructed4, _ = vsss.reconstruct_secret(shares[:4])
    assert reconstructed4 == secret, "Exactly threshold should reconstruct"
    
    print("  ✓ Shamir threshold enforcement tests passed")
    return True


def test_share_integrity_verification():
    """Test share integrity verification"""
    print("Testing share integrity verification...")
    
    vsss = VerifiableShamirSecretSharing(SecurityLevel.HIGH)
    
    secret = 42
    shares = vsss.split_secret(secret, 3, 2)
    
    # All shares should verify
    vkey = vsss.get_verification_key()
    for share in shares:
        assert share.verify_integrity(vkey) == True, "Share integrity should verify"
    
    # Tamper with a share
    shares[0].value = 999999
    assert shares[0].verify_integrity(vkey) == False, "Tampered share should fail verification"
    
    print("  ✓ Share integrity verification tests passed")
    return True


def test_additive_secret_sharing():
    """Test additive secret sharing"""
    print("Testing Additive Secret Sharing...")
    
    add_ss = AdditiveSecretSharing(SecurityLevel.HIGH)
    
    # Test basic split and reconstruct
    value = 12345
    shares = add_ss.create_additive_shares(value, 5)
    
    assert len(shares) == 5, "Should create 5 shares"
    reconstructed = add_ss.reconstruct_additive(shares)
    assert reconstructed == value, "Should reconstruct correctly"
    
    # Test secure addition
    value_a = 100
    value_b = 200
    shares_a = add_ss.create_additive_shares(value_a, 3)
    shares_b = add_ss.create_additive_shares(value_b, 3)
    
    result_shares = add_ss.secure_addition(shares_a, shares_b)
    result = add_ss.reconstruct_additive(result_shares)
    assert result == (300 % add_ss.prime), "Secure addition should work"
    
    print("  ✓ Additive Secret Sharing tests passed")
    return True


def test_mpc_engine_shamir_roundtrip():
    """Test MPC engine Shamir secret sharing roundtrip"""
    print("Testing MPC Engine - Shamir roundtrip...")
    
    engine = PostQuantumSecureMPCEngineV28(
        security_level=SecurityLevel.HIGH,
        default_num_parties=5,
        default_threshold=3
    )
    
    # Test with integer
    test_secret = 1234567890123456789
    result = engine.split_secret_shamir(test_secret, 5, 3)
    
    assert result.success == True, "Split should succeed"
    shares = result.result["shares"]
    
    # Reconstruct
    recon_result = engine.reconstruct_secret_shamir(shares[:3])
    assert recon_result.success == True, "Reconstruction should succeed"
    assert recon_result.result["reconstructed_secret"] == test_secret, "Should match original"
    assert recon_result.verification_passed == True, "Verification should pass"
    
    print("  ✓ MPC Engine Shamir roundtrip tests passed")
    return True


def test_mpc_engine_secure_addition():
    """Test MPC engine secure distributed addition"""
    print("Testing MPC Engine - Secure distributed addition...")
    
    engine = PostQuantumSecureMPCEngineV28(security_level=SecurityLevel.HIGH)
    
    result = engine.secure_distributed_addition(500, 700, 3)
    
    assert result.success == True, "Addition should succeed"
    assert result.result["result"] == 1200, "500 + 700 should equal 1200"
    assert result.verification_passed == True, "Verification should pass"
    assert result.participating_players == 3, "Should use 3 parties"
    
    print("  ✓ MPC Engine secure addition tests passed")
    return True


def test_mpc_engine_random_generation():
    """Test MPC engine verifiable random generation"""
    print("Testing MPC Engine - Verifiable random generation...")
    
    engine = PostQuantumSecureMPCEngineV28(security_level=SecurityLevel.HIGH)
    
    result = engine.generate_verifiable_random_shares(5, 3, bits=256)
    
    assert result.success == True, "Random generation should succeed"
    assert result.result["random_secret"] > 0, "Should generate non-zero random"
    assert result.result["bits"] == 256, "Should respect bit length"
    assert len(result.result["shares"]) == 5, "Should create 5 shares"
    
    # Reconstruct random
    shares = result.result["shares"]
    recon_result = engine.reconstruct_secret_shamir(shares[:3])
    assert recon_result.result["reconstructed_secret"] == result.result["random_secret"], "Should reconstruct"
    
    print("  ✓ MPC Engine random generation tests passed")
    return True


def test_mpc_engine_security_metrics():
    """Test MPC engine security metrics tracking"""
    print("Testing MPC Engine - Security metrics...")
    
    engine = PostQuantumSecureMPCEngineV28(security_level=SecurityLevel.HIGH)
    
    # Perform some operations
    for i in range(5):
        engine.split_secret_shamir(i * 1000, 3, 2)
    
    metrics = engine.get_security_metrics()
    
    assert metrics["version"] == "v28", "Should be version v28"
    assert metrics["security_level"] == "HIGH", "Should be HIGH security"
    assert metrics["metrics"]["total_secrets_split"] == 5, "Should track 5 splits"
    assert metrics["prime_field_size"] > 250, "Should have large prime field"
    assert "integrity_verification_rate_percent" in metrics, "Should have integrity rate"
    
    print("  ✓ MPC Engine security metrics tests passed")
    return True


def test_mpc_engine_security_self_test():
    """Test MPC engine comprehensive security self-test"""
    print("Testing MPC Engine - Security self-test...")
    
    engine = PostQuantumSecureMPCEngineV28(security_level=SecurityLevel.HIGH)
    
    self_test_results = engine.run_security_self_test()
    
    assert self_test_results["version"] == "v28", "Should be v28"
    assert len(self_test_results["tests_run"]) == 4, "Should run 4 self-tests"
    assert self_test_results["all_passed"] == True, "All self-tests should pass"
    
    for test in self_test_results["tests_run"]:
        assert test["passed"] == True, f"Test {test['name']} should pass"
    
    print("  ✓ MPC Engine security self-test passed")
    return True


def test_different_security_levels():
    """Test different security levels"""
    print("Testing different security levels...")
    
    for level in [SecurityLevel.LOW, SecurityLevel.MEDIUM, SecurityLevel.HIGH, SecurityLevel.QUANTUM]:
        engine = PostQuantumSecureMPCEngineV28(security_level=level)
        metrics = engine.get_security_metrics()
        
        assert metrics["security_bits"] == level.value, f"Should have {level.value} bits"
        
        # Test basic operation at each level
        result = engine.split_secret_shamir(42, 3, 2)
        assert result.success == True, f"Should work at {level.name} level"
    
    print("  ✓ All security level tests passed")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum Secure MPC Engine v28 - Test Suite")
    print("=" * 70)
    print()
    
    tests = [
        ("Secure Random Generation", test_secure_random_generation),
        ("Side-Channel Operations", test_side_channel_operations),
        ("Shamir Secret Sharing (Basic)", test_shamir_secret_sharing_basic),
        ("Shamir Threshold Enforcement", test_shamir_threshold_enforcement),
        ("Share Integrity Verification", test_share_integrity_verification),
        ("Additive Secret Sharing", test_additive_secret_sharing),
        ("MPC Engine Shamir Roundtrip", test_mpc_engine_shamir_roundtrip),
        ("MPC Engine Secure Addition", test_mpc_engine_secure_addition),
        ("MPC Engine Random Generation", test_mpc_engine_random_generation),
        ("MPC Engine Security Metrics", test_mpc_engine_security_metrics),
        ("MPC Engine Security Self-Test", test_mpc_engine_security_self_test),
        ("Different Security Levels", test_different_security_levels),
    ]
    
    results = []
    start_time = time.time()
    
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success, None))
        except Exception as e:
            results.append((test_name, False, str(e)))
            print(f"  ✗ FAILED: {e}")
    
    total_time = time.time() - start_time
    
    # Summary
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, s, _ in results if s)
    failed = len(results) - passed
    
    for test_name, success, error in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status} - {test_name}")
        if error:
            print(f"      Error: {error}")
    
    print()
    print(f"Total: {passed}/{len(results)} tests passed")
    print(f"Total time: {total_time:.3f}s")
    print()
    
    # Write test results to JSON
    test_results = {
        "test_suite": "Post-Quantum Secure MPC Engine v28",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": len(results),
        "passed": passed,
        "failed": failed,
        "success_rate": round(passed / len(results) * 100, 2),
        "total_time_seconds": round(total_time, 3),
        "results": [
            {"test": name, "passed": success, "error": error}
            for name, success, error in results
        ]
    }
    
    with open("test_results_post_quantum_secure_mpc_engine_v28_2026_june.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"Test results written to test_results_post_quantum_secure_mpc_engine_v28_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
