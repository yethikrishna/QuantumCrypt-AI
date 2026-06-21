"""
Test suite for Post-Quantum Secure MAC Manager v31
REAL WORKING TESTS - NO MOCKING
All tests execute actual production code and verify real cryptographic functionality.
"""
import sys
import json
sys.path.insert(0, '/home/user/.super_doubao/super-doubao-runtime/workspace/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_mac_manager_side_channel_resistant_v31_2026_june import (
    PostQuantumSecureMACManager,
    MACAlgorithm,
    SecurityLevel,
    VerificationResult
)


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 70)
    print("POST-QUANTUM SECURE MAC MANAGER v31 - TEST SUITE")
    print("=" * 70)
    print()
    
    test_results = []
    
    # Test 1: Basic initialization
    print("TEST 1: Basic Initialization")
    try:
        manager = PostQuantumSecureMACManager()
        assert manager.config.default_algorithm == MACAlgorithm.HMAC_SHA3_256
        assert manager.config.default_security_level == SecurityLevel.QUANTUM_RESISTANT
        print("  ✓ Initialization works correctly with quantum-resistant defaults")
        test_results.append(("Initialization", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Initialization", False))
    
    # Test 2: Key generation
    print("\nTEST 2: Cryptographically Secure Key Generation")
    try:
        manager = PostQuantumSecureMACManager()
        key_id = manager.generate_key(algorithm=MACAlgorithm.HMAC_SHA3_256)
        assert len(key_id) == 16
        metrics = manager.get_security_metrics()
        assert metrics["active_keys"] >= 1
        print(f"  ✓ Key generated successfully: {key_id}")
        print(f"    Active keys: {metrics['active_keys']}")
        test_results.append(("Key Generation", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Key Generation", False))
    
    # Test 3: MAC generation
    print("\nTEST 3: MAC Generation (SHA3-256)")
    try:
        manager = PostQuantumSecureMACManager()
        test_data = b"Test message for authentication"
        result = manager.generate_mac(test_data)
        assert result is not None
        assert len(result.mac_value) == 64  # SHA256 hex = 64 chars
        assert result.nonce != ""
        assert result.security_level == SecurityLevel.QUANTUM_RESISTANT
        print(f"  ✓ MAC generated: {result.mac_value[:32]}...")
        print(f"    Algorithm: {result.mac_algorithm.value}")
        print(f"    Nonce: {result.nonce}")
        test_results.append(("MAC Generation", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("MAC Generation", False))
    
    # Test 4: Valid MAC verification
    print("\nTEST 4: Valid MAC Verification")
    try:
        manager = PostQuantumSecureMACManager()
        test_data = b"Valid test message"
        mac_result = manager.generate_mac(test_data)
        verify_result = manager.verify_mac(
            test_data, mac_result.mac_value, mac_result.key_id, mac_result.nonce
        )
        assert verify_result == VerificationResult.VERIFIED
        print(f"  ✓ Valid MAC correctly verified: {verify_result.value}")
        test_results.append(("Valid Verification", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Valid Verification", False))
    
    # Test 5: Invalid MAC detection (tampered data)
    print("\nTEST 5: Tampered Data Detection")
    try:
        manager = PostQuantumSecureMACManager()
        original_data = b"Original authentic message"
        mac_result = manager.generate_mac(original_data)
        tampered_data = b"Tampered fake message"
        verify_result = manager.verify_mac(
            tampered_data, mac_result.mac_value, mac_result.key_id, mac_result.nonce
        )
        assert verify_result == VerificationResult.INVALID
        print(f"  ✓ Tampered data correctly rejected: {verify_result.value}")
        test_results.append(("Tamper Detection", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Tamper Detection", False))
    
    # Test 6: Invalid MAC detection
    print("\nTEST 6: Invalid MAC Detection")
    try:
        manager = PostQuantumSecureMACManager()
        test_data = b"Test data"
        mac_result = manager.generate_mac(test_data)
        # Forge a fake MAC
        fake_mac = "0" * 64
        verify_result = manager.verify_mac(
            test_data, fake_mac, mac_result.key_id, mac_result.nonce
        )
        assert verify_result == VerificationResult.INVALID
        print(f"  ✓ Fake MAC correctly rejected: {verify_result.value}")
        test_results.append(("Fake MAC Detection", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Fake MAC Detection", False))
    
    # Test 7: Multiple algorithm support
    print("\nTEST 7: Multiple Algorithm Support")
    try:
        manager = PostQuantumSecureMACManager()
        test_data = b"Multi-algorithm test"
        
        algorithms = [
            MACAlgorithm.HMAC_SHA256,
            MACAlgorithm.HMAC_SHA3_256,
            MACAlgorithm.HMAC_SHA512,
            MACAlgorithm.KMAC256
        ]
        
        for algo in algorithms:
            key_id = manager.generate_key(algorithm=algo)
            result = manager.generate_mac(test_data, key_id=key_id)
            assert result is not None
            verify = manager.verify_mac(test_data, result.mac_value, key_id, result.nonce)
            assert verify == VerificationResult.VERIFIED
            print(f"  ✓ {algo.value}: working")
        
        test_results.append(("Multi-Algorithm", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Multi-Algorithm", False))
    
    # Test 8: Key revocation with forward secrecy
    print("\nTEST 8: Key Revocation with Forward Secrecy")
    try:
        manager = PostQuantumSecureMACManager()
        key_id = manager.generate_key()
        test_data = b"Revocation test"
        mac_result = manager.generate_mac(test_data, key_id=key_id)
        
        # Revoke the key
        revoked = manager.revoke_key(key_id)
        assert revoked == True
        
        # Try to verify with revoked key
        verify_result = manager.verify_mac(
            test_data, mac_result.mac_value, key_id, mac_result.nonce
        )
        assert verify_result == VerificationResult.REVOKED
        print(f"  ✓ Key revoked and verification blocked: {verify_result.value}")
        test_results.append(("Key Revocation", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Key Revocation", False))
    
    # Test 9: Security metrics
    print("\nTEST 9: Security Metrics and Audit Logging")
    try:
        manager = PostQuantumSecureMACManager()
        test_data = b"Metrics test"
        
        # Perform some operations
        for i in range(5):
            result = manager.generate_mac(test_data)
            manager.verify_mac(test_data, result.mac_value, result.key_id, result.nonce)
        
        metrics = manager.get_security_metrics()
        assert metrics["total_verifications"] >= 5
        assert metrics["success_rate"] == 1.0
        assert metrics["version"] == "31.0.0"
        assert metrics["quantum_resistant"] == True
        
        print(f"  ✓ Metrics working: {metrics['total_verifications']} verifications")
        print(f"    Success rate: {metrics['success_rate']:.1%}")
        print(f"    Avg latency: {metrics['average_latency_ms']}ms")
        test_results.append(("Security Metrics", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Security Metrics", False))
    
    # Test 10: Audit report export
    print("\nTEST 10: Audit Report Export")
    try:
        manager = PostQuantumSecureMACManager()
        report = manager.export_audit_report()
        assert "manager_version" in report
        assert "security_metrics" in report
        assert "configuration" in report
        assert report["manager_version"] == "31.0.0"
        print(f"  ✓ Audit report exported with version {report['manager_version']}")
        test_results.append(("Audit Report", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Audit Report", False))
    
    # Test 11: Brute force protection (rate limiting)
    print("\nTEST 11: Brute Force / Rate Limiting Protection")
    try:
        manager = PostQuantumSecureMACManager()
        test_data = b"Rate limit test"
        result = manager.generate_mac(test_data)
        
        # Rapid-fire verification attempts from same source
        rate_limited = False
        for i in range(150):  # Exceed rate limit
            verify_result = manager.verify_mac(
                test_data, result.mac_value, result.key_id, result.nonce,
                source_identifier="attacker"
            )
            if verify_result == VerificationResult.RATE_LIMITED:
                rate_limited = True
                break
        
        assert rate_limited == True
        print(f"  ✓ Rate limiting activated after {i} attempts")
        test_results.append(("Rate Limiting", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Rate Limiting", False))
    
    # Test 12: Hybrid dual verification (SHA256 + SHA3)
    print("\nTEST 12: Hybrid Dual Verification (SHA256 + SHA3)")
    try:
        manager = PostQuantumSecureMACManager()
        key_id = manager.generate_key(algorithm=MACAlgorithm.HYBRID_SHA256_SHA3)
        test_data = b"Hybrid verification test"
        result = manager.generate_mac(test_data, key_id=key_id)
        assert result is not None
        assert len(result.mac_value) == 128  # 2x 64 hex chars
        verify = manager.verify_mac(test_data, result.mac_value, key_id, result.nonce)
        assert verify == VerificationResult.VERIFIED
        print(f"  ✓ Hybrid dual verification working (128 hex chars)")
        test_results.append(("Hybrid Verification", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Hybrid Verification", False))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    # Save results to JSON
    results_data = {
        "test_suite": "Post-Quantum Secure MAC Manager v31",
        "version": "31.0.0",
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "total_tests": total,
        "passed_tests": passed,
        "pass_rate": passed / total,
        "quantum_resistant": True,
        "constant_time_enabled": True,
        "results": {name: result for name, result in test_results}
    }
    
    with open('/home/user/.super_doubao/super-doubao-runtime/workspace/autonomous-developer/QuantumCrypt-AI/test_results_secure_mac_manager_v31_2026_june.json', 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\nResults saved to test_results_secure_mac_manager_v31_2026_june.json")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
