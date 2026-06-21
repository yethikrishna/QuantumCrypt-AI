#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Secure MPC Engine v21
QuantumCrypt-AI Production-Grade Testing
"""

import json
import sys
import time

sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_mpc_engine_v21_2026_june import (
    PostQuantumSecureMPCEngine,
    MPCOperation,
    SecurityLevel,
    Share,
    create_mpc_shares,
    reconstruct_mpc_secret
)


def run_tests():
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum Secure MPC Engine v21 Tests")
    print("=" * 70)
    
    test_results = []
    
    # Test 1: Basic secret sharing and reconstruction (3-of-5 threshold)
    print("\n[Test 1] Basic Shamir Secret Sharing (3-of-5)")
    try:
        engine = PostQuantumSecureMPCEngine(SecurityLevel.QUANTUM_256)
        secret = 42
        threshold = 3
        parties = 5
        
        shares = engine.create_secret_shares(secret, threshold, parties)
        
        assert len(shares) == 5, f"Should create 5 shares, got {len(shares)}"
        
        # Reconstruct with exactly threshold shares
        reconstructed = engine.reconstruct_secret(shares[:3])
        assert reconstructed == secret, f"Should reconstruct secret {secret}, got {reconstructed}"
        
        # Reconstruct with more than threshold shares (4 of 5)
        reconstructed2 = engine.reconstruct_secret(shares[:4])
        assert reconstructed2 == secret, "Should work with 4 shares too"
        
        print(f"  ✓ PASS: Secret {secret} shared and reconstructed correctly")
        test_results.append(("Test 1: Basic Secret Sharing", True, ""))
    except Exception as e:
        print(f"  ✗ FAIL: {str(e)}")
        test_results.append(("Test 1: Basic Secret Sharing", False, str(e)))
    
    # Test 2: Threshold enforcement - should fail with insufficient shares
    print("\n[Test 2] Threshold enforcement - insufficient shares")
    try:
        engine = PostQuantumSecureMPCEngine()
        secret = 12345
        threshold = 3
        parties = 5
        
        shares = engine.create_secret_shares(secret, threshold, parties)
        
        # Try to reconstruct with only 2 shares (below threshold)
        try:
            engine.reconstruct_secret(shares[:2])
            print("  ✗ FAIL: Should have raised error for insufficient shares")
            test_results.append(("Test 2: Threshold Enforcement", False, "No error raised"))
        except ValueError as e:
            # Error raised correctly (message contains threshold or need/at least)
            print("  ✓ PASS: Correctly rejected insufficient shares")
            test_results.append(("Test 2: Threshold Enforcement", True, ""))
    except Exception as e:
        print(f"  ✗ FAIL: {str(e)}")
        test_results.append(("Test 2: Threshold Enforcement", False, str(e)))
    
    # Test 3: Different party subsets produce same secret
    print("\n[Test 3] Different share subsets produce same secret")
    try:
        engine = PostQuantumSecureMPCEngine()
        secret = 999999
        threshold = 2
        parties = 5
        
        shares = engine.create_secret_shares(secret, threshold, parties)
        
        # Different subsets should all reconstruct to same secret
        r1 = engine.reconstruct_secret([shares[0], shares[1]])
        r2 = engine.reconstruct_secret([shares[2], shares[4]])
        r3 = engine.reconstruct_secret([shares[1], shares[3]])
        
        assert r1 == r2 == r3 == secret, "All subsets should give same secret"
        
        print("  ✓ PASS: All share subsets reconstruct to same secret")
        test_results.append(("Test 3: Subset Consistency", True, ""))
    except Exception as e:
        print(f"  ✗ FAIL: {str(e)}")
        test_results.append(("Test 3: Subset Consistency", False, str(e)))
    
    # Test 4: Secure homomorphic addition
    print("\n[Test 4] Secure MPC Homomorphic Addition")
    try:
        engine = PostQuantumSecureMPCEngine()
        a = 100
        b = 200
        threshold = 2
        parties = 3
        
        shares_a = engine.create_secret_shares(a, threshold, parties)
        shares_b = engine.create_secret_shares(b, threshold, parties)
        
        # Add shares without reconstructing secrets
        sum_shares = engine.secure_addition(shares_a, shares_b)
        
        # Reconstruct the sum
        result = engine.reconstruct_secret(sum_shares)
        
        assert result == (a + b) % engine.PRIME, f"Expected {a+b}, got {result}"
        
        print(f"  ✓ PASS: Secure addition: {a} + {b} = {result}")
        test_results.append(("Test 4: Secure Addition", True, ""))
    except Exception as e:
        print(f"  ✗ FAIL: {str(e)}")
        test_results.append(("Test 4: Secure Addition", False, str(e)))
    
    # Test 5: Security level configurations
    print("\n[Test 5] Different security level configurations")
    try:
        for level in [SecurityLevel.CLASSICAL_128, SecurityLevel.QUANTUM_128, SecurityLevel.QUANTUM_256]:
            engine = PostQuantumSecureMPCEngine(level)
            secret = 123
            shares = engine.create_secret_shares(secret, 2, 3)
            reconstructed = engine.reconstruct_secret(shares[:2])
            assert reconstructed == secret, f"Failed at level {level}"
        
        print("  ✓ PASS: All security levels work correctly")
        test_results.append(("Test 5: Security Levels", True, ""))
    except Exception as e:
        print(f"  ✗ FAIL: {str(e)}")
        test_results.append(("Test 5: Security Levels", False, str(e)))
    
    # Test 6: Large secret value (edge case)
    print("\n[Test 6] Large secret value handling")
    try:
        engine = PostQuantumSecureMPCEngine()
        # Large secret but still less than prime
        secret = 2**64
        shares = engine.create_secret_shares(secret, 2, 4)
        reconstructed = engine.reconstruct_secret(shares[:2])
        
        assert reconstructed == secret, f"Large secret failed: expected {secret}, got {reconstructed}"
        
        print(f"  ✓ PASS: Large secret {secret} handled correctly")
        test_results.append(("Test 6: Large Secret", True, ""))
    except Exception as e:
        print(f"  ✗ FAIL: {str(e)}")
        test_results.append(("Test 6: Large Secret", False, str(e)))
    
    # Test 7: Share commitment verification
    print("\n[Test 7] Share integrity commitment verification")
    try:
        engine = PostQuantumSecureMPCEngine()
        secret = 555
        shares = engine.create_secret_shares(secret, 2, 3)
        
        secret_hash = engine.hash_function(str(secret).encode()).hexdigest()
        valid, invalid = engine.verify_share_integrity(shares, secret_hash)
        
        assert valid == True, "All shares should verify"
        assert len(invalid) == 0, "No invalid shares"
        
        # Tamper with a share and verify it fails
        shares[0].y = 999999  # Tamper
        valid2, invalid2 = engine.verify_share_integrity(shares, secret_hash)
        assert valid2 == False, "Tampered share should fail verification"
        
        print("  ✓ PASS: Commitment verification detects tampering")
        test_results.append(("Test 7: Commitment Verification", True, ""))
    except Exception as e:
        print(f"  ✗ FAIL: {str(e)}")
        test_results.append(("Test 7: Commitment Verification", False, str(e)))
    
    # Test 8: Convenience functions
    print("\n[Test 8] Convenience wrapper functions")
    try:
        secret = 777
        shares = create_mpc_shares(secret, 2, 3)
        reconstructed = reconstruct_mpc_secret(shares[:2])
        
        assert reconstructed == secret
        
        print("  ✓ PASS: Convenience functions work correctly")
        test_results.append(("Test 8: Convenience Functions", True, ""))
    except Exception as e:
        print(f"  ✗ FAIL: {str(e)}")
        test_results.append(("Test 8: Convenience Functions", False, str(e)))
    
    # Test 9: High-level secure_compute interface
    print("\n[Test 9] High-level secure_compute interface")
    try:
        engine = PostQuantumSecureMPCEngine()
        a, b = 50, 30
        
        shares_a = engine.create_secret_shares(a, 2, 3)
        shares_b = engine.create_secret_shares(b, 2, 3)
        
        result = engine.secure_compute(MPCOperation.ADD, [shares_a, shares_b])
        
        assert result.success == True
        assert result.value == (a + b) % engine.PRIME
        assert result.verification_hash != ""
        
        print(f"  ✓ PASS: secure_compute ADD: {a} + {b} = {result.value}")
        test_results.append(("Test 9: High-level Interface", True, ""))
    except Exception as e:
        print(f"  ✗ FAIL: {str(e)}")
        test_results.append(("Test 9: High-level Interface", False, str(e)))
    
    # Test 10: Audit logging
    print("\n[Test 10] Operation audit logging")
    try:
        engine = PostQuantumSecureMPCEngine()
        shares = engine.create_secret_shares(100, 2, 3)
        engine.reconstruct_secret(shares[:2])
        
        log = engine.get_audit_log()
        
        assert len(log) >= 2, "Should have logged operations"
        assert log[0]['operation'] == 'share_creation'
        
        print(f"  ✓ PASS: Audit log contains {len(log)} operations")
        test_results.append(("Test 10: Audit Logging", True, ""))
    except Exception as e:
        print(f"  ✗ FAIL: {str(e)}")
        test_results.append(("Test 10: Audit Logging", False, str(e)))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, success, _ in test_results if success)
    total = len(test_results)
    
    for name, success, error in test_results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {name}")
        if error:
            print(f"       Error: {error}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    # Save test results
    result_data = {
        'test_module': 'post_quantum_secure_mpc_engine_v21',
        'timestamp': time.time(),
        'tests_passed': passed,
        'tests_total': total,
        'success_rate': passed / total if total > 0 else 0,
        'prime_used': PostQuantumSecureMPCEngine.PRIME,
        'results': [{'name': n, 'success': s, 'error': e} for n, s, e in test_results]
    }
    
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_mpc_engine_v21_2026_june.json', 'w') as f:
        json.dump(result_data, f, indent=2)
    
    print(f"\nTest results saved to: test_results_mpc_engine_v21_2026_june.json")
    
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
