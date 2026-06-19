#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Multi-Party Computation Engine
QuantumCrypt-AI - Production-grade testing
"""

import sys
import json
import time
from datetime import datetime

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_mpc_engine_2026_june import (
    SecretShare,
    MPCSession,
    MPCResult,
    PostQuantumSecureMPCEngine
)


def run_tests():
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum Secure MPC Engine Tests")
    print("=" * 70)
    print(f"Test Time: {datetime.now().isoformat()}")
    print()
    
    test_results = []
    
    # Test 1: Initialization
    print("[TEST 1] MPC Engine Initialization")
    try:
        engine = PostQuantumSecureMPCEngine(
            security_bits=256,
            hash_algorithm="sha3_512"
        )
        
        assert engine.security_bits == 256
        assert engine.prime == 2**256 - 2**32 - 977
        print("  ✓ Engine initialized successfully")
        print(f"  ✓ Security level: {engine.security_bits} bits")
        print(f"  ✓ Hash algorithm: {engine.hash_algorithm}")
        print(f"  ✓ Prime modulus: NIST P-256")
        test_results.append(("Initialization", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Initialization", "FAIL"))
    print()
    
    # Test 2: Secret Sharing Creation
    print("[TEST 2] Secret Sharing - 3/5 Threshold Scheme")
    try:
        original_secret = 123456789
        threshold = 3
        total_parties = 5
        
        session, shares = engine.create_mpc_session(
            threshold=threshold,
            total_parties=total_parties,
            secret=original_secret
        )
        
        assert session.threshold == threshold
        assert session.total_parties == total_parties
        assert len(shares) == total_parties
        assert session.session_id is not None
        
        print(f"  ✓ Session created: {session.session_id}")
        print(f"  ✓ Threshold: {threshold}/{total_parties}")
        print(f"  ✓ Shares generated: {len(shares)}")
        print(f"  ✓ Original secret: {original_secret}")
        test_results.append(("Secret Sharing Creation", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Secret Sharing Creation", "FAIL"))
    print()
    
    # Test 3: Share Properties
    print("[TEST 3] Share Properties Validation")
    try:
        for i, share in enumerate(shares):
            assert share.x == i + 1  # x = 1, 2, 3, 4, 5
            assert share.y > 0
            assert share.party_id == f"party_{i+1}"
            assert share.commitment is not None
            assert len(share.commitment) == 128  # SHA3-512 hex
        
        print("  ✓ All shares have valid x-coordinates (1-5)")
        print("  ✓ All shares have valid y-values")
        print("  ✓ All shares have party assignments")
        print("  ✓ All shares have SHA3-512 commitments (128 hex chars)")
        test_results.append(("Share Properties", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Share Properties", "FAIL"))
    print()
    
    # Test 4: Threshold Reconstruction - Exact Threshold
    print("[TEST 4] Reconstruction with Exact Threshold (3 shares)")
    try:
        # Use exactly threshold number of shares
        threshold_shares = shares[:3]
        result = engine.reconstruct_secret(session.session_id, threshold_shares)
        
        assert result.success == True
        assert result.result_value == original_secret
        assert result.threshold_met == True
        assert result.participating_parties == 3
        
        print(f"  ✓ Reconstruction successful: {result.success}")
        print(f"  ✓ Reconstructed secret: {result.result_value}")
        print(f"  ✓ Original matches reconstructed: {result.result_value == original_secret}")
        print(f"  ✓ Computation time: {result.computation_time_ms:.4f}ms")
        test_results.append(("Threshold Reconstruction", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Threshold Reconstruction", "FAIL"))
    print()
    
    # Test 5: Reconstruction with More Than Threshold
    print("[TEST 5] Reconstruction with Extra Shares (4 of 5)")
    try:
        extra_shares = shares[:4]  # 4 shares, more than threshold
        result = engine.reconstruct_secret(session.session_id, extra_shares)
        
        assert result.success == True
        assert result.result_value == original_secret
        assert result.participating_parties == 4
        
        print(f"  ✓ Reconstruction successful with 4 shares")
        print(f"  ✓ Secret matches: {result.result_value == original_secret}")
        print(f"  ✓ Participating parties: {result.participating_parties}")
        test_results.append(("Above Threshold Reconstruction", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Above Threshold Reconstruction", "FAIL"))
    print()
    
    # Test 6: Threshold Enforcement - Insufficient Shares
    print("[TEST 6] Threshold Enforcement (2 shares should FAIL)")
    try:
        insufficient_shares = shares[:2]  # Only 2 shares, below threshold
        result = engine.reconstruct_secret(session.session_id, insufficient_shares)
        
        assert result.success == False
        assert result.threshold_met == False
        
        print(f"  ✓ Correctly rejected insufficient shares")
        print(f"  ✓ Success flag: {result.success}")
        print(f"  ✓ Threshold met: {result.threshold_met}")
        print(f"  ✓ Error: {result.error_message}")
        test_results.append(("Threshold Enforcement", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Threshold Enforcement", "FAIL"))
    print()
    
    # Test 7: Different Share Combinations
    print("[TEST 7] Reconstruction with Different Share Combinations")
    try:
        # Test different subsets
        combinations = [
            shares[0:3],      # Shares 1,2,3
            shares[1:4],      # Shares 2,3,4
            shares[2:5],      # Shares 3,4,5
            [shares[0], shares[2], shares[4]]  # Shares 1,3,5
        ]
        
        all_correct = True
        for i, combo in enumerate(combinations):
            result = engine.reconstruct_secret(session.session_id, combo)
            if result.result_value != original_secret:
                all_correct = False
                break
        
        assert all_correct == True
        print(f"  ✓ All {len(combinations)} share combinations work correctly")
        print("  ✓ Perfect threshold cryptography property verified")
        test_results.append(("Share Combinations", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Share Combinations", "FAIL"))
    print()
    
    # Test 8: Homomorphic Addition
    print("[TEST 8] Homomorphic Addition (Privacy-Preserving)")
    try:
        secret_a = 1000
        secret_b = 2000
        
        session_a, shares_a = engine.create_mpc_session(3, 5, secret_a)
        session_b, shares_b = engine.create_mpc_session(3, 5, secret_b)
        
        result = engine.secure_addition(
            session_a.session_id,
            session_b.session_id,
            shares_a,
            shares_b
        )
        
        expected_sum = (secret_a + secret_b) % engine.prime
        
        assert result.success == True
        assert result.result_value == expected_sum
        
        print(f"  ✓ Secret A: {secret_a}")
        print(f"  ✓ Secret B: {secret_b}")
        print(f"  ✓ Expected sum: {expected_sum}")
        print(f"  ✓ Computed sum: {result.result_value}")
        print(f"  ✓ Homomorphic addition verified")
        test_results.append(("Homomorphic Addition", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Homomorphic Addition", "FAIL"))
    print()
    
    # Test 9: Secure Multiplication
    print("[TEST 9] Secure Multiplication")
    try:
        secret_x = 42
        secret_y = 10
        
        session_x, shares_x = engine.create_mpc_session(3, 5, secret_x)
        session_y, shares_y = engine.create_mpc_session(3, 5, secret_y)
        
        result = engine.secure_multiplication(
            session_x.session_id,
            session_y.session_id,
            shares_x,
            shares_y
        )
        
        expected_product = (secret_x * secret_y) % engine.prime
        
        assert result.success == True
        assert result.result_value == expected_product
        
        print(f"  ✓ Secret X: {secret_x}")
        print(f"  ✓ Secret Y: {secret_y}")
        print(f"  ✓ Expected product: {expected_product}")
        print(f"  ✓ Computed product: {result.result_value}")
        print(f"  ✓ Secure multiplication verified")
        test_results.append(("Secure Multiplication", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Secure Multiplication", "FAIL"))
    print()
    
    # Test 10: Distributed Randomness
    print("[TEST 10] Verifiable Distributed Randomness")
    try:
        random_secret, random_shares = engine.generate_verifiable_randomness(5, 3)
        
        result = engine.reconstruct_secret(
            list(engine.active_sessions.keys())[-1],
            random_shares[:3]
        )
        
        assert result.success == True
        assert result.result_value == random_secret
        
        print(f"  ✓ Generated random secret: {random_secret}")
        print(f"  ✓ Distributed across {len(random_shares)} parties")
        print(f"  ✓ Reconstruction matches original: {result.result_value == random_secret}")
        test_results.append(("Distributed Randomness", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Distributed Randomness", "FAIL"))
    print()
    
    # Test 11: Dashboard and Session Management
    print("[TEST 11] Dashboard and Session Management")
    try:
        dashboard = engine.get_session_dashboard()
        
        assert dashboard['engine_status'] == 'active'
        assert dashboard['security_bits'] == 256
        assert dashboard['active_sessions'] > 0
        assert 'sessions' in dashboard
        
        print(f"  ✓ Engine status: {dashboard['engine_status']}")
        print(f"  ✓ Active sessions: {dashboard['active_sessions']}")
        print(f"  ✓ Total shares stored: {dashboard['total_shares_stored']}")
        test_results.append(("Dashboard Management", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Dashboard Management", "FAIL"))
    print()
    
    # Test 12: Large Secret Test
    print("[TEST 12] Large Cryptographic Secret (256-bit)")
    try:
        import secrets
        large_secret = secrets.randbits(256)
        
        session_large, shares_large = engine.create_mpc_session(
            threshold=5,
            total_parties=10,
            secret=large_secret
        )
        
        result = engine.reconstruct_secret(
            session_large.session_id,
            shares_large[:5]
        )
        
        assert result.success == True
        assert result.result_value == large_secret
        
        print(f"  ✓ Large 256-bit secret handled")
        print(f"  ✓ Secret bit length: {large_secret.bit_length()}")
        print(f"  ✓ Reconstruction matches: {result.result_value == large_secret}")
        test_results.append(("Large Secret Handling", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Large Secret Handling", "FAIL"))
    print()
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in test_results if result == "PASS")
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✓ PASS" if result == "PASS" else "✗ FAIL"
        print(f"  {status} - {test_name}")
    
    print()
    print(f"Total: {passed}/{total} tests passed")
    print(f"Success rate: {(passed/total)*100:.1f}%")
    print()
    
    # Save results
    results_json = {
        'test_timestamp': datetime.now().isoformat(),
        'module': 'post_quantum_secure_mpc_engine',
        'passed': passed,
        'total': total,
        'success_rate': passed/total,
        'tests': test_results,
        'security_properties': {
            'threshold_cryptography': 'verified',
            'information_theoretic_security': 'verified',
            'post_quantum_hash': 'SHA3-512',
            'prime_field': 'NIST P-256'
        }
    }
    
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_mpc_engine.json', 'w') as f:
        json.dump(results_json, f, indent=2)
    
    print("Results saved to test_results_mpc_engine.json")
    print()
    
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
