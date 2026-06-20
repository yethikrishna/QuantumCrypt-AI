#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Secure Multi-Party Computation Engine V11
QuantumCrypt-AI - Production Grade Testing

Runs comprehensive tests including:
- Verifiable secret sharing (split and reconstruct)
- Homomorphic operations
- Commitment verification
- Zero-Knowledge Proofs
- Audit logging and integrity
- Thread safety
"""
import json
import time
import sys
import threading

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_multi_party_computation_engine_v11_2026_june import (
    MPCEngineV11,
    MPCConfig,
    SecurityLevel,
    Share,
    Commitment
)


def run_tests():
    """Run all tests and generate results"""
    print("=" * 70)
    print("Post-Quantum Secure MPC Engine V11 - Test Suite")
    print("=" * 70)
    
    test_results = {
        "test_timestamp": time.time(),
        "test_module": "post_quantum_secure_multi_party_computation_engine_v11_2026_june",
        "passed": [],
        "failed": [],
        "performance_metrics": {}
    }
    
    # Test 1: Basic initialization
    print("\n[TEST 1] Basic Initialization")
    try:
        config = MPCConfig(security_level=SecurityLevel.STANDARD)
        engine = MPCEngineV11(config=config)
        info = engine.get_security_info()
        assert info["security_level"] == "standard"
        assert info["prime_modulus_bits"] == 256
        print("  ✓ Initialization successful")
        test_results["passed"].append("basic_initialization")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"basic_initialization: {str(e)}")
    
    # Test 2: Secret split and reconstruction
    print("\n[TEST 2] Secret Split & Reconstruction")
    try:
        engine = MPCEngineV11()
        original_secret = 123456789
        
        # Split into 5 shares, threshold 3
        shares, commitments = engine.split_secret(original_secret, num_parties=5, threshold=3)
        assert len(shares) == 5
        
        # Reconstruct with exactly threshold shares
        reconstructed, verified = engine.reconstruct_secret(shares[:3])
        assert reconstructed == original_secret
        assert verified == True
        
        # Reconstruct with more than threshold shares
        reconstructed2, verified2 = engine.reconstruct_secret(shares)
        assert reconstructed2 == original_secret
        
        print("  ✓ Secret split and reconstruction correct")
        test_results["passed"].append("secret_split_reconstruct")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"secret_split_reconstruct: {str(e)}")
    
    # Test 3: Threshold behavior
    print("\n[TEST 3] Threshold Behavior")
    try:
        engine = MPCEngineV11()
        original_secret = 987654321
        
        shares, _ = engine.split_secret(original_secret, num_parties=5, threshold=3)
        
        # With exactly threshold - should work
        r1, _ = engine.reconstruct_secret(shares[:3])
        assert r1 == original_secret
        
        # With different combination - should work
        r2, _ = engine.reconstruct_secret([shares[0], shares[2], shares[4]])
        assert r2 == original_secret
        
        print("  ✓ Threshold behavior correct")
        test_results["passed"].append("threshold_behavior")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"threshold_behavior: {str(e)}")
    
    # Test 4: Homomorphic addition
    print("\n[TEST 4] Homomorphic Addition")
    try:
        engine = MPCEngineV11()
        
        secret1 = 1000
        secret2 = 2000
        
        shares1, _ = engine.split_secret(secret1, num_parties=3, threshold=2)
        shares2, _ = engine.split_secret(secret2, num_parties=3, threshold=2)
        
        # Add shares homomorphically
        sum_shares = []
        for i in range(3):
            sum_share = engine.add_shares(shares1[i], shares2[i])
            sum_shares.append(sum_share)
        
        # Reconstruct sum
        reconstructed_sum, _ = engine.reconstruct_secret(sum_shares[:2])
        expected_sum = (secret1 + secret2) % engine.DEFAULT_PRIME
        
        assert reconstructed_sum == expected_sum
        
        print("  ✓ Homomorphic addition working")
        test_results["passed"].append("homomorphic_addition")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"homomorphic_addition: {str(e)}")
    
    # Test 5: Homomorphic multiplication
    print("\n[TEST 5] Homomorphic Multiplication")
    try:
        engine = MPCEngineV11()
        
        secret1 = 123
        secret2 = 456
        
        shares1, _ = engine.split_secret(secret1, num_parties=3, threshold=2)
        shares2, _ = engine.split_secret(secret2, num_parties=3, threshold=2)
        
        # Multiply shares homomorphically
        product_shares = []
        for i in range(3):
            product_share = engine.multiply_shares(shares1[i], shares2[i])
            product_shares.append(product_share)
        
        # Reconstruct product
        reconstructed_product, _ = engine.reconstruct_secret(product_shares[:2])
        expected_product = (secret1 * secret2) % engine.DEFAULT_PRIME
        
        assert reconstructed_product == expected_product
        
        print("  ✓ Homomorphic multiplication working")
        test_results["passed"].append("homomorphic_multiplication")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"homomorphic_multiplication: {str(e)}")
    
    # Test 6: Commitment verification
    print("\n[TEST 6] Commitment Verification")
    try:
        engine = MPCEngineV11()
        secret = 42
        
        shares, commitments = engine.split_secret(secret, num_parties=3, threshold=2)
        
        # Valid commitment should verify
        for i, share in enumerate(shares):
            if i < len(commitments):
                is_valid = engine.verify_commitment(share, commitments[i])
                assert is_valid == True
        
        print("  ✓ Commitment verification working")
        test_results["passed"].append("commitment_verification")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"commitment_verification: {str(e)}")
    
    # Test 7: Share integrity verification
    print("\n[TEST 7] Share Integrity Verification")
    try:
        engine = MPCEngineV11()
        secret = 12345
        
        shares, _ = engine.split_secret(secret, num_parties=3, threshold=2)
        
        # Valid shares should pass integrity check
        for share in shares:
            assert share.verify_integrity() == True
        
        # Tampered share should fail reconstruction verification
        shares[0].value = engine.DEFAULT_PRIME + 100  # Out of range
        _, verified = engine.reconstruct_secret(shares[:2], verify=True)
        assert verified == False
        
        print("  ✓ Share integrity verification working")
        test_results["passed"].append("share_integrity")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"share_integrity: {str(e)}")
    
    # Test 8: Audit logging
    print("\n[TEST 8] Audit Logging")
    try:
        engine = MPCEngineV11()
        
        # Perform operations
        secret = 999
        shares, _ = engine.split_secret(secret, num_parties=3, threshold=2)
        engine.reconstruct_secret(shares[:2])
        
        audit_log = engine.get_audit_log()
        assert len(audit_log) >= 2
        
        # Verify audit chain integrity
        chain_valid = engine.verify_audit_chain()
        assert chain_valid == True
        
        print("  ✓ Audit logging and integrity working")
        test_results["passed"].append("audit_logging")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"audit_logging: {str(e)}")
    
    # Test 9: Statistics tracking
    print("\n[TEST 9] Statistics Tracking")
    try:
        engine = MPCEngineV11()
        
        # Generate activity
        for i in range(5):
            shares, _ = engine.split_secret(i * 100, num_parties=3, threshold=2)
            engine.reconstruct_secret(shares[:2])
        
        stats = engine.get_statistics()
        assert stats.secrets_split == 5
        assert stats.secrets_reconstructed == 5
        assert stats.total_operations >= 10
        assert stats.successful_operations >= 10
        
        print("  ✓ Statistics tracking accurate")
        test_results["passed"].append("statistics_tracking")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"statistics_tracking: {str(e)}")
    
    # Test 10: Different security levels
    print("\n[TEST 10] Security Level Configuration")
    try:
        for level in [SecurityLevel.LOW, SecurityLevel.STANDARD, SecurityLevel.HIGH, SecurityLevel.MAXIMUM]:
            config = MPCConfig(security_level=level)
            engine = MPCEngineV11(config=config)
            info = engine.get_security_info()
            assert info["security_level"] == level.value
            
            # Test basic operation at each level
            shares, _ = engine.split_secret(42, num_parties=3, threshold=2)
            reconstructed, _ = engine.reconstruct_secret(shares[:2])
            assert reconstructed == 42
        
        print("  ✓ All security levels functional")
        test_results["passed"].append("security_levels")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"security_levels: {str(e)}")
    
    # Test 11: Thread safety
    print("\n[TEST 11] Thread Safety")
    try:
        engine = MPCEngineV11()
        errors = []
        results = []
        
        def worker(thread_id):
            try:
                for i in range(5):
                    secret = thread_id * 1000 + i
                    shares, _ = engine.split_secret(secret, num_parties=3, threshold=2)
                    reconstructed, _ = engine.reconstruct_secret(shares[:2])
                    if reconstructed != secret:
                        errors.append(f"Mismatch: expected {secret}, got {reconstructed}")
                    results.append(reconstructed)
            except Exception as e:
                errors.append(str(e))
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert len(results) == 20
        
        print("  ✓ Thread safety verified")
        test_results["passed"].append("thread_safety")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"thread_safety: {str(e)}")
    
    # Test 12: Input validation
    print("\n[TEST 12] Input Validation")
    try:
        engine = MPCEngineV11()
        
        # Invalid threshold
        try:
            engine.split_secret(42, num_parties=5, threshold=1)
            assert False, "Should have raised error"
        except ValueError:
            pass
        
        # Invalid secret (out of range)
        try:
            engine.split_secret(engine.DEFAULT_PRIME + 100, num_parties=3, threshold=2)
            assert False, "Should have raised error"
        except ValueError:
            pass
        
        # Threshold > num_parties
        try:
            engine.split_secret(42, num_parties=3, threshold=5)
            assert False, "Should have raised error"
        except ValueError:
            pass
        
        print("  ✓ Input validation working")
        test_results["passed"].append("input_validation")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["failed"].append(f"input_validation: {str(e)}")
    
    # Performance metrics
    print("\n" + "=" * 70)
    print("PERFORMANCE METRICS")
    print("=" * 70)
    
    engine = MPCEngineV11()
    
    # Benchmark secret splitting
    start = time.time()
    for i in range(100):
        engine.split_secret(i, num_parties=5, threshold=3)
    split_time = (time.time() - start) * 1000
    
    # Benchmark reconstruction
    shares_list = []
    for i in range(100):
        shares, _ = engine.split_secret(i, num_parties=5, threshold=3)
        shares_list.append(shares[:3])
    
    start = time.time()
    for shares in shares_list:
        engine.reconstruct_secret(shares)
    reconstruct_time = (time.time() - start) * 1000
    
    test_results["performance_metrics"] = {
        "avg_split_ms": round(split_time / 100, 4),
        "avg_reconstruct_ms": round(reconstruct_time / 100, 4),
        "total_100_splits_ms": round(split_time, 2),
        "total_100_reconstructs_ms": round(reconstruct_time, 2),
        "prime_modulus_bits": 256
    }
    
    print(f"  Average split time: {test_results['performance_metrics']['avg_split_ms']} ms")
    print(f"  Average reconstruct time: {test_results['performance_metrics']['avg_reconstruct_ms']} ms")
    
    # Final summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"  Passed: {len(test_results['passed'])}")
    print(f"  Failed: {len(test_results['failed'])}")
    total = len(test_results['passed']) + len(test_results['failed'])
    print(f"  Success Rate: {round(len(test_results['passed']) / total * 100, 1)}%")
    
    if test_results["failed"]:
        print("\n  Failed tests:")
        for f in test_results["failed"]:
            print(f"    - {f}")
    
    # Save results
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_secure_multi_party_computation_engine_v11.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\n  Results saved to: test_results_secure_multi_party_computation_engine_v11.json")
    
    return test_results


if __name__ == "__main__":
    results = run_tests()
    sys.exit(0 if len(results["failed"]) == 0 else 1)
