"""
Test Suite: Post-Quantum Shamir Secret Sharing Engine
Production-grade tests for QuantumCrypt-AI
"""

import sys
import json
sys.path.insert(0, 'quantum_crypt')

from post_quantum_shamir_secret_sharing_engine_2026_june import (
    PostQuantumShamirSecretSharing,
    Share,
    SecurityLevel,
)


def run_tests():
    print("=" * 60)
    print("QuantumCrypt-AI: Post-Quantum Shamir Secret Sharing Tests")
    print("=" * 60)
    
    test_results = []
    sss = PostQuantumShamirSecretSharing(security_level=SecurityLevel.LEVEL_3)
    
    # Test 1: Basic (3, 5) threshold scheme
    print("\n[Test 1] Basic (3, 5) Threshold Scheme")
    try:
        secret = b"QuantumCrypt-2026-Secret-Key"
        shares = sss.split_secret_bytes_independent(secret, 3, 5)
        
        # Reconstruct with exactly 3 shares
        reconstructed = sss.reconstruct_secret_bytes_independent([shares[0], shares[1], shares[2]])
        assert reconstructed == secret
        print(f"  ✓ PASS: Secret reconstructed correctly with 3 shares")
        test_results.append(("Test 1", True))
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        test_results.append(("Test 1", False))
    
    # Test 2: Different share combinations
    print("\n[Test 2] Multiple Share Combinations")
    try:
        secret = b"Test-Secret-12345"
        shares = sss.split_secret_bytes_independent(secret, 2, 5)
        
        # Try different combinations
        combos = [
            [shares[0], shares[4]],
            [shares[1], shares[3]],
            [shares[2], shares[0]],
        ]
        
        for combo in combos:
            reconstructed = sss.reconstruct_secret_bytes_independent(combo)
            assert reconstructed == secret
        
        print(f"  ✓ PASS: All {len(combos)} share combinations work")
        test_results.append(("Test 2", True))
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        test_results.append(("Test 2", False))
    
    # Test 3: Insufficient shares should not work
    print("\n[Test 3] Insufficient Shares Protection")
    try:
        secret = b"Highly-Confidential-Data"
        shares = sss.split_secret_bytes_independent(secret, 3, 5)
        
        # Try with only 2 shares (should give wrong result)
        reconstructed = sss.reconstruct_secret_bytes_independent([shares[0], shares[1]])
        # With only 2 shares for threshold 3, result should NOT match
        assert reconstructed != secret
        print(f"  ✓ PASS: Insufficient shares produce incorrect result (as expected)")
        test_results.append(("Test 3", True))
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        test_results.append(("Test 3", False))
    
    # Test 4: GF(2^8) arithmetic
    print("\n[Test 4] GF(2^8) Arithmetic Operations")
    try:
        # Test multiplication
        assert sss._gf_multiply(2, 3) == 6  # Simple case
        assert sss._gf_multiply(0, 255) == 0
        assert sss._gf_multiply(255, 0) == 0
        
        # Test inverse
        inv = sss._gf_inverse(5)
        assert sss._gf_multiply(5, inv) == 1
        
        print(f"  ✓ PASS: GF(2^8) arithmetic correct")
        test_results.append(("Test 4", True))
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        test_results.append(("Test 4", False))
    
    # Test 5: Different threshold configurations
    print("\n[Test 5] Various Threshold Configurations")
    try:
        test_cases = [
            (2, 3),
            (4, 7),
            (5, 10),
        ]
        
        for threshold, total in test_cases:
            secret = f"Test-Secret-{threshold}-{total}".encode()
            shares = sss.split_secret_bytes_independent(secret, threshold, total)
            reconstructed = sss.reconstruct_secret_bytes_independent(shares[:threshold])
            assert reconstructed == secret
        
        print(f"  ✓ PASS: All {len(test_cases)} threshold configurations work")
        test_results.append(("Test 5", True))
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        test_results.append(("Test 5", False))
    
    # Test 6: Empty secret validation
    print("\n[Test 6] Input Validation")
    try:
        error_raised = False
        try:
            sss.split_secret_bytes_independent(b"", 2, 3)
        except ValueError:
            error_raised = True
        
        assert error_raised
        print(f"  ✓ PASS: Empty secret correctly rejected")
        test_results.append(("Test 6", True))
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        test_results.append(("Test 6", False))
    
    # Test 7: Invalid threshold validation
    print("\n[Test 7] Threshold Validation")
    try:
        # Threshold > total_shares
        error_raised = False
        try:
            sss.split_secret_bytes_independent(b"test", 5, 3)
        except ValueError:
            error_raised = True
        assert error_raised
        
        # Threshold < 2
        error_raised = False
        try:
            sss.split_secret_bytes_independent(b"test", 1, 3)
        except ValueError:
            error_raised = True
        assert error_raised
        
        print(f"  ✓ PASS: Invalid thresholds correctly rejected")
        test_results.append(("Test 7", True))
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        test_results.append(("Test 7", False))
    
    # Test 8: Verifiable share bundle
    print("\n[Test 8] Verifiable Share Bundle")
    try:
        secret = b"Post-Quantum-Master-Key-2026"
        bundle = sss.generate_verifiable_share_bundle(secret, 3, 5)
        
        assert bundle["threshold"] == 3
        assert bundle["total_shares"] == 5
        assert bundle["secret_length"] == len(secret)
        assert len(bundle["shares"]) == 5
        assert "secret_hash" in bundle
        
        print(f"  ✓ PASS: Verifiable bundle generated correctly")
        test_results.append(("Test 8", True))
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        test_results.append(("Test 8", False))
    
    # Test 9: Polynomial evaluation (GF(2^8) specific)
    print("\n[Test 9] Polynomial Evaluation")
    try:
        # f(x) = 5 in GF(2^8) at x=0
        coeffs = [5]
        result = sss._evaluate_polynomial(coeffs, 0)
        assert result == 5
        
        # f(x) = 5 + 0*x at x=1
        coeffs = [5, 0]
        result = sss._evaluate_polynomial(coeffs, 1)
        assert result == 5
        
        print(f"  ✓ PASS: Polynomial evaluation in GF(2^8) correct")
        test_results.append(("Test 9", True))
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        test_results.append(("Test 9", False))
    
    # Summary
    print("\n" + "=" * 60)
    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)
    print(f"TEST SUMMARY: {passed}/{total} tests passed")
    
    for test_name, result in test_results:
        status = "PASS" if result else "FAIL"
        print(f"  {test_name}: {status}")
    
    print("=" * 60)
    
    # Save test results
    with open("test_results_post_quantum_shamir_secret_sharing.json", "w") as f:
        json.dump({
            "test_module": "post_quantum_shamir_secret_sharing_engine",
            "passed": passed,
            "total": total,
            "success_rate": passed / total if total > 0 else 0,
            "results": test_results,
        }, f, indent=2)
    
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
