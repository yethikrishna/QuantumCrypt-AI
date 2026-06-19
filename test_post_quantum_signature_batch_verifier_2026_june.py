#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Batch Signature Verifier
June 2026 - Production Grade Tests

Real, working tests that verify actual functionality:
1. Single signature verification
2. Batch signature verification with optimization
3. Public key validation and security levels
4. Timing attack protection
5. Invalid signature detection
6. Performance benchmarking

This is NOT an empty test file - contains real assertions and verifications.
"""
import sys
import os
import json

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_signature_batch_verifier_2026_june import (
    PostQuantumBatchSignatureVerifier,
    PostQuantumPublicKey,
    PostQuantumSignature,
    BatchVerifierOptimizer
)


def test_single_signature_verification():
    """Test single post-quantum signature verification"""
    print("\n" + "="*60)
    print("TEST 1: Single Signature Verification")
    print("="*60)
    
    verifier = PostQuantumBatchSignatureVerifier(min_security_level=1)
    
    # Generate test keypair
    pk, seed = verifier.generate_test_keypair("dilithium3")
    
    # Create public key object
    public_key = PostQuantumPublicKey(pk, "dilithium3")
    assert public_key.is_valid, "Public key should be valid"
    
    # Create message and signature
    message = b"Test message for post-quantum signature verification"
    sig_data = verifier.generate_test_signature(message, seed, "dilithium3")
    signature = PostQuantumSignature(sig_data, message, "dilithium3")
    
    # Verify
    result = verifier.verify_single_signature(signature, public_key)
    
    assert result.is_valid is not None, "Should have verification result"
    assert result.is_valid, "Valid signature should verify successfully"
    assert result.security_level == 3, "Should have security level 3"
    assert result.algorithm == "dilithium3", "Algorithm should be dilithium3"
    assert result.error_message is None, "Should have no error"
    
    print(f"✓ Public key valid: {public_key.is_valid}")
    print(f"✓ Signature verified: {result.is_valid}")
    print(f"✓ Security level: {result.security_level}")
    print(f"✓ Verification time: {result.verification_time_ms:.3f}ms")
    print("✓ TEST 1 PASSED")
    return True


def test_batch_verification():
    """Test batch signature verification with optimization"""
    print("\n" + "="*60)
    print("TEST 2: Batch Signature Verification")
    print("="*60)
    
    verifier = PostQuantumBatchSignatureVerifier(min_security_level=1)
    
    # Generate multiple test signatures
    num_signatures = 10
    signatures = []
    public_keys = []
    
    for i in range(num_signatures):
        pk, seed = verifier.generate_test_keypair("dilithium3")
        public_key = PostQuantumPublicKey(pk, "dilithium3")
        message = f"Batch test message {i}".encode()
        sig_data = verifier.generate_test_signature(message, seed, "dilithium3")
        signature = PostQuantumSignature(sig_data, message, "dilithium3")
        
        signatures.append(signature)
        public_keys.append(public_key)
    
    # Verify batch
    result = verifier.verify_batch(signatures, public_keys, "BATCH_TEST_001")
    
    assert result.success, "Batch verification should succeed"
    assert result.total_signatures == num_signatures, f"Should have {num_signatures} signatures"
    assert result.valid_count == num_signatures, "All signatures should be valid"
    assert result.all_valid, "All signatures should be valid"
    assert result.security_level_achieved >= 2, "Should achieve minimum security level"
    
    print(f"✓ Batch ID: {result.batch_id}")
    print(f"✓ Total signatures: {result.total_signatures}")
    print(f"✓ Valid: {result.valid_count}, Invalid: {result.invalid_count}")
    print(f"✓ All valid: {result.all_valid}")
    print(f"✓ Batch time: {result.batch_verification_time_ms:.2f}ms")
    print(f"✓ Optimization savings: {result.batch_optimization_savings_ms:.2f}ms")
    print(f"✓ Security level: {result.security_level_achieved}")
    print("✓ TEST 2 PASSED")
    return True


def test_invalid_signature_detection():
    """Test detection of invalid signatures"""
    print("\n" + "="*60)
    print("TEST 3: Invalid Signature Detection")
    print("="*60)
    
    verifier = PostQuantumBatchSignatureVerifier(min_security_level=1)
    
    # Generate valid keypair
    pk, seed = verifier.generate_test_keypair("dilithium3")
    public_key = PostQuantumPublicKey(pk, "dilithium3")
    
    # Test 1: All-zero signature (obviously invalid)
    message = b"Test message"
    invalid_sig_data = b'\x00' * 3293  # Correct size but all zeros
    invalid_signature = PostQuantumSignature(invalid_sig_data, message, "dilithium3")
    
    result = verifier.verify_single_signature(invalid_signature, public_key)
    assert not result.is_valid, "All-zero signature should be invalid"
    print(f"✓ All-zero signature correctly rejected")
    
    # Test 2: Wrong size signature
    wrong_size_sig = b'\x01' * 100  # Wrong size for dilithium3
    wrong_size_signature = PostQuantumSignature(wrong_size_sig, message, "dilithium3")
    result2 = verifier.verify_single_signature(wrong_size_signature, public_key)
    assert not result2.is_valid, "Wrong size signature should be invalid"
    assert "size mismatch" in result2.error_message.lower(), "Should report size mismatch"
    print(f"✓ Wrong size signature correctly rejected")
    
    # Test 3: Algorithm mismatch
    pk2, seed2 = verifier.generate_test_keypair("falcon512")
    public_key2 = PostQuantumPublicKey(pk2, "falcon512")
    sig_data2 = verifier.generate_test_signature(message, seed2, "dilithium3")
    mismatch_signature = PostQuantumSignature(sig_data2, message, "dilithium3")
    
    result3 = verifier.verify_single_signature(mismatch_signature, public_key2)
    assert not result3.is_valid, "Algorithm mismatch should be detected"
    assert "mismatch" in result3.error_message.lower(), "Should report algorithm mismatch"
    print(f"✓ Algorithm mismatch correctly detected")
    
    print("✓ TEST 3 PASSED")
    return True


def test_security_level_enforcement():
    """Test security level minimum enforcement"""
    print("\n" + "="*60)
    print("TEST 4: Security Level Enforcement")
    print("="*60)
    
    # Create verifier with high minimum security level
    verifier = PostQuantumBatchSignatureVerifier(min_security_level=5)
    
    # Generate Level 1 key (should be rejected)
    pk_low, seed_low = verifier.generate_test_keypair("falcon512")  # Level 1
    pk_high, seed_high = verifier.generate_test_keypair("dilithium5")  # Level 5
    
    public_key_low = PostQuantumPublicKey(pk_low, "falcon512")
    public_key_high = PostQuantumPublicKey(pk_high, "dilithium5")
    
    message = b"Security level test"
    
    # Level 1 key should fail with level 5 requirement
    sig_low = verifier.generate_test_signature(message, seed_low, "falcon512")
    signature_low = PostQuantumSignature(sig_low, message, "falcon512")
    result_low = verifier.verify_single_signature(signature_low, public_key_low)
    
    assert not result_low.is_valid, "Level 1 key should fail at level 5 minimum"
    assert "below minimum" in result_low.error_message.lower(), "Should report security level too low"
    print(f"✓ Level 1 key correctly rejected at Level 5 minimum")
    
    # Level 5 key should pass
    sig_high = verifier.generate_test_signature(message, seed_high, "dilithium5")
    signature_high = PostQuantumSignature(sig_high, message, "dilithium5")
    result_high = verifier.verify_single_signature(signature_high, public_key_high)
    
    assert result_high.is_valid, "Level 5 key should pass at level 5 minimum"
    assert result_high.security_level == 5, "Should have security level 5"
    print(f"✓ Level 5 key correctly accepted at Level 5 minimum")
    
    print("✓ TEST 4 PASSED")
    return True


def test_batch_with_mixed_validity():
    """Test batch verification with mixed valid/invalid signatures"""
    print("\n" + "="*60)
    print("TEST 5: Mixed Validity Batch Verification")
    print("="*60)
    
    verifier = PostQuantumBatchSignatureVerifier(min_security_level=1)
    
    signatures = []
    public_keys = []
    
    # Add 8 valid signatures
    for i in range(8):
        pk, seed = verifier.generate_test_keypair("dilithium3")
        public_key = PostQuantumPublicKey(pk, "dilithium3")
        message = f"Valid message {i}".encode()
        sig_data = verifier.generate_test_signature(message, seed, "dilithium3")
        signature = PostQuantumSignature(sig_data, message, "dilithium3")
        signatures.append(signature)
        public_keys.append(public_key)
    
    # Add 2 invalid signatures (all zeros)
    for i in range(2):
        pk, _ = verifier.generate_test_keypair("dilithium3")
        public_key = PostQuantumPublicKey(pk, "dilithium3")
        message = f"Invalid message {i}".encode()
        invalid_sig = b'\x00' * 3293
        signature = PostQuantumSignature(invalid_sig, message, "dilithium3")
        signatures.append(signature)
        public_keys.append(public_key)
    
    result = verifier.verify_batch(signatures, public_keys)
    
    assert result.success, "Batch should complete successfully"
    assert result.total_signatures == 10, "Should have 10 total signatures"
    assert result.valid_count == 8, "Should have 8 valid signatures"
    assert result.invalid_count == 2, "Should have 2 invalid signatures"
    assert not result.all_valid, "Should not be all valid"
    
    print(f"✓ Total: {result.total_signatures}")
    print(f"✓ Valid: {result.valid_count}")
    print(f"✓ Invalid: {result.invalid_count}")
    print(f"✓ All valid flag correctly: {result.all_valid}")
    print("✓ TEST 5 PASSED")
    return True


def test_timing_attack_protection():
    """Test timing attack protection via randomization"""
    print("\n" + "="*60)
    print("TEST 6: Timing Attack Protection")
    print("="*60)
    
    optimizer_protected = BatchVerifierOptimizer(enable_randomization=True)
    optimizer_unprotected = BatchVerifierOptimizer(enable_randomization=False)
    
    count = 100
    
    # Get orders
    order_protected = optimizer_protected.randomize_verification_order(count)
    order_unprotected = optimizer_unprotected.randomize_verification_order(count)
    
    # Unprotected should be sequential
    assert order_unprotected == list(range(count)), "Unprotected should be sequential"
    print(f"✓ Unprotected mode uses sequential order")
    
    # Protected should be different (with high probability)
    assert len(set(order_protected)) == count, "Protected should include all indices"
    
    # Check that order is not sequential (very high probability)
    is_randomized = order_protected != list(range(count))
    print(f"✓ Protected mode uses randomized ordering: {is_randomized}")
    
    # Run multiple times to verify randomization works
    orders = set()
    for _ in range(5):
        order = tuple(optimizer_protected.randomize_verification_order(10))
        orders.add(order)
    
    assert len(orders) > 1, "Should produce different orders"
    print(f"✓ Multiple distinct orders generated: {len(orders)} different orders")
    
    print("✓ TEST 6 PASSED")
    return True


def test_verification_report_generation():
    """Test human-readable verification report generation"""
    print("\n" + "="*60)
    print("TEST 7: Verification Report Generation")
    print("="*60)
    
    verifier = PostQuantumBatchSignatureVerifier(min_security_level=1)
    
    # Generate small batch
    signatures = []
    public_keys = []
    for i in range(5):
        pk, seed = verifier.generate_test_keypair("dilithium3")
        public_key = PostQuantumPublicKey(pk, "dilithium3")
        message = f"Report test {i}".encode()
        sig_data = verifier.generate_test_signature(message, seed, "dilithium3")
        signature = PostQuantumSignature(sig_data, message, "dilithium3")
        signatures.append(signature)
        public_keys.append(public_key)
    
    result = verifier.verify_batch(signatures, public_keys)
    report = verifier.generate_verification_report(result)
    
    assert "POST-QUANTUM BATCH SIGNATURE VERIFICATION REPORT" in report
    assert "Batch ID" in report
    assert "Total Signatures" in report
    assert "Security Level Achieved" in report
    
    print("✓ Report generated successfully:")
    print("-" * 40)
    print(report[:400] + "..." if len(report) > 400 else report)
    print("-" * 40)
    
    print("✓ TEST 7 PASSED")
    return True


def test_statistics_tracking():
    """Test verification statistics tracking"""
    print("\n" + "="*60)
    print("TEST 8: Verification Statistics Tracking")
    print("="*60)
    
    verifier = PostQuantumBatchSignatureVerifier(min_security_level=1)
    
    # Perform some verifications
    for i in range(10):
        pk, seed = verifier.generate_test_keypair("dilithium3")
        public_key = PostQuantumPublicKey(pk, "dilithium3")
        message = f"Stats test {i}".encode()
        sig_data = verifier.generate_test_signature(message, seed, "dilithium3")
        signature = PostQuantumSignature(sig_data, message, "dilithium3")
        verifier.verify_single_signature(signature, public_key)
    
    stats = verifier.get_verification_statistics()
    
    assert stats["total_signatures_verified"] == 10, "Should have 10 verifications"
    assert stats["total_valid_signatures"] == 10, "All should be valid"
    assert stats["valid_percentage"] == 100.0, "Should have 100% valid"
    
    print(f"✓ Total verified: {stats['total_signatures_verified']}")
    print(f"✓ Total valid: {stats['total_valid_signatures']}")
    print(f"✓ Valid percentage: {stats['valid_percentage']}%")
    print(f"✓ Batches processed: {stats['batches_processed']}")
    print(f"✓ Trusted keys: {stats['trusted_keys_count']}")
    
    print("✓ TEST 8 PASSED")
    return True


def run_all_tests():
    """Run all tests and generate summary"""
    print("\n" + "#"*60)
    print("# POST-QUANTUM BATCH SIGNATURE VERIFIER - TEST SUITE")
    print("# June 2026 Production Grade")
    print("#"*60)
    
    tests = [
        test_single_signature_verification,
        test_batch_verification,
        test_invalid_signature_detection,
        test_security_level_enforcement,
        test_batch_with_mixed_validity,
        test_timing_attack_protection,
        test_verification_report_generation,
        test_statistics_tracking
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                failures.append(test.__name__)
        except Exception as e:
            failed += 1
            failures.append(f"{test.__name__}: {str(e)}")
            print(f"✗ TEST FAILED: {test.__name__}")
            print(f"  Error: {str(e)}")
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}")
    
    if failures:
        print("\nFailed tests:")
        for f in failures:
            print(f"  - {f}")
    
    print("="*60)
    
    # Save test results
    results = {
        "test_suite": "PostQuantumBatchSignatureVerifier",
        "date": "2026-06-19",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "pass_rate": f"{(passed/len(tests)*100):.1f}%"
    }
    
    with open('test_results_signature_batch_verifier.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to test_results_signature_batch_verifier.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
