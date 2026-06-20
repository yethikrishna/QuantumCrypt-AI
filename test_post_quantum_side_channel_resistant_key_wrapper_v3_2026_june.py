#!/usr/bin/env python3
"""
Test Suite for QuantumCrypt-AI Side-Channel Resistant Key Wrapper V3
Production-Grade Testing
"""

import sys
import json
import secrets
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_side_channel_resistant_key_wrapper_v3_2026_june import (
    SideChannelResistantKeyWrapperV3,
    ConstantTimeOperations,
    MaskedValue,
    KeyWrapAlgorithm,
    SecurityLevel,
    MaskingScheme,
    WrappedKeyResult,
    UnwrapResult
)


def run_tests():
    print("=" * 70)
    print("QuantumCrypt-AI: Side-Channel Resistant Key Wrapper V3 - TEST SUITE")
    print("=" * 70)
    
    all_passed = True
    test_results = []
    
    # Test 1: Constant-Time Operations
    print("\n[TEST 1] Constant-Time Operations")
    try:
        ct_ops = ConstantTimeOperations()
        
        a = b"test_data_12345"
        b = b"test_data_12345"
        c = b"different_data_"
        
        assert ct_ops.ct_equal(a, b) == True
        assert ct_ops.ct_equal(a, c) == False
        print("  ✓ PASSED: Constant-time equality comparison")
        
        buf = bytearray(b"sensitive_data")
        ct_ops.ct_memzero(buf)
        assert all(b == 0 for b in buf)
        print("  ✓ PASSED: Secure memory zeroization")
        
        test_results.append({"test": "constant_time_ops", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "constant_time_ops", "status": "FAILED", "error": str(e)})
        all_passed = False
    
    # Test 2: Masked Value Secret Sharing
    print("\n[TEST 2] Masked Value Secret Sharing")
    try:
        secret = secrets.token_bytes(32)
        
        for scheme in MaskingScheme:
            masked = MaskedValue(secret, scheme)
            recovered = masked.unmask()
            assert recovered == secret, f"Scheme {scheme} failed"
        
        print(f"  ✓ PASSED: All masking schemes work correctly")
        print(f"    Schemes tested: {[s.value for s in MaskingScheme]}")
        
        test_results.append({"test": "masked_value", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "masked_value", "status": "FAILED", "error": str(e)})
        all_passed = False
    
    # Test 3: Key Wrapper Initialization
    print("\n[TEST 3] Key Wrapper Initialization")
    try:
        kek = secrets.token_bytes(32)
        wrapper = SideChannelResistantKeyWrapperV3(
            kek=kek,
            algorithm=KeyWrapAlgorithm.AES_KW_HMAC,
            security_level=SecurityLevel.LEVEL_3
        )
        
        assert wrapper.VERSION == "3.0.0"
        assert wrapper.algorithm == KeyWrapAlgorithm.AES_KW_HMAC
        assert wrapper.security_level == SecurityLevel.LEVEL_3
        print("  ✓ PASSED: Key Wrapper initialized correctly")
        print(f"    Version: {wrapper.VERSION}")
        print(f"    Algorithm: {wrapper.algorithm.value}")
        print(f"    Security Level: {wrapper.security_level.value}")
        
        test_results.append({"test": "wrapper_init", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "wrapper_init", "status": "FAILED", "error": str(e)})
        all_passed = False
    
    # Test 4: Key Wrap/Unwrap Cycle (256-bit key)
    print("\n[TEST 4] Key Wrap/Unwrap Cycle - 256-bit Key")
    try:
        kek = secrets.token_bytes(32)
        plaintext_key = secrets.token_bytes(32)
        
        wrapper = SideChannelResistantKeyWrapperV3(
            kek=kek,
            algorithm=KeyWrapAlgorithm.AES_KW_HMAC
        )
        
        wrap_result = wrapper.wrap_key(plaintext_key)
        assert isinstance(wrap_result, WrappedKeyResult)
        assert len(wrap_result.wrapped_key) > 0
        assert len(wrap_result.authentication_tag) > 0
        
        unwrap_result = wrapper.unwrap_key(
            wrap_result.wrapped_key,
            wrap_result.authentication_tag
        )
        
        assert isinstance(unwrap_result, UnwrapResult)
        assert unwrap_result.is_valid == True
        assert unwrap_result.authentication_passed == True
        assert unwrap_result.integrity_verified == True
        assert unwrap_result.unwrapped_key[:32] == plaintext_key
        
        print(f"  ✓ PASSED: Wrap/unwrap cycle successful")
        print(f"    Plain key length: {len(plaintext_key)} bytes")
        print(f"    Wrapped key length: {len(wrap_result.wrapped_key)} bytes")
        print(f"    Key match: {unwrap_result.unwrapped_key[:32] == plaintext_key}")
        
        test_results.append({"test": "wrap_unwrap_cycle", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "wrap_unwrap_cycle", "status": "FAILED", "error": str(e)})
        all_passed = False
    
    # Test 5: Key Wrap/Unwrap Cycle (128-bit key)
    print("\n[TEST 5] Key Wrap/Unwrap Cycle - 128-bit Key")
    try:
        kek = secrets.token_bytes(16)
        plaintext_key = secrets.token_bytes(16)
        
        wrapper = SideChannelResistantKeyWrapperV3(
            kek=kek,
            algorithm=KeyWrapAlgorithm.RFC3394_STYLE
        )
        
        wrap_result = wrapper.wrap_key(plaintext_key)
        unwrap_result = wrapper.unwrap_key(wrap_result.wrapped_key)
        
        assert unwrap_result.is_valid == True
        assert unwrap_result.unwrapped_key[:16] == plaintext_key
        print(f"  ✓ PASSED: 128-bit key wrap/unwrap successful")
        
        test_results.append({"test": "wrap_unwrap_128bit", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "wrap_unwrap_128bit", "status": "FAILED", "error": str(e)})
        all_passed = False
    
    # Test 6: Tamper Detection
    print("\n[TEST 6] Tamper Detection")
    try:
        kek = secrets.token_bytes(32)
        plaintext_key = secrets.token_bytes(32)
        
        wrapper = SideChannelResistantKeyWrapperV3(
            kek=kek,
            algorithm=KeyWrapAlgorithm.AES_KW_HMAC
        )
        
        wrap_result = wrapper.wrap_key(plaintext_key)
        
        # Tamper with the wrapped key
        tampered_wrapped = bytearray(wrap_result.wrapped_key)
        tampered_wrapped[20] ^= 0xFF  # Flip byte in wrapped data
        
        unwrap_result = wrapper.unwrap_key(
            bytes(tampered_wrapped),
            wrap_result.authentication_tag
        )
        
        # Tampering should be detected
        assert unwrap_result.is_valid == False or unwrap_result.integrity_verified == False
        print(f"  ✓ PASSED: Tampering correctly detected")
        print(f"    Valid: {unwrap_result.is_valid}")
        print(f"    Integrity verified: {unwrap_result.integrity_verified}")
        
        test_results.append({"test": "tamper_detection", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "tamper_detection", "status": "FAILED", "error": str(e)})
        all_passed = False
    
    # Test 7: Wrong Authentication Tag Detection
    print("\n[TEST 7] Wrong Authentication Tag Detection")
    try:
        kek = secrets.token_bytes(32)
        plaintext_key = secrets.token_bytes(32)
        
        wrapper = SideChannelResistantKeyWrapperV3(
            kek=kek,
            algorithm=KeyWrapAlgorithm.AES_KW_HMAC
        )
        
        wrap_result = wrapper.wrap_key(plaintext_key)
        wrong_tag = secrets.token_bytes(32)
        
        unwrap_result = wrapper.unwrap_key(
            wrap_result.wrapped_key,
            wrong_tag
        )
        
        assert unwrap_result.authentication_passed == False
        print(f"  ✓ PASSED: Wrong authentication tag correctly rejected")
        print(f"    Auth passed: {unwrap_result.authentication_passed}")
        
        test_results.append({"test": "wrong_tag_detection", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "wrong_tag_detection", "status": "FAILED", "error": str(e)})
        all_passed = False
    
    # Test 8: Key Diversification
    print("\n[TEST 8] Key Diversification")
    try:
        kek = secrets.token_bytes(32)
        wrapper = SideChannelResistantKeyWrapperV3(kek=kek)
        
        master_key = secrets.token_bytes(32)
        diversifier1 = b"context_application_1"
        diversifier2 = b"context_application_2"
        
        derived1 = wrapper.diversify_key(master_key, diversifier1)
        derived2 = wrapper.diversify_key(master_key, diversifier2)
        derived1_again = wrapper.diversify_key(master_key, diversifier1)
        
        assert len(derived1) == 32
        assert derived1 != derived2
        assert derived1 == derived1_again
        
        print(f"  ✓ PASSED: Key diversification working correctly")
        print(f"    Same diversifier produces same key: {derived1 == derived1_again}")
        print(f"    Different diversifiers produce different keys: {derived1 != derived2}")
        
        test_results.append({"test": "key_diversification", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "key_diversification", "status": "FAILED", "error": str(e)})
        all_passed = False
    
    # Test 9: Statistics Tracking
    print("\n[TEST 9] Statistics Tracking")
    try:
        kek = secrets.token_bytes(32)
        wrapper = SideChannelResistantKeyWrapperV3(kek=kek)
        
        for i in range(5):
            key = secrets.token_bytes(32)
            result = wrapper.wrap_key(key)
            wrapper.unwrap_key(result.wrapped_key, result.authentication_tag)
        
        stats = wrapper.get_statistics()
        assert stats["wrap_operations"] == 5
        assert stats["unwrap_operations"] == 5
        
        print(f"  ✓ PASSED: Statistics tracking working correctly")
        print(f"    Wrap operations: {stats['wrap_operations']}")
        print(f"    Unwrap operations: {stats['unwrap_operations']}")
        print(f"    Auth failures: {stats['authentication_failures']}")
        
        test_results.append({"test": "statistics_tracking", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "statistics_tracking", "status": "FAILED", "error": str(e)})
        all_passed = False
    
    # Test 10: Different Security Levels
    print("\n[TEST 10] Security Level Configuration")
    try:
        kek = secrets.token_bytes(32)
        
        for level in SecurityLevel:
            wrapper = SideChannelResistantKeyWrapperV3(
                kek=kek,
                security_level=level
            )
            assert wrapper.security_level == level
        
        print(f"  ✓ PASSED: All security levels work correctly")
        print(f"    Levels tested: {[l.value for l in SecurityLevel]}")
        
        test_results.append({"test": "security_levels", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "security_levels", "status": "FAILED", "error": str(e)})
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    passed_count = sum(1 for r in test_results if r["status"] == "PASSED")
    total_count = len(test_results)
    print(f"Passed: {passed_count}/{total_count}")
    
    if all_passed:
        print("\n✓ ALL TESTS PASSED - PRODUCTION READY")
    else:
        print("\n✗ SOME TESTS FAILED")
    
    # Save results
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_side_channel_key_wrapper_v3.json', 'w') as f:
        json.dump({
            "test_suite": "Side-Channel Resistant Key Wrapper V3",
            "version": "3.0.0",
            "timestamp": "2026-06-20",
            "all_passed": all_passed,
            "passed_count": passed_count,
            "total_count": total_count,
            "results": test_results
        }, f, indent=2)
    
    print(f"\nResults saved to test_results_side_channel_key_wrapper_v3.json")
    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
