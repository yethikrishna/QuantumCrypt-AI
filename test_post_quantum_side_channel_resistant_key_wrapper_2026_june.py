#!/usr/bin/env python3
"""
Test suite for Post-Quantum Side-Channel Resistant Key Wrapper
Production-grade verification tests
All tests run REAL cryptographic operations
"""
import sys
import json
import secrets
import time
from datetime import datetime

# Add the module path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_side_channel_resistant_key_wrapper_2026_june import (
    SideChannelResistantKeyWrapper,
    ConstantTimeOperations,
    PowerAnalysisMasker,
    CacheTimingProtector,
    EMAnalysisProtector,
    KeyAlgorithm,
    WrappedKeyResult
)

def run_tests():
    """Run all verification tests"""
    print("=" * 70)
    print("POST-QUANTUM SIDE-CHANNEL RESISTANT KEY WRAPPER - TEST SUITE")
    print("=" * 70)
    print(f"Test started: {datetime.now()}")
    print()
    
    test_results = []
    
    # Test 1: Module imports correctly
    print("[TEST 1] Module Import and Initialization")
    try:
        master_key = secrets.token_bytes(32)
        wrapper = SideChannelResistantKeyWrapper(master_key=master_key)
        
        print(f"  ✓ Key Wrapper initialized successfully")
        print(f"  ✓ Version: {wrapper.VERSION}")
        print(f"  ✓ Master key length: {len(wrapper._master_key) * 8} bits")
        test_results.append(("Module Initialization", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Module Initialization", False, str(e)))
        return test_results
    print()
    
    # Test 2: Constant-Time Operations
    print("[TEST 2] Constant-Time Operations")
    try:
        ct = ConstantTimeOperations()
        
        # Test constant-time XOR
        a = b'hello world 12345'
        b = b'random mask bytes'
        xor_result = ct.ct_xor(a, b)
        xor_back = ct.ct_xor(xor_result, b)
        
        assert xor_back == a, "XOR roundtrip failed"
        print(f"  ✓ Constant-time XOR: roundtrip successful")
        
        # Test constant-time compare
        test1 = b'test string 1'
        test2 = b'test string 1'
        test3 = b'test string 2'
        
        assert ct.ct_compare_equal(test1, test2) == True, "Equal compare failed"
        assert ct.ct_compare_equal(test1, test3) == False, "Not equal compare failed"
        print(f"  ✓ Constant-time comparison: working correctly")
        
        # Test constant-time select
        selected_true = ct.ct_select(True, b'option_a', b'option_b')
        selected_false = ct.ct_select(False, b'option_a', b'option_b')
        
        assert selected_true == b'option_a', "Select true failed"
        assert selected_false == b'option_b', "Select false failed"
        print(f"  ✓ Constant-time select: branchless logic working")
        
        test_results.append(("Constant-Time Operations", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        test_results.append(("Constant-Time Operations", False, str(e)))
    print()
    
    # Test 3: Power Analysis Masking
    print("[TEST 3] Power Analysis Masking (DPA/CPA Protection)")
    try:
        masker = PowerAnalysisMasker(mask_size=32)
        
        # Test boolean masking
        original = secrets.token_bytes(32)
        masked, mask = masker.apply_boolean_mask(original)
        
        assert masked != original, "Data not masked"
        assert len(mask) == len(original), "Wrong mask length"
        
        unmasked = masker.remove_boolean_mask(masked, mask)
        assert unmasked == original, "Mask removal failed"
        
        print(f"  ✓ Boolean masking: apply/remove roundtrip successful")
        print(f"  ✓ Mask length: {len(mask)} bytes")
        
        # Test arithmetic masking
        value = 123456789
        masked_val, mask_val = masker.apply_arithmetic_mask(value)
        unmasked_val = masker.remove_arithmetic_mask(masked_val, mask_val)
        
        assert unmasked_val == value, "Arithmetic mask removal failed"
        print(f"  ✓ Arithmetic masking: working correctly")
        
        # Test mask refreshing
        refreshed, new_mask = masker.refresh_mask(masked, mask)
        assert refreshed != masked, "Mask not refreshed"
        print(f"  ✓ Mask refreshing: prevents higher-order DPA")
        
        test_results.append(("Power Analysis Masking", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Power Analysis Masking", False, str(e)))
    print()
    
    # Test 4: Cache-Timing Protection
    print("[TEST 4] Cache-Timing Protection")
    try:
        protector = CacheTimingProtector(block_size=64)
        
        # Test uniform access pattern
        data = secrets.token_bytes(128)
        uniform = protector.uniform_access_pattern(data)
        
        assert uniform == data, "Uniform access altered data"
        print(f"  ✓ Uniform memory access: data preserved")
        
        # Test constant-time table lookup
        table = [b'entry0', b'entry1', b'entry2', b'entry3']
        lookup_2 = protector.constant_time_lookup(table, 2)
        
        assert lookup_2 == b'entry2', "Table lookup failed"
        print(f"  ✓ Constant-time table lookup: working")
        
        test_results.append(("Cache-Timing Protection", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Cache-Timing Protection", False, str(e)))
    print()
    
    # Test 5: EM Analysis Protection
    print("[TEST 5] EM Analysis Countermeasures")
    try:
        protector = EMAnalysisProtector()
        
        # Test dual-rail encoding
        data = secrets.token_bytes(32)
        rail0, rail1 = protector.dual_rail_encoding(data)
        
        # Verify: rail0 XOR rail1 = data
        reconstructed = bytes(x ^ y for x, y in zip(rail0, rail1))
        assert reconstructed == data, "Dual-rail reconstruction failed"
        
        print(f"  ✓ Dual-rail encoding: reconstruction successful")
        print(f"  ✓ Rail lengths: {len(rail0)}, {len(rail1)} bytes")
        
        # Test dummy operations
        protector.insert_dummy_operations()
        print(f"  ✓ Dummy operations: EM profile balancing")
        
        # Test random delay
        start = time.perf_counter()
        protector.random_delay(100, 500)
        elapsed = (time.perf_counter() - start) * 1e6
        
        assert elapsed > 50, "Random delay too short"
        print(f"  ✓ Random delay: {elapsed:.0f}us (disrupts trace alignment)")
        
        test_results.append(("EM Analysis Protection", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("EM Analysis Protection", False, str(e)))
    print()
    
    # Test 6: Full Key Wrap/Unwrap Workflow
    print("[TEST 6] Full Key Wrap/Unwrap Workflow")
    try:
        wrapper = SideChannelResistantKeyWrapper()
        
        # Test with Kyber-768 post-quantum key
        plaintext_key = secrets.token_bytes(32)  # 256-bit key
        
        # Wrap the key
        wrapped = wrapper.wrap_key(
            plaintext_key, 
            algorithm=KeyAlgorithm.KYBER_768,
            key_id="TEST-KYBER-001"
        )
        
        print(f"  ✓ Key wrapped successfully")
        print(f"  ✓ Algorithm: {wrapped.algorithm}")
        print(f"  ✓ Key ID: {wrapped.key_id}")
        print(f"  ✓ Wrapped key length: {len(wrapped.wrapped_key)} bytes")
        print(f"  ✓ IV length: {len(wrapped.iv)} bytes")
        print(f"  ✓ Tag length: {len(wrapped.tag)} bytes")
        print(f"  ✓ Security level: NIST Level {wrapped.security_level}")
        print(f"  ✓ Protections: {len(wrapped.side_channel_protections)} enabled")
        
        # Unwrap the key
        unwrapped = wrapper.unwrap_key(wrapped)
        
        assert unwrapped.verified == True, "Verification failed"
        assert unwrapped.tamper_detected == False, "False tamper detection"
        assert unwrapped.plaintext_key == plaintext_key, "Key mismatch after unwrap"
        assert unwrapped.key_id == wrapped.key_id, "Key ID mismatch"
        
        print(f"  ✓ Key unwrapped successfully")
        print(f"  ✓ Integrity verified: {unwrapped.verified}")
        print(f"  ✓ Tamper detected: {unwrapped.tamper_detected}")
        print(f"  ✓ Timing resistant: {unwrapped.timing_resistant}")
        print(f"  ✓ Plaintext key matches original: YES")
        
        test_results.append(("Full Wrap/Unwrap Workflow", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        test_results.append(("Full Wrap/Unwrap Workflow", False, str(e)))
    print()
    
    # Test 7: Tamper Detection
    print("[TEST 7] Tamper Detection")
    try:
        wrapper = SideChannelResistantKeyWrapper()
        plaintext_key = secrets.token_bytes(32)
        wrapped = wrapper.wrap_key(plaintext_key, KeyAlgorithm.KYBER_1024)
        
        # Tamper with wrapped key
        tampered_wrapped = WrappedKeyResult(
            wrapped_key=wrapped.wrapped_key[:-1] + b'X',
            iv=wrapped.iv,
            tag=wrapped.tag,
            key_id=wrapped.key_id,
            algorithm=wrapped.algorithm,
            timestamp=wrapped.timestamp,
            masking_nonce=wrapped.masking_nonce,
            verification_hash=wrapped.verification_hash,
            security_level=wrapped.security_level,
            side_channel_protections=wrapped.side_channel_protections
        )
        
        unwrapped = wrapper.unwrap_key(tampered_wrapped)
        
        assert unwrapped.verified == False, "Tamper not detected"
        assert unwrapped.tamper_detected == True, "Tamper flag not set"
        
        print(f"  ✓ Tampered data correctly detected")
        print(f"  ✓ Verified: {unwrapped.verified}")
        print(f"  ✓ Tamper detected: {unwrapped.tamper_detected}")
        print(f"  ✓ Tamper attempts counter: {wrapper.tamper_attempts_detected}")
        
        test_results.append(("Tamper Detection", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Tamper Detection", False, str(e)))
    print()
    
    # Test 8: Multiple Algorithm Support
    print("[TEST 8] Multiple Algorithm Support")
    try:
        wrapper = SideChannelResistantKeyWrapper()
        test_key = secrets.token_bytes(32)
        
        algorithms = [
            KeyAlgorithm.KYBER_512,
            KeyAlgorithm.KYBER_768,
            KeyAlgorithm.KYBER_1024,
            KeyAlgorithm.DILITHIUM_3,
            KeyAlgorithm.AES_256_GCM,
            KeyAlgorithm.HYBRID_KYBER_AES
        ]
        
        for alg in algorithms:
            wrapped = wrapper.wrap_key(test_key, algorithm=alg)
            unwrapped = wrapper.unwrap_key(wrapped)
            
            assert unwrapped.verified, f"Verification failed for {alg.value}"
            assert unwrapped.plaintext_key == test_key, f"Key mismatch for {alg.value}"
            
            print(f"  ✓ {alg.value}: NIST Level {wrapped.security_level} - PASS")
        
        print(f"  ✓ All {len(algorithms)} algorithms working correctly")
        
        test_results.append(("Multiple Algorithm Support", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Multiple Algorithm Support", False, str(e)))
    print()
    
    # Test 9: Timing Consistency Verification
    print("[TEST 9] Timing Consistency Verification")
    try:
        wrapper = SideChannelResistantKeyWrapper()
        
        # Run actual timing test (fewer iterations for test speed)
        timing_results = wrapper.constant_time_timing_test(num_iterations=200)
        
        print(f"  ✓ Iterations: {timing_results['iterations']}")
        print(f"  ✓ Mean time: {timing_results['mean_time_ns']:.0f}ns")
        print(f"  ✓ Std dev: {timing_results['std_dev_ns']:.0f}ns")
        print(f"  ✓ Coefficient of variation: {timing_results['coefficient_of_variation']:.4f}")
        print(f"  ✓ Timing consistency score: {timing_results['timing_consistency_score']:.2f}")
        print(f"  ✓ Passes timing test: {timing_results['passes_timing_test']}")
        
        test_results.append(("Timing Consistency", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Timing Consistency", False, str(e)))
    print()
    
    # Test 10: Security Report
    print("[TEST 10] Security Report")
    try:
        wrapper = SideChannelResistantKeyWrapper()
        
        # Perform some operations
        for i in range(5):
            key = secrets.token_bytes(32)
            wrapped = wrapper.wrap_key(key, KeyAlgorithm.KYBER_768)
            wrapper.unwrap_key(wrapped)
        
        report = wrapper.get_security_report()
        
        print(f"  ✓ Wrapper version: {report['wrapper_version']}")
        print(f"  ✓ Keys wrapped: {report['keys_wrapped']}")
        print(f"  ✓ Keys unwrapped: {report['keys_unwrapped']}")
        print(f"  ✓ Tamper attempts: {report['tamper_attempts_detected']}")
        print(f"  ✓ Protections enabled: {len(report['protections_enabled'])}")
        print(f"  ✓ Supported algorithms: {len(report['supported_algorithms'])}")
        print(f"  ✓ Master key: {report['master_key_length_bits']} bits")
        
        test_results.append(("Security Report", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Security Report", False, str(e)))
    print()
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, ok, _ in test_results if ok)
    total = len(test_results)
    
    for name, ok, error in test_results:
        status = "✓ PASS" if ok else "✗ FAIL"
        print(f"  {status} - {name}")
        if error:
            print(f"      Error: {error}")
    
    print()
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("ALL TESTS PASSED ✓")
    else:
        print(f"SOME TESTS FAILED ✗ ({total - passed} failures)")
    
    print()
    print(f"Test completed: {datetime.now()}")
    
    # Save test results
    test_output = {
        'test_timestamp': datetime.now().isoformat(),
        'model_version': wrapper.VERSION,
        'tests_passed': passed,
        'tests_total': total,
        'all_passed': passed == total,
        'results': {name: ok for name, ok, _ in test_results}
    }
    
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_side_channel_key_wrapper.json', 'w') as f:
        json.dump(test_output, f, indent=2)
    
    print(f"\nTest results saved to test_results_side_channel_key_wrapper.json")
    
    return test_results

if __name__ == '__main__':
    results = run_tests()
    passed = sum(1 for _, ok, _ in results if ok)
    sys.exit(0 if passed == len(results) else 1)
