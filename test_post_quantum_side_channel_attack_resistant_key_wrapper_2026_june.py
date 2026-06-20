#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Side-Channel Attack Resistant Key Wrapper
June 2026 - Production Grade Tests

This test suite validates all functionality of the Side-Channel Resistant
Key Wrapper including constant-time execution, memory obfuscation, glitch
detection, and fault injection resistance.
"""

import os
import sys
import time
import secrets
import tempfile

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_side_channel_attack_resistant_key_wrapper_2026_june import (
    SideChannelResistantKeyWrapper,
    MitigationConfig,
    SideChannelMitigation,
    KeyType,
    constant_time_compare,
    ConstantTimeExecutor,
    MemoryObfuscator,
    GlitchFaultDetector
)


def test_constant_time_comparison():
    """Test constant-time comparison function"""
    print("Test 1: Constant-Time Comparison")
    
    # Test equal values
    a = secrets.token_bytes(32)
    b = bytes(a)
    result = constant_time_compare(a, b)
    print(f"  Equal values: {result}")
    assert result == True, "Equal values should return True"
    
    # Test different values
    c = secrets.token_bytes(32)
    result2 = constant_time_compare(a, c)
    print(f"  Different values: {result2}")
    assert result2 == False, "Different values should return False"
    
    # Test different lengths
    result3 = constant_time_compare(a, a[:16])
    print(f"  Different lengths: {result3}")
    assert result3 == False, "Different lengths should return False"
    
    print("  ✓ PASSED\n")
    return True


def test_engine_initialization():
    """Test wrapper initialization with different mitigation levels"""
    print("Test 2: Engine Initialization")
    
    for level in SideChannelMitigation:
        config = MitigationConfig(mitigation_level=level)
        wrapper = SideChannelResistantKeyWrapper(config)
        summary = wrapper.get_mitigation_summary()
        
        print(f"  {level.value}: Resistance Score = {summary['side_channel_resistance_score']:.1f}")
        assert summary['side_channel_resistance_score'] > 0
    
    print("  ✓ PASSED\n")
    return True


def test_wrapping_key_generation():
    """Test secure wrapping key generation"""
    print("Test 3: Wrapping Key Generation")
    
    wrapper = SideChannelResistantKeyWrapper()
    key_id = "test-wrap-key-001"
    
    result = wrapper.generate_wrapping_key(key_id)
    print(f"  Generated key ID: {result}")
    print(f"  Wrapping keys in store: {len(wrapper.wrapping_keys)}")
    
    assert result == key_id
    assert key_id in wrapper.wrapping_keys
    assert len(wrapper.wrapping_keys[key_id]) == 32  # 256-bit key
    
    print("  ✓ PASSED\n")
    return True


def test_key_wrap_unwrap():
    """Test core key wrap and unwrap functionality"""
    print("Test 4: Key Wrap/Unwrap")
    
    wrapper = SideChannelResistantKeyWrapper()
    wrapper.generate_wrapping_key("main-key")
    
    # Test with different PQC key types
    test_cases = [
        (KeyType.KYBER512, 16, "Kyber512"),
        (KeyType.KYBER768, 24, "Kyber768"),
        (KeyType.KYBER1024, 32, "Kyber1024"),
        (KeyType.DILITHIUM3, 48, "Dilithium3"),
    ]
    
    for key_type, key_size, name in test_cases:
        plaintext_key = secrets.token_bytes(key_size)
        
        # Wrap
        wrapped = wrapper.wrap_key(plaintext_key, key_type, "main-key")
        print(f"  {name}: Wrapped successfully")
        print(f"    Key ID: {wrapped.key_id}")
        print(f"    Resistance Score: {wrapped.side_channel_resistance_score:.1f}")
        print(f"    Wrap counter: {wrapped.wrap_counter}")
        
        # Verify wrapped data is different from plaintext
        assert wrapped.wrapped_data != plaintext_key, "Data should be encrypted"
        
        # Unwrap
        unwrap_result = wrapper.unwrap_key(wrapped)
        assert unwrap_result.success, f"Unwrap should succeed: {unwrap_result.error_message}"
        
        # Verify round-trip integrity
        assert unwrap_result.data == plaintext_key, "Round-trip should preserve key"
        print(f"    Round-trip integrity: ✓")
    
    print("  ✓ PASSED\n")
    return True


def test_authentication_tag_verification():
    """Test that tampered data fails authentication"""
    print("Test 5: Authentication Tag Verification")
    
    wrapper = SideChannelResistantKeyWrapper()
    wrapper.generate_wrapping_key("auth-test-key")
    
    plaintext_key = secrets.token_bytes(32)
    wrapped = wrapper.wrap_key(plaintext_key, KeyType.KYBER768, "auth-test-key")
    
    # Tamper with wrapped data
    tampered_data = bytearray(wrapped.wrapped_data)
    tampered_data[0] ^= 0xFF  # Flip first byte
    wrapped.wrapped_data = bytes(tampered_data)
    
    # Attempt unwrap - should fail
    result = wrapper.unwrap_key(wrapped)
    print(f"  Tampered data unwrap success: {result.success}")
    print(f"  Error message: {result.error_message}")
    
    assert result.success == False, "Tampered data should fail authentication"
    
    print("  ✓ PASSED\n")
    return True


def test_constant_time_executor():
    """Test constant-time execution normalization"""
    print("Test 6: Constant-Time Executor")
    
    config = MitigationConfig(
        mitigation_level=SideChannelMitigation.MAXIMUM,
        timing_normalization=True,
        dummy_operations=True
    )
    
    executor = ConstantTimeExecutor(config)
    
    # Operations of different complexity
    def fast_op():
        return b"fast"
    
    def slow_op():
        result = b""
        for _ in range(1000):
            result += secrets.token_bytes(1)
        return result[:4]
    
    # Run multiple times and check timing variance
    timings_fast = []
    timings_slow = []
    
    for _ in range(10):
        start = time.perf_counter()
        executor.execute(fast_op, target_duration=0.01)
        timings_fast.append(time.perf_counter() - start)
        
        start = time.perf_counter()
        executor.execute(slow_op, target_duration=0.01)
        timings_slow.append(time.perf_counter() - start)
    
    avg_fast = sum(timings_fast) / len(timings_fast)
    avg_slow = sum(timings_slow) / len(timings_slow)
    timing_diff = abs(avg_fast - avg_slow) / max(avg_fast, avg_slow)
    
    print(f"  Fast op avg time: {avg_fast*1000:.2f}ms")
    print(f"  Slow op avg time: {avg_slow*1000:.2f}ms")
    print(f"  Timing difference: {timing_diff*100:.1f}%")
    
    # With normalization, timing difference should be small (< 20%)
    assert timing_diff < 0.20, "Timing should be normalized"
    
    print("  ✓ PASSED\n")
    return True


def test_memory_obfuscator():
    """Test memory obfuscation and secure zeroization"""
    print("Test 7: Memory Obfuscator")
    
    config = MitigationConfig(
        memory_obfuscation=True,
        secure_zeroization=True,
        memory_scramble_passes=3
    )
    
    obfuscator = MemoryObfuscator(config)
    
    # Test scrambling
    original = b"test data for memory obfuscation 12345"
    scrambled = obfuscator.scramble_memory(original)
    
    print(f"  Original length: {len(original)}")
    print(f"  Scrambled length: {len(scrambled)}")
    print(f"  Data changed: {original != scrambled}")
    
    assert len(scrambled) == len(original)
    assert scrambled != original  # Should be different after scramble
    
    # Test secure zeroization
    sensitive = bytearray(b"this is very sensitive key material")
    original_copy = bytes(sensitive)
    
    obfuscator.secure_zeroize(sensitive)
    
    print(f"  Zeroized: {all(b == 0 for b in sensitive)}")
    
    assert all(b == 0 for b in sensitive)
    assert bytes(sensitive) != original_copy
    
    print("  ✓ PASSED\n")
    return True


def test_glitch_fault_detector():
    """Test glitch and fault injection detection"""
    print("Test 8: Glitch/Fault Detector")
    
    config = MitigationConfig(
        glitch_detection=True,
        fault_detection=True,
        noise_injection=True
    )
    
    detector = GlitchFaultDetector(config)
    
    # Normal operation - no glitch/fault
    def normal_op(data):
        return hashlib.sha256(data).digest()
    
    import hashlib
    test_data = b"test input"
    result, glitch, fault = detector.compute_redundant(test_data, normal_op)
    
    print(f"  Normal operation:")
    print(f"    Glitch detected: {glitch}")
    print(f"    Fault detected: {fault}")
    
    assert glitch == False
    assert fault == False
    assert len(result) == 32  # SHA256 output
    
    print("  ✓ PASSED\n")
    return True


def test_side_channel_resistance_verification():
    """Test side-channel resistance verification"""
    print("Test 9: Resistance Verification")
    
    wrapper = SideChannelResistantKeyWrapper(MitigationConfig(
        mitigation_level=SideChannelMitigation.MAXIMUM
    ))
    
    # Run verification (fewer iterations for test speed)
    metrics = wrapper.verify_side_channel_resistance(num_iterations=20)
    
    print(f"  Timing variance (CV): {metrics.timing_variance:.4f}")
    print(f"  Constant-time verified: {metrics.constant_time_verified}")
    print(f"  Leakage detected: {metrics.leakage_detected}")
    print(f"  Overall resistance score: {metrics.overall_resistance_score:.1f}")
    print(f"  Power uniformity: {metrics.power_consumption_uniformity:.2f}")
    
    assert metrics.overall_resistance_score >= 80
    assert metrics.power_consumption_uniformity > 0.8
    
    print("  ✓ PASSED\n")
    return True


def test_mitigation_configuration_levels():
    """Test different mitigation configuration levels"""
    print("Test 10: Mitigation Configuration Levels")
    
    levels = [
        (SideChannelMitigation.MINIMAL, 40),
        (SideChannelMitigation.BASIC, 50),
        (SideChannelMitigation.STANDARD, 65),
        (SideChannelMitigation.ENHANCED, 80),
        (SideChannelMitigation.MAXIMUM, 90),
        (SideChannelMitigation.HSM_LEVEL, 95),
    ]
    
    for level, min_expected_score in levels:
        config = MitigationConfig(mitigation_level=level)
        wrapper = SideChannelResistantKeyWrapper(config)
        score = wrapper._calculate_resistance_score()
        
        print(f"  {level.value}: Score = {score:.1f} (min expected: {min_expected_score})")
        assert score >= min_expected_score, f"{level} should have score >= {min_expected_score}"
    
    print("  ✓ PASSED\n")
    return True


def test_mitigation_summary():
    """Test mitigation summary report"""
    print("Test 11: Mitigation Summary")
    
    wrapper = SideChannelResistantKeyWrapper()
    summary = wrapper.get_mitigation_summary()
    
    print(f"  Level: {summary['mitigation_level']}")
    print(f"  Resistance score: {summary['side_channel_resistance_score']:.1f}")
    print(f"  Active mitigations: {sum(summary['active_mitigations'].values())} enabled")
    print(f"  Dummy ops per call: {summary['dummy_operation_count']}")
    print(f"  Scramble passes: {summary['memory_scramble_passes']}")
    
    assert 'mitigation_level' in summary
    assert 'side_channel_resistance_score' in summary
    assert 'active_mitigations' in summary
    assert summary['side_channel_resistance_score'] > 0
    
    print("  ✓ PASSED\n")
    return True


def test_multiple_wrap_operations():
    """Test multiple wrap operations with counter tracking"""
    print("Test 12: Multiple Wrap Operations")
    
    wrapper = SideChannelResistantKeyWrapper()
    wrapper.generate_wrapping_key("multi-key")
    
    initial_counter = wrapper.wrap_counter
    
    for i in range(5):
        key = secrets.token_bytes(32)
        wrapped = wrapper.wrap_key(key, KeyType.KYBER768, "multi-key")
        print(f"  Wrap {i+1}: Counter = {wrapped.wrap_counter}")
    
    print(f"  Final counter: {wrapper.wrap_counter}")
    
    assert wrapper.wrap_counter == initial_counter + 5
    
    print("  ✓ PASSED\n")
    return True


def run_all_tests():
    """Run all tests and generate results summary"""
    print("=" * 65)
    print("Post-Quantum Side-Channel Resistant Key Wrapper Tests")
    print("June 2026 - Production Grade")
    print("=" * 65 + "\n")
    
    tests = [
        test_constant_time_comparison,
        test_engine_initialization,
        test_wrapping_key_generation,
        test_key_wrap_unwrap,
        test_authentication_tag_verification,
        test_constant_time_executor,
        test_memory_obfuscator,
        test_glitch_fault_detector,
        test_side_channel_resistance_verification,
        test_mitigation_configuration_levels,
        test_mitigation_summary,
        test_multiple_wrap_operations,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"  ✗ FAILED: {e}\n")
            import traceback
            traceback.print_exc()
            results.append(False)
    
    print("=" * 65)
    passed = sum(results)
    total = len(results)
    print(f"TEST SUMMARY: {passed}/{total} tests passed")
    
    if passed == total:
        print("ALL TESTS PASSED ✓")
        print("=" * 65)
        return True
    else:
        print(f"SOME TESTS FAILED ({total - passed} failures)")
        print("=" * 65)
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
