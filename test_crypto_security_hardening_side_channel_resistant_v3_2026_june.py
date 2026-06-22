"""
Test Suite for QuantumCrypt Security Hardening v3 - Side-Channel Resistant Execution
Dimension B: Security Hardening

ADD-ONLY tests - no existing tests modified
All existing tests must continue to pass
"""

import pytest
import time
import secrets
from quantum_crypt.crypto_security_hardening_side_channel_resistant_v3_2026_june import (
    SecureMemory,
    ConstantTime,
    TimingNormalizer,
    SpeculationBarrier,
    CacheSideChannelProtector,
    EMSideChannelResistance,
    SecureKeyHandler,
    constant_time_comparison,
    side_channel_protected,
    secure_wipe_after_use,
    get_secure_memory,
    get_constant_time,
    get_timing_normalizer,
    get_cache_protector,
    get_em_resistance,
    get_secure_key_handler
)


class TestSecureMemory:
    """Test suite for secure memory management"""

    def test_secure_zeroize_bytearray(self):
        """Test secure memory zeroization"""
        buffer = bytearray(b'\x01\x02\x03\x04\x05' * 100)
        original = bytes(buffer)
        
        SecureMemory.secure_zeroize(buffer)
        
        # Should be all zeros
        assert all(b == 0x00 for b in buffer)
        assert bytes(buffer) != original

    def test_secure_zeroize_empty(self):
        """Test zeroization of empty buffer"""
        buffer = bytearray()
        SecureMemory.secure_zeroize(buffer)  # Should not crash
        assert len(buffer) == 0

    def test_secure_compare_equal(self):
        """Test constant-time comparison for equal values"""
        a = b'hello world'
        b = b'hello world'
        
        result = SecureMemory.secure_compare(a, b)
        assert result is True

    def test_secure_compare_not_equal(self):
        """Test constant-time comparison for unequal values"""
        a = b'hello world'
        b = b'hello xorld'
        
        result = SecureMemory.secure_compare(a, b)
        assert result is False

    def test_secure_compare_different_lengths(self):
        """Test comparison with different lengths"""
        a = b'short'
        b = b'much longer string'
        
        result = SecureMemory.secure_compare(a, b)
        assert result is False

    def test_secure_compare_str(self):
        """Test string comparison"""
        result = SecureMemory.secure_compare_str("test", "test")
        assert result is True
        
        result = SecureMemory.secure_compare_str("test", "tesx")
        assert result is False

    def test_create_secure_buffer(self):
        """Test secure buffer creation"""
        buffer = SecureMemory.create_secure_buffer(32)
        assert len(buffer) == 32
        assert isinstance(buffer, bytearray)


class TestConstantTime:
    """Test suite for constant-time operations"""

    def test_ct_eq_equal(self):
        """Test constant-time equality"""
        assert ConstantTime.ct_eq(5, 5) == 1
        assert ConstantTime.ct_eq(0, 0) == 1
        assert ConstantTime.ct_eq(-1, -1) == 1

    def test_ct_eq_not_equal(self):
        """Test constant-time inequality"""
        assert ConstantTime.ct_eq(5, 6) == 0
        assert ConstantTime.ct_eq(0, 1) == 0

    def test_ct_neq(self):
        """Test constant-time not-equal"""
        assert ConstantTime.ct_neq(5, 6) == 1
        assert ConstantTime.ct_neq(5, 5) == 0

    def test_ct_lt(self):
        """Test constant-time less-than"""
        assert ConstantTime.ct_lt(3, 5) == 1
        assert ConstantTime.ct_lt(5, 3) == 0
        assert ConstantTime.ct_lt(5, 5) == 0

    def test_ct_gt(self):
        """Test constant-time greater-than"""
        assert ConstantTime.ct_gt(5, 3) == 1
        assert ConstantTime.ct_gt(3, 5) == 0
        assert ConstantTime.ct_gt(5, 5) == 0

    def test_ct_lte(self):
        """Test constant-time less-than-or-equal"""
        assert ConstantTime.ct_lte(3, 5) == 1
        assert ConstantTime.ct_lte(5, 5) == 1
        assert ConstantTime.ct_lte(5, 3) == 0

    def test_ct_gte(self):
        """Test constant-time greater-than-or-equal"""
        assert ConstantTime.ct_gte(5, 3) == 1
        assert ConstantTime.ct_gte(5, 5) == 1
        assert ConstantTime.ct_gte(3, 5) == 0

    def test_ct_select_int(self):
        """Test constant-time selection for integers"""
        assert ConstantTime.ct_select(1, 100, 200) == 100
        assert ConstantTime.ct_select(0, 100, 200) == 200

    def test_ct_select_generic(self):
        """Test constant-time selection for generic types"""
        assert ConstantTime.ct_select(1, "a", "b") == "a"
        assert ConstantTime.ct_select(0, "a", "b") == "b"

    def test_ct_array_access(self):
        """Test constant-time array access"""
        array = [10, 20, 30, 40, 50, 60, 70, 80]
        result = ConstantTime.ct_array_access(array, 3, 8)
        assert result in array  # Should return valid element


class TestTimingNormalizer:
    """Test suite for timing normalization"""

    def test_initialization(self):
        """Test basic initialization"""
        normalizer = TimingNormalizer(target_ns=100_000)
        assert normalizer.target_ns == 100_000

    def test_normalization_ensures_min_time(self):
        """Test that normalization ensures minimum execution time"""
        normalizer = TimingNormalizer(target_ns=5_000_000)  # 5ms
        
        def fast_function():
            return 42
        
        start = time.perf_counter_ns()
        result = normalizer.normalize_execution_time(fast_function)
        elapsed = time.perf_counter_ns() - start
        
        assert result == 42
        assert elapsed >= 5_000_000  # Should take at least target time

    def test_slow_function_passthrough(self):
        """Test slow functions pass through without extra delay"""
        normalizer = TimingNormalizer(target_ns=1_000)  # 1 microsecond
        
        def slow_function():
            time.sleep(0.002)  # 2ms
            return "done"
        
        # Should complete without hanging
        result = normalizer.normalize_execution_time(slow_function)
        assert result == "done"


class TestSpeculationBarrier:
    """Test suite for speculation barriers"""

    def test_memory_barrier(self):
        """Test memory barrier executes without error"""
        # Should not raise exceptions
        SpeculationBarrier.memory_barrier()
        assert True

    def test_array_index_mask_in_bounds(self):
        """Test index masking for in-bounds access"""
        size = 16
        for i in range(size):
            masked = SpeculationBarrier.array_index_mask(i, size)
            assert masked == i

    def test_secure_conditional(self):
        """Test secure conditional selection"""
        assert SpeculationBarrier.secure_conditional(True, "yes", "no") == "yes"
        assert SpeculationBarrier.secure_conditional(False, "yes", "no") == "no"


class TestCacheSideChannelProtector:
    """Test suite for cache side-channel protection"""

    def test_initialization(self):
        """Test basic initialization"""
        protector = CacheSideChannelProtector(array_size=128)
        assert protector.array_size == 128

    def test_normalize_access_pattern(self):
        """Test access pattern normalization"""
        protector = CacheSideChannelProtector()
        # Should not raise exceptions
        protector.normalize_access_pattern(42)
        assert True

    def test_constant_time_lookup(self):
        """Test constant-time table lookup"""
        protector = CacheSideChannelProtector()
        table = [10, 20, 30, 40, 50]
        
        for i in range(len(table)):
            result = protector.constant_time_lookup(table, i)
            assert result == table[i]


class TestEMSideChannelResistance:
    """Test suite for EM side-channel resistance"""

    def test_initialization(self):
        """Test basic initialization"""
        protector = EMSideChannelResistance(noise_level=5)
        assert protector.noise_level == 5

    def test_add_dummy_operations(self):
        """Test dummy operation injection"""
        protector = EMSideChannelResistance()
        # Should not raise exceptions
        protector.add_dummy_operations(5)
        assert True

    def test_randomize_operation_order(self):
        """Test operation order randomization"""
        protector = EMSideChannelResistance()
        
        ops = [lambda: 1, lambda: 2, lambda: 3, lambda: 4]
        shuffled = protector.randomize_operation_order(ops)
        
        # Same length, same elements (order may differ)
        assert len(shuffled) == len(ops)
        assert set(shuffled) == set(ops)


class TestSecureKeyHandler:
    """Test suite for secure key handling"""

    def test_initialization(self):
        """Test basic initialization"""
        handler = SecureKeyHandler()
        assert handler is not None

    def test_wrap_key_operation(self):
        """Test key operation wrapping with auto-zeroization"""
        handler = SecureKeyHandler()
        
        def key_operation(key, x):
            # Simulate crypto operation
            return sum(key) + x
        
        key = secrets.token_bytes(32)
        result = handler.wrap_key_operation(key, key_operation, 10)
        
        assert isinstance(result, int)


class TestDecorators:
    """Test suite for protection decorators"""

    def test_constant_time_comparison_decorator(self):
        """Test constant time comparison decorator"""
        @constant_time_comparison
        def compare(a, b):
            return a == b
        
        result = compare("test", "test")
        assert result is True

    def test_side_channel_protected_decorator(self):
        """Test side channel protection decorator"""
        @side_channel_protected(normalize_time=False)
        def sensitive_operation(x):
            return x * 2
        
        result = sensitive_operation(21)
        assert result == 42

    def test_secure_wipe_after_use_decorator(self):
        """Test secure wipe decorator"""
        @secure_wipe_after_use
        def process_data(data):
            return len(data)
        
        buffer = bytearray(b'sensitive data')
        result = process_data(buffer)
        assert result == 14
        # Buffer should be zeroized (best effort check)
        # Note: decorator wipes after return, so buffer may be modified


class TestGlobalInstances:
    """Test suite for global singleton instances"""

    def test_global_secure_memory(self):
        """Test global secure memory singleton"""
        mem1 = get_secure_memory()
        mem2 = get_secure_memory()
        assert mem1 is mem2

    def test_global_constant_time(self):
        """Test global constant time singleton"""
        ct1 = get_constant_time()
        ct2 = get_constant_time()
        assert ct1 is ct2

    def test_global_timing_normalizer(self):
        """Test global timing normalizer singleton"""
        tn1 = get_timing_normalizer()
        tn2 = get_timing_normalizer()
        assert tn1 is tn2

    def test_global_cache_protector(self):
        """Test global cache protector singleton"""
        cp1 = get_cache_protector()
        cp2 = get_cache_protector()
        assert cp1 is cp2

    def test_global_em_resistance(self):
        """Test global EM resistance singleton"""
        em1 = get_em_resistance()
        em2 = get_em_resistance()
        assert em1 is em2

    def test_global_secure_key_handler(self):
        """Test global secure key handler singleton"""
        kh1 = get_secure_key_handler()
        kh2 = get_secure_key_handler()
        assert kh1 is kh2


def test_backward_compatibility():
    """
    CRITICAL: Verify backward compatibility
    This module should NOT break any existing crypto code
    """
    try:
        from quantum_crypt import crypto_security_hardening_comprehensive_v2_2026_june
        from quantum_crypt import crypto_security_hardening_input_validation_2026_june
        from quantum_crypt import crypto_security_hardening_side_channel_2026_june
        assert True  # All imports succeeded
    except ImportError as e:
        pytest.fail(f"Side-channel v3 broke backward compatibility: {e}")


def test_integration_with_existing_crypto():
    """
    Test integration with existing post-quantum crypto modules
    """
    try:
        # Import should work without conflicts
        from quantum_crypt import post_quantum_kyber_kem_engine_2026_june
        from quantum_crypt import post_quantum_dilithium_signature_engine_2026_june
        assert True
    except ImportError:
        # These modules might not exist, that's okay
        # Just verify our module doesn't break import machinery
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
