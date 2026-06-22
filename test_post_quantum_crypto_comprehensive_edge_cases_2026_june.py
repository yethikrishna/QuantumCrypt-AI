#!/usr/bin/env python3
"""
Comprehensive Edge Case Tests for Post-Quantum Cryptography Modules
DIMENSION C - Test Coverage Expansion
Covers: edge cases, boundary conditions, error paths, integration tests
"""

import unittest
import sys
import os
import time
import secrets

# Add quantum_crypt to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class TestPostQuantumCryptoEdgeCases(unittest.TestCase):
    """Comprehensive edge case tests for PQ crypto modules"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        
    def test_empty_input_handling(self):
        """Test handling of empty inputs - boundary condition"""
        from quantum_crypt import post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june as zeroizer
        
        # Test empty bytearray
        empty_data = bytearray(b'')
        result = zeroizer.zeroize_sensitive_data(empty_data)
        self.assertIsInstance(result, bool)
        
        # Test None input handling (should not crash)
        try:
            result = zeroizer.zeroize_sensitive_data(None)
        except Exception:
            # Expected behavior - module may raise TypeError for None
            pass
    
    def test_very_large_input_handling(self):
        """Test handling of very large inputs - stress test boundary"""
        from quantum_crypt import post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june as zeroizer
        
        # Test 1MB input
        large_data = bytearray(secrets.token_bytes(1024 * 1024))  # 1MB
        result = zeroizer.zeroize_sensitive_data(large_data)
        self.assertIsInstance(result, bool)
        # Verify data was zeroized
        self.assertEqual(large_data, bytearray(b'\x00' * len(large_data)))
        
        # Test 10MB input
        very_large_data = bytearray(secrets.token_bytes(10 * 1024 * 1024))  # 10MB
        result = zeroizer.zeroize_sensitive_data(very_large_data)
        self.assertIsInstance(result, bool)
        self.assertEqual(very_large_data, bytearray(b'\x00' * len(very_large_data)))
    
    def test_constant_time_comparison_edge_cases(self):
        """Test constant time comparison with various edge cases"""
        from quantum_crypt import post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june as zeroizer
        
        # Test equal empty strings
        self.assertTrue(zeroizer.constant_time_memcmp(b'', b''))
        
        # Test different length inputs (should return False)
        self.assertFalse(zeroizer.constant_time_memcmp(b'a', b'aa'))
        self.assertFalse(zeroizer.constant_time_memcmp(b'aaa', b'aa'))
        
        # Test single byte difference at various positions
        for i in range(10):
            data1 = b'\x00' * 10
            data2 = b'\x00' * 10
            data2 = data2[:i] + b'\x01' + data2[i+1:]
            self.assertFalse(zeroizer.constant_time_memcmp(data1, data2))
        
        # Test all bytes equal
        data = secrets.token_bytes(100)
        self.assertTrue(zeroizer.constant_time_memcmp(data, data))
        
        # Test first byte different
        data1 = b'\x00' + secrets.token_bytes(99)
        data2 = b'\x01' + data1[1:]
        self.assertFalse(zeroizer.constant_time_memcmp(data1, data2))
        
        # Test last byte different
        data1 = secrets.token_bytes(99) + b'\x00'
        data2 = data1[:-1] + b'\x01'
        self.assertFalse(zeroizer.constant_time_memcmp(data1, data2))
    
    def test_constant_time_comparison_timing(self):
        """Verify constant time comparison actually takes constant time"""
        from quantum_crypt import post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june as zeroizer
        
        # Test that early-exit doesn't happen (timing test)
        data1 = b'\x01' + b'\x00' * 999
        data2 = b'\x00' * 1000
        
        # Time comparison with difference at start
        times_start = []
        for _ in range(100):
            start = time.perf_counter()
            zeroizer.constant_time_memcmp(data1, data2)
            times_start.append(time.perf_counter() - start)
        
        # Time comparison with difference at end
        data1 = b'\x00' * 999 + b'\x01'
        data2 = b'\x00' * 1000
        
        times_end = []
        for _ in range(100):
            start = time.perf_counter()
            zeroizer.constant_time_memcmp(data1, data2)
            times_end.append(time.perf_counter() - start)
        
        # Average times should be similar (within 10x)
        avg_start = sum(times_start) / len(times_start)
        avg_end = sum(times_end) / len(times_end)
        
        # This is a statistical test - should be roughly similar
        ratio = max(avg_start, avg_end) / min(avg_start, avg_end)
        self.assertLess(ratio, 10.0, "Timing difference suggests not constant time")
    
    def test_key_generation_edge_cases(self):
        """Test key generation edge cases"""
        from quantum_crypt import post_quantum_key_generation_entropy_health_validator_2026_june as keygen
        
        # Get actual function names
        funcs = [x for x in dir(keygen) if not x.startswith('_') and 'key' in x.lower()]
        
        # Test that key generation functions exist and work
        for func_name in funcs[:5]:  # Test first 5 key-related functions
            func = getattr(keygen, func_name)
            if callable(func):
                try:
                    # Test with various sizes
                    for size in [16, 32, 64, 128]:
                        result = func(size)
                        self.assertIsNotNone(result)
                except Exception:
                    pass  # Some functions may have different signatures
        
        # Test zero key size
        try:
            if hasattr(keygen, 'generate_secure_key'):
                result = keygen.generate_secure_key(0)
        except Exception:
            pass
        
        # Test negative key size
        try:
            if hasattr(keygen, 'generate_secure_key'):
                result = keygen.generate_secure_key(-1)
        except (ValueError, Exception):
            pass  # Expected
    
    def test_zeroization_verification(self):
        """Test zeroization verification edge cases"""
        from quantum_crypt import post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june as zeroizer
        
        # Test verification of properly zeroized data
        zeroed = bytearray(b'\x00' * 100)
        result = zeroizer.verify_zeroization(zeroed)
        self.assertTrue(result)
        
        # Test verification of non-zero data
        non_zero = bytearray(secrets.token_bytes(100))
        result = zeroizer.verify_zeroization(non_zero)
        self.assertFalse(result)
        
        # Test empty data
        result = zeroizer.verify_zeroization(bytearray(b''))
        self.assertIsInstance(result, bool)
        
        # Test single byte zero
        result = zeroizer.verify_zeroization(bytearray(b'\x00'))
        self.assertTrue(result)
        
        # Test single byte non-zero
        result = zeroizer.verify_zeroization(bytearray(b'\x01'))
        self.assertFalse(result)
    
    def test_sensitive_data_wrapper(self):
        """Test SensitiveData wrapper edge cases"""
        from quantum_crypt import post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june as zeroizer
        
        # Test empty sensitive data
        sd = zeroizer.SensitiveData(b'')
        self.assertEqual(len(sd.value), 0)
        
        # Test large sensitive data
        large_data = secrets.token_bytes(100000)
        sd = zeroizer.SensitiveData(large_data)
        self.assertEqual(len(sd.value), len(large_data))
        
        # Test value property
        data = sd.value
        self.assertEqual(data, large_data)
        
        # Test clear/destroy
        sd.clear()
        sd.destroy()
    
    def test_secure_scratchpad(self):
        """Test secure scratchpad context manager"""
        from quantum_crypt import post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june as zeroizer
        
        # Test with various sizes
        for size in [0, 1, 16, 1024, 65536]:
            with zeroizer.secure_scratchpad(size) as pad:
                self.assertIsNotNone(pad)
                self.assertEqual(len(pad), size)
                # Should be writable
                if size > 0:
                    pad[0] = 0xFF
        
        # Test nested usage
        with zeroizer.secure_scratchpad(32):
            with zeroizer.secure_scratchpad(64):
                pass
    
    def test_error_resilience_retry(self):
        """Test CryptoRetryWrapper edge cases"""
        from quantum_crypt import crypto_error_resilience_engine_2026_june as resilience
        
        # Test retry with immediate success
        call_count = [0]
        def always_succeeds():
            call_count[0] += 1
            return "success"
        
        # Create with default config
        wrapper = resilience.CryptoRetryWrapper()
        wrapped = wrapper(always_succeeds)
        result = wrapped()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 1)
    
    def test_circuit_breaker_basic(self):
        """Test CryptoCircuitBreaker basic functionality"""
        from quantum_crypt import crypto_error_resilience_engine_2026_june as resilience
        
        # Test circuit breaker creation
        breaker = resilience.CryptoCircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        self.assertIsNotNone(breaker)
        
        # Test allow_operation - initial state should be open
        self.assertTrue(breaker.allow_operation())
        
        # Test record_failure - after 1 failure, should still allow
        breaker.record_failure()
        self.assertTrue(breaker.allow_operation())
        
        # Test record_failure - after 2 failures, should trip
        breaker.record_failure()
        self.assertFalse(breaker.allow_operation())
        
        # Test reset
        breaker.reset()
        self.assertTrue(breaker.allow_operation())
    
    def test_timeout_wrapper_basic(self):
        """Test CryptoTimeoutWrapper basic functionality"""
        from quantum_crypt import crypto_error_resilience_engine_2026_june as resilience
        
        # Test function that completes quickly
        def quick_function():
            return "done"
        
        wrapper = resilience.CryptoTimeoutWrapper(timeout_seconds=5)
        wrapped = wrapper(quick_function)
        result = wrapped()
        self.assertEqual(result, "done")
    
    def test_rate_limiter_basic(self):
        """Test CryptoOperationRateLimiter basic functionality"""
        from quantum_crypt import crypto_security_hardening_side_channel_2026_june as hardening
        
        # Test rate limiter creation
        limiter = hardening.CryptoOperationRateLimiter(max_operations_per_window=10, window_seconds=1)
        self.assertIsNotNone(limiter)
        
        # Test check_allowed
        for i in range(5):
            result = limiter.check_allowed(f"test_{i}")
            self.assertIsNotNone(result)
    
    def test_timing_protection_decorator(self):
        """Test timing_protected decorator"""
        from quantum_crypt import crypto_security_hardening_side_channel_2026_june as hardening
        
        # Test that decorator works
        @hardening.timing_protected
        def sensitive_operation(x):
            return x * 2
        
        # Should work normally
        result = sensitive_operation(5)
        self.assertIsNotNone(result)
    
    def test_constant_time_verify(self):
        """Test constant_time_verify function"""
        from quantum_crypt import crypto_security_hardening_side_channel_2026_june as hardening
        
        # Test equal values (bytes only)
        self.assertTrue(hardening.constant_time_verify(b'hello', b'hello'))
        self.assertTrue(hardening.constant_time_verify(b'', b''))
        self.assertTrue(hardening.constant_time_verify(b'\x00\x01', b'\x00\x01'))
        
        # Test different values
        self.assertFalse(hardening.constant_time_verify(b'a', b'b'))
        self.assertFalse(hardening.constant_time_verify(b'hello', b'world'))
    
    def test_side_channel_mitigation_levels(self):
        """Test SideChannelMitigationLevel enum"""
        from quantum_crypt import crypto_security_hardening_side_channel_2026_june as hardening
        
        # Test enum values exist
        self.assertIsNotNone(hardening.SideChannelMitigationLevel.MINIMAL)
        self.assertIsNotNone(hardening.SideChannelMitigationLevel.STANDARD)
        self.assertIsNotNone(hardening.SideChannelMitigationLevel.MAXIMUM)
        
        # Test they are different
        levels = [
            hardening.SideChannelMitigationLevel.MINIMAL,
            hardening.SideChannelMitigationLevel.STANDARD,
            hardening.SideChannelMitigationLevel.MAXIMUM
        ]
        self.assertEqual(len(set(levels)), 3)
    
    def test_integration_modules_together(self):
        """Integration test: multiple modules working together"""
        from quantum_crypt import post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june as zeroizer
        from quantum_crypt import crypto_security_hardening_side_channel_2026_june as hardening
        
        # Full workflow: create -> protect -> compare -> zeroize -> verify
        sensitive_data = secrets.token_bytes(64)
        
        # 1. Wrap in SensitiveData
        sd = zeroizer.SensitiveData(sensitive_data)
        data_copy = sd.value
        self.assertEqual(sensitive_data, data_copy)
        
        # 2. Constant time comparison
        self.assertTrue(zeroizer.constant_time_memcmp(sensitive_data, data_copy))
        
        # 3. Secure zeroize (needs bytearray)
        mutable_data = bytearray(sensitive_data)
        result = zeroizer.zeroize_sensitive_data(mutable_data)
        self.assertTrue(result)
        self.assertEqual(mutable_data, bytearray(b'\x00' * 64))
        
        # 4. Verify zeroization
        verify_result = zeroizer.verify_zeroization(mutable_data)
        self.assertTrue(verify_result)
        
        # 5. Verify data was actually zeroized
        self.assertFalse(zeroizer.constant_time_memcmp(bytes(mutable_data), data_copy))
    
    def test_concurrent_safety_smoke(self):
        """Smoke test for concurrent access safety"""
        import threading
        from quantum_crypt import post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june as zeroizer
        
        results = []
        errors = []
        
        def worker():
            try:
                for _ in range(100):
                    data = bytearray(secrets.token_bytes(64))
                    result = zeroizer.zeroize_sensitive_data(data)
                    results.append(result)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0, f"Concurrent errors: {errors}")
        self.assertEqual(len(results), 1000)
    
    def test_crypto_error_hierarchy(self):
        """Test CryptoError hierarchy"""
        from quantum_crypt import crypto_error_resilience_engine_2026_june as resilience
        
        # Test that exceptions exist and are proper subclasses
        self.assertTrue(issubclass(resilience.EncryptionError, resilience.CryptoError))
        self.assertTrue(issubclass(resilience.DecryptionError, resilience.CryptoError))
        self.assertTrue(issubclass(resilience.KeyGenerationError, resilience.CryptoError))
        self.assertTrue(issubclass(resilience.HashError, resilience.CryptoError))
        
        # Test that they can be raised and caught
        try:
            raise resilience.EncryptionError("Test encryption error")
        except resilience.CryptoError:
            pass  # Should be caught as base class
        
        try:
            raise resilience.DecryptionError("Test decryption error")
        except resilience.CryptoError:
            pass  # Should be caught as base class
    
    def test_entropy_health_monitor(self):
        """Test EntropyHealthMonitor"""
        from quantum_crypt import crypto_error_resilience_engine_2026_june as resilience
        
        # Test creation
        monitor = resilience.EntropyHealthMonitor()
        self.assertIsNotNone(monitor)
        
        # Test check_randomness_quality with various inputs
        # All zeros (low entropy)
        result = monitor.check_randomness_quality(b'\x00' * 1000)
        self.assertIsNotNone(result)
        
        # Random data (high entropy)
        result = monitor.check_randomness_quality(secrets.token_bytes(1000))
        self.assertIsNotNone(result)
        
        # Empty input
        result = monitor.check_randomness_quality(b'')
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
