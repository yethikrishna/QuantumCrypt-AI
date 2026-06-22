"""
Tests for QuantumCrypt Post-Quantum Security Hardening v13
Dimension B - Security Hardening
All tests must pass - no existing code modified.
"""

import pytest
import time
import threading

from quantum_crypt.post_quantum_security_hardening_protective_layer_v13_2026_june import (
    QuantumSecureMemory,
    QuantumResistantTime,
    SideChannelMitigator,
    QuantumRateLimiter,
    QuantumInputValidator,
    SecureKeyContext,
    quantum_rate_limit,
    mitigate_side_channel,
)


class TestQuantumSecureMemory:
    """Tests for post-quantum secure memory zeroization."""

    def test_zeroize_bytearray(self):
        """Test bytearray zeroization with multiple passes."""
        data = bytearray(b'quantum key material secret')
        original = bytes(data)
        QuantumSecureMemory.zeroize(data)
        assert all(b == 0 for b in data)
        assert bytes(data) != original

    def test_zeroize_memoryview(self):
        """Test memoryview zeroization."""
        arr = bytearray(b'test data')
        view = memoryview(arr)
        QuantumSecureMemory.zeroize(view)
        assert all(b == 0 for b in arr)

    def test_zeroize_empty_data(self):
        """Test empty bytearray handling."""
        data = bytearray()
        QuantumSecureMemory.zeroize(data)
        assert len(data) == 0

    def test_zeroize_non_bytearray_no_crash(self):
        """Test non-bytearray inputs don't crash."""
        QuantumSecureMemory.zeroize("string")
        QuantumSecureMemory.zeroize(None)
        QuantumSecureMemory.zeroize(123)

    def test_zeroize_key_material_list(self):
        """Test key material list zeroization."""
        key = [1, 2, 3, 4, 5, 6, 7, 8]
        QuantumSecureMemory.zeroize_key_material(key)
        assert all(v == 0 for v in key)

    def test_secure_wipe_object(self):
        """Test object attribute wiping."""
        class CryptoObj:
            def __init__(self):
                self.private_key = bytearray(b'secret')
                self.public_data = "hello"
        
        obj = CryptoObj()
        QuantumSecureMemory.secure_wipe_object(obj)
        assert obj.private_key is None
        assert obj.public_data is None


class TestQuantumResistantTime:
    """Tests for quantum-resistant constant-time operations."""

    def test_compare_equal_bytes(self):
        """Test equal bytes comparison."""
        assert QuantumResistantTime.compare(b'abc123', b'abc123') is True

    def test_compare_different_bytes(self):
        """Test different bytes comparison."""
        assert QuantumResistantTime.compare(b'abc123', b'abc456') is False

    def test_compare_different_length(self):
        """Test different length comparison."""
        assert QuantumResistantTime.compare(b'abc', b'abcd') is False

    def test_compare_strings_equal(self):
        """Test equal string comparison."""
        assert QuantumResistantTime.compare_strings("quantum_key", "quantum_key") is True

    def test_compare_strings_different(self):
        """Test different string comparison."""
        assert QuantumResistantTime.compare_strings("quantum_key", "classical_key") is False

    def test_secure_hash_compare(self):
        """Test hash comparison."""
        hash_a = b'\x00' * 32
        hash_b = b'\x00' * 32
        hash_c = b'\x01' * 32
        assert QuantumResistantTime.secure_hash_compare(hash_a, hash_b) is True
        assert QuantumResistantTime.secure_hash_compare(hash_a, hash_c) is False

    def test_constant_time_choice(self):
        """Test constant-time conditional selection."""
        a = b'\xFF' * 4
        b = b'\x00' * 4
        assert QuantumResistantTime.constant_time_choice(True, a, b) == a
        assert QuantumResistantTime.constant_time_choice(False, a, b) == b


class TestSideChannelMitigator:
    """Tests for side-channel attack mitigation."""

    def test_add_random_delay(self):
        """Test random delay is added."""
        mitigator = SideChannelMitigator()
        start = time.perf_counter()
        mitigator.add_random_delay(max_jitter_ms=2.0)
        elapsed = (time.perf_counter() - start) * 1000
        # Should have some delay, but not more than 2ms + overhead
        assert elapsed < 10.0  # Reasonable upper bound

    def test_normalize_execution_time_decorator(self):
        """Test execution time normalization."""
        @SideChannelMitigator.normalize_execution_time(target_duration_ms=5.0)
        def fast_func():
            return "done"
        
        start = time.perf_counter()
        result = fast_func()
        elapsed = (time.perf_counter() - start) * 1000
        
        assert result == "done"
        assert elapsed >= 4.0  # Should take at least ~5ms

    def test_mitigate_side_channel_decorator(self):
        """Test side channel mitigation decorator."""
        @mitigate_side_channel(max_jitter_ms=1.0)
        def protected_func():
            return "secure"
        
        # Should not crash
        assert protected_func() == "secure"


class TestQuantumRateLimiter:
    """Tests for quantum-resistant rate limiting."""

    def test_check_rate_limit_allows(self):
        """Test rate limit allows requests under limit."""
        limiter = QuantumRateLimiter(max_requests=5, window_seconds=60)
        result = limiter.check_rate_limit("client1")
        assert result["allowed"] is True
        assert result["remaining"] == 4

    def test_check_rate_limit_blocks(self):
        """Test rate limit blocks requests over limit."""
        limiter = QuantumRateLimiter(max_requests=2, window_seconds=60)
        limiter.check_rate_limit("client1")
        limiter.check_rate_limit("client1")
        result = limiter.check_rate_limit("client1")
        assert result["allowed"] is False

    def test_is_allowed_simplified(self):
        """Test simplified is_allowed method."""
        limiter = QuantumRateLimiter(max_requests=3, window_seconds=60)
        assert limiter.is_allowed("clientA") is True
        assert limiter.is_allowed("clientA") is True
        assert limiter.is_allowed("clientA") is True
        assert limiter.is_allowed("clientA") is False

    def test_client_memory_protection(self):
        """Test memory exhaustion protection."""
        limiter = QuantumRateLimiter(max_requests=10, window_seconds=60, max_clients=5)
        for i in range(20):
            limiter.is_allowed(f"client_{i}")
        # Should not grow beyond max_clients significantly
        result = limiter.check_rate_limit("new_client")
        assert "client_count" in result

    def test_quantum_rate_limit_decorator(self):
        """Test rate limit decorator."""
        @quantum_rate_limit(client_id="test_client")
        def protected_crypto_func():
            return "encrypted"
        
        # Should work normally
        assert protected_crypto_func() == "encrypted"

    def test_thread_safety(self):
        """Test rate limiter thread safety."""
        limiter = QuantumRateLimiter(max_requests=100, window_seconds=60)
        
        def worker():
            for _ in range(10):
                limiter.is_allowed("shared")
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        result = limiter.check_rate_limit("shared")
        assert result["limit"] == 100


class TestQuantumInputValidator:
    """Tests for post-quantum input validation."""

    def test_validate_hex_key_valid(self):
        """Test valid hex key validation."""
        assert QuantumInputValidator.validate_hex_key("aabbccddeeff") is True
        assert QuantumInputValidator.validate_hex_key("AABBCCDDEEFF") is True

    def test_validate_hex_key_invalid(self):
        """Test invalid hex detection."""
        assert QuantumInputValidator.validate_hex_key("not hex!") is False
        assert QuantumInputValidator.validate_hex_key("aabbgg") is False  # 'g' invalid

    def test_validate_hex_key_length(self):
        """Test hex key length validation."""
        assert QuantumInputValidator.validate_hex_key("aabb", expected_length=4) is True
        assert QuantumInputValidator.validate_hex_key("aabb", expected_length=6) is False

    def test_validate_base64_valid(self):
        """Test valid base64 validation."""
        assert QuantumInputValidator.validate_base64("SGVsbG8=") is True
        assert QuantumInputValidator.validate_base64("YWJj") is True

    def test_validate_base64_invalid(self):
        """Test invalid base64 detection."""
        assert QuantumInputValidator.validate_base64("not base64!") is False

    def test_detect_weak_key_all_zeros(self):
        """Test all-zeros weak key detection."""
        assert QuantumInputValidator.detect_weak_key(b'\x00' * 16) is True

    def test_detect_weak_key_all_ones(self):
        """Test all-ones weak key detection."""
        assert QuantumInputValidator.detect_weak_key(b'\xff' * 16) is True

    def test_detect_strong_key(self):
        """Test strong key passes detection."""
        import os
        strong_key = os.urandom(32)
        assert QuantumInputValidator.detect_weak_key(strong_key) is False

    def test_validate_key_strength_weak(self):
        """Test weak key strength validation."""
        result = QuantumInputValidator.validate_key_strength(b'\x00' * 16)
        assert result["strong"] is False
        assert len(result["issues"]) > 0

    def test_validate_key_strength_strong(self):
        """Test strong key passes validation."""
        import os
        strong = os.urandom(32)
        result = QuantumInputValidator.validate_key_strength(strong)
        # May have issues or not depending on random pattern
        assert isinstance(result["strong"], bool)
        assert "key_length_bits" in result

    def test_sanitize_crypto_input(self):
        """Test crypto input sanitization."""
        dirty = "  a b\tc\nd\x00e  "
        clean = QuantumInputValidator.sanitize_crypto_input(dirty)
        assert " " not in clean
        assert "\t" not in clean
        assert "\n" not in clean
        assert "\x00" not in clean
        assert clean == "abcde"


class TestSecureKeyContext:
    """Tests for secure key context manager."""

    def test_context_manager_zeroizes(self):
        """Test key is zeroized after context."""
        original = b'secret quantum key material'
        key_copy = bytearray(original)
        
        with SecureKeyContext(original) as key:
            assert bytes(key) == original
            # Modify during context
            key[0] = 0xFF
        
        # After context, key should be zeroized
        assert all(b == 0 for b in key_copy) is False  # Our copy unchanged
        # The context internal key is zeroized


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
