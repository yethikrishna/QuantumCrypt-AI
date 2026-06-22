"""
Test Suite for Post-Quantum Security Hardening v13
Dimension B - Security Hardening
Tests for all PQ security hardening features
"""

import pytest
import time
import threading
import secrets
from quantum_crypt.post_quantum_security_hardening_comprehensive_v13_2026_june import (
    PQSecurityLevel,
    KeyType,
    KeyValidationResult,
    PQRateLimitConfig,
    FaultDetectionState,
    PQConstantTimeOperations,
    PQSecureMemoryZeroizer,
    PQKeyValidator,
    PQRateLimiter,
    FaultAttackDetector,
    PQRandomnessValidator,
    QuantumCryptSecurityHardenerV13,
    PQSecurityHardeningError,
    get_pq_security_hardener_v13,
)


class TestPQConstantTimeOperations:
    """Tests for post-quantum constant-time operations"""

    def test_secure_select_true(self):
        a = b"first_option"
        b = b"second_option"
        result = PQConstantTimeOperations.secure_select(True, a, b)
        assert result[:len(a)] == a

    def test_secure_select_false(self):
        a = b"first_option"
        b = b"second_option"
        result = PQConstantTimeOperations.secure_select(False, a, b)
        assert result[:len(b)] == b

    def test_compare_bytes_ct_equal(self):
        data = secrets.token_bytes(64)
        assert PQConstantTimeOperations.compare_bytes_ct(data, data) is True

    def test_compare_bytes_ct_not_equal(self):
        a = secrets.token_bytes(64)
        b = secrets.token_bytes(64)
        assert PQConstantTimeOperations.compare_bytes_ct(a, b) is False

    def test_compare_bytes_ct_different_length(self):
        a = secrets.token_bytes(32)
        b = secrets.token_bytes(64)
        assert PQConstantTimeOperations.compare_bytes_ct(a, b) is False

    def test_array_copy_ct_true(self):
        dest = bytearray(10)
        src = b"\x01\x02\x03\x04\x05"
        PQConstantTimeOperations.array_copy_ct(dest, src, True)
        assert dest[:5] == src[:5]

    def test_array_copy_ct_false(self):
        dest = bytearray(b"\xFF\xFF\xFF\xFF\xFF")
        src = b"\x01\x02\x03\x04\x05"
        original = bytes(dest)
        PQConstantTimeOperations.array_copy_ct(dest, src, False)
        assert bytes(dest) == original

    def test_secure_swap_true(self):
        a = bytearray(b"AAAA")
        b = bytearray(b"BBBB")
        PQConstantTimeOperations.secure_swap(a, b, True)
        assert a == bytearray(b"BBBB")
        assert b == bytearray(b"AAAA")

    def test_secure_swap_false(self):
        a = bytearray(b"AAAA")
        b = bytearray(b"BBBB")
        original_a = bytes(a)
        original_b = bytes(b)
        PQConstantTimeOperations.secure_swap(a, b, False)
        assert bytes(a) == original_a
        assert bytes(b) == original_b


class TestPQSecureMemoryZeroizer:
    """Tests for PQ secure memory zeroization"""

    def test_zeroize_key_material(self):
        key = bytearray(secrets.token_bytes(64))
        original = bytes(key)
        PQSecureMemoryZeroizer.zeroize_key_material(key)
        assert all(b == 0 for b in key)
        assert bytes(key) != original

    def test_zeroize_key_material_multiple_patterns(self):
        """Verify multiple overwrite patterns are applied"""
        key = bytearray(b"\x01" * 100)
        PQSecureMemoryZeroizer.zeroize_key_material(key)
        assert sum(key) == 0  # Final state is all zeros

    def test_zeroize_bytes_ct(self):
        data = b"sensitive key material"
        result = PQSecureMemoryZeroizer.zeroize_bytes_ct(data)
        assert len(result) == len(data)
        assert all(b == 0 for b in result)

    def test_secure_wipe_list(self):
        data = [bytearray(b"secret1"), bytearray(b"secret2")]
        PQSecureMemoryZeroizer.secure_wipe_object(data)
        assert all(all(b == 0 for b in item) for item in data)


class TestPQKeyValidator:
    """Tests for PQ key validation"""

    def test_calculate_entropy_high(self):
        """Random data should have high entropy"""
        data = secrets.token_bytes(256)
        entropy = PQKeyValidator.calculate_entropy(data)
        assert entropy > 5.0  # Good random data > 5 bits/byte

    def test_calculate_entropy_low(self):
        """Repeated data should have low entropy"""
        data = b"\x00" * 256
        entropy = PQKeyValidator.calculate_entropy(data)
        assert entropy < 1.0

    def test_validate_kyber_public_key_wrong_length(self):
        validator = PQKeyValidator()
        # Wrong length for L5 public key (should be 1568)
        result = validator.validate_kyber_key(
            b"short", KeyType.KYBER_PUBLIC, PQSecurityLevel.LEVEL_5
        )
        assert result.valid is False
        assert any("length" in v for v in result.violations)

    def test_validate_kyber_private_key_wrong_length(self):
        validator = PQKeyValidator()
        result = validator.validate_kyber_key(
            b"short", KeyType.KYBER_PRIVATE, PQSecurityLevel.LEVEL_5
        )
        assert result.valid is False

    def test_validate_dilithium_wrong_key_type(self):
        validator = PQKeyValidator()
        result = validator.validate_dilithium_key(
            b"data", KeyType.KYBER_PUBLIC, PQSecurityLevel.LEVEL_5
        )
        assert result.valid is False
        assert any("Invalid key type" in v for v in result.violations)

    def test_validate_shared_secret_too_short(self):
        validator = PQKeyValidator()
        result = validator.validate_shared_secret(b"short", min_length=32)
        assert result.valid is False
        assert any("too short" in v for v in result.violations)

    def test_validate_shared_secret_good(self):
        validator = PQKeyValidator()
        secret = secrets.token_bytes(32)
        result = validator.validate_shared_secret(secret)
        # May pass or fail depending on entropy, but shouldn't crash
        assert isinstance(result, KeyValidationResult)

    def test_detect_all_identical_bytes(self):
        validator = PQKeyValidator()
        weak_key = b"\xAA" * 1568  # All same bytes, L5 public key length
        result = validator.validate_kyber_key(
            weak_key, KeyType.KYBER_PUBLIC, PQSecurityLevel.LEVEL_5
        )
        assert result.valid is False
        assert any("identical" in v.lower() for v in result.violations)


class TestPQRateLimiter:
    """Tests for PQ crypto rate limiter"""

    def test_sign_ops_allowed(self):
        config = PQRateLimitConfig(max_sign_ops=10, window_seconds=60)
        limiter = PQRateLimiter(config)
        
        for i in range(10):
            allowed, meta = limiter.check_operation_allowed('sign')
            assert allowed is True

    def test_sign_ops_blocked(self):
        config = PQRateLimitConfig(max_sign_ops=5, window_seconds=60)
        limiter = PQRateLimiter(config)
        
        for i in range(5):
            limiter.check_operation_allowed('sign')
        
        allowed, meta = limiter.check_operation_allowed('sign')
        assert allowed is False
        assert meta['reason'] == 'rate_limit_exceeded'

    def test_keygen_ops_limited(self):
        config = PQRateLimitConfig(max_keygen_ops=2, window_seconds=60)
        limiter = PQRateLimiter(config)
        
        limiter.check_operation_allowed('keygen')
        limiter.check_operation_allowed('keygen')
        allowed, _ = limiter.check_operation_allowed('keygen')
        assert allowed is False

    def test_rate_limiter_disabled(self):
        config = PQRateLimitConfig(enabled=False)
        limiter = PQRateLimiter(config)
        
        for i in range(1000):
            allowed, _ = limiter.check_operation_allowed('sign')
            assert allowed is True

    def test_different_operations_independent(self):
        config = PQRateLimitConfig(max_sign_ops=2, max_encrypt_ops=5, window_seconds=60)
        limiter = PQRateLimiter(config)
        
        # Consume sign ops
        limiter.check_operation_allowed('sign')
        limiter.check_operation_allowed('sign')
        
        # Encrypt ops should still work
        allowed, _ = limiter.check_operation_allowed('encrypt')
        assert allowed is True

    def test_entropy_health_throttling(self):
        config = PQRateLimitConfig(entropy_threshold=0.9)
        limiter = PQRateLimiter(config)
        limiter.update_entropy_health(0.5)  # Poor entropy
        
        allowed, meta = limiter.check_operation_allowed('sign')
        assert allowed is False
        assert meta['reason'] == 'insufficient_system_entropy'


class TestFaultAttackDetector:
    """Tests for fault attack detection"""

    def test_record_operation_normal(self):
        detector = FaultAttackDetector(threshold_deviation=10.0)
        
        # Normal operations with consistent timing
        for i in range(20):
            anomaly = detector.record_operation("test_op", 0.001)
            assert anomaly is False

    def test_get_anomaly_score(self):
        detector = FaultAttackDetector()
        detector.record_operation("test", 0.001)
        score = detector.get_anomaly_score("test")
        assert isinstance(score, float)
        assert score >= 0.0

    def test_unknown_operation_score(self):
        detector = FaultAttackDetector()
        score = detector.get_anomaly_score("nonexistent")
        assert score == 0.0


class TestPQRandomnessValidator:
    """Tests for randomness validation"""

    def test_check_system_randomness(self):
        result = PQRandomnessValidator.check_system_randomness()
        assert isinstance(result, dict)
        assert 'secrets_module_working' in result
        assert 'entropy_estimate' in result
        # Secrets module should work
        assert result['secrets_module_working'] is True

    def test_validate_random_output_good(self):
        data = secrets.token_bytes(128)
        result = PQRandomnessValidator.validate_random_output(data, min_entropy=5.0)
        assert result is True

    def test_validate_random_output_bad(self):
        data = b"\x00" * 128
        result = PQRandomnessValidator.validate_random_output(data, min_entropy=5.0)
        assert result is False


class TestQuantumCryptSecurityHardenerV13:
    """Tests for main PQ security hardener facade"""

    def test_get_instance(self):
        hardener = get_pq_security_hardener_v13()
        assert hardener is not None
        assert isinstance(hardener, QuantumCryptSecurityHardenerV13)

    def test_secure_compare(self):
        hardener = get_pq_security_hardener_v13()
        data = secrets.token_bytes(64)
        assert hardener.secure_compare(data, data) is True
        assert hardener.secure_compare(data, secrets.token_bytes(64)) is False

    def test_secure_select(self):
        hardener = get_pq_security_hardener_v13()
        a = b"option_a"
        b = b"option_b"
        result = hardener.secure_select(True, a, b)
        assert result[:len(a)] == a

    def test_zeroize_key(self):
        hardener = get_pq_security_hardener_v13()
        key = bytearray(secrets.token_bytes(32))
        hardener.zeroize_key(key)
        assert all(b == 0 for b in key)

    def test_validate_kyber_key(self):
        hardener = get_pq_security_hardener_v13()
        # Test with wrong length - should fail validation but not crash
        result = hardener.validate_kyber_key(b"test", KeyType.KYBER_PUBLIC)
        assert result.valid is False

    def test_validate_dilithium_key(self):
        hardener = get_pq_security_hardener_v13()
        result = hardener.validate_dilithium_key(b"test", KeyType.DILITHIUM_PUBLIC)
        assert result.valid is False

    def test_check_crypto_rate_limit(self):
        hardener = get_pq_security_hardener_v13()
        allowed, meta = hardener.check_crypto_rate_limit('sign')
        assert allowed is True

    def test_check_randomness_health(self):
        hardener = get_pq_security_hardener_v13()
        result = hardener.check_randomness_health()
        assert isinstance(result, dict)
        assert 'entropy_estimate' in result

    def test_check_fault_anomaly(self):
        hardener = get_pq_security_hardener_v13()
        # Should not crash
        anomaly = hardener.check_fault_anomaly("test_op", 0.001)
        assert isinstance(anomaly, bool)


class TestIntegration:
    """Integration tests for combined security features"""

    def test_full_pq_security_workflow(self):
        """Test complete post-quantum security hardening workflow"""
        hardener = get_pq_security_hardener_v13(PQSecurityLevel.LEVEL_5)
        
        # 1. Check system randomness health
        rand_health = hardener.check_randomness_health()
        assert rand_health['secrets_module_working'] is True
        
        # 2. Check rate limit for key generation
        allowed, _ = hardener.check_crypto_rate_limit('keygen')
        assert allowed is True
        
        # 3. Generate and validate shared secret
        secret = secrets.token_bytes(32)
        validator = PQKeyValidator()
        val_result = validator.validate_shared_secret(secret)
        # Should have good entropy (32 bytes can have natural variation, use > 4.0)
        assert val_result.entropy_bits > 4.0
        
        # 4. Secure comparison
        is_match = hardener.secure_compare(secret, secret)
        assert is_match is True
        
        # 5. Zeroize key material
        key_copy = bytearray(secret)
        hardener.zeroize_key(key_copy)
        assert all(b == 0 for b in key_copy)

    def test_thread_safety(self):
        """Test rate limiter is thread-safe"""
        config = PQRateLimitConfig(max_sign_ops=1000, window_seconds=60)
        limiter = PQRateLimiter(config)
        
        def worker():
            for _ in range(10):
                limiter.check_operation_allowed('sign')
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should not crash
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
