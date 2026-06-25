"""
Test Suite for QuantumCrypt Comprehensive Security Hardening Framework v30
Dimension B - Security Hardening
June 25, 2026

Tests cover:
1. Protected Key Material Wrappers
2. Crypto-Specific Side-Channel Protection
3. Key Operation Rate Limiting
4. Crypto Security Context Isolation
5. All existing functionality (regression tests)
"""
import pytest
import time
import threading
from crypto_security_hardening_framework_v30_2026_june import (
    ProtectedKey,
    CryptoSecureMemory,
    CryptoSideChannelProtection,
    CryptoConstantTime,
    CryptoInputValidator,
    CryptoOperationRateLimiter,
    CryptoSecurityHardeningWrapper,
    CryptoSecurityContext,
    SecurityLevel,
    KeySensitivity,
    CryptoRateLimitConfig,
    ValidationRule,
    KeyMetadata,
    CryptoSecurityError,
    CryptoValidationError,
    CryptoRateLimitError,
    crypto_secure_memory,
    crypto_constant_time,
    crypto_side_channel,
    default_crypto_validator,
    default_crypto_rate_limiter,
)

class TestProtectedKey:
    """Tests for ProtectedKey cryptographic key wrapper"""
    
    def test_protected_key_prevents_leakage(self):
        """Test that ProtectedKey prevents accidental str/repr leakage"""
        key_material = bytearray(b"private_key_material_12345")
        protected = ProtectedKey(
            key_material,
            KeySensitivity.PRIVATE_KEY_FULL,
            "CRYSTALS-Kyber",
            1024
        )
        
        # str/repr should not reveal the key
        assert "PROTECTED" in str(protected)
        assert "CRYSTALS-Kyber" in repr(protected)
        assert "1024" in repr(protected)
        assert b"private_key" not in str(protected).encode()
    
    def test_protected_key_explicit_access(self):
        """Test explicit key access methods"""
        key = bytearray(b"test_key")
        protected = ProtectedKey(key, KeySensitivity.EPHEMERAL_KEY, "Test", 256)
        
        assert protected.use_for_signing() == key
        assert protected.use_for_decryption() == key
    
    def test_protected_key_usage_tracking(self):
        """Test that key usage is tracked"""
        protected = ProtectedKey(
            b"key",
            KeySensitivity.PRIVATE_KEY_FULL,
            "Test",
            256
        )
        
        protected.use_for_signing()
        protected.use_for_signing()
        protected.use_for_decryption()
        
        meta = protected.get_metadata()
        assert meta.sign_count == 2
        assert meta.decrypt_count == 1
    
    def test_protected_key_sensitivity_levels(self):
        """Test all key sensitivity levels"""
        levels = [
            KeySensitivity.PUBLIC_KEY,
            KeySensitivity.PRIVATE_KEY_PART,
            KeySensitivity.PRIVATE_KEY_FULL,
            KeySensitivity.EPHEMERAL_KEY,
            KeySensitivity.MASTER_KEY,
            KeySensitivity.PRE_SHARED_SECRET,
        ]
        for level in levels:
            pk = ProtectedKey(b"key", level, "Test", 256)
            assert pk._metadata.sensitivity == level

class TestCryptoSecureMemory:
    """Tests for crypto-specific secure memory"""
    
    def test_zeroize_bytes_multiple_passes(self):
        """Test bytearray zeroization with multiple passes"""
        data = bytearray(b"secret_crypto_key_material")
        CryptoSecureMemory.zeroize_bytes(data)
        assert all(b == 0 for b in data)
    
    def test_crypto_secure_scope(self):
        """Test crypto secure scope context manager"""
        with CryptoSecureMemory.crypto_secure_scope():
            temp = bytearray(b"sensitive_key_op")
            temp[0] = 0x01
        # Should exit cleanly
        assert True
    
    def test_auto_zeroize_key_bytearray(self):
        """Test auto key zeroization for bytearray"""
        data = bytearray(b"private_key")
        CryptoSecureMemory.auto_zeroize_key(data)
        assert all(b == 0 for b in data)

class TestCryptoSideChannelProtection:
    """Tests for crypto-specific side channel protection"""
    
    def test_constant_time_delay(self):
        """Test constant time delay actually delays"""
        start = time.perf_counter_ns()
        CryptoSideChannelProtection.constant_time_delay(50000)  # 50us
        elapsed = time.perf_counter_ns() - start
        assert elapsed >= 50000
    
    def test_cache_noise_generator_large(self):
        """Test large cache noise generator for crypto"""
        CryptoSideChannelProtection.cache_noise_generator(100)
    
    def test_key_blinding_round_trip(self):
        """Test key blinding and unblinding"""
        original = 123456789
        blinded, blind = CryptoSideChannelProtection.key_blinding(original)
        assert blinded != original
        unblinded = CryptoSideChannelProtection.key_unblind(blinded, blind)
        assert unblinded == original
    
    def test_dummy_crypto_ops(self):
        """Test dummy crypto operations for noise"""
        CryptoSideChannelProtection.dummy_crypto_ops(5)

class TestCryptoConstantTime:
    """Tests for constant time crypto operations"""
    
    def test_constant_time_compare_bytes(self):
        """Test constant time bytes comparison"""
        assert CryptoConstantTime.compare(b"abc", b"abc") == True
        assert CryptoConstantTime.compare(b"abc", b"abd") == False
    
    def test_constant_time_compare_strings(self):
        """Test constant time string comparison"""
        assert CryptoConstantTime.compare("test", "test") == True
        assert CryptoConstantTime.compare("test", "tesx") == False
    
    def test_constant_time_select(self):
        """Test constant time conditional selection"""
        assert CryptoConstantTime.select(True, 100, 200) == 100
        assert CryptoConstantTime.select(False, 100, 200) == 200

class TestCryptoInputValidator:
    """Tests for crypto input validation"""
    
    def test_wrap_protected_key_valid(self):
        """Test wrapping valid key material"""
        validator = CryptoInputValidator(SecurityLevel.STRICT)
        key = bytearray(b"valid_key_material")
        result = validator.wrap_protected_key(
            key,
            KeySensitivity.PRIVATE_KEY_FULL,
            "Kyber",
            1024
        )
        assert isinstance(result, ProtectedKey)
    
    def test_wrap_protected_key_none_raises(self):
        """Test wrapping None raises validation error"""
        validator = CryptoInputValidator()
        with pytest.raises(CryptoValidationError):
            validator.wrap_protected_key(
                None,
                KeySensitivity.PRIVATE_KEY_FULL,
                "Kyber",
                1024
            )
    
    def test_paranoid_level_null_byte_detection(self):
        """Test paranoid level detects suspicious null patterns"""
        validator = CryptoInputValidator(SecurityLevel.PARANOID)
        suspicious = b'\x00' * 200
        result = validator.validate(suspicious)
        assert result["valid"] == False

class TestCryptoOperationRateLimiter:
    """Tests for crypto operation rate limiting"""
    
    def test_sign_operation_rate_limit(self):
        """Test signing operation rate limiting"""
        limiter = CryptoOperationRateLimiter()
        key_id = "test_key_sign"
        
        for i in range(1000):
            result = limiter.check_sign_operation(key_id)
            assert result["allowed"] == True
        
        result = limiter.check_sign_operation(key_id)
        assert result["allowed"] == False
        assert result["blocked"] == True
    
    def test_decrypt_operation_rate_limit(self):
        """Test decryption operation rate limiting"""
        limiter = CryptoOperationRateLimiter()
        key_id = "test_key_decrypt"
        
        for i in range(500):
            result = limiter.check_decrypt_operation(key_id)
            assert result["allowed"] == True
        
        result = limiter.check_decrypt_operation(key_id)
        assert result["allowed"] == False
    
    def test_keygen_operation_rate_limit(self):
        """Test key generation operation rate limiting"""
        limiter = CryptoOperationRateLimiter()
        key_id = "test_keygen"
        
        for i in range(10):
            result = limiter.check_keygen_operation(key_id)
            assert result["allowed"] == True
        
        result = limiter.check_keygen_operation(key_id)
        assert result["allowed"] == False

class TestCryptoSecurityContext:
    """Tests for crypto security context isolation"""
    
    def test_context_creation(self):
        """Test basic context creation"""
        ctx = CryptoSecurityContext("test_crypto_ctx", SecurityLevel.STRICT)
        assert ctx.name == "test_crypto_ctx"
        assert ctx.security_level == SecurityLevel.STRICT
    
    def test_context_store_and_retrieve_key(self):
        """Test storing and retrieving keys in context"""
        ctx = CryptoSecurityContext("test")
        key_material = bytearray(b"my_private_key")
        
        ctx.store_key(
            "kyber_key_1",
            key_material,
            KeySensitivity.PRIVATE_KEY_FULL,
            "CRYSTALS-Kyber",
            1024
        )
        
        retrieved = ctx.get_key_for_signing("kyber_key_1")
        assert retrieved == key_material
    
    def test_context_audit_logging(self):
        """Test operation audit logging"""
        ctx = CryptoSecurityContext("audit_test")
        ctx.store_key("k1", b"key", KeySensitivity.EPHEMERAL_KEY, "Test", 256)
        ctx.get_key_for_signing("k1")
        
        audit = ctx.get_audit_log()
        assert len(audit) >= 2
        assert any(e["type"] == "key_stored" for e in audit)
        assert any(e["type"] == "sign_operation" for e in audit)
    
    def test_context_isolate_manager(self):
        """Test isolate context manager"""
        ctx = CryptoSecurityContext("isolated_ctx")
        with ctx.isolate():
            ctx.store_key("temp", b"key", KeySensitivity.EPHEMERAL_KEY, "Test", 256)
            assert ctx.get_key_for_signing("temp") == b"key"

class TestCryptoSecurityHardeningWrapper:
    """Tests for crypto security hardening wrapper"""
    
    def test_wrap_sign_function(self):
        """Test wrapping a signing function"""
        wrapper = CryptoSecurityHardeningWrapper()
        protected_key = ProtectedKey(
            b"key",
            KeySensitivity.PRIVATE_KEY_FULL,
            "Test",
            256
        )
        
        def mock_sign(message, key):
            return f"signed:{message.decode()}"
        
        wrapped = wrapper.wrap_sign_function(mock_sign, "key1", protected_key)
        result = wrapped(b"test_message")
        assert "signed:test_message" in result
    
    def test_wrap_decrypt_function(self):
        """Test wrapping a decryption function"""
        wrapper = CryptoSecurityHardeningWrapper()
        protected_key = ProtectedKey(
            b"key",
            KeySensitivity.PRIVATE_KEY_FULL,
            "Test",
            256
        )
        
        def mock_decrypt(ciphertext, key):
            return f"decrypted:{ciphertext.decode()}"
        
        wrapped = wrapper.wrap_decrypt_function(mock_decrypt, "key1", protected_key)
        result = wrapped(b"encrypted_data")
        assert "decrypted:encrypted_data" in result
    
    def test_create_security_context(self):
        """Test creating security context from wrapper"""
        wrapper = CryptoSecurityHardeningWrapper(SecurityLevel.STRICT)
        ctx = wrapper.create_context("my_crypto_context")
        assert isinstance(ctx, CryptoSecurityContext)
        assert ctx.name == "my_crypto_context"

class TestThreadSafety:
    """Thread safety tests for crypto components"""
    
    def test_rate_limiter_thread_safe(self):
        """Test rate limiter under concurrent access"""
        limiter = CryptoOperationRateLimiter()
        key_id = "concurrent_crypto_test"
        errors = []
        
        def worker():
            try:
                for _ in range(50):
                    limiter.check_sign_operation(key_id)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0

class TestRegression:
    """Regression tests for all existing functionality"""
    
    def test_secure_hash(self):
        """Regression: secure hashing"""
        result = CryptoConstantTime.secure_hash(b"test")
        assert len(result) == 64  # SHA512 output
    
    def test_validation_rule_add(self):
        """Regression: adding custom validation rules"""
        validator = CryptoInputValidator()
        validator.add_rule(ValidationRule(
            name="positive_length",
            validator=lambda x: len(x) > 0,
            error_message="Must have positive length"
        ))
        result = validator.validate(b"non_empty")
        assert result["valid"] == True
    
    def test_custom_rate_limit_config(self):
        """Regression: custom rate limit config"""
        config = CryptoRateLimitConfig(
            max_sign_ops=500,
            max_decrypt_ops=200,
            max_key_gen_ops=5
        )
        limiter = CryptoOperationRateLimiter(config)
        assert limiter.config.max_sign_ops == 500

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
