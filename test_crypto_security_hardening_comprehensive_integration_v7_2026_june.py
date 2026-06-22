"""
Tests for Comprehensive Crypto Security Hardening Integration V7
Dimension B: Security Hardening

All tests are ADD-ONLY - no existing tests modified.
"""

import pytest
import time
import threading
import secrets
from quantum_crypt.crypto_security_hardening_comprehensive_integration_v7_2026_june import (
    CryptoSecurityLevel,
    CryptoOperationType,
    CryptoAlgorithmClass,
    CryptoSecurityEventType,
    CryptoSecurityEvent,
    CryptoSecurityAuditLog,
    CryptoValidationError,
    CryptoInputValidator,
    SecureKey,
    SideChannelResistant,
    RandomnessHealthError,
    RandomnessHealthMonitor,
    CryptoSecurityPolicy,
    CryptoPolicyEnforcer,
    CryptoSecurityHardeningFacade,
    get_crypto_security_audit_log,
    crypto_validate_key,
    crypto_validate_nonce,
    crypto_constant_time_compare,
    crypto_generate_secure_random,
    crypto_create_secure_key,
    get_crypto_security_metrics,
)


# =============================================================================
# Test Crypto Security Enums
# =============================================================================

class TestCryptoSecurityEnums:
    def test_crypto_security_levels(self):
        """Test crypto security level ordering."""
        assert CryptoSecurityLevel.DISABLED.value < CryptoSecurityLevel.BASIC.value
        assert CryptoSecurityLevel.BASIC.value < CryptoSecurityLevel.STANDARD.value
        assert CryptoSecurityLevel.STANDARD.value < CryptoSecurityLevel.ENHANCED.value
        assert CryptoSecurityLevel.ENHANCED.value < CryptoSecurityLevel.FIPS140_3.value
    
    def test_crypto_operation_types(self):
        """Test all crypto operation types exist."""
        ops = [op.name for op in CryptoOperationType]
        assert "KEY_GENERATION" in ops
        assert "ENCRYPTION" in ops
        assert "DECRYPTION" in ops
        assert "SIGNATURE" in ops
        assert "RANDOM_GENERATION" in ops
    
    def test_algorithm_classes(self):
        """Test algorithm classification enums."""
        classes = [c.name for c in CryptoAlgorithmClass]
        assert "POST_QUANTUM" in classes
        assert "CLASSIC_MODERN" in classes
        assert "LEGACY" in classes


# =============================================================================
# Test Crypto Security Audit Log
# =============================================================================

class TestCryptoSecurityAuditLog:
    def test_audit_log_creation(self):
        """Test audit log initialization."""
        log = CryptoSecurityAuditLog()
        assert log.get_event_count() == 0
    
    def test_audit_log_event_logging(self):
        """Test crypto event logging."""
        log = CryptoSecurityAuditLog()
        event = CryptoSecurityEvent(
            event_type=CryptoSecurityEventType.KEY_GENERATION,
            operation=CryptoOperationType.KEY_GENERATION,
            algorithm="Kyber-768",
        )
        log.log(event)
        assert log.get_event_count() == 1
    
    def test_audit_log_algorithm_tracking(self):
        """Test algorithm usage tracking."""
        log = CryptoSecurityAuditLog()
        for alg in ["Kyber-768", "AES-256", "Kyber-768", "Dilithium-3"]:
            log.log(CryptoSecurityEvent(
                event_type=CryptoSecurityEventType.ALGORITHM_USAGE,
                operation=CryptoOperationType.ENCRYPTION,
                algorithm=alg,
            ))
        top = log.get_top_algorithms(limit=2)
        assert top[0][0] == "Kyber-768"
        assert top[0][1] == 2
    
    def test_audit_log_compliance_metrics(self):
        """Test compliance metrics calculation."""
        log = CryptoSecurityAuditLog()
        log.log(CryptoSecurityEvent(
            event_type=CryptoSecurityEventType.KEY_GENERATION,
            operation=CryptoOperationType.KEY_GENERATION,
            success=True,
        ))
        log.log(CryptoSecurityEvent(
            event_type=CryptoSecurityEventType.CERTIFICATE_VALIDATION_FAIL,
            operation=CryptoOperationType.CERTIFICATE_VALIDATE,
            success=False,
        ))
        metrics = log.get_compliance_metrics()
        assert metrics["total_operations"] == 2
        assert metrics["failure_rate"] == 0.5
    
    def test_global_audit_log_singleton(self):
        """Test global audit log is singleton."""
        log1 = get_crypto_security_audit_log()
        log2 = get_crypto_security_audit_log()
        assert log1 is log2


# =============================================================================
# Test Crypto Input Validator
# =============================================================================

class TestCryptoInputValidator:
    def test_validator_creation(self):
        """Test validator initialization."""
        validator = CryptoInputValidator()
        assert validator.security_level == CryptoSecurityLevel.STANDARD
    
    def test_validate_key_valid_aes(self):
        """Test valid AES key validation."""
        validator = CryptoInputValidator()
        key = secrets.token_bytes(32)  # AES-256
        result = validator.validate_key_length(key, "AES-256", "aes_key")
        assert result == key
    
    def test_validate_key_valid_kyber(self):
        """Test valid Kyber key validation."""
        validator = CryptoInputValidator()
        key = secrets.token_bytes(2400)  # Kyber-768
        result = validator.validate_key_length(key, "Kyber-768")
        assert result == key
    
    def test_validate_key_wrong_type(self):
        """Test key type validation error."""
        validator = CryptoInputValidator()
        with pytest.raises(CryptoValidationError):
            validator.validate_key_length("not_bytes", "AES-256")
    
    def test_validate_key_wrong_length(self):
        """Test key length validation error."""
        validator = CryptoInputValidator()
        wrong_key = secrets.token_bytes(16)  # Wrong for AES-256
        with pytest.raises(CryptoValidationError):
            validator.validate_key_length(wrong_key, "AES-256")
    
    def test_validate_key_all_zeros_enhanced(self):
        """Test all-zeros key detection at ENHANCED level."""
        validator = CryptoInputValidator(security_level=CryptoSecurityLevel.ENHANCED)
        zero_key = b'\x00' * 32
        with pytest.raises(CryptoValidationError):
            validator.validate_key_length(zero_key, "AES-256")
    
    def test_validate_nonce_valid(self):
        """Test valid nonce validation."""
        validator = CryptoInputValidator()
        nonce = secrets.token_bytes(12)  # AES-GCM nonce
        result = validator.validate_nonce(nonce, "AES-GCM")
        assert result == nonce
    
    def test_validate_plaintext_valid(self):
        """Test valid plaintext validation."""
        validator = CryptoInputValidator()
        pt = b"Hello, World!"
        result = validator.validate_plaintext(pt)
        assert result == pt
    
    def test_validate_plaintext_too_large(self):
        """Test plaintext size limit."""
        validator = CryptoInputValidator()
        large_pt = b"x" * (100 * 1024 * 1024)  # 100MB
        with pytest.raises(CryptoValidationError):
            validator.validate_plaintext(large_pt)
    
    def test_disabled_level_bypasses_validation(self):
        """Test DISABLED level bypasses checks."""
        validator = CryptoInputValidator(security_level=CryptoSecurityLevel.DISABLED)
        result = validator.validate_key_length("not_bytes", "AES-256")
        assert result == "not_bytes"


# =============================================================================
# Test SecureKey
# =============================================================================

class TestSecureKey:
    def test_secure_key_creation(self):
        """Test secure key wrapper creation."""
        key_data = secrets.token_bytes(32)
        with SecureKey(key_data, "AES-256") as sk:
            assert sk.algorithm == "AES-256"
            assert sk.key_id is not None
            assert sk.is_zeroized is False
    
    def test_secure_key_get_bytes(self):
        """Test key data retrieval."""
        key_data = secrets.token_bytes(32)
        with SecureKey(key_data, "AES-256") as sk:
            retrieved = sk.get_bytes()
            assert retrieved == key_data
    
    def test_secure_key_zeroize(self):
        """Test key zeroization."""
        key_data = secrets.token_bytes(32)
        sk = SecureKey(key_data, "AES-256")
        sk.zeroize()
        assert sk.is_zeroized is True
    
    def test_secure_key_access_after_zeroize(self):
        """Test accessing key after zeroization fails."""
        key_data = secrets.token_bytes(32)
        sk = SecureKey(key_data, "AES-256")
        sk.zeroize()
        with pytest.raises(CryptoValidationError):
            sk.get_bytes()
    
    def test_secure_key_context_manager(self):
        """Test context manager auto-zeroization."""
        key_data = secrets.token_bytes(32)
        sk = None
        with SecureKey(key_data, "AES-256") as key:
            sk = key
            assert not sk.is_zeroized
        assert sk.is_zeroized


# =============================================================================
# Test SideChannelResistant
# =============================================================================

class TestSideChannelResistant:
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison for equal values."""
        a = b"test data 12345"
        b = b"test data 12345"
        assert SideChannelResistant.constant_time_compare(a, b) is True
    
    def test_constant_time_compare_not_equal(self):
        """Test constant-time comparison for different values."""
        a = b"test data 12345"
        b = b"test data 54321"
        assert SideChannelResistant.constant_time_compare(a, b) is False
    
    def test_constant_time_select(self):
        """Test constant-time selection."""
        a = b"\x01\x02\x03"
        b = b"\x04\x05\x06"
        result_true = SideChannelResistant.constant_time_select(True, a, b)
        result_false = SideChannelResistant.constant_time_select(False, a, b)
        assert result_true == a
        assert result_false == b
    
    def test_constant_time_select_different_lengths(self):
        """Test constant-time select raises for different lengths."""
        with pytest.raises(ValueError):
            SideChannelResistant.constant_time_select(True, b"short", b"much longer")


# =============================================================================
# Test RandomnessHealthMonitor
# =============================================================================

class TestRandomnessHealthMonitor:
    def test_monitor_creation(self):
        """Test monitor initialization."""
        monitor = RandomnessHealthMonitor()
        assert monitor is not None
    
    def test_good_randomness_passes(self):
        """Test good randomness passes health checks."""
        monitor = RandomnessHealthMonitor()
        good_data = secrets.token_bytes(256)
        assert monitor.check_randomness(good_data) is True
    
    def test_generate_checked_random(self):
        """Test random generation with health check."""
        monitor = RandomnessHealthMonitor()
        data = monitor.generate_checked_random(32)
        assert len(data) == 32
        assert isinstance(data, bytes)
    
    def test_small_random_skips_checks(self):
        """Test very small data skips health checks."""
        monitor = RandomnessHealthMonitor()
        assert monitor.check_randomness(b"tiny") is True


# =============================================================================
# Test Crypto Security Policy & Enforcer
# =============================================================================

class TestCryptoSecurityPolicy:
    def test_policy_creation(self):
        """Test security policy creation."""
        policy = CryptoSecurityPolicy(
            name="standard",
            allowed_algorithms={"AES-256", "Kyber-768"},
            blocked_algorithms={"SHA-1", "3DES"},
        )
        assert policy.name == "standard"
        assert "SHA-1" in policy.blocked_algorithms


class TestCryptoPolicyEnforcer:
    def test_enforcer_creation(self):
        """Test policy enforcer initialization."""
        enforcer = CryptoPolicyEnforcer()
        assert enforcer is not None
    
    def test_policy_registration(self):
        """Test policy registration."""
        enforcer = CryptoPolicyEnforcer()
        policy = CryptoSecurityPolicy(
            name="test",
            allowed_algorithms=set(),
            blocked_algorithms={"SHA-1"},
        )
        enforcer.register_policy(policy)
    
    def test_blocked_algorithm_validation(self):
        """Test blocked algorithm validation."""
        enforcer = CryptoPolicyEnforcer()
        policy = CryptoSecurityPolicy(
            name="test",
            allowed_algorithms=set(),
            blocked_algorithms={"SHA-1"},
        )
        enforcer.register_policy(policy)
        with pytest.raises(CryptoValidationError):
            enforcer.validate_algorithm("SHA-1", "test")
    
    def test_allowed_algorithm_validation(self):
        """Test allowed algorithm validation."""
        enforcer = CryptoPolicyEnforcer()
        policy = CryptoSecurityPolicy(
            name="test",
            allowed_algorithms={"AES-256"},
            blocked_algorithms=set(),
        )
        enforcer.register_policy(policy)
        assert enforcer.validate_algorithm("AES-256", "test") is True
    
    def test_secure_operation_decorator(self):
        """Test secure operation decorator."""
        enforcer = CryptoPolicyEnforcer()
        
        @enforcer.secure_operation("default")
        def encrypt(data: bytes) -> bytes:
            return data[::-1]
        
        result = encrypt(b"test")
        assert result == b"tset"


# =============================================================================
# Test Crypto Security Hardening Facade
# =============================================================================

class TestCryptoSecurityHardeningFacade:
    def test_facade_creation(self):
        """Test facade initialization."""
        facade = CryptoSecurityHardeningFacade()
        assert facade.security_level == CryptoSecurityLevel.STANDARD
    
    def test_facade_key_validation(self):
        """Test facade key validation."""
        facade = CryptoSecurityHardeningFacade()
        key = secrets.token_bytes(32)
        result = facade.validate_key(key, "AES-256")
        assert result == key
    
    def test_facade_nonce_validation(self):
        """Test facade nonce validation."""
        facade = CryptoSecurityHardeningFacade()
        nonce = secrets.token_bytes(12)
        result = facade.validate_nonce(nonce, "AES-GCM")
        assert result == nonce
    
    def test_facade_constant_time_compare(self):
        """Test facade constant-time comparison."""
        facade = CryptoSecurityHardeningFacade()
        assert facade.constant_time_compare(b"a", b"a") is True
        assert facade.constant_time_compare(b"a", b"b") is False
    
    def test_facade_random_generation(self):
        """Test facade secure random generation."""
        facade = CryptoSecurityHardeningFacade()
        data = facade.generate_secure_random(32)
        assert len(data) == 32
    
    def test_facade_secure_key_creation(self):
        """Test facade secure key creation."""
        facade = CryptoSecurityHardeningFacade()
        key_data = secrets.token_bytes(32)
        with facade.create_secure_key(key_data, "AES-256") as sk:
            assert sk.get_bytes() == key_data
    
    def test_facade_audit_metrics(self):
        """Test facade audit metrics."""
        facade = CryptoSecurityHardeningFacade()
        metrics = facade.get_audit_metrics()
        assert "total_operations" in metrics
        assert "failure_rate" in metrics


# =============================================================================
# Test Convenience Functions
# =============================================================================

class TestConvenienceFunctions:
    def test_crypto_validate_key(self):
        """Test global key validation."""
        key = secrets.token_bytes(32)
        result = crypto_validate_key(key, "AES-256")
        assert result == key
    
    def test_crypto_validate_nonce(self):
        """Test global nonce validation."""
        nonce = secrets.token_bytes(12)
        result = crypto_validate_nonce(nonce, "AES-GCM")
        assert result == nonce
    
    def test_crypto_constant_time_compare(self):
        """Test global compare function."""
        assert crypto_constant_time_compare(b"x", b"x") is True
    
    def test_crypto_generate_secure_random(self):
        """Test global random generation."""
        data = crypto_generate_secure_random(16)
        assert len(data) == 16
    
    def test_crypto_create_secure_key(self):
        """Test global secure key creation."""
        key_data = secrets.token_bytes(32)
        with crypto_create_secure_key(key_data, "AES-256") as sk:
            assert sk.get_bytes() == key_data
    
    def test_get_crypto_security_metrics(self):
        """Test security metrics function."""
        metrics = get_crypto_security_metrics()
        assert isinstance(metrics, dict)


# =============================================================================
# Test Thread Safety
# =============================================================================

class TestThreadSafety:
    def test_audit_log_thread_safety(self):
        """Test audit log thread safety."""
        log = CryptoSecurityAuditLog()
        
        def log_events(n):
            for _ in range(n):
                log.log(CryptoSecurityEvent(
                    event_type=CryptoSecurityEventType.KEY_GENERATION,
                    operation=CryptoOperationType.KEY_GENERATION,
                    algorithm="test",
                ))
        
        threads = [threading.Thread(target=log_events, args=(100,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert log.get_event_count() == 1000


# =============================================================================
# RUN ALL TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
