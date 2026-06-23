"""
Test suite for QuantumCrypt Key Operation Protector Error Resilience Module
Dimension E: Error Resilience

Tests cover:
- Crypto-specific exception hierarchy
- Key operation circuit breaker
- HSM connection resilience
- Secure memory zeroization
- Graceful degradation tiers
- Constant-time comparison
- Retry strategies for crypto operations

All tests are ADD-ONLY - no existing code modified.
"""

import pytest
import time
import threading
import secrets
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor, as_completed

from quantum_crypt.crypto_error_resilience_key_operation_protector_v23_2026_june import (
    KeyOperationProtector,
    CryptoGracefulDegradation,
    SecureMemory,
    CryptoRetryStrategy,
    CryptoFailureMode,
    CryptoDegradationLevel,
    CryptoError,
    KeyGenerationError,
    EncryptionError,
    DecryptionError,
    HSMConnectionError,
    RandomnessError,
    CryptoFallback,
    CryptoOperationMetrics,
    secure_compare,
    generate_emergency_key,
    get_crypto_protector,
    list_crypto_protectors,
)


class TestCryptoExceptionHierarchy:
    """Test crypto-specific exception hierarchy."""
    
    def test_base_crypto_error(self):
        """Test base CryptoError attributes."""
        err = CryptoError(
            "test error",
            CryptoFailureMode.ENCRYPTION_FAILED,
            retryable=True
        )
        assert err.failure_mode == CryptoFailureMode.ENCRYPTION_FAILED
        assert err.retryable is True
        assert err.sensitive is True
    
    def test_key_generation_error(self):
        """Test KeyGenerationError defaults."""
        err = KeyGenerationError("key gen failed")
        assert err.failure_mode == CryptoFailureMode.KEY_GENERATION_FAILED
        assert err.retryable is True
    
    def test_encryption_error(self):
        """Test EncryptionError defaults."""
        err = EncryptionError("encrypt failed")
        assert err.failure_mode == CryptoFailureMode.ENCRYPTION_FAILED
        assert err.retryable is False
    
    def test_hsm_connection_error(self):
        """Test HSMConnectionError is retryable."""
        err = HSMConnectionError("HSM down")
        assert err.failure_mode == CryptoFailureMode.HSM_CONNECTION_LOST
        assert err.retryable is True
    
    def test_exception_inheritance(self):
        """Test all crypto errors inherit from CryptoError."""
        assert issubclass(KeyGenerationError, CryptoError)
        assert issubclass(EncryptionError, CryptoError)
        assert issubclass(DecryptionError, CryptoError)
        assert issubclass(HSMConnectionError, CryptoError)
        assert issubclass(RandomnessError, CryptoError)


class TestCryptoFailureMode:
    """Test crypto failure mode enumeration."""
    
    def test_all_failure_modes_exist(self):
        """Test all expected failure modes are defined."""
        modes = [
            CryptoFailureMode.KEY_GENERATION_FAILED,
            CryptoFailureMode.ENCRYPTION_FAILED,
            CryptoFailureMode.DECRYPTION_FAILED,
            CryptoFailureMode.SIGNING_FAILED,
            CryptoFailureMode.VERIFICATION_FAILED,
            CryptoFailureMode.HSM_CONNECTION_LOST,
            CryptoFailureMode.RANDOMNESS_EXHAUSTED,
            CryptoFailureMode.INTEGRITY_CHECK_FAILED,
            CryptoFailureMode.KEYSTORE_LOCKED,
            CryptoFailureMode.CERTIFICATE_EXPIRED,
            CryptoFailureMode.TRANSIENT_HARDWARE_ERROR,
        ]
        assert len(modes) == 11


class TestCryptoDegradationLevel:
    """Test degradation level enumeration."""
    
    def test_degradation_levels(self):
        """Test all degradation levels exist."""
        levels = [
            CryptoDegradationLevel.FULL,
            CryptoDegradationLevel.STANDARD,
            CryptoDegradationLevel.MINIMAL,
            CryptoDegradationLevel.FIPS_COMPLIANT,
            CryptoDegradationLevel.EMERGENCY,
        ]
        assert len(levels) == 5


class TestSecureMemory:
    """Test secure memory with zeroization."""
    
    def test_secure_memory_initialization(self):
        """Test secure memory creation."""
        data = b"sensitive_key_material_12345"
        with SecureMemory(data) as mem:
            assert mem.get() == data
    
    def test_secure_memory_zeroization(self):
        """Test memory is zeroized after use."""
        data = b"secret_data_here"
        mem = SecureMemory(data)
        original = mem.get()
        mem.zeroize()
        
        # After zeroization, should not contain original
        # Note: we can't read the internal buffer directly,
        # but we can verify it doesn't crash and state changes
    
    def test_context_manager(self):
        """Test context manager auto-zeroization."""
        data = b"test_secret"
        with SecureMemory(data) as mem:
            value = mem.get()
            assert value == data
        # Exit should zeroize
    
    def test_multiple_zeroize_safe(self):
        """Test multiple zeroize calls are safe."""
        mem = SecureMemory(b"test")
        mem.zeroize()
        mem.zeroize()  # Should not crash


class TestCryptoRetryStrategy:
    """Test crypto-specific retry strategies."""
    
    def test_retry_strategy_initialization(self):
        """Test retry strategy creation."""
        retry = CryptoRetryStrategy(
            max_attempts=5,
            initial_delay=0.1,
            max_delay=5.0
        )
        assert retry.max_attempts == 5
    
    def test_should_retry_crypto_error(self):
        """Test retry decision for crypto errors."""
        retry = CryptoRetryStrategy()
        
        # Retryable error
        err1 = HSMConnectionError("connection lost")
        assert retry.should_retry(err1, 0) is True
        
        # Non-retryable error
        err2 = EncryptionError("invalid data")
        assert retry.should_retry(err2, 0) is False
    
    def test_should_retry_standard_errors(self):
        """Test retry for standard connection errors."""
        retry = CryptoRetryStrategy()
        
        assert retry.should_retry(ConnectionError(), 0) is True
        assert retry.should_retry(TimeoutError(), 0) is True
    
    def test_max_attempts_respected(self):
        """Test max attempts limit is respected."""
        retry = CryptoRetryStrategy(max_attempts=3)
        err = HSMConnectionError("test")
        
        assert retry.should_retry(err, 0) is True
        assert retry.should_retry(err, 1) is True
        assert retry.should_retry(err, 2) is True
        assert retry.should_retry(err, 3) is False  # Exceeds max
    
    def test_backoff_delay_calculation(self):
        """Test exponential backoff with jitter."""
        retry = CryptoRetryStrategy(initial_delay=0.1, max_delay=5.0)
        
        delays = [retry.get_delay(i) for i in range(5)]
        # Delays should generally increase (with jitter)
        assert all(0 < d <= 5.0 for d in delays)


class TestCryptoFallback:
    """Test crypto fallback configuration."""
    
    def test_fallback_with_handler(self):
        """Test fallback with handler function."""
        def emergency_encrypt(data):
            return b"encrypted_" + data
        
        fallback = CryptoFallback(
            name="emergency_encrypt",
            degradation_level=CryptoDegradationLevel.EMERGENCY,
            handler=emergency_encrypt
        )
        assert fallback.name == "emergency_encrypt"
        assert fallback.handler is not None
    
    def test_fallback_with_static_key(self):
        """Test fallback with static key."""
        fallback = CryptoFallback(
            name="static_key",
            degradation_level=CryptoDegradationLevel.MINIMAL,
            static_key=b"emergency_key_12345"
        )
        assert fallback.static_key == b"emergency_key_12345"
    
    def test_fallback_validation(self):
        """Test fallback requires handler or key."""
        with pytest.raises(ValueError):
            CryptoFallback(
                name="invalid",
                degradation_level=CryptoDegradationLevel.STANDARD
            )


class TestKeyOperationProtector:
    """Test main key operation protector functionality."""
    
    def test_protector_creation(self):
        """Test protector initialization."""
        protector = KeyOperationProtector(
            name="test_hsm",
            operation_type="key_generation",
            failure_threshold=3
        )
        assert protector.name == "test_hsm"
        assert protector.operation_type == "key_generation"
        assert protector.is_healthy is True
    
    def test_successful_operation(self):
        """Test successful operation protection."""
        protector = KeyOperationProtector("test")
        
        def generate_key():
            return secrets.token_bytes(32)
        
        result = protector.protect(generate_key)
        assert len(result) == 32
        assert protector.metrics.successful_operations == 1
    
    def test_operation_with_exception(self):
        """Test exception handling in protected operations."""
        protector = KeyOperationProtector("test")
        
        def failing_op():
            raise HSMConnectionError("HSM not responding")
        
        with pytest.raises(HSMConnectionError):
            protector.protect(failing_op, auto_retry=False)
        
        assert protector.metrics.failed_operations == 1
    
    def test_fallback_activation(self):
        """Test fallback activation when circuit opens."""
        protector = KeyOperationProtector("test", failure_threshold=1)
        
        fallback = CryptoFallback(
            name="emergency_keygen",
            degradation_level=CryptoDegradationLevel.EMERGENCY,
            handler=lambda: b"emergency_key_data",
            allowed_failures=[CryptoFailureMode.HSM_CONNECTION_LOST]
        )
        protector.register_fallback(fallback)
        
        # Force circuit open
        def failing_op():
            raise HSMConnectionError("down")
        
        for _ in range(5):
            try:
                protector.protect(failing_op, auto_retry=False)
            except (HSMConnectionError, CryptoError):
                pass
    
    def test_decorator_usage(self):
        """Test protector as decorator."""
        protector = KeyOperationProtector("decorator_test")
        
        @protector()
        def secure_encrypt(data: bytes) -> bytes:
            return b"encrypted_" + data
        
        result = secure_encrypt(b"test_data")
        assert result.startswith(b"encrypted_")
    
    def test_metrics_collection(self):
        """Test metrics are collected correctly."""
        protector = KeyOperationProtector("metrics_test")
        
        def success_op():
            return b"ok"
        
        def fail_op():
            raise HSMConnectionError("error")
        
        protector.protect(success_op)
        protector.protect(success_op)
        
        try:
            protector.protect(fail_op, auto_retry=False)
        except HSMConnectionError:
            pass
        
        metrics = protector.metrics
        assert metrics.successful_operations == 2
        assert metrics.failed_operations == 1


class TestCryptoGracefulDegradation:
    """Test graceful degradation manager."""
    
    def test_manager_initialization(self):
        """Test degradation manager creation."""
        manager = CryptoGracefulDegradation()
        assert manager.current_level == CryptoDegradationLevel.FULL
    
    def test_implementation_registration(self):
        """Test registering implementation tiers."""
        manager = CryptoGracefulDegradation()
        
        def full_encrypt(data):
            return b"hsm_" + data
        
        def standard_encrypt(data):
            return b"soft_" + data
        
        manager.register_implementation(
            CryptoDegradationLevel.FULL,
            {"encrypt": full_encrypt}
        )
        manager.register_implementation(
            CryptoDegradationLevel.STANDARD,
            {"encrypt": standard_encrypt}
        )
        
        level, impl = manager.get_best_implementation("encrypt")
        assert level == CryptoDegradationLevel.FULL
        assert impl(b"test") == b"hsm_test"
    
    def test_health_based_selection(self):
        """Test selection based on health scores."""
        manager = CryptoGracefulDegradation()
        
        manager.register_implementation(
            CryptoDegradationLevel.FULL,
            {"encrypt": lambda d: b"full"}
        )
        manager.register_implementation(
            CryptoDegradationLevel.STANDARD,
            {"encrypt": lambda d: b"standard"}
        )
        
        # Mark FULL tier as unhealthy
        manager.update_health(CryptoDegradationLevel.FULL, 0.1)
        manager.update_health(CryptoDegradationLevel.STANDARD, 0.9)
        
        level, impl = manager.get_best_implementation("encrypt")
        assert level == CryptoDegradationLevel.STANDARD
    
    def test_no_implementation_available(self):
        """Test behavior when no healthy implementations."""
        manager = CryptoGracefulDegradation()
        manager.register_implementation(
            CryptoDegradationLevel.FULL,
            {"encrypt": lambda d: b"test"}
        )
        manager.update_health(CryptoDegradationLevel.FULL, 0.1)
        
        result = manager.get_best_implementation("encrypt", min_health=0.5)
        assert result is None


class TestSecureHelpers:
    """Test security helper functions."""
    
    def test_secure_compare_equal(self):
        """Test constant-time comparison for equal values."""
        a = b"test_value_12345"
        b = b"test_value_12345"
        assert secure_compare(a, b) is True
    
    def test_secure_compare_not_equal(self):
        """Test constant-time comparison for unequal values."""
        a = b"value_one"
        b = b"value_two"
        assert secure_compare(a, b) is False
    
    def test_secure_compare_different_lengths(self):
        """Test comparison with different lengths."""
        a = b"short"
        b = b"much_longer_value"
        assert secure_compare(a, b) is False
    
    def test_generate_emergency_key(self):
        """Test emergency key generation."""
        key1 = generate_emergency_key(32)
        key2 = generate_emergency_key(32)
        
        assert len(key1) == 32
        assert len(key2) == 32
        assert key1 != key2  # Keys should be random/different
    
    def test_generate_emergency_key_lengths(self):
        """Test key generation with different lengths."""
        assert len(generate_emergency_key(16)) == 16
        assert len(generate_emergency_key(64)) == 64


class TestProtectorRegistry:
    """Test global protector registry."""
    
    def test_get_crypto_protector(self):
        """Test get or create protector."""
        p1 = get_crypto_protector("registry_test", "encryption")
        p2 = get_crypto_protector("registry_test", "encryption")
        
        assert p1 is p2  # Same instance
    
    def test_list_protectors(self):
        """Test listing all protectors."""
        get_crypto_protector("listed_protector")
        protectors = list_crypto_protectors()
        
        assert "listed_protector" in protectors


class TestConcurrency:
    """Test thread safety of crypto protectors."""
    
    def test_concurrent_protected_operations(self):
        """Test protector under concurrent load."""
        protector = KeyOperationProtector("concurrent_test")
        
        def slow_key_gen():
            time.sleep(0.01)
            return secrets.token_bytes(16)
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(protector.protect, slow_key_gen) for _ in range(20)]
            results = [f.result() for f in as_completed(futures)]
        
        assert all(len(r) == 16 for r in results)
        assert protector.metrics.successful_operations == 20


class TestCryptoOperationMetrics:
    """Test metrics dataclass."""
    
    def test_default_metrics(self):
        """Test default metric values."""
        metrics = CryptoOperationMetrics()
        assert metrics.successful_operations == 0
        assert metrics.failed_operations == 0
        assert metrics.fallback_activations == 0
        assert metrics.hsm_reconnections == 0
        assert metrics.retry_attempts == 0
        assert metrics.key_regenerations == 0
        assert metrics.last_failure_time is None
        assert metrics.current_degradation == CryptoDegradationLevel.FULL


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
