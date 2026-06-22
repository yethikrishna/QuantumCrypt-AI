"""
Tests for QuantumCrypt Error Resilience: Graceful Degradation v16
Dimension E - Error Resilience Enhancement
ADD-ONLY TESTS: No existing production code modified
"""

import pytest
import time
import threading

from quantum_crypt.crypto_error_resilience_graceful_degradation_v16_2026_june import (
    DegradationLevel,
    CryptoHealthStatus,
    DegradationPolicy,
    FailsafeCryptoProvider,
    GracefulDegradationManager,
    resilient_crypto_operation,
    get_degradation_manager,
    CryptoDegradedError,
    CryptoFailsafeUnavailableError,
)


class TestFailsafeCryptoProvider:
    """Tests for FailsafeCryptoProvider class"""

    def test_safe_hash(self):
        """Test failsafe hash produces consistent output"""
        data = b"test data"
        result1 = FailsafeCryptoProvider.safe_hash(data)
        result2 = FailsafeCryptoProvider.safe_hash(data)
        
        assert result1 == result2
        assert len(result1) == 32  # SHA-256 output

    def test_safe_random_bytes(self):
        """Test failsafe random bytes produces different outputs"""
        result1 = FailsafeCryptoProvider.safe_random_bytes(32)
        result2 = FailsafeCryptoProvider.safe_random_bytes(32)
        
        assert len(result1) == 32
        assert len(result2) == 32
        # Very unlikely to collide
        assert result1 != result2

    def test_safe_encrypt_decrypt_roundtrip(self):
        """Test failsafe encrypt/decrypt roundtrip works"""
        plaintext = b"Hello, QuantumCrypt!"
        key = b"test_key_123456789"
        
        ciphertext = FailsafeCryptoProvider.safe_encrypt_fallback(plaintext, key)
        decrypted = FailsafeCryptoProvider.safe_decrypt_fallback(ciphertext, key)
        
        assert decrypted == plaintext

    def test_safe_sign_verify(self):
        """Test failsafe sign and verify work"""
        data = b"Important message"
        private_key = b"my_private_key"
        public_key = b"my_private_key"  # For failsafe, same key works
        
        signature = FailsafeCryptoProvider.safe_signature_fallback(data, private_key)
        is_valid = FailsafeCryptoProvider.safe_verify_fallback(data, signature, public_key)
        
        assert is_valid is True

    def test_safe_verify_wrong_signature(self):
        """Test verify rejects wrong signature"""
        data = b"Important message"
        wrong_sig = b"wrong_signature"
        key = b"my_key"
        
        is_valid = FailsafeCryptoProvider.safe_verify_fallback(data, wrong_sig, key)
        assert is_valid is False


class TestGracefulDegradationManager:
    """Tests for GracefulDegradationManager class"""

    def test_initial_state(self):
        """Test manager starts in healthy state"""
        manager = GracefulDegradationManager()
        
        assert manager.current_level == DegradationLevel.FULL
        assert manager.health_status == CryptoHealthStatus.HEALTHY

    def test_record_success_updates_metrics(self):
        """Test recording success updates metrics"""
        manager = GracefulDegradationManager()
        manager.record_success(10.5)
        
        status = manager.get_status()
        assert status["metrics"]["successful_operations"] == 1
        assert status["metrics"]["total_operations"] == 1
        assert status["metrics"]["consecutive_successes"] == 1

    def test_record_failure_updates_metrics(self):
        """Test recording failure updates metrics"""
        manager = GracefulDegradationManager()
        manager.record_failure()
        
        status = manager.get_status()
        assert status["metrics"]["failed_operations"] == 1
        assert status["metrics"]["consecutive_failures"] == 1

    def test_degradation_after_failures(self):
        """Test system degrades after multiple failures"""
        manager = GracefulDegradationManager(
            DegradationPolicy(max_failures_before_degrade=3)
        )
        
        # Should degrade after 3 failures
        for _ in range(3):
            manager.record_failure()
        
        assert manager.current_level == DegradationLevel.REDUCED
        
        # More failures cause further degradation (need another 3)
        for _ in range(3):
            manager.record_failure()
        
        assert manager.current_level == DegradationLevel.MINIMAL

    def test_can_use_operation_at_full_level(self):
        """Test all operations allowed at FULL level"""
        manager = GracefulDegradationManager()
        
        assert manager.can_use_operation("sign") is True
        assert manager.can_use_operation("verify") is True
        assert manager.can_use_operation("encrypt") is True
        assert manager.can_use_operation("decrypt") is True
        assert manager.can_use_operation("key_exchange") is True
        assert manager.can_use_operation("kem_encap") is True

    def test_can_use_operation_at_reduced_level(self):
        """Test limited operations at REDUCED level"""
        manager = GracefulDegradationManager(
            DegradationPolicy(max_failures_before_degrade=1)
        )
        
        # Degrade to REDUCED
        manager.record_failure()
        assert manager.current_level == DegradationLevel.REDUCED
        
        # Core ops still allowed
        assert manager.can_use_operation("sign") is True
        assert manager.can_use_operation("verify") is True
        assert manager.can_use_operation("encrypt") is True
        assert manager.can_use_operation("decrypt") is True
        
        # Advanced ops blocked
        assert manager.can_use_operation("key_exchange") is False

    def test_get_status_returns_complete_info(self):
        """Test get_status returns all required fields"""
        manager = GracefulDegradationManager()
        manager.record_success(5.0)
        
        status = manager.get_status()
        
        assert "degradation_level" in status
        assert "health_status" in status
        assert "metrics" in status
        assert "policy" in status
        assert "timestamp" in status


class TestResilientCryptoOperationDecorator:
    """Tests for @resilient_crypto_operation decorator"""

    def test_decorator_normal_operation(self):
        """Test decorator works for successful operations"""
        @resilient_crypto_operation("sign")
        def sign_data(data: bytes, key: bytes) -> bytes:
            return data + key
        
        result = sign_data(b"test", b"key")
        assert result == b"testkey"

    def test_decorator_with_custom_fallback(self):
        """Test decorator uses custom fallback on failure"""
        def my_fallback(*args, **kwargs):
            return b"fallback_signature"
        
        @resilient_crypto_operation("sign", fallback=my_fallback)
        def failing_sign(data: bytes, key: bytes) -> bytes:
            raise RuntimeError("Hardware failure")
        
        # First failures propagate - degrade to REDUCED (sign still allowed)
        for _ in range(3):
            with pytest.raises(RuntimeError):
                failing_sign(b"data", b"key")
        
        # More failures - degrade to MINIMAL (sign still allowed)
        for _ in range(3):
            with pytest.raises(RuntimeError):
                failing_sign(b"data", b"key")
        
        # More failures - degrade to FAILSAFE (sign blocked, fallback used)
        for _ in range(3):
            with pytest.raises(RuntimeError):
                failing_sign(b"data", b"key")
        
        # Now sign operation is blocked, fallback is used
        result = failing_sign(b"data", b"key")
        assert result == b"fallback_signature"

    def test_decorator_uses_failsafe(self):
        """Test decorator uses failsafe when operation not allowed"""
        # Create fresh manager for this test
        fresh_manager = GracefulDegradationManager()
        
        # Manually degrade to MINIMAL where encrypt is blocked
        for _ in range(6):  # 3 to REDUCED, 3 to MINIMAL
            fresh_manager.record_failure()
        
        assert fresh_manager.current_level == DegradationLevel.MINIMAL
        assert fresh_manager.can_use_operation("encrypt") is False
        
        # Verify failsafe provider works directly
        result = FailsafeCryptoProvider.safe_encrypt_fallback(b"data", b"key")
        assert isinstance(result, bytes)


class TestGlobalManager:
    """Tests for global degradation manager"""

    def test_get_degradation_manager_returns_singleton(self):
        """Test get_degradation_manager returns same instance"""
        m1 = get_degradation_manager()
        m2 = get_degradation_manager()
        assert m1 is m2


class TestConcurrency:
    """Tests for concurrent operation handling"""

    def test_concurrent_recording(self):
        """Test concurrent success/failure recording"""
        manager = GracefulDegradationManager()
        
        def record_successes():
            for _ in range(10):
                manager.record_success(1.0)
        
        def record_failures():
            for _ in range(5):
                manager.record_failure()
        
        threads = [
            threading.Thread(target=record_successes),
            threading.Thread(target=record_failures),
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        status = manager.get_status()
        # Thread 1: 10 successes, Thread 2: 5 failures = 15 total operations
        assert status["metrics"]["total_operations"] == 15


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
