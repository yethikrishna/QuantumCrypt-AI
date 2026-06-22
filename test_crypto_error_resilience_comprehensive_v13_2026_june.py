"""
Tests for QuantumCrypt Error Resilience Framework v13 - June 22, 2026
"""

import pytest
import time
import secrets
from datetime import datetime, timedelta
from quantum_crypt.crypto_error_resilience_comprehensive_v13_2026_june import (
    QuantumCryptError, CryptoError, KeyManagementError,
    AlgorithmError, AlgorithmFailureError, CertificateError,
    CryptoOperationMode, KeyStatus, CryptoRetryConfig,
    KeyHealthMonitor, CryptoCircuitBreaker, EntropyHealthMonitor,
    CertificateValidationGrace, SafeCryptoExecutor,
    crypto_retry, algorithm_fallback_chain,
    secure_zeroize, secure_buffer, create_crypto_resilience_suite,
    HSMConnectionError, AlgorithmNotSupportedError,
    CertificateExpiredError,
)

class TestExceptionHierarchy:
    def test_base_exception(self):
        err = QuantumCryptError("test", "CODE", {})
        assert err.message == "test"
        assert err.code == "CODE"
    
    def test_inheritance(self):
        assert issubclass(CryptoError, QuantumCryptError)
        assert issubclass(KeyManagementError, CryptoError)

class TestSecureMemory:
    def test_zeroize(self):
        data = bytearray(b'test123')
        secure_zeroize(data)
        assert all(b == 0 for b in data)
    
    def test_secure_buffer(self):
        with secure_buffer(32) as buf:
            assert len(buf) == 32

class TestKeyHealthMonitor:
    def test_register_key(self):
        monitor = KeyHealthMonitor()
        monitor.register_key("key-001", max_uses=1000)
        assert monitor.get_health_score("key-001") == 1.0

class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CryptoCircuitBreaker("AES")
        assert cb.is_open is False
    
    def test_trips_after_failures(self):
        cb = CryptoCircuitBreaker("test", failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open is True
    
    def test_recovers(self):
        cb = CryptoCircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        assert cb.is_open is False

class TestEntropyMonitor:
    def test_get_random(self):
        monitor = EntropyHealthMonitor()
        result = monitor.get_random_bytes(32)
        assert len(result) == 32

class TestCryptoRetry:
    def test_retry(self):
        call_count = [0]
        @crypto_retry(CryptoRetryConfig(max_attempts=3))
        def flaky():
            call_count[0] += 1
            if call_count[0] < 2:
                raise HSMConnectionError("temp", "ERR")
            return "ok"
        assert flaky() == "ok"
        assert call_count[0] == 2

class TestCertificateGrace:
    def test_valid(self):
        grace = CertificateValidationGrace()
        future = datetime.utcnow() + timedelta(days=30)
        valid, renew = grace.validate_with_grace(future)
        assert valid is True
        assert renew is False

class TestSafeExecutor:
    def test_success(self):
        result = SafeCryptoExecutor.execute(lambda: 42)
        assert result.success is True
        assert result.value == 42

class TestFactory:
    def test_create_suite(self):
        suite = create_crypto_resilience_suite()
        assert 'key_monitor' in suite
        assert 'entropy_monitor' in suite

class TestEnums:
    def test_modes(self):
        assert "normal" in [m.value for m in CryptoOperationMode]

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
