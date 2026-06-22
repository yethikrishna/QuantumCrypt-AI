"""
Test Suite for QuantumCrypt Error Resilience v17
Crypto-Specific Key Operation Protection with Side-Channel Resistant Retries

DIMENSION E - Error Resilience
ADD-ONLY - tests only, no production code modifications
"""

import pytest
import time
import threading
import secrets
import hashlib
from quantum_crypt.crypto_error_resilience_key_operation_protection_v17_2026_june import (
    SecureBytes, KeySensitivityLevel,
    constant_time_compare, constant_time_delay, secure_memzero,
    KeyCompromiseDetector, KeyUsageAnomaly,
    CryptoOperationTimeout,
    SecureRetryEngine, CryptoRetryPolicy, CryptoOperationType, CryptoFailureMode,
    HSMEmulator, crypto_hsm,
    CipherSuiteManager, cipher_manager, CipherSuite, CipherSuitePriority,
    CryptoResilienceController, crypto_resilience,
    CryptoResilienceError, CryptoTimeoutError, CryptoRetryExhaustedError,
    HSMError, KeyNotFoundError, KeyCompromiseError
)

# -----------------------------------------------------------------------------
# SECURE BYTES TESTS
# -----------------------------------------------------------------------------

class TestSecureBytes:
    def test_create_from_bytes(self):
        data = b"test_secret_key_12345"
        sb = SecureBytes.from_bytes(data)
        assert sb.get() == data
    
    def test_zeroize_destroys_data(self):
        data = b"sensitive_material_here"
        sb = SecureBytes.from_bytes(data)
        sb.zeroize()
        try:
            sb.get()
            assert False, "Should raise ValueError after zeroize"
        except ValueError:
            pass
    
    def test_sensitivity_level(self):
        sb = SecureBytes.from_bytes(b"test", KeySensitivityLevel.PUBLIC)
        assert sb.sensitivity == KeySensitivityLevel.PUBLIC
    
    def test_len_works(self):
        data = b"12345"
        sb = SecureBytes.from_bytes(data)
        assert len(sb) == 5

# -----------------------------------------------------------------------------
# CONSTANT-TIME UTILITY TESTS
# -----------------------------------------------------------------------------

class TestConstantTimeUtils:
    def test_constant_time_compare_equal(self):
        a = b"hello_world_12345"
        b = b"hello_world_12345"
        assert constant_time_compare(a, b) == True
    
    def test_constant_time_compare_not_equal(self):
        a = b"hello_world_12345"
        b = b"hello_world_12346"
        assert constant_time_compare(a, b) == False
    
    def test_constant_time_compare_different_lengths(self):
        a = b"short"
        b = b"longer_string"
        assert constant_time_compare(a, b) == False
    
    def test_secure_memzero(self):
        buf = bytearray(b"this_is_sensitive_data")
        original = bytes(buf)
        secure_memzero(buf)
        assert bytes(buf) != original
        assert all(b == 0 for b in buf)
    
    def test_constant_time_delay(self):
        start = time.time()
        constant_time_delay(10.0)  # 10ms
        elapsed = (time.time() - start) * 1000
        assert elapsed >= 10.0  # Should always wait at least the delay

# -----------------------------------------------------------------------------
# KEY COMPROMISE DETECTOR TESTS
# -----------------------------------------------------------------------------

class TestKeyCompromiseDetector:
    def test_initialization(self):
        kcd = KeyCompromiseDetector()
        assert kcd is not None
    
    def test_records_usage(self):
        kcd = KeyCompromiseDetector()
        kcd.record_usage("key1", 10.0, True)
        # Should not raise
    
    def test_normal_usage_low_risk(self):
        kcd = KeyCompromiseDetector()
        for _ in range(60):
            kcd.record_usage("key1", 10.0, True)
        risk = kcd.get_risk_score("key1")
        assert risk < 0.5  # Low risk for consistent pattern
    
    def test_get_anomalies(self):
        kcd = KeyCompromiseDetector()
        anomalies = kcd.get_anomalies()
        assert isinstance(anomalies, list)

# -----------------------------------------------------------------------------
# CRYPTO TIMEOUT TESTS
# -----------------------------------------------------------------------------

class TestCryptoOperationTimeout:
    def test_initialization(self):
        cot = CryptoOperationTimeout(timeout_ms=1000.0)
        assert cot.timeout_ms == 1000.0
    
    def test_successful_execution(self):
        cot = CryptoOperationTimeout(timeout_ms=1000.0)
        
        def fast_func():
            return "success"
        
        result = cot.execute(fast_func)
        assert result == "success"

# -----------------------------------------------------------------------------
# SECURE RETRY ENGINE TESTS
# -----------------------------------------------------------------------------

class TestSecureRetryEngine:
    def test_initialization(self):
        engine = SecureRetryEngine()
        assert engine is not None
    
    def test_succeeds_on_first_try(self):
        engine = SecureRetryEngine(CryptoRetryPolicy(max_attempts=3))
        
        def always_succeeds():
            return "success"
        
        result = engine.execute(CryptoOperationType.ENCRYPTION, always_succeeds)
        assert result == "success"
    
    def test_succeeds_on_retry(self):
        engine = SecureRetryEngine(CryptoRetryPolicy(max_attempts=3))
        call_count = [0]
        
        def succeeds_on_second():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("transient error")
            return "success"
        
        result = engine.execute(CryptoOperationType.ENCRYPTION, succeeds_on_second)
        assert result == "success"
        assert call_count[0] == 2
    
    def test_get_metrics(self):
        engine = SecureRetryEngine()
        metrics = engine.get_metrics()
        assert metrics.operations_total == 0
        assert metrics.success_rate == 1.0

# -----------------------------------------------------------------------------
# HSM EMULATOR TESTS
# -----------------------------------------------------------------------------

class TestHSMEmulator:
    def test_store_and_retrieve_key(self):
        hsm = HSMEmulator()
        key = secrets.token_bytes(32)
        hsm.store_key("test_key", key)
        retrieved = hsm.retrieve_key("test_key")
        assert retrieved == key
    
    def test_key_not_found_raises(self):
        hsm = HSMEmulator()
        try:
            hsm.retrieve_key("nonexistent")
            assert False, "Should raise KeyNotFoundError"
        except KeyNotFoundError:
            pass
    
    def test_lock_prevents_access(self):
        hsm = HSMEmulator()
        hsm.store_key("key1", secrets.token_bytes(32))
        hsm.lock()
        try:
            hsm.retrieve_key("key1")
            assert False, "Should raise HSMError when locked"
        except HSMError:
            pass
        hsm.unlock()
        # Should work after unlock
        assert hsm.retrieve_key("key1") is not None
    
    def test_get_key_info(self):
        hsm = HSMEmulator()
        key = secrets.token_bytes(32)
        hsm.store_key("key1", key, KeySensitivityLevel.CRITICAL)
        info = hsm.get_key_info("key1")
        assert "created" in info
        assert "sensitivity" in info
        assert "usage_count" in info
    
    def test_global_instance(self):
        assert crypto_hsm is not None
        assert isinstance(crypto_hsm, HSMEmulator)

# -----------------------------------------------------------------------------
# CIPHER SUITE MANAGER TESTS
# -----------------------------------------------------------------------------

class TestCipherSuiteManager:
    def test_get_preferred_suite(self):
        preferred = cipher_manager.get_preferred_suite()
        assert preferred is not None
        assert isinstance(preferred, CipherSuite)
    
    def test_register_suite(self):
        manager = CipherSuiteManager()
        suite = CipherSuite(
            name="Test-Cipher", algorithm="TEST", key_size_bits=256,
            priority=CipherSuitePriority.SECONDARY, fips_compliant=True
        )
        manager.register_suite(suite)
        suites = manager.get_available_suites()
        assert len(suites) == 1
    
    def test_global_manager_has_suites(self):
        suites = cipher_manager.get_available_suites()
        assert len(suites) >= 3  # AES-256, ChaCha20, AES-128

# -----------------------------------------------------------------------------
# CRYPTO RESILIENCE CONTROLLER TESTS
# -----------------------------------------------------------------------------

class TestCryptoResilienceController:
    def test_singleton_pattern(self):
        c1 = CryptoResilienceController()
        c2 = CryptoResilienceController()
        assert c1 is c2
    
    def test_protect_operation_decorator(self):
        @crypto_resilience.protect_operation(CryptoOperationType.HASHING)
        def sha256_hash(data: bytes) -> bytes:
            return hashlib.sha256(data).digest()
        
        result = sha256_hash(b"test_data")
        assert len(result) == 32
    
    def test_get_health_report(self):
        report = crypto_resilience.get_health_report()
        assert "retry_engine" in report
        assert "cipher_suites" in report
        assert "hsm" in report
    
    def test_global_instance(self):
        assert crypto_resilience is not None
        assert isinstance(crypto_resilience, CryptoResilienceController)

# -----------------------------------------------------------------------------
# EXCEPTION HIERARCHY TESTS
# -----------------------------------------------------------------------------

class TestExceptions:
    def test_crypto_resilience_error_base(self):
        err = CryptoResilienceError("test error", detail="extra")
        assert "test error" in str(err)
        assert hasattr(err, 'timestamp')
        assert hasattr(err, 'details')
    
    def test_specific_exceptions_inherit_base(self):
        assert issubclass(CryptoTimeoutError, CryptoResilienceError)
        assert issubclass(CryptoRetryExhaustedError, CryptoResilienceError)
        assert issubclass(HSMError, CryptoResilienceError)
        assert issubclass(KeyNotFoundError, HSMError)
        assert issubclass(KeyCompromiseError, HSMError)

# -----------------------------------------------------------------------------
# CONCURRENCY TESTS
# -----------------------------------------------------------------------------

class TestConcurrency:
    def test_hsm_thread_safe(self):
        hsm = HSMEmulator()
        hsm.store_key("shared_key", secrets.token_bytes(32))
        threads = []
        
        def worker():
            for _ in range(10):
                hsm.retrieve_key("shared_key")
        
        for _ in range(10):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        # Should complete without deadlock
    
    def test_retry_engine_thread_safe(self):
        engine = SecureRetryEngine()
        threads = []
        
        def worker():
            def func():
                return "ok"
            for _ in range(5):
                engine.execute(CryptoOperationType.HASHING, func)
        
        for _ in range(5):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()

# -----------------------------------------------------------------------------
# BACKWARD COMPATIBILITY TESTS
# -----------------------------------------------------------------------------

class TestBackwardCompatibility:
    def test_no_breaking_changes(self):
        """All new functionality is additive."""
        sb = SecureBytes.from_bytes(b"test")
        assert sb is not None
        
        hsm = HSMEmulator()
        assert hsm is not None
    
    def test_constant_time_compare_standard(self):
        """Uses hmac.compare_digest which is Python standard."""
        import hmac
        a = b"test"
        b = b"test"
        assert constant_time_compare(a, b) == hmac.compare_digest(a, b)

# -----------------------------------------------------------------------------
# RUN TESTS
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("QuantumCrypt Crypto Resilience v17 - Test Suite")
    print("=" * 60)
    
    # Run self-tests from module
    from quantum_crypt.crypto_error_resilience_key_operation_protection_v17_2026_june import run_self_tests
    results = run_self_tests()
    
    print(f"\nFinal: {results['tests_passed']}/{results['tests_passed'] + results['tests_failed']} tests passed")
    
    if results['tests_failed'] > 0:
        exit(1)
    exit(0)
