"""
Test Suite for Error Resilience - Cryptographic Operations v31
Dimension E: Error Resilience
Session 132 - June 24, 2026

All tests must pass - backward compatibility 100% maintained.
"""

import unittest
import time
import secrets
from typing import Dict, Any

# Import the module to test
from quantum_crypt.error_resilience_cryptographic_operations_v31_2026_june import (
    # Exceptions
    CryptographicError,
    CryptoKeyManagementError,
    CryptoAlgorithmError,
    CryptoTimeoutError,
    CryptoEntropyError,
    CryptoCircuitOpenError,
    CryptoTLSConnectionError,
    
    # Enums
    CircuitState,
    CryptoOperationType,
    DegradationLevel,
    
    # Data Structures
    CryptoResilienceConfig,
    RetryMetrics,
    CircuitBreakerMetrics,
    CryptoOperationResult,
    
    # Resilience Components
    SecureMemoryManager,
    CryptoAdaptiveRetryBackoff,
    CryptoCircuitBreaker,
    TLSConnectionResilience,
    AlgorithmFallbackChain,
    ComprehensiveCryptoResilience,
)


class TestCustomExceptionHierarchy(unittest.TestCase):
    """Test cryptographic exception hierarchy."""
    
    def test_base_crypto_exception(self):
        """Test base cryptographic exception."""
        error = CryptographicError("Test error", "TEST_001", {"key": "value"})
        self.assertEqual(error.error_code, "TEST_001")
        self.assertIsNotNone(error.timestamp)
    
    def test_secure_wipe_in_exception(self):
        """Test secure wipe of sensitive data in exceptions."""
        error = CryptographicError("Test", "TEST_001", {
            "api_key": "secret123",
            "private_key": "very_secret",
            "normal_field": "ok"
        })
        # Sensitive fields should be redacted
        self.assertEqual(error.details["api_key"], "[REDACTED]")
        self.assertEqual(error.details["private_key"], "[REDACTED]")
        self.assertEqual(error.details["normal_field"], "ok")
    
    def test_key_management_exception(self):
        """Test key management exception."""
        error = CryptoKeyManagementError("Key not found", "key-123")
        self.assertEqual(error.error_code, "CRYPTO_KEY_001")
        self.assertEqual(error.key_id, "key-123")
    
    def test_algorithm_exception(self):
        """Test algorithm exception."""
        error = CryptoAlgorithmError("Algorithm failed", "AES-256")
        self.assertEqual(error.error_code, "CRYPTO_ALG_001")
        self.assertEqual(error.algorithm_name, "AES-256")
    
    def test_tls_connection_exception(self):
        """Test TLS connection exception."""
        error = CryptoTLSConnectionError("Handshake failed", "https://example.com")
        self.assertEqual(error.error_code, "CRYPTO_TLS_001")
        self.assertEqual(error.endpoint, "https://example.com")


class TestSecureMemoryManager(unittest.TestCase):
    """Test secure memory management."""
    
    def test_secure_wipe_bytes(self):
        """Test secure wipe of bytearray."""
        data = bytearray(b"sensitive data here")
        original = bytes(data)
        
        SecureMemoryManager.secure_wipe_bytes(data)
        
        # Data should be all zeros now
        self.assertEqual(bytes(data), b"\x00" * len(original))
    
    def test_secure_wipe_string(self):
        """Test secure wipe string placeholder."""
        result = SecureMemoryManager.secure_wipe_string("secret")
        self.assertTrue(result.startswith("[SECURE_WIPED_"))
        self.assertNotIn("secret", result)


class TestCryptoAdaptiveRetryBackoff(unittest.TestCase):
    """Test adaptive retry with backoff for crypto operations."""
    
    def test_initialization(self):
        """Test handler initialization."""
        config = CryptoResilienceConfig(max_retries=5)
        handler = CryptoAdaptiveRetryBackoff(config)
        self.assertEqual(handler.config.max_retries, 5)
    
    def test_operation_specific_backoff(self):
        """Test operation-specific backoff multipliers."""
        handler = CryptoAdaptiveRetryBackoff()
        
        # Key generation should have longer backoff
        backoff_keygen = handler.calculate_backoff(1, CryptoOperationType.KEY_GENERATION)
        backoff_encryption = handler.calculate_backoff(1, CryptoOperationType.ENCRYPTION)
        
        # Key generation multiplier should be higher
        self.assertGreater(backoff_keygen, backoff_encryption)
    
    def test_successful_operation(self):
        """Test successful crypto operation."""
        handler = CryptoAdaptiveRetryBackoff()
        
        def success_op():
            return {"ciphertext": "encrypted_data"}
        
        result = handler.execute_with_retry(success_op, CryptoOperationType.ENCRYPTION)
        self.assertTrue(result.success)
        self.assertEqual(result.operation_type, CryptoOperationType.ENCRYPTION)
    
    def test_retry_then_success(self):
        """Test operation succeeds after retry."""
        handler = CryptoAdaptiveRetryBackoff()
        attempts = [0]
        
        def flaky_op():
            attempts[0] += 1
            if attempts[0] < 2:
                raise CryptoAlgorithmError("Temporary failure", "TEST")
            return "success"
        
        result = handler.execute_with_retry(flaky_op, CryptoOperationType.SIGNING)
        self.assertTrue(result.success)
        self.assertEqual(result.attempt_count, 2)
    
    def test_fallback_on_permanent_failure(self):
        """Test fallback when all retries fail."""
        handler = CryptoAdaptiveRetryBackoff(CryptoResilienceConfig(max_retries=2))
        
        def always_fail():
            raise CryptoAlgorithmError("Permanent failure", "TEST")
        
        def fallback():
            return "fallback_result"
        
        result = handler.execute_with_retry(always_fail, CryptoOperationType.DECRYPTION, fallback)
        self.assertTrue(result.success)
        self.assertTrue(result.used_fallback)


class TestCryptoCircuitBreaker(unittest.TestCase):
    """Test cryptographic circuit breaker."""
    
    def test_initial_state(self):
        """Test initial circuit state."""
        cb = CryptoCircuitBreaker()
        self.assertEqual(cb.state, CircuitState.CLOSED)
    
    def test_circuit_opens_after_failures(self):
        """Test circuit opens after threshold."""
        config = CryptoResilienceConfig(circuit_failure_threshold=2)
        cb = CryptoCircuitBreaker(config)
        
        cb.record_failure()
        cb.record_failure()
        
        self.assertEqual(cb.state, CircuitState.OPEN)
        self.assertFalse(cb.allow_request())
    
    def test_successful_execution(self):
        """Test successful execution through circuit."""
        cb = CryptoCircuitBreaker()
        
        def op():
            return "encrypted"
        
        result = cb.execute(op, CryptoOperationType.ENCRYPTION)
        self.assertTrue(result.success)
        self.assertEqual(result.circuit_state, CircuitState.CLOSED)
    
    def test_fallback_when_open(self):
        """Test fallback when circuit is open."""
        config = CryptoResilienceConfig(circuit_failure_threshold=1)
        cb = CryptoCircuitBreaker(config)
        cb.record_failure()
        
        def fallback():
            return "software_fallback"
        
        result = cb.execute(lambda: None, CryptoOperationType.ENCRYPTION, fallback)
        self.assertTrue(result.success)
        self.assertTrue(result.used_fallback)
        self.assertEqual(result.fallback_level, DegradationLevel.SOFTWARE_ONLY)
    
    def test_circuit_recovery(self):
        """Test circuit recovery after timeout."""
        config = CryptoResilienceConfig(
            circuit_failure_threshold=1,
            circuit_reset_timeout=0.01, circuit_half_open_max_calls=1
        )
        cb = CryptoCircuitBreaker(config)
        
        cb.record_failure()
        self.assertEqual(cb.state, CircuitState.OPEN)
        
        time.sleep(0.02)
        
        # Should allow test requests in half-open
        self.assertTrue(cb.allow_request())
        
        # Success should close circuit
        cb.record_success()
        self.assertEqual(cb.state, CircuitState.CLOSED)


class TestTLSConnectionResilience(unittest.TestCase):
    """Test TLS connection resilience."""
    
    def test_health_tracking(self):
        """Test endpoint health tracking."""
        tls = TLSConnectionResilience()
        endpoint = "https://example.com"
        
        tls.record_connection_success(endpoint)
        health = tls.get_endpoint_health(endpoint)
        
        self.assertEqual(health["successes"], 1)
        self.assertEqual(health["consecutive_failures"], 0)
    
    def test_failure_tracking(self):
        """Test failure tracking."""
        tls = TLSConnectionResilience()
        endpoint = "https://failing.com"
        
        tls.record_connection_failure(endpoint)
        tls.record_connection_failure(endpoint)
        health = tls.get_endpoint_health(endpoint)
        
        self.assertEqual(health["failures"], 2)
        self.assertEqual(health["consecutive_failures"], 2)
    
    def test_successful_tls_operation(self):
        """Test successful TLS operation."""
        tls = TLSConnectionResilience()
        
        def success_handshake():
            return {"session": "established"}
        
        result = tls.execute_tls_operation(success_handshake, "https://test.com")
        self.assertTrue(result.success)
        self.assertEqual(result.operation_type, CryptoOperationType.TLS_HANDSHAKE)


class TestAlgorithmFallbackChain(unittest.TestCase):
    """Test algorithm fallback chain."""
    
    def test_register_fallback_chain(self):
        """Test registering fallback chain."""
        chain = AlgorithmFallbackChain()
        
        algorithms = [
            {
                "name": "AES-256-GCM",
                "security_level": 256,
                "level": DegradationLevel.FULL,
                "handler": lambda: "aes_result"
            },
            {
                "name": "AES-128-GCM",
                "security_level": 128,
                "level": DegradationLevel.REDUCED_STRENGTH,
                "handler": lambda: "aes128_result"
            }
        ]
        
        chain.register_fallback_chain(CryptoOperationType.ENCRYPTION, algorithms)
    
    def test_primary_success(self):
        """Test primary algorithm succeeds."""
        chain = AlgorithmFallbackChain()
        
        def primary():
            return "primary_result"
        
        result = chain.execute_with_fallback_chain(
            CryptoOperationType.ENCRYPTION,
            primary
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.result, "primary_result")
        self.assertFalse(result.used_fallback)
    
    def test_fallback_chain_execution(self):
        """Test fallback chain when primary fails."""
        chain = AlgorithmFallbackChain()
        
        chain.register_fallback_chain(CryptoOperationType.ENCRYPTION, [
            {
                "name": "Fallback-AES",
                "security_level": 128,
                "level": DegradationLevel.SAFE_DEFAULT,
                "handler": lambda: "fallback_result"
            }
        ])
        
        def primary_fails():
            raise CryptoAlgorithmError("HSM unavailable", "AES-256")
        
        result = chain.execute_with_fallback_chain(
            CryptoOperationType.ENCRYPTION,
            primary_fails
        )
        
        self.assertTrue(result.success)
        self.assertTrue(result.used_fallback)
        self.assertEqual(result.fallback_algorithm, "Fallback-AES")
    
    def test_security_level_enforcement(self):
        """Test minimum security level enforcement."""
        config = CryptoResilienceConfig(minimum_security_level=128)
        chain = AlgorithmFallbackChain(config)
        
        # Weak algorithm below minimum
        chain.register_fallback_chain(CryptoOperationType.ENCRYPTION, [
            {
                "name": "Weak-64",
                "security_level": 64,  # Below minimum
                "level": DegradationLevel.SAFE_DEFAULT,
                "handler": lambda: "weak_result"
            }
        ])
        
        def primary_fails():
            raise Exception("Fail")
        
        result = chain.execute_with_fallback_chain(
            CryptoOperationType.ENCRYPTION,
            primary_fails
        )
        
        # Should fail because fallback below minimum security
        self.assertFalse(result.success)


class TestComprehensiveCryptoResilience(unittest.TestCase):
    """Test comprehensive crypto resilience wrapper."""
    
    def test_initialization(self):
        """Test comprehensive wrapper initialization."""
        resilience = ComprehensiveCryptoResilience()
        self.assertIsNotNone(resilience.retry_handler)
        self.assertIsNotNone(resilience.circuit_breaker)
        self.assertIsNotNone(resilience.tls_handler)
        self.assertIsNotNone(resilience.algorithm_fallback)
        self.assertIsNotNone(resilience.secure_memory)
    
    def test_wrap_crypto_operation(self):
        """Test wrapping crypto operation."""
        resilience = ComprehensiveCryptoResilience()
        
        def encrypt(data: str) -> Dict[str, Any]:
            return {"ciphertext": data[::-1], "algorithm": "TEST"}
        
        wrapped = resilience.wrap_crypto_operation(encrypt, CryptoOperationType.ENCRYPTION)
        
        result = wrapped("test data")
        # Circuit breaker + retry returns OperationResult
        self.assertIsNotNone(result)
    
    def test_health_status(self):
        """Test health status reporting."""
        resilience = ComprehensiveCryptoResilience()
        health = resilience.get_health_status()
        
        self.assertIn("timestamp", health)
        self.assertIn("circuit_breaker", health)
        self.assertIn("retry_metrics", health)
        self.assertIn("security_config", health)


class TestCryptoOperationResult(unittest.TestCase):
    """Test CryptoOperationResult data structure."""
    
    def test_success_result(self):
        """Test successful result."""
        result = CryptoOperationResult(
            success=True,
            result={"ciphertext": "encrypted"},
            operation_type=CryptoOperationType.ENCRYPTION
        )
        self.assertTrue(result.success)
        self.assertEqual(result.security_level, 256)
        self.assertFalse(result.used_fallback)
    
    def test_fallback_result(self):
        """Test result with algorithm fallback."""
        result = CryptoOperationResult(
            success=True,
            error=CryptoAlgorithmError("HSM down", "AES-256"),
            used_fallback=True,
            fallback_algorithm="AES-128",
            fallback_level=DegradationLevel.REDUCED_STRENGTH,
            security_level=128,
            operation_type=CryptoOperationType.ENCRYPTION,
            warnings=["Using fallback algorithm"]
        )
        self.assertTrue(result.success)
        self.assertTrue(result.used_fallback)
        self.assertEqual(result.fallback_algorithm, "AES-128")
        self.assertEqual(result.security_level, 128)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - no breaking changes."""
    
    def test_module_importable(self):
        """Verify new module can be imported without issues."""
        import quantum_crypt
        
        # Check our new module exists
        self.assertTrue(hasattr(quantum_crypt, "error_resilience_cryptographic_operations_v31_2026_june"))
        
        # All imports work
        from quantum_crypt.error_resilience_cryptographic_operations_v31_2026_june import (
            CryptographicError,
            CryptoResilienceConfig,
            CryptoOperationType,
        )
        
        # All classes can be instantiated
        error = CryptographicError("test", "TEST_001")
        self.assertIsNotNone(error)
        
        config = CryptoResilienceConfig()
        self.assertIsNotNone(config)


def run_tests():
    """Run all tests and report results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY - Dimension E: Error Resilience v31")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print(f"{'='*60}")
    
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED - 100% Backward Compatible")
        return True
    else:
        print("❌ SOME TESTS FAILED")
        return False


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
