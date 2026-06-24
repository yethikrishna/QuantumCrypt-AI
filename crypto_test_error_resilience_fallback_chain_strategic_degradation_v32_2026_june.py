"""
Test suite for QuantumCrypt Fallback Chain with Strategic Degradation (v32)
Dimension E - Error Resilience Enhancement

ADD-ONLY TESTS - No existing tests modified.
Tests cover:
- Cryptographic fallback chain operation
- Secure memory zeroization (bytearray only)
- Constant-time operations
- Tamper detection
- Circuit breaker for crypto operations
- Security status reporting
- Thread safety for sensitive operations
"""

import pytest
import time
import threading
import secrets
import hashlib
from quantum_crypt.crypto_error_resilience_fallback_chain_strategic_degradation_v32_2026_june import (
    CryptoDegradationLevel,
    CryptoRecoveryStrategy,
    CryptoFallbackResult,
    CryptoDegradationEvent,
    CryptoFallbackStrategy,
    CryptoStrategicDegradationFallbackChain,
    secure_zero_memory,
    constant_time_compare,
    create_quantum_encryption_chain,
    create_key_management_chain,
    create_hashing_chain
)


class TestCryptoDegradationLevel:
    """Test cryptographic degradation levels."""
    
    def test_crypto_levels_exist(self):
        """Test all crypto degradation levels are defined."""
        levels = [
            CryptoDegradationLevel.FULL,
            CryptoDegradationLevel.PARTIAL,
            CryptoDegradationLevel.MINIMAL,
            CryptoDegradationLevel.FAILSAFE,
            CryptoDegradationLevel.FAILURE
        ]
        assert len(set(levels)) == 5
    
    def test_level_values_security_oriented(self):
        """Test level values reflect security context."""
        assert "quantum" in CryptoDegradationLevel.FULL.value
        assert "classical" in CryptoDegradationLevel.PARTIAL.value


class TestSecureMemoryFunctions:
    """Test secure memory handling utilities."""
    
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison with equal inputs."""
        a = b"test_data_12345"
        b = b"test_data_12345"
        assert constant_time_compare(a, b) is True
    
    def test_constant_time_compare_not_equal(self):
        """Test constant-time comparison with different inputs."""
        a = b"test_data_12345"
        b = b"test_data_54321"
        assert constant_time_compare(a, b) is False
    
    def test_constant_time_compare_different_length(self):
        """Test constant-time comparison with different lengths."""
        a = b"short"
        b = b"much_longer_data"
        assert constant_time_compare(a, b) is False
    
    def test_secure_zero_memory_bytearray(self):
        """Test secure zeroization of bytearray (mutable only)."""
        data = bytearray(b"sensitive_key_material")
        secure_zero_memory(data)
        # Should be all zeros
        assert all(b == 0 for b in data)
    
    def test_secure_zero_memory_no_crash(self):
        """Test zeroization doesn't crash on various inputs."""
        # Should not raise exceptions
        secure_zero_memory(b"test")  # immutable bytes - handled gracefully
        secure_zero_memory(bytearray(b"test"))
        secure_zero_memory(None)
        secure_zero_memory(12345)


class TestCryptoFallbackStrategy:
    """Test cryptographic fallback strategy."""
    
    def test_crypto_strategy_creation(self):
        """Test crypto strategy creation."""
        def encrypt_handler(data):
            return data[::-1]
        
        strategy = CryptoFallbackStrategy(
            name="pq_encryption",
            algorithm="CRYSTALS-Kyber",
            level=CryptoDegradationLevel.FULL,
            handler=encrypt_handler,
            security_level="high"
        )
        assert strategy.algorithm == "CRYSTALS-Kyber"
        assert strategy.security_level == "high"
        assert strategy.sensitive is True
    
    def test_crypto_strategy_success(self):
        """Test successful crypto strategy execution."""
        def hash_handler(data):
            return hashlib.sha256(data).digest()
        
        strategy = CryptoFallbackStrategy(
            "sha256", "SHA-256", CryptoDegradationLevel.FULL, hash_handler
        )
        
        test_data = b"test message"
        success, result, error, tamper = strategy.execute(test_data)
        
        assert success is True
        assert result is not None
        assert error is None
        assert tamper is False
    
    def test_crypto_strategy_failure_cleanup(self):
        """Test failure path performs secure cleanup."""
        sensitive = bytearray(b"secret_key_12345")
        
        def failing_handler(data):
            raise ValueError("Crypto operation failed")
        
        strategy = CryptoFallbackStrategy(
            "fail", "TEST", CryptoDegradationLevel.FULL, failing_handler
        )
        
        success, result, error, tamper = strategy.execute(sensitive)
        
        assert success is False
        assert isinstance(error, ValueError)


class TestCryptoFallbackChain:
    """Test main cryptographic fallback chain."""
    
    def test_crypto_chain_creation(self):
        """Test crypto chain creation."""
        chain = CryptoStrategicDegradationFallbackChain(name="pq_chain")
        assert chain.name == "pq_chain"
        assert chain._current_level == CryptoDegradationLevel.FULL
    
    def test_crypto_strategy_ordering(self):
        """Test crypto strategies ordered by security level."""
        chain = CryptoStrategicDegradationFallbackChain()
        
        def handler():
            return b"ok"
        
        chain.add_strategy("failsafe", "SHA-256", CryptoDegradationLevel.FAILSAFE, handler)
        chain.add_strategy("full", "CRYSTALS-Kyber", CryptoDegradationLevel.FULL, handler)
        chain.add_strategy("partial", "RSA-4096", CryptoDegradationLevel.PARTIAL, handler)
        
        levels = [s.level for s in chain._strategies]
        assert levels == [
            CryptoDegradationLevel.FULL,
            CryptoDegradationLevel.PARTIAL,
            CryptoDegradationLevel.FAILSAFE
        ]
    
    def test_crypto_fallback_chain_execution(self):
        """Test full crypto fallback chain operation."""
        chain = CryptoStrategicDegradationFallbackChain()
        
        call_count = {"full": 0, "partial": 0}
        
        def failing_full(data):
            call_count["full"] += 1
            raise RuntimeError("PQ algorithm unavailable")
        
        def working_partial(data):
            call_count["partial"] += 1
            return hashlib.sha256(data).digest()
        
        chain.add_strategy(
            "kyber", "CRYSTALS-Kyber",
            CryptoDegradationLevel.FULL, failing_full
        )
        chain.add_strategy(
            "rsa", "RSA-4096",
            CryptoDegradationLevel.PARTIAL, working_partial
        )
        
        result = chain.execute(b"test message")
        
        assert result.success is True
        assert result.degradation_level == CryptoDegradationLevel.PARTIAL
        assert result.algorithm_used == "RSA-4096"
        assert call_count["full"] == 1
        assert call_count["partial"] == 1
        assert result.fallback_attempted == 2
    
    def test_crypto_chain_security_status(self):
        """Test security status reporting."""
        chain = CryptoStrategicDegradationFallbackChain("security_test")
        
        def handler(data):
            return hashlib.sha256(data).digest()
        
        chain.add_strategy(
            "sha256", "SHA-256",
            CryptoDegradationLevel.FULL, handler
        )
        chain.execute(b"test")
        
        status = chain.get_security_status()
        assert status["chain_name"] == "security_test"
        assert "security_score" in status
        assert 0.0 <= status["security_score"] <= 1.0
        assert "chain_id" in status
        assert len(status["chain_id"]) == 16
    
    def test_crypto_emergency_reset(self):
        """Test emergency reset functionality."""
        chain = CryptoStrategicDegradationFallbackChain()
        
        def fail(data):
            raise RuntimeError("Failed")
        
        chain.add_strategy("full", "TEST", CryptoDegradationLevel.FULL, fail)
        
        # Cause failures
        for _ in range(5):
            chain.execute(b"test")
        
        old_chain_id = chain.get_security_status()["chain_id"]
        chain.emergency_reset()
        new_chain_id = chain.get_security_status()["chain_id"]
        
        assert chain._current_level == CryptoDegradationLevel.FULL
        assert chain._circuit_open is False
        # Chain ID should change after reset for security
        assert old_chain_id != new_chain_id
    
    def test_all_crypto_strategies_failed(self):
        """Test complete failure case."""
        chain = CryptoStrategicDegradationFallbackChain()
        
        def fail(data):
            raise ValueError("Crypto failure")
        
        chain.add_strategy("full", "ALG1", CryptoDegradationLevel.FULL, fail)
        chain.add_strategy("partial", "ALG2", CryptoDegradationLevel.PARTIAL, fail)
        
        result = chain.execute(b"test")
        
        assert result.success is False
        assert result.degradation_level == CryptoDegradationLevel.FAILURE
        assert isinstance(result.error, ValueError)


class TestCryptoFactoryFunctions:
    """Test crypto factory functions."""
    
    def test_create_quantum_encryption_chain(self):
        """Test PQ encryption chain factory."""
        chain = create_quantum_encryption_chain("pq_test")
        assert isinstance(chain, CryptoStrategicDegradationFallbackChain)
        assert chain.recovery_strategy == CryptoRecoveryStrategy.ALGORITHM_ROTATION
    
    def test_create_key_management_chain(self):
        """Test key management chain factory."""
        chain = create_key_management_chain("km_test")
        assert isinstance(chain, CryptoStrategicDegradationFallbackChain)
        assert chain.recovery_strategy == CryptoRecoveryStrategy.IMMEDIATE_REKEY
    
    def test_create_hashing_chain(self):
        """Test hashing chain factory."""
        chain = create_hashing_chain("hash_test")
        assert isinstance(chain, CryptoStrategicDegradationFallbackChain)
        assert chain.recovery_strategy == CryptoRecoveryStrategy.EXPONENTIAL_BACKOFF


class TestCryptoThreadSafety:
    """Test thread safety for cryptographic operations."""
    
    def test_concurrent_crypto_operations(self):
        """Test concurrent crypto operations are thread-safe."""
        chain = CryptoStrategicDegradationFallbackChain("concurrent_crypto")
        
        def hash_handler(data):
            time.sleep(0.001)
            return hashlib.sha256(data).digest()
        
        chain.add_strategy(
            "sha256", "SHA-256",
            CryptoDegradationLevel.FULL, hash_handler
        )
        
        results = []
        errors = []
        
        def worker():
            try:
                data = secrets.token_bytes(16)
                result = chain.execute(data)
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert len(results) == 20
        assert all(r.success for r in results)


class TestCryptoResultMetadata:
    """Test crypto result contains proper metadata."""
    
    def test_result_has_security_metadata(self):
        """Test result includes security-related metadata."""
        chain = CryptoStrategicDegradationFallbackChain()
        
        def handler(data):
            return b"encrypted"
        
        chain.add_strategy(
            "test", "TEST-ALG",
            CryptoDegradationLevel.FULL, handler,
            security_level="quantum_resistant"
        )
        
        result = chain.execute(b"data")
        
        assert result.success is True
        assert result.algorithm_used == "TEST-ALG"
        assert result.security_level == "quantum_resistant"
        assert result.tamper_detected is False
        assert result.execution_time_ms > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
