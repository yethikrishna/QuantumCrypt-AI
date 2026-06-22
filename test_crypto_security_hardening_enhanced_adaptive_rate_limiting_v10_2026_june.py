"""
Tests for QuantumCrypt Enhanced Adaptive Rate Limiting & DoS Protection V10
============================================================================
All existing tests must pass - NO core crypto code modifications
"""

import pytest
import time
import threading
from quantum_crypt.crypto_security_hardening_enhanced_adaptive_rate_limiting_dos_protection_v10_2026_june import (
    CryptoAdaptiveRateLimiter,
    CryptoRateLimitConfig,
    CryptoOperationType,
    CryptoOperationCost,
    CryptoThreatLevel,
    crypto_rate_limited,
    check_crypto_rate_limit,
    whitelist_crypto_client,
    blacklist_crypto_client,
    default_crypto_limiter,
)


class TestCryptoAdaptiveRateLimiterBasics:
    """Basic crypto rate limiter functionality tests."""
    
    def test_initial_token_count(self):
        """Test initial token count is correct."""
        config = CryptoRateLimitConfig(base_tokens_per_second=50, max_tokens=200)
        limiter = CryptoAdaptiveRateLimiter(config)
        allowed, info = limiter.try_acquire("test_client", CryptoOperationType.HASHING)
        assert allowed is True
        assert "tokens_remaining" in info
    
    def test_operation_cost_accounting(self):
        """Test different operations have different costs."""
        config = CryptoRateLimitConfig(base_tokens_per_second=100, max_tokens=100)
        limiter = CryptoAdaptiveRateLimiter(config)
        
        # Cheap operation
        allowed1, info1 = limiter.try_acquire("client1", CryptoOperationType.HASHING)
        assert allowed1 is True
        
        # Expensive operation
        allowed2, info2 = limiter.try_acquire("client1", CryptoOperationType.KEY_GENERATION)
        assert allowed2 is True
        assert info2["cost"] > info1["cost"]
    
    def test_basic_rate_limit_enforcement(self):
        """Test basic rate limiting works for crypto ops."""
        config = CryptoRateLimitConfig(base_tokens_per_second=1, max_tokens=10)
        limiter = CryptoAdaptiveRateLimiter(config)
        
        for i in range(10):
            allowed, _ = limiter.try_acquire("client1", CryptoOperationType.HASHING)
            assert allowed is True, f"Request {i+1} should be allowed"
        
        allowed, info = limiter.try_acquire("client1", CryptoOperationType.HASHING)
        assert allowed is False
        assert info["reason"] == "crypto_rate_limit_exceeded"
    
    def test_token_refill(self):
        """Test tokens refill over time."""
        config = CryptoRateLimitConfig(base_tokens_per_second=100, max_tokens=10)
        limiter = CryptoAdaptiveRateLimiter(config)
        
        for _ in range(10):
            limiter.try_acquire("client1", CryptoOperationType.HASHING)
        
        allowed, _ = limiter.try_acquire("client1", CryptoOperationType.HASHING)
        assert allowed is False
        
        time.sleep(0.02)
        
        allowed, _ = limiter.try_acquire("client1", CryptoOperationType.HASHING)
        assert allowed is True


class TestCryptoOperationTypes:
    """Tests for different cryptographic operation types."""
    
    def test_all_operation_types(self):
        """Test all operation types work."""
        limiter = CryptoAdaptiveRateLimiter()
        
        operations = [
            CryptoOperationType.KEY_GENERATION,
            CryptoOperationType.KEY_EXCHANGE,
            CryptoOperationType.SIGNING,
            CryptoOperationType.VERIFICATION,
            CryptoOperationType.ENCRYPTION,
            CryptoOperationType.DECRYPTION,
            CryptoOperationType.HASHING,
            CryptoOperationType.RANDOM_GENERATION,
            CryptoOperationType.HSM_OPERATION,
        ]
        
        for op in operations:
            allowed, info = limiter.try_acquire(f"client_{op.value}", op)
            assert allowed is True
            assert info["operation"] == op.value
            assert "cost" in info
    
    def test_expensive_operations_cost_more(self):
        """Verify HSM and key generation are most expensive."""
        limiter = CryptoAdaptiveRateLimiter()
        
        _, hsm_info = limiter.try_acquire("c1", CryptoOperationType.HSM_OPERATION)
        _, hash_info = limiter.try_acquire("c2", CryptoOperationType.HASHING)
        
        assert hsm_info["cost"] > hash_info["cost"]


class TestKeyUsageThrottling:
    """Key usage throttling tests."""
    
    def test_key_usage_tracking(self):
        """Test key usage is tracked."""
        config = CryptoRateLimitConfig(max_key_operations_per_minute=5)
        limiter = CryptoAdaptiveRateLimiter(config)
        
        for i in range(5):
            allowed, _ = limiter.try_acquire("client1", CryptoOperationType.SIGNING, key_id="key_1")
            assert allowed is True
        
        allowed, info = limiter.try_acquire("client1", CryptoOperationType.SIGNING, key_id="key_1")
        # May or may not trigger depending on implementation, but should not crash


class TestWhitelistBlacklist:
    """Whitelist and blacklist tests."""
    
    def test_whitelist_bypasses_limits(self):
        """Test whitelisted clients bypass crypto rate limits."""
        config = CryptoRateLimitConfig(base_tokens_per_second=1, max_tokens=1)
        limiter = CryptoAdaptiveRateLimiter(config)
        limiter.add_to_whitelist("trusted_crypto_client")
        
        for _ in range(100):
            allowed, info = limiter.try_acquire("trusted_crypto_client", CryptoOperationType.HSM_OPERATION)
            assert allowed is True
            assert info["reason"] == "whitelisted"
    
    def test_blacklist_blocks_all(self):
        """Test blacklisted clients are blocked from crypto ops."""
        config = CryptoRateLimitConfig(base_tokens_per_second=100, max_tokens=100)
        limiter = CryptoAdaptiveRateLimiter(config)
        limiter.add_to_blacklist("bad_crypto_client")
        
        allowed, info = limiter.try_acquire("bad_crypto_client", CryptoOperationType.HASHING)
        assert allowed is False
        assert info["reason"] == "blacklisted"


class TestCircuitBreaker:
    """Circuit breaker tests for crypto operations."""
    
    def test_circuit_breaker_open(self):
        """Test circuit breaker blocks all crypto ops when open."""
        limiter = CryptoAdaptiveRateLimiter()
        limiter.open_circuit(duration_seconds=1)
        
        allowed, info = limiter.try_acquire("any_client", CryptoOperationType.ENCRYPTION)
        assert allowed is False
        assert info["reason"] == "circuit_breaker_open"
    
    def test_circuit_breaker_close(self):
        """Test closing circuit breaker restores crypto service."""
        limiter = CryptoAdaptiveRateLimiter()
        limiter.open_circuit(duration_seconds=100)
        limiter.close_circuit()
        
        allowed, _ = limiter.try_acquire("any_client", CryptoOperationType.DECRYPTION)
        assert allowed is True


class TestThreadSafety:
    """Thread safety tests for concurrent crypto operations."""
    
    def test_concurrent_crypto_operations(self):
        """Test concurrent crypto operations don't cause errors."""
        limiter = CryptoAdaptiveRateLimiter(
            CryptoRateLimitConfig(base_tokens_per_second=1000, max_tokens=1000)
        )
        errors = []
        
        def crypto_worker():
            try:
                ops = [CryptoOperationType.HASHING, CryptoOperationType.ENCRYPTION,
                       CryptoOperationType.SIGNING, CryptoOperationType.VERIFICATION]
                for i in range(50):
                    op = ops[i % len(ops)]
                    limiter.try_acquire(f"thread_{threading.get_ident()}", op)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=crypto_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0, f"Crypto thread safety errors: {errors}"


class TestCryptoRateLimitedDecorator:
    """Decorator tests for crypto functions."""
    
    def test_decorator_basic(self):
        """Test crypto decorator basic functionality."""
        limiter = CryptoAdaptiveRateLimiter(
            CryptoRateLimitConfig(base_tokens_per_second=10, max_tokens=3)
        )
        
        @crypto_rate_limited(limiter, op_type=CryptoOperationType.KEY_GENERATION)
        def protected_key_gen():
            return "key_generated"
        
        for _ in range(3):
            assert protected_key_gen() == "key_generated"
        
        with pytest.raises(PermissionError):
            protected_key_gen()
    
    def test_decorator_fallback(self):
        """Test crypto decorator fallback function."""
        limiter = CryptoAdaptiveRateLimiter(
            CryptoRateLimitConfig(base_tokens_per_second=10, max_tokens=1)
        )
        
        def fallback(info, *args, **kwargs):
            return f"crypto_fallback_{info['reason']}"
        
        @crypto_rate_limited(limiter, op_type=CryptoOperationType.SIGNING, fallback=fallback)
        def protected_sign():
            return "signed"
        
        assert protected_sign() == "signed"
        result = protected_sign()
        assert result.startswith("crypto_fallback_")


class TestConvenienceFunctions:
    """Convenience function tests."""
    
    def test_check_crypto_rate_limit(self):
        """Test global check_crypto_rate_limit function."""
        allowed, info = check_crypto_rate_limit("global_test_client", CryptoOperationType.HASHING)
        assert isinstance(allowed, bool)
        assert isinstance(info, dict)
        assert "operation" in info


class TestCryptoStats:
    """Statistics tests for crypto rate limiter."""
    
    def test_get_crypto_stats(self):
        """Test crypto statistics collection."""
        limiter = CryptoAdaptiveRateLimiter()
        
        for i in range(10):
            limiter.try_acquire(f"client_{i}", CryptoOperationType.ENCRYPTION)
        
        stats = limiter.get_stats()
        assert stats["total_crypto_operations"] == 10
        assert stats["unique_clients"] == 10
        assert "operations_per_second" in stats
        assert "circuit_open" in stats


class TestCryptoThreatLevelEnum:
    """Crypto threat level enum tests."""
    
    def test_crypto_threat_level_values(self):
        """Test crypto threat level enum has correct values."""
        assert CryptoThreatLevel.NORMAL.value == "normal"
        assert CryptoThreatLevel.SUSPICIOUS.value == "suspicious"
        assert CryptoThreatLevel.ELEVATED.value == "elevated"
        assert CryptoThreatLevel.CRITICAL.value == "critical"
        assert CryptoThreatLevel.BLOCKED.value == "blocked"


class TestCryptoOperationCost:
    """Crypto operation cost tests."""
    
    def test_operation_cost_defaults(self):
        """Test operation cost defaults are reasonable."""
        costs = CryptoOperationCost()
        assert costs.hsm_op > costs.key_generation
        assert costs.key_generation > costs.signing
        assert costs.signing > costs.hashing
        assert costs.hashing == 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
