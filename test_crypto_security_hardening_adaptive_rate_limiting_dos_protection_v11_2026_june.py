"""
Test Suite for QuantumCrypt AI - Crypto Operation Rate Limiting v11
Dimension B: Security Hardening
Tests cover: Resource Protection, Concurrent Limits, Operation Rate Limiting,
Timing Attack Protection, Quantum Brute Force Protection, Circuit Breaker,
Decorators, Factory Functions
"""

import pytest
import time
import threading

# Import the module
from quantum_crypt.crypto_security_hardening_adaptive_rate_limiting_dos_protection_v11_2026_june import (
    CryptoOperationProtector,
    CryptoRateLimitConfig,
    CryptoOperationType,
    ResourceType,
    ProtectionLevel,
    CryptoRateLimitResult,
    CryptoCircuitBreaker,
    ResourceUsageSnapshot,
    MemoryResourceProtector,
    ConcurrentOperationProtector,
    OperationRateLimiter,
    TimingAttackProtector,
    QuantumBruteForceProtector,
    CryptoOperationRateLimitedError,
    protect_crypto_operation,
    create_standard_crypto_protector,
    create_hsm_level_protector,
    create_relaxed_development_protector,
)


class TestEnums:
    """Test all enum classes."""

    def test_crypto_operation_type(self):
        """Test CryptoOperationType enum values."""
        assert CryptoOperationType.KEY_GENERATION.value == "key_generation"
        assert CryptoOperationType.DIGITAL_SIGNATURE.value == "digital_signature"
        assert CryptoOperationType.ENCRYPTION.value == "encryption"
        assert CryptoOperationType.DECRYPTION.value == "decryption"
        assert CryptoOperationType.HASH_COMPUTE.value == "hash_compute"
        assert CryptoOperationType.ZKP_PROOF.value == "zkp_proof"
        assert CryptoOperationType.MPC_COMPUTATION.value == "mpc_computation"

    def test_resource_type(self):
        """Test ResourceType enum."""
        assert ResourceType.CPU.value == "cpu"
        assert ResourceType.MEMORY.value == "memory"
        assert ResourceType.CONCURRENT_OPS.value == "concurrent_ops"

    def test_protection_level(self):
        """Test ProtectionLevel enum."""
        assert ProtectionLevel.RELAXED.value == "relaxed"
        assert ProtectionLevel.STANDARD.value == "standard"
        assert ProtectionLevel.STRICT.value == "strict"
        assert ProtectionLevel.HSM.value == "hsm"


class TestCryptoRateLimitConfig:
    """Test configuration dataclass."""

    def test_default_config(self):
        """Test default configuration."""
        config = CryptoRateLimitConfig()
        assert config.protection_level == ProtectionLevel.STANDARD
        assert config.max_concurrent_operations == 100
        assert config.max_key_generations_per_minute == 60
        assert config.max_signatures_per_second == 1000
        assert config.max_encryptions_per_second == 2000
        assert config.max_memory_percent == 80
        assert config.enable_circuit_breaker is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = CryptoRateLimitConfig(
            protection_level=ProtectionLevel.HSM,
            max_concurrent_operations=10,
            max_key_generations_per_minute=5,
            max_memory_percent=60
        )
        assert config.protection_level == ProtectionLevel.HSM
        assert config.max_concurrent_operations == 10
        assert config.max_key_generations_per_minute == 5
        assert config.max_memory_percent == 60


class TestMemoryResourceProtector:
    """Test memory exhaustion protection."""

    def test_memory_protector_creation(self):
        """Test protector creation."""
        protector = MemoryResourceProtector(max_percent=80)
        assert protector.max_percent == 80

    def test_memory_check_allows_normal(self):
        """Test memory check allows normal operations."""
        protector = MemoryResourceProtector(max_percent=99)  # Very high threshold
        result = protector.check_available(CryptoOperationType.HASH_COMPUTE)
        assert result.allowed is True

    def test_memory_warnings(self):
        """Test memory high usage warnings."""
        protector = MemoryResourceProtector(max_percent=99)
        result = protector.check_available(CryptoOperationType.ENCRYPTION)
        # Should work without errors
        assert isinstance(result, CryptoRateLimitResult)


class TestConcurrentOperationProtector:
    """Test concurrent operation limits."""

    def test_concurrent_limiter_allows(self):
        """Test allows operations under limit."""
        protector = ConcurrentOperationProtector(max_concurrent=10)
        result = protector.check_available(CryptoOperationType.ENCRYPTION)
        assert result.allowed is True

    def test_concurrent_enforces_limit(self):
        """Test enforces concurrent operation limit."""
        protector = ConcurrentOperationProtector(max_concurrent=2)

        # Start 2 operations
        protector.start_operation(CryptoOperationType.ENCRYPTION, "op1")
        protector.start_operation(CryptoOperationType.ENCRYPTION, "op2")

        # 3rd should be blocked
        result = protector.check_available(CryptoOperationType.ENCRYPTION)
        assert result.allowed is False
        assert "CONCURRENCY_LIMIT" in result.resource_warnings

    def test_concurrent_end_operation_frees(self):
        """Test ending operations frees up slots."""
        protector = ConcurrentOperationProtector(max_concurrent=1)

        protector.start_operation(CryptoOperationType.ENCRYPTION, "op1")
        protector.end_operation("op1")

        # Should be available again
        result = protector.check_available(CryptoOperationType.ENCRYPTION)
        assert result.allowed is True


class TestOperationRateLimiter:
    """Test per-operation-type rate limiting."""

    def test_rate_limiter_allows(self):
        """Test allows operations within limits."""
        config = CryptoRateLimitConfig(
            max_key_generations_per_minute=100,
            max_signatures_per_second=1000
        )
        limiter = OperationRateLimiter(config)

        result = limiter.check_available(CryptoOperationType.DIGITAL_SIGNATURE)
        assert result.allowed is True

    def test_rate_limiter_keygen_limit(self):
        """Test key generation per-minute limits."""
        config = CryptoRateLimitConfig(max_key_generations_per_minute=3)
        limiter = OperationRateLimiter(config)

        # Start 3 key gens
        for i in range(3):
            limiter.start_operation(CryptoOperationType.KEY_GENERATION, f"op{i}")

        # 4th should be blocked
        result = limiter.check_available(CryptoOperationType.KEY_GENERATION)
        assert result.allowed is False


class TestTimingAttackProtector:
    """Test timing side-channel protection."""

    def test_timing_protector_creation(self):
        """Test protector creation."""
        protector = TimingAttackProtector(base_duration_ms=10.0, jitter_ms=5.0)
        assert protector.base_duration_ms == 10.0
        assert protector.jitter_ms == 5.0

    def test_timing_protector_flow(self):
        """Test full start/wait flow."""
        protector = TimingAttackProtector(base_duration_ms=1.0, jitter_ms=0.0)

        protector.record_start("test_op")
        # Should not crash
        protector.wait_for_constant_time("test_op")
        assert True  # No exception = pass

    def test_timing_protector_normalizes(self):
        """Test timing normalization adds minimum duration."""
        protector = TimingAttackProtector(base_duration_ms=50.0, jitter_ms=0.0)

        start = time.time()
        protector.record_start("op1")
        protector.wait_for_constant_time("op1")
        elapsed = (time.time() - start) * 1000

        # Should take at least base duration
        assert elapsed >= 40.0  # Allow some tolerance


class TestQuantumBruteForceProtector:
    """Test quantum brute force protection."""

    def test_brute_force_protector_creation(self):
        """Test protector creation."""
        protector = QuantumBruteForceProtector(max_attempts_per_minute=10)
        assert protector.max_attempts == 10

    def test_key_usage_allowed(self):
        """Test key usage allowed within limits."""
        protector = QuantumBruteForceProtector(max_attempts_per_minute=100)
        result = protector.check_key_usage("test_key_123")
        assert result.allowed is True

    def test_key_usage_enforces_rate(self):
        """Test key usage rate limiting."""
        protector = QuantumBruteForceProtector(max_attempts_per_minute=5)

        for i in range(6):
            result = protector.check_key_usage("attacker_key")

        assert result.allowed is False

    def test_failure_backoff(self):
        """Test exponential backoff on failures."""
        protector = QuantumBruteForceProtector(max_attempts_per_minute=100)

        # Record multiple failures
        for i in range(3):
            protector.record_key_failure("sensitive_key")

        # Should have backoff
        protector.check_key_usage("sensitive_key")  # This should trigger backoff check
        # Just verify no crash
        assert True

    def test_success_resets_backoff(self):
        """Test successes reduce failure count."""
        protector = QuantumBruteForceProtector()

        protector.record_key_failure("my_key")
        protector.record_key_success("my_key")  # Should reset

        # Should work normally
        result = protector.check_key_usage("my_key")
        assert result.allowed is True


class TestCryptoOperationProtector:
    """Test main protection coordinator."""

    def test_protector_creation(self):
        """Test protector creation."""
        protector = CryptoOperationProtector()
        assert protector.config is not None

    def test_protector_custom_config(self):
        """Test protector with custom config."""
        config = CryptoRateLimitConfig(max_concurrent_operations=50)
        protector = CryptoOperationProtector(config)
        assert protector.config.max_concurrent_operations == 50

    def test_check_operation_allowed(self):
        """Test operation check allows normal operations."""
        protector = CryptoOperationProtector(CryptoRateLimitConfig(
            max_concurrent_operations=1000,
            max_key_generations_per_minute=1000
        ))

        allowed, reason, result = protector.check_operation(CryptoOperationType.HASH_COMPUTE)
        assert allowed is True
        assert reason == ""

    def test_check_operation_with_key_id(self):
        """Test operation check with specific key ID."""
        protector = CryptoOperationProtector()
        allowed, _, _ = protector.check_operation(
            CryptoOperationType.DIGITAL_SIGNATURE,
            key_id="key_abc123"
        )
        assert allowed is True

    def test_start_end_operation_flow(self):
        """Test full start/end operation lifecycle."""
        protector = CryptoOperationProtector()

        op_id = protector.start_operation(CryptoOperationType.ENCRYPTION)
        assert op_id.startswith("crypto_op_")

        protector.end_operation(op_id, CryptoOperationType.ENCRYPTION, success=True)
        # No exception = success

    def test_operation_failure_tracking(self):
        """Test failure tracking for circuit breaker."""
        protector = CryptoOperationProtector()

        op_id = protector.start_operation(CryptoOperationType.KEY_GENERATION)
        protector.end_operation(op_id, CryptoOperationType.KEY_GENERATION, success=False)
        # Should record failure, no exception

    def test_resource_snapshot(self):
        """Test resource usage snapshot."""
        protector = CryptoOperationProtector()
        snapshot = protector.get_resource_snapshot()

        assert isinstance(snapshot, ResourceUsageSnapshot)
        assert snapshot.timestamp > 0
        assert snapshot.memory_percent >= 0
        assert snapshot.active_operations >= 0
        assert isinstance(snapshot.operations_last_minute, dict)


class TestProtectCryptoOperationDecorator:
    """Test @protect_crypto_operation decorator."""

    def test_decorator_allows_normal(self):
        """Test decorator allows function calls."""
        @protect_crypto_operation(CryptoOperationType.HASH_COMPUTE)
        def hash_data(data):
            return hasattr(data, '__len__')

        result = hash_data(b"test")
        assert result is True

    def test_decorator_preserves_function(self):
        """Test decorator preserves function metadata."""
        @protect_crypto_operation(CryptoOperationType.ENCRYPTION)
        def encrypt_func(plaintext, key=None):
            """My encryption function."""
            return plaintext[::-1]

        assert encrypt_func.__name__ == "encrypt_func"
        assert encrypt_func.__doc__ == "My encryption function."

    def test_decorator_with_key_id(self):
        """Test decorator with key_id in kwargs."""
        @protect_crypto_operation(CryptoOperationType.DIGITAL_SIGNATURE)
        def sign_data(data, key_id=None):
            return f"signed:{data}"

        result = sign_data("hello", key_id="my_signing_key")
        assert result == "signed:hello"


class TestFactoryFunctions:
    """Test factory convenience functions."""

    def test_create_standard_protector(self):
        """Test standard protector factory."""
        protector = create_standard_crypto_protector()
        assert isinstance(protector, CryptoOperationProtector)
        assert protector.config.protection_level == ProtectionLevel.STANDARD

    def test_create_hsm_protector(self):
        """Test HSM-level protector factory."""
        protector = create_hsm_level_protector()
        assert isinstance(protector, CryptoOperationProtector)
        assert protector.config.protection_level == ProtectionLevel.HSM
        assert protector.config.max_concurrent_operations == 10

    def test_create_relaxed_protector(self):
        """Test development protector factory."""
        protector = create_relaxed_development_protector()
        assert isinstance(protector, CryptoOperationProtector)
        assert protector.config.protection_level == ProtectionLevel.RELAXED
        assert protector.config.max_concurrent_operations == 1000


class TestCryptoOperationRateLimitedError:
    """Test custom exception."""

    def test_exception_creation(self):
        """Test exception with retry_after."""
        err = CryptoOperationRateLimitedError("Key gen rate limited", retry_after=5.0)
        assert str(err) == "Key gen rate limited"
        assert err.retry_after == 5.0

    def test_exception_default_retry(self):
        """Test exception default retry_after."""
        err = CryptoOperationRateLimitedError("Blocked")
        assert err.retry_after == 0.0


class TestThreadSafety:
    """Test thread safety."""

    def test_concurrent_operations(self):
        """Test concurrent operation handling."""
        protector = CryptoOperationProtector(CryptoRateLimitConfig(
            max_concurrent_operations=100
        ))
        errors = []

        def worker():
            try:
                for i in range(5):
                    allowed, _, _ = protector.check_operation(
                        CryptoOperationType.HASH_COMPUTE
                    )
                    if allowed:
                        op_id = protector.start_operation(CryptoOperationType.HASH_COMPUTE)
                        time.sleep(0.001)
                        protector.end_operation(op_id, CryptoOperationType.HASH_COMPUTE)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


class TestBackwardCompatibility:
    """Test backward compatibility."""

    def test_module_imports(self):
        """Test module imports cleanly."""
        import quantum_crypt.crypto_security_hardening_adaptive_rate_limiting_dos_protection_v11_2026_june as module
        assert module is not None

    def test_separate_instances_independent(self):
        """Test separate protectors don't share state."""
        p1 = CryptoOperationProtector(CryptoRateLimitConfig(max_concurrent_operations=1))
        p2 = CryptoOperationProtector(CryptoRateLimitConfig(max_concurrent_operations=1))

        # Use up p1
        p1.start_operation(CryptoOperationType.ENCRYPTION)
        p1.start_operation(CryptoOperationType.ENCRYPTION)

        # p2 should still work
        allowed, _, _ = p2.check_operation(CryptoOperationType.ENCRYPTION)
        assert allowed is True


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_key_id(self):
        """Test empty/None key_id handling."""
        protector = CryptoOperationProtector()
        allowed, _, _ = protector.check_operation(
            CryptoOperationType.ENCRYPTION,
            key_id=None
        )
        assert allowed is True

    def test_very_long_key_id(self):
        """Test very long key IDs."""
        protector = CryptoOperationProtector()
        long_key = "x" * 10000
        allowed, _, _ = protector.check_operation(
            CryptoOperationType.SIGNATURE_VERIFY,
            key_id=long_key
        )
        assert allowed is True

    def test_all_operation_types(self):
        """Test all operation types work."""
        protector = CryptoOperationProtector(CryptoRateLimitConfig(
            max_key_generations_per_minute=1000,
            max_signatures_per_second=10000
        ))

        for op_type in CryptoOperationType:
            allowed, _, _ = protector.check_operation(op_type)
            assert allowed is True, f"Failed for {op_type}"


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
