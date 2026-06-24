"""
Comprehensive Test Suite - QuantumCrypt AI Observability V17
Dimension D: Observability & Instrumentation

Tests all crypto-specific observability features:
1. Crypto Operation Classification
2. Crypto Baggage Context Propagation
3. Crypto-Specific Metrics (per algorithm, key size, operation type)
4. Crypto Operation Timer (nanosecond precision)
5. Entropy Monitoring & Quality Assessment
6. Crypto Health Checks (entropy, HSM, algorithm health)
7. Crypto Audit Logging & Compliance Trail
8. Crypto Instrumentation Decorator
9. Global Enable/Disable Controls
"""

import pytest
import time
import json
import threading
from typing import Dict, Any

# Import the crypto observability module
from quantum_crypt.crypto_observability_enhanced_crypto_telemetry_v17_2026_june import (
    # Operation Classification
    CryptoOperationType,
    CryptoAlgorithm,
    CryptoSecurityLevel,
    
    # Context & Baggage
    CryptoBaggageKey,
    CryptoBaggageContext,
    
    # Metrics
    CryptoOperationStats,
    CryptoMetricsRegistry,
    get_default_crypto_registry,
    
    # Timing
    CryptoOperationTimer,
    
    # Entropy Monitoring
    EntropyMonitor,
    get_entropy_monitor,
    
    # Health Checks
    CryptoHealthStatus,
    CryptoHealthResult,
    CryptoHealthChecker,
    get_crypto_health_checker,
    
    # Logging & Audit
    CryptoLogLevel,
    CryptoLogEntry,
    CryptoAuditLogger,
    get_audit_logger,
    
    # Decorators
    crypto_instrumented,
    
    # Export & Control
    export_crypto_metrics_json,
    export_crypto_health_json,
    export_audit_trail_json,
    disable_crypto_instrumentation,
    enable_crypto_instrumentation,
)


# -----------------------------------------------------------------------------
# Test Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def clean_crypto_baggage():
    """Fixture to ensure clean crypto baggage context."""
    CryptoBaggageContext.clear()
    yield
    CryptoBaggageContext.clear()


@pytest.fixture
def fresh_crypto_registry():
    """Fixture with fresh crypto metrics registry."""
    return CryptoMetricsRegistry()


@pytest.fixture
def fresh_entropy_monitor():
    """Fixture with fresh entropy monitor."""
    return EntropyMonitor(sample_interval_seconds=0.0)


@pytest.fixture
def fresh_health_checker(fresh_crypto_registry, fresh_entropy_monitor):
    """Fixture with fresh crypto health checker."""
    return CryptoHealthChecker(fresh_crypto_registry, fresh_entropy_monitor)


@pytest.fixture
def fresh_audit_logger():
    """Fixture with fresh audit logger."""
    return CryptoAuditLogger("test_crypto")


# -----------------------------------------------------------------------------
# Crypto Operation Classification Tests
# -----------------------------------------------------------------------------

class TestCryptoOperationClassification:
    """Tests for crypto operation classification system."""
    
    def test_operation_type_enum(self):
        """Test all crypto operation types are defined."""
        # Key operations
        assert CryptoOperationType.KEY_GENERATION.value == "key_generation"
        assert CryptoOperationType.KEY_EXCHANGE.value == "key_exchange"
        assert CryptoOperationType.KEY_DERIVATION.value == "key_derivation"
        
        # Signature operations
        assert CryptoOperationType.SIGNATURE_GENERATION.value == "signature_generation"
        assert CryptoOperationType.SIGNATURE_VERIFICATION.value == "signature_verification"
        
        # Cipher operations
        assert CryptoOperationType.ENCRYPTION.value == "encryption"
        assert CryptoOperationType.DECRYPTION.value == "decryption"
        
        # Hash & MAC
        assert CryptoOperationType.HASH.value == "hash"
        assert CryptoOperationType.HMAC.value == "hmac"
        
        # Random
        assert CryptoOperationType.RANDOM_GENERATION.value == "random_generation"
        
        # Certificate
        assert CryptoOperationType.CERTIFICATE_GENERATION.value == "certificate_generation"
        assert CryptoOperationType.CERTIFICATE_VERIFICATION.value == "certificate_verification"
        
        # HSM & TLS
        assert CryptoOperationType.HSM_OPERATION.value == "hsm_operation"
        assert CryptoOperationType.TLS_HANDSHAKE.value == "tls_handshake"
        
        # Post-Quantum KEM
        assert CryptoOperationType.KEM_ENCAPSULATION.value == "kem_encapsulation"
        assert CryptoOperationType.KEM_DECAPSULATION.value == "kem_decapsulation"
    
    def test_algorithm_enum(self):
        """Test all supported algorithms."""
        # Post-Quantum
        assert CryptoAlgorithm.CRYSTALS_KYBER.value == "CRYSTALS-Kyber"
        assert CryptoAlgorithm.CRYSTALS_DILITHIUM.value == "CRYSTALS-Dilithium"
        assert CryptoAlgorithm.FALCON.value == "Falcon"
        assert CryptoAlgorithm.SPHINCS.value == "SPHINCS+"
        assert CryptoAlgorithm.NTRU.value == "NTRU"
        assert CryptoAlgorithm.BIKE.value == "BIKE"
        assert CryptoAlgorithm.HQC.value == "HQC"
        
        # Classic
        assert CryptoAlgorithm.RSA.value == "RSA"
        assert CryptoAlgorithm.ECDSA.value == "ECDSA"
        assert CryptoAlgorithm.ECDH.value == "ECDH"
        assert CryptoAlgorithm.AES.value == "AES"
        assert CryptoAlgorithm.SHA2.value == "SHA-2"
        assert CryptoAlgorithm.SHA3.value == "SHA-3"
        assert CryptoAlgorithm.CHACHA20.value == "ChaCha20"
        
        # Hybrid
        assert CryptoAlgorithm.HYBRID_CLASSIC_PQ.value == "Hybrid_Classic_PQ"
    
    def test_security_level_enum(self):
        """Test NIST security levels."""
        assert CryptoSecurityLevel.LEVEL_1.value == 1
        assert CryptoSecurityLevel.LEVEL_2.value == 2
        assert CryptoSecurityLevel.LEVEL_3.value == 3
        assert CryptoSecurityLevel.LEVEL_4.value == 4
        assert CryptoSecurityLevel.LEVEL_5.value == 5


# -----------------------------------------------------------------------------
# Crypto Baggage Context Tests
# -----------------------------------------------------------------------------

class TestCryptoBaggageContext:
    """Tests for crypto baggage context propagation."""
    
    def test_set_and_get(self, clean_crypto_baggage):
        """Test basic set/get operations."""
        token = CryptoBaggageContext.set(CryptoBaggageKey.ALGORITHM.value, "CRYSTALS-Kyber")
        assert CryptoBaggageContext.get(CryptoBaggageKey.ALGORITHM.value) == "CRYSTALS-Kyber"
        CryptoBaggageContext.reset(token)
    
    def test_generate_operation_id(self, clean_crypto_baggage):
        """Test crypto operation ID generation."""
        op_id = CryptoBaggageContext.generate_operation_id()
        assert op_id.startswith("crypto_op_")
        assert len(op_id) > 10
        assert CryptoBaggageContext.get(CryptoBaggageKey.OPERATION_ID.value) == op_id
    
    def test_set_bulk_context(self, clean_crypto_baggage):
        """Test bulk context setting."""
        token = CryptoBaggageContext.set_bulk({
            CryptoBaggageKey.OPERATION_TYPE.value: "key_generation",
            CryptoBaggageKey.ALGORITHM.value: "RSA",
            CryptoBaggageKey.KEY_SIZE_BITS.value: 4096,
        })
        
        assert CryptoBaggageContext.get(CryptoBaggageKey.OPERATION_TYPE.value) == "key_generation"
        assert CryptoBaggageContext.get(CryptoBaggageKey.ALGORITHM.value) == "RSA"
        assert CryptoBaggageContext.get(CryptoBaggageKey.KEY_SIZE_BITS.value) == 4096
        
        CryptoBaggageContext.reset(token)
    
    def test_get_all_context(self, clean_crypto_baggage):
        """Test getting all context items."""
        CryptoBaggageContext.set("test1", "value1")
        CryptoBaggageContext.set("test2", "value2")
        all_items = CryptoBaggageContext.get_all()
        assert "test1" in all_items
        assert "test2" in all_items
    
    def test_thread_context_isolation(self, clean_crypto_baggage):
        """Test that context is properly isolated between threads."""
        results: Dict[str, str] = {}
        
        def thread_func(tid: str):
            CryptoBaggageContext.set(f"thread_{tid}", f"value_{tid}")
            time.sleep(0.01)
            results[tid] = CryptoBaggageContext.get(f"thread_{tid}", "not_found")
        
        threads = []
        for i in range(3):
            t = threading.Thread(target=thread_func, args=(str(i),))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        for i in range(3):
            assert results[str(i)] == f"value_{i}"


# -----------------------------------------------------------------------------
# Crypto Metrics Tests
# -----------------------------------------------------------------------------

class TestCryptoMetrics:
    """Tests for crypto-specific metrics collection."""
    
    def test_operation_stats_record(self):
        """Test crypto operation stats recording."""
        stats = CryptoOperationStats()
        
        stats.record(duration_ns=1_000_000, key_size=2048)
        stats.record(duration_ns=2_000_000, key_size=4096)
        stats.record(duration_ns=500_000, key_size=2048, error=True)
        
        assert stats.count == 3
        assert stats.error_count == 1
        assert stats.key_sizes[2048] == 2
        assert stats.key_sizes[4096] == 1
        assert stats.get_avg_time_ms() == pytest.approx(1.166, rel=0.01)
    
    def test_operation_stats_to_dict(self):
        """Test operation stats serialization."""
        stats = CryptoOperationStats()
        stats.record(duration_ns=1_000_000)
        
        d = stats.to_dict()
        assert "count" in d
        assert "avg_time_ms" in d
        assert "error_count" in d
        assert "error_rate" in d
    
    def test_record_key_generation(self, fresh_crypto_registry):
        """Test recording key generation operation."""
        fresh_crypto_registry.record_operation(
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.CRYSTALS_KYBER,
            duration_ns=10_000_000,
            key_size_bits=1536,
            uses_hsm=False,
            error=False,
        )
        
        stats = fresh_crypto_registry.get_operation_stats(CryptoOperationType.KEY_GENERATION)
        assert stats.count == 1
        
        alg_stats = fresh_crypto_registry.get_algorithm_stats(CryptoAlgorithm.CRYSTALS_KYBER)
        assert alg_stats.count == 1
    
    def test_record_signature_operation(self, fresh_crypto_registry):
        """Test recording signature operation."""
        fresh_crypto_registry.record_operation(
            operation_type=CryptoOperationType.SIGNATURE_GENERATION,
            algorithm=CryptoAlgorithm.CRYSTALS_DILITHIUM,
            duration_ns=5_000_000,
            key_size_bits=2048,
            uses_hsm=True,
        )
        
        hsm_stats = fresh_crypto_registry.get_hsm_stats()
        assert hsm_stats.count == 1
    
    def test_record_error_operation(self, fresh_crypto_registry):
        """Test recording failed operation."""
        fresh_crypto_registry.record_operation(
            operation_type=CryptoOperationType.DECRYPTION,
            algorithm=CryptoAlgorithm.AES,
            duration_ns=100_000,
            error=True,
        )
        
        summary = fresh_crypto_registry.get_all_metrics()["summary"]
        assert summary["total_errors"] == 1
        assert summary["error_rate"] == 1.0
    
    def test_entropy_sample_recording(self, fresh_crypto_registry):
        """Test entropy sample recording."""
        fresh_crypto_registry.record_entropy_sample(7.8, "system_csprng")
        fresh_crypto_registry.record_entropy_sample(7.9, "system_csprng")
        
        summary = fresh_crypto_registry.get_entropy_summary()
        assert summary["samples"] == 2
        assert summary["avg_entropy"] == pytest.approx(7.85)
    
    def test_get_all_metrics(self, fresh_crypto_registry):
        """Test complete metrics snapshot."""
        fresh_crypto_registry.record_operation(
            CryptoOperationType.HASH,
            CryptoAlgorithm.SHA3,
            duration_ns=100_000,
        )
        
        metrics = fresh_crypto_registry.get_all_metrics()
        assert "summary" in metrics
        assert "by_operation" in metrics
        assert "by_algorithm" in metrics
        assert "hsm" in metrics
        assert "entropy" in metrics
    
    def test_default_registry_singleton(self):
        """Test default registry singleton pattern."""
        r1 = get_default_crypto_registry()
        r2 = get_default_crypto_registry()
        assert r1 is r2


# -----------------------------------------------------------------------------
# Crypto Operation Timer Tests
# -----------------------------------------------------------------------------

class TestCryptoOperationTimer:
    """Tests for high-precision crypto operation timer."""
    
    def test_timer_context_manager(self, fresh_crypto_registry):
        """Test timer as context manager."""
        with CryptoOperationTimer(
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.RSA,
            key_size_bits=4096,
            registry=fresh_crypto_registry,
        ):
            time.sleep(0.001)
        
        stats = fresh_crypto_registry.get_operation_stats(CryptoOperationType.KEY_GENERATION)
        assert stats.count == 1
        assert stats.min_time_ns > 0
    
    def test_timer_with_hsm_flag(self, fresh_crypto_registry):
        """Test timer with HSM operation flag."""
        with CryptoOperationTimer(
            operation_type=CryptoOperationType.HSM_OPERATION,
            algorithm=CryptoAlgorithm.AES,
            uses_hsm=True,
            registry=fresh_crypto_registry,
        ):
            pass
        
        hsm_stats = fresh_crypto_registry.get_hsm_stats()
        assert hsm_stats.count == 1
    
    def test_timer_exception_recording(self, fresh_crypto_registry):
        """Test that exceptions are properly recorded."""
        with pytest.raises(ValueError, match="Test error"):
            with CryptoOperationTimer(
                operation_type=CryptoOperationType.DECRYPTION,
                algorithm=CryptoAlgorithm.AES,
                registry=fresh_crypto_registry,
            ):
                raise ValueError("Test error")
        
        stats = fresh_crypto_registry.get_operation_stats(CryptoOperationType.DECRYPTION)
        assert stats.count == 1
        assert stats.error_count == 1


# -----------------------------------------------------------------------------
# Entropy Monitor Tests
# -----------------------------------------------------------------------------

class TestEntropyMonitor:
    """Tests for entropy quality monitoring."""
    
    def test_shannon_entropy_calculation(self):
        """Test Shannon entropy calculation."""
        # Uniform random data should have high entropy
        import os
        sample = os.urandom(256)
        entropy = EntropyMonitor._calculate_shannon_entropy(sample)
        # Good random data should be > 7.5 bits/byte
        assert entropy > 7.0
    
    def test_entropy_sampling(self, fresh_entropy_monitor):
        """Test entropy sampling."""
        entropy = fresh_entropy_monitor.sample_entropy(sample_size=64)
        assert entropy >= 0.0
        assert entropy <= 8.0  # Max theoretical entropy
    
    def test_get_current_entropy_estimate(self, fresh_entropy_monitor):
        """Test getting entropy estimate."""
        fresh_entropy_monitor.sample_entropy(sample_size=64)
        estimate = fresh_entropy_monitor.get_current_entropy_estimate()
        assert estimate >= 0.0
    
    def test_entropy_sufficiency_check(self, fresh_entropy_monitor):
        """Test entropy sufficiency check."""
        # After sampling, should have sufficient entropy
        fresh_entropy_monitor.sample_entropy(sample_size=256)
        is_sufficient = fresh_entropy_monitor.is_entropy_sufficient(min_bits=6.0)
        assert is_sufficient is True
    
    def test_default_entropy_monitor_singleton(self):
        """Test default entropy monitor singleton."""
        m1 = get_entropy_monitor()
        m2 = get_entropy_monitor()
        assert m1 is m2


# -----------------------------------------------------------------------------
# Crypto Health Check Tests
# -----------------------------------------------------------------------------

class TestCryptoHealthChecks:
    """Tests for crypto health assessment system."""
    
    def test_health_status_enum(self):
        """Test crypto health status values."""
        assert CryptoHealthStatus.SECURE.value == "secure"
        assert CryptoHealthStatus.DEGRADED.value == "degraded"
        assert CryptoHealthStatus.AT_RISK.value == "at_risk"
        assert CryptoHealthStatus.FAILED.value == "failed"
    
    def test_hsm_availability_setting(self, fresh_health_checker):
        """Test HSM availability setting."""
        fresh_health_checker.set_hsm_available(True)
        assert fresh_health_checker._hsm_available is True
        
        fresh_health_checker.set_hsm_available(False)
        assert fresh_health_checker._hsm_available is False
    
    def test_health_assessment_basic(self, fresh_health_checker):
        """Test basic health assessment."""
        result = fresh_health_checker.assess_health()
        
        assert result.overall_status in [CryptoHealthStatus.AT_RISK, 
            CryptoHealthStatus.SECURE,
            CryptoHealthStatus.DEGRADED,
        ]
        assert result.entropy_bits > 0.0
        assert result.timestamp is not None
    
    def test_health_result_serialization(self, fresh_health_checker):
        """Test health result serialization."""
        result = fresh_health_checker.assess_health()
        d = result.to_dict()
        
        assert "overall_status" in d
        assert "entropy" in d
        assert "hsm_available" in d
        assert "algorithm_health" in d
        assert "recommendations" in d
    
    def test_default_health_checker_singleton(self):
        """Test default health checker singleton."""
        hc1 = get_crypto_health_checker()
        hc2 = get_crypto_health_checker()
        assert hc1 is hc2


# -----------------------------------------------------------------------------
# Crypto Audit Logging Tests
# -----------------------------------------------------------------------------

class TestCryptoAuditLogging:
    """Tests for crypto audit logging system."""
    
    def test_audit_logging(self, fresh_audit_logger):
        """Test audit level logging."""
        entry = fresh_audit_logger.audit(
            "Key generation completed",
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.CRYSTALS_KYBER,
        )
        
        assert entry.level == "AUDIT"
        assert entry.operation_type == "key_generation"
        assert entry.algorithm == "CRYSTALS-Kyber"
        assert entry.success is True
    
    def test_security_logging(self, fresh_audit_logger):
        """Test security event logging."""
        entry = fresh_audit_logger.security(
            "Unauthorized key access attempt detected",
            operation_type=CryptoOperationType.HSM_OPERATION,
        )
        
        assert entry.level == "SECURITY"
    
    def test_error_logging(self, fresh_audit_logger):
        """Test error logging."""
        entry = fresh_audit_logger.error(
            "Signature verification failed",
            error="Invalid signature format",
            operation_type=CryptoOperationType.SIGNATURE_VERIFICATION,
        )
        
        assert entry.error == "Invalid signature format"
        assert entry.success is True  # Log itself succeeded
    
    def test_log_entry_serialization(self, fresh_audit_logger):
        """Test log entry serialization."""
        entry = fresh_audit_logger.info("Test log")
        d = entry.to_dict()
        
        assert "timestamp" in d
        assert "level" in d
        assert "message" in d
        assert "success" in d
    
    def test_log_entry_json(self, fresh_audit_logger):
        """Test log entry JSON serialization."""
        entry = fresh_audit_logger.audit("Audit event")
        json_str = entry.to_json()
        parsed = json.loads(json_str)
        assert parsed["message"] == "Audit event"
    
    def test_audit_trail_retrieval(self, fresh_audit_logger):
        """Test audit trail retrieval."""
        for i in range(5):
            fresh_audit_logger.audit(f"Operation {i}")
        
        trail = fresh_audit_logger.get_audit_trail(limit=3)
        assert len(trail) == 3
    
    def test_default_audit_logger_singleton(self):
        """Test default audit logger singleton."""
        l1 = get_audit_logger()
        l2 = get_audit_logger()
        assert l1 is l2


# -----------------------------------------------------------------------------
# Crypto Instrumentation Decorator Tests
# -----------------------------------------------------------------------------

class TestCryptoInstrumentationDecorator:
    """Tests for crypto instrumentation decorator."""
    
    def test_decorator_basic_functionality(self):
        """Test basic decorator functionality."""
        @crypto_instrumented(
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.RSA,
            key_size_bits=2048,
        )
        def generate_key():
            return "keypair_123"
        
        result = generate_key()
        assert result == "keypair_123"
    
    def test_decorator_with_hsm(self):
        """Test decorator with HSM operation."""
        @crypto_instrumented(
            operation_type=CryptoOperationType.SIGNATURE_GENERATION,
            algorithm=CryptoAlgorithm.ECDSA,
            uses_hsm=True,
        )
        def hsm_sign():
            return "signature"
        
        result = hsm_sign()
        assert result == "signature"
    
    def test_decorator_exception_propagation(self):
        """Test that exceptions propagate through decorator."""
        @crypto_instrumented(
            operation_type=CryptoOperationType.DECRYPTION,
            algorithm=CryptoAlgorithm.AES,
        )
        def failing_decrypt():
            raise ValueError("Decryption failed: invalid padding")
        
        with pytest.raises(ValueError, match="invalid padding"):
            failing_decrypt()
    
    def test_decorator_metadata_preserved(self):
        """Test that function metadata is preserved."""
        @crypto_instrumented(
            operation_type=CryptoOperationType.HASH,
            algorithm=CryptoAlgorithm.SHA3,
        )
        def documented_hash(data: bytes) -> bytes:
            """Compute SHA3-256 hash."""
            return data
        
        assert documented_hash.__doc__ == "Compute SHA3-256 hash."
        assert documented_hash.__name__ == "documented_hash"
    
    def test_decorator_context_propagation(self, clean_crypto_baggage):
        """Test that decorator propagates baggage context."""
        @crypto_instrumented(
            operation_type=CryptoOperationType.KEY_EXCHANGE,
            algorithm=CryptoAlgorithm.ECDH,
        )
        def key_exchange():
            return CryptoBaggageContext.get(CryptoBaggageKey.OPERATION_ID.value)
        
        op_id = key_exchange()
        assert op_id is not None
        assert op_id.startswith("crypto_op_")


# -----------------------------------------------------------------------------
# Export & Control Tests
# -----------------------------------------------------------------------------

class TestExportAndControl:
    """Tests for export functions and global controls."""
    
    def test_export_metrics_json(self):
        """Test metrics JSON export."""
        json_str = export_crypto_metrics_json()
        parsed = json.loads(json_str)
        assert "summary" in parsed
        assert "by_operation" in parsed
    
    def test_export_health_json(self):
        """Test health status JSON export."""
        json_str = export_crypto_health_json()
        parsed = json.loads(json_str)
        assert "overall_status" in parsed
        assert "entropy" in parsed
    
    def test_export_audit_trail_json(self):
        """Test audit trail JSON export."""
        json_str = export_audit_trail_json(limit=10)
        parsed = json.loads(json_str)
        assert isinstance(parsed, list)
    
    def test_enable_disable_instrumentation(self):
        """Test global instrumentation control."""
        enable_crypto_instrumentation()
        disable_crypto_instrumentation()
        # Should not raise


# -----------------------------------------------------------------------------
# Integration Tests
# -----------------------------------------------------------------------------

class TestIntegration:
    """Integration tests for full crypto observability pipeline."""
    
    def test_full_crypto_observability_pipeline(
        self,
        clean_crypto_baggage,
        fresh_crypto_registry,
        fresh_audit_logger,
    ):
        """Test full pipeline: context -> timer -> metrics -> logging."""
        # Set context
        CryptoBaggageContext.set_bulk({
            CryptoBaggageKey.OPERATION_TYPE.value: "key_generation",
            CryptoBaggageKey.ALGORITHM.value: "CRYSTALS-Kyber",
        })
        
        # Record operation with timing
        with CryptoOperationTimer(
            CryptoOperationType.KEY_GENERATION,
            CryptoAlgorithm.CRYSTALS_KYBER,
            key_size_bits=1536,
            registry=fresh_crypto_registry,
        ):
            time.sleep(0.001)
        
        # Log audit event
        fresh_audit_logger.audit("Key generation complete")
        
        # Verify
        stats = fresh_crypto_registry.get_operation_stats(CryptoOperationType.KEY_GENERATION)
        assert stats.count == 1
    
    def test_concurrent_crypto_operations(self, fresh_crypto_registry):
        """Test instrumentation under concurrent crypto load."""
        
        def worker():
            for _ in range(10):
                with CryptoOperationTimer(
                    CryptoOperationType.HASH,
                    CryptoAlgorithm.SHA2,
                    registry=fresh_crypto_registry,
                ):
                    pass
        
        threads = []
        for _ in range(5):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        stats = fresh_crypto_registry.get_operation_stats(CryptoOperationType.HASH)
        assert stats.count == 50
    
    def test_backward_compatibility(self):
        """Test that new module doesn't break existing imports."""
        from quantum_crypt import crypto_observability_enhanced_crypto_telemetry_v17_2026_june
        
        assert hasattr(crypto_observability_enhanced_crypto_telemetry_v17_2026_june, "CryptoOperationType")
        assert hasattr(crypto_observability_enhanced_crypto_telemetry_v17_2026_june, "crypto_instrumented")
        assert hasattr(crypto_observability_enhanced_crypto_telemetry_v17_2026_june, "get_default_crypto_registry")


# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
