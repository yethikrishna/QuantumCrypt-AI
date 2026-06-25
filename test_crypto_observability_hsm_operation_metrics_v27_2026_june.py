"""
Tests for QuantumCrypt AI - HSM Operation Observability v27
DIMENSION D: Observability & Instrumentation

ONLY add tests - NO production code modified.
All existing tests must continue to pass.
"""

import pytest
import time
import threading
import secrets
from quantum_crypt.crypto_observability_hsm_operation_metrics_v27_2026_june import (
    HSMOperationObserver,
    CryptoOperationType,
    HSMStatus,
    ComplianceLevel,
    ThreadLocalCryptoContext,
    enable_crypto_instrumentation,
    disable_crypto_instrumentation,
    get_global_observer,
)


class TestHSMOperationObserver:
    """Test suite for HSM operation observer."""

    def test_observer_disabled_by_default(self):
        """Test that observer is disabled by default - no-op behavior."""
        observer = HSMOperationObserver(enabled=False)
        
        # All operations should be no-ops when disabled
        span = observer.start_crypto_span(CryptoOperationType.KEY_GENERATION)
        assert span is None
        
        observer.end_crypto_span(span)  # Should not raise
        observer.add_compliance_event(span, "key_gen", ComplianceLevel.FIPS_140_3_LEVEL_3)
        
        metrics = observer.get_health_metrics()
        assert metrics.error_count == 0

    def test_start_and_end_crypto_span(self):
        """Test basic crypto span lifecycle."""
        observer = HSMOperationObserver(enabled=True)
        
        span = observer.start_crypto_span(
            CryptoOperationType.KEY_GENERATION,
            algorithm="CRYSTALS-Kyber",
            key_size=1024,
        )
        
        assert span is not None
        assert span.trace_id is not None
        assert span.span_id is not None
        assert span.operation_type == "key_generation"
        assert span.algorithm == "CRYSTALS-Kyber"
        assert span.key_size == 1024
        assert span.start_time > 0
        assert span.end_time is None
        
        time.sleep(0.01)
        observer.end_crypto_span(span, success=True)
        
        assert span.end_time is not None
        assert span.end_time > span.start_time

    def test_span_hierarchy_nested_operations(self):
        """Test nested crypto operations with parent-child relationships."""
        observer = HSMOperationObserver(enabled=True)
        
        parent = observer.start_crypto_span(
            CryptoOperationType.SIGNATURE_GENERATION,
            algorithm="CRYSTALS-Dilithium",
        )
        
        child = observer.start_crypto_span(
            CryptoOperationType.HASH_COMPUTATION,
            algorithm="SHA3-512",
            trace_id=parent.trace_id,
            parent_span_id=parent.span_id,
        )
        
        assert child.trace_id == parent.trace_id
        assert child.parent_span_id == parent.span_id
        
        observer.end_crypto_span(child)
        observer.end_crypto_span(parent)

    def test_compliance_event_logging(self):
        """Test FIPS compliance event logging."""
        observer = HSMOperationObserver(enabled=True)
        
        span = observer.start_crypto_span(CryptoOperationType.KEY_GENERATION)
        observer.add_compliance_event(
            span,
            "key_generation_approved",
            ComplianceLevel.FIPS_140_3_LEVEL_3,
            details={"key_type": "asymmetric", "approved": True},
        )
        
        assert len(span.compliance_events) == 1
        event = span.compliance_events[0]
        assert event["event_type"] == "key_generation_approved"
        assert event["compliance_level"] == "fips_140_3_level_3"
        
        observer.end_crypto_span(span)

    def test_baggage_propagation_across_operations(self):
        """Test baggage propagation across crypto operation boundaries."""
        observer = HSMOperationObserver(enabled=True)
        
        span = observer.start_crypto_span(CryptoOperationType.ENCRYPTION)
        observer.propagate_baggage(span, "key_id", "hsm-key-001")
        observer.propagate_baggage(span, "request_id", "crypto-req-abc123")
        
        assert observer.get_baggage(span, "key_id") == "hsm-key-001"
        assert observer.get_baggage(span, "request_id") == "crypto-req-abc123"
        assert observer.get_baggage(span, "nonexistent") is None
        
        observer.end_crypto_span(span)

    def test_latency_percentile_calculation(self):
        """Test latency percentile calculation for crypto operations."""
        observer = HSMOperationObserver(enabled=True)
        
        # Simulate multiple key generation operations
        for i in range(50):
            span = observer.start_crypto_span(CryptoOperationType.KEY_GENERATION)
            time.sleep(0.001)
            observer.end_crypto_span(span)
        
        percentiles = observer.calculate_latency_percentiles(CryptoOperationType.KEY_GENERATION)
        
        assert percentiles["count"] == 50
        assert percentiles["min"] > 0
        assert percentiles["max"] >= percentiles["p999"]
        assert percentiles["p99"] >= percentiles["p95"]
        assert percentiles["p95"] >= percentiles["p90"]
        assert percentiles["p90"] >= percentiles["p75"]
        assert percentiles["p75"] >= percentiles["p50"]
        assert percentiles["avg"] > 0

    def test_health_metrics_calculation(self):
        """Test health metrics calculation for crypto subsystem."""
        observer = HSMOperationObserver(enabled=True)
        
        # Successful operations
        for i in range(90):
            span = observer.start_crypto_span(CryptoOperationType.ENCRYPTION)
            observer.end_crypto_span(span, success=True)
        
        # Failed operations
        for i in range(10):
            span = observer.start_crypto_span(CryptoOperationType.ENCRYPTION)
            observer.end_crypto_span(span, success=False, error_type="hsm_timeout")
        
        health = observer.get_health_metrics()
        
        assert health.operation_success_rate == pytest.approx(0.9, rel=0.01)
        assert health.error_count == 10
        assert health.last_health_check > 0

    def test_randomness_quality_monitoring(self):
        """Test randomness quality monitoring."""
        observer = HSMOperationObserver(enabled=True)
        
        # Record cryptographically secure random samples
        for _ in range(100):
            observer.record_randomness_sample(secrets.token_bytes(32))
        
        quality = observer.assess_randomness_quality()
        
        assert quality.sample_count == 100
        assert quality.entropy_bits_per_byte > 0
        # High-quality randomness should have entropy close to 8 bits/byte
        assert quality.entropy_bits_per_byte > 7.0
        assert quality.runs_test_passed is True

    def test_algorithm_usage_tracking(self):
        """Test algorithm usage statistics tracking."""
        observer = HSMOperationObserver(enabled=True)
        
        # Mix of different algorithms
        for _ in range(30):
            observer.start_crypto_span(CryptoOperationType.KEY_ENCAPSULATION, algorithm="CRYSTALS-Kyber")
        for _ in range(20):
            observer.start_crypto_span(CryptoOperationType.SIGNATURE_GENERATION, algorithm="CRYSTALS-Dilithium")
        for _ in range(10):
            observer.start_crypto_span(CryptoOperationType.HASH_COMPUTATION, algorithm="SHA3-256")
        
        usage = observer.get_algorithm_usage_stats()
        
        assert usage["CRYSTALS-Kyber"] == 30
        assert usage["CRYSTALS-Dilithium"] == 20
        assert usage["SHA3-256"] == 10

    def test_operation_counters(self):
        """Test operation counters tracking."""
        observer = HSMOperationObserver(enabled=True)
        
        for _ in range(5):
            observer.start_crypto_span(CryptoOperationType.KEY_GENERATION)
        for _ in range(3):
            observer.start_crypto_span(CryptoOperationType.SIGNATURE_VERIFICATION)
        for _ in range(2):
            observer.start_crypto_span(CryptoOperationType.BATCH_VERIFICATION)
        
        counters = observer.get_operation_counters()
        
        assert counters["key_generation"] == 5
        assert counters["signature_verification"] == 3
        assert counters["batch_verification"] == 2

    def test_trace_crypto_operation_decorator(self):
        """Test trace decorator for crypto operations."""
        observer = HSMOperationObserver(enabled=True)
        
        @observer.trace_crypto_operation(
            CryptoOperationType.KEY_ENCAPSULATION,
            algorithm="CRYSTALS-Kyber-768",
        )
        def mock_encapsulate(public_key: bytes) -> dict:
            return {
                "ciphertext": secrets.token_bytes(1088),
                "shared_secret": secrets.token_bytes(32),
            }
        
        result = mock_encapsulate(b"fake_pubkey")
        
        assert "ciphertext" in result
        assert "shared_secret" in result
        
        counters = observer.get_operation_counters()
        assert counters["key_encapsulation"] == 1

    def test_decorator_no_op_when_disabled(self):
        """Test that decorator is no-op when observer is disabled."""
        observer = HSMOperationObserver(enabled=False)
        
        call_count = [0]
        
        @observer.trace_crypto_operation(CryptoOperationType.DECRYPTION)
        def test_func():
            call_count[0] += 1
            return "decrypted"
        
        result = test_func()
        
        assert result == "decrypted"
        assert call_count[0] == 1
        
        # No counters should be incremented
        counters = observer.get_operation_counters()
        assert counters.get("decryption", 0) == 0

    def test_thread_local_context_isolation(self):
        """Test thread-local crypto context isolation."""
        observer = HSMOperationObserver(enabled=True)
        results = {}
        
        def thread_worker(thread_id: int):
            span = observer.start_crypto_span(CryptoOperationType.RANDOM_GENERATION)
            ThreadLocalCryptoContext.set_current_span(span)
            time.sleep(0.01)
            current = ThreadLocalCryptoContext.get_current_span()
            results[thread_id] = current.span_id if current else None
            observer.end_crypto_span(span)
        
        threads = [
            threading.Thread(target=thread_worker, args=(1,)),
            threading.Thread(target=thread_worker, args=(2,)),
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Each thread should have its own span context
        assert results[1] is not None
        assert results[2] is not None
        assert results[1] != results[2]

    def test_export_metrics_json(self):
        """Test JSON export for observability platforms."""
        observer = HSMOperationObserver(
            enabled=True,
            service_name="test-crypto-service",
            hsm_model="test-hsm-v1",
        )
        
        span = observer.start_crypto_span(CryptoOperationType.KEY_GENERATION)
        observer.add_compliance_event(
            span, "test_event", ComplianceLevel.FIPS_140_3_LEVEL_3
        )
        observer.end_crypto_span(span)
        
        export_json = observer.export_metrics_json()
        
        assert "test-crypto-service" in export_json
        assert "test-hsm-v1" in export_json
        assert "operation_counters" in export_json
        assert "latency_percentiles" in export_json
        assert "health_metrics" in export_json
        assert "randomness_quality" in export_json

    def test_global_observer_lifecycle(self):
        """Test global observer enable/disable lifecycle."""
        disable_crypto_instrumentation()
        observer = get_global_observer()
        assert observer.enabled is False
        
        enable_crypto_instrumentation(
            service_name="global-test",
            hsm_model="global-hsm",
        )
        observer = get_global_observer()
        assert observer.enabled is True
        assert observer.service_name == "global-test"
        assert observer.hsm_model == "global-hsm"
        
        disable_crypto_instrumentation()
        observer = get_global_observer()
        assert observer.enabled is False

    def test_exception_propagation_in_decorator(self):
        """Test that exceptions propagate correctly through decorator."""
        observer = HSMOperationObserver(enabled=True)
        
        @observer.trace_crypto_operation(CryptoOperationType.DECRYPTION)
        def failing_decrypt():
            raise ValueError("Invalid ciphertext")
        
        with pytest.raises(ValueError, match="Invalid ciphertext"):
            failing_decrypt()
        
        # Error should be counted
        counters = observer.get_operation_counters()
        assert counters["decryption"] == 1

    def test_hsm_status_update(self):
        """Test HSM status updates."""
        observer = HSMOperationObserver(enabled=True)
        
        assert observer.hsm_status == HSMStatus.ONLINE
        
        observer.update_hsm_status(HSMStatus.DEGRADED)
        assert observer.hsm_status == HSMStatus.DEGRADED
        
        observer.update_hsm_status(HSMStatus.MAINTENANCE)
        assert observer.hsm_status == HSMStatus.MAINTENANCE
        
        observer.update_hsm_status(HSMStatus.ONLINE)
        assert observer.hsm_status == HSMStatus.ONLINE

    def test_compliance_audit_log_retrieval(self):
        """Test compliance audit log retrieval."""
        observer = HSMOperationObserver(enabled=True)
        
        span1 = observer.start_crypto_span(CryptoOperationType.KEY_GENERATION)
        observer.add_compliance_event(span1, "event1", ComplianceLevel.FIPS_140_3_LEVEL_3)
        observer.end_crypto_span(span1)
        
        span2 = observer.start_crypto_span(CryptoOperationType.SIGNATURE_GENERATION)
        observer.add_compliance_event(span2, "event2", ComplianceLevel.FIPS_140_3_LEVEL_3)
        observer.end_crypto_span(span2)
        
        log = observer.get_compliance_audit_log()
        assert len(log) >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
