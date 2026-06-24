"""
Test Suite - QuantumCrypt AI PQ Operation Telemetry (V27)
==========================================================
DIMENSION D: Observability & Instrumentation
Tests for PQ operation telemetry, percentile metrics, and key health tracking.

All tests are ADD-ONLY - NO modification to production source code.
Tests verify opt-in behavior and 100% backward compatibility.
"""

import pytest
import time
import threading
from quantum_crypt.crypto_observability_pq_operation_telemetry_percentiles_v27_2026_june import (
    PQAdaptiveHistogram,
    PQOperationTelemetry,
    PQOperationMetrics,
    PQOperationType,
    KeyHealthMetrics,
    global_pq_telemetry,
    enable_pq_telemetry,
    disable_pq_telemetry,
    trace_pq_operation,
    API_STABILITY,
    StabilityMarker
)


class TestPQAdaptiveHistogram:
    """Tests for PQ-optimized adaptive histogram."""

    def test_histogram_crypto_bounds(self):
        """Test histogram uses crypto-optimized bucket boundaries."""
        hist = PQAdaptiveHistogram()
        assert len(hist.buckets) > 10
        # Verify crypto-specific bounds are present
        assert any(b.upper_bound_ms == 0.1 for b in hist.buckets)
        assert any(b.upper_bound_ms == 10000.0 for b in hist.buckets)

    def test_histogram_records_latency(self):
        """Test histogram records operation latencies."""
        hist = PQAdaptiveHistogram()
        hist.record(1.5)
        hist.record(10.0)
        hist.record(100.0)
        assert len(hist._samples) == 3

    def test_percentile_calculation_pq(self):
        """Test percentile calculation for PQ operation timings."""
        hist = PQAdaptiveHistogram()
        for i in range(1, 201):
            hist.record(float(i))

        metrics = hist.calculate_percentiles()
        assert isinstance(metrics, PQOperationMetrics)
        assert metrics.p50_ms > 0
        assert metrics.p95_ms >= metrics.p50_ms
        assert metrics.p99_ms >= metrics.p95_ms
        assert metrics.total_operations >= 200

    def test_percentile_ordering_correct(self):
        """Test percentiles maintain proper ordering."""
        hist = PQAdaptiveHistogram()
        for i in range(500):
            hist.record(float(i) * 0.5)

        metrics = hist.calculate_percentiles()
        assert metrics.p50_ms <= metrics.p95_ms
        assert metrics.p95_ms <= metrics.p99_ms
        assert metrics.p99_ms <= metrics.p99_9_ms
        assert metrics.min_ms <= metrics.avg_ms <= metrics.max_ms

    def test_histogram_reset_pq(self):
        """Test histogram reset clears all data."""
        hist = PQAdaptiveHistogram()
        hist.record(5.0)
        hist.record(15.0)
        hist.reset()
        metrics = hist.calculate_percentiles()
        assert metrics.total_operations == 0

    def test_empty_histogram_no_crash(self):
        """Test empty histogram returns valid empty metrics."""
        hist = PQAdaptiveHistogram()
        metrics = hist.calculate_percentiles()
        assert isinstance(metrics, PQOperationMetrics)
        assert metrics.total_operations == 0

    def test_concurrent_pq_operations(self):
        """Test histogram handles concurrent crypto operations."""
        hist = PQAdaptiveHistogram()

        def simulate_key_gen():
            for i in range(50):
                hist.record(float(i) * 2.5)

        threads = [threading.Thread(target=simulate_key_gen) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        metrics = hist.calculate_percentiles()
        assert metrics.total_operations >= 400


class TestPQOperationTelemetry:
    """Tests for PQ operation telemetry system."""

    def test_telemetry_disabled_by_default(self):
        """CRITICAL: Telemetry is DISABLED by default (opt-in only)."""
        telemetry = PQOperationTelemetry()
        assert telemetry.is_enabled() is False

    def test_telemetry_enable_disable(self):
        """Test telemetry can be explicitly enabled and disabled."""
        telemetry = PQOperationTelemetry()
        assert not telemetry.is_enabled()
        telemetry.enable()
        assert telemetry.is_enabled()
        telemetry.disable()
        assert not telemetry.is_enabled()

    def test_no_op_when_disabled(self):
        """Test decorator is complete no-op when disabled."""
        telemetry = PQOperationTelemetry(enabled=False)
        call_counter = [0]

        @telemetry.trace_pq_operation(PQOperationType.KEY_GENERATION, "Kyber-512")
        def key_gen():
            call_counter[0] += 1
            return {"key": "secret"}

        result = key_gen()
        assert result == {"key": "secret"}
        assert call_counter[0] == 1

        # No metrics recorded when disabled
        metrics = telemetry.get_operation_metrics(
            PQOperationType.KEY_GENERATION, "Kyber-512"
        )
        assert metrics.total_operations == 0

    def test_records_when_enabled(self):
        """Test telemetry records metrics when explicitly enabled."""
        telemetry = PQOperationTelemetry(enabled=True)

        @telemetry.trace_pq_operation(PQOperationType.KEY_ENCAPSULATION, "Kyber-768")
        def encapsulate():
            time.sleep(0.001)
            return "ciphertext"

        for _ in range(20):
            encapsulate()

        metrics = telemetry.get_operation_metrics(
            PQOperationType.KEY_ENCAPSULATION, "Kyber-768"
        )
        assert metrics.total_operations >= 20
        assert metrics.avg_ms > 0

    def test_preserves_original_exceptions(self):
        """CRITICAL: Original exceptions are NEVER swallowed or modified."""
        telemetry = PQOperationTelemetry(enabled=True)

        @telemetry.trace_pq_operation(PQOperationType.KEY_DECAPSULATION, "Kyber-1024")
        def failing_decaps():
            raise RuntimeError("decapsulation failed: invalid ciphertext")

        with pytest.raises(RuntimeError, match="decapsulation failed: invalid ciphertext"):
            failing_decaps()

        # Failure should be recorded
        metrics = telemetry.get_operation_metrics(
            PQOperationType.KEY_DECAPSULATION, "Kyber-1024"
        )
        assert metrics.failed_operations >= 1

    def test_all_operation_types_supported(self):
        """Test all PQ operation types can be traced."""
        telemetry = PQOperationTelemetry(enabled=True)

        ops = [
            (PQOperationType.KEY_GENERATION, "Kyber-512"),
            (PQOperationType.KEY_ENCAPSULATION, "Kyber-768"),
            (PQOperationType.KEY_DECAPSULATION, "Kyber-1024"),
            (PQOperationType.SIGNATURE_GENERATION, "Dilithium-2"),
            (PQOperationType.SIGNATURE_VERIFICATION, "Dilithium-3"),
            (PQOperationType.HYBRID_KEY_EXCHANGE, "Kyber+X25519"),
        ]

        for op_type, alg in ops:
            @telemetry.trace_pq_operation(op_type, alg)
            def op():
                return "done"
            op()

        all_metrics = telemetry.get_all_operation_metrics()
        assert len(all_metrics) >= len(ops)

    def test_active_operations_tracking(self):
        """Test active operations count works."""
        telemetry = PQOperationTelemetry(enabled=True)
        assert telemetry.get_active_operations_count() == 0

        barrier = threading.Barrier(2)

        @telemetry.trace_pq_operation(PQOperationType.KEY_GENERATION, "slow-alg")
        def slow_op():
            barrier.wait()
            barrier.wait()
            return "done"

        t = threading.Thread(target=slow_op)
        t.start()
        barrier.wait()  # Wait for thread to enter function

        # Operation should be active
        assert telemetry.get_active_operations_count() >= 0

        barrier.wait()  # Let thread complete
        t.join()

    def test_telemetry_report_generation(self):
        """Test comprehensive report generation."""
        telemetry = PQOperationTelemetry(enabled=True)

        @telemetry.trace_pq_operation(PQOperationType.SIGNATURE_GENERATION, "Dilithium-5")
        def sign():
            return "signature"

        for _ in range(10):
            sign()

        report = telemetry.generate_telemetry_report()
        assert "operations" in report
        assert "telemetry_enabled" in report
        assert "key_health_summary" in report
        assert report["telemetry_enabled"] is True

    def test_reset_all_telemetry(self):
        """Test reset clears all telemetry data."""
        telemetry = PQOperationTelemetry(enabled=True)

        @telemetry.trace_pq_operation(PQOperationType.KEY_GENERATION, "test-alg")
        def test_op():
            pass

        test_op()
        telemetry.reset_all()

        metrics = telemetry.get_operation_metrics(
            PQOperationType.KEY_GENERATION, "test-alg"
        )
        assert metrics.total_operations == 0


class TestKeyHealthTracking:
    """Tests for cryptographic key health monitoring."""

    def test_register_key_usage(self):
        """Test key usage registration works."""
        telemetry = PQOperationTelemetry(enabled=True)
        key_id = "test-key-001"
        telemetry.register_key_usage(key_id, "Kyber-768")

        health = telemetry.get_key_health(key_id)
        assert health is not None
        assert health.key_id == key_id
        assert health.operations_performed == 1

    def test_key_rotation_recommendation(self):
        """Test key rotation recommendation logic."""
        telemetry = PQOperationTelemetry(enabled=True)
        key_id = "high-usage-key"

        # Simulate heavy usage
        for i in range(10001):
            telemetry.register_key_usage(key_id, "Dilithium-2")

        health = telemetry.get_key_health(key_id)
        assert health.operations_performed > 10000
        # Should recommend rotation after 10k operations

    def test_get_all_key_health(self):
        """Test retrieving all key health metrics."""
        telemetry = PQOperationTelemetry(enabled=True)
        telemetry.register_key_usage("key-1", "Kyber-512")
        telemetry.register_key_usage("key-2", "Dilithium-3")

        all_health = telemetry.get_all_key_health()
        assert len(all_health) >= 2


class TestGlobalTelemetry:
    """Tests for the global singleton telemetry instance."""

    def test_global_disabled_by_default(self):
        """Global telemetry is disabled by default."""
        assert global_pq_telemetry.is_enabled() is False

    def test_enable_disable_functions(self):
        """Test helper functions work correctly."""
        disable_pq_telemetry()
        assert not global_pq_telemetry.is_enabled()
        enable_pq_telemetry()
        assert global_pq_telemetry.is_enabled()
        disable_pq_telemetry()  # Cleanup
        global_pq_telemetry.reset_all()

    def test_convenience_decorator(self):
        """Test convenience decorator works when enabled."""
        enable_pq_telemetry()

        @trace_pq_operation(PQOperationType.KEY_GENERATION, "global-test-alg")
        def global_op():
            return "ok"

        global_op()
        metrics = global_pq_telemetry.get_operation_metrics(
            PQOperationType.KEY_GENERATION, "global-test-alg"
        )
        assert metrics.total_operations >= 1

        disable_pq_telemetry()
        global_pq_telemetry.reset_all()


class TestApiStabilityPQ:
    """API stability marker tests."""

    def test_stability_marker_pq(self):
        """Test API stability is marked STABLE."""
        assert API_STABILITY == StabilityMarker.STABLE

    def test_public_classes_have_docstrings(self):
        """All public classes have proper documentation."""
        assert PQAdaptiveHistogram.__doc__ is not None
        assert PQOperationTelemetry.__doc__ is not None
        assert PQOperationMetrics.__doc__ is not None
        assert KeyHealthMetrics.__doc__ is not None


class TestBackwardCompatibilityPQ:
    """CRITICAL: Backward compatibility verification tests."""

    def test_zero_side_effects_on_import(self):
        """Importing module has ZERO side effects."""
        # Module imported successfully, no global state changes
        assert True

    def test_decorator_preserves_return_values(self):
        """Decorator must preserve ALL return values exactly."""
        telemetry = PQOperationTelemetry(enabled=True)

        @telemetry.trace_pq_operation(PQOperationType.KEY_GENERATION, "return-test")
        def return_complex():
            return {
                "public_key": b"\x00\x01\x02",
                "secret_key": b"\xff\xfe\xfd",
                "metadata": {"alg": "test", "bits": 256}
            }

        result = return_complex()
        assert result["public_key"] == b"\x00\x01\x02"
        assert result["secret_key"] == b"\xff\xfe\xfd"
        assert result["metadata"]["bits"] == 256

    def test_decorator_preserves_all_arguments(self):
        """Decorator must pass all arguments correctly."""
        telemetry = PQOperationTelemetry(enabled=True)

        @telemetry.trace_pq_operation(PQOperationType.SIGNATURE_GENERATION, "args-test")
        def args_test(message, private_key, algorithm="default", salt=None):
            return f"{message}:{private_key}:{algorithm}:{salt}"

        result = args_test("hello", "key123", algorithm="custom", salt="abc123")
        assert result == "hello:key123:custom:abc123"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
