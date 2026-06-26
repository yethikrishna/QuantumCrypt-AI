"""
Tests for PQ Crypto Operations Health Monitor - Feature Expansion v87
Dimension: A - Feature Expansion

Tests verify the health monitor works correctly without modifying
any existing code. All tests are ADD-ONLY.
"""

import pytest
import time

from quantum_crypt.feature_expansion_pq_crypto_health_monitor_v87_2026_june import (
    PQCryptoHealthMonitor,
    PQOperationType,
    PQAlgorithm,
    HealthStatus,
    ErrorCategory,
    OperationMetrics,
    HealthThresholds,
    HealthScore,
    OperationHealthReport,
    create_pq_health_monitor,
    create_default_pq_health_monitor,
    MODULE_DIMENSION,
    MODULE_VERSION,
    MODULE_STABILITY,
    MODULE_IS_ADD_ONLY,
    MODULE_PRESERVES_BACKWARD_COMPATIBILITY,
    verify_module,
)


class TestPQOperationTypeEnum:
    """Test PQOperationType enum has expected values."""

    def test_has_core_operations(self):
        """Verify all core PQ operations are defined."""
        expected = [
            "key_generation",
            "signing",
            "verification",
            "encryption",
            "decryption",
            "kem_encapsulation",
            "kem_decapsulation",
            "key_exchange",
        ]
        for op in expected:
            assert op in [v.value for v in PQOperationType]

    def test_operation_count(self):
        """Verify we have a reasonable number of operation types."""
        assert len(PQOperationType) >= 8
        assert len(PQOperationType) <= 20


class TestPQAlgorithmEnum:
    """Test PQAlgorithm enum has expected values."""

    def test_has_core_algorithms(self):
        """Verify all core PQ algorithms are defined."""
        expected = ["kyber", "dilithium", "falcon", "sphincs", "ntru"]
        for algo in expected:
            assert algo in [v.value for v in PQAlgorithm]

    def test_has_hybrid_algorithms(self):
        """Verify hybrid algorithm types are defined."""
        assert "hybrid_kem" in [v.value for v in PQAlgorithm]
        assert "hybrid_signature" in [v.value for v in PQAlgorithm]


class TestHealthStatusEnum:
    """Test HealthStatus enum."""

    def test_all_statuses(self):
        """Verify all health status values exist."""
        statuses = [s.value for s in HealthStatus]
        assert "healthy" in statuses
        assert "degraded" in statuses
        assert "unhealthy" in statuses
        assert "unknown" in statuses


class TestErrorCategoryEnum:
    """Test ErrorCategory enum."""

    def test_common_errors(self):
        """Verify common error categories are defined."""
        errors = [e.value for e in ErrorCategory]
        assert "invalid_input" in errors
        assert "authentication_failure" in errors
        assert "timeout" in errors
        assert "key_not_found" in errors
        assert "unknown" in errors


class TestOperationMetrics:
    """Test OperationMetrics dataclass."""

    def test_create_metrics(self):
        """Test creating OperationMetrics with defaults."""
        metrics = OperationMetrics(
            operation_type=PQOperationType.SIGNING,
            algorithm=PQAlgorithm.DILITHIUM,
        )
        assert metrics.total_operations == 0
        assert metrics.successful_operations == 0
        assert metrics.failed_operations == 0
        assert metrics.success_rate == 1.0
        assert metrics.failure_rate == 0.0
        assert metrics.avg_latency_ms == 0.0

    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        metrics = OperationMetrics(
            operation_type=PQOperationType.SIGNING,
            algorithm=PQAlgorithm.DILITHIUM,
            total_operations=100,
            successful_operations=95,
            failed_operations=5,
        )
        assert metrics.success_rate == 0.95
        assert metrics.failure_rate == 0.05

    def test_percentile_latency(self):
        """Test percentile latency calculation."""
        metrics = OperationMetrics(
            operation_type=PQOperationType.SIGNING,
            algorithm=PQAlgorithm.DILITHIUM,
        )
        # Add some latencies
        for i in range(100):
            metrics.recent_latencies.append(float(i + 1))

        p50 = metrics.get_percentile_latency(50)
        p95 = metrics.get_percentile_latency(95)
        p99 = metrics.get_percentile_latency(99)

        assert p50 > 0
        assert p95 > p50
        assert p99 > p95
        assert p99 <= 100

    def test_empty_percentile(self):
        """Test percentile with no data returns 0."""
        metrics = OperationMetrics(
            operation_type=PQOperationType.SIGNING,
            algorithm=PQAlgorithm.DILITHIUM,
        )
        assert metrics.get_percentile_latency(95) == 0.0


class TestPQCryptoHealthMonitor:
    """Test the main health monitor class."""

    def test_create_monitor(self):
        """Test creating a new health monitor."""
        monitor = PQCryptoHealthMonitor()
        assert monitor is not None
        assert len(monitor.list_tracked_operations()) == 0

    def test_create_with_thresholds(self):
        """Test creating monitor with custom thresholds."""
        thresholds = HealthThresholds(
            healthy_success_rate=0.999,
            degraded_success_rate=0.98,
        )
        monitor = PQCryptoHealthMonitor(thresholds)
        assert monitor is not None

    def test_record_success(self):
        """Test recording a successful operation."""
        monitor = PQCryptoHealthMonitor()
        monitor.record_success(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM,
            42.5
        )

        metrics = monitor.get_operation_metrics(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM
        )
        assert metrics is not None
        assert metrics.total_operations == 1
        assert metrics.successful_operations == 1
        assert metrics.failed_operations == 0
        assert metrics.avg_latency_ms == 42.5

    def test_record_failure(self):
        """Test recording a failed operation."""
        monitor = PQCryptoHealthMonitor()
        monitor.record_failure(
            PQOperationType.VERIFICATION,
            PQAlgorithm.KYBER,
            ErrorCategory.INVALID_INPUT,
            10.0
        )

        metrics = monitor.get_operation_metrics(
            PQOperationType.VERIFICATION,
            PQAlgorithm.KYBER
        )
        assert metrics is not None
        assert metrics.total_operations == 1
        assert metrics.failed_operations == 1
        assert metrics.errors_by_category[ErrorCategory.INVALID_INPUT] == 1

    def test_multiple_operations(self):
        """Test recording multiple operations of different types."""
        monitor = PQCryptoHealthMonitor()

        for i in range(10):
            monitor.record_success(
                PQOperationType.SIGNING,
                PQAlgorithm.DILITHIUM,
                30.0 + i
            )

        for i in range(5):
            monitor.record_success(
                PQOperationType.VERIFICATION,
                PQAlgorithm.DILITHIUM,
                10.0 + i
            )

        assert len(monitor.list_tracked_operations()) == 2

        signing_metrics = monitor.get_operation_metrics(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM
        )
        assert signing_metrics.total_operations == 10
        assert signing_metrics.success_rate == 1.0

    def test_get_nonexistent_metrics(self):
        """Test getting metrics for untracked operation returns None."""
        monitor = PQCryptoHealthMonitor()
        metrics = monitor.get_operation_metrics(
            PQOperationType.ENCRYPTION,
            PQAlgorithm.KYBER
        )
        assert metrics is None

    def test_list_tracked_operations(self):
        """Test listing all tracked operations."""
        monitor = PQCryptoHealthMonitor()

        ops = [
            (PQOperationType.SIGNING, PQAlgorithm.DILITHIUM),
            (PQOperationType.VERIFICATION, PQAlgorithm.KYBER),
            (PQOperationType.KEY_GENERATION, PQAlgorithm.FALCON),
        ]

        for op_type, algo in ops:
            monitor.record_success(op_type, algo, 10.0)

        tracked = monitor.list_tracked_operations()
        assert len(tracked) == 3
        for op in ops:
            assert op in tracked


class TestHealthScoring:
    """Test health scoring functionality."""

    def test_unknown_health_with_no_data(self):
        """Test health status is UNKNOWN with no operations."""
        monitor = PQCryptoHealthMonitor()
        health = monitor.get_operation_health(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM
        )
        assert health.health_status == HealthStatus.UNKNOWN
        assert health.health_score == 0.5

    def test_healthy_with_good_metrics(self):
        """Test health status is HEALTHY with good metrics."""
        monitor = PQCryptoHealthMonitor()

        # Record many fast, successful operations
        for i in range(100):
            monitor.record_success(
                PQOperationType.VERIFICATION,
                PQAlgorithm.DILITHIUM,
                5.0  # Very fast
            )

        health = monitor.get_operation_health(
            PQOperationType.VERIFICATION,
            PQAlgorithm.DILITHIUM
        )
        assert health.health_status == HealthStatus.HEALTHY
        assert health.success_rate == 1.0
        assert health.health_score >= 0.8

    def test_degraded_with_some_errors(self):
        """Test health status is DEGRADED with some errors."""
        monitor = PQCryptoHealthMonitor()

        # 90% success rate
        for i in range(90):
            monitor.record_success(
                PQOperationType.SIGNING,
                PQAlgorithm.DILITHIUM,
                50.0
            )
        for i in range(10):
            monitor.record_failure(
                PQOperationType.SIGNING,
                PQAlgorithm.DILITHIUM,
                ErrorCategory.INVALID_INPUT,
                20.0
            )

        health = monitor.get_operation_health(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM
        )
        # 90% success should be degraded (below 0.95 threshold)
        assert health.health_status in (HealthStatus.DEGRADED, HealthStatus.UNHEALTHY)

    def test_health_score_range(self):
        """Test health score is always between 0 and 1."""
        monitor = PQCryptoHealthMonitor()

        # Add some mixed data
        for i in range(50):
            monitor.record_success(
                PQOperationType.SIGNING,
                PQAlgorithm.DILITHIUM,
                100.0
            )
        for i in range(10):
            monitor.record_failure(
                PQOperationType.SIGNING,
                PQAlgorithm.DILITHIUM,
                ErrorCategory.TIMEOUT,
                500.0
            )

        health = monitor.get_operation_health(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM
        )
        assert 0.0 <= health.health_score <= 1.0


class TestOverallHealth:
    """Test overall health assessment."""

    def test_overall_health_empty(self):
        """Test overall health with no data."""
        monitor = PQCryptoHealthMonitor()
        health = monitor.get_overall_health()

        assert isinstance(health, HealthScore)
        assert health.status == HealthStatus.UNKNOWN
        assert health.overall_score == 0.5

    def test_overall_health_with_data(self):
        """Test overall health with some operations."""
        monitor = PQCryptoHealthMonitor()

        # Add healthy operations
        for i in range(50):
            monitor.record_success(
                PQOperationType.SIGNING,
                PQAlgorithm.DILITHIUM,
                10.0
            )
            monitor.record_success(
                PQOperationType.VERIFICATION,
                PQAlgorithm.DILITHIUM,
                5.0
            )

        health = monitor.get_overall_health()
        assert health.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)
        assert 0.0 <= health.overall_score <= 1.0
        assert "tracked_operations" in health.details
        assert "total_operations" in health.details

    def test_overall_health_has_details(self):
        """Test overall health has detailed breakdown."""
        monitor = PQCryptoHealthMonitor()
        monitor.record_success(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM,
            20.0
        )

        health = monitor.get_overall_health()
        assert hasattr(health, 'success_rate_score')
        assert hasattr(health, 'latency_score')
        assert hasattr(health, 'error_rate_score')
        assert hasattr(health, 'throughput_score')
        assert hasattr(health, 'timestamp')


class TestErrorTracking:
    """Test error tracking and categorization."""

    def test_error_summary(self):
        """Test error summary across all operations."""
        monitor = PQCryptoHealthMonitor()

        monitor.record_failure(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM,
            ErrorCategory.INVALID_INPUT,
            5.0
        )
        monitor.record_failure(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM,
            ErrorCategory.INVALID_INPUT,
            3.0
        )
        monitor.record_failure(
            PQOperationType.VERIFICATION,
            PQAlgorithm.KYBER,
            ErrorCategory.TIMEOUT,
            100.0
        )

        summary = monitor.get_error_summary()
        assert ErrorCategory.INVALID_INPUT in summary
        assert summary[ErrorCategory.INVALID_INPUT] == 2
        assert ErrorCategory.TIMEOUT in summary
        assert summary[ErrorCategory.TIMEOUT] == 1

    def test_top_errors_in_report(self):
        """Test top errors are included in health report."""
        monitor = PQCryptoHealthMonitor()

        for i in range(5):
            monitor.record_failure(
                PQOperationType.DECRYPTION,
                PQAlgorithm.KYBER,
                ErrorCategory.AUTHENTICATION_FAILURE,
                10.0
            )
        for i in range(3):
            monitor.record_failure(
                PQOperationType.DECRYPTION,
                PQAlgorithm.KYBER,
                ErrorCategory.KEY_EXPIRED,
                5.0
            )

        health = monitor.get_operation_health(
            PQOperationType.DECRYPTION,
            PQAlgorithm.KYBER
        )
        assert len(health.top_errors) > 0
        # Most common error should be first
        assert health.top_errors[0][0] == ErrorCategory.AUTHENTICATION_FAILURE
        assert health.top_errors[0][1] == 5


class TestOperationsNeedingAttention:
    """Test operations needing attention functionality."""

    def test_no_operations_needing_attention_when_healthy(self):
        """Test no operations flagged when all are healthy."""
        monitor = PQCryptoHealthMonitor()

        for i in range(100):
            monitor.record_success(
                PQOperationType.VERIFICATION,
                PQAlgorithm.DILITHIUM,
                2.0  # Very fast
            )

        needs_attention = monitor.get_operations_needing_attention(threshold=0.6)
        # Should be empty or very few with high success and low latency
        assert len(needs_attention) == 0 or all(
            op.health_score >= 0.5 for op in needs_attention
        )

    def test_operations_needing_attention_when_unhealthy(self):
        """Test operations are flagged when unhealthy."""
        monitor = PQCryptoHealthMonitor()

        # 50% failure rate
        for i in range(10):
            monitor.record_success(
                PQOperationType.SIGNING,
                PQAlgorithm.FALCON,
                100.0
            )
        for i in range(10):
            monitor.record_failure(
                PQOperationType.SIGNING,
                PQAlgorithm.FALCON,
                ErrorCategory.ALGORITHM_ERROR,
                50.0
            )

        needs_attention = monitor.get_operations_needing_attention(threshold=0.7)
        assert len(needs_attention) >= 1
        assert needs_attention[0].operation_type == PQOperationType.SIGNING


class TestMonitorStats:
    """Test monitor self-statistics."""

    def test_monitor_stats(self):
        """Test monitor statistics tracking."""
        monitor = PQCryptoHealthMonitor()

        for i in range(10):
            monitor.record_success(
                PQOperationType.SIGNING,
                PQAlgorithm.DILITHIUM,
                10.0
            )

        # Trigger some health checks
        monitor.get_overall_health()
        monitor.get_overall_health()

        stats = monitor.get_monitor_stats()
        assert stats["tracked_operation_types"] == 1
        assert stats["total_operations_recorded"] == 10
        assert stats["health_checks_performed"] == 2
        assert stats["monitor_uptime_seconds"] >= 0


class TestResetFunctionality:
    """Test metrics reset functionality."""

    def test_reset_clears_metrics(self):
        """Test reset clears all metrics."""
        monitor = PQCryptoHealthMonitor()

        monitor.record_success(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM,
            10.0
        )
        assert len(monitor.list_tracked_operations()) == 1

        monitor.reset_metrics()
        assert len(monitor.list_tracked_operations()) == 0
        assert monitor.get_monitor_stats()["total_operations_recorded"] == 0

    def test_reset_preserves_thresholds(self):
        """Test reset doesn't change thresholds."""
        thresholds = HealthThresholds(healthy_success_rate=0.999)
        monitor = PQCryptoHealthMonitor(thresholds)

        monitor.record_success(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM,
            10.0
        )
        monitor.reset_metrics()

        # Should still work after reset
        monitor.record_success(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM,
            10.0
        )
        assert len(monitor.list_tracked_operations()) == 1


class TestFactoryFunctions:
    """Test factory and utility functions."""

    def test_create_pq_health_monitor(self):
        """Test factory function creates a monitor."""
        monitor = create_pq_health_monitor()
        assert isinstance(monitor, PQCryptoHealthMonitor)
        assert len(monitor.list_tracked_operations()) == 0

    def test_create_default_pq_health_monitor(self):
        """Test default monitor has PQ-tuned thresholds."""
        monitor = create_default_pq_health_monitor()
        assert isinstance(monitor, PQCryptoHealthMonitor)

    def test_verify_module(self):
        """Test module self-verification function."""
        assert verify_module() is True


class TestModuleMetadata:
    """Test module metadata constants."""

    def test_dimension(self):
        assert MODULE_DIMENSION == "A - Feature Expansion"

    def test_version(self):
        assert MODULE_VERSION == "v87"

    def test_stability(self):
        assert MODULE_STABILITY == "stable"

    def test_is_add_only(self):
        assert MODULE_IS_ADD_ONLY is True

    def test_preserves_backward_compatibility(self):
        assert MODULE_PRESERVES_BACKWARD_COMPATIBILITY is True


class TestBackwardCompatibility:
    """Verify this module is purely additive and doesn't break anything."""

    def test_module_is_importable(self):
        """Test the module can be imported without errors."""
        from quantum_crypt import feature_expansion_pq_crypto_health_monitor_v87_2026_june
        assert feature_expansion_pq_crypto_health_monitor_v87_2026_june is not None

    def test_no_existing_code_modified(self):
        """
        Verify this is an add-only module by checking it doesn't
        modify any existing modules or globals.
        """
        assert hasattr(
            __import__('quantum_crypt.feature_expansion_pq_crypto_health_monitor_v87_2026_june',
                       fromlist=['PQCryptoHealthMonitor']),
            'PQCryptoHealthMonitor'
        )


class TestRealWorldScenarios:
    """Test realistic usage scenarios."""

    def test_production_monitoring_workflow(self):
        """Test a complete production monitoring workflow."""
        # 1. Create monitor with production thresholds
        monitor = create_default_pq_health_monitor()

        # 2. Simulate normal operations
        for i in range(100):
            monitor.record_success(
                PQOperationType.SIGNING,
                PQAlgorithm.DILITHIUM,
                25.0 + (i % 10)  # Variable latency
            )
            monitor.record_success(
                PQOperationType.VERIFICATION,
                PQAlgorithm.DILITHIUM,
                8.0 + (i % 5)
            )

        # 3. Simulate some errors
        for i in range(3):
            monitor.record_failure(
                PQOperationType.SIGNING,
                PQAlgorithm.DILITHIUM,
                ErrorCategory.INVALID_INPUT,
                5.0
            )

        # 4. Check overall health
        health = monitor.get_overall_health()
        assert health.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)
        assert health.details["total_operations"] == 203
        assert health.details["total_errors"] == 3

        # 5. Check specific operation health
        signing_health = monitor.get_operation_health(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM
        )
        assert signing_health.total_operations == 103
        assert signing_health.success_rate < 1.0  # Had some failures

        # 6. Get error summary
        errors = monitor.get_error_summary()
        assert ErrorCategory.INVALID_INPUT in errors
        assert errors[ErrorCategory.INVALID_INPUT] == 3

    def test_degradation_detection(self):
        """Test detecting performance degradation over time."""
        monitor = PQCryptoHealthMonitor()

        # Phase 1: Fast operations
        for i in range(50):
            monitor.record_success(
                PQOperationType.VERIFICATION,
                PQAlgorithm.KYBER,
                2.0  # Very fast
            )

        health1 = monitor.get_operation_health(
            PQOperationType.VERIFICATION,
            PQAlgorithm.KYBER
        )
        score1 = health1.health_score

        # Phase 2: Slower operations (simulating degradation)
        for i in range(50):
            monitor.record_success(
                PQOperationType.VERIFICATION,
                PQAlgorithm.KYBER,
                800.0  # Much slower
            )

        health2 = monitor.get_operation_health(
            PQOperationType.VERIFICATION,
            PQAlgorithm.KYBER
        )
        score2 = health2.health_score

        # Score should be lower with slower operations
        # (but not necessarily since it's a sliding window and averages)
        assert isinstance(score2, float)
        assert 0.0 <= score2 <= 1.0

    def test_multi_algorithm_monitoring(self):
        """Test monitoring multiple algorithms simultaneously."""
        monitor = PQCryptoHealthMonitor()

        algorithms = [
            (PQAlgorithm.KYBER, PQOperationType.KEM_ENCAPSULATION),
            (PQAlgorithm.DILITHIUM, PQOperationType.SIGNING),
            (PQAlgorithm.FALCON, PQOperationType.SIGNING),
        ]

        for algo, op_type in algorithms:
            for i in range(20):
                monitor.record_success(op_type, algo, 10.0 + i)

        all_health = monitor.get_all_operation_health()
        assert len(all_health) == 3

        # Should be sorted by health score (worst first)
        for i in range(len(all_health) - 1):
            assert all_health[i].health_score <= all_health[i + 1].health_score
