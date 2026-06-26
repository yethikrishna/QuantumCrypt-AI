"""
PQ Crypto Operations Health Monitor - QuantumCrypt-AI Feature Expansion
Version: v87
Date: June 2026
Dimension: A - Feature Expansion

Monitors the health and performance of post-quantum cryptographic operations
in production environments. Tracks success rates, latency distributions,
error patterns, and provides health scoring.

ADD-ONLY: This module is purely additive. It does not modify any existing
code or break backward compatibility.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
import time
import statistics
from collections import deque


class PQOperationType(str, Enum):
    """Types of post-quantum cryptographic operations."""
    KEY_GENERATION = "key_generation"
    SIGNING = "signing"
    VERIFICATION = "verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    KEM_ENCAPSULATION = "kem_encapsulation"
    KEM_DECAPSULATION = "kem_decapsulation"
    KEY_EXCHANGE = "key_exchange"
    KEY_ROTATION = "key_rotation"
    HASHING = "hashing"
    SIGNATURE_BATCH_VERIFY = "signature_batch_verify"


class PQAlgorithm(str, Enum):
    """Post-quantum algorithm types."""
    KYBER = "kyber"
    DILITHIUM = "dilithium"
    FALCON = "falcon"
    SPHINCS = "sphincs"
    NTRU = "ntru"
    HYBRID_KEM = "hybrid_kem"
    HYBRID_SIGNATURE = "hybrid_signature"
    ARGON2ID = "argon2id"
    SHA3 = "sha3"


class HealthStatus(str, Enum):
    """Health status levels for crypto operations."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ErrorCategory(str, Enum):
    """Categories of crypto operation errors."""
    INVALID_INPUT = "invalid_input"
    AUTHENTICATION_FAILURE = "authentication_failure"
    KEY_NOT_FOUND = "key_not_found"
    KEY_EXPIRED = "key_expired"
    MEMORY_ERROR = "memory_error"
    TIMEOUT = "timeout"
    HARDWARE_ERROR = "hardware_error"
    RANDOMNESS_FAILURE = "randomness_failure"
    ALGORITHM_ERROR = "algorithm_error"
    UNKNOWN = "unknown"


@dataclass
class OperationMetrics:
    """Metrics for a single type of crypto operation."""
    operation_type: PQOperationType
    algorithm: PQAlgorithm
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    total_latency_ms: float = 0.0
    min_latency_ms: float = float('inf')
    max_latency_ms: float = 0.0
    recent_latencies: deque = field(default_factory=lambda: deque(maxlen=1000))
    errors_by_category: Dict[ErrorCategory, int] = field(default_factory=dict)
    last_operation_time: float = 0.0
    first_operation_time: float = 0.0

    @property
    def success_rate(self) -> float:
        """Calculate success rate (0.0 - 1.0)."""
        if self.total_operations == 0:
            return 1.0
        return self.successful_operations / self.total_operations

    @property
    def failure_rate(self) -> float:
        """Calculate failure rate (0.0 - 1.0)."""
        if self.total_operations == 0:
            return 0.0
        return self.failed_operations / self.total_operations

    @property
    def avg_latency_ms(self) -> float:
        """Calculate average latency in milliseconds."""
        if self.total_operations == 0:
            return 0.0
        return self.total_latency_ms / self.total_operations

    @property
    def operations_per_second(self) -> float:
        """Calculate operations per second based on elapsed time."""
        if self.first_operation_time == 0:
            return 0.0
        elapsed = time.time() - self.first_operation_time
        if elapsed <= 0:
            return 0.0
        return self.total_operations / elapsed

    def get_percentile_latency(self, percentile: float) -> float:
        """Calculate latency at a given percentile (0-100)."""
        if not self.recent_latencies:
            return 0.0
        sorted_latencies = sorted(self.recent_latencies)
        index = int(len(sorted_latencies) * percentile / 100)
        index = min(index, len(sorted_latencies) - 1)
        return sorted_latencies[index]


@dataclass
class HealthThresholds:
    """Thresholds for determining health status."""
    # Success rate thresholds
    healthy_success_rate: float = 0.99
    degraded_success_rate: float = 0.95

    # Latency thresholds (ms)
    healthy_latency_p95_ms: float = 1000.0
    degraded_latency_p95_ms: float = 5000.0

    # Error rate thresholds
    healthy_error_rate: float = 0.01
    degraded_error_rate: float = 0.05

    # Throughput thresholds (ops/sec) - below this is concerning
    min_healthy_throughput: float = 1.0


@dataclass
class HealthScore:
    """Overall health score for crypto operations."""
    overall_score: float  # 0.0 - 1.0
    status: HealthStatus
    success_rate_score: float
    latency_score: float
    error_rate_score: float
    throughput_score: float
    details: Dict[str, float]
    timestamp: float


@dataclass
class OperationHealthReport:
    """Health report for a specific operation type."""
    operation_type: PQOperationType
    algorithm: PQAlgorithm
    health_status: HealthStatus
    health_score: float
    success_rate: float
    avg_latency_ms: float
    p95_latency_ms: float
    total_operations: int
    total_errors: int
    top_errors: List[Tuple[ErrorCategory, int]]
    throughput_ops_sec: float
    last_updated: float


class PQCryptoHealthMonitor:
    """
    Monitors the health and performance of post-quantum cryptographic operations.

    Features:
    - Real-time operation metrics tracking
    - Success/failure rate monitoring
    - Latency distribution analysis (avg, p50, p95, p99)
    - Error categorization and trend analysis
    - Health scoring with configurable thresholds
    - Throughput monitoring
    - Operation history with sliding window

    Usage:
        monitor = PQCryptoHealthMonitor()
        monitor.record_success(PQOperationType.SIGNING, PQAlgorithm.DILITHIUM, 15.5)
        monitor.record_failure(PQOperationType.VERIFICATION, PQAlgorithm.KYBER,
                              ErrorCategory.INVALID_INPUT, 5.2)
        health = monitor.get_overall_health()
    """

    def __init__(self, thresholds: Optional[HealthThresholds] = None):
        self._metrics: Dict[Tuple[PQOperationType, PQAlgorithm], OperationMetrics] = {}
        self._thresholds = thresholds or HealthThresholds()
        self._start_time = time.time()
        self._total_operations = 0
        self._health_check_count = 0

    def _get_or_create_metrics(self, op_type: PQOperationType,
                                algorithm: PQAlgorithm) -> OperationMetrics:
        """Get or create metrics for an operation/algorithm pair."""
        key = (op_type, algorithm)
        if key not in self._metrics:
            self._metrics[key] = OperationMetrics(
                operation_type=op_type,
                algorithm=algorithm,
            )
        return self._metrics[key]

    def record_success(self, op_type: PQOperationType, algorithm: PQAlgorithm,
                       latency_ms: float) -> None:
        """
        Record a successful crypto operation.

        Args:
            op_type: Type of operation performed
            algorithm: PQ algorithm used
            latency_ms: Operation latency in milliseconds
        """
        metrics = self._get_or_create_metrics(op_type, algorithm)
        now = time.time()

        metrics.total_operations += 1
        metrics.successful_operations += 1
        metrics.total_latency_ms += latency_ms
        metrics.min_latency_ms = min(metrics.min_latency_ms, latency_ms)
        metrics.max_latency_ms = max(metrics.max_latency_ms, latency_ms)
        metrics.recent_latencies.append(latency_ms)
        metrics.last_operation_time = now

        if metrics.first_operation_time == 0:
            metrics.first_operation_time = now

        self._total_operations += 1

    def record_failure(self, op_type: PQOperationType, algorithm: PQAlgorithm,
                       error_category: ErrorCategory, latency_ms: float = 0.0) -> None:
        """
        Record a failed crypto operation.

        Args:
            op_type: Type of operation that failed
            algorithm: PQ algorithm used
            error_category: Category of the error
            latency_ms: Time spent before failure (in ms)
        """
        metrics = self._get_or_create_metrics(op_type, algorithm)
        now = time.time()

        metrics.total_operations += 1
        metrics.failed_operations += 1
        metrics.total_latency_ms += latency_ms
        metrics.recent_latencies.append(latency_ms)
        metrics.last_operation_time = now

        if metrics.first_operation_time == 0:
            metrics.first_operation_time = now

        # Track error category
        if error_category not in metrics.errors_by_category:
            metrics.errors_by_category[error_category] = 0
        metrics.errors_by_category[error_category] += 1

        self._total_operations += 1

    def get_operation_metrics(self, op_type: PQOperationType,
                              algorithm: PQAlgorithm) -> Optional[OperationMetrics]:
        """
        Get metrics for a specific operation/algorithm pair.

        Returns:
            OperationMetrics or None if no data
        """
        key = (op_type, algorithm)
        return self._metrics.get(key)

    def list_tracked_operations(self) -> List[Tuple[PQOperationType, PQAlgorithm]]:
        """List all operation/algorithm pairs being tracked."""
        return list(self._metrics.keys())

    def get_operation_health(self, op_type: PQOperationType,
                             algorithm: PQAlgorithm) -> OperationHealthReport:
        """
        Get health report for a specific operation type.

        Args:
            op_type: Operation type to check
            algorithm: Algorithm to check

        Returns:
            OperationHealthReport with health assessment
        """
        metrics = self._get_or_create_metrics(op_type, algorithm)
        return self._calculate_operation_health(metrics)

    def _calculate_operation_health(self, metrics: OperationMetrics) -> OperationHealthReport:
        """Calculate health status for a single operation type."""
        if metrics.total_operations == 0:
            return OperationHealthReport(
                operation_type=metrics.operation_type,
                algorithm=metrics.algorithm,
                health_status=HealthStatus.UNKNOWN,
                health_score=0.5,
                success_rate=1.0,
                avg_latency_ms=0.0,
                p95_latency_ms=0.0,
                total_operations=0,
                total_errors=0,
                top_errors=[],
                throughput_ops_sec=0.0,
                last_updated=time.time(),
            )

        # Calculate health components
        success_rate = metrics.success_rate
        p95_latency = metrics.get_percentile_latency(95)
        throughput = metrics.operations_per_second

        # Score each dimension (0-1)
        success_score = self._score_success_rate(success_rate)
        latency_score = self._score_latency(p95_latency)
        throughput_score = self._score_throughput(throughput)

        # Weighted health score
        health_score = (
            success_score * 0.5 +
            latency_score * 0.3 +
            throughput_score * 0.2
        )

        # Determine status
        if health_score >= 0.8:
            status = HealthStatus.HEALTHY
        elif health_score >= 0.5:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.UNHEALTHY

        # Get top errors
        sorted_errors = sorted(
            metrics.errors_by_category.items(),
            key=lambda x: x[1],
            reverse=True
        )
        top_errors = sorted_errors[:5]

        return OperationHealthReport(
            operation_type=metrics.operation_type,
            algorithm=metrics.algorithm,
            health_status=status,
            health_score=round(health_score, 3),
            success_rate=round(success_rate, 4),
            avg_latency_ms=round(metrics.avg_latency_ms, 2),
            p95_latency_ms=round(p95_latency, 2),
            total_operations=metrics.total_operations,
            total_errors=metrics.failed_operations,
            top_errors=top_errors,
            throughput_ops_sec=round(throughput, 2),
            last_updated=time.time(),
        )

    def _score_success_rate(self, success_rate: float) -> float:
        """Score success rate (0-1)."""
        if success_rate >= self._thresholds.healthy_success_rate:
            return 1.0
        elif success_rate >= self._thresholds.degraded_success_rate:
            # Linear interpolation between degraded and healthy
            range_span = (self._thresholds.healthy_success_rate -
                          self._thresholds.degraded_success_rate)
            if range_span > 0:
                return (success_rate - self._thresholds.degraded_success_rate) / range_span * 0.5 + 0.5
            return 0.5
        else:
            # Below degraded threshold
            return max(0.0, success_rate / self._thresholds.degraded_success_rate * 0.5)

    def _score_latency(self, p95_latency_ms: float) -> float:
        """Score latency (0-1, lower is better)."""
        if p95_latency_ms <= 0:
            return 1.0
        if p95_latency_ms <= self._thresholds.healthy_latency_p95_ms:
            return 1.0
        elif p95_latency_ms <= self._thresholds.degraded_latency_p95_ms:
            # Linear interpolation
            range_span = (self._thresholds.degraded_latency_p95_ms -
                          self._thresholds.healthy_latency_p95_ms)
            if range_span > 0:
                excess = p95_latency_ms - self._thresholds.healthy_latency_p95_ms
                return 1.0 - (excess / range_span * 0.5)
            return 0.5
        else:
            # Above degraded threshold
            return max(0.0, 0.5 - (p95_latency_ms - self._thresholds.degraded_latency_p95_ms) /
                       self._thresholds.degraded_latency_p95_ms * 0.5)

    def _score_throughput(self, throughput: float) -> float:
        """Score throughput (0-1, higher is better)."""
        if throughput >= self._thresholds.min_healthy_throughput * 10:
            return 1.0
        elif throughput >= self._thresholds.min_healthy_throughput:
            return 0.5 + (throughput - self._thresholds.min_healthy_throughput) / (
                self._thresholds.min_healthy_throughput * 9
            ) * 0.5
        elif throughput > 0:
            return (throughput / self._thresholds.min_healthy_throughput) * 0.5
        else:
            return 0.0

    def get_overall_health(self) -> HealthScore:
        """
        Get overall health score across all tracked operations.

        Returns:
            HealthScore with overall assessment
        """
        self._health_check_count += 1

        if not self._metrics:
            return HealthScore(
                overall_score=0.5,
                status=HealthStatus.UNKNOWN,
                success_rate_score=0.0,
                latency_score=0.0,
                error_rate_score=0.0,
                throughput_score=0.0,
                details={"note": "No operations tracked yet"},
                timestamp=time.time(),
            )

        # Aggregate metrics across all operations
        all_reports = []
        for metrics in self._metrics.values():
            report = self._calculate_operation_health(metrics)
            all_reports.append(report)

        # Calculate average scores
        avg_health = sum(r.health_score for r in all_reports) / len(all_reports)
        avg_success = sum(r.success_rate for r in all_reports) / len(all_reports)
        avg_latency = sum(r.avg_latency_ms for r in all_reports) / len(all_reports)
        avg_throughput = sum(r.throughput_ops_sec for r in all_reports) / len(all_reports)

        # Calculate overall error rate
        total_ops = sum(r.total_operations for r in all_reports)
        total_errors = sum(r.total_errors for r in all_reports)
        error_rate = total_errors / total_ops if total_ops > 0 else 0.0

        # Determine overall status
        if avg_health >= 0.8:
            status = HealthStatus.HEALTHY
        elif avg_health >= 0.5:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.UNHEALTHY

        return HealthScore(
            overall_score=round(avg_health, 3),
            status=status,
            success_rate_score=round(avg_success, 4),
            latency_score=round(self._score_latency(avg_latency), 3),
            error_rate_score=round(1.0 - error_rate, 4),
            throughput_score=round(self._score_throughput(avg_throughput), 3),
            details={
                "tracked_operations": len(all_reports),
                "total_operations": total_ops,
                "total_errors": total_errors,
                "error_rate": round(error_rate, 4),
                "avg_latency_ms": round(avg_latency, 2),
                "avg_throughput_ops_sec": round(avg_throughput, 2),
                "monitor_uptime_sec": round(time.time() - self._start_time, 1),
            },
            timestamp=time.time(),
        )

    def get_all_operation_health(self) -> List[OperationHealthReport]:
        """Get health reports for all tracked operations."""
        reports = []
        for metrics in self._metrics.values():
            reports.append(self._calculate_operation_health(metrics))

        # Sort by health score (worst first)
        reports.sort(key=lambda r: r.health_score)
        return reports

    def get_error_summary(self) -> Dict[ErrorCategory, int]:
        """Get summary of all errors by category across all operations."""
        error_summary: Dict[ErrorCategory, int] = {}
        for metrics in self._metrics.values():
            for category, count in metrics.errors_by_category.items():
                if category not in error_summary:
                    error_summary[category] = 0
                error_summary[category] += count
        return error_summary

    def get_operations_needing_attention(self, threshold: float = 0.6) -> List[OperationHealthReport]:
        """
        Get operations that need attention (health score below threshold).

        Args:
            threshold: Health score threshold below which to flag

        Returns:
            List of OperationHealthReport for operations needing attention
        """
        all_reports = self.get_all_operation_health()
        return [r for r in all_reports if r.health_score < threshold]

    def reset_metrics(self) -> None:
        """Reset all metrics (useful for testing or new monitoring periods)."""
        self._metrics.clear()
        self._total_operations = 0
        self._start_time = time.time()

    def get_monitor_stats(self) -> Dict[str, float]:
        """Get statistics about the monitor itself."""
        return {
            "tracked_operation_types": len(self._metrics),
            "total_operations_recorded": self._total_operations,
            "health_checks_performed": self._health_check_count,
            "monitor_uptime_seconds": round(time.time() - self._start_time, 2),
        }


def create_pq_health_monitor(thresholds: Optional[HealthThresholds] = None) -> PQCryptoHealthMonitor:
    """Factory function to create a new PQ crypto health monitor."""
    return PQCryptoHealthMonitor(thresholds)


def create_default_pq_health_monitor() -> PQCryptoHealthMonitor:
    """
    Create a health monitor with default production thresholds.

    Default thresholds are tuned for post-quantum crypto operations
    which tend to have higher latency than classical crypto.
    """
    thresholds = HealthThresholds(
        healthy_success_rate=0.995,
        degraded_success_rate=0.97,
        healthy_latency_p95_ms=500.0,  # PQ ops are slower
        degraded_latency_p95_ms=2000.0,
        healthy_error_rate=0.005,
        degraded_error_rate=0.03,
        min_healthy_throughput=0.5,
    )
    return PQCryptoHealthMonitor(thresholds)


# Module metadata for backward compatibility and dimension tracking
MODULE_DIMENSION = "A - Feature Expansion"
MODULE_VERSION = "v87"
MODULE_STABILITY = "stable"
MODULE_IS_ADD_ONLY = True
MODULE_PRESERVES_BACKWARD_COMPATIBILITY = True


def verify_module() -> bool:
    """Self-verification function to ensure module loads correctly."""
    try:
        monitor = create_pq_health_monitor()
        assert monitor is not None
        assert len(monitor.list_tracked_operations()) == 0

        # Record some operations
        monitor.record_success(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM,
            45.5
        )
        monitor.record_success(
            PQOperationType.VERIFICATION,
            PQAlgorithm.DILITHIUM,
            12.3
        )
        monitor.record_failure(
            PQOperationType.VERIFICATION,
            PQAlgorithm.KYBER,
            ErrorCategory.INVALID_INPUT,
            5.0
        )

        # Check metrics
        assert len(monitor.list_tracked_operations()) == 3
        assert monitor.get_monitor_stats()["total_operations_recorded"] == 3

        # Check health
        health = monitor.get_overall_health()
        assert health is not None
        assert 0.0 <= health.overall_score <= 1.0
        assert health.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED,
                                 HealthStatus.UNHEALTHY, HealthStatus.UNKNOWN)

        # Check operation health
        op_health = monitor.get_operation_health(
            PQOperationType.SIGNING,
            PQAlgorithm.DILITHIUM
        )
        assert op_health.success_rate == 1.0
        assert op_health.total_operations == 1

        # Check error summary
        errors = monitor.get_error_summary()
        assert ErrorCategory.INVALID_INPUT in errors
        assert errors[ErrorCategory.INVALID_INPUT] == 1

        # Test reset
        monitor.reset_metrics()
        assert len(monitor.list_tracked_operations()) == 0

        return True
    except Exception:
        return False
