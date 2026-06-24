"""
Observability: Post-Quantum Key Operation Metrics with SLO Monitoring v28
DIMENSION D - Observability & Instrumentation

This module provides OPT-IN metrics collection with SLO monitoring for
post-quantum cryptographic operations. All instrumentation is disabled by
default and must be explicitly enabled.

Philosophy: WRAP, DON'T REPLACE. Layer on top of existing code.
"""

import os
import time
import threading
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from datetime import datetime, timedelta


class CryptoOperation(Enum):
    """Standard crypto operations for metrics tracking"""
    KEY_GENERATION = "key_generation"
    KEY_ENCAPSULATION = "key_encapsulation"
    KEY_DECAPSULATION = "key_decapsulation"
    SIGNATURE_GENERATION = "signature_generation"
    SIGNATURE_VERIFICATION = "signature_verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    HASH_COMPUTATION = "hash_computation"
    HMAC_GENERATION = "hmac_generation"
    KDF_DERIVATION = "kdf_derivation"
    RANDOM_GENERATION = "random_generation"
    CERTIFICATE_SIGNING = "certificate_signing"
    CERTIFICATE_VERIFICATION = "certificate_verification"


class SLOStatus(Enum):
    """SLO compliance status"""
    OK = "ok"
    WARNING = "warning"
    BREACH = "breach"


@dataclass
class SLOThreshold:
    """SLO threshold configuration"""
    operation: CryptoOperation
    latency_p95_ms: float  # 95th percentile latency target
    error_rate_max: float  # Max allowed error rate (0.0-1.0)
    availability_min: float  # Min required availability (0.0-1.0)
    throughput_min: float  # Min required ops/second


@dataclass
class OperationMetrics:
    """Metrics for a single operation type"""
    operation: CryptoOperation
    latencies: list = field(default_factory=list)
    errors: int = 0
    successes: int = 0
    window_start: float = field(default_factory=time.time)
    window_seconds: int = 300  # 5-minute window

    @property
    def total(self) -> int:
        return self.successes + self.errors

    @property
    def error_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.errors / self.total

    @property
    def availability(self) -> float:
        if self.total == 0:
            return 1.0
        return self.successes / self.total

    @property
    def throughput_ops_sec(self) -> float:
        elapsed = time.time() - self.window_start
        if elapsed <= 0:
            return 0.0
        return self.total / elapsed

    def get_percentile(self, p: float) -> float:
        """Get latency percentile (0-100)"""
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        idx = int(len(sorted_latencies) * p / 100)
        return sorted_latencies[min(idx, len(sorted_latencies) - 1)]

    def record_success(self, latency_ms: float):
        """Record a successful operation"""
        self._maybe_rotate_window()
        self.successes += 1
        self.latencies.append(latency_ms)
        if len(self.latencies) > 10000:
            self.latencies = self.latencies[-5000:]

    def record_error(self, latency_ms: float):
        """Record a failed operation"""
        self._maybe_rotate_window()
        self.errors += 1
        self.latencies.append(latency_ms)
        if len(self.latencies) > 10000:
            self.latencies = self.latencies[-5000:]

    def _maybe_rotate_window(self):
        """Rotate metrics window if expired"""
        elapsed = time.time() - self.window_start
        if elapsed > self.window_seconds:
            self.latencies = []
            self.errors = 0
            self.successes = 0
            self.window_start = time.time()


@dataclass
class SLOResult:
    """SLO compliance check result"""
    operation: CryptoOperation
    status: SLOStatus
    latency_p95_ms: float
    latency_target: float
    error_rate: float
    error_rate_max: float
    availability: float
    availability_min: float
    throughput: float
    throughput_min: float
    violations: list = field(default_factory=list)


class CryptoMetrics:
    """OPT-IN metrics collector for crypto operations
    
    Disabled by default. Enable with:
        CryptoMetrics.enable()
    """
    
    _enabled: bool = False
    _metrics: Dict[CryptoOperation, OperationMetrics] = {}
    _slo_thresholds: Dict[CryptoOperation, SLOThreshold] = {}
    _lock = threading.Lock()
    _default_slos = {
        CryptoOperation.KEY_GENERATION: SLOThreshold(
            operation=CryptoOperation.KEY_GENERATION,
            latency_p95_ms=100.0,
            error_rate_max=0.01,
            availability_min=0.999,
            throughput_min=10.0
        ),
        CryptoOperation.KEY_ENCAPSULATION: SLOThreshold(
            operation=CryptoOperation.KEY_ENCAPSULATION,
            latency_p95_ms=50.0,
            error_rate_max=0.001,
            availability_min=0.9999,
            throughput_min=50.0
        ),
        CryptoOperation.KEY_DECAPSULATION: SLOThreshold(
            operation=CryptoOperation.KEY_DECAPSULATION,
            latency_p95_ms=50.0,
            error_rate_max=0.001,
            availability_min=0.9999,
            throughput_min=50.0
        ),
        CryptoOperation.SIGNATURE_GENERATION: SLOThreshold(
            operation=CryptoOperation.SIGNATURE_GENERATION,
            latency_p95_ms=100.0,
            error_rate_max=0.005,
            availability_min=0.9995,
            throughput_min=20.0
        ),
        CryptoOperation.SIGNATURE_VERIFICATION: SLOThreshold(
            operation=CryptoOperation.SIGNATURE_VERIFICATION,
            latency_p95_ms=20.0,
            error_rate_max=0.001,
            availability_min=0.9999,
            throughput_min=100.0
        ),
        CryptoOperation.ENCRYPTION: SLOThreshold(
            operation=CryptoOperation.ENCRYPTION,
            latency_p95_ms=10.0,
            error_rate_max=0.001,
            availability_min=0.9999,
            throughput_min=500.0
        ),
        CryptoOperation.DECRYPTION: SLOThreshold(
            operation=CryptoOperation.DECRYPTION,
            latency_p95_ms=10.0,
            error_rate_max=0.001,
            availability_min=0.9999,
            throughput_min=500.0
        ),
    }

    @classmethod
    def enable(cls):
        """Enable metrics collection (OPT-IN only)"""
        with cls._lock:
            cls._enabled = True
            # Initialize default metrics
            for op in CryptoOperation:
                if op not in cls._metrics:
                    cls._metrics[op] = OperationMetrics(operation=op)
                if op not in cls._slo_thresholds and op in cls._default_slos:
                    cls._slo_thresholds[op] = cls._default_slos[op]

    @classmethod
    def disable(cls):
        """Disable metrics collection"""
        with cls._lock:
            cls._enabled = False

    @classmethod
    def is_enabled(cls) -> bool:
        return cls._enabled and os.environ.get("QUANTUMCRYPT_METRICS_ENABLED", "0") == "1"

    @classmethod
    def record_operation(
        cls,
        operation: CryptoOperation,
        latency_ms: float,
        success: bool = True
    ):
        """Record a crypto operation if metrics are enabled"""
        if not cls.is_enabled():
            return

        with cls._lock:
            if operation not in cls._metrics:
                cls._metrics[operation] = OperationMetrics(operation=operation)

            if success:
                cls._metrics[operation].record_success(latency_ms)
            else:
                cls._metrics[operation].record_error(latency_ms)

    @classmethod
    def get_metrics(cls, operation: CryptoOperation) -> Optional[OperationMetrics]:
        """Get metrics for an operation"""
        with cls._lock:
            return cls._metrics.get(operation)

    @classmethod
    def get_all_metrics(cls) -> Dict[CryptoOperation, OperationMetrics]:
        """Get all metrics"""
        with cls._lock:
            return dict(cls._metrics)

    @classmethod
    def check_slo(cls, operation: CryptoOperation) -> Optional[SLOResult]:
        """Check SLO compliance for an operation"""
        with cls._lock:
            if operation not in cls._metrics or operation not in cls._slo_thresholds:
                return None

            metrics = cls._metrics[operation]
            threshold = cls._slo_thresholds[operation]
            violations = []

            latency_p95 = metrics.get_percentile(95)
            if latency_p95 > threshold.latency_p95_ms:
                violations.append(f"Latency P95 exceeded: {latency_p95:.2f}ms > {threshold.latency_p95_ms}ms")

            if metrics.error_rate > threshold.error_rate_max:
                violations.append(f"Error rate exceeded: {metrics.error_rate:.4f} > {threshold.error_rate_max}")

            if metrics.availability < threshold.availability_min:
                violations.append(f"Availability below target: {metrics.availability:.4f} < {threshold.availability_min}")

            if metrics.total > 10 and metrics.throughput_ops_sec < threshold.throughput_min:
                violations.append(f"Throughput below target: {metrics.throughput_ops_sec:.2f} < {threshold.throughput_min}")

            if not violations:
                status = SLOStatus.OK
            elif len(violations) == 1:
                status = SLOStatus.WARNING
            else:
                status = SLOStatus.BREACH

            return SLOResult(
                operation=operation,
                status=status,
                latency_p95_ms=latency_p95,
                latency_target=threshold.latency_p95_ms,
                error_rate=metrics.error_rate,
                error_rate_max=threshold.error_rate_max,
                availability=metrics.availability,
                availability_min=threshold.availability_min,
                throughput=metrics.throughput_ops_sec,
                throughput_min=threshold.throughput_min,
                violations=violations
            )

    @classmethod
    def check_all_slos(cls) -> Dict[CryptoOperation, SLOResult]:
        """Check SLO compliance for all operations"""
        results = {}
        for op in cls._slo_thresholds.keys():
            result = cls.check_slo(op)
            if result:
                results[op] = result
        return results

    @classmethod
    def get_overall_slo_status(cls) -> SLOStatus:
        """Get overall SLO status across all operations"""
        results = cls.check_all_slos().values()
        statuses = [r.status for r in results]
        
        if SLOStatus.BREACH in statuses:
            return SLOStatus.BREACH
        if SLOStatus.WARNING in statuses:
            return SLOStatus.WARNING
        return SLOStatus.OK

    @classmethod
    def set_custom_threshold(cls, threshold: SLOThreshold):
        """Set a custom SLO threshold"""
        with cls._lock:
            cls._slo_thresholds[threshold.operation] = threshold

    @classmethod
    def reset_metrics(cls):
        """Reset all metrics (for testing)"""
        with cls._lock:
            cls._metrics = {}
            for op in CryptoOperation:
                cls._metrics[op] = OperationMetrics(operation=op)


def measured(operation: CryptoOperation):
    """Decorator for OPT-IN metrics measurement of crypto operations
    
    Usage:
        @measured(CryptoOperation.KEY_GENERATION)
        def generate_key():
            ...
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            if not CryptoMetrics.is_enabled():
                return func(*args, **kwargs)

            start = time.time()
            try:
                result = func(*args, **kwargs)
                latency = (time.time() - start) * 1000
                CryptoMetrics.record_operation(operation, latency, success=True)
                return result
            except Exception as e:
                latency = (time.time() - start) * 1000
                CryptoMetrics.record_operation(operation, latency, success=False)
                raise
        return wrapper
    return decorator


class MetricsExporter:
    """Export metrics in various formats (OPT-IN)"""

    @staticmethod
    def to_prometheus() -> str:
        """Export metrics in Prometheus format"""
        if not CryptoMetrics.is_enabled():
            return ""

        lines = []
        metrics = CryptoMetrics.get_all_metrics()
        
        for op, m in metrics.items():
            op_name = op.value
            
            lines.append(f"# HELP crypto_{op_name}_total Total {op_name} operations")
            lines.append(f"# TYPE crypto_{op_name}_total counter")
            lines.append(f"crypto_{op_name}_total {m.total}")
            
            lines.append(f"# HELP crypto_{op_name}_errors Total {op_name} errors")
            lines.append(f"# TYPE crypto_{op_name}_errors counter")
            lines.append(f"crypto_{op_name}_errors {m.errors}")
            
            lines.append(f"# HELP crypto_{op_name}_error_rate {op_name} error rate")
            lines.append(f"# TYPE crypto_{op_name}_error_rate gauge")
            lines.append(f"crypto_{op_name}_error_rate {m.error_rate:.6f}")
            
            for pct in [50, 90, 95, 99]:
                val = m.get_percentile(pct)
                lines.append(f"# HELP crypto_{op_name}_latency_p{pct}_ms {op_name} latency P{pct}")
                lines.append(f"# TYPE crypto_{op_name}_latency_p{pct}_ms gauge")
                lines.append(f"crypto_{op_name}_latency_p{pct}_ms {val:.3f}")

        return "\n".join(lines)

    @staticmethod
    def to_json() -> Dict[str, Any]:
        """Export metrics as JSON-serializable dict"""
        if not CryptoMetrics.is_enabled():
            return {}

        result = {}
        metrics = CryptoMetrics.get_all_metrics()
        
        for op, m in metrics.items():
            result[op.value] = {
                "total": m.total,
                "successes": m.successes,
                "errors": m.errors,
                "error_rate": m.error_rate,
                "availability": m.availability,
                "throughput_ops_sec": m.throughput_ops_sec,
                "latency_p50_ms": m.get_percentile(50),
                "latency_p90_ms": m.get_percentile(90),
                "latency_p95_ms": m.get_percentile(95),
                "latency_p99_ms": m.get_percentile(99),
            }
        
        return result


# Export public API
__all__ = [
    "CryptoMetrics",
    "CryptoOperation",
    "SLOStatus",
    "SLOThreshold",
    "SLOResult",
    "OperationMetrics",
    "measured",
    "MetricsExporter",
]
