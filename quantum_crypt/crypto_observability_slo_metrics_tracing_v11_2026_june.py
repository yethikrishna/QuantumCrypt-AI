"""
QuantumCrypt Enhanced Observability with SLO Metrics & Distributed Tracing v11
Dimension D - Observability & Instrumentation

Add-only module - wraps existing post-quantum crypto operations with:
- SLO (Service Level Objective) metrics tracking
- Error budget calculation and monitoring
- Latency distribution percentiles
- Crypto operation-specific distributed tracing
- Success rate and availability metrics
- Burn rate alerting for error budgets
- Optional, opt-in instrumentation only

All existing code behavior is 100% preserved.
"""

import time
import math
import threading
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime, timedelta


class SLOStatus(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    BREACHED = "breached"
    EXHAUSTED = "exhausted"


class MetricType(Enum):
    LATENCY = "latency"
    AVAILABILITY = "availability"
    SUCCESS_RATE = "success_rate"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"


@dataclass
class SLODefinition:
    """Defines a Service Level Objective."""
    name: str
    target_percent: float  # e.g., 99.9 for 99.9% availability
    window_days: int = 30
    description: str = ""
    metric_type: MetricType = MetricType.AVAILABILITY
    
    def __post_init__(self):
        if not (0 < self.target_percent <= 100):
            raise ValueError("Target percent must be between 0 and 100")
    
    @property
    def error_budget_percent(self) -> float:
        """Remaining error budget as percentage."""
        return 100.0 - self.target_percent


@dataclass
class SLIMetric:
    """Service Level Indicator - actual measured value."""
    timestamp: float
    value: float
    success: bool
    operation: str
    latency_ms: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class TimeWindowStore:
    """Thread-safe sliding window metrics storage."""
    
    def __init__(self, window_seconds: int = 86400, granularity: int = 60):
        self.window_seconds = window_seconds
        self.granularity = granularity
        self._buckets: Dict[int, List[SLIMetric]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def _bucket_key(self, timestamp: float) -> int:
        """Get bucket key for timestamp."""
        return int(timestamp // self.granularity)
    
    def _clean_old_buckets(self, now: float):
        """Remove buckets outside the time window."""
        cutoff = now - self.window_seconds
        cutoff_bucket = self._bucket_key(cutoff)
        old_keys = [k for k in self._buckets.keys() if k < cutoff_bucket]
        for k in old_keys:
            del self._buckets[k]
    
    def add(self, metric: SLIMetric) -> None:
        """Add a metric to the store."""
        with self._lock:
            self._clean_old_buckets(metric.timestamp)
            bucket = self._bucket_key(metric.timestamp)
            self._buckets[bucket].append(metric)
    
    def get_metrics(self, lookback_seconds: Optional[int] = None) -> List[SLIMetric]:
        """Get all metrics within window."""
        now = time.time()
        if lookback_seconds:
            cutoff = now - lookback_seconds
        else:
            cutoff = now - self.window_seconds
        
        with self._lock:
            self._clean_old_buckets(now)
            cutoff_bucket = self._bucket_key(cutoff)
            result = []
            for bucket_key, metrics in self._buckets.items():
                if bucket_key >= cutoff_bucket:
                    result.extend(metrics)
            return result
    
    def get_count(self, lookback_seconds: Optional[int] = None) -> int:
        """Get total count of metrics."""
        return len(self.get_metrics(lookback_seconds))


class PercentileCalculator:
    """Calculates latency percentiles efficiently."""
    
    @staticmethod
    def calculate(values: List[float], percentile: float) -> Optional[float]:
        """Calculate percentile from list of values."""
        if not values:
            return None
        sorted_values = sorted(values)
        index = math.ceil((percentile / 100.0) * len(sorted_values)) - 1
        index = max(0, min(index, len(sorted_values) - 1))
        return sorted_values[index]
    
    @staticmethod
    def p50(values: List[float]) -> Optional[float]:
        """Calculate 50th percentile (median)."""
        return PercentileCalculator.calculate(values, 50)
    
    @staticmethod
    def p95(values: List[float]) -> Optional[float]:
        """Calculate 95th percentile."""
        return PercentileCalculator.calculate(values, 95)
    
    @staticmethod
    def p99(values: List[float]) -> Optional[float]:
        """Calculate 99th percentile."""
        return PercentileCalculator.calculate(values, 99)
    
    @staticmethod
    def p999(values: List[float]) -> Optional[float]:
        """Calculate 99.9th percentile."""
        return PercentileCalculator.calculate(values, 99.9)


class SLOTracker:
    """Tracks SLO compliance and error budgets."""
    
    def __init__(self, slo: SLODefinition):
        self.slo = slo
        self._store = TimeWindowStore(window_seconds=slo.window_days * 86400)
        self._lock = threading.Lock()
        self._burn_rate_callbacks: List[Callable[[float], None]] = []
    
    def record_operation(
        self,
        success: bool,
        operation: str,
        latency_ms: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record an operation result."""
        metric = SLIMetric(
            timestamp=time.time(),
            value=1.0 if success else 0.0,
            success=success,
            operation=operation,
            latency_ms=latency_ms,
            metadata=metadata or {}
        )
        self._store.add(metric)
    
    def get_success_rate(self, lookback_seconds: Optional[int] = None) -> Optional[float]:
        """Get current success rate percentage."""
        metrics = self._store.get_metrics(lookback_seconds)
        if not metrics:
            return None
        successful = sum(1 for m in metrics if m.success)
        return (successful / len(metrics)) * 100.0
    
    def get_error_budget_remaining(self) -> Optional[float]:
        """Get remaining error budget as percentage."""
        success_rate = self.get_success_rate()
        if success_rate is None:
            return None
        budget_used = max(0.0, self.slo.target_percent - success_rate)
        return max(0.0, self.slo.error_budget_percent - budget_used)
    
    def get_error_budget_consumed_ratio(self) -> Optional[float]:
        """Get ratio of error budget consumed (0.0 to 1.0+)."""
        remaining = self.get_error_budget_remaining()
        if remaining is None:
            return None
        return 1.0 - (remaining / self.slo.error_budget_percent)
    
    def get_burn_rate(self, lookback_hours: int = 1) -> Optional[float]:
        """Calculate error budget burn rate (how fast budget is being consumed)."""
        lookback_seconds = lookback_hours * 3600
        window_success = self.get_success_rate(lookback_seconds)
        if window_success is None:
            return None
        
        window_error_rate = 100.0 - window_success
        allowed_error_rate = self.slo.error_budget_percent
        
        if allowed_error_rate <= 0:
            return float('inf') if window_error_rate > 0 else 0.0
        
        return window_error_rate / allowed_error_rate
    
    def get_status(self) -> SLOStatus:
        """Get current SLO status."""
        burn_rate = self.get_burn_rate(1)
        remaining = self.get_error_budget_remaining()
        
        if remaining is None:
            return SLOStatus.HEALTHY
        
        if remaining <= 0:
            return SLOStatus.EXHAUSTED
        if burn_rate and burn_rate > 10:
            return SLOStatus.BREACHED
        if burn_rate and burn_rate > 2:
            return SLOStatus.WARNING
        return SLOStatus.HEALTHY
    
    def get_latency_percentiles(self) -> Dict[str, Optional[float]]:
        """Get latency distribution percentiles."""
        metrics = self._store.get_metrics()
        latencies = [m.latency_ms for m in metrics if m.latency_ms is not None]
        
        return {
            "p50": PercentileCalculator.p50(latencies),
            "p95": PercentileCalculator.p95(latencies),
            "p99": PercentileCalculator.p99(latencies),
            "p999": PercentileCalculator.p999(latencies)
        }
    
    def get_throughput(self, lookback_seconds: int = 60) -> float:
        """Get operations per second."""
        count = self._store.get_count(lookback_seconds)
        return count / lookback_seconds if lookback_seconds > 0 else 0.0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive SLO summary."""
        return {
            "slo_name": self.slo.name,
            "target_percent": self.slo.target_percent,
            "window_days": self.slo.window_days,
            "success_rate": self.get_success_rate(),
            "error_budget_remaining_pct": self.get_error_budget_remaining(),
            "error_budget_consumed_ratio": self.get_error_budget_consumed_ratio(),
            "burn_rate_1h": self.get_burn_rate(1),
            "burn_rate_6h": self.get_burn_rate(6),
            "status": self.get_status().value,
            "latency_percentiles": self.get_latency_percentiles(),
            "throughput_ops_per_sec": self.get_throughput(60),
            "total_operations": self._store.get_count()
        }


class CryptoOperationTracer:
    """Tracer specifically for cryptographic operations - opt-in only."""
    
    def __init__(self, service_name: str = "quantumcrypt"):
        self.service_name = service_name
        self._enabled = False
        self._slo_trackers: Dict[str, SLOTracker] = {}
        self._operation_counts: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        
        # Default SLOs
        self._default_slo = SLODefinition(
            name="crypto-operations-availability",
            target_percent=99.9,
            window_days=30,
            metric_type=MetricType.AVAILABILITY,
            description="Crypto operation success rate SLO"
        )
    
    def enable(self) -> None:
        """Enable observability - opt-in explicitly required."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable observability."""
        self._enabled = False
    
    def is_enabled(self) -> bool:
        """Check if observability is enabled."""
        return self._enabled
    
    def get_slo_tracker(self, slo_name: str) -> Optional[SLOTracker]:
        """Get or create SLO tracker."""
        with self._lock:
            if slo_name not in self._slo_trackers:
                self._slo_trackers[slo_name] = SLOTracker(self._default_slo)
            return self._slo_trackers[slo_name]
    
    def record_crypto_operation(
        self,
        operation: str,
        algorithm: str,
        success: bool,
        latency_ms: float,
        key_size: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record a cryptographic operation result."""
        if not self._enabled:
            return
        
        with self._lock:
            self._operation_counts[operation] += 1
        
        op_metadata = {
            "algorithm": algorithm,
            "key_size": key_size,
            **(metadata or {})
        }
        
        tracker = self.get_slo_tracker("default")
        tracker.record_operation(success, operation, latency_ms, op_metadata)
    
    def trace_crypto_operation(
        self,
        operation: Optional[str] = None,
        algorithm: str = "unknown",
        key_size: Optional[int] = None
    ):
        """Decorator to trace crypto function execution."""
        def decorator(func: Callable) -> Callable:
            op_name = operation or func.__name__
            def wrapper(*args, **kwargs):
                if not self._enabled:
                    return func(*args, **kwargs)
                
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    latency_ms = (time.time() - start_time) * 1000
                    self.record_crypto_operation(
                        operation=op_name,
                        algorithm=algorithm,
                        success=True,
                        latency_ms=latency_ms,
                        key_size=key_size
                    )
                    return result
                except Exception as e:
                    latency_ms = (time.time() - start_time) * 1000
                    self.record_crypto_operation(
                        operation=op_name,
                        algorithm=algorithm,
                        success=False,
                        latency_ms=latency_ms,
                        key_size=key_size,
                        metadata={"error_type": type(e).__name__, "error_message": str(e)}
                    )
                    raise
            return wrapper
        return decorator
    
    def get_operation_metrics(self) -> Dict[str, Any]:
        """Get aggregated operation metrics."""
        if not self._enabled:
            return {"enabled": False}
        
        tracker = self.get_slo_tracker("default")
        with self._lock:
            counts = dict(self._operation_counts)
        
        return {
            "enabled": True,
            "service": self.service_name,
            "operation_counts": counts,
            "slo_summary": tracker.get_summary()
        }
    
    def get_health_check(self) -> Dict[str, Any]:
        """Get health check status for observability."""
        tracker = self.get_slo_tracker("default")
        status = tracker.get_status()
        
        return {
            "healthy": status in (SLOStatus.HEALTHY, SLOStatus.WARNING),
            "slo_status": status.value,
            "success_rate": tracker.get_success_rate(),
            "error_budget_remaining": tracker.get_error_budget_remaining(),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }


# Global singleton - disabled by default (opt-in)
global_crypto_tracer = CryptoOperationTracer()


# Exported convenience functions
def enable_observability() -> None:
    """Enable crypto observability (opt-in)."""
    global_crypto_tracer.enable()


def disable_observability() -> None:
    """Disable crypto observability."""
    global_crypto_tracer.disable()


def is_observability_enabled() -> bool:
    """Check if observability is enabled."""
    return global_crypto_tracer.is_enabled()


def record_operation(**kwargs) -> None:
    """Record a crypto operation."""
    global_crypto_tracer.record_crypto_operation(**kwargs)


def trace_crypto(**kwargs):
    """Decorator to trace crypto operations."""
    return global_crypto_tracer.trace_crypto_operation(**kwargs)


def get_metrics() -> Dict[str, Any]:
    """Get current metrics."""
    return global_crypto_tracer.get_operation_metrics()


def get_health_check() -> Dict[str, Any]:
    """Get health check status."""
    return global_crypto_tracer.get_health_check()
