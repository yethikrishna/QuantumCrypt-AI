"""
QuantumCrypt AI - Post-Quantum Cryptography Operation Telemetry
Dimension D: Observability & Instrumentation v10
Version: 10.0.0
Status: STABLE (OPT-IN ONLY - disabled by default)

This module provides comprehensive telemetry for post-quantum
cryptographic operations including latency distribution tracking,
operation timing, histogram metrics, and performance benchmarking.

All instrumentation is OPT-IN and disabled by default.

COMPLIES WITH INCREMENTAL BUILD PHILOSOPHY:
- ADD-ONLY: New module, no existing code modified
- WRAPPER: Wraps existing functions, no core logic changes
- OPT-IN: Disabled by default, explicit enable required
- BACKWARD COMPATIBLE: No breaking changes
"""

import os
import time
import math
import threading
import statistics
from typing import Dict, Any, Optional, Callable, TypeVar, List
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import functools

# -----------------------------------------------------------------------------
# GLOBAL CONFIGURATION - OPT-IN BY DEFAULT
# -----------------------------------------------------------------------------
# ALL instrumentation is DISABLED by default
# Must explicitly set QUANTUMCRYPT_TELEMETRY_ENABLED=1 to enable

TELEMETRY_ENABLED: bool = os.environ.get("QUANTUMCRYPT_TELEMETRY_ENABLED", "0") == "1"

# -----------------------------------------------------------------------------
# OPERATION TYPE ENUMERATION
# -----------------------------------------------------------------------------

class PQOperationType(Enum):
    """Types of post-quantum cryptographic operations"""
    KEY_GENERATION = "key_generation"
    KEY_ENCAPSULATION = "key_encapsulation"
    KEY_DECAPSULATION = "key_decapsulation"
    SIGNATURE_GENERATION = "signature_generation"
    SIGNATURE_VERIFICATION = "signature_verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    HASH_COMPUTATION = "hash_computation"
    RANDOM_GENERATION = "random_generation"
    KEY_EXCHANGE = "key_exchange"

class PQAlgorithm(Enum):
    """Post-quantum algorithms"""
    CRYSTALS_KYBER = "CRYSTALS-Kyber"
    CRYSTALS_DILITHIUM = "CRYSTALS-Dilithium"
    FALCON = "Falcon"
    SPHINCS = "SPHINCS+"
    NTRU = "NTRU"
    CLASSIC_MCELIECE = "Classic-McEliece"
    BIKE = "BIKE"
    HQC = "HQC"

# -----------------------------------------------------------------------------
# LATENCY HISTOGRAM IMPLEMENTATION
# -----------------------------------------------------------------------------

@dataclass
class LatencyHistogram:
    """Histogram for latency distribution tracking"""
    
    # Exponential bucket boundaries (microseconds)
    BUCKET_BOUNDARIES: List[float] = field(default_factory=lambda: [
        1, 2, 5, 10, 20, 50, 100, 200, 500,
        1000, 2000, 5000, 10000, 20000, 50000,
        100000, 200000, 500000, 1000000
    ])
    
    def __post_init__(self):
        self.buckets: List[int] = [0] * len(self.BUCKET_BOUNDARIES)
        self.inf_count: int = 0
        self._lock = threading.Lock()
    
    def record(self, latency_us: float) -> None:
        """Record a latency value (microseconds)"""
        with self._lock:
            for i, boundary in enumerate(self.BUCKET_BOUNDARIES):
                if latency_us <= boundary:
                    self.buckets[i] += 1
                    return
            self.inf_count += 1
    
    def get_percentile(self, p: float) -> Optional[float]:
        """Calculate approximate percentile value"""
        with self._lock:
            total = sum(self.buckets) + self.inf_count
            if total == 0:
                return None
            
            target = total * p
            cumulative = 0
            
            for i, count in enumerate(self.buckets):
                cumulative += count
                if cumulative >= target:
                    return self.BUCKET_BOUNDARIES[i]
            
            return float('inf')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert histogram to dictionary"""
        with self._lock:
            return {
                "buckets": {
                    f"<={b}us": self.buckets[i]
                    for i, b in enumerate(self.BUCKET_BOUNDARIES)
                },
                "overflow": self.inf_count,
                "total": sum(self.buckets) + self.inf_count
            }

# -----------------------------------------------------------------------------
# SLIDING WINDOW STATISTICS
# -----------------------------------------------------------------------------

@dataclass
class SlidingWindowStats:
    """Sliding window statistics for recent operations"""
    window_size: int = 1000
    
    def __post_init__(self):
        self._samples: deque = deque(maxlen=self.window_size)
        self._lock = threading.Lock()
    
    def record(self, value: float) -> None:
        """Record a sample"""
        with self._lock:
            self._samples.append(value)
    
    def get_stats(self) -> Dict[str, Optional[float]]:
        """Get current statistics"""
        with self._lock:
            samples = list(self._samples)
        
        if not samples:
            return {
                "count": 0,
                "min": None,
                "max": None,
                "mean": None,
                "median": None,
                "p50": None,
                "p90": None,
                "p95": None,
                "p99": None,
                "std_dev": None
            }
        
        sorted_samples = sorted(samples)
        n = len(samples)
        
        return {
            "count": n,
            "min": min(samples),
            "max": max(samples),
            "mean": statistics.mean(samples),
            "median": statistics.median(samples),
            "p50": sorted_samples[int(n * 0.50)],
            "p90": sorted_samples[int(n * 0.90)],
            "p95": sorted_samples[int(n * 0.95)],
            "p99": sorted_samples[int(n * 0.99)],
            "std_dev": statistics.stdev(samples) if n > 1 else 0.0
        }

# -----------------------------------------------------------------------------
# OPERATION METRICS RECORDER
# -----------------------------------------------------------------------------

@dataclass
class OperationMetrics:
    """Metrics for a specific operation type"""
    operation_type: PQOperationType
    algorithm: Optional[PQAlgorithm] = None
    
    def __post_init__(self):
        self.histogram = LatencyHistogram()
        self.sliding_window = SlidingWindowStats(window_size=1000)
        self.total_count: int = 0
        self.error_count: int = 0
        self.total_latency_us: float = 0.0
        self._lock = threading.Lock()
    
    def record_success(self, latency_us: float) -> None:
        """Record a successful operation - always works"""
        with self._lock:
            self.total_count += 1
            self.total_latency_us += latency_us
        
        self.histogram.record(latency_us)
        self.sliding_window.record(latency_us)
    
    def record_error(self, latency_us: float) -> None:
        """Record a failed operation - always works"""
        with self._lock:
            self.total_count += 1
            self.error_count += 1
            self.total_latency_us += latency_us
        
        self.histogram.record(latency_us)
        self.sliding_window.record(latency_us)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get operation metrics summary"""
        with self._lock:
            total = self.total_count
            errors = self.error_count
            total_latency = self.total_latency_us
        
        return {
            "operation": self.operation_type.value,
            "algorithm": self.algorithm.value if self.algorithm else None,
            "total_operations": total,
            "error_count": errors,
            "error_rate": (errors / total * 100) if total > 0 else 0.0,
            "average_latency_us": (total_latency / total) if total > 0 else 0.0,
            "sliding_window": self.sliding_window.get_stats(),
            "histogram": self.histogram.to_dict()
        }

# -----------------------------------------------------------------------------
# GLOBAL TELEMETRY REGISTRY
# -----------------------------------------------------------------------------

class TelemetryRegistry:
    """Global registry for all operation metrics"""
    
    def __init__(self):
        self._metrics: Dict[tuple, OperationMetrics] = {}
        self._lock = threading.Lock()
    
    def get_metrics(
        self,
        operation_type: PQOperationType,
        algorithm: Optional[PQAlgorithm] = None
    ) -> OperationMetrics:
        """Get or create metrics for an operation type"""
        key = (operation_type, algorithm)
        
        with self._lock:
            if key not in self._metrics:
                self._metrics[key] = OperationMetrics(operation_type, algorithm)
            return self._metrics[key]
    
    def record_operation(
        self,
        operation_type: PQOperationType,
        algorithm: Optional[PQAlgorithm],
        latency_us: float,
        success: bool = True
    ) -> None:
        """Record an operation"""
        if not TELEMETRY_ENABLED:
            return
        
        metrics = self.get_metrics(operation_type, algorithm)
        if success:
            metrics.record_success(latency_us)
        else:
            metrics.record_error(latency_us)
    
    def get_all_summaries(self) -> List[Dict[str, Any]]:
        """Get summaries for all tracked operations"""
        with self._lock:
            metrics_list = list(self._metrics.values())
        
        return [m.get_summary() for m in metrics_list]
    
    def reset(self) -> None:
        """Reset all metrics"""
        with self._lock:
            self._metrics.clear()

# Global telemetry registry instance
_global_registry = TelemetryRegistry()

def get_telemetry_registry() -> TelemetryRegistry:
    """Get the global telemetry registry"""
    return _global_registry

# -----------------------------------------------------------------------------
# TELEMETRY DECORATOR
# -----------------------------------------------------------------------------

T = TypeVar('T')

def telemetry(
    operation_type: PQOperationType,
    algorithm: Optional[PQAlgorithm] = None
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to add telemetry to a cryptographic operation.
    OPT-IN ONLY - does nothing unless QUANTUMCRYPT_TELEMETRY_ENABLED=1
    
    Usage:
        @telemetry(PQOperationType.KEY_GENERATION, PQAlgorithm.CRYSTALS_KYBER)
        def generate_keypair():
            # Your existing code here
            return keypair
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not TELEMETRY_ENABLED:
                return func(*args, **kwargs)
            
            registry = get_telemetry_registry()
            start_time = time.perf_counter()
            
            try:
                result = func(*args, **kwargs)
                latency_us = (time.perf_counter() - start_time) * 1_000_000
                registry.record_operation(operation_type, algorithm, latency_us, success=True)
                return result
            except Exception as e:
                latency_us = (time.perf_counter() - start_time) * 1_000_000
                registry.record_operation(operation_type, algorithm, latency_us, success=False)
                raise
        
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# CONTEXT MANAGER FOR MANUAL INSTRUMENTATION
# -----------------------------------------------------------------------------

class OperationTimer:
    """Context manager for timing cryptographic operations"""
    
    def __init__(
        self,
        operation_type: PQOperationType,
        algorithm: Optional[PQAlgorithm] = None,
        attributes: Optional[Dict[str, Any]] = None
    ):
        self.operation_type = operation_type
        self.algorithm = algorithm
        self.attributes = attributes or {}
        self.start_time: Optional[float] = None
        self.registry = get_telemetry_registry()
    
    def __enter__(self):
        if TELEMETRY_ENABLED:
            self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if not TELEMETRY_ENABLED or self.start_time is None:
            return
        
        latency_us = (time.perf_counter() - self.start_time) * 1_000_000
        success = exc_type is None
        
        self.registry.record_operation(
            self.operation_type,
            self.algorithm,
            latency_us,
            success=success
        )
        
        # Don't suppress exceptions
        return False

# -----------------------------------------------------------------------------
# BENCHMARKING UTILITIES
# -----------------------------------------------------------------------------

def benchmark_operation(
    func: Callable,
    iterations: int = 100,
    warmup: int = 10,
    args: tuple = (),
    **kwargs
) -> Dict[str, Any]:
    """
    Benchmark a cryptographic operation.
    Always works regardless of TELEMETRY_ENABLED setting.
    
    Returns detailed benchmark statistics.
    """
    # Warmup runs
    for _ in range(warmup):
        func(*args, **kwargs)
    
    # Timed runs
    latencies_us = []
    errors = 0
    
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            func(*args, **kwargs)
            latency_us = (time.perf_counter() - start) * 1_000_000
            latencies_us.append(latency_us)
        except Exception:
            errors += 1
    
    latencies_us.sort()
    n = len(latencies_us)
    
    if n == 0:
        return {
            "iterations": iterations,
            "successful": 0,
            "errors": errors,
            "error_rate": 100.0
        }
    
    return {
        "iterations": iterations,
        "successful": n,
        "errors": errors,
        "error_rate": (errors / iterations) * 100,
        "min_us": min(latencies_us),
        "max_us": max(latencies_us),
        "mean_us": statistics.mean(latencies_us),
        "median_us": statistics.median(latencies_us),
        "p50_us": latencies_us[int(n * 0.50)],
        "p90_us": latencies_us[int(n * 0.90)],
        "p95_us": latencies_us[int(n * 0.95)],
        "p99_us": latencies_us[int(n * 0.99)],
        "std_dev_us": statistics.stdev(latencies_us) if n > 1 else 0.0,
        "operations_per_second": 1_000_000 / statistics.mean(latencies_us)
    }

# -----------------------------------------------------------------------------
# HEALTH CHECK INTEGRATION
# -----------------------------------------------------------------------------

def get_health_status() -> Dict[str, Any]:
    """
    Get telemetry-based health status.
    Always returns a valid status dict regardless of enable flag.
    """
    if not TELEMETRY_ENABLED:
        return {
            "status": "disabled",
            "message": "PQ operation telemetry is disabled (OPT-IN only)",
            "enabled": False
        }
    
    registry = get_telemetry_registry()
    summaries = registry.get_all_summaries()
    
    total_ops = sum(s["total_operations"] for s in summaries)
    total_errors = sum(s["error_count"] for s in summaries)
    
    error_rate = (total_errors / total_ops * 100) if total_ops > 0 else 0
    
    health_status = "healthy"
    if error_rate > 5.0:
        health_status = "degraded"
    if error_rate > 20.0:
        health_status = "unhealthy"
    
    return {
        "status": health_status,
        "enabled": True,
        "total_operations": total_ops,
        "total_errors": total_errors,
        "error_rate_pct": error_rate,
        "tracked_operations": len(summaries),
        "operations": summaries
    }

# -----------------------------------------------------------------------------
# METRICS EXPORT
# -----------------------------------------------------------------------------

def export_prometheus_format() -> str:
    """Export metrics in Prometheus text format"""
    lines = [
        "# HELP quantumcrypt_pq_operations_total Total PQ operations",
        "# TYPE quantumcrypt_pq_operations_total counter",
        "# HELP quantumcrypt_pq_operations_errors_total Total PQ operation errors",
        "# TYPE quantumcrypt_pq_operations_errors_total counter",
        "# HELP quantumcrypt_pq_latency_us PQ operation latency in microseconds",
        "# TYPE quantumcrypt_pq_latency_us summary"
    ]
    
    if not TELEMETRY_ENABLED:
        return "\n".join(lines) + "\n# Telemetry is disabled (OPT-IN only)\n"
    
    registry = get_telemetry_registry()
    summaries = registry.get_all_summaries()
    
    for summary in summaries:
        op = summary["operation"]
        alg = summary["algorithm"] or "unknown"
        
        labels = f'operation="{op}",algorithm="{alg}"'
        
        lines.append(f'quantumcrypt_pq_operations_total{{{labels}}} {summary["total_operations"]}')
        lines.append(f'quantumcrypt_pq_operations_errors_total{{{labels}}} {summary["error_count"]}')
        
        sw = summary["sliding_window"]
        if sw["count"] > 0:
            lines.append(f'quantumcrypt_pq_latency_us{{{labels},quantile="0.5"}} {sw["p50"]:.2f}')
            lines.append(f'quantumcrypt_pq_latency_us{{{labels},quantile="0.9"}} {sw["p90"]:.2f}')
            lines.append(f'quantumcrypt_pq_latency_us{{{labels},quantile="0.99"}} {sw["p99"]:.2f}')
    
    return "\n".join(lines) + "\n"

# -----------------------------------------------------------------------------
# USAGE EXAMPLES (DOCUMENTATION)
# -----------------------------------------------------------------------------

"""
EXAMPLE USAGE - OPT-IN ONLY:

1. Enable telemetry:
   export QUANTUMCRYPT_TELEMETRY_ENABLED=1

2. Instrument functions with decorator:
   from quantum_crypt.crypto_observability_pq_operation_telemetry_latency_v10_2026_june import (
       telemetry, PQOperationType, PQAlgorithm
   )

   @telemetry(PQOperationType.KEY_GENERATION, PQAlgorithm.CRYSTALS_KYBER)
   def kyber_generate_keypair():
       # Your existing key generation code
       return public_key, private_key

3. Manual instrumentation with context manager:
   with OperationTimer(PQOperationType.ENCRYPTION, PQAlgorithm.CRYSTALS_KYBER):
       ciphertext = encrypt(data, public_key)

4. Benchmark operations:
   result = benchmark_operation(kyber_generate_keypair, iterations=1000)
   print(f"Mean latency: {result['mean_us']:.2f}us")
   print(f"Throughput: {result['operations_per_second']:.0f} ops/sec")

5. Get health status:
   status = get_health_status()
   print(f"Health: {status['status']}, Error rate: {status['error_rate_pct']:.1f}%")

6. Export Prometheus metrics:
   metrics = export_prometheus_format()
   # Serve via HTTP endpoint
"""

# -----------------------------------------------------------------------------
# SANITY CHECK - ENSURE NO SIDE EFFECTS WHEN DISABLED
# -----------------------------------------------------------------------------

# This module has ZERO runtime impact when TELEMETRY_ENABLED is False (default)
# All instrumentation paths are guarded by the TELEMETRY_ENABLED flag
# No monkey-patching, no global side effects
# Purely additive and opt-in only
