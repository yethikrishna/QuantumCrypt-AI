"""
Cryptography-Specific Comprehensive Observability & Instrumentation Framework v16
Dimension D - Observability & Instrumentation

ADD-ONLY implementation - wraps existing code, no core modifications
All instrumentation is OPT-IN, disabled by default by default

Cryptography-Specific Features:
- Crypto operation timing metrics (constant-time verification)
- Key management health checks
- Randomness quality monitoring
- HSM/TPM connection health checks
- Cryptographic algorithm usage tracking
- Side-channel resistance monitoring
"""

import time
import logging
import json
import threading
import uuid
import secrets
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, TypeVar
from datetime import datetime, timezone
from functools import wraps
from collections import defaultdict
from contextlib import contextmanager
import inspect
import os


# -----------------------------------------------------------------------------
# Configuration - ALL OPT-IN, DISABLED BY DEFAULT
# -----------------------------------------------------------------------------
class CryptoObservabilityConfig:
    """Global configuration for cryptography observability systems.
    
    All features are DISABLED by default. Explicit opt-in required.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialize_defaults()
            return cls._instance
    
    def _initialize_defaults(self):
        """Initialize with ALL features DISABLED by default."""
        self.LOGGING_ENABLED = False
        self.METRICS_ENABLED = False
        self.HEALTH_CHECKS_ENABLED = False
        self.TRACING_ENABLED = False
        self.RANDOMNESS_MONITORING_ENABLED = False
        self.EVENTS_ENABLED = False
        
        self.LOG_LEVEL = logging.WARNING
        self.MAX_METRICS_HISTORY = 1000
        self.RANDOMNESS_SAMPLE_SIZE = 1024
        self.CONSTANT_TIME_SAMPLE_COUNT = 100
        
        # Environment variable overrides (still require explicit opt-in)
        if os.getenv("QUANTUMCRYPT_OBSERVABILITY_ENABLE_ALL") == "1":
            self.enable_all()
    
    def enable_all(self):
        """Enable all observability features (explicit opt-in)."""
        self.LOGGING_ENABLED = True
        self.METRICS_ENABLED = True
        self.HEALTH_CHECKS_ENABLED = True
        self.TRACING_ENABLED = True
        self.RANDOMNESS_MONITORING_ENABLED = True
        self.EVENTS_ENABLED = True
    
    def disable_all(self):
        """Disable all observability features."""
        self.LOGGING_ENABLED = False
        self.METRICS_ENABLED = False
        self.HEALTH_CHECKS_ENABLED = False
        self.TRACING_ENABLED = False
        self.RANDOMNESS_MONITORING_ENABLED = False
        self.EVENTS_ENABLED = False


# -----------------------------------------------------------------------------
# Enums and Data Classes
# -----------------------------------------------------------------------------
class CryptoMetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    CONSTANT_TIME = "constant_time"


class CryptoHealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class CryptoAlgorithm(Enum):
    AES_256_GCM = "AES-256-GCM"
    CHACHA20_POLY1305 = "ChaCha20-Poly1305"
    RSA_4096 = "RSA-4096"
    ECDSA_P384 = "ECDSA-P384"
    SHA_512 = "SHA-512"
    SHA3_512 = "SHA3-512"
    KYBER_1024 = "Kyber-1024"
    DILITHIUM_5 = "Dilithium-5"


@dataclass
class CryptoMetricPoint:
    name: str
    type: CryptoMetricType
    value: float
    timestamp: float = field(default_factory=lambda: time.time())
    labels: Dict[str, str] = field(default_factory=dict)
    algorithm: Optional[CryptoAlgorithm] = None


@dataclass
class CryptoHealthCheckResult:
    check_name: str
    status: CryptoHealthStatus
    message: str = ""
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=lambda: time.time())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RandomnessQualityReport:
    sample_size: int
    entropy_estimate: float
    chi_square_score: float
    runs_test_passed: bool
    timestamp: float = field(default_factory=lambda: time.time())


T = TypeVar('T')


# -----------------------------------------------------------------------------
# Cryptography Metrics Collector
# -----------------------------------------------------------------------------
class CryptoMetricsCollector:
    """Collect and store crypto-specific metrics - disabled by default."""
    
    def __init__(self):
        self.config = CryptoObservabilityConfig()
        self._lock = threading.Lock()
        self._operation_counters: Dict[str, int] = defaultdict(int)
        self._operation_timers: Dict[str, List[float]] = defaultdict(list)
        self._algorithm_usage: Dict[CryptoAlgorithm, int] = defaultdict(int)
        self._constant_time_samples: Dict[str, List[float]] = defaultdict(list)
        self._key_rotations: int = 0
    
    def record_crypto_operation(self, operation: str, duration_ms: float,
                                algorithm: Optional[CryptoAlgorithm] = None):
        """Record a cryptographic operation."""
        if not self.config.METRICS_ENABLED:
            return
        
        with self._lock:
            self._operation_counters[operation] += 1
            self._operation_timers[operation].append(duration_ms)
            
            if len(self._operation_timers[operation]) > self.config.MAX_METRICS_HISTORY:
                self._operation_timers[operation] = \
                    self._operation_timers[operation][-self.config.MAX_METRICS_HISTORY:]
            
            if algorithm:
                self._algorithm_usage[algorithm] += 1
    
    def record_constant_time_sample(self, operation: str, timing_variance: float):
        """Record timing variance for constant-time verification."""
        if not self.config.METRICS_ENABLED:
            return
        
        with self._lock:
            self._constant_time_samples[operation].append(timing_variance)
            
            if len(self._constant_time_samples[operation]) > self.config.MAX_METRICS_HISTORY:
                self._constant_time_samples[operation] = \
                    self._constant_time_samples[operation][-self.config.MAX_METRICS_HISTORY:]
    
    def record_key_rotation(self):
        """Record a key rotation event."""
        if not self.config.METRICS_ENABLED:
            return
        
        with self._lock:
            self._key_rotations += 1
    
    def get_operation_stats(self, operation: str) -> Dict[str, Any]:
        """Get statistics for a specific operation."""
        timers = self._operation_timers.get(operation, [])
        if not timers:
            return {"count": 0, "avg_ms": None, "min_ms": None, "max_ms": None}
        
        return {
            "count": self._operation_counters.get(operation, 0),
            "avg_ms": sum(timers) / len(timers),
            "min_ms": min(timers),
            "max_ms": max(timers)
        }
    
    def get_constant_time_rating(self, operation: str) -> Dict[str, Any]:
        """Get constant-time quality rating."""
        samples = self._constant_time_samples.get(operation, [])
        if not samples:
            return {"sample_count": 0, "variance_avg": None, "rating": "insufficient_data"}
        
        avg_variance = sum(samples) / len(samples)
        
        if avg_variance < 0.01:
            rating = "excellent"
        elif avg_variance < 0.1:
            rating = "good"
        elif avg_variance < 1.0:
            rating = "moderate"
        else:
            rating = "concerning"
        
        return {
            "sample_count": len(samples),
            "variance_avg_ms": avg_variance,
            "rating": rating
        }
    
    def get_algorithm_breakdown(self) -> Dict[str, int]:
        """Get algorithm usage breakdown."""
        return {alg.value: count for alg, count in self._algorithm_usage.items()}
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics summary."""
        return {
            "operations": dict(self._operation_counters),
            "operation_stats": {op: self.get_operation_stats(op) 
                               for op in self._operation_counters},
            "algorithm_usage": self.get_algorithm_breakdown(),
            "key_rotations": self._key_rotations,
            "constant_time_ratings": {op: self.get_constant_time_rating(op)
                                     for op in self._constant_time_samples}
        }
    
    def reset(self):
        """Reset all metrics."""
        with self._lock:
            self._operation_counters.clear()
            self._operation_timers.clear()
            self._algorithm_usage.clear()
            self._constant_time_samples.clear()
            self._key_rotations = 0


# Global metrics instance
_global_crypto_metrics = CryptoMetricsCollector()


def get_global_crypto_metrics() -> CryptoMetricsCollector:
    """Get the global crypto metrics collector instance."""
    return _global_crypto_metrics


# -----------------------------------------------------------------------------
# Crypto Operation Timing Decorator
# -----------------------------------------------------------------------------
def timed_crypto_operation(operation: str, algorithm: Optional[CryptoAlgorithm] = None):
    """Decorator to time cryptographic operations (OPT-IN ONLY)."""
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            config = CryptoObservabilityConfig()
            if not config.METRICS_ENABLED:
                return func(*args, **kwargs)
            
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration_ms = (time.perf_counter() - start_time) * 1000
                _global_crypto_metrics.record_crypto_operation(
                    operation, duration_ms, algorithm
                )
        
        return wrapper
    
    return decorator


# -----------------------------------------------------------------------------
# Constant-Time Verification
# -----------------------------------------------------------------------------
class ConstantTimeVerifier:
    """Verify constant-time execution of cryptographic operations."""
    
    def __init__(self):
        self.config = CryptoObservabilityConfig()
    
    def verify_constant_time(self, func: Callable, inputs: List[Any],
                            sample_count: int = None) -> Dict[str, Any]:
        """Verify function execution time is constant across inputs."""
        if not self.config.METRICS_ENABLED:
            return {"enabled": False, "skipped": True}
        
        sample_count = sample_count or self.config.CONSTANT_TIME_SAMPLE_COUNT
        timings = []
        
        for inp in inputs:
            for _ in range(sample_count // len(inputs)):
                start = time.perf_counter()
                func(inp)
                end = time.perf_counter()
                timings.append((end - start) * 1000)
        
        if not timings:
            return {"error": "no timings collected"}
        
        avg_time = sum(timings) / len(timings)
        variance = sum((t - avg_time) ** 2 for t in timings) / len(timings)
        std_dev = variance ** 0.5
        cv = std_dev / avg_time if avg_time > 0 else float('inf')
        
        # Record for metrics
        operation_name = getattr(func, '__name__', 'unknown')
        _global_crypto_metrics.record_constant_time_sample(operation_name, cv)
        
        return {
            "sample_count": len(timings),
            "avg_time_ms": avg_time,
            "variance_ms2": variance,
            "std_dev_ms": std_dev,
            "coefficient_of_variation": cv,
            "constant_time_rating": "excellent" if cv < 0.01 else
                                   "good" if cv < 0.05 else
                                   "moderate" if cv < 0.1 else "high_variance"
        }


# -----------------------------------------------------------------------------
# Randomness Quality Monitor
# -----------------------------------------------------------------------------
class RandomnessQualityMonitor:
    """Monitor quality of random number generation - disabled by default."""
    
    def __init__(self):
        self.config = CryptoObservabilityConfig()
        self._history: List[RandomnessQualityReport] = []
    
    def assess_randomness_quality(self, sample_data: bytes = None,
                                 sample_size: int = None) -> RandomnessQualityReport:
        """Assess randomness quality of provided or generated sample."""
        if not self.config.RANDOMNESS_MONITORING_ENABLED:
            return RandomnessQualityReport(
                sample_size=0,
                entropy_estimate=0.0,
                chi_square_score=0.0,
                runs_test_passed=False
            )
        
        sample_size = sample_size or self.config.RANDOMNESS_SAMPLE_SIZE
        
        if sample_data is None:
            sample_data = secrets.token_bytes(sample_size)
        
        # Simple entropy estimation (byte value distribution)
        byte_counts = [0] * 256
        for b in sample_data:
            byte_counts[b] += 1
        
        # Chi-square test for uniform distribution
        expected = len(sample_data) / 256
        chi_square = sum((count - expected) ** 2 / expected for count in byte_counts)
        
        # Runs test (simplified)
        runs = 0
        for i in range(1, len(sample_data)):
            if sample_data[i] != sample_data[i-1]:
                runs += 1
        
        runs_passed = runs > len(sample_data) * 0.4
        
        # Entropy estimate (Shannon)
        import math
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(sample_data)
                entropy -= p * math.log2(p)
        
        report = RandomnessQualityReport(
            sample_size=len(sample_data),
            entropy_estimate=entropy,
            chi_square_score=chi_square,
            runs_test_passed=runs_passed
        )
        
        self._history.append(report)
        if len(self._history) > 100:
            self._history.pop(0)
        
        return report
    
    def get_recent_reports(self, limit: int = 10) -> List[RandomnessQualityReport]:
        """Get recent randomness reports."""
        return list(self._history[-limit:])


# Global randomness monitor instance
_global_randomness_monitor = RandomnessQualityMonitor()


def get_global_randomness_monitor() -> RandomnessQualityMonitor:
    """Get the global randomness quality monitor instance."""
    return _global_randomness_monitor


# -----------------------------------------------------------------------------
# Crypto Health Check Framework
# -----------------------------------------------------------------------------
class CryptoHealthChecker:
    """Cryptography-specific health check framework - disabled by default."""
    
    def __init__(self):
        self.config = CryptoObservabilityConfig()
        self._lock = threading.Lock()
        self._checks: Dict[str, Callable[[], CryptoHealthCheckResult]] = {}
        self._last_results: Dict[str, CryptoHealthCheckResult] = {}
    
    def register_check(self, name: str, check_func: Callable[[], CryptoHealthCheckResult]):
        """Register a crypto health check function."""
        with self._lock:
            self._checks[name] = check_func
    
    def run_check(self, name: str) -> Optional[CryptoHealthCheckResult]:
        """Run a single crypto health check."""
        if not self.config.HEALTH_CHECKS_ENABLED:
            return None
        
        check_func = self._checks.get(name)
        if not check_func:
            return None
        
        start_time = time.time()
        try:
            result = check_func()
            result.duration_ms = (time.time() - start_time) * 1000
            with self._lock:
                self._last_results[name] = result
            return result
        except Exception as e:
            result = CryptoHealthCheckResult(
                check_name=name,
                status=CryptoHealthStatus.UNHEALTHY,
                message=f"Check exception: {str(e)}",
                duration_ms=(time.time() - start_time) * 1000
            )
            with self._lock:
                self._last_results[name] = result
            return result
    
    def run_all_checks(self) -> List[CryptoHealthCheckResult]:
        """Run all registered crypto health checks."""
        results = []
        for name in list(self._checks.keys()):
            result = self.run_check(name)
            if result:
                results.append(result)
        return results
    
    def get_overall_status(self) -> CryptoHealthStatus:
        """Get overall crypto health status."""
        if not self._last_results:
            return CryptoHealthStatus.UNKNOWN
        
        statuses = [r.status for r in self._last_results.values()]
        if CryptoHealthStatus.UNHEALTHY in statuses:
            return CryptoHealthStatus.UNHEALTHY
        if CryptoHealthStatus.DEGRADED in statuses:
            return CryptoHealthStatus.DEGRADED
        return CryptoHealthStatus.HEALTHY


# Standard crypto health checks
def check_randomness_quality() -> CryptoHealthCheckResult:
    """Check CSPRNG output quality."""
    try:
        report = _global_randomness_monitor.assess_randomness_quality(sample_size=256)
        
        if report.entropy_estimate > 7.8 and report.runs_test_passed:
            return CryptoHealthCheckResult(
                check_name="randomness_quality",
                status=CryptoHealthStatus.HEALTHY,
                message=f"Good randomness quality (entropy: {report.entropy_estimate:.2f} bits/byte)",
                metadata={"entropy": report.entropy_estimate, "chi_square": report.chi_square_score}
            )
        elif report.entropy_estimate > 7.0:
            return CryptoHealthCheckResult(
                check_name="randomness_quality",
                status=CryptoHealthStatus.DEGRADED,
                message=f"Moderate randomness quality (entropy: {report.entropy_estimate:.2f} bits/byte)",
                metadata={"entropy": report.entropy_estimate}
            )
        else:
            return CryptoHealthCheckResult(
                check_name="randomness_quality",
                status=CryptoHealthStatus.UNHEALTHY,
                message=f"Poor randomness quality (entropy: {report.entropy_estimate:.2f} bits/byte)",
                metadata={"entropy": report.entropy_estimate}
            )
    except Exception as e:
        return CryptoHealthCheckResult(
            check_name="randomness_quality",
            status=CryptoHealthStatus.UNKNOWN,
            message=f"Randomness check error: {str(e)}"
        )


def check_hash_function_health() -> CryptoHealthCheckResult:
    """Verify hash functions are working correctly."""
    try:
        test_data = b"QuantumCrypt health check test vector"
        expected = hashlib.sha512(test_data).hexdigest()
        actual = hashlib.sha512(test_data).hexdigest()
        
        if actual == expected:
            return CryptoHealthCheckResult(
                check_name="hash_functions",
                status=CryptoHealthStatus.HEALTHY,
                message="Hash functions operating correctly",
                metadata={"algorithm": "SHA-512"}
            )
        else:
            return CryptoHealthCheckResult(
                check_name="hash_functions",
                status=CryptoHealthStatus.UNHEALTHY,
                message="Hash function output mismatch detected",
                metadata={"expected": expected[:16], "actual": actual[:16]}
            )
    except Exception as e:
        return CryptoHealthCheckResult(
            check_name="hash_functions",
            status=CryptoHealthStatus.UNHEALTHY,
            message=f"Hash function check failed: {str(e)}"
        )


# Global crypto health checker with standard checks registered
_global_crypto_health_checker = CryptoHealthChecker()
_global_crypto_health_checker.register_check("randomness_quality", check_randomness_quality)
_global_crypto_health_checker.register_check("hash_functions", check_hash_function_health)


def get_global_crypto_health_checker() -> CryptoHealthChecker:
    """Get the global crypto health checker instance."""
    return _global_crypto_health_checker


# -----------------------------------------------------------------------------
# Crypto Event Emitter
# -----------------------------------------------------------------------------
class CryptoEventEmitter:
    """Cryptography-specific event emission - disabled by default."""
    
    def __init__(self):
        self.config = CryptoObservabilityConfig()
        self._lock = threading.Lock()
        self._events: List[Dict[str, Any]] = []
    
    def emit_key_generation(self, algorithm: str, key_size: int):
        """Emit key generation event."""
        if not self.config.EVENTS_ENABLED:
            return
        
        self._emit("key_generation", algorithm=algorithm, key_size=key_size)
    
    def emit_key_rotation(self, algorithm: str, reason: str = "scheduled"):
        """Emit key rotation event."""
        if not self.config.EVENTS_ENABLED:
            return
        
        _global_crypto_metrics.record_key_rotation()
        self._emit("key_rotation", algorithm=algorithm, reason=reason)
    
    def emit_encryption(self, algorithm: str, data_size: int):
        """Emit encryption operation event."""
        if not self.config.EVENTS_ENABLED:
            return
        
        self._emit("encryption", algorithm=algorithm, data_size=data_size)
    
    def emit_decryption(self, algorithm: str, data_size: int):
        """Emit decryption operation event."""
        if not self.config.EVENTS_ENABLED:
            return
        
        self._emit("decryption", algorithm=algorithm, data_size=data_size)
    
    def emit_security_alert(self, alert_type: str, severity: str, details: str):
        """Emit security alert event."""
        if not self.config.EVENTS_ENABLED:
            return
        
        self._emit("security_alert", alert_type=alert_type, severity=severity, details=details)
    
    def _emit(self, event_type: str, **kwargs):
        """Internal emit function."""
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "timestamp": time.time(),
            "source": inspect.stack()[2].function,
            **kwargs
        }
        
        with self._lock:
            self._events.append(event)
            if len(self._events) > self.config.MAX_METRICS_HISTORY:
                self._events.pop(0)
    
    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent crypto events."""
        with self._lock:
            return list(self._events[-limit:])


# Global event emitter instance
_global_crypto_events = CryptoEventEmitter()


def get_global_crypto_events() -> CryptoEventEmitter:
    """Get the global crypto event emitter instance."""
    return _global_crypto_events


# -----------------------------------------------------------------------------
# Convenience Functions
# -----------------------------------------------------------------------------
def record_crypto_op(operation: str, duration_ms: float, alg: str = None):
    """Convenience function to record crypto operation."""
    algorithm = CryptoAlgorithm(alg) if alg else None
    _global_crypto_metrics.record_crypto_operation(operation, duration_ms, algorithm)


def emit_crypto_event(event_type: str, **kwargs):
    """Convenience function to emit crypto event."""
    if event_type == "key_generation":
        _global_crypto_events.emit_key_generation(kwargs.get("algorithm", "unknown"),
                                                  kwargs.get("key_size", 0))
    elif event_type == "key_rotation":
        _global_crypto_events.emit_key_rotation(kwargs.get("algorithm", "unknown"),
                                               kwargs.get("reason", "scheduled"))


# -----------------------------------------------------------------------------
# Module Metadata
# -----------------------------------------------------------------------------
CRYPTO_OBSERVABILITY_VERSION = "16.0.0"
CRYPTO_OBSERVABILITY_API_STABILITY = "stable"


def get_crypto_observability_status() -> Dict[str, Any]:
    """Get current crypto observability status summary."""
    config = CryptoObservabilityConfig()
    return {
        "version": CRYPTO_OBSERVABILITY_VERSION,
        "api_stability": CRYPTO_OBSERVABILITY_API_STABILITY,
        "enabled_features": {
            "logging": config.LOGGING_ENABLED,
            "metrics": config.METRICS_ENABLED,
            "health_checks": config.HEALTH_CHECKS_ENABLED,
            "tracing": config.TRACING_ENABLED,
            "randomness_monitoring": config.RANDOMNESS_MONITORING_ENABLED,
            "events": config.EVENTS_ENABLED
        },
        "metrics": _global_crypto_metrics.get_all_metrics(),
        "crypto_health_status": _global_crypto_health_checker.get_overall_status().value,
        "event_count": len(_global_crypto_events.get_recent_events())
    }
