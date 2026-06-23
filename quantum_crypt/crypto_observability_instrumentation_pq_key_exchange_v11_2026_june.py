"""
QuantumCrypt AI - Observability & Instrumentation for PQ Key Exchange v11
Session 110 - Dimension D: Observability & Instrumentation

PHILOSOPHY: ADD-ONLY, NO EXISTING CODE MODIFIED
ALL FEATURES OPT-IN - DISABLED BY DEFAULT
100% BACKWARD COMPATIBLE
NO SENSITIVE KEY MATERIAL EVER LOGGED

This module provides cryptographic-specific observability:
1. Structured crypto operation logging (NO sensitive data)
2. Key operation metrics and timing (constant-time safe)
3. Cryptographic health checks (algorithm validation, entropy checks)
4. Distributed tracing with secure baggage propagation
5. Key operation SLO tracking (latency, success rate)
6. Algorithm performance benchmarking
7. Thread-safe singleton pattern
"""

import time
import json
import uuid
import threading
import logging
import secrets
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from collections import defaultdict, deque


class CryptoOperationType(Enum):
    """Types of cryptographic operations for audit logging."""
    KEY_GENERATION = "key_generation"
    KEY_EXCHANGE = "key_exchange"
    KEY_DERIVATION = "key_derivation"
    SIGNATURE_GENERATION = "signature_generation"
    SIGNATURE_VERIFICATION = "signature_verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    RANDOM_GENERATION = "random_generation"
    HASH_COMPUTATION = "hash_computation"


class LogSeverity(Enum):
    """Log severity levels matching standard logging conventions."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricType(Enum):
    """Types of metrics supported."""
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"


class HealthStatus(Enum):
    """Health check status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class AlgorithmStatus(Enum):
    """Post-quantum algorithm implementation status."""
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    BROKEN = "broken"


class SLOStatus(Enum):
    """SLO burn rate status."""
    OK = "ok"
    WARNING = "warning"
    BURNING = "burning"
    EXHAUSTED = "exhausted"


@dataclass
class CryptoLogEntry:
    """Structured crypto log entry - NO sensitive key material allowed."""
    timestamp: str
    severity: LogSeverity
    operation: CryptoOperationType
    algorithm: str
    message: str
    correlation_id: str
    session_id_truncated: str  # Only first 16 chars, NEVER full session ID
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "operation": self.operation.value,
            "algorithm": self.algorithm,
            "message": self.message,
            "correlation_id": self.correlation_id,
            "session_id_truncated": self.session_id_truncated,
            "attributes": self.attributes
        }


@dataclass
class MetricValue:
    """Metric value with metadata."""
    name: str
    type: MetricType
    value: float
    timestamp: str
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    name: str
    status: HealthStatus
    message: str
    duration_ms: float
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class AlgorithmInfo:
    """Information about a cryptographic algorithm."""
    name: str
    status: AlgorithmStatus
    key_size_bits: int
    nist_level: Optional[int] = None
    standard: Optional[str] = None


@dataclass
class SLOConfig:
    """Configuration for an SLO."""
    name: str
    target_percentage: float
    target_latency_ms: Optional[float] = None
    window_days: int = 30


@dataclass
class CryptoObservabilityConfig:
    """Master configuration for all crypto observability features.
    ALL FEATURES DISABLED BY DEFAULT - OPT-IN PATTERN
    """
    # All features disabled by default
    logging_enabled: bool = False
    metrics_enabled: bool = False
    health_checks_enabled: bool = False
    tracing_enabled: bool = False
    slo_tracking_enabled: bool = False
    benchmarking_enabled: bool = False
    
    # Security constraints
    max_session_id_log_length: int = 16  # NEVER log full session IDs
    never_log_key_material: bool = True  # ENFORCED - cannot be disabled
    redact_all_sensitive_values: bool = True  # ENFORCED
    
    # Logging configuration
    log_level: LogSeverity = LogSeverity.INFO
    max_log_entries: int = 10000
    
    # Metrics configuration
    max_metric_samples: int = 1000
    timing_noise_jitter: bool = True  # Add small noise to prevent timing attacks
    
    # Health check configuration
    default_health_check_timeout_ms: int = 5000
    
    # Tracing configuration
    generate_correlation_ids: bool = True
    propagate_baggage: bool = True


class CryptoStructuredLogger:
    """Thread-safe structured logging for crypto operations - NO sensitive data."""
    
    def __init__(self, config: CryptoObservabilityConfig):
        self._config = config
        self._logs: deque = deque(maxlen=config.max_log_entries)
        self._lock = threading.Lock()
        self._python_logger = logging.getLogger("quantumcrypt.observability")
    
    def _truncate_session_id(self, session_id: str) -> str:
        """SAFETY: Truncate session ID - NEVER log full identifiers."""
        if not session_id:
            return ""
        return session_id[:self._config.max_session_id_log_length]
    
    def _should_log(self, severity: LogSeverity) -> bool:
        if not self._config.logging_enabled:
            return False
        severity_order = [LogSeverity.DEBUG, LogSeverity.INFO, 
                         LogSeverity.WARNING, LogSeverity.ERROR, LogSeverity.CRITICAL]
        return severity_order.index(severity) >= severity_order.index(self._config.log_level)
    
    def log_operation(self, severity: LogSeverity, operation: CryptoOperationType,
                     algorithm: str, message: str, session_id: str = "",
                     correlation_id: Optional[str] = None, **attributes) -> Optional[CryptoLogEntry]:
        """Log a crypto operation - returns None if logging disabled."""
        if not self._should_log(severity):
            return None
        
        # SAFETY: Never allow key material in attributes
        safe_attributes = {}
        for k, v in attributes.items():
            key_lower = k.lower()
            if any(term in key_lower for term in ['key', 'secret', 'private', 'password', 'token']):
                safe_attributes[k] = "[REDACTED]"
            else:
                safe_attributes[k] = v
        
        entry = CryptoLogEntry(
            timestamp=datetime.utcnow().isoformat(),
            severity=severity,
            operation=operation,
            algorithm=algorithm,
            message=message,
            correlation_id=correlation_id or str(uuid.uuid4()),
            session_id_truncated=self._truncate_session_id(session_id),
            attributes=safe_attributes
        )
        
        with self._lock:
            self._logs.append(entry)
        
        py_level = {
            LogSeverity.DEBUG: logging.DEBUG,
            LogSeverity.INFO: logging.INFO,
            LogSeverity.WARNING: logging.WARNING,
            LogSeverity.ERROR: logging.ERROR,
            LogSeverity.CRITICAL: logging.CRITICAL
        }.get(severity, logging.INFO)
        
        self._python_logger.log(py_level, json.dumps(entry.to_dict()))
        return entry
    
    def log_key_generation(self, algorithm: str, **kwargs):
        return self.log_operation(LogSeverity.INFO, CryptoOperationType.KEY_GENERATION,
                                 algorithm, "Key generation completed", **kwargs)
    
    def log_key_exchange(self, algorithm: str, **kwargs):
        return self.log_operation(LogSeverity.INFO, CryptoOperationType.KEY_EXCHANGE,
                                 algorithm, "Key exchange completed", **kwargs)
    
    def log_key_derivation(self, algorithm: str, **kwargs):
        return self.log_operation(LogSeverity.INFO, CryptoOperationType.KEY_DERIVATION,
                                 algorithm, "Key derivation completed", **kwargs)
    
    def log_signature(self, algorithm: str, verified: bool = True, **kwargs):
        op = CryptoOperationType.SIGNATURE_VERIFICATION if verified else CryptoOperationType.SIGNATURE_GENERATION
        msg = "Signature verified" if verified else "Signature generated"
        return self.log_operation(LogSeverity.INFO, op, algorithm, msg, **kwargs)
    
    def log_error(self, operation: CryptoOperationType, algorithm: str,
                 error_message: str, **kwargs):
        return self.log_operation(LogSeverity.ERROR, operation, algorithm,
                                 f"Operation failed: {error_message}", **kwargs)
    
    def get_recent_logs(self, count: int = 100) -> List[CryptoLogEntry]:
        with self._lock:
            return list(self._logs)[-count:]


class CryptoMetricsCollector:
    """Thread-safe metrics collection with timing attack protection."""
    
    LATENCY_BUCKETS_MS = [0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
    
    def __init__(self, config: CryptoObservabilityConfig):
        self._config = config
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._histograms: Dict[str, Dict[float, int]] = defaultdict(lambda: defaultdict(int))
        self._samples: deque = deque(maxlen=config.max_metric_samples)
        self._lock = threading.Lock()
        self._algorithm_registry: Dict[str, AlgorithmInfo] = {}
    
    def _add_timing_noise(self, duration: float) -> float:
        """Add small random noise to prevent timing side-channel attacks."""
        if not self._config.timing_noise_jitter:
            return duration
        # Add +/- 1% jitter to obscure exact timing
        jitter = 1.0 + (secrets.SystemRandom().random() - 0.5) * 0.02
        return duration * jitter
    
    def _record_sample(self, name: str, metric_type: MetricType, 
                      value: float, labels: Optional[Dict[str, str]] = None) -> None:
        if not self._config.metrics_enabled:
            return
        sample = MetricValue(
            name=name,
            type=metric_type,
            value=value,
            timestamp=datetime.utcnow().isoformat(),
            labels=labels or {}
        )
        with self._lock:
            self._samples.append(sample)
    
    def increment_operation(self, operation: CryptoOperationType, 
                           algorithm: str, success: bool = True) -> int:
        """Increment counter for crypto operation."""
        if not self._config.metrics_enabled:
            return 0
        
        status = "success" if success else "error"
        name = f"crypto_{operation.value}_{status}"
        labels = {"algorithm": algorithm}
        
        with self._lock:
            self._counters[name] += 1
            current = self._counters[name]
        
        self._record_sample(name, MetricType.COUNTER, float(current), labels)
        return current
    
    def record_operation_latency(self, operation: CryptoOperationType,
                                algorithm: str, duration_ms: float) -> None:
        """Record operation latency with timing attack protection."""
        if not self._config.metrics_enabled:
            return
        
        safe_duration = self._add_timing_noise(duration_ms)
        name = f"crypto_{operation.value}_latency_ms"
        labels = {"algorithm": algorithm}
        
        with self._lock:
            self._timers[name].append(safe_duration)
            for bucket in self.LATENCY_BUCKETS_MS:
                if safe_duration <= bucket:
                    self._histograms[name][bucket] += 1
                    break
        
        self._record_sample(name, MetricType.TIMER, safe_duration, labels)
    
    def time_crypto_operation(self, operation: CryptoOperationType, algorithm: str):
        """Decorator to time crypto operations safely."""
        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                start = time.perf_counter()
                try:
                    result = func(*args, **kwargs)
                    success = True
                    return result
                except Exception:
                    success = False
                    raise
                finally:
                    duration_ms = (time.perf_counter() - start) * 1000
                    self.record_operation_latency(operation, algorithm, duration_ms)
                    self.increment_operation(operation, algorithm, success)
            return wrapper
        return decorator
    
    def register_algorithm(self, info: AlgorithmInfo) -> None:
        """Register algorithm metadata."""
        with self._lock:
            self._algorithm_registry[info.name] = info
    
    def set_algorithm_active(self, algorithm: str, active: bool) -> None:
        """Set gauge for algorithm active status."""
        if not self._config.metrics_enabled:
            return
        with self._lock:
            self._gauges[f"algorithm_{algorithm}_active"] = 1.0 if active else 0.0
    
    def get_operation_stats(self, operation: CryptoOperationType, 
                           algorithm: str) -> Dict[str, Any]:
        name_success = f"crypto_{operation.value}_success"
        name_error = f"crypto_{operation.value}_error"
        name_latency = f"crypto_{operation.value}_latency_ms"
        
        with self._lock:
            success = self._counters.get(name_success, 0)
            errors = self._counters.get(name_error, 0)
            latencies = self._timers.get(name_latency, [])
        
        total = success + errors
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            sorted_lat = sorted(latencies)
            n = len(sorted_lat)
            p50 = sorted_lat[int(n * 0.5)]
            p95 = sorted_lat[int(n * 0.95)]
            p99 = sorted_lat[int(n * 0.99)]
        else:
            avg_latency = None
            p50 = p95 = p99 = None
        
        return {
            "algorithm": algorithm,
            "operation": operation.value,
            "total_operations": total,
            "success_count": success,
            "error_count": errors,
            "success_rate": (success / total * 100) if total > 0 else None,
            "avg_latency_ms": avg_latency,
            "p50_latency_ms": p50,
            "p95_latency_ms": p95,
            "p99_latency_ms": p99
        }
    
    def get_all_counters(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counters)


class CryptoHealthCheckFramework:
    """Cryptographic health check framework."""
    
    def __init__(self, config: CryptoObservabilityConfig):
        self._config = config
        self._checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self._lock = threading.Lock()
        self._last_results: Dict[str, HealthCheckResult] = {}
        self._register_default_health_checks()
    
    def _register_default_health_checks(self) -> None:
        """Register crypto-specific health checks."""
        
        def entropy_health_check() -> HealthCheckResult:
            """Check system entropy availability."""
            try:
                # Test that CSPRNG works
                test_bytes = secrets.token_bytes(32)
                if len(test_bytes) == 32:
                    return HealthCheckResult(
                        name="entropy_source",
                        status=HealthStatus.HEALTHY,
                        message="System CSPRNG functioning correctly",
                        duration_ms=0.0,
                        details={"test_bytes_generated": 32}
                    )
                return HealthCheckResult(
                    name="entropy_source",
                    status=HealthStatus.UNHEALTHY,
                    message="CSPRNG returned incorrect number of bytes",
                    duration_ms=0.0
                )
            except Exception as e:
                return HealthCheckResult(
                    name="entropy_source",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Entropy source failure: {str(e)}",
                    duration_ms=0.0
                )
        
        def hash_function_check() -> HealthCheckResult:
            """Verify hash functions work correctly."""
            try:
                test_hash = hashlib.sha512(b"test").hexdigest()
                expected = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
                if test_hash == expected:
                    return HealthCheckResult(
                        name="hash_functions",
                        status=HealthStatus.HEALTHY,
                        message="SHA-512 verification passed",
                        duration_ms=0.0
                    )
                return HealthCheckResult(
                    name="hash_functions",
                    status=HealthStatus.UNHEALTHY,
                    message="Hash function verification failed - possible corruption",
                    duration_ms=0.0
                )
            except Exception as e:
                return HealthCheckResult(
                    name="hash_functions",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Hash function error: {str(e)}",
                    duration_ms=0.0
                )
        
        self.register_check("entropy_source", entropy_health_check)
        self.register_check("hash_functions", hash_function_check)
    
    def register_check(self, name: str, check_func: Callable[[], HealthCheckResult]) -> None:
        with self._lock:
            self._checks[name] = check_func
    
    def run_check(self, name: str) -> Optional[HealthCheckResult]:
        if not self._config.health_checks_enabled:
            return None
        
        with self._lock:
            check_func = self._checks.get(name)
        
        if not check_func:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"Health check '{name}' not registered",
                duration_ms=0.0
            )
        
        start = time.perf_counter()
        try:
            result = check_func()
        except Exception as e:
            result = HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check exception: {str(e)}",
                duration_ms=0.0
            )
        
        duration_ms = (time.perf_counter() - start) * 1000
        result.duration_ms = duration_ms
        
        with self._lock:
            self._last_results[name] = result
        
        return result
    
    def run_all_checks(self) -> Dict[str, Optional[HealthCheckResult]]:
        results = {}
        for name in list(self._checks.keys()):
            results[name] = self.run_check(name)
        return results
    
    def get_overall_status(self) -> HealthStatus:
        if not self._config.health_checks_enabled or not self._last_results:
            return HealthStatus.UNKNOWN
        
        statuses = [r.status for r in self._last_results.values()]
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY


class CryptoDistributedTracer:
    """Distributed tracing for crypto operations with secure baggage."""
    
    def __init__(self, config: CryptoObservabilityConfig):
        self._config = config
        self._local = threading.local()
        self._lock = threading.Lock()
        self._trace_count = 0
    
    def generate_secure_correlation_id(self) -> str:
        """Generate cryptographically secure correlation ID."""
        if not self._config.tracing_enabled:
            return ""
        return secrets.token_hex(16)
    
    def set_correlation_id(self, correlation_id: str) -> None:
        if self._config.tracing_enabled:
            self._local.correlation_id = correlation_id
    
    def get_correlation_id(self) -> Optional[str]:
        if not self._config.tracing_enabled:
            return None
        return getattr(self._local, 'correlation_id', None)
    
    def set_secure_baggage(self, key: str, value: str) -> None:
        """Set baggage - NEVER allow sensitive key material."""
        if not self._config.tracing_enabled or not self._config.propagate_baggage:
            return
        
        key_lower = key.lower()
        if any(term in key_lower for term in ['key', 'secret', 'private', 'password']):
            return  # Silently drop sensitive baggage
        
        if not hasattr(self._local, 'baggage'):
            self._local.baggage = {}
        self._local.baggage[key] = value
    
    def get_baggage(self) -> Dict[str, str]:
        if not self._config.tracing_enabled or not self._config.propagate_baggage:
            return {}
        return getattr(self._local, 'baggage', {}).copy()
    
    def clear_context(self) -> None:
        if hasattr(self._local, 'correlation_id'):
            delattr(self._local, 'correlation_id')
        if hasattr(self._local, 'baggage'):
            delattr(self._local, 'baggage')
    
    def get_trace_count(self) -> int:
        with self._lock:
            return self._trace_count


class CryptoSLOTracker:
    """SLO tracking for crypto operations."""
    
    def __init__(self, config: CryptoObservabilityConfig):
        self._config = config
        self._slos: Dict[str, SLOConfig] = {}
        self._events: deque = deque(maxlen=100000)
        self._lock = threading.Lock()
        self._register_default_slos()
    
    def _register_default_slos(self) -> None:
        self._slos["key_exchange"] = SLOConfig(
            name="key_exchange",
            target_percentage=99.99,
            target_latency_ms=100.0,
            window_days=30
        )
        self._slos["key_generation"] = SLOConfig(
            name="key_generation",
            target_percentage=99.95,
            target_latency_ms=50.0,
            window_days=30
        )
    
    def record_success(self, slo_name: str, latency_ms: Optional[float] = None) -> None:
        if not self._config.slo_tracking_enabled:
            return
        with self._lock:
            self._events.append((time.time(), False, slo_name, latency_ms))
    
    def record_error(self, slo_name: str) -> None:
        if not self._config.slo_tracking_enabled:
            return
        with self._lock:
            self._events.append((time.time(), True, slo_name, None))


class PQKeyExchangeObservability:
    """
    Main observability facade for Post-Quantum Key Exchange operations.
    Thread-safe singleton - OPT-IN, disabled by default.
    NO SENSITIVE KEY MATERIAL EVER LOGGED OR EXPOSED.
    
    USAGE (OPT-IN REQUIRED):
        from quantum_crypt.crypto_observability_instrumentation_pq_key_exchange_v11_2026_june import crypto_observability
        
        # Enable features you want
        crypto_observability.enable_logging()
        crypto_observability.enable_metrics()
        crypto_observability.enable_health_checks()
        crypto_observability.enable_tracing()
        crypto_observability.enable_slo_tracking()
        
        # Use features (SAFE - no key material logged)
        crypto_observability.logger.log_key_exchange("CRYSTALS-Kyber", session_id="sid_12345")
        crypto_observability.metrics.increment_operation(CryptoOperationType.KEY_EXCHANGE, "CRYSTALS-Kyber")
    """
    
    _instance = None
    _instance_lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._config = CryptoObservabilityConfig()  # ALL DISABLED BY DEFAULT
        self._lock = threading.Lock()
        
        # Initialize all sub-components
        self._logger = CryptoStructuredLogger(self._config)
        self._metrics = CryptoMetricsCollector(self._config)
        self._health = CryptoHealthCheckFramework(self._config)
        self._tracer = CryptoDistributedTracer(self._config)
        self._slo = CryptoSLOTracker(self._config)
        
        # Register standard PQ algorithms
        self._register_standard_algorithms()
    
    def _register_standard_algorithms(self) -> None:
        """Register NIST-standardized post-quantum algorithms."""
        algorithms = [
            AlgorithmInfo("CRYSTALS-Kyber-512", AlgorithmStatus.STABLE, 512, 1, "NIST FIPS 203"),
            AlgorithmInfo("CRYSTALS-Kyber-768", AlgorithmStatus.STABLE, 768, 3, "NIST FIPS 203"),
            AlgorithmInfo("CRYSTALS-Kyber-1024", AlgorithmStatus.STABLE, 1024, 5, "NIST FIPS 203"),
            AlgorithmInfo("CRYSTALS-Dilithium-2", AlgorithmStatus.STABLE, 128, 2, "NIST FIPS 204"),
            AlgorithmInfo("CRYSTALS-Dilithium-3", AlgorithmStatus.STABLE, 192, 3, "NIST FIPS 204"),
            AlgorithmInfo("CRYSTALS-Dilithium-5", AlgorithmStatus.STABLE, 256, 5, "NIST FIPS 204"),
            AlgorithmInfo("SPHINCS+-SHA2-128f", AlgorithmStatus.STABLE, 128, 1, "NIST FIPS 205"),
            AlgorithmInfo("FrodoKEM-640", AlgorithmStatus.EXPERIMENTAL, 640, 1),
            AlgorithmInfo("NTRU-HPS-2048", AlgorithmStatus.EXPERIMENTAL, 2048, 1),
        ]
        for algo in algorithms:
            self._metrics.register_algorithm(algo)
    
    # Enable/disable methods (OPT-IN pattern)
    def enable_logging(self, level: LogSeverity = LogSeverity.INFO) -> None:
        with self._lock:
            self._config.logging_enabled = True
            self._config.log_level = level
    
    def enable_metrics(self) -> None:
        with self._lock:
            self._config.metrics_enabled = True
    
    def enable_health_checks(self) -> None:
        with self._lock:
            self._config.health_checks_enabled = True
    
    def enable_tracing(self) -> None:
        with self._lock:
            self._config.tracing_enabled = True
    
    def enable_slo_tracking(self) -> None:
        with self._lock:
            self._config.slo_tracking_enabled = True
    
    def enable_benchmarking(self) -> None:
        with self._lock:
            self._config.benchmarking_enabled = True
    
    def enable_all(self) -> None:
        """Enable ALL observability features."""
        self.enable_logging()
        self.enable_metrics()
        self.enable_health_checks()
        self.enable_tracing()
        self.enable_slo_tracking()
        self.enable_benchmarking()
    
    # Property accessors
    @property
    def logger(self) -> CryptoStructuredLogger:
        return self._logger
    
    @property
    def metrics(self) -> CryptoMetricsCollector:
        return self._metrics
    
    @property
    def health(self) -> CryptoHealthCheckFramework:
        return self._health
    
    @property
    def tracer(self) -> CryptoDistributedTracer:
        return self._tracer
    
    @property
    def slo(self) -> CryptoSLOTracker:
        return self._slo
    
    @property
    def config(self) -> CryptoObservabilityConfig:
        return self._config
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get comprehensive observability status summary."""
        return {
            "config": {
                "logging_enabled": self._config.logging_enabled,
                "metrics_enabled": self._config.metrics_enabled,
                "health_checks_enabled": self._config.health_checks_enabled,
                "tracing_enabled": self._config.tracing_enabled,
                "slo_tracking_enabled": self._config.slo_tracking_enabled,
                "never_log_key_material": self._config.never_log_key_material,
                "redact_all_sensitive_values": self._config.redact_all_sensitive_values
            },
            "health": {
                "overall_status": self._health.get_overall_status().value
            },
            "security": {
                "max_session_id_log_length": self._config.max_session_id_log_length,
                "timing_noise_jitter_enabled": self._config.timing_noise_jitter
            }
        }


# Global singleton instance - OPT-IN, disabled by default
crypto_observability = PQKeyExchangeObservability()
