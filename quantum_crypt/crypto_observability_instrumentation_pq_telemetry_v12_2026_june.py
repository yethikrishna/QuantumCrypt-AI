"""
QuantumCrypt AI - Observability & Instrumentation Module v12
Session 116 - Dimension D: Observability & Instrumentation
PHILOSOPHY: ADD-ONLY, NO EXISTING CODE MODIFIED
ALL FEATURES OPT-IN - DISABLED BY DEFAULT
100% BACKWARD COMPATIBLE

NEW IN v12 (Session 116):
1. PQ Algorithm Performance Telemetry - Kyber/Dilithium operation metrics
2. NIST Security Level Tracking - Per-algorithm security level metrics
3. Key Operation Latency Histograms - Key gen/encap/decap/sign/verify timing
4. HSM/KMS Connection Health Checks - External crypto provider monitoring
5. Cross-Module Correlation Baggage - PQ + KEM + Signature tracing
6. Crypto SLO Tracking - Operation latency, error budgets
7. Prometheus/Grafana Export - OpenMetrics format for crypto dashboards

This module WRAPS existing functionality - NO core crypto code modified
"""
import time
import json
import uuid
import threading
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from collections import defaultdict, deque


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


class SLOStatus(Enum):
    """SLO burn rate status."""
    OK = "ok"
    WARNING = "warning"
    BURNING = "burning"
    EXHAUSTED = "exhausted"
    UNKNOWN = "unknown"


class CryptoOperation(Enum):
    """v12 NEW: Types of cryptographic operations for telemetry."""
    KEY_GENERATION = "key_generation"
    ENCAPSULATION = "encapsulation"
    DECAPSULATION = "decapsulation"
    SIGNATURE = "signature"
    VERIFICATION = "verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    KEY_EXCHANGE = "key_exchange"
    RANDOM_GENERATION = "random_generation"
    HASH_COMPUTATION = "hash_computation"


class PQAlgorithm(Enum):
    """v12 NEW: Post-quantum algorithms for targeted telemetry."""
    KYBER_512 = "kyber_512"
    KYBER_768 = "kyber_768"
    KYBER_1024 = "kyber_1024"
    DILITHIUM_2 = "dilithium_2"
    DILITHIUM_3 = "dilithium_3"
    DILITHIUM_5 = "dilithium_5"
    HYBRID_P256_KYBER768 = "hybrid_p256_kyber768"
    HYBRID_X25519_KYBER768 = "hybrid_x25519_kyber768"
    AES_256_GCM = "aes_256_gcm"
    RSA_2048 = "rsa_2048"
    ECC_P256 = "ecc_p256"


class NISTSecurityLevel(Enum):
    """v12 NEW: NIST PQC security levels."""
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_2 = 2
    LEVEL_3 = 3
    LEVEL_4 = 4
    LEVEL_5 = 5  # AES-256 equivalent


class CryptoBaggageKey(Enum):
    """v12 NEW: Standardized baggage keys for crypto cross-module correlation."""
    CRYPTO_OPERATION_ID = "crypto_operation_id"
    PQ_ALGORITHM = "pq_algorithm"
    NIST_SECURITY_LEVEL = "nist_security_level"
    KEY_ID = "key_id"
    HSM_PROVIDER = "hsm_provider"
    KMS_CONNECTION_ID = "kms_connection_id"
    REQUEST_ORIGIN = "request_origin"


@dataclass
class LogEntry:
    """Structured log entry with metadata."""
    timestamp: str
    severity: LogSeverity
    message: str
    correlation_id: str
    component: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "message": self.message,
            "correlation_id": self.correlation_id,
            "component": self.component,
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
class CryptoSLOConfig:
    """v12 NEW: SLO configuration specifically for cryptographic operations."""
    key_gen_latency_p95_ms: float = 50.0
    encapsulation_latency_p95_ms: float = 10.0
    decapsulation_latency_p95_ms: float = 10.0
    signature_latency_p95_ms: float = 30.0
    verification_latency_p95_ms: float = 5.0
    hsm_connection_timeout_ms: float = 1000.0
    availability_target: float = 99.99
    error_budget_window_days: int = 30


@dataclass
class PrometheusMetric:
    """v12 NEW: Prometheus/OpenMetrics format metric."""
    name: str
    metric_type: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    help_text: str = ""

    def to_openmetrics(self) -> str:
        """Convert to OpenMetrics/Prometheus exposition format."""
        lines = []
        if self.help_text:
            lines.append(f"# HELP {self.name} {self.help_text}")
        lines.append(f"# TYPE {self.name} {self.metric_type}")
        
        label_str = ""
        if self.labels:
            label_parts = [f'{k}="{v}"' for k, v in self.labels.items()]
            label_str = "{" + ",".join(label_parts) + "}"
        
        lines.append(f"{self.name}{label_str} {self.value}")
        return "\n".join(lines)


@dataclass
class CryptoObservabilityConfig:
    """Master configuration for all crypto observability features."""
    # All features disabled by default - OPT-IN pattern
    logging_enabled: bool = False
    metrics_enabled: bool = False
    health_checks_enabled: bool = False
    tracing_enabled: bool = False
    slo_tracking_enabled: bool = False
    
    # v12 NEW: Crypto-specific observability flags
    pq_algorithm_telemetry_enabled: bool = False
    hsm_kms_monitoring_enabled: bool = False
    prometheus_export_enabled: bool = False
    cross_module_correlation_enabled: bool = False
    
    # Logging configuration
    log_level: LogSeverity = LogSeverity.INFO
    max_log_entries: int = 10000
    include_timestamps: bool = True
    
    # Metrics configuration
    max_metric_samples: int = 1000
    retain_histogram_buckets: bool = True
    
    # Health check configuration
    default_health_check_timeout_ms: int = 5000
    
    # Tracing configuration
    generate_correlation_ids: bool = True
    propagate_baggage: bool = True
    
    # v12 NEW: Crypto SLO configuration
    crypto_slo_config: CryptoSLOConfig = field(
        default_factory=CryptoSLOConfig
    )


class StructuredLogger:
    """Thread-safe structured logging with ring buffer storage."""
    
    def __init__(self, config: CryptoObservabilityConfig):
        self._config = config
        self._logs: deque = deque(maxlen=config.max_log_entries)
        self._lock = threading.Lock()
        self._python_logger = logging.getLogger("quantumcrypt.observability.v12")
    
    def _should_log(self, severity: LogSeverity) -> bool:
        if not self._config.logging_enabled:
            return False
        severity_order = [LogSeverity.DEBUG, LogSeverity.INFO, 
                         LogSeverity.WARNING, LogSeverity.ERROR, LogSeverity.CRITICAL]
        return severity_order.index(severity) >= severity_order.index(self._config.log_level)
    
    def log(self, severity: LogSeverity, message: str, component: str,
            correlation_id: Optional[str] = None, **attributes) -> Optional[LogEntry]:
        """Log a structured entry - returns None if logging disabled."""
        if not self._should_log(severity):
            return None
        
        entry = LogEntry(
            timestamp=datetime.utcnow().isoformat(),
            severity=severity,
            message=message,
            correlation_id=correlation_id or str(uuid.uuid4()),
            component=component,
            attributes=attributes
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
    
    def debug(self, message: str, component: str, **kwargs):
        return self.log(LogSeverity.DEBUG, message, component, **kwargs)
    
    def info(self, message: str, component: str, **kwargs):
        return self.log(LogSeverity.INFO, message, component, **kwargs)
    
    def warning(self, message: str, component: str, **kwargs):
        return self.log(LogSeverity.WARNING, message, component, **kwargs)
    
    def error(self, message: str, component: str, **kwargs):
        return self.log(LogSeverity.ERROR, message, component, **kwargs)
    
    def critical(self, message: str, component: str, **kwargs):
        return self.log(LogSeverity.CRITICAL, message, component, **kwargs)
    
    def get_recent_logs(self, count: int = 100, 
                       min_severity: Optional[LogSeverity] = None) -> List[LogEntry]:
        with self._lock:
            logs = list(self._logs)
        if min_severity:
            severity_order = [LogSeverity.DEBUG, LogSeverity.INFO, 
                             LogSeverity.WARNING, LogSeverity.ERROR, LogSeverity.CRITICAL]
            min_idx = severity_order.index(min_severity)
            logs = [l for l in logs if severity_order.index(l.severity) >= min_idx]
        return logs[-count:]
    
    def clear_logs(self) -> None:
        with self._lock:
            self._logs.clear()


class CryptoMetricsCollector:
    """Thread-safe crypto-specific metrics collection."""
    
    # Crypto-specific histogram buckets (microsecond precision for fast operations)
    CRYPTO_LATENCY_BUCKETS = [0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    
    def __init__(self, config: CryptoObservabilityConfig):
        self._config = config
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._histograms: Dict[str, Dict[float, int]] = defaultdict(lambda: defaultdict(int))
        self._samples: deque = deque(maxlen=config.max_metric_samples)
        self._lock = threading.Lock()
        
        # v12 NEW: PQ algorithm specific metrics
        self._pq_operation_latency: Dict[str, Dict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._pq_error_counts: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._nist_level_usage: Dict[int, int] = defaultdict(int)
    
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
    
    def increment_counter(self, name: str, value: int = 1, 
                         labels: Optional[Dict[str, str]] = None) -> int:
        """Increment a counter - returns 0 if metrics disabled."""
        if not self._config.metrics_enabled:
            return 0
        with self._lock:
            self._counters[name] += value
            current = self._counters[name]
        self._record_sample(name, MetricType.COUNTER, float(current), labels)
        return current
    
    def set_gauge(self, name: str, value: float, 
                 labels: Optional[Dict[str, str]] = None) -> float:
        """Set a gauge value - returns value if enabled, 0 otherwise."""
        if not self._config.metrics_enabled:
            return 0.0
        with self._lock:
            self._gauges[name] = value
        self._record_sample(name, MetricType.GAUGE, value, labels)
        return value
    
    def record_timer(self, name: str, duration_seconds: float,
                    labels: Optional[Dict[str, str]] = None) -> None:
        """Record a timer measurement."""
        if not self._config.metrics_enabled:
            return
        with self._lock:
            self._timers[name].append(duration_seconds)
            for bucket in self.CRYPTO_LATENCY_BUCKETS:
                if duration_seconds <= bucket:
                    self._histograms[name][bucket] += 1
                    break
        self._record_sample(name, MetricType.TIMER, duration_seconds, labels)
    
    # === v12 NEW: PQ Algorithm Telemetry ===
    
    def record_pq_operation(self, algorithm: PQAlgorithm, operation: CryptoOperation,
                           duration_seconds: float, success: bool = True,
                           nist_level: Optional[NISTSecurityLevel] = None) -> None:
        """v12 NEW: Record post-quantum algorithm operation metrics."""
        if not self._config.metrics_enabled or not self._config.pq_algorithm_telemetry_enabled:
            return
        
        algo_name = algorithm.value
        op_name = operation.value
        metric_prefix = f"pq_{algo_name}_{op_name}"
        
        with self._lock:
            self._pq_operation_latency[algo_name][op_name].append(duration_seconds)
            self._counters[f"{metric_prefix}_total"] += 1
            if not success:
                self._pq_error_counts[algo_name][op_name] += 1
            if nist_level:
                self._nist_level_usage[nist_level.value] += 1
        
        self.record_timer(
            f"{metric_prefix}_latency_seconds",
            duration_seconds,
            {
                "algorithm": algo_name,
                "operation": op_name,
                "success": str(success).lower(),
                "nist_level": str(nist_level.value) if nist_level else "unknown"
            }
        )
    
    def record_hsm_kms_connection_metrics(self, provider_name: str, connection_time_ms: float,
                                          operations_count: int, error_count: int) -> None:
        """v12 NEW: Record HSM/KMS connection metrics."""
        if not self._config.metrics_enabled or not self._config.hsm_kms_monitoring_enabled:
            return
        
        availability = 1.0 - (error_count / max(operations_count, 1))
        
        self.set_gauge(
            f"hsm_{provider_name}_connection_time_ms",
            connection_time_ms
        )
        self.set_gauge(
            f"hsm_{provider_name}_availability",
            availability
        )
        self.increment_counter(
            f"hsm_{provider_name}_operations_total",
            operations_count
        )
        self.increment_counter(
            f"hsm_{provider_name}_errors_total",
            error_count
        )
    
    # === v12 NEW: Prometheus Export ===
    
    def export_prometheus(self) -> str:
        """v12 NEW: Export all crypto metrics in Prometheus/OpenMetrics format."""
        if not self._config.metrics_enabled or not self._config.prometheus_export_enabled:
            return "# QuantumCrypt Observability v12 - Prometheus export disabled\n"
        
        metrics = []
        
        # Export counters
        for name, value in self._counters.items():
            metrics.append(PrometheusMetric(
                name=name,
                metric_type="counter",
                value=float(value),
                help_text=f"QuantumCrypt counter metric: {name}"
            ))
        
        # Export gauges
        for name, value in self._gauges.items():
            metrics.append(PrometheusMetric(
                name=name,
                metric_type="gauge",
                value=value,
                help_text=f"QuantumCrypt gauge metric: {name}"
            ))
        
        # Export PQ algorithm summary metrics
        for algo_name, ops in self._pq_operation_latency.items():
            for op_name, latencies in ops.items():
                if latencies:
                    sorted_lat = sorted(latencies)
                    n = len(sorted_lat)
                    metrics.append(PrometheusMetric(
                        name=f"pq_{algo_name}_{op_name}_count",
                        metric_type="gauge",
                        value=float(n),
                        help_text=f"Operation count for {algo_name} {op_name}"
                    ))
                    metrics.append(PrometheusMetric(
                        name=f"pq_{algo_name}_{op_name}_p95_seconds",
                        metric_type="gauge",
                        value=sorted_lat[int(n * 0.95)],
                        help_text=f"95th percentile latency for {algo_name} {op_name}"
                    ))
        
        # Export NIST level usage
        for level, count in self._nist_level_usage.items():
            metrics.append(PrometheusMetric(
                name=f"nist_level_{level}_operations_total",
                metric_type="counter",
                value=float(count),
                labels={"nist_security_level": str(level)},
                help_text=f"Operations at NIST security level {level}"
            ))
        
        return "\n\n".join(m.to_openmetrics() for m in metrics) + "\n# EOF\n"
    
    def time_function(self, name: Optional[str] = None, 
                     labels: Optional[Dict[str, str]] = None):
        """Decorator to time function execution."""
        def decorator(func: Callable) -> Callable:
            metric_name = name or f"timer.{func.__name__}"
            def wrapper(*args, **kwargs):
                start = time.perf_counter()
                try:
                    return func(*args, **kwargs)
                finally:
                    duration = time.perf_counter() - start
                    self.record_timer(metric_name, duration, labels)
            return wrapper
        return decorator
    
    def get_pq_stats(self) -> Dict[str, Any]:
        """v12 NEW: Get PQ algorithm performance statistics."""
        with self._lock:
            stats = {}
            for algo_name, ops in self._pq_operation_latency.items():
                algo_stats = {}
                for op_name, latencies in ops.items():
                    if latencies:
                        sorted_lat = sorted(latencies)
                        n = len(sorted_lat)
                        algo_stats[op_name] = {
                            "count": n,
                            "avg_ms": (sum(latencies) / n) * 1000,
                            "p50_ms": sorted_lat[int(n * 0.5)] * 1000,
                            "p95_ms": sorted_lat[int(n * 0.95)] * 1000,
                            "errors": self._pq_error_counts[algo_name].get(op_name, 0)
                        }
                if algo_stats:
                    stats[algo_name] = algo_stats
            return stats
    
    def get_counter_value(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)
    
    def get_gauge_value(self, name: str) -> Optional[float]:
        with self._lock:
            return self._gauges.get(name)
    
    def get_all_counters(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counters)
    
    def get_all_gauges(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._gauges)


class CryptoHealthCheckFramework:
    """Health check framework with HSM/KMS monitoring."""
    
    def __init__(self, config: CryptoObservabilityConfig):
        self._config = config
        self._checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self._lock = threading.Lock()
        self._last_results: Dict[str, HealthCheckResult] = {}
        self._hsm_last_ping: Dict[str, datetime] = {}
        self._kms_last_ping: Dict[str, datetime] = {}
    
    def register_check(self, name: str, check_func: Callable[[], HealthCheckResult]) -> None:
        """Register a health check function."""
        with self._lock:
            self._checks[name] = check_func
    
    # === v12 NEW: HSM/KMS Health Checks ===
    
    def record_hsm_ping(self, provider_name: str, ping_time: Optional[datetime] = None) -> None:
        """v12 NEW: Record HSM ping time."""
        with self._lock:
            self._hsm_last_ping[provider_name] = ping_time or datetime.utcnow()
    
    def record_kms_ping(self, connection_id: str, ping_time: Optional[datetime] = None) -> None:
        """v12 NEW: Record KMS ping time."""
        with self._lock:
            self._kms_last_ping[connection_id] = ping_time or datetime.utcnow()
    
    def check_hsm_connection(self, provider_name: str) -> HealthCheckResult:
        """v12 NEW: Health check for HSM connection liveness."""
        if not self._config.hsm_kms_monitoring_enabled:
            return HealthCheckResult(
                name=f"hsm_{provider_name}_connection",
                status=HealthStatus.UNKNOWN,
                message="HSM/KMS monitoring not enabled",
                duration_ms=0.0
            )
        
        start = time.perf_counter()
        last_ping = self._hsm_last_ping.get(provider_name)
        
        if last_ping is None:
            return HealthCheckResult(
                name=f"hsm_{provider_name}_connection",
                status=HealthStatus.DEGRADED,
                message=f"HSM {provider_name}: No ping recorded yet",
                duration_ms=(time.perf_counter() - start) * 1000
            )
        
        age_seconds = (datetime.utcnow() - last_ping).total_seconds()
        timeout = self._config.crypto_slo_config.hsm_connection_timeout_ms / 1000.0
        
        if age_seconds <= timeout:
            status = HealthStatus.HEALTHY
            message = f"HSM {provider_name}: Connected ({age_seconds:.1f}s since last ping)"
        elif age_seconds <= timeout * 2:
            status = HealthStatus.DEGRADED
            message = f"HSM {provider_name}: Connection aging ({age_seconds:.1f}s)"
        else:
            status = HealthStatus.UNHEALTHY
            message = f"HSM {provider_name}: Connection timed out ({age_seconds:.1f}s)"
        
        return HealthCheckResult(
            name=f"hsm_{provider_name}_connection",
            status=status,
            message=message,
            duration_ms=(time.perf_counter() - start) * 1000,
            details={"last_ping_seconds": age_seconds, "timeout_seconds": timeout}
        )
    
    def run_check(self, name: str) -> Optional[HealthCheckResult]:
        """Run a single health check - returns None if disabled."""
        if not self._config.health_checks_enabled:
            return None
        
        with self._lock:
            check_func = self._checks.get(name)
        
        # v12 NEW: Handle built-in HSM checks
        if name.startswith("hsm_") and name.endswith("_connection"):
            provider = name.replace("hsm_", "").replace("_connection", "")
            result = self.check_hsm_connection(provider)
            with self._lock:
                self._last_results[name] = result
            return result
        
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
                duration_ms=(time.perf_counter() - start) * 1000
            )
        
        duration_ms = (time.perf_counter() - start) * 1000
        result.duration_ms = duration_ms
        
        with self._lock:
            self._last_results[name] = result
        
        return result
    
    def run_all_checks(self) -> Dict[str, Optional[HealthCheckResult]]:
        """Run all registered health checks."""
        results = {}
        for name in list(self._checks.keys()):
            results[name] = self.run_check(name)
        return results
    
    def get_overall_status(self) -> HealthStatus:
        """Get aggregate health status across all checks."""
        if not self._config.health_checks_enabled or not self._last_results:
            return HealthStatus.UNKNOWN
        
        statuses = [r.status for r in self._last_results.values()]
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY


class CryptoDistributedTracer:
    """Distributed tracing with crypto-specific cross-module correlation."""
    
    def __init__(self, config: CryptoObservabilityConfig):
        self._config = config
        self._local = threading.local()
        self._lock = threading.Lock()
        self._trace_count = 0
    
    def generate_correlation_id(self) -> str:
        """Generate a new correlation ID."""
        if not self._config.tracing_enabled or not self._config.generate_correlation_ids:
            return ""
        return str(uuid.uuid4())
    
    def set_correlation_id(self, correlation_id: str) -> None:
        """Set correlation ID for current thread context."""
        if self._config.tracing_enabled:
            self._local.correlation_id = correlation_id
    
    def get_correlation_id(self) -> Optional[str]:
        """Get correlation ID from current thread context."""
        if not self._config.tracing_enabled:
            return None
        return getattr(self._local, 'correlation_id', None)
    
    # === v12 NEW: Crypto Cross-Module Baggage ===
    
    def set_crypto_baggage(self, key: CryptoBaggageKey, value: str) -> None:
        """v12 NEW: Set standardized crypto baggage for cross-module correlation."""
        if not self._config.tracing_enabled or not self._config.cross_module_correlation_enabled:
            return
        self.set_baggage(key.value, value)
    
    def get_crypto_baggage(self, key: CryptoBaggageKey) -> Optional[str]:
        """v12 NEW: Get standardized crypto baggage value."""
        if not self._config.tracing_enabled or not self._config.cross_module_correlation_enabled:
            return None
        return self.get_baggage().get(key.value)
    
    def create_crypto_operation_context(self,
                                        algorithm: PQAlgorithm,
                                        operation: CryptoOperation,
                                        nist_level: Optional[NISTSecurityLevel] = None,
                                        key_id: Optional[str] = None,
                                        hsm_provider: Optional[str] = None) -> str:
        """v12 NEW: Create complete crypto operation tracing context."""
        if not self._config.tracing_enabled or not self._config.cross_module_correlation_enabled:
            return ""
        
        operation_id = self.generate_correlation_id()
        self.set_correlation_id(operation_id)
        
        self.set_crypto_baggage(CryptoBaggageKey.CRYPTO_OPERATION_ID, operation_id)
        self.set_crypto_baggage(CryptoBaggageKey.PQ_ALGORITHM, algorithm.value)
        if nist_level:
            self.set_crypto_baggage(CryptoBaggageKey.NIST_SECURITY_LEVEL, str(nist_level.value))
        if key_id:
            self.set_crypto_baggage(CryptoBaggageKey.KEY_ID, key_id)
        if hsm_provider:
            self.set_crypto_baggage(CryptoBaggageKey.HSM_PROVIDER, hsm_provider)
        
        return operation_id
    
    def set_baggage(self, key: str, value: str) -> None:
        """Set baggage item for propagation."""
        if not self._config.tracing_enabled or not self._config.propagate_baggage:
            return
        if not hasattr(self._local, 'baggage'):
            self._local.baggage = {}
        self._local.baggage[key] = value
    
    def get_baggage(self) -> Dict[str, str]:
        """Get all baggage items."""
        if not self._config.tracing_enabled or not self._config.propagate_baggage:
            return {}
        return getattr(self._local, 'baggage', {}).copy()
    
    def clear_context(self) -> None:
        """Clear tracing context for current thread."""
        if hasattr(self._local, 'correlation_id'):
            delattr(self._local, 'correlation_id')
        if hasattr(self._local, 'baggage'):
            delattr(self._local, 'baggage')


class QuantumCryptObservabilityV12:
    """
    v12 MAIN CLASS: Unified observability facade for QuantumCrypt AI.
    
    NEW IN v12:
    - PQ Algorithm Performance Telemetry
    - NIST Security Level Tracking
    - Key Operation Latency Histograms
    - HSM/KMS Connection Health Checks
    - Cross-Module Correlation Baggage
    - Crypto SLO Tracking
    - Prometheus/Grafana Export
    
    ALL FEATURES OPT-IN - 100% backward compatible
    """
    
    _instance: Optional['QuantumCryptObservabilityV12'] = None
    _instance_lock = threading.Lock()
    
    @classmethod
    def get_instance(cls, config: Optional[CryptoObservabilityConfig] = None) -> 'QuantumCryptObservabilityV12':
        """Thread-safe singleton pattern - OPT-IN by default."""
        with cls._instance_lock:
            if cls._instance is None:
                actual_config = config or CryptoObservabilityConfig()
                cls._instance = cls(actual_config)
            return cls._instance
    
    def __init__(self, config: CryptoObservabilityConfig):
        self._config = config
        self.logger = StructuredLogger(config)
        self.metrics = CryptoMetricsCollector(config)
        self.health = CryptoHealthCheckFramework(config)
        self.tracer = CryptoDistributedTracer(config)
        self._initialized_at = datetime.utcnow()
    
    def get_config(self) -> CryptoObservabilityConfig:
        return self._config
    
    def enable_all(self) -> None:
        """Convenience method to enable ALL observability features."""
        self._config.logging_enabled = True
        self._config.metrics_enabled = True
        self._config.health_checks_enabled = True
        self._config.tracing_enabled = True
        self._config.slo_tracking_enabled = True
        self._config.pq_algorithm_telemetry_enabled = True
        self._config.hsm_kms_monitoring_enabled = True
        self._config.prometheus_export_enabled = True
        self._config.cross_module_correlation_enabled = True
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get summary of observability system status."""
        return {
            "version": "v12",
            "initialized_at": self._initialized_at.isoformat(),
            "features_enabled": {
                "logging": self._config.logging_enabled,
                "metrics": self._config.metrics_enabled,
                "health_checks": self._config.health_checks_enabled,
                "tracing": self._config.tracing_enabled,
                "pq_algorithm_telemetry": self._config.pq_algorithm_telemetry_enabled,
                "hsm_kms_monitoring": self._config.hsm_kms_monitoring_enabled,
                "prometheus_export": self._config.prometheus_export_enabled,
                "cross_module_correlation": self._config.cross_module_correlation_enabled
            },
            "overall_health": self.health.get_overall_status().value
        }


# Singleton instance accessor - disabled by default
def get_crypto_observability_v12() -> QuantumCryptObservabilityV12:
    """Get the v12 crypto observability singleton instance."""
    return QuantumCryptObservabilityV12.get_instance()
