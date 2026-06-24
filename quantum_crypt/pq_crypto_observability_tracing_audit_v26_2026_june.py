"""
QuantumCrypt AI - PQ Crypto Observability & Instrumentation Module (Dimension D)
Version: v26 - June 2026
Philosophy: ADD-ONLY, OPT-IN, Backward Compatible, No breaking changes
This module provides PQ crypto-specific observability:
1. PQ crypto operation tracing with unique key operation IDs
2. Crypto-specific metrics with algorithm and security level labels
3. HSM connection health monitoring with dependency tracking
4. Key management audit logging with sensitive data redaction
5. Randomness quality and entropy metrics
6. Algorithm performance benchmarking with percentiles (P50, P95, P99)
7. Prometheus exposition format for crypto metrics
8. All instrumentation is OPT-IN - existing code behavior 100% preserved
"""
import json
import time
import uuid
import math
import threading
import secrets
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List, Tuple
from functools import wraps
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import contextvars
import hashlib


# -----------------------------------------------------------------------------
# Core Enums and Data Classes
# -----------------------------------------------------------------------------
class CryptoOperationType(Enum):
    KEY_GENERATION = "key_generation"
    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    VERIFICATION = "verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    RANDOMNESS = "randomness"
    HSM_CONNECT = "hsm_connect"
    HSM_DISCONNECT = "hsm_disconnect"


class PQSecurityLevel(Enum):
    LEVEL_1 = "NIST_LEVEL_1"  # 128-bit
    LEVEL_3 = "NIST_LEVEL_3"  # 192-bit
    LEVEL_5 = "NIST_LEVEL_5"  # 256-bit


class AuditLogLevel(Enum):
    AUDIT = "AUDIT"
    SECURITY = "SECURITY"
    OPERATIONAL = "OPERATIONAL"
    DEBUG = "DEBUG"


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class CryptoMetric:
    name: str
    algorithm: str
    security_level: PQSecurityLevel
    operation_type: CryptoOperationType
    value: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class PercentileResult:
    p50: float
    p95: float
    p99: float
    min: float
    max: float
    avg: float
    count: int


@dataclass
class KeyOperationContext:
    operation_id: str
    algorithm: str
    operation_type: CryptoOperationType
    security_level: PQSecurityLevel
    start_time: float
    trace_id: str = ""
    user_id: str = ""
    key_id: str = ""


@dataclass
class HealthCheck:
    name: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class EntropyMetrics:
    bits_available: int
    bits_consumed: int
    quality_score: float  # 0.0 - 1.0
    source: str = "system"


# -----------------------------------------------------------------------------
# Context Variables
# -----------------------------------------------------------------------------
_current_key_operation: contextvars.ContextVar[Optional[KeyOperationContext]] = contextvars.ContextVar(
    "current_key_operation",
    default=None
)

_correlation_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "crypto_correlation_id",
    default=None
)


# -----------------------------------------------------------------------------
# Global Configuration (ALL OPT-IN BY DEFAULT)
# -----------------------------------------------------------------------------
class CryptoObservabilityConfig:
    """PQ Crypto observability configuration - ALL OPT-IN by default"""
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        # ALL FEATURES DISABLED BY DEFAULT - OPT-IN ONLY
        self.audit_logging_enabled: bool = False
        self.crypto_metrics_enabled: bool = False
        self.health_monitoring_enabled: bool = False
        self.tracing_enabled: bool = False
        self.entropy_monitoring_enabled: bool = False
        self.prometheus_exposition_enabled: bool = False
        self.sensitive_data_redaction: bool = True
        self.min_audit_level: AuditLogLevel = AuditLogLevel.SECURITY
        self._initialized = True
    
    def enable_all(self):
        """Enable all crypto observability features"""
        self.audit_logging_enabled = True
        self.crypto_metrics_enabled = True
        self.health_monitoring_enabled = True
        self.tracing_enabled = True
        self.entropy_monitoring_enabled = True
        self.prometheus_exposition_enabled = True
    
    def enable_audit_logging(self):
        self.audit_logging_enabled = True
    
    def enable_metrics(self):
        self.crypto_metrics_enabled = True
    
    def enable_health_monitoring(self):
        self.health_monitoring_enabled = True
    
    def enable_tracing(self):
        self.tracing_enabled = True
    
    def enable_entropy_monitoring(self):
        self.entropy_monitoring_enabled = True
    
    def enable_prometheus(self):
        self.prometheus_exposition_enabled = True
    
    @classmethod
    def _reset_for_testing(cls):
        """Reset ALL singletons for test isolation - FOR TESTING ONLY"""
        with cls._lock:
            cls._instance = None
        
        # Also reset all global module-level singletons
        global _global_audit_logger, _global_metrics, _global_health, _global_tracing
        _global_audit_logger = None
        _global_metrics = None
        _global_health = None
        _global_tracing = None


# -----------------------------------------------------------------------------
# Percentile Histogram
# -----------------------------------------------------------------------------
class PercentileHistogram:
    """Thread-safe histogram for crypto latency percentiles"""
    
    def __init__(self, max_samples: int = 10000):
        self._samples: deque = deque(maxlen=max_samples)
        self._lock = threading.Lock()
        self._sum = 0.0
        self._count = 0
    
    def record(self, value: float):
        with self._lock:
            self._samples.append(value)
            self._sum += value
            self._count += 1
    
    def get_percentiles(self) -> PercentileResult:
        with self._lock:
            if not self._samples:
                return PercentileResult(0, 0, 0, 0, 0, 0, 0)
            
            sorted_samples = sorted(self._samples)
            n = len(sorted_samples)
            
            def get_p(pct: float) -> float:
                idx = max(0, min(n - 1, int(math.ceil(n * pct / 100)) - 1))
                return sorted_samples[idx]
            
            return PercentileResult(
                p50=get_p(50),
                p95=get_p(95),
                p99=get_p(99),
                min=sorted_samples[0],
                max=sorted_samples[-1],
                avg=self._sum / self._count if self._count > 0 else 0,
                count=self._count
            )


# -----------------------------------------------------------------------------
# Sensitive Data Redaction
# -----------------------------------------------------------------------------
class SensitiveDataRedactor:
    """Redacts sensitive crypto material from logs"""
    
    REDACTION_MARKER = "[REDACTED]"
    KEY_ID_PATTERN_LENGTH = 8
    
    @classmethod
    def redact_key_material(cls, data: Any) -> Any:
        """Recursively redact sensitive key material"""
        if isinstance(data, bytes):
            return cls.REDACTION_MARKER.encode()
        elif isinstance(data, str):
            # Check if looks like hex key material
            if len(data) > 32 and all(c in '0123456789abcdefABCDEF' for c in data):
                return f"{cls.REDACTION_MARKER}({len(data)} bytes)"
            return data
        elif isinstance(data, dict):
            return {k: cls.redact_key_material(v) for k, v in data.items()}
        elif isinstance(data, (list, tuple)):
            return [cls.redact_key_material(item) for item in data]
        else:
            return data
    
    @classmethod
    def hash_key_id(cls, key_material: bytes) -> str:
        """Generate a safe hash-based key ID for logging"""
        h = hashlib.sha256(key_material).hexdigest()
        return f"key-{h[:cls.KEY_ID_PATTERN_LENGTH]}"


# -----------------------------------------------------------------------------
# Crypto Audit Logger
# -----------------------------------------------------------------------------
class CryptoAuditLogger:
    """Audit logger for crypto operations with sensitive data redaction"""
    
    def __init__(self, name: str = "quantum_crypt"):
        self.name = name
        self.config = CryptoObservabilityConfig()
        self.redactor = SensitiveDataRedactor()
    
    def _log(self, level: AuditLogLevel, message: str, **kwargs):
        """Internal audit log method"""
        if not self.config.audit_logging_enabled:
            return
        
        if level.value < self.config.min_audit_level.value:
            return
        
        # Get current operation context
        ctx = _current_key_operation.get()
        cid = _correlation_id.get()
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "logger": self.name,
            "audit_level": level.value,
            "message": message,
            "correlation_id": cid,
            "operation_id": ctx.operation_id if ctx else None,
            "algorithm": ctx.algorithm if ctx else None,
            "operation_type": ctx.operation_type.value if ctx else None,
            "security_level": ctx.security_level.value if ctx else None,
        }
        
        # Add and redact extra fields
        for key, value in kwargs.items():
            if self.config.sensitive_data_redaction:
                log_entry[key] = self.redactor.redact_key_material(value)
            else:
                log_entry[key] = value
        
        print(json.dumps(log_entry))
    
    def audit(self, message: str, **kwargs):
        """Mandatory audit log - always logged if enabled"""
        self._log(AuditLogLevel.AUDIT, message, **kwargs)
    
    def security(self, message: str, **kwargs):
        """Security-relevant events"""
        self._log(AuditLogLevel.SECURITY, message, **kwargs)
    
    def operational(self, message: str, **kwargs):
        """Operational events"""
        self._log(AuditLogLevel.OPERATIONAL, message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        """Debug events"""
        self._log(AuditLogLevel.DEBUG, message, **kwargs)


# -----------------------------------------------------------------------------
# PQ Crypto Metrics Collector
# -----------------------------------------------------------------------------
class PQCryptoMetricsCollector:
    """Metrics collector specialized for PQ crypto operations"""
    
    def __init__(self):
        self.config = CryptoObservabilityConfig()
        self._operation_metrics: Dict[Tuple[str, str, str], List[float]] = defaultdict(list)
        self._histograms: Dict[str, PercentileHistogram] = {}
        self._counters: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        self._entropy_metrics = EntropyMetrics(256, 0, 1.0)
    
    def record_operation(self, algorithm: str, operation_type: CryptoOperationType,
                        security_level: PQSecurityLevel, duration_ms: float):
        """Record a crypto operation duration"""
        if not self.config.crypto_metrics_enabled:
            return
        
        key = (algorithm, operation_type.value, security_level.value)
        
        with self._lock:
            self._operation_metrics[key].append(duration_ms)
            self._counters[f"{algorithm}_{operation_type.value}_total"] += 1
            
            # Record for percentiles
            hist_key = f"{algorithm}_{operation_type.value}"
            if hist_key not in self._histograms:
                self._histograms[hist_key] = PercentileHistogram()
            self._histograms[hist_key].record(duration_ms)
    
    def increment_counter(self, name: str, value: int = 1):
        """Increment a counter metric"""
        if not self.config.crypto_metrics_enabled:
            return
        
        with self._lock:
            self._counters[name] += value
    
    def update_entropy(self, bits_consumed: int, quality_score: Optional[float] = None):
        """Update entropy consumption metrics"""
        if not self.config.entropy_monitoring_enabled:
            return
        
        with self._lock:
            self._entropy_metrics.bits_consumed += bits_consumed
            if quality_score is not None:
                self._entropy_metrics.quality_score = quality_score
    
    def get_operation_percentiles(self, algorithm: str, operation_type: CryptoOperationType) -> Optional[PercentileResult]:
        """Get percentile stats for an algorithm operation"""
        with self._lock:
            hist_key = f"{algorithm}_{operation_type.value}"
            hist = self._histograms.get(hist_key)
            if hist:
                return hist.get_percentiles()
            return None
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all aggregated metrics"""
        with self._lock:
            result = {
                "counters": dict(self._counters),
                "operation_latency": {},
                "entropy": {
                    "bits_available": self._entropy_metrics.bits_available,
                    "bits_consumed": self._entropy_metrics.bits_consumed,
                    "quality_score": self._entropy_metrics.quality_score
                }
            }
            
            for (alg, op, level), durations in self._operation_metrics.items():
                if durations:
                    key = f"{alg}_{op}_{level}"
                    result["operation_latency"][key] = {
                        "algorithm": alg,
                        "operation": op,
                        "security_level": level,
                        "count": len(durations),
                        "avg_ms": sum(durations) / len(durations),
                        "min_ms": min(durations),
                        "max_ms": max(durations)
                    }
            
            return result
    
    def export_prometheus(self) -> str:
        """Export in Prometheus exposition format"""
        if not self.config.prometheus_exposition_enabled:
            return ""
        
        lines = []
        metrics = self.get_all_metrics()
        
        # Counters
        for name, value in metrics["counters"].items():
            safe_name = name.replace("-", "_").replace(".", "_")
            lines.append(f"# TYPE crypto_{safe_name}_total counter")
            lines.append(f"crypto_{safe_name}_total {value}")
        
        # Latency histograms
        for key, data in metrics["operation_latency"].items():
            safe_key = key.replace("-", "_").replace(".", "_")
            lines.append(f"# TYPE crypto_{safe_key}_latency_seconds summary")
            
            percentiles = self.get_operation_percentiles(
                data["algorithm"],
                CryptoOperationType(data["operation"])
            )
            
            if percentiles:
                lines.append(f'crypto_{safe_key}_latency_seconds{{quantile="0.5"}} {percentiles.p50 / 1000}')
                lines.append(f'crypto_{safe_key}_latency_seconds{{quantile="0.95"}} {percentiles.p95 / 1000}')
                lines.append(f'crypto_{safe_key}_latency_seconds{{quantile="0.99"}} {percentiles.p99 / 1000}')
            lines.append(f"crypto_{safe_key}_latency_seconds_count {data['count']}")
        
        return "\n".join(lines) + "\n"
    
    def reset(self):
        with self._lock:
            self._operation_metrics.clear()
            self._histograms.clear()
            self._counters.clear()
            self._entropy_metrics = EntropyMetrics(256, 0, 1.0)


# -----------------------------------------------------------------------------
# Key Operation Tracing Manager
# -----------------------------------------------------------------------------
class KeyOperationTracingManager:
    """Manages tracing context for key cryptographic operations"""
    
    def __init__(self):
        self.config = CryptoObservabilityConfig()
    
    def generate_operation_id(self) -> str:
        """Generate unique operation ID"""
        return f"crypto-op-{uuid.uuid4().hex[:12]}"
    
    def generate_trace_id(self) -> str:
        """Generate W3C compliant trace ID"""
        return uuid.uuid4().hex
    
    def start_operation(self, algorithm: str, operation_type: CryptoOperationType,
                       security_level: PQSecurityLevel, **kwargs) -> KeyOperationContext:
        """Start tracking a cryptographic key operation"""
        if not self.config.tracing_enabled:
            return KeyOperationContext("", algorithm, operation_type, security_level, 0)
        
        ctx = KeyOperationContext(
            operation_id=self.generate_operation_id(),
            algorithm=algorithm,
            operation_type=operation_type,
            security_level=security_level,
            start_time=time.time(),
            trace_id=self.generate_trace_id(),
            key_id=kwargs.get("key_id", ""),
            user_id=kwargs.get("user_id", "")
        )
        
        _current_key_operation.set(ctx)
        
        # Set correlation ID if not already set
        if not _correlation_id.get():
            _correlation_id.set(f"qc-cid-{uuid.uuid4().hex[:12]}")
        
        return ctx
    
    def end_operation(self, ctx: KeyOperationContext, success: bool = True) -> float:
        """End tracking and return duration in ms"""
        duration_ms = (time.time() - ctx.start_time) * 1000
        
        # Record metrics
        metrics = get_crypto_metrics()
        metrics.record_operation(ctx.algorithm, ctx.operation_type, ctx.security_level, duration_ms)
        
        # Audit log
        logger = CryptoAuditLogger()
        logger.audit(
            "Crypto operation completed",
            duration_ms=round(duration_ms, 2),
            success=success
        )
        
        return duration_ms
    
    def get_current_operation(self) -> Optional[KeyOperationContext]:
        return _current_key_operation.get()
    
    def get_correlation_id(self) -> Optional[str]:
        return _correlation_id.get()


# -----------------------------------------------------------------------------
# HSM Health Monitor with Dependencies
# -----------------------------------------------------------------------------
class HSMHealthMonitor:
    """Health monitoring for HSM connections with dependency tracking"""
    
    def __init__(self):
        self.config = CryptoObservabilityConfig()
        self._checks: Dict[str, Callable[[], HealthCheck]] = {}
        self._dependencies: Dict[str, List[str]] = {}
        self._lock = threading.Lock()
        self._hsm_connection_stats = {
            "successful_connections": 0,
            "failed_connections": 0,
            "connection_timeouts": 0,
            "last_health_check": 0.0
        }
    
    def reset(self):
        """Reset all health checks and stats - FOR TESTING ONLY"""
        with self._lock:
            self._checks.clear()
            self._dependencies.clear()
            self._hsm_connection_stats = {
                "successful_connections": 0,
                "failed_connections": 0,
                "connection_timeouts": 0,
                "last_health_check": 0.0
            }
    
    def register_health_check(self, name: str, check_func: Callable[[], HealthCheck],
                             dependencies: Optional[List[str]] = None):
        """Register a health check with optional dependencies"""
        with self._lock:
            self._checks[name] = check_func
            self._dependencies[name] = dependencies or []
    
    def record_hsm_connection(self, success: bool):
        """Record HSM connection attempt"""
        with self._lock:
            if success:
                self._hsm_connection_stats["successful_connections"] += 1
            else:
                self._hsm_connection_stats["failed_connections"] += 1
            self._hsm_connection_stats["last_health_check"] = time.time()
    
    def record_hsm_timeout(self):
        """Record HSM timeout"""
        with self._lock:
            self._hsm_connection_stats["connection_timeouts"] += 1
    
    def _resolve_dependencies(self, name: str, results: Dict[str, HealthCheck]) -> HealthStatus:
        """Resolve health status considering dependencies"""
        check = results.get(name)
        if not check:
            return HealthStatus.UNHEALTHY
        
        status = check.status
        
        for dep in self._dependencies.get(name, []):
            dep_status = self._resolve_dependencies(dep, results)
            if dep_status == HealthStatus.UNHEALTHY:
                return HealthStatus.UNHEALTHY
            elif dep_status == HealthStatus.DEGRADED and status == HealthStatus.HEALTHY:
                status = HealthStatus.DEGRADED
        
        return status
    
    def run_health_checks(self) -> Dict[str, Any]:
        """Run all health checks with dependency resolution"""
        if not self.config.health_monitoring_enabled:
            return {"health_monitoring_enabled": False}
        
        raw_results = {}
        
        with self._lock:
            # Run all checks
            for name, check_func in self._checks.items():
                start_time = time.time()
                try:
                    result = check_func()
                    result.duration_ms = (time.time() - start_time) * 1000
                    raw_results[name] = result
                except Exception as e:
                    raw_results[name] = HealthCheck(
                        name=name,
                        status=HealthStatus.UNHEALTHY,
                        message=f"Check failed: {str(e)}",
                        duration_ms=(time.time() - start_time) * 1000
                    )
            
            # Resolve dependencies
            final_results = []
            overall = HealthStatus.HEALTHY
            
            for name, result in raw_results.items():
                resolved = self._resolve_dependencies(name, raw_results)
                result.status = resolved
                final_results.append(result)
                
                if resolved == HealthStatus.UNHEALTHY:
                    overall = HealthStatus.UNHEALTHY
                elif resolved == HealthStatus.DEGRADED and overall == HealthStatus.HEALTHY:
                    overall = HealthStatus.DEGRADED
        
        return {
            "overall_status": overall.value,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "hsm_stats": self._hsm_connection_stats.copy(),
            "checks": [
                {
                    "name": r.name,
                    "status": r.status.value,
                    "message": r.message,
                    "duration_ms": round(r.duration_ms, 2),
                    "dependencies": self._dependencies.get(r.name, []),
                    "details": r.details
                }
                for r in final_results
            ]
        }


# -----------------------------------------------------------------------------
# Decorators
# -----------------------------------------------------------------------------
def traced_crypto_operation(algorithm: str, operation_type: CryptoOperationType,
                           security_level: PQSecurityLevel = PQSecurityLevel.LEVEL_5):
    """
    Decorator for tracing cryptographic operations - OPT-IN
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = CryptoObservabilityConfig()
            if not config.tracing_enabled and not config.crypto_metrics_enabled:
                return func(*args, **kwargs)
            
            tracing = KeyOperationTracingManager()
            ctx = tracing.start_operation(algorithm, operation_type, security_level)
            
            try:
                result = func(*args, **kwargs)
                tracing.end_operation(ctx, success=True)
                return result
            except Exception as e:
                tracing.end_operation(ctx, success=False)
                raise
        return wrapper
    return decorator


def audited_crypto_operation(audit_level: AuditLogLevel = AuditLogLevel.AUDIT,
                            redact_sensitive: bool = True):
    """
    Decorator for auditing crypto operations - OPT-IN
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            config = CryptoObservabilityConfig()
            if not config.audit_logging_enabled:
                return func(*args, **kwargs)
            
            logger = CryptoAuditLogger()
            func_name = func.__name__
            
            logger._log(audit_level, f"START: {func_name}", function=func_name)
            
            try:
                result = func(*args, **kwargs)
                logger._log(audit_level, f"COMPLETE: {func_name}", 
                           function=func_name, success=True)
                return result
            except Exception as e:
                logger.security(f"FAILED: {func_name}",
                               function=func_name,
                               error_type=type(e).__name__,
                               success=False)
                raise
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Global Singleton Instances
# -----------------------------------------------------------------------------
_global_audit_logger: Optional[CryptoAuditLogger] = None
_global_metrics: Optional[PQCryptoMetricsCollector] = None
_global_health: Optional[HSMHealthMonitor] = None
_global_tracing: Optional[KeyOperationTracingManager] = None


def get_audit_logger() -> CryptoAuditLogger:
    global _global_audit_logger
    if _global_audit_logger is None:
        _global_audit_logger = CryptoAuditLogger()
    return _global_audit_logger


def get_crypto_metrics() -> PQCryptoMetricsCollector:
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = PQCryptoMetricsCollector()
    return _global_metrics


def get_health_monitor() -> HSMHealthMonitor:
    global _global_health
    if _global_health is None:
        _global_health = HSMHealthMonitor()
    return _global_health


def get_tracing_manager() -> KeyOperationTracingManager:
    global _global_tracing
    if _global_tracing is None:
        _global_tracing = KeyOperationTracingManager()
    return _global_tracing


def get_config() -> CryptoObservabilityConfig:
    return CryptoObservabilityConfig()


# -----------------------------------------------------------------------------
# Export Public API
# -----------------------------------------------------------------------------
__all__ = [
    "CryptoObservabilityConfig", "get_config",
    "CryptoOperationType", "PQSecurityLevel", "AuditLogLevel", "HealthStatus",
    "CryptoMetric", "PercentileResult", "KeyOperationContext", 
    "EntropyMetrics", "PercentileHistogram",
    "SensitiveDataRedactor",
    "CryptoAuditLogger", "get_audit_logger", "audited_crypto_operation",
    "PQCryptoMetricsCollector", "get_crypto_metrics",
    "KeyOperationTracingManager", "get_tracing_manager", "traced_crypto_operation",
    "HSMHealthMonitor", "get_health_monitor",
]
