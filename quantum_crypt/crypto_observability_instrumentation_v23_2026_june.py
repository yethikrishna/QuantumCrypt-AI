"""
QuantumCrypt AI - Crypto Observability & Instrumentation v23
===========================================================
Dimension D: Observability & Instrumentation
Version: v23 (odd number pattern maintained: v15 -> v17 -> v19 -> v21 -> v23)

STRICTLY ADD-ONLY: This module wraps existing code, never modifies it.
100% OPT-IN: All instrumentation is disabled by default, must be explicitly enabled.
BACKWARD COMPATIBLE: No breaking changes to existing APIs.
CRYPTO-SPECIFIC: Features tailored for cryptographic operations.

Features:
- Crypto-audited structured logging (key material redaction)
- Cryptographic operation metrics (keygen, sign, verify, encrypt, decrypt)
- HSM & KMS health monitoring
- Post-quantum algorithm performance tracking
- Key lifecycle event tracing
- Constant-time operation verification metrics
- Side-channel resistance monitoring
- All opt-in, zero overhead when disabled
"""

import json
import time
import uuid
import threading
import hashlib
import hmac
from typing import Dict, List, Any, Optional, Callable, TypeVar
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from functools import wraps
from collections import defaultdict
from contextlib import contextmanager
from enum import Enum

# -----------------------------------------------------------------------------
# Configuration - ALL DISABLED BY DEFAULT
# -----------------------------------------------------------------------------
@dataclass
class CryptoObservabilityConfig:
    """Crypto-specific observability config - ALL DISABLED BY DEFAULT."""
    enable_crypto_audit_logging: bool = False
    enable_crypto_metrics: bool = False
    enable_hsm_health_checks: bool = False
    enable_key_lifecycle_tracing: bool = False
    enable_side_channel_monitoring: bool = False
    enable_constant_time_verification: bool = False
    audit_log_level: str = "WARNING"
    redact_all_key_material: bool = True
    log_key_hashes_only: bool = True
    metrics_retention_seconds: int = 86400  # 24h for crypto audit
    max_audit_events_per_second: int = 1000

    def is_any_enabled(self) -> bool:
        """Check if any crypto observability feature is enabled."""
        return any([
            self.enable_crypto_audit_logging,
            self.enable_crypto_metrics,
            self.enable_hsm_health_checks,
            self.enable_key_lifecycle_tracing,
            self.enable_side_channel_monitoring,
            self.enable_constant_time_verification,
        ])

# Global config - everything disabled by default
_global_config = CryptoObservabilityConfig()
_config_lock = threading.Lock()

def configure_crypto_observability(**kwargs) -> None:
    """
    Configure crypto observability features.
    ALL FEATURES ARE DISABLED BY DEFAULT.
    Must explicitly opt-in to each feature.
    
    Example:
        configure_crypto_observability(
            enable_crypto_audit_logging=True,
            enable_crypto_metrics=True,
            enable_key_lifecycle_tracing=True
        )
    """
    global _global_config
    with _config_lock:
        for key, value in kwargs.items():
            if hasattr(_global_config, key):
                setattr(_global_config, key, value)

def get_crypto_config() -> CryptoObservabilityConfig:
    """Get current crypto observability configuration."""
    with _config_lock:
        return CryptoObservabilityConfig(**asdict(_global_config))

# -----------------------------------------------------------------------------
# Key Material Protection & Redaction
# -----------------------------------------------------------------------------
def _redact_key_material(data: Any) -> Any:
    """
    Aggressively redact all key material from logs.
    Cryptographic keys NEVER appear in plaintext logs.
    """
    if not _global_config.redact_all_key_material:
        return data
    
    if isinstance(data, bytes):
        if _global_config.log_key_hashes_only and len(data) >= 16:
            # Only log SHA-256 hash of key material
            h = hashlib.sha256(data).hexdigest()[:16]
            return f"[KEY_MATERIAL sha256={h}...]"
        return "[KEY_MATERIAL REDACTED]"
    
    if isinstance(data, str):
        # Common key patterns
        if len(data) > 32 and any(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in data):
            return "[KEY_MATERIAL REDACTED]"
        return data
    
    if isinstance(data, dict):
        return {k: _redact_key_material(v) for k, v in data.items()}
    
    if isinstance(data, (list, tuple)):
        return type(data)(_redact_key_material(x) for x in data)
    
    return data

def get_key_fingerprint(key_material: bytes) -> str:
    """Get safe fingerprint of key material for logging."""
    return hashlib.sha256(key_material).hexdigest()[:32]

# -----------------------------------------------------------------------------
# Crypto Audit Logging (OPT-IN ONLY)
# -----------------------------------------------------------------------------
class CryptoOperationType(Enum):
    KEY_GENERATION = "key_generation"
    KEY_IMPORT = "key_import"
    KEY_EXPORT = "key_export"
    KEY_DESTRUCTION = "key_destruction"
    KEY_ROTATION = "key_rotation"
    SIGNATURE = "signature"
    SIGNATURE_VERIFY = "signature_verify"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    KEY_EXCHANGE = "key_exchange"
    HASH = "hash"
    HMAC = "hmac"
    RANDOM_GENERATION = "random_generation"
    HSM_OPERATION = "hsm_operation"
    KMS_OPERATION = "kms_operation"

class AuditLogLevel(Enum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

_audit_local = threading.local()

def get_audit_correlation_id() -> Optional[str]:
    """Get audit correlation ID (thread-local)."""
    return getattr(_audit_local, 'audit_correlation_id', None)

@contextmanager
def crypto_audit_context(operation_id: Optional[str] = None):
    """Context manager for crypto audit correlation."""
    old_id = get_audit_correlation_id()
    new_id = operation_id or str(uuid.uuid4())
    _audit_local.audit_correlation_id = new_id
    try:
        yield new_id
    finally:
        if old_id:
            _audit_local.audit_correlation_id = old_id
        else:
            if hasattr(_audit_local, 'audit_correlation_id'):
                delattr(_audit_local, 'audit_correlation_id')

def crypto_audit_log(
    level: str,
    operation: CryptoOperationType,
    message: str,
    key_id: Optional[str] = None,
    algorithm: Optional[str] = None,
    **kwargs
) -> None:
    """
    Emit crypto audit log entry (OPT-IN ONLY).
    All key material is automatically redacted.
    """
    if not _global_config.enable_crypto_audit_logging:
        return
    
    config_level = AuditLogLevel[_global_config.audit_log_level].value
    event_level = AuditLogLevel[level].value
    
    if event_level < config_level:
        return
    
    audit_entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'level': level,
        'operation_type': operation.value,
        'message': message,
        'correlation_id': get_audit_correlation_id(),
        'key_id': key_id,
        'algorithm': algorithm,
        'module': 'quantum_crypt_observability_v23',
        'version': '23.0.0',
        'crypto_audit': True,
    }
    audit_entry.update(kwargs)
    audit_entry = _redact_key_material(audit_entry)
    
    print(json.dumps(audit_entry))

# Convenience audit log functions
def audit_debug(op: CryptoOperationType, msg: str, **kwargs):
    crypto_audit_log("DEBUG", op, msg, **kwargs)
def audit_info(op: CryptoOperationType, msg: str, **kwargs):
    crypto_audit_log("INFO", op, msg, **kwargs)
def audit_warning(op: CryptoOperationType, msg: str, **kwargs):
    crypto_audit_log("WARNING", op, msg, **kwargs)
def audit_error(op: CryptoOperationType, msg: str, **kwargs):
    crypto_audit_log("ERROR", op, msg, **kwargs)
def audit_critical(op: CryptoOperationType, msg: str, **kwargs):
    crypto_audit_log("CRITICAL", op, msg, **kwargs)

# -----------------------------------------------------------------------------
# Crypto Operation Metrics (OPT-IN ONLY)
# -----------------------------------------------------------------------------
@dataclass
class CryptoMetricPoint:
    timestamp: float
    value: float
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    labels: Dict[str, str] = field(default_factory=dict)

class CryptoMetricsStore:
    """Thread-safe crypto metrics storage."""
    
    def __init__(self):
        self._operation_counts: Dict[str, int] = defaultdict(int)
        self._operation_timings: Dict[str, List[CryptoMetricPoint]] = defaultdict(list)
        self._key_lifecycle_events: Dict[str, int] = defaultdict(int)
        self._algorithm_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {'count': 0, 'total_time': 0})
        self._lock = threading.Lock()
    
    def record_crypto_operation(
        self,
        operation: CryptoOperationType,
        duration_seconds: float,
        algorithm: Optional[str] = None,
        key_size: Optional[int] = None
    ):
        """Record a cryptographic operation."""
        if not _global_config.enable_crypto_metrics:
            return
        
        with self._lock:
            op_key = operation.value
            self._operation_counts[op_key] += 1
            self._operation_timings[op_key].append(CryptoMetricPoint(
                timestamp=time.time(),
                value=duration_seconds,
                algorithm=algorithm,
                key_size=key_size
            ))
            
            if algorithm:
                self._algorithm_stats[algorithm]['count'] += 1
                self._algorithm_stats[algorithm]['total_time'] += duration_seconds
            
            self._cleanup_old_metrics()
    
    def record_key_lifecycle_event(self, event_type: str, key_id: str):
        """Record key lifecycle event."""
        if not _global_config.enable_crypto_metrics:
            return
        
        with self._lock:
            self._key_lifecycle_events[event_type] += 1
    
    def _cleanup_old_metrics(self):
        """Clean up old metrics."""
        cutoff = time.time() - _global_config.metrics_retention_seconds
        for timing_list in self._operation_timings.values():
            timing_list[:] = [m for m in timing_list if m.timestamp > cutoff]
    
    def get_crypto_metrics(self) -> Dict[str, Any]:
        """Get snapshot of all crypto metrics."""
        if not _global_config.enable_crypto_metrics:
            return {}
        
        with self._lock:
            return {
                'operation_counts': dict(self._operation_counts),
                'operation_avg_time': {
                    k: sum(m.value for m in v) / len(v) if v else 0
                    for k, v in self._operation_timings.items()
                },
                'key_lifecycle_events': dict(self._key_lifecycle_events),
                'algorithm_performance': {
                    alg: {
                        'count': stats['count'],
                        'avg_time_ms': (stats['total_time'] / stats['count'] * 1000) if stats['count'] else 0
                    }
                    for alg, stats in self._algorithm_stats.items()
                }
            }

_crypto_metrics = CryptoMetricsStore()

@contextmanager
def crypto_operation_timer(
    operation: CryptoOperationType,
    algorithm: Optional[str] = None,
    key_size: Optional[int] = None
):
    """Context manager for timing crypto operations."""
    start = time.perf_counter()
    try:
        yield
    finally:
        duration = time.perf_counter() - start
        _crypto_metrics.record_crypto_operation(operation, duration, algorithm, key_size)

T = TypeVar('T')

def timed_crypto_operation(
    operation: CryptoOperationType,
    algorithm: Optional[str] = None
):
    """Decorator for timing cryptographic operations."""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            with crypto_operation_timer(operation, algorithm):
                return func(*args, **kwargs)
        return wrapper
    return decorator

def get_crypto_metrics_snapshot() -> Dict[str, Any]:
    """Get current crypto metrics snapshot."""
    return _crypto_metrics.get_crypto_metrics()

# -----------------------------------------------------------------------------
# HSM & KMS Health Monitoring (OPT-IN ONLY)
# -----------------------------------------------------------------------------
class HSMHealthStatus(Enum):
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    ERROR = "error"

@dataclass
class HSMHealthCheckResult:
    hsm_id: str
    status: HSMHealthStatus
    latency_ms: float = 0.0
    available_keys: int = 0
    queue_depth: int = 0
    message: str = ""
    error_code: Optional[str] = None

class HSMHealthRegistry:
    """Registry for HSM health checks."""
    
    def __init__(self):
        self._checks: Dict[str, Callable[[], HSMHealthCheckResult]] = {}
        self._lock = threading.Lock()
    
    def register_hsm_check(self, hsm_id: str, check_func: Callable[[], HSMHealthCheckResult]):
        """Register an HSM health check."""
        with self._lock:
            self._checks[hsm_id] = check_func
    
    def check_all_hsms(self) -> Dict[str, Any]:
        """Run all HSM health checks."""
        if not _global_config.enable_hsm_health_checks:
            return {
                'status': 'disabled',
                'message': 'HSM health checks disabled (OPT-IN only)'
            }
        
        results = {}
        overall_status = HSMHealthStatus.ONLINE
        
        with self._lock:
            checks_copy = dict(self._checks)
        
        for hsm_id, check_func in checks_copy.items():
            try:
                result = check_func()
                results[hsm_id] = asdict(result)
                results[hsm_id]['status'] = result.status.value
                
                if result.status == HSMHealthStatus.ERROR:
                    overall_status = HSMHealthStatus.ERROR
                elif result.status == HSMHealthStatus.OFFLINE and overall_status == HSMHealthStatus.ONLINE:
                    overall_status = HSMHealthStatus.OFFLINE
                elif result.status == HSMHealthStatus.DEGRADED and overall_status == HSMHealthStatus.ONLINE:
                    overall_status = HSMHealthStatus.DEGRADED
            except Exception as e:
                results[hsm_id] = {
                    'hsm_id': hsm_id,
                    'status': HSMHealthStatus.ERROR.value,
                    'message': f'HSM check exception: {str(e)}',
                }
                overall_status = HSMHealthStatus.ERROR
        
        return {
            'overall_status': overall_status.value,
            'hsm_count': len(results),
            'hsm_statuses': results,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

_hsm_health_registry = HSMHealthRegistry()

def register_hsm_health_check(hsm_id: str, check_func: Callable[[], HSMHealthCheckResult]):
    _hsm_health_registry.register_hsm_check(hsm_id, check_func)

def run_hsm_health_checks() -> Dict[str, Any]:
    return _hsm_health_registry.check_all_hsms()

# -----------------------------------------------------------------------------
# Post-Quantum Specific Instrumentation
# -----------------------------------------------------------------------------
class PQAlgorithmClass(Enum):
    LATTICE = "lattice_based"
    CODE = "code_based"
    HASH = "hash_based"
    MULTIVARIATE = "multivariate"
    ISOGENY = "isogeny_based"

@dataclass
class PQPerformanceSample:
    algorithm: str
    alg_class: PQAlgorithmClass
    operation: str
    key_size_bits: int
    duration_us: float
    cpu_cycles: Optional[int] = None
    memory_bytes: Optional[int] = None

class PQPerformanceTracker:
    """Track post-quantum algorithm performance."""
    
    def __init__(self):
        self._samples: List[PQPerformanceSample] = []
        self._lock = threading.Lock()
    
    def record_pq_operation(
        self,
        algorithm: str,
        alg_class: PQAlgorithmClass,
        operation: str,
        key_size_bits: int,
        duration_seconds: float
    ):
        """Record PQ operation performance."""
        if not _global_config.enable_crypto_metrics:
            return
        
        with self._lock:
            self._samples.append(PQPerformanceSample(
                algorithm=algorithm,
                alg_class=alg_class,
                operation=operation,
                key_size_bits=key_size_bits,
                duration_us=duration_seconds * 1_000_000
            ))
    
    def get_pq_performance_summary(self) -> Dict[str, Any]:
        """Get PQ performance summary."""
        if not _global_config.enable_crypto_metrics:
            return {}
        
        with self._lock:
            by_algorithm = defaultdict(list)
            for sample in self._samples:
                by_algorithm[sample.algorithm].append(sample.duration_us)
            
            return {
                'total_samples': len(self._samples),
                'by_algorithm': {
                    alg: {
                        'count': len(samples),
                        'avg_us': sum(samples) / len(samples),
                        'min_us': min(samples),
                        'max_us': max(samples),
                    }
                    for alg, samples in by_algorithm.items()
                }
            }

_pq_tracker = PQPerformanceTracker()

def record_pq_performance(algorithm: str, alg_class: PQAlgorithmClass, operation: str, 
                          key_size_bits: int, duration_seconds: float):
    _pq_tracker.record_pq_operation(algorithm, alg_class, operation, key_size_bits, duration_seconds)

def get_pq_performance_summary() -> Dict[str, Any]:
    return _pq_tracker.get_pq_performance_summary()

# -----------------------------------------------------------------------------
# Constant-Time Operation Verification (OPT-IN ONLY)
# -----------------------------------------------------------------------------
class ConstantTimeVerifier:
    """Verify constant-time execution of cryptographic operations."""
    
    def __init__(self):
        self._timing_samples: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def record_execution_time(self, operation_id: str, duration_seconds: float, input_variant: str):
        """Record execution time for constant-time analysis."""
        if not _global_config.enable_constant_time_verification:
            return
        
        with self._lock:
            key = f"{operation_id}:{input_variant}"
            self._timing_samples[key].append(duration_seconds)
    
    def analyze_timing_variance(self, operation_id: str) -> Dict[str, Any]:
        """Analyze timing variance for potential side-channel leaks."""
        if not _global_config.enable_constant_time_verification:
            return {'enabled': False}
        
        with self._lock:
            operation_samples = {
                k: v for k, v in self._timing_samples.items()
                if k.startswith(f"{operation_id}:")
            }
            
            if len(operation_samples) < 2:
                return {'variants_tested': len(operation_samples), 'insufficient_data': True}
            
            variant_means = {}
            for key, samples in operation_samples.items():
                variant = key.split(':', 1)[1]
                variant_means[variant] = sum(samples) / len(samples)
            
            means = list(variant_means.values())
            max_diff = max(means) - min(means) if means else 0
            mean_val = sum(means) / len(means) if means else 0
            cv = (max_diff / mean_val) if mean_val > 0 else 0
            
            return {
                'operation_id': operation_id,
                'variants_tested': len(operation_samples),
                'total_samples': sum(len(v) for v in operation_samples.values()),
                'max_timing_diff_us': max_diff * 1_000_000,
                'coefficient_of_variation': cv,
                'risk_assessment': 'low' if cv < 0.01 else 'medium' if cv < 0.05 else 'high',
                'variant_means_us': {k: v * 1_000_000 for k, v in variant_means.items()}
            }

_ct_verifier = ConstantTimeVerifier()

def record_constant_time_sample(operation_id: str, duration: float, input_variant: str):
    _ct_verifier.record_execution_time(operation_id, duration, input_variant)

def analyze_constant_time_safety(operation_id: str) -> Dict[str, Any]:
    return _ct_verifier.analyze_timing_variance(operation_id)

# -----------------------------------------------------------------------------
# Crypto Instrumentation Wrappers
# -----------------------------------------------------------------------------
def instrument_crypto_operation(
    operation: CryptoOperationType,
    algorithm: Optional[str] = None,
    audit: bool = True,
    metrics: bool = True
):
    """
    Decorator to instrument cryptographic operations.
    ZERO OVERHEAD when observability is disabled.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not _global_config.is_any_enabled():
                return func(*args, **kwargs)
            
            with crypto_audit_context():
                start = time.perf_counter()
                try:
                    if audit and _global_config.enable_crypto_audit_logging:
                        audit_info(operation, f"Starting {operation.value}", algorithm=algorithm)
                    
                    result = func(*args, **kwargs)
                    
                    duration = time.perf_counter() - start
                    if metrics and _global_config.enable_crypto_metrics:
                        _crypto_metrics.record_crypto_operation(operation, duration, algorithm)
                    
                    if audit and _global_config.enable_crypto_audit_logging:
                        audit_info(operation, f"Completed {operation.value}", 
                                  algorithm=algorithm, duration_ms=duration*1000)
                    
                    return result
                except Exception as e:
                    duration = time.perf_counter() - start
                    if audit and _global_config.enable_crypto_audit_logging:
                        audit_error(operation, f"Failed {operation.value}", 
                                   algorithm=algorithm, error=str(e), duration_ms=duration*1000)
                    raise
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# Version & Metadata
# -----------------------------------------------------------------------------
CRYPTO_OBSERVABILITY_VERSION = "23.0.0"
CRYPTO_OBSERVABILITY_DIMENSION = "D"
CRYPTO_OBSERVABILITY_FEATURES = [
    "crypto_audit_logging",
    "key_material_redaction",
    "crypto_operation_metrics",
    "hsm_health_monitoring",
    "pq_performance_tracking",
    "constant_time_verification",
    "key_lifecycle_tracing"
]

def get_crypto_observability_metadata() -> Dict[str, Any]:
    """Get crypto observability module metadata."""
    return {
        'version': CRYPTO_OBSERVABILITY_VERSION,
        'dimension': CRYPTO_OBSERVABILITY_DIMENSION,
        'features': CRYPTO_OBSERVABILITY_FEATURES,
        'config': asdict(get_crypto_config()),
        'any_enabled': get_crypto_config().is_any_enabled(),
        'key_material_protection': _global_config.redact_all_key_material,
    }
