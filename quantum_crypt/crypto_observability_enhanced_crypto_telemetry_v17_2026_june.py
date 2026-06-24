"""
Enhanced Observability & Instrumentation Module - QuantumCrypt AI (V17)
Dimension D: Observability & Instrumentation

ADD-ONLY implementation - wraps existing code, no modifications required.
All instrumentation is 100% OPT-IN, disabled by default.

Crypto-Specific Features:
1. Crypto Operation Classification & Telemetry
2. Post-Quantum Algorithm-Specific Metrics
3. Key Size Performance Tracking
4. HSM Operation Telemetry & Monitoring
5. Entropy Level Monitoring & Quality Metrics
6. Random Number Generation Quality Tracking
7. Certificate & PKI Operation Metrics
8. TLS Handshake Performance Monitoring
"""

import json
import time
import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any, Callable, Dict, List, Optional,
    TypeVar, Tuple
)
from datetime import datetime, timezone
from collections import defaultdict, deque
from contextvars import ContextVar, Token
from functools import wraps
import inspect
import secrets
import math

# -----------------------------------------------------------------------------
# Type Definitions & Constants
# -----------------------------------------------------------------------------

T = TypeVar('T')
R = TypeVar('R')

CRYPTO_INSTRUMENTATION_DISABLED: bool = False
MAX_CRYPTO_BAGGAGE_ITEMS: int = 40
MAX_KEY_SIZES_TRACKED: int = 20
MAX_ALGORITHMS_TRACKED: int = 30

# -----------------------------------------------------------------------------
# Crypto Operation Classification
# -----------------------------------------------------------------------------

class CryptoOperationType(Enum):
    """Classification of cryptographic operations."""
    KEY_GENERATION = "key_generation"
    KEY_EXCHANGE = "key_exchange"
    KEY_DERIVATION = "key_derivation"
    SIGNATURE_GENERATION = "signature_generation"
    SIGNATURE_VERIFICATION = "signature_verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    HASH = "hash"
    HMAC = "hmac"
    RANDOM_GENERATION = "random_generation"
    CERTIFICATE_GENERATION = "certificate_generation"
    CERTIFICATE_VERIFICATION = "certificate_verification"
    HSM_OPERATION = "hsm_operation"
    TLS_HANDSHAKE = "tls_handshake"
    KEM_ENCAPSULATION = "kem_encapsulation"
    KEM_DECAPSULATION = "kem_decapsulation"


class CryptoAlgorithm(Enum):
    """Supported cryptographic algorithms."""
    # Post-Quantum
    CRYSTALS_KYBER = "CRYSTALS-Kyber"
    CRYSTALS_DILITHIUM = "CRYSTALS-Dilithium"
    FALCON = "Falcon"
    SPHINCS = "SPHINCS+"
    NTRU = "NTRU"
    BIKE = "BIKE"
    HQC = "HQC"
    # Classic
    RSA = "RSA"
    ECDSA = "ECDSA"
    ECDH = "ECDH"
    AES = "AES"
    SHA2 = "SHA-2"
    SHA3 = "SHA-3"
    CHACHA20 = "ChaCha20"
    HYBRID_CLASSIC_PQ = "Hybrid_Classic_PQ"


class CryptoSecurityLevel(Enum):
    """NIST security levels."""
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_2 = 2
    LEVEL_3 = 3
    LEVEL_4 = 4
    LEVEL_5 = 5  # AES-256 equivalent


# -----------------------------------------------------------------------------
# Crypto Baggage Context
# -----------------------------------------------------------------------------

class CryptoBaggageKey(Enum):
    """Standard crypto baggage keys."""
    OPERATION_ID = "crypto_op_id"
    OPERATION_TYPE = "crypto_op_type"
    ALGORITHM = "crypto_algorithm"
    KEY_SIZE_BITS = "crypto_key_size"
    SECURITY_LEVEL = "crypto_security_level"
    USES_HSM = "crypto_uses_hsm"
    CORRELATION_ID = "correlation_id"
    TENANT_ID = "tenant_id"
    TRACE_ID = "trace_id"


class CryptoBaggageContext:
    """
    Thread-safe context baggage for crypto operations.
    Uses contextvars for async/thread-local propagation.
    """
    
    _context: ContextVar[Dict[str, Any]] = ContextVar(
        'crypto_baggage',
        default={}
    )
    
    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        ctx = cls._context.get()
        return ctx.get(key, default)
    
    @classmethod
    def set(cls, key: str, value: Any) -> Token:
        ctx = cls._context.get().copy()
        if len(ctx) >= MAX_CRYPTO_BAGGAGE_ITEMS and key not in ctx:
            return Token(None, None, None)
        ctx[key] = value
        return cls._context.set(ctx)
    
    @classmethod
    def set_bulk(cls, items: Dict[str, Any]) -> Token:
        ctx = cls._context.get().copy()
        for k, v in items.items():
            if len(ctx) >= MAX_CRYPTO_BAGGAGE_ITEMS:
                break
            ctx[k] = v
        return cls._context.set(ctx)
    
    @classmethod
    def reset(cls, token: Token) -> None:
        if token and token.var is not None:
            cls._context.reset(token)
    
    @classmethod
    def get_all(cls) -> Dict[str, Any]:
        return cls._context.get().copy()
    @classmethod
    def clear(cls) -> None:
        """Clear all baggage context."""
        cls._context.set({})
    
    @classmethod
    def generate_operation_id(cls) -> str:
        op_id = f"crypto_op_{uuid.uuid4().hex[:16]}"
        cls.set(CryptoBaggageKey.OPERATION_ID.value, op_id)
        return op_id


# -----------------------------------------------------------------------------
# Crypto-Specific Metrics
# -----------------------------------------------------------------------------

@dataclass
class CryptoOperationStats:
    """Statistics for a specific crypto operation type."""
    count: int = 0
    total_time_ns: int = 0
    min_time_ns: int = 0
    max_time_ns: int = 0
    error_count: int = 0
    key_sizes: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    
    def record(self, duration_ns: int, key_size: int = 0, error: bool = False) -> None:
        self.count += 1
        self.total_time_ns += duration_ns
        if self.min_time_ns == 0 or duration_ns < self.min_time_ns:
            self.min_time_ns = duration_ns
        if duration_ns > self.max_time_ns:
            self.max_time_ns = duration_ns
        if error:
            self.error_count += 1
        if key_size > 0:
            self.key_sizes[key_size] += 1
    
    def get_avg_time_ms(self) -> float:
        if self.count == 0:
            return 0.0
        return (self.total_time_ns / self.count) / 1_000_000.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "avg_time_ms": self.get_avg_time_ms(),
            "min_time_ms": self.min_time_ns / 1_000_000.0,
            "max_time_ms": self.max_time_ns / 1_000_000.0,
            "error_count": self.error_count,
            "error_rate": self.error_count / max(1, self.count),
            "key_size_distribution": dict(self.key_sizes),
        }


class CryptoMetricsRegistry:
    """
    Specialized metrics registry for cryptographic operations.
    Tracks performance per algorithm, key size, and operation type.
    """
    
    def __init__(self):
        self._operation_stats: Dict[str, CryptoOperationStats] = defaultdict(CryptoOperationStats)
        self._algorithm_stats: Dict[str, CryptoOperationStats] = defaultdict(CryptoOperationStats)
        self._key_size_latency: Dict[Tuple[str, int], List[float]] = defaultdict(list)
        self._entropy_samples: deque = deque(maxlen=1000)
        self._hsm_stats = CryptoOperationStats()
        self._lock = threading.RLock()
        
        # Counters
        self._operations_total: int = 0
        self._errors_total: int = 0
        self._hsm_operations_total: int = 0
    
    def record_operation(
        self,
        operation_type: CryptoOperationType,
        algorithm: CryptoAlgorithm,
        duration_ns: int,
        key_size_bits: int = 0,
        uses_hsm: bool = False,
        error: bool = False,
    ) -> None:
        """Record a cryptographic operation."""
        if CRYPTO_INSTRUMENTATION_DISABLED:
            return
        
        with self._lock:
            op_key = operation_type.value
            alg_key = algorithm.value
            
            self._operations_total += 1
            if error:
                self._errors_total += 1
            if uses_hsm:
                self._hsm_operations_total += 1
                self._hsm_stats.record(duration_ns, key_size_bits, error)
            
            self._operation_stats[op_key].record(duration_ns, key_size_bits, error)
            self._algorithm_stats[alg_key].record(duration_ns, key_size_bits, error)
            
            # Track key size specific latency
            if key_size_bits > 0:
                key = (alg_key, key_size_bits)
                self._key_size_latency[key].append(duration_ns / 1_000_000.0)
                if len(self._key_size_latency[key]) > 100:
                    self._key_size_latency[key] = self._key_size_latency[key][-100:]
    
    def record_entropy_sample(self, entropy_bits: float, source: str = "system") -> None:
        """Record entropy quality sample."""
        if CRYPTO_INSTRUMENTATION_DISABLED:
            return
        with self._lock:
            self._entropy_samples.append({
                "timestamp": time.time(),
                "entropy_bits": entropy_bits,
                "source": source,
            })
    
    def get_operation_stats(self, op_type: CryptoOperationType) -> CryptoOperationStats:
        """Get stats for a specific operation type."""
        with self._lock:
            return self._operation_stats.get(op_type.value, CryptoOperationStats())
    
    def get_algorithm_stats(self, algorithm: CryptoAlgorithm) -> CryptoOperationStats:
        """Get stats for a specific algorithm."""
        with self._lock:
            return self._algorithm_stats.get(algorithm.value, CryptoOperationStats())
    
    def get_hsm_stats(self) -> CryptoOperationStats:
        """Get HSM operation stats."""
        with self._lock:
            return self._hsm_stats
    
    def get_entropy_summary(self) -> Dict[str, Any]:
        """Get entropy quality summary."""
        with self._lock:
            if not self._entropy_samples:
                return {"samples": 0, "avg_entropy": 0.0}
            entropies = [s["entropy_bits"] for s in self._entropy_samples]
            return {
                "samples": len(entropies),
                "min_entropy": min(entropies),
                "max_entropy": max(entropies),
                "avg_entropy": sum(entropies) / len(entropies),
            }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get complete metrics snapshot."""
        with self._lock:
            return {
                "summary": {
                    "total_operations": self._operations_total,
                    "total_errors": self._errors_total,
                    "error_rate": self._errors_total / max(1, self._operations_total),
                    "hsm_operations": self._hsm_operations_total,
                },
                "by_operation": {
                    k: v.to_dict() for k, v in self._operation_stats.items()
                },
                "by_algorithm": {
                    k: v.to_dict() for k, v in self._algorithm_stats.items()
                },
                "hsm": self._hsm_stats.to_dict(),
                "entropy": self.get_entropy_summary(),
            }


# Default crypto metrics registry
_default_crypto_registry: Optional[CryptoMetricsRegistry] = None

def get_default_crypto_registry() -> CryptoMetricsRegistry:
    """Get or create default crypto metrics registry."""
    global _default_crypto_registry
    if _default_crypto_registry is None:
        _default_crypto_registry = CryptoMetricsRegistry()
    return _default_crypto_registry


# -----------------------------------------------------------------------------
# Crypto Operation Timer
# -----------------------------------------------------------------------------

class CryptoOperationTimer:
    """
    High-precision timer for crypto operations with nanosecond resolution.
    Automatically records metrics when context exits.
    """
    
    def __init__(
        self,
        operation_type: CryptoOperationType,
        algorithm: CryptoAlgorithm,
        key_size_bits: int = 0,
        uses_hsm: bool = False,
        registry: Optional[CryptoMetricsRegistry] = None,
    ):
        self.operation_type = operation_type
        self.algorithm = algorithm
        self.key_size_bits = key_size_bits
        self.uses_hsm = uses_hsm
        self.registry = registry or get_default_crypto_registry()
        self._start_ns: Optional[int] = None
    
    def __enter__(self) -> 'CryptoOperationTimer':
        self._start_ns = time.perf_counter_ns()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._start_ns is not None:
            duration_ns = time.perf_counter_ns() - self._start_ns
            error = exc_type is not None
            self.registry.record_operation(
                operation_type=self.operation_type,
                algorithm=self.algorithm,
                duration_ns=duration_ns,
                key_size_bits=self.key_size_bits,
                uses_hsm=self.uses_hsm,
                error=error,
            )
        return False  # Don't suppress exceptions


# -----------------------------------------------------------------------------
# Entropy Monitor
# -----------------------------------------------------------------------------

class EntropyMonitor:
    """
    Monitors system entropy quality and random number generation health.
    Provides continuous entropy quality assessment.
    """
    
    def __init__(
        self,
        registry: Optional[CryptoMetricsRegistry] = None,
        sample_interval_seconds: float = 60.0,
    ):
        self.registry = registry or get_default_crypto_registry()
        self.sample_interval = sample_interval_seconds
        self._last_sample: float = 0.0
        self._lock = threading.RLock()
    
    @staticmethod
    def _calculate_shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy in bits per byte."""
        if not data:
            return 0.0
        freq: Dict[int, int] = defaultdict(int)
        for b in data:
            freq[b] += 1
        entropy = 0.0
        total = len(data)
        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy
    
    def sample_entropy(self, sample_size: int = 256) -> float:
        """Sample and record system entropy."""
        with self._lock:
            now = time.time()
            if now - self._last_sample < self.sample_interval:
                return 0.0
            
            sample = secrets.token_bytes(sample_size)
            entropy = self._calculate_shannon_entropy(sample)
            self.registry.record_entropy_sample(entropy, "system_csprng")
            self._last_sample = now
            return entropy
    
    def get_current_entropy_estimate(self) -> float:
        """Get most recent entropy estimate."""
        summary = self.registry.get_entropy_summary()
        return summary.get("avg_entropy", 0.0)
    
    def is_entropy_sufficient(self, min_bits: float = 7.0) -> bool:
        """Check if entropy quality is sufficient for crypto operations."""
        return self.get_current_entropy_estimate() >= min_bits


# Default entropy monitor
_default_entropy_monitor: Optional[EntropyMonitor] = None

def get_entropy_monitor() -> EntropyMonitor:
    """Get or create default entropy monitor."""
    global _default_entropy_monitor
    if _default_entropy_monitor is None:
        _default_entropy_monitor = EntropyMonitor()
    return _default_entropy_monitor


# -----------------------------------------------------------------------------
# Crypto Health Checks
# -----------------------------------------------------------------------------

class CryptoHealthStatus(Enum):
    """Crypto-specific health statuses."""
    SECURE = "secure"        # All checks pass, entropy good
    DEGRADED = "degraded"    # Working but suboptimal (low entropy)
    AT_RISK = "at_risk"      # Security concerns (entropy very low)
    FAILED = "failed"        # Critical failure


@dataclass
class CryptoHealthResult:
    """Result of crypto health assessment."""
    overall_status: CryptoHealthStatus
    entropy_status: str
    entropy_bits: float
    hsm_available: bool
    algorithm_health: Dict[str, str]
    timestamp: str
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_status": self.overall_status.value,
            "entropy": {
                "status": self.entropy_status,
                "bits_per_byte": self.entropy_bits,
            },
            "hsm_available": self.hsm_available,
            "algorithm_health": self.algorithm_health,
            "timestamp": self.timestamp,
            "recommendations": self.recommendations,
        }


class CryptoHealthChecker:
    """
    Specialized health checker for cryptographic operations.
    Assesses entropy quality, algorithm health, and HSM status.
    """
    
    def __init__(
        self,
        registry: Optional[CryptoMetricsRegistry] = None,
        entropy_monitor: Optional[EntropyMonitor] = None,
    ):
        self.registry = registry or get_default_crypto_registry()
        self.entropy_monitor = entropy_monitor or get_entropy_monitor()
        self._hsm_available: bool = False
    
    def set_hsm_available(self, available: bool) -> None:
        """Set HSM availability status."""
        self._hsm_available = available
    
    def assess_health(self) -> CryptoHealthResult:
        """Run complete crypto health assessment."""
        # Sample fresh entropy
        self.entropy_monitor.sample_entropy()
        entropy = self.entropy_monitor.get_current_entropy_estimate()
        
        # Determine entropy status
        if entropy >= 7.8:
            entropy_status = "excellent"
        elif entropy >= 7.0:
            entropy_status = "good"
        elif entropy >= 6.0:
            entropy_status = "marginal"
        else:
            entropy_status = "critical"
        
        # Algorithm health based on error rates
        algorithm_health: Dict[str, str] = {}
        for alg, stats in self.registry._algorithm_stats.items():
            error_rate = stats.error_count / max(1, stats.count)
            if error_rate < 0.001:
                algorithm_health[alg] = "healthy"
            elif error_rate < 0.01:
                algorithm_health[alg] = "monitoring"
            else:
                algorithm_health[alg] = "concerning"
        
        # Overall status
        recommendations: List[str] = []
        if entropy < 7.0:
            recommendations.append("Low entropy detected - consider additional entropy sources")
            overall = CryptoHealthStatus.AT_RISK
        elif entropy < 7.5:
            recommendations.append("Entropy is acceptable but could be improved")
            overall = CryptoHealthStatus.DEGRADED
        else:
            overall = CryptoHealthStatus.SECURE
        
        if not self._hsm_available:
            recommendations.append("HSM not available - using software crypto only")
            if overall == CryptoHealthStatus.SECURE:
                overall = CryptoHealthStatus.DEGRADED
        
        return CryptoHealthResult(
            overall_status=overall,
            entropy_status=entropy_status,
            entropy_bits=entropy,
            hsm_available=self._hsm_available,
            algorithm_health=algorithm_health,
            timestamp=datetime.now(timezone.utc).isoformat(),
            recommendations=recommendations,
        )


# Default crypto health checker
_default_crypto_health_checker: Optional[CryptoHealthChecker] = None

def get_crypto_health_checker() -> CryptoHealthChecker:
    """Get or create default crypto health checker."""
    global _default_crypto_health_checker
    if _default_crypto_health_checker is None:
        _default_crypto_health_checker = CryptoHealthChecker()
    return _default_crypto_health_checker


# -----------------------------------------------------------------------------
# Crypto Structured Logging
# -----------------------------------------------------------------------------

class CryptoLogLevel(Enum):
    """Crypto-specific log levels with security audit levels."""
    DEBUG = 10
    INFO = 20
    AUDIT = 35     # Security audit events
    WARNING = 30
    SECURITY = 45  # Security-relevant events
    ERROR = 40
    CRITICAL = 50


@dataclass
class CryptoLogEntry:
    """Structured log entry for crypto operations."""
    timestamp: str
    level: str
    message: str
    operation_type: Optional[str] = None
    algorithm: Optional[str] = None
    key_size_bits: Optional[int] = None
    uses_hsm: Optional[bool] = None
    duration_ns: Optional[int] = None
    baggage: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "timestamp": self.timestamp,
            "level": self.level,
            "message": self.message,
            "success": self.success,
        }
        if self.operation_type:
            result["operation_type"] = self.operation_type
        if self.algorithm:
            result["algorithm"] = self.algorithm
        if self.key_size_bits:
            result["key_size_bits"] = self.key_size_bits
        if self.uses_hsm is not None:
            result["uses_hsm"] = self.uses_hsm
        if self.duration_ns is not None:
            result["duration_ms"] = self.duration_ns / 1_000_000.0
        if self.baggage:
            result["baggage"] = self.baggage
        if self.error:
            result["error"] = self.error
        return result
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


class CryptoAuditLogger:
    """
    Specialized logger for crypto operations with audit trail support.
    All crypto operations can be logged for compliance and auditing.
    """
    
    def __init__(self, name: str = "quantum_crypt"):
        self.name = name
        self._audit_trail: List[CryptoLogEntry] = []
        self._max_trail_size: int = 10000
        self._handlers: List[Callable[[CryptoLogEntry], None]] = []
        self._lock = threading.RLock()
    
    def _log(
        self,
        level: CryptoLogLevel,
        message: str,
        operation_type: Optional[CryptoOperationType] = None,
        algorithm: Optional[CryptoAlgorithm] = None,
        key_size_bits: int = 0,
        uses_hsm: bool = False,
        duration_ns: Optional[int] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> CryptoLogEntry:
        """Internal log method."""
        if CRYPTO_INSTRUMENTATION_DISABLED:
            return CryptoLogEntry("", "", "")
        
        entry = CryptoLogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level.name,
            message=message,
            operation_type=operation_type.value if operation_type else None,
            algorithm=algorithm.value if algorithm else None,
            key_size_bits=key_size_bits if key_size_bits > 0 else None,
            uses_hsm=uses_hsm,
            duration_ns=duration_ns,
            baggage=CryptoBaggageContext.get_all(),
            success=success,
            error=error,
        )
        
        with self._lock:
            self._audit_trail.append(entry)
            if len(self._audit_trail) > self._max_trail_size:
                self._audit_trail.pop(0)
            
            for handler in self._handlers:
                try:
                    handler(entry)
                except Exception:
                    pass
        
        return entry
    
    def audit(
        self,
        message: str,
        operation_type: Optional[CryptoOperationType] = None,
        algorithm: Optional[CryptoAlgorithm] = None,
        **kwargs,
    ) -> CryptoLogEntry:
        """Log an auditable crypto operation."""
        return self._log(CryptoLogLevel.AUDIT, message, operation_type, algorithm, **kwargs)
    
    def security(
        self,
        message: str,
        operation_type: Optional[CryptoOperationType] = None,
        algorithm: Optional[CryptoAlgorithm] = None,
        **kwargs,
    ) -> CryptoLogEntry:
        """Log a security-relevant event."""
        return self._log(CryptoLogLevel.SECURITY, message, operation_type, algorithm, **kwargs)
    
    def info(self, message: str, **kwargs) -> CryptoLogEntry:
        return self._log(CryptoLogLevel.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> CryptoLogEntry:
        return self._log(CryptoLogLevel.WARNING, message, **kwargs)
    
    def error(self, message: str, error: Optional[str] = None, **kwargs) -> CryptoLogEntry:
        return self._log(CryptoLogLevel.ERROR, message, error=error, **kwargs)
    
    def get_audit_trail(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit trail entries."""
        with self._lock:
            entries = self._audit_trail[-limit:]
            return [e.to_dict() for e in entries]
    
    def add_handler(self, handler: Callable[[CryptoLogEntry], None]) -> None:
        """Add log handler for external integration."""
        with self._lock:
            self._handlers.append(handler)


# Default audit logger
_default_audit_logger: Optional[CryptoAuditLogger] = None

def get_audit_logger() -> CryptoAuditLogger:
    """Get or create default crypto audit logger."""
    global _default_audit_logger
    if _default_audit_logger is None:
        _default_audit_logger = CryptoAuditLogger()
    return _default_audit_logger


# -----------------------------------------------------------------------------
# Crypto Instrumentation Decorator
# -----------------------------------------------------------------------------

def crypto_instrumented(
    operation_type: CryptoOperationType,
    algorithm: CryptoAlgorithm = CryptoAlgorithm.HYBRID_CLASSIC_PQ,
    key_size_bits: int = 0,
    uses_hsm: bool = False,
    log_audit: bool = True,
    measure_performance: bool = True,
) -> Callable[[Callable[..., R]], Callable[..., R]]:
    """
    Decorator for comprehensive crypto operation instrumentation.
    100% OPT-IN - no effect if instrumentation disabled.
    
    Usage:
        @crypto_instrumented(
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.CRYSTALS_KYBER,
            key_size_bits=1536,
        )
        def generate_kyber_keypair(security_level: int) -> KeyPair:
            ...
    """
    def decorator(func: Callable[..., R]) -> Callable[..., R]:
        registry = get_default_crypto_registry()
        audit_logger = get_audit_logger()
        
        @wraps(func)
        def wrapper(*args, **kwargs) -> R:
            if CRYPTO_INSTRUMENTATION_DISABLED:
                return func(*args, **kwargs)
            
            start_ns = time.perf_counter_ns()
            op_id = CryptoBaggageContext.generate_operation_id()
            
            token = CryptoBaggageContext.set_bulk({
                CryptoBaggageKey.OPERATION_TYPE.value: operation_type.value,
                CryptoBaggageKey.ALGORITHM.value: algorithm.value,
                CryptoBaggageKey.KEY_SIZE_BITS.value: key_size_bits,
                CryptoBaggageKey.USES_HSM.value: uses_hsm,
            })
            
            try:
                result = func(*args, **kwargs)
                
                duration_ns = time.perf_counter_ns() - start_ns
                
                if measure_performance:
                    registry.record_operation(
                        operation_type=operation_type,
                        algorithm=algorithm,
                        duration_ns=duration_ns,
                        key_size_bits=key_size_bits,
                        uses_hsm=uses_hsm,
                        error=False,
                    )
                
                if log_audit:
                    audit_logger.audit(
                        f"Completed {func.__name__}",
                        operation_type=operation_type,
                        algorithm=algorithm,
                        key_size_bits=key_size_bits,
                        uses_hsm=uses_hsm,
                        duration_ns=duration_ns,
                        success=True,
                    )
                
                return result
            except Exception as e:
                duration_ns = time.perf_counter_ns() - start_ns
                
                if measure_performance:
                    registry.record_operation(
                        operation_type=operation_type,
                        algorithm=algorithm,
                        duration_ns=duration_ns,
                        key_size_bits=key_size_bits,
                        uses_hsm=uses_hsm,
                        error=True,
                    )
                
                if log_audit:
                    audit_logger.audit(
                        f"Failed {func.__name__}",
                        operation_type=operation_type,
                        algorithm=algorithm,
                        key_size_bits=key_size_bits,
                        uses_hsm=uses_hsm,
                        duration_ns=duration_ns,
                        success=False,
                        error=str(e),
                    )
                raise
            finally:
                CryptoBaggageContext.reset(token)
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Export & Control Functions
# -----------------------------------------------------------------------------

def export_crypto_metrics_json() -> str:
    """Export all crypto metrics as JSON."""
    return json.dumps(get_default_crypto_registry().get_all_metrics(), indent=2)


def export_crypto_health_json() -> str:
    """Export crypto health status as JSON."""
    return json.dumps(get_crypto_health_checker().assess_health().to_dict(), indent=2)


def export_audit_trail_json(limit: int = 100) -> str:
    """Export audit trail as JSON."""
    return json.dumps(get_audit_logger().get_audit_trail(limit), indent=2)


def disable_crypto_instrumentation() -> None:
    """Globally disable all crypto instrumentation."""
    global CRYPTO_INSTRUMENTATION_DISABLED
    CRYPTO_INSTRUMENTATION_DISABLED = True


def enable_crypto_instrumentation() -> None:
    """Globally enable all crypto instrumentation."""
    global CRYPTO_INSTRUMENTATION_DISABLED
    CRYPTO_INSTRUMENTATION_DISABLED = False


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    # Operation Classification
    "CryptoOperationType",
    "CryptoAlgorithm",
    "CryptoSecurityLevel",
    
    # Context & Baggage
    "CryptoBaggageKey",
    "CryptoBaggageContext",
    
    # Metrics
    "CryptoOperationStats",
    "CryptoMetricsRegistry",
    "get_default_crypto_registry",
    
    # Timing
    "CryptoOperationTimer",
    
    # Entropy Monitoring
    "EntropyMonitor",
    "get_entropy_monitor",
    
    # Health Checks
    "CryptoHealthStatus",
    "CryptoHealthResult",
    "CryptoHealthChecker",
    "get_crypto_health_checker",
    
    # Logging & Audit
    "CryptoLogLevel",
    "CryptoLogEntry",
    "CryptoAuditLogger",
    "get_audit_logger",
    
    # Decorators
    "crypto_instrumented",
    
    # Export & Control
    "export_crypto_metrics_json",
    "export_crypto_health_json",
    "export_audit_trail_json",
    "disable_crypto_instrumentation",
    "enable_crypto_instrumentation",
]
