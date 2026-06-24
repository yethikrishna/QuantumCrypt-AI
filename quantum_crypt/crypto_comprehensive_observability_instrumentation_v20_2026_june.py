"""
QuantumCrypt AI - Comprehensive Cryptographic Observability & Instrumentation v20
DIMENSION D - Observability & Instrumentation

ADD-ONLY implementation - wraps existing crypto code, no modifications to core logic.
All instrumentation is OPT-IN, disabled by default.
Cryptographic operation telemetry with security event tracking.

Stability: STABLE
Backward Compatible: YES
Dependencies: None (pure Python)
"""

import time
import threading
import json
import hashlib
import secrets
from typing import Dict, List, Any, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from functools import wraps
import uuid

T = TypeVar('T')

class CryptoOperationType(Enum):
    """Types of cryptographic operations for telemetry"""
    KEY_GENERATION = "key_generation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    HASHING = "hashing"
    KEY_EXCHANGE = "key_exchange"
    RANDOM_GENERATION = "random_generation"
    SIGNATURE_VERIFICATION = "signature_verification"

class SecurityEventType(Enum):
    """Types of security events for audit logging"""
    KEY_CREATED = "key_created"
    KEY_ROTATED = "key_rotated"
    KEY_DESTROYED = "key_destroyed"
    ENCRYPTION_PERFORMED = "encryption_performed"
    DECRYPTION_PERFORMED = "decryption_performed"
    SIGNATURE_CREATED = "signature_created"
    SIGNATURE_VALID = "signature_valid"
    SIGNATURE_INVALID = "signature_invalid"
    AUTHENTICATION_SUCCESS = "auth_success"
    AUTHENTICATION_FAILURE = "auth_failure"
    RANDOM_ENTROPY_COLLECTED = "entropy_collected"

class MetricType(Enum):
    """Metric types"""
    COUNTER = "counter"
    GAUGE = "gauge"
    TIMER = "timer"
    HISTOGRAM = "histogram"

class CryptoHealthStatus(Enum):
    """Cryptographic module health status"""
    OPERATIONAL = "operational"
    DEGRADED_PERFORMANCE = "degraded_performance"
    LOW_ENTROPY = "low_entropy"
    KEY_EXPIRING = "key_expiring"
    CRITICAL_FAILURE = "critical_failure"

@dataclass
class CryptoOperationTelemetry:
    """Telemetry record for a cryptographic operation"""
    operation_id: str
    operation_type: CryptoOperationType
    algorithm: str
    key_size_bits: int
    start_time: float
    end_time: Optional[float] = None
    success: bool = True
    error_type: Optional[str] = None
    input_size_bytes: Optional[int] = None
    output_size_bytes: Optional[int] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecurityEvent:
    """Security audit event"""
    event_id: str
    event_type: SecurityEventType
    timestamp: float = field(default_factory=time.time)
    severity: str = "INFO"
    algorithm: Optional[str] = None
    key_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class KeyLifecycleEvent:
    """Key lifecycle tracking event"""
    key_id: str
    algorithm: str
    key_size: int
    creation_time: float
    expiration_time: Optional[float] = None
    rotation_count: int = 0
    operations_performed: int = 0

class ThreadSafeCryptoMetricStore:
    """Thread-safe storage for cryptographic metrics"""
    
    def __init__(self, max_records: int = 5000):
        self._lock = threading.RLock()
        self._operation_telemetry: deque = deque(maxlen=max_records)
        self._security_events: deque = deque(maxlen=max_records)
        self._counters: Dict[str, int] = defaultdict(int)
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._key_lifecycle: Dict[str, KeyLifecycleEvent] = {}
        self._max_records = max_records
    
    def record_operation(self, telemetry: CryptoOperationTelemetry) -> None:
        """Record cryptographic operation telemetry"""
        with self._lock:
            self._operation_telemetry.append(telemetry)
            counter_key = f"op.{telemetry.operation_type.value}.{telemetry.algorithm}"
            self._counters[counter_key] += 1
            
            if telemetry.end_time and telemetry.start_time:
                duration = telemetry.end_time - telemetry.start_time
                timer_key = f"time.{telemetry.operation_type.value}.{telemetry.algorithm}"
                self._timers[timer_key].append(duration)
                if len(self._timers[timer_key]) > 1000:
                    self._timers[timer_key] = self._timers[timer_key][-1000:]
    
    def record_security_event(self, event: SecurityEvent) -> None:
        """Record security audit event"""
        with self._lock:
            self._security_events.append(event)
            counter_key = f"security.{event.event_type.value}"
            self._counters[counter_key] += 1
    
    def track_key_creation(self, key_id: str, algorithm: str, key_size: int) -> None:
        """Start tracking key lifecycle"""
        with self._lock:
            self._key_lifecycle[key_id] = KeyLifecycleEvent(
                key_id=key_id,
                algorithm=algorithm,
                key_size=key_size,
                creation_time=time.time()
            )
    
    def track_key_usage(self, key_id: str) -> None:
        """Increment key usage counter"""
        with self._lock:
            if key_id in self._key_lifecycle:
                self._key_lifecycle[key_id].operations_performed += 1
    
    def get_operation_statistics(self) -> Dict[str, Any]:
        """Get cryptographic operation statistics"""
        with self._lock:
            stats = {
                "total_operations": len(self._operation_telemetry),
                "by_algorithm": defaultdict(int),
                "by_operation_type": defaultdict(int),
                "success_rate": 0.0,
                "avg_duration_by_op": {}
            }
            
            successful = 0
            for op in self._operation_telemetry:
                stats["by_algorithm"][op.algorithm] += 1
                stats["by_operation_type"][op.operation_type.value] += 1
                if op.success:
                    successful += 1
            
            if self._operation_telemetry:
                stats["success_rate"] = successful / len(self._operation_telemetry)
            
            # Calculate average durations
            for timer_key, durations in self._timers.items():
                if durations:
                    stats["avg_duration_by_op"][timer_key] = sum(durations) / len(durations)
            
            return stats
    
    def get_security_event_summary(self) -> Dict[str, Any]:
        """Get security event summary"""
        with self._lock:
            summary = {
                "total_events": len(self._security_events),
                "by_type": defaultdict(int),
                "by_severity": defaultdict(int)
            }
            
            for event in self._security_events:
                summary["by_type"][event.event_type.value] += 1
                summary["by_severity"][event.severity] += 1
            
            return summary
    
    def get_key_lifecycle_summary(self) -> Dict[str, Any]:
        """Get key management summary"""
        with self._lock:
            keys = list(self._key_lifecycle.values())
            return {
                "active_keys": len(keys),
                "total_operations": sum(k.operations_performed for k in keys),
                "keys_by_algorithm": defaultdict(int),
                "oldest_key_age_seconds": 0.0
            }
    
    def increment_counter(self, name: str, value: int = 1) -> None:
        """Generic counter increment"""
        with self._lock:
            self._counters[name] += value
    
    def get_counter(self, name: str) -> int:
        """Get counter value"""
        with self._lock:
            return self._counters.get(name, 0)

class CryptoStructuredLogger:
    """Structured logger for cryptographic operations (OPT-IN)"""
    
    def __init__(self, enabled: bool = False):
        self._enabled = enabled
        self._lock = threading.Lock()
        self._audit_log: deque = deque(maxlen=10000)
    
    def enable(self) -> None:
        """Enable logging (EXPLICIT OPT-IN)"""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable logging"""
        self._enabled = False
    
    def log_crypto_operation(self, operation: CryptoOperationType, algorithm: str,
                             success: bool, **kwargs) -> None:
        """Log cryptographic operation if enabled"""
        if not self._enabled:
            return
        
        entry = {
            "timestamp": time.time(),
            "type": "crypto_operation",
            "operation": operation.value,
            "algorithm": algorithm,
            "success": success,
            "details": kwargs
        }
        
        with self._lock:
            self._audit_log.append(entry)
    
    def log_security_event(self, event_type: SecurityEventType, severity: str = "INFO",
                           **kwargs) -> None:
        """Log security event if enabled"""
        if not self._enabled:
            return
        
        entry = {
            "timestamp": time.time(),
            "type": "security_event",
            "event": event_type.value,
            "severity": severity,
            "details": kwargs
        }
        
        with self._lock:
            self._audit_log.append(entry)
    
    def get_audit_log(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries"""
        with self._lock:
            return list(self._audit_log)[-count:]

class CryptoHealthChecker:
    """Health checking for cryptographic modules"""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._checks: Dict[str, Callable[[], Dict[str, Any]]] = {}
        self._last_results: Dict[str, Any] = {}
    
    def register_check(self, name: str, check_fn: Callable[[], Dict[str, Any]]) -> None:
        """Register a health check function"""
        with self._lock:
            self._checks[name] = check_fn
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all cryptographic health checks"""
        results = {}
        overall_status = CryptoHealthStatus.OPERATIONAL
        
        for name, check_fn in self._checks.items():
            try:
                result = check_fn()
                results[name] = result
                if result.get("status") == "degraded":
                    overall_status = CryptoHealthStatus.DEGRADED_PERFORMANCE
                elif result.get("status") == "critical":
                    overall_status = CryptoHealthStatus.CRITICAL_FAILURE
            except Exception as e:
                results[name] = {
                    "status": "error",
                    "error": str(e)
                }
                overall_status = CryptoHealthStatus.CRITICAL_FAILURE
        
        return {
            "overall_status": overall_status.value,
            "checks": results,
            "timestamp": time.time()
        }
    
    def check_entropy_quality(self) -> Dict[str, Any]:
        """Check system entropy quality"""
        try:
            # Test random generation performance
            start = time.time()
            test_bytes = secrets.token_bytes(1024 * 1024)  # 1MB
            duration = time.time() - start
            
            throughput = (1024 * 1024) / duration if duration > 0 else 0
            
            return {
                "status": "healthy",
                "throughput_mbps": throughput / (1024 * 1024),
                "generation_time_ms": duration * 1000
            }
        except Exception as e:
            return {
                "status": "critical",
                "error": str(e)
            }

def crypto_timed(operation_type: CryptoOperationType, algorithm: str):
    """Decorator to time and track cryptographic operations (OPT-IN)"""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not CryptoInstrumentationManager.is_instrumentation_enabled():
                return func(*args, **kwargs)
            
            op_id = CryptoInstrumentationManager._generate_operation_id()
            telemetry = CryptoOperationTelemetry(
                operation_id=op_id,
                operation_type=operation_type,
                algorithm=algorithm,
                key_size_bits=kwargs.get('key_size', 256),
                start_time=time.time()
            )
            
            try:
                result = func(*args, **kwargs)
                telemetry.end_time = time.time()
                telemetry.success = True
                CryptoInstrumentationManager.record_operation(telemetry)
                return result
            except Exception as e:
                telemetry.end_time = time.time()
                telemetry.success = False
                telemetry.error_type = type(e).__name__
                CryptoInstrumentationManager.record_operation(telemetry)
                raise
        return wrapper
    return decorator

def crypto_audited(event_type: SecurityEventType, severity: str = "INFO"):
    """Decorator to audit log security-sensitive operations (OPT-IN)"""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not CryptoInstrumentationManager.is_audit_logging_enabled():
                return func(*args, **kwargs)
            
            result = func(*args, **kwargs)
            
            event = SecurityEvent(
                event_id=CryptoInstrumentationManager._generate_operation_id(),
                event_type=event_type,
                severity=severity,
                details={"function": func.__name__}
            )
            CryptoInstrumentationManager.record_security_event(event)
            
            return result
        return wrapper
    return decorator

class CryptoInstrumentationManager:
    """Central manager for QuantumCrypt observability (SINGLETON)"""
    
    _instance: Optional['CryptoInstrumentationManager'] = None
    _lock = threading.Lock()
    
    def __new__(cls) -> 'CryptoInstrumentationManager':
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._metrics = ThreadSafeCryptoMetricStore()
        self._logger = CryptoStructuredLogger(enabled=False)
        self._health = CryptoHealthChecker()
        
        self._enable_instrumentation = False
        self._enable_audit_logging = False
        self._initialized = True
        
        # Register default health checks
        self._health.register_check("entropy_quality", self._health.check_entropy_quality)
    
    @classmethod
    def enable_all(cls) -> None:
        """Enable ALL crypto observability (EXPLICIT OPT-IN)"""
        instance = cls()
        instance._enable_instrumentation = True
        instance._enable_audit_logging = True
        instance._logger.enable()
    
    @classmethod
    def disable_all(cls) -> None:
        """Disable ALL crypto observability"""
        instance = cls()
        instance._enable_instrumentation = False
        instance._enable_audit_logging = False
        instance._logger.disable()
    
    @classmethod
    def is_instrumentation_enabled(cls) -> bool:
        return cls()._enable_instrumentation
    
    @classmethod
    def is_audit_logging_enabled(cls) -> bool:
        return cls()._enable_audit_logging
    
    @classmethod
    def record_operation(cls, telemetry: CryptoOperationTelemetry) -> None:
        cls()._metrics.record_operation(telemetry)
    
    @classmethod
    def record_security_event(cls, event: SecurityEvent) -> None:
        cls()._metrics.record_security_event(event)
        cls()._logger.log_security_event(event.event_type, event.severity, **event.details)
    
    @classmethod
    def track_key_creation(cls, key_id: str, algorithm: str, key_size: int) -> None:
        cls()._metrics.track_key_creation(key_id, algorithm, key_size)
    
    @classmethod
    def track_key_usage(cls, key_id: str) -> None:
        cls()._metrics.track_key_usage(key_id)
    
    @classmethod
    def get_crypto_statistics(cls) -> Dict[str, Any]:
        """Get comprehensive crypto operation statistics"""
        return cls()._metrics.get_operation_statistics()
    
    @classmethod
    def get_security_summary(cls) -> Dict[str, Any]:
        """Get security event summary"""
        return cls()._metrics.get_security_event_summary()
    
    @classmethod
    def get_health_status(cls) -> Dict[str, Any]:
        """Get cryptographic health status"""
        return cls()._health.run_all_checks()
    
    @classmethod
    def get_audit_log(cls, count: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries"""
        return cls()._logger.get_audit_log(count)
    
    @classmethod
    def get_observability_status(cls) -> Dict[str, Any]:
        """Get status of all observability features"""
        instance = cls()
        stats = instance._metrics.get_operation_statistics()
        return {
            "instrumentation_enabled": {
                "operation_tracking": instance._enable_instrumentation,
                "audit_logging": instance._enable_audit_logging
            },
            "operations_tracked": stats["total_operations"],
            "security_events": len(instance._metrics._security_events),
            "health_checks_registered": len(instance._health._checks),
            "stability": "STABLE",
            "api_version": "v20",
            "module": "QuantumCrypt-AI"
        }
    
    @staticmethod
    def _generate_operation_id() -> str:
        """Generate unique operation ID"""
        return hashlib.sha256(f"{uuid.uuid4()}{time.time()}".encode()).hexdigest()[:16]

# Export public API
__all__ = [
    'CryptoInstrumentationManager',
    'crypto_timed',
    'crypto_audited',
    'CryptoOperationType',
    'SecurityEventType',
    'CryptoHealthStatus',
    'CryptoOperationTelemetry',
    'SecurityEvent',
    'ThreadSafeCryptoMetricStore',
    'CryptoStructuredLogger',
    'CryptoHealthChecker',
]
