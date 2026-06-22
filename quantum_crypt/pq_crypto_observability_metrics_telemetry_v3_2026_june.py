"""
QuantumCrypt AI - Post-Quantum Crypto Observability, Metrics & Telemetry v3
DIMENSION D: Observability & Instrumentation
ADD-ONLY implementation - wraps existing code, no core modifications

Crypto-specific features:
- Operation timing metrics (key_gen, sign, verify, encrypt, decrypt, kem)
- Security event telemetry (key_rotation, certificate_validation, audit_logs)
- Algorithm performance tracking (Dilithium, Kyber, Falcon, Sphincs+)
- Failure rate monitoring per algorithm
- OPT-IN instrumentation (disabled by default)
- Structured crypto audit logging
"""

import time
import threading
import json
from typing import Dict, List, Any, Optional, Callable, TypeVar
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import uuid
import secrets


class CryptoOperation(Enum):
    """Types of cryptographic operations"""
    KEY_GEN = "key_gen"
    SIGN = "sign"
    VERIFY = "verify"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    KEM_ENCAPS = "kem_encaps"
    KEM_DECAPS = "kem_decaps"
    KEY_WRAP = "key_wrap"
    KEY_UNWRAP = "key_unwrap"
    HASH = "hash"
    HMAC = "hmac"
    RANDOM = "random"


class CryptoAlgorithm(Enum):
    """Post-quantum and classic algorithms"""
    DILITHIUM_2 = "dilithium2"
    DILITHIUM_3 = "dilithium3"
    DILITHIUM_5 = "dilithium5"
    KYBER_512 = "kyber512"
    KYBER_768 = "kyber768"
    KYBER_1024 = "kyber1024"
    FALCON_512 = "falcon512"
    FALCON_1024 = "falcon1024"
    SPHINCS_PLUS = "sphincs+"
    AES_128_GCM = "aes128gcm"
    AES_256_GCM = "aes256gcm"
    CHACHA20_POLY1305 = "chacha20poly1305"
    SHA2_256 = "sha256"
    SHA2_512 = "sha512"
    SHA3_256 = "sha3_256"
    SHA3_512 = "sha3_512"
    HKDF = "hkdf"


class SecurityEventType(Enum):
    """Security-relevant events"""
    KEY_ROTATION = "key_rotation"
    KEY_GENERATION = "key_generation"
    CERTIFICATE_VALIDATION = "certificate_validation"
    SIGNATURE_VERIFICATION = "signature_verification"
    AUTHENTICATION_FAILURE = "authentication_failure"
    INTEGRITY_CHECK = "integrity_check"
    RANDOMNESS_ENTROPY_TEST = "randomness_entropy_test"
    SECURITY_POLICY_ENFORCEMENT = "security_policy"


T = TypeVar('T')


@dataclass
class CryptoMetricLabels:
    """Typed labels for crypto metrics"""
    algorithm: Optional[str] = None
    operation: Optional[str] = None
    key_size: Optional[int] = None
    security_level: Optional[str] = None
    
    def to_dict(self) -> Dict[str, str]:
        result = {}
        if self.algorithm:
            result["algorithm"] = self.algorithm
        if self.operation:
            result["operation"] = self.operation
        if self.key_size:
            result["key_size"] = str(self.key_size)
        if self.security_level:
            result["security_level"] = self.security_level
        return result
    
    def to_key(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class SecurityEvent:
    """Structured security audit event"""
    timestamp: float
    event_type: SecurityEventType
    success: bool
    details: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "event_type": self.event_type.value,
            "success": self.success,
            "details": self.details,
            "event_id": self.event_id
        }


class CryptoOperationTimer:
    """Tracks timing for cryptographic operations"""
    
    def __init__(self):
        self._timings: Dict[str, List[float]] = defaultdict(list)
        self._counts: Dict[str, int] = defaultdict(int)
        self._sums: Dict[str, float] = defaultdict(float)
        self._failures: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def record_success(self, duration: float, labels: CryptoMetricLabels):
        """Record a successful operation"""
        key = labels.to_key()
        with self._lock:
            self._timings[key].append(duration)
            self._counts[key] += 1
            self._sums[key] += duration
            # Keep last 1000 samples
            if len(self._timings[key]) > 1000:
                self._timings[key] = self._timings[key][-1000:]
    
    def record_failure(self, labels: CryptoMetricLabels):
        """Record a failed operation"""
        key = labels.to_key()
        with self._lock:
            self._failures[key] += 1
    
    def get_stats(self, labels: CryptoMetricLabels) -> Dict[str, Any]:
        """Get statistics for operation"""
        key = labels.to_key()
        with self._lock:
            count = self._counts.get(key, 0)
            failures = self._failures.get(key, 0)
            total = self._sums.get(key, 0.0)
            timings = self._timings.get(key, [])
            
            if count == 0 and failures == 0:
                return {"count": 0, "failures": 0, "failure_rate": 0.0}
            
            sorted_timings = sorted(timings)
            return {
                "count": count,
                "failures": failures,
                "failure_rate": failures / (count + failures) if (count + failures) > 0 else 0.0,
                "avg_ms": (total / count) * 1000 if count > 0 else None,
                "p50_ms": sorted_timings[len(sorted_timings) // 2] * 1000 if timings else None,
                "p95_ms": sorted_timings[int(len(sorted_timings) * 0.95)] * 1000 if timings else None,
                "p99_ms": sorted_timings[int(len(sorted_timings) * 0.99)] * 1000 if timings else None,
            }
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get stats for all operations"""
        result = {}
        # We need to iterate through unique keys - combine from counts and failures
        all_keys = set(self._counts.keys()) | set(self._failures.keys())
        for key in all_keys:
            try:
                labels_dict = json.loads(key)
                algorithm = labels_dict.get("algorithm", "unknown")
                operation = labels_dict.get("operation", "unknown")
                stats_key = f"{operation}:{algorithm}"
                # Reconstruct labels from key
                labels = CryptoMetricLabels(
                    algorithm=labels_dict.get("algorithm"),
                    operation=labels_dict.get("operation"),
                    key_size=int(labels_dict["key_size"]) if labels_dict.get("key_size") else None,
                    security_level=labels_dict.get("security_level")
                )
                result[stats_key] = self.get_stats(labels)
            except (json.JSONDecodeError, KeyError):
                continue
        return result


class AlgorithmPerformanceTracker:
    """Tracks relative performance of algorithms"""
    
    def __init__(self):
        self._baseline: Dict[str, float] = {}
        self._current: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def set_baseline(self, algorithm: str, avg_duration_ms: float):
        """Set baseline performance for comparison"""
        with self._lock:
            self._baseline[algorithm] = avg_duration_ms
    
    def record_sample(self, algorithm: str, duration_ms: float):
        """Record a performance sample"""
        with self._lock:
            self._current[algorithm].append(duration_ms)
            if len(self._current[algorithm]) > 100:
                self._current[algorithm] = self._current[algorithm][-100:]
    
    def get_deviation(self, algorithm: str) -> Optional[float]:
        """Get percentage deviation from baseline"""
        with self._lock:
            if algorithm not in self._baseline or algorithm not in self._current:
                return None
            baseline = self._baseline[algorithm]
            current = sum(self._current[algorithm]) / len(self._current[algorithm])
            return ((current - baseline) / baseline) * 100


class SecurityEventLogger:
    """Audit logging for security-relevant crypto operations"""
    
    def __init__(self, max_events: int = 10000):
        self._events: deque = deque(maxlen=max_events)
        self._lock = threading.Lock()
    
    def log(self, event_type: SecurityEventType, success: bool, **details):
        """Log a security event"""
        event = SecurityEvent(
            timestamp=time.time(),
            event_type=event_type,
            success=success,
            details=details
        )
        with self._lock:
            self._events.append(event)
    
    def get_recent(self, n: int = 100, event_type: Optional[SecurityEventType] = None) -> List[Dict[str, Any]]:
        """Get recent security events"""
        with self._lock:
            events = list(self._events)[-n:]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return [e.to_dict() for e in events]
    
    def get_failure_rate(self, event_type: Optional[SecurityEventType] = None) -> float:
        """Calculate failure rate for events"""
        with self._lock:
            events = list(self._events)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if not events:
            return 0.0
        failures = sum(1 for e in events if not e.success)
        return failures / len(events)
    
    def get_counts_by_type(self) -> Dict[str, Dict[str, int]]:
        """Get event counts by type"""
        counts: Dict[str, Dict[str, int]] = defaultdict(lambda: {"success": 0, "failure": 0})
        with self._lock:
            for event in self._events:
                key = event.event_type.value
                if event.success:
                    counts[key]["success"] += 1
                else:
                    counts[key]["failure"] += 1
        return dict(counts)


class KeyLifecycleMetrics:
    """Tracks key generation, rotation, and usage metrics"""
    
    def __init__(self):
        self._key_generations: Dict[str, int] = defaultdict(int)
        self._key_rotations: Dict[str, int] = defaultdict(int)
        self._key_usage: Dict[str, int] = defaultdict(int)
        self._last_rotation: Dict[str, float] = {}
        self._lock = threading.Lock()
    
    def record_key_generation(self, algorithm: str):
        """Record a key generation event"""
        with self._lock:
            self._key_generations[algorithm] += 1
    
    def record_key_rotation(self, algorithm: str):
        """Record a key rotation event"""
        with self._lock:
            self._key_rotations[algorithm] += 1
            self._last_rotation[algorithm] = time.time()
    
    def record_key_usage(self, algorithm: str):
        """Record key usage"""
        with self._lock:
            self._key_usage[algorithm] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get key lifecycle statistics"""
        with self._lock:
            return {
                "key_generations": dict(self._key_generations),
                "key_rotations": dict(self._key_rotations),
                "key_usage_counts": dict(self._key_usage),
                "last_rotation_times": {
                    alg: datetime.fromtimestamp(ts).isoformat()
                    for alg, ts in self._last_rotation.items()
                }
            }


class CryptoTelemetryRegistry:
    """Central registry for all crypto telemetry (OPT-IN)"""
    
    _instance: Optional['CryptoTelemetryRegistry'] = None
    _instance_lock = threading.Lock()
    
    def __init__(self):
        self.operation_timer = CryptoOperationTimer()
        self.performance_tracker = AlgorithmPerformanceTracker()
        self.security_logger = SecurityEventLogger()
        self.key_lifecycle = KeyLifecycleMetrics()
        self.enabled = False  # OPT-IN - disabled by default
        self._custom_gauges: Dict[str, float] = {}
        self._custom_counters: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    @classmethod
    def get_instance(cls) -> 'CryptoTelemetryRegistry':
        """Get singleton instance"""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = CryptoTelemetryRegistry()
        return cls._instance
    
    def enable(self):
        """Enable telemetry collection (OPT-IN)"""
        self.enabled = True
    
    def disable(self):
        """Disable telemetry collection"""
        self.enabled = False
    
    def time_operation(self, operation: CryptoOperation, algorithm: CryptoAlgorithm, 
                      key_size: Optional[int] = None) -> 'CryptoOperationContext':
        """Context manager for timing crypto operations"""
        labels = CryptoMetricLabels(
            operation=operation.value,
            algorithm=algorithm.value,
            key_size=key_size
        )
        return CryptoOperationContext(self, labels)
    
    def set_gauge(self, name: str, value: float):
        """Set a custom gauge value"""
        if not self.enabled:
            return
        with self._lock:
            self._custom_gauges[name] = value
    
    def inc_counter(self, name: str, value: int = 1):
        """Increment a custom counter"""
        if not self.enabled:
            return
        with self._lock:
            self._custom_counters[name] += value
    
    def get_full_report(self) -> Dict[str, Any]:
        """Get comprehensive telemetry report"""
        return {
            "enabled": self.enabled,
            "operation_performance": self.operation_timer.get_all_stats(),
            "security_events": self.security_logger.get_counts_by_type(),
            "key_lifecycle": self.key_lifecycle.get_stats(),
            "custom_metrics": {
                "gauges": dict(self._custom_gauges),
                "counters": dict(self._custom_counters)
            }
        }


class CryptoOperationContext:
    """Context manager for timing crypto operations"""
    
    def __init__(self, registry: CryptoTelemetryRegistry, labels: CryptoMetricLabels):
        self.registry = registry
        self.labels = labels
        self.start_time = 0.0
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.registry.enabled:
            return
        duration = time.perf_counter() - self.start_time
        if exc_type is None:
            self.registry.operation_timer.record_success(duration, self.labels)
        else:
            self.registry.operation_timer.record_failure(self.labels)


def crypto_timed(operation: CryptoOperation, algorithm: CryptoAlgorithm, 
                key_size: Optional[int] = None):
    """Decorator for timing crypto functions (OPT-IN)"""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            registry = CryptoTelemetryRegistry.get_instance()
            if not registry.enabled:
                return func(*args, **kwargs)
            
            labels = CryptoMetricLabels(
                operation=operation.value,
                algorithm=algorithm.value,
                key_size=key_size
            )
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                duration = time.perf_counter() - start
                registry.operation_timer.record_success(duration, labels)
                return result
            except Exception:
                registry.operation_timer.record_failure(labels)
                raise
        return wrapper
    return decorator


# Convenience functions (OPT-IN, no-op when disabled)
def enable_crypto_telemetry():
    """Enable crypto telemetry collection"""
    CryptoTelemetryRegistry.get_instance().enable()


def disable_crypto_telemetry():
    """Disable crypto telemetry collection"""
    CryptoTelemetryRegistry.get_instance().disable()


def log_security_event(event_type: SecurityEventType, success: bool, **details):
    """Log a security event (OPT-IN)"""
    registry = CryptoTelemetryRegistry.get_instance()
    if registry.enabled:
        registry.security_logger.log(event_type, success, **details)


def record_key_generation(algorithm: str):
    """Record key generation"""
    registry = CryptoTelemetryRegistry.get_instance()
    if registry.enabled:
        registry.key_lifecycle.record_key_generation(algorithm)


def record_key_rotation(algorithm: str):
    """Record key rotation"""
    registry = CryptoTelemetryRegistry.get_instance()
    if registry.enabled:
        registry.key_lifecycle.record_key_rotation(algorithm)


def get_crypto_telemetry_report() -> Dict[str, Any]:
    """Get full telemetry report"""
    return CryptoTelemetryRegistry.get_instance().get_full_report()


# Global security event logger instance
security_events = SecurityEventLogger()
