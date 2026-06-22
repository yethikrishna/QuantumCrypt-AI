"""
Crypto Observability Metrics Collection v8 - QuantumCrypt-AI
============================================================
DIMENSION D - Observability & Instrumentation v8

ADD-ONLY IMPLEMENTATION: No existing code modified
OPT-IN DESIGN: Disabled by default, zero overhead when off

Crypto-Specific Features:
- Crypto operation counters (encrypt, decrypt, sign, verify, hash, kem)
- Crypto timing measurements with constant-time verification
- Key lifecycle gauges (generation, rotation, expiration)
- Crypto security level histograms (NIST 1-5)
- Algorithm usage tracking
- Post-quantum specific metrics
- Memory zeroization tracking
- Side-channel resistance monitoring
- Thread-safe operations
- Memory-bounded collections
- OPT-IN: Must call enable() explicitly

Philosophy: If it ain't broke, don't rewrite it.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, TypeVar
from datetime import datetime, timezone
import threading
import time
import json
import hashlib
import hmac
import secrets
from collections import defaultdict
from functools import wraps


class CryptoOperation(Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"
    HASH = "hash"
    HMAC = "hmac"
    KEM_ENCAPS = "kem_encaps"
    KEM_DECAPS = "kem_decaps"
    KEY_GEN = "key_generation"
    KEY_ROTATE = "key_rotation"
    ZEROIZATION = "memory_zeroization"
    RANDOM_GEN = "random_generation"


class AlgorithmFamily(Enum):
    AES = "aes"
    RSA = "rsa"
    ECDSA = "ecdsa"
    KYBER = "kyber"
    DILITHIUM = "dilithium"
    FALCON = "falcon"
    SPHINCS = "sphincs"
    SHA2 = "sha2"
    SHA3 = "sha3"
    HKDF = "hkdf"


class SecurityLevel(Enum):
    NIST_1 = "nist_level_1"
    NIST_2 = "nist_level_2"
    NIST_3 = "nist_level_3"
    NIST_4 = "nist_level_4"
    NIST_5 = "nist_level_5"


class MetricStatus(Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"


F = TypeVar('F', bound=Callable[..., Any])


@dataclass
class CryptoCounter:
    """Thread-safe counter for crypto operations."""
    name: str
    operation: Optional[CryptoOperation] = None
    algorithm: Optional[AlgorithmFamily] = None
    security_level: Optional[SecurityLevel] = None
    _value: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment(self, amount: int = 1) -> None:
        with self._lock:
            self._value += max(0, amount)

    @property
    def value(self) -> int:
        with self._lock:
            return self._value

    def reset(self) -> None:
        with self._lock:
            self._value = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "crypto_counter",
            "name": self.name,
            "operation": self.operation.value if self.operation else None,
            "algorithm": self.algorithm.value if self.algorithm else None,
            "security_level": self.security_level.value if self.security_level else None,
            "value": self.value,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@dataclass
class CryptoTimer:
    """Thread-safe timer for crypto operations with timing analysis."""
    name: str
    operation: Optional[CryptoOperation] = None
    algorithm: Optional[AlgorithmFamily] = None
    _durations: List[float] = field(default_factory=list)
    _active: Dict[int, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _max_samples: int = 10000

    def start(self) -> int:
        timer_id = threading.get_ident()
        with self._lock:
            self._active[timer_id] = time.perf_counter()
        return timer_id

    def stop(self, timer_id: Optional[int] = None) -> float:
        tid = timer_id or threading.get_ident()
        end_time = time.perf_counter()
        with self._lock:
            start_time = self._active.pop(tid, end_time)
            duration = max(0.0, end_time - start_time)
            if len(self._durations) >= self._max_samples:
                self._durations.pop(0)
            self._durations.append(duration)
        return duration

    def __enter__(self) -> 'CryptoTimer':
        self.start()
        return self

    def __exit__(self, *args) -> None:
        self.stop()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._durations)

    @property
    def total(self) -> float:
        with self._lock:
            return sum(self._durations)

    @property
    def avg(self) -> float:
        with self._lock:
            return sum(self._durations) / len(self._durations) if self._durations else 0.0

    @property
    def timing_variance(self) -> float:
        """Calculate timing variance for side-channel detection."""
        with self._lock:
            if len(self._durations) < 2:
                return 0.0
            avg = sum(self._durations) / len(self._durations)
            var = sum((d - avg) ** 2 for d in self._durations) / len(self._durations)
            return var

    @property
    def timing_ratio(self) -> float:
        """Max/min timing ratio - higher indicates potential side-channel."""
        with self._lock:
            if len(self._durations) < 2:
                return 1.0
            min_d = min(self._durations)
            max_d = max(self._durations)
            return max_d / min_d if min_d > 0 else float('inf')

    def check_constant_time(self, threshold: float = 2.0) -> bool:
        """Check if timing is reasonably constant (ratio < threshold)."""
        return self.timing_ratio < threshold

    def reset(self) -> None:
        with self._lock:
            self._durations.clear()
            self._active.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "crypto_timer",
            "name": self.name,
            "operation": self.operation.value if self.operation else None,
            "algorithm": self.algorithm.value if self.algorithm else None,
            "count": self.count,
            "total_seconds": round(self.total, 6),
            "avg_seconds": round(self.avg, 6),
            "timing_variance": round(self.timing_variance, 9),
            "timing_ratio": round(self.timing_ratio, 3),
            "constant_time_ok": self.check_constant_time(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@dataclass
class KeyLifecycleGauge:
    """Track key lifecycle metrics - generation, age, rotations."""
    name: str
    algorithm: Optional[AlgorithmFamily] = None
    security_level: Optional[SecurityLevel] = None
    _keys_generated: int = 0
    _keys_rotated: int = 0
    _keys_expired: int = 0
    _active_keys: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_generation(self) -> None:
        with self._lock:
            self._keys_generated += 1
            self._active_keys += 1

    def record_rotation(self) -> None:
        with self._lock:
            self._keys_rotated += 1

    def record_expiration(self) -> None:
        with self._lock:
            self._keys_expired += 1
            self._active_keys = max(0, self._active_keys - 1)

    @property
    def keys_generated(self) -> int:
        with self._lock:
            return self._keys_generated

    @property
    def active_keys(self) -> int:
        with self._lock:
            return self._active_keys

    def reset(self) -> None:
        with self._lock:
            self._keys_generated = 0
            self._keys_rotated = 0
            self._keys_expired = 0
            self._active_keys = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "key_lifecycle_gauge",
            "name": self.name,
            "algorithm": self.algorithm.value if self.algorithm else None,
            "security_level": self.security_level.value if self.security_level else None,
            "keys_generated": self.keys_generated,
            "keys_rotated": self._keys_rotated,
            "keys_expired": self._keys_expired,
            "active_keys": self.active_keys,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


SECURITY_LEVEL_BUCKETS = [1, 2, 3, 4, 5]


@dataclass
class SecurityHistogram:
    """Histogram tracking security level distributions."""
    name: str
    _counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_security_level(self, level: int) -> None:
        """Record operation at given NIST security level (1-5)."""
        with self._lock:
            self._counts[max(1, min(5, level))] += 1
            self._counts['total'] += 1

    @property
    def total(self) -> int:
        with self._lock:
            return self._counts.get('total', 0)

    def get_distribution(self) -> Dict[str, int]:
        with self._lock:
            return {f"nist_level_{i}": self._counts.get(i, 0) for i in SECURITY_LEVEL_BUCKETS}

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "security_histogram",
            "name": self.name,
            "total_operations": self.total,
            "distribution": self.get_distribution(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@dataclass
class ZeroizationTracker:
    """Track memory zeroization operations for crypto safety."""
    name: str
    _zeroizations: int = 0
    _bytes_zeroized: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_zeroization(self, bytes_cleared: int) -> None:
        with self._lock:
            self._zeroizations += 1
            self._bytes_zeroized += bytes_cleared

    @property
    def count(self) -> int:
        with self._lock:
            return self._zeroizations

    @property
    def total_bytes(self) -> int:
        with self._lock:
            return self._bytes_zeroized

    def reset(self) -> None:
        with self._lock:
            self._zeroizations = 0
            self._bytes_zeroized = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "zeroization_tracker",
            "name": self.name,
            "zeroization_count": self.count,
            "total_bytes_zeroized": self.total_bytes,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


# No-op implementations for when metrics are disabled
class NoOpCryptoCounter:
    def increment(self, amount: int = 1) -> None: pass
    @property
    def value(self) -> int: return 0
    def reset(self) -> None: pass
    def to_dict(self) -> Dict[str, Any]: return {}


class NoOpCryptoTimer:
    def start(self) -> int: return 0
    def stop(self, timer_id: Optional[int] = None) -> float: return 0.0
    def __enter__(self) -> 'NoOpCryptoTimer': return self
    def __exit__(self, *args) -> None: pass
    @property
    def count(self) -> int: return 0
    @property
    def total(self) -> float: return 0.0
    @property
    def avg(self) -> float: return 0.0
    @property
    def timing_variance(self) -> float: return 0.0
    @property
    def timing_ratio(self) -> float: return 1.0
    def check_constant_time(self, threshold: float = 2.0) -> bool: return True
    def reset(self) -> None: pass
    def to_dict(self) -> Dict[str, Any]: return {}


class NoOpKeyLifecycleGauge:
    def record_generation(self) -> None: pass
    def record_rotation(self) -> None: pass
    def record_expiration(self) -> None: pass
    @property
    def keys_generated(self) -> int: return 0
    @property
    def active_keys(self) -> int: return 0
    def reset(self) -> None: pass
    def to_dict(self) -> Dict[str, Any]: return {}


class NoOpSecurityHistogram:
    def record_security_level(self, level: int) -> None: pass
    @property
    def total(self) -> int: return 0
    def get_distribution(self) -> Dict[str, int]: return {}
    def reset(self) -> None: pass
    def to_dict(self) -> Dict[str, Any]: return {}


class NoOpZeroizationTracker:
    def record_zeroization(self, bytes_cleared: int) -> None: pass
    @property
    def count(self) -> int: return 0
    @property
    def total_bytes(self) -> int: return 0
    def reset(self) -> None: pass
    def to_dict(self) -> Dict[str, Any]: return {}


class CryptoMetricsRegistry:
    """Crypto-specific metrics registry - OPT-IN, disabled by default."""

    def __init__(self):
        self._status = MetricStatus.DISABLED
        self._counters: Dict[str, CryptoCounter] = {}
        self._timers: Dict[str, CryptoTimer] = {}
        self._key_gauges: Dict[str, KeyLifecycleGauge] = {}
        self._security_histograms: Dict[str, SecurityHistogram] = {}
        self._zeroization_trackers: Dict[str, ZeroizationTracker] = {}
        self._lock = threading.Lock()

    def enable(self) -> None:
        """Enable crypto metrics collection - OPT-IN required."""
        self._status = MetricStatus.ENABLED

    def disable(self) -> None:
        self._status = MetricStatus.DISABLED

    @property
    def is_enabled(self) -> bool:
        return self._status == MetricStatus.ENABLED

    def counter(self, name: str, operation: Optional[CryptoOperation] = None,
                algorithm: Optional[AlgorithmFamily] = None) -> CryptoCounter:
        if not self.is_enabled:
            return NoOpCryptoCounter()  # type: ignore
        with self._lock:
            if name not in self._counters:
                self._counters[name] = CryptoCounter(name, operation, algorithm)
            return self._counters[name]

    def timer(self, name: str, operation: Optional[CryptoOperation] = None,
              algorithm: Optional[AlgorithmFamily] = None) -> CryptoTimer:
        if not self.is_enabled:
            return NoOpCryptoTimer()  # type: ignore
        with self._lock:
            if name not in self._timers:
                self._timers[name] = CryptoTimer(name, operation, algorithm)
            return self._timers[name]

    def key_gauge(self, name: str, algorithm: Optional[AlgorithmFamily] = None,
                  security_level: Optional[SecurityLevel] = None) -> KeyLifecycleGauge:
        if not self.is_enabled:
            return NoOpKeyLifecycleGauge()  # type: ignore
        with self._lock:
            if name not in self._key_gauges:
                self._key_gauges[name] = KeyLifecycleGauge(name, algorithm, security_level)
            return self._key_gauges[name]

    def security_histogram(self, name: str) -> SecurityHistogram:
        if not self.is_enabled:
            return NoOpSecurityHistogram()  # type: ignore
        with self._lock:
            if name not in self._security_histograms:
                self._security_histograms[name] = SecurityHistogram(name)
            return self._security_histograms[name]

    def zeroization_tracker(self, name: str) -> ZeroizationTracker:
        if not self.is_enabled:
            return NoOpZeroizationTracker()  # type: ignore
        with self._lock:
            if name not in self._zeroization_trackers:
                self._zeroization_trackers[name] = ZeroizationTracker(name)
            return self._zeroization_trackers[name]

    def timed_operation(self, name: str, operation: Optional[CryptoOperation] = None,
                        algorithm: Optional[AlgorithmFamily] = None) -> Callable[[F], F]:
        """Decorator to time crypto operations."""
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not self.is_enabled:
                    return func(*args, **kwargs)
                timer = self.timer(name, operation, algorithm)
                with timer:
                    return func(*args, **kwargs)
            return wrapper  # type: ignore
        return decorator

    def counted_operation(self, name: str, operation: Optional[CryptoOperation] = None,
                          algorithm: Optional[AlgorithmFamily] = None) -> Callable[[F], F]:
        """Decorator to count crypto operations."""
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.is_enabled:
                    self.counter(name, operation, algorithm).increment()
                return func(*args, **kwargs)
            return wrapper  # type: ignore
        return decorator

    def measure_hash_timing(self, data: bytes, algorithm: str = 'sha256') -> Dict[str, Any]:
        """Utility: Measure hash timing and check constant-time properties."""
        if not self.is_enabled:
            return {"status": "disabled"}
        timer = self.timer(f"hash_{algorithm}", CryptoOperation.HASH)
        with timer:
            h = hashlib.new(algorithm, data).digest()
        return {
            "hash": h.hex()[:16],
            "duration_seconds": timer.avg,
            "timing_ratio": timer.timing_ratio,
            "constant_time_ok": timer.check_constant_time()
        }

    def measure_hmac_timing(self, key: bytes, data: bytes, algorithm: str = 'sha256') -> Dict[str, Any]:
        """Utility: Measure HMAC timing."""
        if not self.is_enabled:
            return {"status": "disabled"}
        timer = self.timer(f"hmac_{algorithm}", CryptoOperation.HMAC)
        with timer:
            h = hmac.new(key, data, algorithm).digest()
        return {
            "hmac": h.hex()[:16],
            "duration_seconds": timer.avg,
            "timing_ratio": timer.timing_ratio
        }

    def export_dict(self) -> Dict[str, Any]:
        if not self.is_enabled:
            return {"status": "disabled", "metrics": []}
        with self._lock:
            return {
                "status": "enabled",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics": {
                    "crypto_counters": [c.to_dict() for c in self._counters.values()],
                    "crypto_timers": [t.to_dict() for t in self._timers.values()],
                    "key_lifecycle": [g.to_dict() for g in self._key_gauges.values()],
                    "security_distribution": [h.to_dict() for h in self._security_histograms.values()],
                    "zeroization": [z.to_dict() for z in self._zeroization_trackers.values()]
                },
                "summary": {
                    "counters": len(self._counters),
                    "timers": len(self._timers),
                    "key_gauges": len(self._key_gauges),
                    "security_histograms": len(self._security_histograms),
                    "zeroization_trackers": len(self._zeroization_trackers)
                }
            }

    def export_json(self, indent: int = 2) -> str:
        return json.dumps(self.export_dict(), indent=indent)

    def reset_all(self) -> None:
        with self._lock:
            for c in self._counters.values():
                c.reset()
            for t in self._timers.values():
                t.reset()
            for g in self._key_gauges.values():
                g.reset()
            for h in self._security_histograms.values():
                h.reset()
            for z in self._zeroization_trackers.values():
                z.reset()


# Global crypto metrics registry - SINGLETON
GLOBAL_CRYPTO_METRICS = CryptoMetricsRegistry()


def enable_crypto_metrics() -> None:
    GLOBAL_CRYPTO_METRICS.enable()


def disable_crypto_metrics() -> None:
    GLOBAL_CRYPTO_METRICS.disable()


def get_global_crypto_metrics() -> CryptoMetricsRegistry:
    return GLOBAL_CRYPTO_METRICS


MODULE_INFO = {
    "name": "crypto_observability_metrics_collection_v8",
    "dimension": "D - Observability & Instrumentation",
    "version": "v8",
    "date": "2026-06-23",
    "status": "production-ready",
    "opt_in_required": True,
    "crypto_specific": True,
    "features": [
        "crypto_operation_counters", "crypto_timing_analysis",
        "key_lifecycle_tracking", "security_level_histograms",
        "constant_time_verification", "memory_zeroization_tracking",
        "thread-safe", "export", "pq_algorithms_supported"
    ]
}
