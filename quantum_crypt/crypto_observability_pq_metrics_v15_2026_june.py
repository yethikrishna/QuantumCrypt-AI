"""
Post-Quantum Crypto Observability v15 - QuantumCrypt-AI
Cryptographic Operation Metrics, Audit Logging, and Health Checks
================================================================
API STABILITY: EXPERIMENTAL (v15 - PQ crypto integration)
BACKWARD COMPATIBLE: YES - 100% opt-in, no breaking changes
DEPENDENCIES: Standard library only (no external packages)

This module provides:
1. Structured cryptographic operation logging (OPT-IN, disabled by default)
2. Metrics collection for PQ crypto operations
3. Health checks for cryptographic subsystems
4. Key material usage tracking and audit trails
5. All instrumentation wraps existing code - NO core modifications
"""

import time
import json
import hashlib
import hmac
import secrets
import threading
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from datetime import datetime, timezone


class CryptoOperationType(Enum):
    """Types of cryptographic operations that can be instrumented."""
    KEY_GENERATION = "key_generation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEY_EXCHANGE = "key_exchange"
    HASHING = "hashing"
    RANDOM_GENERATION = "random_generation"
    SIGNATURE_VERIFICATION = "signature_verification"
    KEY_VALIDATION = "key_validation"
    HEALTH_CHECK = "health_check"


class PQAlgorithmFamily(Enum):
    """NIST Post-Quantum algorithm families."""
    CRYSTALS_KYBER = "CRYSTALS-Kyber"
    CRYSTALS_DILITHIUM = "CRYSTALS-Dilithium"
    FALCON = "FALCON"
    SPHINCS_PLUS = "SPHINCS+"
    CLASSICAL = "Classical"
    HYBRID = "Hybrid"


class KeySensitivityLevel(Enum):
    """Key material sensitivity classification."""
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    CRITICAL = "critical"


@dataclass
class CryptoEvent:
    """Structured crypto event with audit context."""
    operation_type: CryptoOperationType
    algorithm_family: PQAlgorithmFamily
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    correlation_id: str = ""
    module_name: str = ""
    success: bool = True
    duration_ms: float = 0.0
    key_size_bits: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    audit_id: str = ""
    key_sensitivity: KeySensitivityLevel = KeySensitivityLevel.INTERNAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_type": self.operation_type.value,
            "algorithm_family": self.algorithm_family.value,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "module_name": self.module_name,
            "success": self.success,
            "duration_ms": round(self.duration_ms, 4),
            "key_size_bits": self.key_size_bits,
            "metadata": self.metadata,
            "audit_id": self.audit_id,
            "key_sensitivity": self.key_sensitivity.value,
            "version": "v15"
        }


class CryptoMetricsCollector:
    """
    Thread-safe metrics collector for cryptographic operations.
    OPT-IN: Must be explicitly enabled via enable()
    Memory-bounded to prevent leaks.
    """

    def __init__(self):
        self._enabled = False
        self._lock = threading.RLock()
        self._operation_counters: Dict[str, int] = defaultdict(int)
        self._operation_timers: Dict[str, List[float]] = defaultdict(list)
        self._key_usage_counters: Dict[str, int] = defaultdict(int)
        self._entropy_gauges: Dict[str, float] = {}
        self._max_samples = 1000  # Prevent memory explosion
        self._bytes_processed: int = 0

    def enable(self) -> None:
        """Enable metrics collection. Disabled by default."""
        with self._lock:
            self._enabled = True

    def disable(self) -> None:
        """Disable metrics collection."""
        with self._lock:
            self._enabled = False

    def is_enabled(self) -> bool:
        return self._enabled

    def record_crypto_operation(
        self,
        operation: str,
        algorithm: str,
        duration_ms: float,
        success: bool = True,
        key_size: int = 0
    ) -> None:
        """Record a cryptographic operation metric."""
        if not self._enabled:
            return

        with self._lock:
            key = f"{operation}:{algorithm}:{'success' if success else 'failure'}"
            self._operation_counters[key] += 1
            self._operation_timers[key].append(duration_ms)
            if len(self._operation_timers[key]) > self._max_samples:
                self._operation_timers[key] = self._operation_timers[key][-self._max_samples:]

    def increment_key_usage(self, key_id: str, sensitivity: str) -> None:
        """Track key material usage."""
        if not self._enabled:
            return

        with self._lock:
            key = f"key_usage:{key_id}:{sensitivity}"
            self._key_usage_counters[key] += 1

    def record_bytes_processed(self, byte_count: int) -> None:
        """Track total bytes processed by crypto operations."""
        if not self._enabled:
            return

        with self._lock:
            self._bytes_processed += byte_count

    def set_entropy_estimate(self, source: str, estimate_bits: float) -> None:
        """Set current entropy estimate for a source."""
        if not self._enabled:
            return

        with self._lock:
            self._entropy_gauges[source] = estimate_bits

    def get_snapshot(self) -> Dict[str, Any]:
        """Get a snapshot of all collected crypto metrics."""
        with self._lock:
            return {
                "operation_counts": dict(self._operation_counters),
                "operation_timing_stats": {
                    name: {
                        "count": len(timings),
                        "min": min(timings) if timings else 0,
                        "max": max(timings) if timings else 0,
                        "avg": sum(timings) / len(timings) if timings else 0,
                        "p50": sorted(timings)[len(timings) // 2] if timings else 0,
                        "p95": sorted(timings)[int(len(timings) * 0.95)] if timings else 0,
                        "p99": sorted(timings)[int(len(timings) * 0.99)] if timings else 0,
                    }
                    for name, timings in self._operation_timers.items()
                },
                "key_usage_counts": dict(self._key_usage_counters),
                "entropy_estimates": dict(self._entropy_gauges),
                "total_bytes_processed": self._bytes_processed,
                "enabled": self._enabled,
                "version": "v15"
            }

    def reset(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self._operation_counters.clear()
            self._operation_timers.clear()
            self._key_usage_counters.clear()
            self._entropy_gauges.clear()
            self._bytes_processed = 0


class StructuredCryptoLogger:
    """
    Structured audit logger for cryptographic operations.
    OPT-IN: Must be explicitly enabled
    HMAC-chained for tamper-evident audit trails
    """

    def __init__(self, metrics_collector: CryptoMetricsCollector):
        self._enabled = False
        self._metrics = metrics_collector
        self._output_handler: Callable[[str], None] = print
        self._chain_key: bytes = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._entry_count = 0

    def enable(self) -> None:
        """Enable structured crypto logging."""
        with self._lock:
            self._enabled = True

    def disable(self) -> None:
        """Disable structured crypto logging."""
        with self._lock:
            self._enabled = False

    def is_enabled(self) -> bool:
        return self._enabled

    def set_output_handler(self, handler: Callable[[str], None]) -> None:
        """Set custom log output handler."""
        with self._lock:
            self._output_handler = handler

    def _chain_mac(self, entry_json: str) -> str:
        """Generate HMAC chain for tamper-evident logging."""
        entry_bytes = entry_json.encode()
        mac = hmac.new(self._chain_key, entry_bytes, hashlib.sha256)
        self._chain_key = mac.digest()  # Chain to next entry
        return mac.hexdigest()

    def log_event(self, event: CryptoEvent) -> None:
        """Log a crypto event if enabled."""
        if not self._enabled:
            return

        event_dict = event.to_dict()

        with self._lock:
            self._entry_count += 1
            event_dict["entry_sequence"] = self._entry_count
            entry_json = json.dumps(event_dict, separators=(",", ":"))
            event_dict["chain_mac"] = self._chain_mac(entry_json)
            final_entry = json.dumps(event_dict, separators=(",", ":"))
            self._output_handler(final_entry)

        if self._metrics.is_enabled():
            self._metrics.record_crypto_operation(
                event.operation_type.value,
                event.algorithm_family.value,
                event.duration_ms,
                event.success,
                event.key_size_bits
            )

    def log_crypto_operation(
        self,
        operation_type: CryptoOperationType,
        algorithm_family: PQAlgorithmFamily,
        module_name: str,
        success: bool = True,
        duration_ms: float = 0.0,
        key_size_bits: int = 0,
        key_sensitivity: KeySensitivityLevel = KeySensitivityLevel.INTERNAL,
        metadata: Optional[Dict[str, Any]] = None,
        correlation_id: str = ""
    ) -> None:
        """Convenience method to log a crypto operation."""
        event = CryptoEvent(
            operation_type=operation_type,
            algorithm_family=algorithm_family,
            module_name=module_name,
            success=success,
            duration_ms=duration_ms,
            key_size_bits=key_size_bits,
            key_sensitivity=key_sensitivity,
            metadata=metadata or {},
            correlation_id=correlation_id,
            audit_id=generate_audit_id()
        )
        self.log_event(event)


class CryptoHealthChecker:
    """
    Health check framework for cryptographic subsystems.
    Validates entropy sources, algorithm availability, etc.
    """

    def __init__(self, metrics_collector: CryptoMetricsCollector):
        self._metrics = metrics_collector
        self._checks: Dict[str, Callable[[], Dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._register_default_checks()

    def _register_default_checks(self) -> None:
        """Register built-in crypto health checks."""
        self.register_check("system_random", self._check_system_random)
        self.register_check("hash_algorithms", self._check_hash_algorithms)
        self.register_check("hmac_operations", self._check_hmac_operations)

    def _check_system_random(self) -> Dict[str, Any]:
        """Check system CSPRNG availability."""
        try:
            test_bytes = secrets.token_bytes(32)
            return {
                "healthy": len(test_bytes) == 32,
                "message": "System CSPRNG functioning",
                "source": "secrets module"
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(type(e).__name__),
                "message": f"CSPRNG failure: {str(e)}"
            }

    def _check_hash_algorithms(self) -> Dict[str, Any]:
        """Check hash algorithm availability."""
        try:
            test_data = b"health_check_test"
            hashes = {
                "sha256": hashlib.sha256(test_data).hexdigest(),
                "sha512": hashlib.sha512(test_data).hexdigest(),
                "sha3_256": hashlib.sha3_256(test_data).hexdigest()
            }
            return {
                "healthy": all(len(h) == 64 or len(h) == 128 for h in hashes.values()),
                "algorithms_available": list(hashes.keys()),
                "message": "All hash algorithms available"
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(type(e).__name__),
                "message": f"Hash algorithm failure: {str(e)}"
            }

    def _check_hmac_operations(self) -> Dict[str, Any]:
        """Check HMAC operation integrity."""
        try:
            key = secrets.token_bytes(32)
            data = b"test_message"
            mac1 = hmac.new(key, data, hashlib.sha256).digest()
            mac2 = hmac.new(key, data, hashlib.sha256).digest()
            constant_time_ok = hmac.compare_digest(mac1, mac2)
            return {
                "healthy": constant_time_ok,
                "constant_time_compare": constant_time_ok,
                "message": "HMAC operations functioning"
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(type(e).__name__),
                "message": f"HMAC failure: {str(e)}"
            }

    def register_check(self, name: str, check_fn: Callable[[], Dict[str, Any]]) -> None:
        """Register a custom health check function."""
        with self._lock:
            self._checks[name] = check_fn

    def run_health_check(self) -> Dict[str, Any]:
        """Run all registered crypto health checks."""
        start_time = time.time()
        results = {}
        overall_healthy = True

        with self._lock:
            checks_copy = dict(self._checks)

        for name, check_fn in checks_copy.items():
            try:
                result = check_fn()
                results[name] = result
                if not result.get("healthy", True):
                    overall_healthy = False
            except Exception as e:
                results[name] = {
                    "healthy": False,
                    "error": str(type(e).__name__),
                    "message": str(e)
                }
                overall_healthy = False

        duration_ms = (time.time() - start_time) * 1000

        if self._metrics.is_enabled():
            self._metrics.record_crypto_operation(
                "health_check", "internal", duration_ms, overall_healthy
            )

        return {
            "healthy": overall_healthy,
            "checks": results,
            "duration_ms": round(duration_ms, 4),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "v15"
        }

    def get_liveness_probe(self) -> Dict[str, Any]:
        """Simple liveness probe."""
        return {
            "alive": True,
            "crypto_ready": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "v15"
        }


class CryptoInstrumentationWrapper:
    """
    Wrapper class that instruments crypto operations with metrics and logging.
    WRAPS existing crypto functions - NO core code modifications.
    All instrumentation is OPT-IN via enable_instrumentation().
    """

    def __init__(self):
        self.metrics = CryptoMetricsCollector()
        self.logger = StructuredCryptoLogger(self.metrics)
        self.health = CryptoHealthChecker(self.metrics)
        self._instrumentation_enabled = False
        self._lock = threading.Lock()

    def enable_instrumentation(self) -> None:
        """Enable ALL crypto instrumentation."""
        with self._lock:
            self.metrics.enable()
            self.logger.enable()
            self._instrumentation_enabled = True

    def disable_instrumentation(self) -> None:
        """Disable ALL crypto instrumentation."""
        with self._lock:
            self.metrics.disable()
            self.logger.disable()
            self._instrumentation_enabled = False

    def is_instrumented(self) -> bool:
        return self._instrumentation_enabled

    def wrap_crypto_function(
        self,
        func: Callable,
        operation_type: CryptoOperationType,
        algorithm_family: PQAlgorithmFamily,
        module_name: str,
        key_size_bits: int = 0,
        key_sensitivity: KeySensitivityLevel = KeySensitivityLevel.INTERNAL
    ) -> Callable:
        """
        Wrap a crypto function with metrics and logging.
        Returns original function if instrumentation is disabled.
        """
        def wrapped(*args, **kwargs):
            if not self._instrumentation_enabled:
                return func(*args, **kwargs)

            start_time = time.time()
            success = True
            result = None
            bytes_processed = 0

            try:
                result = func(*args, **kwargs)
                # Estimate bytes processed from args
                for arg in args:
                    if isinstance(arg, (bytes, bytearray)):
                        bytes_processed += len(arg)
                return result
            except Exception as e:
                success = False
                raise
            finally:
                duration_ms = (time.time() - start_time) * 1000
                self.metrics.record_crypto_operation(
                    operation_type.value,
                    algorithm_family.value,
                    duration_ms,
                    success,
                    key_size_bits
                )
                if bytes_processed > 0:
                    self.metrics.record_bytes_processed(bytes_processed)
                self.logger.log_crypto_operation(
                    operation_type=operation_type,
                    algorithm_family=algorithm_family,
                    module_name=module_name,
                    success=success,
                    duration_ms=duration_ms,
                    key_size_bits=key_size_bits,
                    key_sensitivity=key_sensitivity,
                    metadata={"bytes_processed": bytes_processed}
                )

        return wrapped

    def timed_crypto_operation(
        self,
        operation_type: str,
        algorithm: str,
        key_size: int = 0
    ):
        """Decorator for timing crypto operations."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                if not self._instrumentation_enabled:
                    return func(*args, **kwargs)

                start_time = time.time()
                success = True
                try:
                    return func(*args, **kwargs)
                except Exception:
                    success = False
                    raise
                finally:
                    duration_ms = (time.time() - start_time) * 1000
                    self.metrics.record_crypto_operation(
                        operation_type, algorithm, duration_ms, success, key_size
                    )
            return wrapper
        return decorator


# Global singleton instance - OPT-IN, disabled by default
CRYPTO_INSTRUMENTATION = CryptoInstrumentationWrapper()


def get_crypto_instrumentation() -> CryptoInstrumentationWrapper:
    """
    Get the global crypto instrumentation instance.
    NOTE: Instrumentation is DISABLED by default.
    Call .enable_instrumentation() to activate.
    """
    return CRYPTO_INSTRUMENTATION


def generate_audit_id() -> str:
    """Generate a unique audit trail ID."""
    timestamp = str(time.time_ns()).encode()
    random_data = secrets.token_bytes(32)
    return hashlib.sha256(timestamp + random_data).hexdigest()[:32]


def generate_correlation_id() -> str:
    """Generate a cross-system correlation ID."""
    return generate_audit_id()


"""
HONEST LIMITATIONS (v15):
1. DISABLED BY DEFAULT - Users must explicitly opt-in to all instrumentation
2. Memory bounded - max 1000 samples per metric to prevent leaks
3. No network export - Metrics stay in memory, user must export manually
4. No actual PQ algorithm implementations - wraps existing classical crypto only
5. HMAC chaining is memory-only - restart resets the chain
6. Thread-safe but not multiprocess-safe
7. Health checks are BASIC - only validate standard library availability
8. No formal entropy certification - estimates are heuristic only
9. No persistence - Metrics and logs reset on process restart
10. Standard library only - No OpenSSL, liboqs, or crypto library bindings
11. Key usage tracking requires explicit user calls - no automatic tracking
12. No side-channel resistance claims - this is instrumentation only
"""
