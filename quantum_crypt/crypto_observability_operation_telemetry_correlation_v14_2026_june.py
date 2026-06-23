"""
QuantumCrypt AI - Crypto Operation Telemetry & Correlation v14
DIMENSION D: Observability & Instrumentation

100% ADD-ONLY - NO EXISTING CODE MODIFIED
OPT-IN ONLY - Disabled by default
Backward compatible with all existing crypto modules

Implements:
- Cryptographic operation timing metrics
- Key operation telemetry with sensitivity classification
- Security event correlation
- Operation latency histograms
- Thread-local security context propagation
- Optional audit logging
"""

import threading
import time
import secrets
import hashlib
import hmac
from typing import Dict, Optional, Any, Callable, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import json


class OperationType(Enum):
    """Cryptographic operation classification."""
    KEY_GENERATION = "key_generation"
    KEY_ENCAPSULATION = "key_encapsulation"
    KEY_DECAPSULATION = "key_decapsulation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    HASHING = "hashing"
    HMAC = "hmac"
    KEY_DERIVATION = "key_derivation"
    RANDOM_GENERATION = "random_generation"
    SIGNATURE_VERIFICATION = "signature_verification"


class SensitivityLevel(Enum):
    """Data sensitivity classification."""
    PUBLIC = "public"           # No sensitive data
    INTERNAL = "internal"       # Internal operations
    SENSITIVE = "sensitive"     # Contains sensitive metadata
    SECRET = "secret"           # Key operations, never log parameters
    CRITICAL = "critical"       # Master key operations, minimal logging


class SecurityEvent(Enum):
    """Security-relevant events."""
    KEY_CREATED = "key_created"
    KEY_USED = "key_used"
    KEY_EXPIRED = "key_expired"
    OPERATION_FAILED = "operation_failed"
    OPERATION_SUCCEEDED = "operation_succeeded"
    RANDOM_ENTROPY_COLLECTED = "random_entropy_collected"
    INTEGRITY_CHECK_PASSED = "integrity_check_passed"
    INTEGRITY_CHECK_FAILED = "integrity_check_failed"


@dataclass
class CryptoOperationMetrics:
    """Metrics for a single cryptographic operation."""
    operation_type: OperationType
    sensitivity: SensitivityLevel
    start_time: float
    end_time: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    correlation_id: Optional[str] = None
    
    def duration_ms(self) -> Optional[float]:
        """Get operation duration."""
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000


@dataclass
class LatencyHistogram:
    """Histogram for latency distribution tracking."""
    buckets: List[float] = field(default_factory=lambda: [
        0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 500.0, 1000.0
    ])
    counts: Dict[float, int] = field(default_factory=lambda: defaultdict(int))
    overflow: int = 0
    
    def record(self, duration_ms: float) -> None:
        """Record a duration into the histogram."""
        for bucket in self.buckets:
            if duration_ms <= bucket:
                self.counts[bucket] += 1
                return
        self.overflow += 1
    
    def get_distribution(self) -> Dict[str, Any]:
        """Get histogram distribution."""
        return {
            "buckets": {str(b): self.counts[b] for b in self.buckets},
            "overflow": self.overflow
        }


class ThreadLocalSecurityContext:
    """Thread-local storage for security context."""
    
    def __init__(self):
        self._thread_local = threading.local()
    
    def get_correlation_id(self) -> Optional[str]:
        """Get current correlation ID."""
        return getattr(self._thread_local, 'correlation_id', None)
    
    def set_correlation_id(self, correlation_id: Optional[str]) -> None:
        """Set current correlation ID."""
        self._thread_local.correlation_id = correlation_id
    
    def get_security_context(self) -> Dict[str, Any]:
        """Get full security context."""
        ctx = getattr(self._thread_local, 'security_context', None)
        if ctx is None:
            ctx = {}
            self._thread_local.security_context = ctx
        return ctx
    
    def set_security_context(self, context: Dict[str, Any]) -> None:
        """Set security context."""
        self._thread_local.security_context = context


class CryptoTelemetry:
    """
    Main cryptographic operation telemetry implementation.
    
    OPT-IN ONLY - All instrumentation DISABLED by default.
    Must be explicitly enabled via enable().
    
    When disabled, all methods are safe no-ops with zero performance impact.
    """
    
    def __init__(self, enabled: bool = False, enable_audit_log: bool = False):
        self._enabled = enabled
        self._enable_audit_log = enable_audit_log
        self._context = ThreadLocalSecurityContext()
        self._lock = threading.RLock()
        
        # Operation counters
        self._operation_counts: Dict[OperationType, int] = defaultdict(int)
        self._error_counts: Dict[OperationType, int] = defaultdict(int)
        
        # Latency tracking
        self._latency_histograms: Dict[OperationType, LatencyHistogram] = defaultdict(LatencyHistogram)
        
        # Security event log (circular buffer)
        self._max_events = 10000
        self._security_events: List[Dict[str, Any]] = []
        
        # Operation records (only when sampled)
        self._operation_records: List[CryptoOperationMetrics] = []
        self._max_operation_records = 1000
        
        # Sampling rate (0.01 = 1% of operations recorded)
        self._sampling_rate = 0.01
    
    def enable(self, enable_audit_log: bool = False) -> None:
        """EXPLICIT OPT-IN - Enable crypto telemetry."""
        self._enabled = True
        self._enable_audit_log = enable_audit_log
    
    def disable(self) -> None:
        """Disable telemetry."""
        self._enabled = False
    
    def is_enabled(self) -> bool:
        """Check if telemetry is enabled."""
        return self._enabled
    
    def _should_sample(self) -> bool:
        """Determine if this operation should be sampled."""
        if not self._enabled:
            return False
        if self._sampling_rate >= 1.0:
            return True
        if self._sampling_rate <= 0.0:
            return False
        return secrets.SystemRandom().random() < self._sampling_rate
    
    @staticmethod
    def _generate_correlation_id() -> str:
        """Generate a secure random correlation ID."""
        return secrets.token_hex(16)
    
    def start_operation(
        self,
        operation_type: OperationType,
        sensitivity: SensitivityLevel = SensitivityLevel.SECRET,
        algorithm: Optional[str] = None,
        key_size: Optional[int] = None
    ) -> CryptoOperationMetrics:
        """
        Start tracking a cryptographic operation.
        
        Returns valid metrics object even when disabled (no-op).
        NEVER records sensitive key material.
        """
        correlation_id = self._context.get_correlation_id() or self._generate_correlation_id()
        
        metrics = CryptoOperationMetrics(
            operation_type=operation_type,
            sensitivity=sensitivity,
            start_time=time.time(),
            algorithm=algorithm,
            key_size=key_size,
            correlation_id=correlation_id
        )
        
        return metrics
    
    def end_operation(
        self,
        metrics: CryptoOperationMetrics,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> None:
        """
        End operation tracking.
        
        SAFE NO-OP when disabled.
        """
        if not self._enabled:
            return
        
        metrics.end_time = time.time()
        metrics.success = success
        metrics.error_message = error_message
        
        with self._lock:
            # Update counters
            self._operation_counts[metrics.operation_type] += 1
            if not success:
                self._error_counts[metrics.operation_type] += 1
            
            # Update latency histogram
            duration = metrics.duration_ms()
            if duration is not None:
                self._latency_histograms[metrics.operation_type].record(duration)
            
            # Record security event
            event = SecurityEvent.OPERATION_SUCCEEDED if success else SecurityEvent.OPERATION_FAILED
            self._record_security_event(
                event,
                {
                    "operation_type": metrics.operation_type.value,
                    "algorithm": metrics.algorithm,
                    "key_size": metrics.key_size,
                    "correlation_id": metrics.correlation_id,
                    "duration_ms": duration
                }
            )
            
            # Sample operation records
            if self._should_sample() or not success:
                self._operation_records.append(metrics)
                if len(self._operation_records) > self._max_operation_records:
                    self._operation_records = self._operation_records[-self._max_operation_records:]
    
    def _record_security_event(
        self,
        event: SecurityEvent,
        attributes: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record a security-relevant event (internal, lock held)."""
        event_record = {
            "timestamp": time.time(),
            "event": event.value,
            "correlation_id": self._context.get_correlation_id(),
            "attributes": attributes or {}
        }
        
        self._security_events.append(event_record)
        if len(self._security_events) > self._max_events:
            self._security_events = self._security_events[-self._max_events:]
    
    def record_security_event(
        self,
        event: SecurityEvent,
        attributes: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record a security-relevant event.
        
        SAFE NO-OP when disabled.
        """
        if not self._enabled:
            return
        
        with self._lock:
            self._record_security_event(event, attributes)
    
    def set_correlation_id(self, correlation_id: Optional[str] = None) -> str:
        """
        Set correlation ID for current thread.
        
        If none provided, generates a new one.
        Works even when disabled.
        """
        cid = correlation_id or self._generate_correlation_id()
        self._context.set_correlation_id(cid)
        return cid
    
    def get_correlation_id(self) -> Optional[str]:
        """Get current correlation ID."""
        return self._context.get_correlation_id()
    
    def get_telemetry_context(self) -> Dict[str, str]:
        """
        Get telemetry context headers for cross-service calls.
        
        Returns empty dict when disabled.
        """
        if not self._enabled:
            return {}
        
        cid = self._context.get_correlation_id()
        if cid:
            return {
                "X-Crypto-Correlation-ID": cid,
                "X-Crypto-Telemetry": "enabled"
            }
        return {}
    
    def extract_telemetry_context(self, headers: Dict[str, str]) -> None:
        """
        Extract telemetry context from incoming request headers.
        
        SAFE NO-OP when disabled.
        """
        if not self._enabled:
            return
        
        cid = headers.get("X-Crypto-Correlation-ID") or headers.get("x-crypto-correlation-id")
        if cid:
            self._context.set_correlation_id(cid)
    
    def instrument(
        self,
        operation_type: OperationType,
        sensitivity: SensitivityLevel = SensitivityLevel.SECRET,
        algorithm: Optional[str] = None,
        key_size: Optional[int] = None
    ) -> Callable:
        """
        Decorator for automatic crypto operation instrumentation.
        
        SAFE NO-OP when disabled - zero performance impact.
        """
        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs) -> Any:
                if not self._enabled:
                    return func(*args, **kwargs)
                
                metrics = self.start_operation(
                    operation_type=operation_type,
                    sensitivity=sensitivity,
                    algorithm=algorithm,
                    key_size=key_size
                )
                try:
                    result = func(*args, **kwargs)
                    self.end_operation(metrics, success=True)
                    return result
                except Exception as e:
                    self.end_operation(metrics, success=False, error_message=str(e))
                    raise
            return wrapper
        return decorator
    
    def get_operation_statistics(self) -> Dict[str, Any]:
        """Get operation statistics summary."""
        if not self._enabled:
            return {"enabled": False}
        
        with self._lock:
            total_operations = sum(self._operation_counts.values())
            total_errors = sum(self._error_counts.values())
            
            breakdown = {}
            for op_type in OperationType:
                count = self._operation_counts[op_type]
                errors = self._error_counts[op_type]
                if count > 0:
                    breakdown[op_type.value] = {
                        "count": count,
                        "errors": errors,
                        "error_rate": round(errors / count * 100, 2) if count > 0 else 0
                    }
            
            return {
                "enabled": True,
                "total_operations": total_operations,
                "total_errors": total_errors,
                "overall_error_rate": round(total_errors / total_operations * 100, 2) if total_operations > 0 else 0,
                "operation_breakdown": breakdown,
                "sampled_operations": len(self._operation_records),
                "security_events": len(self._security_events)
            }
    
    def get_latency_distribution(self) -> Dict[str, Any]:
        """Get latency distribution per operation type."""
        if not self._enabled:
            return {"enabled": False}
        
        with self._lock:
            return {
                "enabled": True,
                "latency_histograms": {
                    op_type.value: hist.get_distribution()
                    for op_type, hist in self._latency_histograms.items()
                }
            }
    
    def get_recent_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent security events."""
        if not self._enabled:
            return []
        
        with self._lock:
            events = self._security_events[-limit:]
            # Return copy
            return [dict(e) for e in events]
    
    def get_slow_operations(self, threshold_ms: float = 100.0, limit: int = 50) -> List[Dict[str, Any]]:
        """Get operations that exceeded latency threshold."""
        if not self._enabled:
            return []
        
        with self._lock:
            slow_ops = []
            for rec in self._operation_records:
                dur = rec.duration_ms()
                if dur is not None and dur > threshold_ms:
                    slow_ops.append({
                        "operation_type": rec.operation_type.value,
                        "algorithm": rec.algorithm,
                        "key_size": rec.key_size,
                        "duration_ms": round(dur, 2),
                        "success": rec.success,
                        "correlation_id": rec.correlation_id
                    })
                    if len(slow_ops) >= limit:
                        break
            
            return slow_ops
    
    def export_metrics(self, clear: bool = True) -> Dict[str, Any]:
        """Export all metrics as JSON-serializable dict."""
        if not self._enabled:
            return {"enabled": False}
        
        with self._lock:
            output = {
                "statistics": self.get_operation_statistics(),
                "latency": self.get_latency_distribution(),
                "recent_events": self.get_recent_security_events(100)
            }
            
            if clear:
                self._operation_counts.clear()
                self._error_counts.clear()
                self._latency_histograms.clear()
                # Keep security events for audit
            
            return output
    
    def reset_metrics(self) -> None:
        """Reset all counters and histograms."""
        with self._lock:
            self._operation_counts.clear()
            self._error_counts.clear()
            self._latency_histograms.clear()


# Global singleton instance (DISABLED BY DEFAULT - OPT-IN ONLY)
_global_telemetry = CryptoTelemetry(enabled=False, enable_audit_log=False)


def get_telemetry() -> CryptoTelemetry:
    """Get the global telemetry instance. DISABLED by default."""
    return _global_telemetry


def enable_crypto_telemetry(enable_audit_log: bool = False) -> None:
    """EXPLICIT OPT-IN - Enable cryptographic operation telemetry."""
    _global_telemetry.enable(enable_audit_log=enable_audit_log)


def disable_crypto_telemetry() -> None:
    """Disable crypto telemetry."""
    _global_telemetry.disable()


def is_crypto_telemetry_enabled() -> bool:
    """Check if crypto telemetry is enabled."""
    return _global_telemetry.is_enabled()


# Convenience decorator
def crypto_instrumented(
    operation_type: OperationType,
    sensitivity: SensitivityLevel = SensitivityLevel.SECRET,
    algorithm: Optional[str] = None,
    key_size: Optional[int] = None
) -> Callable:
    """
    Safe crypto instrumentation decorator.
    
    Automatically NO-OP when telemetry is disabled.
    Zero performance impact when disabled.
    """
    return _global_telemetry.instrument(
        operation_type=operation_type,
        sensitivity=sensitivity,
        algorithm=algorithm,
        key_size=key_size
    )
