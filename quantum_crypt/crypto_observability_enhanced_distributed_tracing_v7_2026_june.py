"""
QuantumCrypt AI - Enhanced Distributed Tracing Module (Dimension D - Observability)
Version: V7
Stability: STABLE
Backward Compatible: YES
Opt-In: YES (disabled by default)

This module adds distributed tracing capabilities ON TOP of existing crypto code.
No existing code is modified - this is purely additive.
"""

import time
import uuid
import threading
import hashlib
import secrets
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from contextlib import contextmanager


class CryptoSpanKind(Enum):
    KEY_GENERATION = "key_generation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEY_EXCHANGE = "key_exchange"
    HASHING = "hashing"
    RANDOM_GENERATION = "random_generation"
    INTERNAL = "internal"


class SpanStatus(Enum):
    OK = "ok"
    ERROR = "error"
    UNSET = "unset"


class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CryptoSpanEvent:
    """Security-aware span event with sensitive data masking."""
    name: str
    timestamp: float = field(default_factory=time.time)
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Mask sensitive data in attributes."""
        for key, value in list(self.attributes.items()):
            if any(sensitive in key.lower() for sensitive in ['key', 'secret', 'private', 'password', 'token']):
                if isinstance(value, (str, bytes)) and len(value) > 8:
                    self.attributes[key] = f"[REDACTED length={len(value)} hash={self._hash_value(value)}]"
    
    def _hash_value(self, value: Any) -> str:
        """Hash sensitive values for verification without exposure."""
        data = value.encode() if isinstance(value, str) else value
        return hashlib.sha256(data).hexdigest()[:16]


@dataclass
class CryptoSpan:
    """Security-aware span for cryptographic operations."""
    name: str
    operation_type: CryptoSpanKind
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    status: SpanStatus = SpanStatus.UNSET
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[CryptoSpanEvent] = field(default_factory=list)
    _sensitive_fields: set = field(default_factory=lambda: {
        'key', 'secret', 'private_key', 'public_key', 'password',
        'plaintext', 'ciphertext', 'signature', 'nonce', 'salt'
    })
    
    def add_event(self, name: str, **attributes) -> None:
        """Add a security-masked event to the span."""
        self.events.append(CryptoSpanEvent(name=name, attributes=attributes))
    
    def set_attribute(self, key: str, value: Any, sensitive: bool = False) -> None:
        """Set an attribute, with optional security masking."""
        if sensitive or key.lower() in self._sensitive_fields:
            if isinstance(value, (str, bytes)):
                self.attributes[key] = f"[REDACTED length={len(value)}]"
            else:
                self.attributes[key] = "[REDACTED]"
        else:
            self.attributes[key] = value
    
    def set_status(self, status: SpanStatus) -> None:
        """Set the span status."""
        self.status = status
    
    def end(self) -> None:
        """End the span with secure timestamp."""
        self.end_time = time.perf_counter()
    
    @property
    def duration_ns(self) -> Optional[int]:
        """Get span duration in nanoseconds (high precision)."""
        if self.end_time and self.start_time:
            return int((self.end_time - self.start_time) * 1e9)
        return None
    
    @property
    def duration_ms(self) -> Optional[float]:
        """Get span duration in milliseconds."""
        if duration_ns := self.duration_ns:
            return duration_ns / 1e6
        return None


class CryptoTraceContext:
    """Thread-local trace context with secure storage."""
    
    _thread_local = threading.local()
    
    @classmethod
    def get_current_span(cls) -> Optional[CryptoSpan]:
        """Get the current active span."""
        return getattr(cls._thread_local, 'current_span', None)
    
    @classmethod
    def set_current_span(cls, span: Optional[CryptoSpan]) -> None:
        """Set the current active span."""
        cls._thread_local.current_span = span
    
    @classmethod
    def get_trace_id(cls) -> Optional[str]:
        """Get the current trace ID."""
        span = cls.get_current_span()
        return span.trace_id if span else None
    
    @classmethod
    def clear(cls) -> None:
        """Securely clear context."""
        cls._thread_local.current_span = None


class CryptoEnhancedTracer:
    """
    Enhanced distributed tracer for cryptographic operations.
    OPT-IN - must be explicitly enabled.
    No impact on existing code when disabled.
    Security-aware with sensitive data masking.
    """
    
    def __init__(self, service_name: str = "quantum_crypt"):
        self.service_name = service_name
        self.enabled = False
        self.spans: Dict[str, List[CryptoSpan]] = defaultdict(list)
        self.max_spans_per_trace = 500
        self.max_trace_age_seconds = 3600
        self._lock = threading.Lock()
        self._trace_start_times: Dict[str, float] = {}
    
    def enable(self) -> None:
        """Enable tracing."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable tracing and clear all data."""
        self.enabled = False
        with self._lock:
            self.spans.clear()
            self._trace_start_times.clear()
    
    def is_enabled(self) -> bool:
        """Check if tracing is enabled."""
        return self.enabled
    
    def start_span(
        self,
        name: str,
        operation_type: CryptoSpanKind = CryptoSpanKind.INTERNAL,
        security_level: SecurityLevel = SecurityLevel.MEDIUM,
        parent_trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        **attributes
    ) -> CryptoSpan:
        """
        Start a new crypto span.
        Returns a no-op span if tracing is disabled.
        """
        if not self.enabled:
            return self._create_noop_span(name, operation_type)
        
        trace_id = parent_trace_id or self._generate_secure_trace_id()
        span_id = self._generate_secure_span_id()
        
        # Inherit from thread-local context
        current_span = CryptoTraceContext.get_current_span()
        if current_span and not parent_span_id:
            parent_span_id = current_span.span_id
            if not parent_trace_id:
                trace_id = current_span.trace_id
        
        span = CryptoSpan(
            name=name,
            operation_type=operation_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            security_level=security_level,
            start_time=time.perf_counter()
        )
        
        # Add attributes with masking
        for key, value in attributes.items():
            span.set_attribute(key, value)
        
        with self._lock:
            if trace_id not in self._trace_start_times:
                self._trace_start_times[trace_id] = time.time()
            
            trace_spans = self.spans[trace_id]
            if len(trace_spans) < self.max_spans_per_trace:
                trace_spans.append(span)
        
        return span
    
    def _create_noop_span(self, name: str, operation_type: CryptoSpanKind) -> CryptoSpan:
        """Create a no-op span for when tracing is disabled."""
        return CryptoSpan(
            name=name,
            operation_type=operation_type,
            trace_id="noop",
            span_id="noop",
            start_time=0,
            end_time=0
        )
    
    def _generate_secure_trace_id(self) -> str:
        """Generate a cryptographically secure trace ID."""
        return secrets.token_hex(16)
    
    def _generate_secure_span_id(self) -> str:
        """Generate a cryptographically secure span ID."""
        return secrets.token_hex(8)
    
    def get_trace(self, trace_id: str) -> List[CryptoSpan]:
        """Get all spans for a trace."""
        with self._lock:
            return list(self.spans.get(trace_id, []))
    
    def get_crypto_operation_summary(self, trace_id: str) -> Dict[str, Any]:
        """Get summary of cryptographic operations in a trace."""
        spans = self.get_trace(trace_id)
        if not spans:
            return {}
        
        ops_by_type = defaultdict(int)
        total_duration_ns = 0
        error_count = 0
        
        for span in spans:
            ops_by_type[span.operation_type.value] += 1
            if span.duration_ns:
                total_duration_ns += span.duration_ns
            if span.status == SpanStatus.ERROR:
                error_count += 1
        
        return {
            "trace_id": trace_id,
            "total_operations": len(spans),
            "operations_by_type": dict(ops_by_type),
            "total_duration_ns": total_duration_ns,
            "total_duration_ms": total_duration_ns / 1e6,
            "error_count": error_count,
            "service": self.service_name
        }
    
    def cleanup_old_traces(self) -> int:
        """Remove old traces to prevent memory leaks."""
        now = time.time()
        removed = 0
        
        with self._lock:
            old_traces = [
                tid for tid, start in self._trace_start_times.items()
                if (now - start) > self.max_trace_age_seconds
            ]
            
            for tid in old_traces:
                self.spans.pop(tid, None)
                self._trace_start_times.pop(tid, None)
                removed += 1
        
        return removed
    
    def export_secure_spans(self, trace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Export spans with all sensitive data already masked."""
        result = []
        with self._lock:
            if trace_id:
                spans = self.spans.get(trace_id, [])
            else:
                spans = [s for spans in self.spans.values() for s in spans]
            
            for span in spans:
                result.append({
                    "name": span.name,
                    "operation_type": span.operation_type.value,
                    "security_level": span.security_level.value,
                    "trace_id": span.trace_id,
                    "span_id": span.span_id,
                    "parent_span_id": span.parent_span_id,
                    "duration_ns": span.duration_ns,
                    "duration_ms": span.duration_ms,
                    "status": span.status.value,
                    "attributes": span.attributes,
                    "events": [
                        {
                            "name": e.name,
                            "timestamp": e.timestamp,
                            "attributes": e.attributes
                        }
                        for e in span.events
                    ]
                })
        return result


def crypto_traced(
    name: Optional[str] = None,
    operation_type: CryptoSpanKind = CryptoSpanKind.INTERNAL,
    security_level: SecurityLevel = SecurityLevel.MEDIUM,
    **attributes
):
    """
    Decorator for tracing cryptographic operations.
    OPT-IN - only active if tracer is enabled.
    Security-aware - masks sensitive data.
    
    Usage:
        @crypto_traced("key_gen", CryptoSpanKind.KEY_GENERATION, SecurityLevel.CRITICAL)
        def generate_key():
            ...
    """
    def decorator(func: Callable) -> Callable:
        span_name = name or func.__name__
        
        def wrapper(*args, **kwargs):
            tracer = GLOBAL_CRYPTO_TRACER
            if not tracer.is_enabled():
                return func(*args, **kwargs)
            
            span = tracer.start_span(
                span_name,
                operation_type=operation_type,
                security_level=security_level,
                **attributes
            )
            CryptoTraceContext.set_current_span(span)
            
            try:
                result = func(*args, **kwargs)
                span.set_status(SpanStatus.OK)
                return result
            except Exception as e:
                span.set_status(SpanStatus.ERROR)
                span.set_attribute("error.type", type(e).__name__)
                span.add_event("exception_occurred", message=str(e))
                raise
            finally:
                span.end()
                CryptoTraceContext.clear()
        
        return wrapper
    return decorator


@contextmanager
def crypto_trace_span(
    name: str,
    operation_type: CryptoSpanKind = CryptoSpanKind.INTERNAL,
    security_level: SecurityLevel = SecurityLevel.MEDIUM,
    **attributes
):
    """
    Context manager for tracing cryptographic operations.
    OPT-IN - no-op if tracing is disabled.
    
    Usage:
        with crypto_trace_span("encrypt", CryptoSpanKind.ENCRYPTION):
            ciphertext = encrypt(data, key)
    """
    tracer = GLOBAL_CRYPTO_TRACER
    if not tracer.is_enabled():
        yield
        return
    
    span = tracer.start_span(
        name,
        operation_type=operation_type,
        security_level=security_level,
        **attributes
    )
    CryptoTraceContext.set_current_span(span)
    
    try:
        yield span
        span.set_status(SpanStatus.OK)
    except Exception as e:
        span.set_status(SpanStatus.ERROR)
        span.set_attribute("error.type", type(e).__name__)
        span.add_event("exception_occurred", message=str(e))
        raise
    finally:
        span.end()
        CryptoTraceContext.clear()


# Global tracer instance - OPT-IN, disabled by default
GLOBAL_CRYPTO_TRACER = CryptoEnhancedTracer()
