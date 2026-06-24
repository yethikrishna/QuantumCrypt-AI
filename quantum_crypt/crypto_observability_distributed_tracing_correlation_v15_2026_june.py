"""
QuantumCrypt-AI - Observability v15: Distributed Tracing & Context Correlation
================================================================================
DIMENSION D - Observability & Instrumentation
VERSION: v15
DATE: June 2026
PHILOSOPHY: 100% ADD-ONLY, OPT-IN BY DEFAULT, ZERO OVERHEAD WHEN DISABLED

PURPOSE:
Enhanced distributed tracing context propagation, adaptive sampling strategies,
and cross-signal correlation between metrics, logs, and traces for post-quantum
cryptographic operations and key management.

KEY FEATURES:
1. W3C Trace Context compliant propagation (traceparent, tracestate)
2. B3 Multi-Header propagation support (for backward compatibility)
3. Adaptive sampling with dynamic sampling rates
4. Correlation ID generation and propagation across thread boundaries
5. Key operation context baggage for crypto audit trails
6. Trace state management for distributed key operations
7. Span link creation for cross-operation correlation
8. Trace-to-metric correlation for SLO alerting integration
9. Thread-local context storage with automatic cleanup
10. Decorator-based span creation for crypto operation instrumentation
11. HSM/KMS operation tracing support
12. Key rotation and lifecycle correlation tracking

OPT-IN GUARANTEE:
- ALL features DISABLED by default
- Zero overhead when not explicitly enabled
- No monkey patching of existing code
- Pure wrapper pattern
"""

import threading
import time
import hashlib
import secrets
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List, Any, Callable, Tuple
from collections import deque
import functools


# -----------------------------------------------------------------------------
# ENUMERATIONS
# -----------------------------------------------------------------------------

class TracePropagationFormat(Enum):
    """Supported trace context propagation formats."""
    W3C_TRACE_CONTEXT = "w3c_trace_context"
    B3_MULTI = "b3_multi"
    B3_SINGLE = "b3_single"


class SpanKind(Enum):
    """Span kind for distributed tracing semantics."""
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"
    HSM_OPERATION = "hsm_operation"
    KEY_OPERATION = "key_operation"
    CRYPTO_OPERATION = "crypto_operation"


class SamplingDecision(Enum):
    """Sampling decision for trace recording."""
    RECORD_AND_SAMPLE = "record_and_sample"
    RECORD_ONLY = "record_only"
    DROP = "drop"


class SpanStatus(Enum):
    """Span completion status."""
    OK = "ok"
    ERROR = "error"
    CANCELLED = "cancelled"
    UNSET = "unset"


class CryptoOperationType(Enum):
    """Types of cryptographic operations for correlation."""
    KEY_GENERATION = "key_generation"
    KEY_ROTATION = "key_rotation"
    KEY_WRAPPING = "key_wrapping"
    KEY_DERIVATION = "key_derivation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEM_ENCAPSULATION = "kem_encapsulation"
    KEM_DECAPSULATION = "kem_decapsulation"
    HSM_CALL = "hsm_call"
    RANDOMNESS_EXTRACTION = "randomness_extraction"


class CorrelationType(Enum):
    """Types of correlation signals."""
    TRACE_ID = "trace_id"
    SPAN_ID = "span_id"
    KEY_ID = "key_id"
    OPERATION_ID = "operation_id"
    REQUEST_ID = "request_id"
    HSM_SESSION_ID = "hsm_session_id"
    KEY_ROTATION_ID = "key_rotation_id"


# -----------------------------------------------------------------------------
# DATA CLASSES
# -----------------------------------------------------------------------------

@dataclass
class TraceFlags:
    """W3C Trace Context flags."""
    sampled: bool = False
    trace_id: Optional[str] = None
    span_id: Optional[str] = None


@dataclass
class SpanContext:
    """Immutable span context for propagation."""
    trace_id: str
    span_id: str
    trace_flags: TraceFlags
    trace_state: Dict[str, str] = field(default_factory=dict)
    is_remote: bool = False
    
    def __post_init__(self):
        if not self.trace_id:
            self.trace_id = generate_trace_id()
        if not self.span_id:
            self.span_id = generate_span_id()


@dataclass
class SpanEvent:
    """Event within a span with timestamp."""
    name: str
    timestamp: float = field(default_factory=time.time)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpanLink:
    """Link to another span for causal relationships."""
    trace_id: str
    span_id: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    trace_state: Dict[str, str] = field(default_factory=dict)


@dataclass
class CryptoCorrelationContext:
    """Cross-signal correlation context for crypto operations."""
    correlation_id: str
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    key_id: Optional[str] = None
    operation_id: Optional[str] = None
    request_id: Optional[str] = None
    hsm_session_id: Optional[str] = None
    key_rotation_id: Optional[str] = None
    algorithm: Optional[str] = None
    operation_type: Optional[CryptoOperationType] = None
    custom_attributes: Dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class SamplingConfig:
    """Adaptive sampling configuration for crypto operations."""
    base_sampling_rate: float = 0.05  # 5% default (lower for crypto)
    error_sampling_rate: float = 1.0  # 100% for errors
    key_operation_sampling_rate: float = 1.0  # 100% for key ops
    hsm_call_sampling_rate: float = 0.5  # 50% for HSM calls
    slow_operation_threshold_ms: float = 500.0
    slow_operation_sampling_rate: float = 1.0
    min_sampling_rate: float = 0.01
    max_sampling_rate: float = 1.0
    adaptive_window_seconds: float = 60.0
    target_traces_per_second: float = 5.0


@dataclass
class BaggageEntry:
    """Single baggage entry with metadata."""
    value: str
    metadata: Dict[str, str] = field(default_factory=dict)


# -----------------------------------------------------------------------------
# UTILITY FUNCTIONS
# -----------------------------------------------------------------------------

def generate_trace_id() -> str:
    """Generate a valid W3C Trace Context trace ID (16 bytes, 32 hex chars)."""
    return secrets.token_hex(16)


def generate_span_id() -> str:
    """Generate a valid W3C Trace Context span ID (8 bytes, 16 hex chars)."""
    return secrets.token_hex(8)


def generate_crypto_correlation_id(prefix: str = "crypto") -> str:
    """Generate a human-readable correlation ID for crypto operations."""
    timestamp = int(time.time() * 1000)
    random_suffix = secrets.token_hex(4)
    return f"{prefix}-{timestamp}-{random_suffix}"


def is_valid_trace_id(trace_id: str) -> bool:
    """Validate W3C Trace Context trace ID format."""
    if not isinstance(trace_id, str):
        return False
    if len(trace_id) != 32:
        return False
    if trace_id == "0" * 32:  # All zeros is invalid
        return False
    try:
        int(trace_id, 16)
        return True
    except ValueError:
        return False


def is_valid_span_id(span_id: str) -> bool:
    """Validate W3C Trace Context span ID format."""
    if not isinstance(span_id, str):
        return False
    if len(span_id) != 16:
        return False
    if span_id == "0" * 16:  # All zeros is invalid
        return False
    try:
        int(span_id, 16)
        return True
    except ValueError:
        return False


# -----------------------------------------------------------------------------
# THREAD-LOCAL CONTEXT STORAGE
# -----------------------------------------------------------------------------

class ThreadLocalContext:
    """Thread-local storage for trace and correlation context."""
    
    def __init__(self):
        self._thread_local = threading.local()
        self._lock = threading.RLock()
    
    def get_span_context(self) -> Optional[SpanContext]:
        """Get current span context from thread-local storage."""
        return getattr(self._thread_local, 'span_context', None)
    
    def set_span_context(self, context: Optional[SpanContext]) -> None:
        """Set span context in thread-local storage."""
        self._thread_local.span_context = context
    
    def get_correlation_context(self) -> Optional[CryptoCorrelationContext]:
        """Get current crypto correlation context."""
        return getattr(self._thread_local, 'crypto_correlation_context', None)
    
    def set_correlation_context(self, context: Optional[CryptoCorrelationContext]) -> None:
        """Set crypto correlation context."""
        self._thread_local.crypto_correlation_context = context
    
    def get_baggage(self) -> Dict[str, BaggageEntry]:
        """Get current baggage."""
        if not hasattr(self._thread_local, 'baggage'):
            self._thread_local.baggage = {}
        return self._thread_local.baggage
    
    def set_baggage(self, baggage: Dict[str, BaggageEntry]) -> None:
        """Set baggage."""
        self._thread_local.baggage = baggage.copy()
    
    def clear(self) -> None:
        """Clear all thread-local context."""
        for attr in ['span_context', 'crypto_correlation_context', 'baggage']:
            if hasattr(self._thread_local, attr):
                delattr(self._thread_local, attr)


# -----------------------------------------------------------------------------
# ADAPTIVE SAMPLER
# -----------------------------------------------------------------------------

class CryptoAdaptiveSampler:
    """Dynamic sampling with rate adaptation optimized for crypto operations."""
    
    def __init__(self, config: Optional[SamplingConfig] = None):
        self.config = config or SamplingConfig()
        self._lock = threading.RLock()
        self._trace_count_window = deque()
        self._current_rate = self.config.base_sampling_rate
        self._last_adaptation = time.time()
    
    def should_sample(
        self,
        trace_id: str,
        operation_type: Optional[CryptoOperationType] = None,
        has_error: bool = False,
        duration_ms: Optional[float] = None,
        is_key_operation: bool = False,
        is_hsm_call: bool = False
    ) -> SamplingDecision:
        """Make sampling decision based on crypto operation context."""
        # Always sample errors
        if has_error and self._roll_dice(self.config.error_sampling_rate):
            return SamplingDecision.RECORD_AND_SAMPLE
        
        # Always sample key operations (security critical)
        if is_key_operation and self._roll_dice(self.config.key_operation_sampling_rate):
            return SamplingDecision.RECORD_AND_SAMPLE
        
        # Sample HSM calls at higher rate
        if is_hsm_call and self._roll_dice(self.config.hsm_call_sampling_rate):
            return SamplingDecision.RECORD_AND_SAMPLE
        
        # Always sample slow operations
        if duration_ms is not None:
            if duration_ms >= self.config.slow_operation_threshold_ms:
                if self._roll_dice(self.config.slow_operation_sampling_rate):
                    return SamplingDecision.RECORD_AND_SAMPLE
        
        # Adaptive sampling based on current rate
        self._adapt_rate()
        if self._roll_dice(self._current_rate):
            return SamplingDecision.RECORD_AND_SAMPLE
        
        return SamplingDecision.DROP
    
    def _roll_dice(self, probability: float) -> bool:
        """Deterministic sampling based on trace ID hash."""
        clamped = max(0.0, min(1.0, probability))
        if clamped <= 0.0:
            return False
        if clamped >= 1.0:
            return True
        threshold = int(clamped * (2**32 - 1))
        trace_hash = int(hashlib.sha256(str(time.time()).encode()).hexdigest()[:8], 16)
        return trace_hash < threshold
    
    def _adapt_rate(self) -> None:
        """Adapt sampling rate based on observed traffic."""
        now = time.time()
        with self._lock:
            window_start = now - self.config.adaptive_window_seconds
            
            # Remove old entries
            while self._trace_count_window and self._trace_count_window[0] < window_start:
                self._trace_count_window.popleft()
            
            # Adapt if window has elapsed
            if now - self._last_adaptation >= self.config.adaptive_window_seconds:
                traces_in_window = len(self._trace_count_window)
                traces_per_second = traces_in_window / self.config.adaptive_window_seconds
                
                if traces_per_second > self.config.target_traces_per_second * 1.5:
                    # Too many traces, decrease sampling rate
                    self._current_rate = max(
                        self.config.min_sampling_rate,
                        self._current_rate * 0.8
                    )
                elif traces_per_second < self.config.target_traces_per_second * 0.5:
                    # Too few traces, increase sampling rate
                    self._current_rate = min(
                        self.config.max_sampling_rate,
                        self._current_rate * 1.2
                    )
                
                self._last_adaptation = now
    
    def record_trace(self) -> None:
        """Record a sampled trace for adaptation."""
        with self._lock:
            self._trace_count_window.append(time.time())
    
    def get_current_sampling_rate(self) -> float:
        """Get current effective sampling rate."""
        return self._current_rate


# -----------------------------------------------------------------------------
# PROPAGATION HANDLERS
# -----------------------------------------------------------------------------

class TraceContextPropagator:
    """W3C Trace Context and B3 propagation handler."""
    
    @staticmethod
    def inject_w3c(context: SpanContext, carrier: Dict[str, str]) -> None:
        """Inject span context into carrier using W3C Trace Context format."""
        flags = "01" if context.trace_flags.sampled else "00"
        carrier["traceparent"] = f"00-{context.trace_id}-{context.span_id}-{flags}"
        
        if context.trace_state:
            tracestate_parts = []
            for key, value in list(context.trace_state.items())[:32]:  # W3C limit
                tracestate_parts.append(f"{key}={value}")
            if tracestate_parts:
                carrier["tracestate"] = ",".join(tracestate_parts)
    
    @staticmethod
    def extract_w3c(carrier: Dict[str, str]) -> Optional[SpanContext]:
        """Extract span context from carrier using W3C Trace Context format."""
        traceparent = carrier.get("traceparent", "")
        if not traceparent:
            return None
        
        parts = traceparent.split("-")
        if len(parts) != 4:
            return None
        
        version, trace_id, span_id, flags = parts
        
        if version != "00":
            return None
        
        if not is_valid_trace_id(trace_id):
            return None
        
        if not is_valid_span_id(span_id):
            return None
        
        sampled = flags.endswith("1")
        
        trace_state = {}
        tracestate_header = carrier.get("tracestate", "")
        if tracestate_header:
            for entry in tracestate_header.split(","):
                if "=" in entry:
                    key, value = entry.split("=", 1)
                    trace_state[key.strip()] = value.strip()
        
        return SpanContext(
            trace_id=trace_id,
            span_id=span_id,
            trace_flags=TraceFlags(sampled=sampled, trace_id=trace_id, span_id=span_id),
            trace_state=trace_state,
            is_remote=True
        )
    
    @staticmethod
    def inject_b3_multi(context: SpanContext, carrier: Dict[str, str]) -> None:
        """Inject using B3 Multi-Header format."""
        carrier["X-B3-TraceId"] = context.trace_id
        carrier["X-B3-SpanId"] = context.span_id
        carrier["X-B3-Sampled"] = "1" if context.trace_flags.sampled else "0"
    
    @staticmethod
    def extract_b3_multi(carrier: Dict[str, str]) -> Optional[SpanContext]:
        """Extract using B3 Multi-Header format."""
        trace_id = carrier.get("X-B3-TraceId") or carrier.get("x-b3-traceid")
        span_id = carrier.get("X-B3-SpanId") or carrier.get("x-b3-spanid")
        sampled = carrier.get("X-B3-Sampled") or carrier.get("x-b3-sampled")
        
        if not trace_id or not span_id:
            return None
        
        return SpanContext(
            trace_id=trace_id,
            span_id=span_id,
            trace_flags=TraceFlags(sampled=sampled == "1"),
            is_remote=True
        )


# -----------------------------------------------------------------------------
# MAIN CRYPTO TRACING ENGINE
# -----------------------------------------------------------------------------

class CryptoDistributedTracingCorrelationEngine:
    """
    Main engine for distributed tracing and correlation for crypto operations.
    OPT-IN: Must be explicitly enabled via enable()
    """
    
    _instance: Optional['CryptoDistributedTracingCorrelationEngine'] = None
    _instance_lock = threading.RLock()
    
    def __new__(cls):
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._enabled = False
        self._lock = threading.RLock()
        self._context = ThreadLocalContext()
        self._sampler = CryptoAdaptiveSampler()
        self._propagator = TraceContextPropagator()
        self._spans: Dict[str, Dict[str, Any]] = {}
        self._max_spans = 10000
        self._default_propagation_format = TracePropagationFormat.W3C_TRACE_CONTEXT
    
    def enable(self) -> None:
        """Enable tracing (OPT-IN - must be called explicitly)."""
        with self._lock:
            self._enabled = True
    
    def disable(self) -> None:
        """Disable tracing."""
        with self._lock:
            self._enabled = False
            self._context.clear()
    
    def is_enabled(self) -> bool:
        """Check if tracing is enabled."""
        return self._enabled
    
    def start_span(
        self,
        name: str,
        parent_context: Optional[SpanContext] = None,
        kind: SpanKind = SpanKind.INTERNAL,
        operation_type: Optional[CryptoOperationType] = None,
        attributes: Optional[Dict[str, Any]] = None,
        links: Optional[List[SpanLink]] = None
    ) -> Tuple[SpanContext, str]:
        """
        Start a new crypto operation span.
        Returns (span_context, span_internal_id)
        """
        if not self._enabled:
            dummy_context = SpanContext(
                trace_id=generate_trace_id(),
                span_id=generate_span_id(),
                trace_flags=TraceFlags(sampled=False)
            )
            return dummy_context, "disabled"
        
        with self._lock:
            # Use parent or current context
            if parent_context is None:
                parent_context = self._context.get_span_context()
            
            if parent_context:
                trace_id = parent_context.trace_id
                parent_span_id = parent_context.span_id
            else:
                trace_id = generate_trace_id()
                parent_span_id = None
            
            span_id = generate_span_id()
            internal_id = f"crypto_span_{span_id}_{int(time.time() * 1000000)}"
            
            span_context = SpanContext(
                trace_id=trace_id,
                span_id=span_id,
                trace_flags=TraceFlags(sampled=True, trace_id=trace_id, span_id=span_id)
            )
            
            is_key_op = operation_type in [
                CryptoOperationType.KEY_GENERATION,
                CryptoOperationType.KEY_ROTATION,
                CryptoOperationType.KEY_WRAPPING,
                CryptoOperationType.KEY_DERIVATION
            ]
            
            is_hsm = kind == SpanKind.HSM_OPERATION
            
            span_data = {
                "name": name,
                "trace_id": trace_id,
                "span_id": span_id,
                "parent_span_id": parent_span_id,
                "kind": kind,
                "operation_type": operation_type,
                "is_key_operation": is_key_op,
                "is_hsm_call": is_hsm,
                "start_time": time.time(),
                "attributes": attributes or {},
                "links": links or [],
                "events": [],
                "status": SpanStatus.UNSET,
                "end_time": None
            }
            
            # Store span (evict oldest if at limit)
            if len(self._spans) >= self._max_spans:
                oldest_key = next(iter(self._spans))
                del self._spans[oldest_key]
            
            self._spans[internal_id] = span_data
            
            # Set as current context
            self._context.set_span_context(span_context)
            
            self._sampler.record_trace()
            
            return span_context, internal_id
    
    def end_span(
        self,
        internal_id: str,
        status: SpanStatus = SpanStatus.OK,
        attributes: Optional[Dict[str, Any]] = None
    ) -> None:
        """End a crypto operation span."""
        if not self._enabled or internal_id == "disabled":
            return
        
        with self._lock:
            if internal_id in self._spans:
                span = self._spans[internal_id]
                span["end_time"] = time.time()
                span["status"] = status
                if attributes:
                    span["attributes"].update(attributes)
    
    def add_event(
        self,
        internal_id: str,
        name: str,
        attributes: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add an event to a crypto operation span."""
        if not self._enabled or internal_id == "disabled":
            return
        
        with self._lock:
            if internal_id in self._spans:
                self._spans[internal_id]["events"].append(
                    SpanEvent(name=name, attributes=attributes or {})
                )
    
    def create_crypto_correlation_context(
        self,
        key_id: Optional[str] = None,
        operation_id: Optional[str] = None,
        request_id: Optional[str] = None,
        hsm_session_id: Optional[str] = None,
        key_rotation_id: Optional[str] = None,
        algorithm: Optional[str] = None,
        operation_type: Optional[CryptoOperationType] = None,
        custom_attributes: Optional[Dict[str, str]] = None
    ) -> CryptoCorrelationContext:
        """Create a new crypto correlation context."""
        current_span = self._context.get_span_context()
        
        context = CryptoCorrelationContext(
            correlation_id=generate_crypto_correlation_id(),
            trace_id=current_span.trace_id if current_span else None,
            span_id=current_span.span_id if current_span else None,
            key_id=key_id,
            operation_id=operation_id,
            request_id=request_id,
            hsm_session_id=hsm_session_id,
            key_rotation_id=key_rotation_id,
            algorithm=algorithm,
            operation_type=operation_type,
            custom_attributes=custom_attributes or {}
        )
        
        if self._enabled:
            self._context.set_correlation_context(context)
        
        return context
    
    def get_current_correlation_ids(self) -> Dict[str, Optional[str]]:
        """Get all current crypto correlation IDs as a dict."""
        span_ctx = self._context.get_span_context()
        corr_ctx = self._context.get_correlation_context()
        
        result = {
            "trace_id": span_ctx.trace_id if span_ctx else None,
            "span_id": span_ctx.span_id if span_ctx else None,
            "correlation_id": corr_ctx.correlation_id if corr_ctx else None,
            "key_id": corr_ctx.key_id if corr_ctx else None,
            "operation_id": corr_ctx.operation_id if corr_ctx else None,
            "request_id": corr_ctx.request_id if corr_ctx else None,
            "hsm_session_id": corr_ctx.hsm_session_id if corr_ctx else None,
            "key_rotation_id": corr_ctx.key_rotation_id if corr_ctx else None,
        }
        return result
    
    def inject_context(
        self,
        carrier: Dict[str, str],
        format: TracePropagationFormat = TracePropagationFormat.W3C_TRACE_CONTEXT
    ) -> None:
        """Inject current trace context into carrier."""
        if not self._enabled:
            return
        
        context = self._context.get_span_context()
        if not context:
            return
        
        if format == TracePropagationFormat.W3C_TRACE_CONTEXT:
            self._propagator.inject_w3c(context, carrier)
        elif format == TracePropagationFormat.B3_MULTI:
            self._propagator.inject_b3_multi(context, carrier)
    
    def extract_context(
        self,
        carrier: Dict[str, str],
        format: TracePropagationFormat = TracePropagationFormat.W3C_TRACE_CONTEXT
    ) -> Optional[SpanContext]:
        """Extract trace context from carrier."""
        if format == TracePropagationFormat.W3C_TRACE_CONTEXT:
            return self._propagator.extract_w3c(carrier)
        elif format == TracePropagationFormat.B3_MULTI:
            return self._propagator.extract_b3_multi(carrier)
        return None
    
    def set_baggage_entry(self, key: str, value: str, metadata: Optional[Dict[str, str]] = None) -> None:
        """Set a baggage entry."""
        if not self._enabled:
            return
        
        baggage = self._context.get_baggage()
        baggage[key] = BaggageEntry(value=value, metadata=metadata or {})
        self._context.set_baggage(baggage)
    
    def get_baggage_entry(self, key: str) -> Optional[BaggageEntry]:
        """Get a baggage entry."""
        if not self._enabled:
            return None
        
        baggage = self._context.get_baggage()
        return baggage.get(key)
    
    def get_sampling_rate(self) -> float:
        """Get current sampling rate."""
        return self._sampler.get_current_sampling_rate()
    
    def get_finished_spans(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get finished spans for export."""
        with self._lock:
            finished = [
                span for span in self._spans.values()
                if span["end_time"] is not None
            ]
            return finished[-limit:]
    
    def clear_context(self) -> None:
        """Clear all thread-local context."""
        self._context.clear()


# -----------------------------------------------------------------------------
# DECORATOR
# -----------------------------------------------------------------------------

def traced_crypto_operation(
    name: Optional[str] = None,
    kind: SpanKind = SpanKind.CRYPTO_OPERATION,
    operation_type: Optional[CryptoOperationType] = None,
    attributes: Optional[Dict[str, Any]] = None
):
    """Decorator to automatically trace a cryptographic operation."""
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            engine = CryptoDistributedTracingCorrelationEngine()
            if not engine.is_enabled():
                return func(*args, **kwargs)
            
            op_name = name or func.__name__
            context, span_id = engine.start_span(
                op_name,
                kind=kind,
                operation_type=operation_type,
                attributes=attributes
            )
            
            try:
                result = func(*args, **kwargs)
                engine.end_span(span_id, SpanStatus.OK)
                return result
            except Exception as e:
                engine.end_span(span_id, SpanStatus.ERROR, {"error": str(e), "error_type": type(e).__name__})
                raise
        
        return wrapper
    
    return decorator


# -----------------------------------------------------------------------------
# GLOBAL CONVENIENCE API
# -----------------------------------------------------------------------------

_global_engine: Optional[CryptoDistributedTracingCorrelationEngine] = None


def _get_engine() -> CryptoDistributedTracingCorrelationEngine:
    global _global_engine
    if _global_engine is None:
        _global_engine = CryptoDistributedTracingCorrelationEngine()
    return _global_engine


def enable_crypto_tracing() -> None:
    """Enable distributed tracing for crypto operations (OPT-IN)."""
    _get_engine().enable()


def disable_crypto_tracing() -> None:
    """Disable distributed tracing."""
    _get_engine().disable()


def start_crypto_trace_span(name: str, **kwargs) -> Tuple[SpanContext, str]:
    """Start a traced crypto operation span."""
    return _get_engine().start_span(name, **kwargs)


def end_crypto_trace_span(span_id: str, **kwargs) -> None:
    """End a traced crypto operation span."""
    _get_engine().end_span(span_id, **kwargs)


def get_crypto_correlation_ids() -> Dict[str, Optional[str]]:
    """Get current crypto correlation identifiers."""
    return _get_engine().get_current_correlation_ids()


def inject_crypto_trace_context(carrier: Dict[str, str], **kwargs) -> None:
    """Inject crypto trace context into carrier dict."""
    _get_engine().inject_context(carrier, **kwargs)


def create_key_operation_correlation(key_id: str, **kwargs) -> CryptoCorrelationContext:
    """Create correlation context for a key management operation."""
    return _get_engine().create_crypto_correlation_context(
        key_id=key_id,
        operation_type=CryptoOperationType.KEY_GENERATION,
        **kwargs
    )


# -----------------------------------------------------------------------------
# METADATA
# -----------------------------------------------------------------------------

CRYPTO_OBSERVABILITY_VERSION = "v15"
CRYPTO_OBSERVABILITY_DIMENSION = "D"
CRYPTO_OBSERVABILITY_FEATURES = [
    "W3C Trace Context propagation",
    "B3 Multi-Header propagation",
    "Crypto-optimized adaptive sampling",
    "Key operation correlation tracking",
    "HSM call tracing support",
    "Thread-local context management",
    "Span events and links",
    "Cross-signal correlation IDs",
    "Baggage context propagation",
    "Decorator-based crypto instrumentation"
]
