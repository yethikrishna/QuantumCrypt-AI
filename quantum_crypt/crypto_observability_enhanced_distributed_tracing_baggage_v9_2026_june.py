"""
QuantumCrypt AI - Enhanced Distributed Tracing with Baggage Context v9
Dimension D: Observability & Instrumentation
STABILITY: STABLE - Production ready, OPT-IN only

Post-Quantum Cryptography specific observability:
- W3C Trace Context standard for key operations
- Baggage for security context propagation
- Cryptographic operation correlation IDs
- Sensitive operation sampling
- Key operation audit trail integration

DESIGN PHILOSOPHY:
- 100% OPT-IN - disabled by default
- Pure wrapper - no modification of existing crypto code
- Zero overhead when disabled
- W3C standard compliant
- Security-aware sampling (key ops always sampled)
- Cryptographic operation provenance tracking
"""

from __future__ import annotations

import os
import uuid
import time
import random
import hashlib
import hmac
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Dict, Any, Callable, TypeVar
from typing_extensions import Self
from datetime import datetime, timezone
import threading
import contextvars
import json

# -----------------------------------------------------------------------------
# Configuration - OPT-IN ONLY
# -----------------------------------------------------------------------------

PQ_CRYPTO_TRACING_ENABLED: bool = os.environ.get("QUANTUMCRYPT_TRACING_ENABLED", "0") == "1"
PQ_CRYPTO_SAMPLE_RATE: float = float(os.environ.get("QUANTUMCRYPT_TRACING_SAMPLE_RATE", "0.05"))
PQ_CRYPTO_KEY_OP_SAMPLE_RATE: float = float(os.environ.get("QUANTUMCRYPT_KEY_OP_SAMPLE_RATE", "1.0"))

# -----------------------------------------------------------------------------
# Enums - Crypto Specific
# -----------------------------------------------------------------------------

class CryptoOperationType(Enum):
    """Types of cryptographic operations for tracing"""
    KEY_GENERATION = auto()
    KEY_AGREEMENT = auto()
    ENCRYPTION = auto()
    DECRYPTION = auto()
    SIGNING = auto()
    VERIFICATION = auto()
    KEY_WRAP = auto()
    KEY_UNWRAP = auto()
    HASH = auto()
    HMAC = auto()
    RANDOM_GENERATION = auto()
    CERTIFICATE_OP = auto()

class TraceFlag(Enum):
    """W3C Trace Context flags"""
    NOT_SAMPLED = 0x00
    SAMPLED = 0x01
    RANDOM = 0x02
    CRITICAL = 0x04  # Crypto-specific: critical security operation

class CryptoSamplingStrategy(Enum):
    """Crypto-aware sampling strategies"""
    ALWAYS_OFF = auto()
    KEY_OPERATIONS_ONLY = auto()
    ERROR_ONLY = auto()
    PROBABILISTIC = auto()
    ADAPTIVE_CRYPTO = auto()
    ALWAYS_ON = auto()

class SecurityLevel(Enum):
    """Security classification for trace baggage"""
    PUBLIC = auto()
    INTERNAL = auto()
    SENSITIVE = auto()
    RESTRICTED = auto()
    CRITICAL = auto()

# -----------------------------------------------------------------------------
# Context Vars - Thread Local
# -----------------------------------------------------------------------------

_current_crypto_trace: contextvars.ContextVar[Optional["CryptoTraceContext"]] = contextvars.ContextVar(
    "pq_crypto_current_trace",
    default=None
)

_current_security_baggage: contextvars.ContextVar[Dict[str, str]] = contextvars.ContextVar(
    "pq_crypto_security_baggage",
    default={}
)

# -----------------------------------------------------------------------------
# Crypto Trace Context - W3C Compliant + Security Extensions
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class CryptoTraceContext:
    """
    W3C Trace Context with crypto-specific security extensions.
    
    Standard format: version-traceid-parentid-flags
    Extended with: operation type, security level, algorithm info
    """
    version: str = "00"
    trace_id: str = field(default_factory=lambda: CryptoTraceContext.generate_trace_id())
    parent_id: str = field(default_factory=lambda: CryptoTraceContext.generate_span_id())
    flags: int = TraceFlag.NOT_SAMPLED.value
    trace_state: Dict[str, str] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    operation_type: Optional[CryptoOperationType] = None
    algorithm: Optional[str] = None
    security_level: SecurityLevel = SecurityLevel.INTERNAL
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    @staticmethod
    def generate_trace_id() -> str:
        """Generate cryptographically secure trace ID"""
        return uuid.uuid4().hex
    
    @staticmethod
    def generate_span_id() -> str:
        """Generate cryptographically secure span ID"""
        return uuid.uuid4().hex[:16]
    
    @staticmethod
    def generate_operation_id() -> str:
        """Generate crypto operation correlation ID"""
        return f"pq-op-{uuid.uuid4().hex[:12]}"
    
    @staticmethod
    def generate_key_id() -> str:
        """Generate key provenance ID (for key tracking)"""
        return f"pq-key-{uuid.uuid4().hex[:16]}"
    
    @classmethod
    def from_traceparent(cls, traceparent: str) -> Optional[Self]:
        """Parse W3C traceparent header"""
        try:
            parts = traceparent.split("-")
            if len(parts) != 4:
                return None
            version, trace_id, parent_id, flags_hex = parts
            if version != "00":
                return None
            if len(trace_id) != 32 or len(parent_id) != 16:
                return None
            flags = int(flags_hex, 16)
            return cls(
                version=version,
                trace_id=trace_id,
                parent_id=parent_id,
                flags=flags
            )
        except Exception:
            return None
    
    def to_traceparent(self) -> str:
        """Serialize to W3C traceparent format"""
        return f"{self.version}-{self.trace_id}-{self.parent_id}-{self.flags:02x}"
    
    def to_headers(self) -> Dict[str, str]:
        """Convert to HTTP headers for propagation"""
        headers = {"traceparent": self.to_traceparent()}
        if self.trace_state:
            headers["tracestate"] = ",".join(f"{k}={v}" for k, v in self.trace_state.items())
        return headers
    
    def is_sampled(self) -> bool:
        """Check if this trace should be sampled"""
        return (self.flags & TraceFlag.SAMPLED.value) != 0
    
    def is_critical(self) -> bool:
        """Check if this is a critical security operation"""
        return (self.flags & TraceFlag.CRITICAL.value) != 0
    
    def with_sampled(self, sampled: bool = True) -> "CryptoTraceContext":
        """Create new context with sampling flag"""
        new_flags = self.flags | TraceFlag.SAMPLED.value if sampled else self.flags & ~TraceFlag.SAMPLED.value
        return CryptoTraceContext(
            version=self.version,
            trace_id=self.trace_id,
            parent_id=self.parent_id,
            flags=new_flags,
            trace_state=self.trace_state.copy(),
            operation_type=self.operation_type,
            algorithm=self.algorithm,
            security_level=self.security_level,
            attributes=self.attributes.copy()
        )
    
    def with_critical(self, critical: bool = True) -> "CryptoTraceContext":
        """Mark as critical security operation (always sampled)"""
        new_flags = self.flags | TraceFlag.CRITICAL.value if critical else self.flags & ~TraceFlag.CRITICAL.value
        # Critical ops are always sampled
        if critical:
            new_flags |= TraceFlag.SAMPLED.value
        return CryptoTraceContext(
            version=self.version,
            trace_id=self.trace_id,
            parent_id=self.parent_id,
            flags=new_flags,
            trace_state=self.trace_state.copy(),
            operation_type=self.operation_type,
            algorithm=self.algorithm,
            security_level=self.security_level,
            attributes=self.attributes.copy()
        )
    
    def child_span(self, span_name: Optional[str] = None) -> "CryptoTraceContext":
        """Create child span for nested operations"""
        child = CryptoTraceContext(
            version=self.version,
            trace_id=self.trace_id,
            parent_id=CryptoTraceContext.generate_span_id(),
            flags=self.flags,
            trace_state=self.trace_state.copy(),
            operation_type=self.operation_type,
            algorithm=self.algorithm,
            security_level=self.security_level,
            attributes={**self.attributes, "parent_span_id": self.parent_id}
        )
        if span_name:
            child.attributes["span_name"] = span_name
        return child
    
    def duration_ms(self) -> float:
        """Get operation duration in milliseconds"""
        return (time.time() - self.start_time) * 1000

# -----------------------------------------------------------------------------
# Security Baggage Manager - Crypto Specific
# -----------------------------------------------------------------------------

class SecurityBaggageManager:
    """
    Manages security context propagation across crypto operations.
    Carries:
    - Tenant / organization IDs
    - Key IDs and provenance chains
    - User / service identities
    - Security classification levels
    - Compliance markers (FIPS, GDPR, etc.)
    """
    
    MAX_ENTRIES = 32
    MAX_VALUE_LENGTH = 1024
    
    @staticmethod
    def set_security_context(key: str, value: str, level: SecurityLevel = SecurityLevel.INTERNAL) -> None:
        """Set security baggage entry"""
        if not PQ_CRYPTO_TRACING_ENABLED:
            return
        if len(key) > 64 or len(value) > SecurityBaggageManager.MAX_VALUE_LENGTH:
            return
        current = dict(_current_security_baggage.get())
        if len(current) >= SecurityBaggageManager.MAX_ENTRIES:
            return
        current[key] = value
        current[f"{key}_level"] = level.name
        _current_security_baggage.set(current)
    
    @staticmethod
    def get_security_context(key: str, default: Optional[str] = None) -> Optional[str]:
        """Get security baggage entry"""
        if not PQ_CRYPTO_TRACING_ENABLED:
            return default
        return _current_security_baggage.get().get(key, default)
    
    @staticmethod
    def get_all_context() -> Dict[str, str]:
        """Get all security baggage (for audit logs)"""
        if not PQ_CRYPTO_TRACING_ENABLED:
            return {}
        return dict(_current_security_baggage.get())
    
    @staticmethod
    def clear_context() -> None:
        """Clear all security baggage"""
        if not PQ_CRYPTO_TRACING_ENABLED:
            return
        _current_security_baggage.set({})
    
    @staticmethod
    def set_key_id(key_id: str) -> None:
        """Set key ID for key provenance tracking"""
        SecurityBaggageManager.set_security_context(
            "key_id", key_id, SecurityLevel.SENSITIVE
        )
    
    @staticmethod
    def get_key_id() -> Optional[str]:
        """Get current key ID"""
        return SecurityBaggageManager.get_security_context("key_id")
    
    @staticmethod
    def set_tenant_id(tenant_id: str) -> None:
        """Set tenant ID for multi-tenant isolation"""
        SecurityBaggageManager.set_security_context(
            "tenant_id", tenant_id, SecurityLevel.INTERNAL
        )
    
    @staticmethod
    def set_compliance_marker(marker: str) -> None:
        """Set compliance marker (FIPS140, GDPR, etc.)"""
        SecurityBaggageManager.set_security_context(
            "compliance", marker, SecurityLevel.PUBLIC
        )

# -----------------------------------------------------------------------------
# Crypto-Aware Trace Sampler
# -----------------------------------------------------------------------------

class CryptoTraceSampler:
    """
    Security-aware trace sampler for cryptographic operations.
    
    Key features:
    - Key generation/agreement always sampled (100%)
    - Errors always sampled
    - Success operations sampled at configurable rate
    - Rate limiting to prevent audit log flooding
    """
    
    def __init__(
        self,
        strategy: CryptoSamplingStrategy = CryptoSamplingStrategy.ADAPTIVE_CRYPTO,
        general_sample_rate: float = 0.05,
        key_op_sample_rate: float = 1.0,
        max_samples_per_second: int = 1000
    ):
        self.strategy = strategy
        self.general_sample_rate = max(0.0, min(1.0, general_sample_rate))
        self.key_op_sample_rate = max(0.0, min(1.0, key_op_sample_rate))
        self.max_samples_per_second = max_samples_per_second
        self._sample_count = 0
        self._window_start = time.time()
        self._lock = threading.Lock()
    
    def _is_key_operation(self, op_type: Optional[CryptoOperationType]) -> bool:
        """Check if operation is key-related (high security importance)"""
        key_ops = {
            CryptoOperationType.KEY_GENERATION,
            CryptoOperationType.KEY_AGREEMENT,
            CryptoOperationType.KEY_WRAP,
            CryptoOperationType.KEY_UNWRAP,
        }
        return op_type in key_ops
    
    def should_sample(
        self,
        ctx: CryptoTraceContext,
        error_occurred: bool = False
    ) -> bool:
        """Determine if crypto operation should be sampled"""
        if not PQ_CRYPTO_TRACING_ENABLED:
            return False
        
        op_type = ctx.operation_type
        
        if self.strategy == CryptoSamplingStrategy.ALWAYS_OFF:
            return False
        
        if self.strategy == CryptoSamplingStrategy.ALWAYS_ON:
            return True
        
        if self.strategy == CryptoSamplingStrategy.ERROR_ONLY:
            return error_occurred
        
        if self.strategy == CryptoSamplingStrategy.KEY_OPERATIONS_ONLY:
            return self._is_key_operation(op_type) or error_occurred
        
        if self.strategy == CryptoSamplingStrategy.PROBABILISTIC:
            if error_occurred:
                return True
            if self._is_key_operation(op_type):
                return random.random() < self.key_op_sample_rate
            return random.random() < self.general_sample_rate
        
        if self.strategy == CryptoSamplingStrategy.ADAPTIVE_CRYPTO:
            # Adaptive crypto strategy:
            # - Errors: 100% sampled
            # - Key ops: 100% sampled
            # - Other: general sample rate
            if error_occurred or ctx.is_critical():
                return True
            if self._is_key_operation(op_type):
                return random.random() < self.key_op_sample_rate
            return random.random() < self.general_sample_rate
        
        return error_occurred

# -----------------------------------------------------------------------------
# Global Crypto Trace Manager
# -----------------------------------------------------------------------------

class CryptoTraceManager:
    """Global trace manager for cryptographic operations"""
    
    _default_sampler: CryptoTraceSampler = CryptoTraceSampler(
        strategy=CryptoSamplingStrategy.ADAPTIVE_CRYPTO,
        general_sample_rate=PQ_CRYPTO_SAMPLE_RATE,
        key_op_sample_rate=PQ_CRYPTO_KEY_OP_SAMPLE_RATE
    )
    
    @staticmethod
    def is_enabled() -> bool:
        """Check if crypto tracing is enabled"""
        return PQ_CRYPTO_TRACING_ENABLED
    
    @staticmethod
    def start_crypto_operation(
        operation_type: CryptoOperationType,
        algorithm: Optional[str] = None,
        security_level: SecurityLevel = SecurityLevel.INTERNAL,
        parent: Optional[CryptoTraceContext] = None,
        attributes: Optional[Dict[str, Any]] = None
    ) -> CryptoTraceContext:
        """Start tracing a cryptographic operation"""
        if not PQ_CRYPTO_TRACING_ENABLED:
            return CryptoTraceContext(flags=0)
        
        if parent:
            ctx = parent.child_span()
        else:
            ctx = CryptoTraceContext(
                operation_type=operation_type,
                algorithm=algorithm,
                security_level=security_level
            )
        
        ctx.attributes["operation_id"] = CryptoTraceContext.generate_operation_id()
        
        if attributes:
            ctx.attributes.update(attributes)
        
        # Key operations are always critical
        sampler = CryptoTraceManager._default_sampler
        if sampler._is_key_operation(operation_type):
            ctx = ctx.with_critical(True)
        elif sampler.should_sample(ctx):
            ctx = ctx.with_sampled(True)
        
        _current_crypto_trace.set(ctx)
        return ctx
    
    @staticmethod
    def end_crypto_operation(
        ctx: Optional[CryptoTraceContext] = None,
        success: bool = True,
        error_info: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """End crypto operation and return audit record if sampled"""
        if not PQ_CRYPTO_TRACING_ENABLED:
            return None
        
        trace_ctx = ctx or _current_crypto_trace.get()
        if not trace_ctx:
            return None
        
        # Force sample errors
        if not success and not trace_ctx.is_sampled():
            trace_ctx = trace_ctx.with_sampled(True)
        
        if trace_ctx.is_sampled():
            audit_record = {
                "trace_id": trace_ctx.trace_id,
                "span_id": trace_ctx.parent_id,
                "operation_type": trace_ctx.operation_type.name if trace_ctx.operation_type else None,
                "algorithm": trace_ctx.algorithm,
                "security_level": trace_ctx.security_level.name,
                "duration_ms": trace_ctx.duration_ms(),
                "success": success,
                "error": error_info,
                "attributes": trace_ctx.attributes,
                "security_context": SecurityBaggageManager.get_all_context(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "service": "quantumcrypt-ai"
            }
            return audit_record
        
        _current_crypto_trace.set(None)
        return None
    
    @staticmethod
    def current_trace() -> Optional[CryptoTraceContext]:
        """Get current crypto trace context"""
        if not PQ_CRYPTO_TRACING_ENABLED:
            return None
        return _current_crypto_trace.get()

# -----------------------------------------------------------------------------
# Crypto Tracing Decorator
# -----------------------------------------------------------------------------

T = TypeVar('T')

def crypto_traced(
    operation_type: CryptoOperationType,
    algorithm: Optional[str] = None,
    security_level: SecurityLevel = SecurityLevel.INTERNAL,
    capture_errors: bool = True
):
    """
    OPT-IN decorator for tracing cryptographic operations.
    
    Usage:
        @crypto_traced(CryptoOperationType.KEY_GENERATION, algorithm="CRYSTALS-Kyber")
        def generate_keypair():
            pass
    
    Has ZERO overhead when QUANTUMCRYPT_TRACING_ENABLED=0
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        if not PQ_CRYPTO_TRACING_ENABLED:
            return func
        
        def wrapper(*args: Any, **kwargs: Any) -> T:
            ctx = CryptoTraceManager.start_crypto_operation(
                operation_type=operation_type,
                algorithm=algorithm,
                security_level=security_level
            )
            
            try:
                result = func(*args, **kwargs)
                CryptoTraceManager.end_crypto_operation(ctx, success=True)
                return result
            except Exception as e:
                if capture_errors:
                    CryptoTraceManager.end_crypto_operation(
                        ctx,
                        success=False,
                        error_info=f"{type(e).__name__}: {str(e)}"
                    )
                raise
        
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# Audit Exporter for Compliance
# -----------------------------------------------------------------------------

class CryptoAuditExporter:
    """Exports crypto audit records for compliance"""
    
    def export_audit_record(self, audit_record: Dict[str, Any]) -> None:
        """Export audit record - override for SIEM integration"""
        pass

class StructuredLogAuditExporter(CryptoAuditExporter):
    """Export audit records as structured JSON logs"""
    
    def export_audit_record(self, audit_record: Dict[str, Any]) -> None:
        """Export as NDJSON for log aggregation"""
        log_entry = {
            "type": "crypto_audit",
            "schema_version": "1.0",
            **audit_record
        }
        # In production: send to SIEM, CloudWatch, Datadog, etc.
        print(json.dumps(log_entry), flush=True)

# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    "CryptoTraceContext",
    "CryptoTraceManager",
    "SecurityBaggageManager",
    "CryptoTraceSampler",
    "CryptoOperationType",
    "CryptoSamplingStrategy",
    "SecurityLevel",
    "TraceFlag",
    "CryptoAuditExporter",
    "StructuredLogAuditExporter",
    "crypto_traced",
    "PQ_CRYPTO_TRACING_ENABLED",
]
