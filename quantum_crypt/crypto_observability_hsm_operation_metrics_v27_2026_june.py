"""
QuantumCrypt AI - HSM Operation Observability with Metrics v27
DIMENSION D: Observability & Instrumentation

ADD-ONLY implementation - wraps existing code, no core modifications.
All instrumentation is OPT-IN, disabled by default.
Preserves 100% backward compatibility.

Features added in v27:
- HSM (Hardware Security Module) operation metrics tracking
- Post-quantum crypto operation latency percentiles
- Key operation lifecycle tracing with baggage propagation
- Crypto primitive usage counters and health metrics
- FIPS 140-3 compliance event logging
- Randomness quality monitoring
"""

import time
import uuid
import threading
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import json


class CryptoOperationType(Enum):
    """Types of cryptographic operations for tracing."""
    KEY_GENERATION = "key_generation"
    KEY_ENCAPSULATION = "key_encapsulation"
    KEY_DECAPSULATION = "key_decapsulation"
    SIGNATURE_GENERATION = "signature_generation"
    SIGNATURE_VERIFICATION = "signature_verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    HASH_COMPUTATION = "hash_computation"
    RANDOM_GENERATION = "random_generation"
    KEY_AGREEMENT = "key_agreement"
    BATCH_VERIFICATION = "batch_verification"


class HSMStatus(Enum):
    """HSM operational status."""
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"


class ComplianceLevel(Enum):
    """FIPS compliance levels."""
    FIPS_140_2_LEVEL_1 = "fips_140_2_level_1"
    FIPS_140_2_LEVEL_2 = "fips_140_2_level_2"
    FIPS_140_2_LEVEL_3 = "fips_140_2_level_3"
    FIPS_140_3_LEVEL_1 = "fips_140_3_level_1"
    FIPS_140_3_LEVEL_2 = "fips_140_3_level_2"
    FIPS_140_3_LEVEL_3 = "fips_140_3_level_3"
    FIPS_140_3_LEVEL_4 = "fips_140_3_level_4"


@dataclass
class CryptoSpanContext:
    """Context for crypto operation tracing span."""
    trace_id: str
    span_id: str
    operation_type: str
    parent_span_id: Optional[str] = None
    baggage: Dict[str, Any] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    compliance_events: List[Dict[str, Any]] = field(default_factory=list)
    key_id: Optional[str] = None
    algorithm: Optional[str] = None
    key_size: Optional[int] = None


@dataclass
class CryptoHealthMetrics:
    """Health metrics for crypto operations."""
    operation_success_rate: float = 1.0
    average_latency_ms: float = 0.0
    error_count: int = 0
    timeout_count: int = 0
    hsm_utilization: float = 0.0
    entropy_quality_score: float = 1.0
    last_health_check: float = 0.0


@dataclass
class RandomnessQualityMetrics:
    """Metrics for random number generation quality."""
    sample_count: int = 0
    chi_square_score: float = 0.0
    entropy_bits_per_byte: float = 0.0
    runs_test_passed: bool = True
    longest_run_score: float = 0.0


class ThreadLocalCryptoContext:
    """Thread-local storage for crypto trace context."""
    _local = threading.local()

    @classmethod
    def get_current_span(cls) -> Optional[CryptoSpanContext]:
        return getattr(cls._local, 'current_crypto_span', None)

    @classmethod
    def set_current_span(cls, span: Optional[CryptoSpanContext]):
        cls._local.current_crypto_span = span


class HSMOperationObserver:
    """
    HSM operation observer with metrics and tracing.
    
    OPT-IN instrumentation - must be explicitly enabled.
    Wraps existing crypto modules without modification.
    """

    def __init__(
        self,
        service_name: str = "quantumcrypt-ai",
        hsm_model: str = "virtual-hsm",
        compliance_level: ComplianceLevel = ComplianceLevel.FIPS_140_3_LEVEL_3,
        enabled: bool = False,
    ):
        self.service_name = service_name
        self.hsm_model = hsm_model
        self.compliance_level = compliance_level
        self.enabled = enabled
        self.hsm_status = HSMStatus.ONLINE
        
        # Tracing storage
        self._spans: Dict[str, CryptoSpanContext] = {}
        self._traces: Dict[str, List[CryptoSpanContext]] = defaultdict(list)
        
        # Metrics storage
        self._operation_latencies: Dict[str, List[float]] = defaultdict(list)
        self._operation_counters: Dict[str, int] = defaultdict(int)
        self._error_counters: Dict[str, int] = defaultdict(int)
        self._algorithm_usage: Dict[str, int] = defaultdict(int)
        
        # Health monitoring
        self._health_history: deque = deque(maxlen=1000)
        self._randomness_samples: deque = deque(maxlen=10000)
        
        # Compliance audit log
        self._compliance_log: List[Dict[str, Any]] = []
        
        self._lock = threading.Lock()

    def generate_trace_id(self) -> str:
        """Generate a unique trace ID."""
        return str(uuid.uuid4())

    def generate_span_id(self) -> str:
        """Generate a unique span ID."""
        return str(uuid.uuid4())[:16]

    def start_crypto_span(
        self,
        operation_type: CryptoOperationType,
        algorithm: Optional[str] = None,
        key_id: Optional[str] = None,
        key_size: Optional[int] = None,
        trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        baggage: Optional[Dict[str, Any]] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Optional[CryptoSpanContext]:
        """
        Start a new crypto operation span.
        
        Returns None if instrumentation is disabled - safe for no-op calls.
        """
        if not self.enabled:
            return None

        span = CryptoSpanContext(
            trace_id=trace_id or self.generate_trace_id(),
            span_id=self.generate_span_id(),
            operation_type=operation_type.value,
            parent_span_id=parent_span_id,
            baggage=baggage or {},
            attributes=attributes or {},
            algorithm=algorithm,
            key_id=key_id,
            key_size=key_size,
            start_time=time.time(),
        )

        with self._lock:
            self._spans[span.span_id] = span
            self._traces[span.trace_id].append(span)
            self._operation_counters[operation_type.value] += 1
            if algorithm:
                self._algorithm_usage[algorithm] += 1

        ThreadLocalCryptoContext.set_current_span(span)
        return span

    def end_crypto_span(
        self,
        span: Optional[CryptoSpanContext],
        success: bool = True,
        error_type: Optional[str] = None,
    ) -> None:
        """End a crypto operation span."""
        if not self.enabled or span is None:
            return

        span.end_time = time.time()
        duration_ms = (span.end_time - span.start_time) * 1000

        with self._lock:
            self._operation_latencies[span.operation_type].append(duration_ms)
            
            if not success:
                self._error_counters[span.operation_type] += 1
                span.attributes["error"] = error_type or "unknown_error"

        ThreadLocalCryptoContext.set_current_span(None)

    def add_compliance_event(
        self,
        span: Optional[CryptoSpanContext],
        event_type: str,
        compliance_level: ComplianceLevel,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Add a FIPS compliance event to the trace.
        
        Thread-safe, no-op if disabled.
        """
        if not self.enabled or span is None:
            return

        event = {
            "event_type": event_type,
            "compliance_level": compliance_level.value,
            "timestamp": time.time(),
            "details": details or {},
            "hsm_model": self.hsm_model,
        }

        with self._lock:
            span.compliance_events.append(event)
            self._compliance_log.append(event)

    def propagate_baggage(
        self,
        span: Optional[CryptoSpanContext],
        key: str,
        value: Any,
    ) -> None:
        """Propagate baggage across crypto operation boundaries."""
        if not self.enabled or span is None:
            return

        with self._lock:
            span.baggage[key] = value

    def get_baggage(self, span: Optional[CryptoSpanContext], key: str) -> Optional[Any]:
        """Get baggage value from span context."""
        if not self.enabled or span is None:
            return None
        return span.baggage.get(key)

    def record_randomness_sample(self, random_bytes: bytes) -> None:
        """Record random bytes sample for quality monitoring."""
        if not self.enabled:
            return

        with self._lock:
            self._randomness_samples.append(random_bytes)

    def calculate_latency_percentiles(
        self,
        operation_type: CryptoOperationType,
    ) -> Dict[str, float]:
        """Calculate latency percentiles for a crypto operation."""
        with self._lock:
            samples = sorted(self._operation_latencies.get(operation_type.value, []))

        if not samples:
            return {
                "p50": 0.0, "p75": 0.0, "p90": 0.0,
                "p95": 0.0, "p99": 0.0, "p999": 0.0,
                "count": 0, "min": 0.0, "max": 0.0, "avg": 0.0,
            }

        def _p(percentile: float) -> float:
            idx = int(len(samples) * percentile)
            return samples[min(idx, len(samples) - 1)]

        return {
            "p50": _p(0.50),
            "p75": _p(0.75),
            "p90": _p(0.90),
            "p95": _p(0.95),
            "p99": _p(0.99),
            "p999": _p(0.999),
            "count": len(samples),
            "min": samples[0],
            "max": samples[-1],
            "avg": sum(samples) / len(samples),
        }

    def get_health_metrics(self) -> CryptoHealthMetrics:
        """Get current crypto subsystem health metrics."""
        with self._lock:
            total_ops = sum(self._operation_counters.values())
            total_errors = sum(self._error_counters.values())

        success_rate = 1.0 if total_ops == 0 else (total_ops - total_errors) / total_ops

        return CryptoHealthMetrics(
            operation_success_rate=success_rate,
            error_count=total_errors,
            timeout_count=self._error_counters.get("timeout", 0),
            last_health_check=time.time(),
        )

    def assess_randomness_quality(self) -> RandomnessQualityMetrics:
        """Assess random number generator quality using basic statistical tests."""
        with self._lock:
            samples = list(self._randomness_samples)

        if not samples:
            return RandomnessQualityMetrics()

        # Combine all samples
        all_data = b''.join(samples)
        n = len(all_data)

        # Simple entropy estimation
        byte_counts = defaultdict(int)
        for b in all_data:
            byte_counts[b] += 1

        import math
        entropy = 0.0
        for count in byte_counts.values():
            p = count / n
            entropy -= p * math.log2(p) if p > 0 else 0

        # Chi-square test (simplified)
        expected = n / 256
        chi_square = sum((count - expected) ** 2 / expected for count in byte_counts.values())

        return RandomnessQualityMetrics(
            sample_count=len(samples),
            chi_square_score=chi_square,
            entropy_bits_per_byte=entropy,
            runs_test_passed=entropy > 7.5,  # Threshold for good randomness
        )

    def get_algorithm_usage_stats(self) -> Dict[str, int]:
        """Get algorithm usage statistics."""
        with self._lock:
            return dict(self._algorithm_usage)

    def get_operation_counters(self) -> Dict[str, int]:
        """Get operation counters."""
        with self._lock:
            return dict(self._operation_counters)

    def trace_crypto_operation(
        self,
        operation_type: CryptoOperationType,
        algorithm: Optional[str] = None,
    ) -> Callable:
        """
        Decorator for tracing crypto operations.
        
        ADD-ONLY wrapper - does not modify wrapped function.
        100% backward compatible - no-op if disabled.
        """
        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)

                parent = ThreadLocalCryptoContext.get_current_span()
                span = self.start_crypto_span(
                    operation_type=operation_type,
                    algorithm=algorithm,
                    trace_id=parent.trace_id if parent else None,
                    parent_span_id=parent.span_id if parent else None,
                    attributes={
                        "function": func.__name__,
                        "hsm_model": self.hsm_model,
                    },
                    baggage=parent.baggage if parent else {},
                )

                try:
                    result = func(*args, **kwargs)
                    self.end_crypto_span(span, success=True)
                    return result

                except Exception as e:
                    self.end_crypto_span(span, success=False, error_type=type(e).__name__)
                    raise

            return wrapper
        return decorator

    def export_metrics_json(self) -> str:
        """Export all metrics as JSON for observability platforms."""
        with self._lock:
            export_data = {
                "service": self.service_name,
                "hsm_model": self.hsm_model,
                "compliance_level": self.compliance_level.value,
                "hsm_status": self.hsm_status.value,
                "export_time": time.time(),
                "enabled": self.enabled,
                "operation_counters": dict(self._operation_counters),
                "error_counters": dict(self._error_counters),
                "algorithm_usage": dict(self._algorithm_usage),
                "latency_percentiles": {
                    op.value: self.calculate_latency_percentiles(op)
                    for op in CryptoOperationType
                },
                "health_metrics": self.get_health_metrics().__dict__,
                "randomness_quality": self.assess_randomness_quality().__dict__,
                "compliance_event_count": len(self._compliance_log),
                "trace_count": len(self._traces),
            }

        return json.dumps(export_data, indent=2)

    def update_hsm_status(self, status: HSMStatus) -> None:
        """Update HSM operational status."""
        with self._lock:
            self.hsm_status = status

    def get_compliance_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get compliance audit log entries."""
        with self._lock:
            return list(self._compliance_log[-limit:])


# Global observer instance - OPT-IN, disabled by default
_global_observer = HSMOperationObserver(enabled=False)


def get_global_observer() -> HSMOperationObserver:
    """Get the global HSM observer instance."""
    return _global_observer


def enable_crypto_instrumentation(
    service_name: str = "quantumcrypt-ai",
    hsm_model: str = "virtual-hsm",
    compliance_level: ComplianceLevel = ComplianceLevel.FIPS_140_3_LEVEL_3,
) -> None:
    """Explicitly enable crypto instrumentation - must be called to activate."""
    global _global_observer
    _global_observer = HSMOperationObserver(
        service_name=service_name,
        hsm_model=hsm_model,
        compliance_level=compliance_level,
        enabled=True,
    )


def disable_crypto_instrumentation() -> None:
    """Disable crypto instrumentation completely."""
    global _global_observer
    _global_observer = HSMOperationObserver(enabled=False)
