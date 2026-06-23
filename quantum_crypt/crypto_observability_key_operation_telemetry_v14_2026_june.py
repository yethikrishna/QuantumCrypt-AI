"""
QuantumCrypt Observability v14 - Key Operation Telemetry Integration
Dimension D: Observability & Instrumentation
Provides OPT-IN telemetry, metrics, and tracing for v17 side-channel key protection modules.

DESIGN PHILOSOPHY:
- ADD-ONLY: Wraps existing functionality, NO core modification
- BACKWARD COMPATIBLE: All existing code continues to work unchanged
- OPT-IN: ALL features DISABLED by default, explicit enable required
- ZERO OVERHEAD: When disabled, operations are pure no-ops
- CRYPTO-SAFE: No sensitive key material in logs or metrics
- FIPS COMPLIANT: No exposure of plaintext key material

STABILITY: EXPERIMENTAL (OPT-IN only)
"""
import os
import sys
import time
import json
import hashlib
import threading
from typing import Any, Callable, Optional, Dict, List, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

# Try to import the v17 crypto security module gracefully
try:
    from .crypto_security_hardening_side_channel_key_protection_v17_2026_june import (
        KeySensitivityLevel,
        CryptoSecurityConfig,
        SecureKeyBuffer,
        ConstantTimeCryptoOperations,
        TimingAttackProtector,
        KeyOperationProtector,
        SideChannelResistantKEM,
        SecureKeyRotationManager,
    )
    CRYPTO_MODULE_AVAILABLE = True
except ImportError:
    CRYPTO_MODULE_AVAILABLE = False


class CryptoTelemetryLevel(Enum):
    """Telemetry verbosity levels for crypto operations"""
    DISABLED = 0
    BASIC = 1      # Counts only, no details
    DETAILED = 2   # Operation types and durations
    DEBUG = 3      # Full tracing (no key material)


@dataclass
class CryptoTelemetryConfig:
    """Configuration for cryptographic operation telemetry"""
    # Master switch - ALL disabled by default
    enabled: bool = False
    
    # Telemetry level
    telemetry_level: CryptoTelemetryLevel = CryptoTelemetryLevel.DISABLED
    
    # Feature toggles - ALL disabled by default
    enable_metrics: bool = False
    enable_tracing: bool = False
    enable_structured_logging: bool = False
    enable_health_checks: bool = False
    
    # Security boundaries - CRITICAL: NEVER expose key material
    enable_key_hash_tracking: bool = False  # Track SHA-256 hashes only
    max_key_size_tracking: bool = True       # Track key sizes only
    
    # Metrics configuration
    metrics_namespace: str = "quantumcrypt_crypto"
    max_metrics_points: int = 10000
    enable_prometheus_export: bool = False
    
    # Logging configuration - NO KEY MATERIAL EVER
    log_json_format: bool = True
    include_timestamps: bool = True
    log_operation_types_only: bool = True  # No parameters in logs
    
    # Sampling configuration
    sampling_rate: float = 1.0
    max_log_entries_per_second: int = 50
    
    def __post_init__(self):
        self._thread_local = threading.local()
        # If master enabled is False, force ALL features off
        if not self.enabled:
            self.enable_metrics = False
            self.enable_tracing = False
            self.enable_structured_logging = False
            self.enable_health_checks = False
            self.enable_key_hash_tracking = False
            self.telemetry_level = CryptoTelemetryLevel.DISABLED


class CryptoOperationMetrics:
    """
    Metrics collector for cryptographic key operations.
    Tracks operation counts, durations, types - NO KEY MATERIAL.
    ALL OPERATIONS ARE NO-OP WHEN DISABLED.
    """
    
    def __init__(self, config: Optional[CryptoTelemetryConfig] = None):
        self.config = config or CryptoTelemetryConfig()
        self._lock = threading.Lock()
        
        # Metrics storage - only used if enabled
        self._operation_counts: Dict[str, int] = defaultdict(int)
        self._operation_durations: Dict[str, List[float]] = defaultdict(list)
        self._key_operation_counts: Dict[str, int] = defaultdict(int)
        self._zeroization_counts: Dict[str, int] = defaultdict(int)
        self._error_counts: Dict[str, int] = defaultdict(int)
        
        # Health metrics
        self._start_time = time.time()
        self._keys_created = 0
        self._keys_zeroized = 0
    
    def record_key_operation(
        self,
        operation: str,
        key_sensitivity: str,
        duration_ns: int,
        success: bool = True
    ) -> None:
        """Record a key operation - NO-OP if disabled"""
        if not self.config.enable_metrics:
            return
        
        with self._lock:
            op_key = f"{operation}_{key_sensitivity}"
            self._operation_counts[op_key] += 1
            self._operation_durations[op_key].append(duration_ns / 1e9)
            
            # Trim to prevent memory growth
            if len(self._operation_durations[op_key]) > 500:
                self._operation_durations[op_key] = self._operation_durations[op_key][-250:]
            
            if not success:
                self._error_counts[op_key] += 1
    
    def record_key_creation(self, key_size: int, sensitivity: str) -> None:
        """Record key creation - NO-OP if disabled"""
        if not self.config.enable_metrics:
            return
        
        with self._lock:
            self._keys_created += 1
            self._key_operation_counts[f"create_{sensitivity}_{key_size}"] += 1
    
    def record_key_zeroization(self, key_size: int, sensitivity: str) -> None:
        """Record key zeroization - NO-OP if disabled"""
        if not self.config.enable_metrics:
            return
        
        with self._lock:
            self._keys_zeroized += 1
            self._zeroization_counts[f"zeroize_{sensitivity}_{key_size}"] += 1
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary - empty dict if disabled"""
        if not self.config.enable_metrics:
            return {}
        
        with self._lock:
            summary = {
                "total_crypto_operations": sum(self._operation_counts.values()),
                "total_errors": sum(self._error_counts.values()),
                "keys_created_total": self._keys_created,
                "keys_zeroized_total": self._keys_zeroized,
                "operations_by_type": dict(self._operation_counts),
                "uptime_seconds": time.time() - self._start_time,
            }
            
            # Average durations
            avg_durations = {}
            for op_name, durations in self._operation_durations.items():
                if durations:
                    avg_durations[op_name] = sum(durations) / len(durations)
            summary["average_durations_seconds"] = avg_durations
            
            return summary
    
    def export_prometheus_format(self) -> str:
        """Export Prometheus format - empty if disabled"""
        if not self.config.enable_metrics or not self.config.enable_prometheus_export:
            return ""
        
        metrics = self.get_metrics_summary()
        ns = self.config.metrics_namespace
        lines = []
        
        lines.append(f"# HELP {ns}_operations_total Total cryptographic operations")
        lines.append(f"# TYPE {ns}_operations_total counter")
        lines.append(f"{ns}_operations_total {metrics.get('total_crypto_operations', 0)}")
        
        lines.append(f"# HELP {ns}_errors_total Total crypto operation errors")
        lines.append(f"# TYPE {ns}_errors_total counter")
        lines.append(f"{ns}_errors_total {metrics.get('total_errors', 0)}")
        
        lines.append(f"# HELP {ns}_keys_created_total Keys created")
        lines.append(f"# TYPE {ns}_keys_created_total counter")
        lines.append(f"{ns}_keys_created_total {metrics.get('keys_created_total', 0)}")
        
        lines.append(f"# HELP {ns}_keys_zeroized_total Keys securely zeroized")
        lines.append(f"# TYPE {ns}_keys_zeroized_total counter")
        lines.append(f"{ns}_keys_zeroized_total {metrics.get('keys_zeroized_total', 0)}")
        
        return "\n".join(lines) + "\n"


class StructuredCryptoLogger:
    """
    Structured JSON logger for crypto operations.
    CRITICAL: NEVER logs key material - only operation metadata.
    ALL LOGGING DISABLED BY DEFAULT.
    """
    
    def __init__(self, config: Optional[CryptoTelemetryConfig] = None):
        self.config = config or CryptoTelemetryConfig()
        self._lock = threading.Lock()
        self._log_buffer: List[Dict[str, Any]] = []
    
    def _should_log(self) -> bool:
        if not self.config.enable_structured_logging:
            return False
        if self.config.sampling_rate < 1.0:
            import random
            return random.random() < self.config.sampling_rate
        return True
    
    def log_operation(
        self,
        operation: str,
        key_sensitivity: Optional[str] = None,
        key_size: Optional[int] = None,
        level: str = "INFO",
        **kwargs
    ) -> None:
        """Log crypto operation - NO KEY MATERIAL, NO-OP if disabled"""
        if not self._should_log():
            return
        
        log_entry = {
            "timestamp": time.time() if self.config.include_timestamps else None,
            "level": level,
            "operation": operation,
            "module": "crypto_security_v17",
            "observability_version": "v14",
        }
        
        # Only add safe metadata
        if key_sensitivity:
            log_entry["key_sensitivity"] = key_sensitivity
        if key_size and self.config.max_key_size_tracking:
            log_entry["key_size_bytes"] = key_size
        
        # Never allow 'key_material' or similar fields
        safe_kwargs = {k: v for k, v in kwargs.items() 
                      if 'key' not in k.lower() and 'secret' not in k.lower()}
        log_entry.update(safe_kwargs)
        
        with self._lock:
            self._log_buffer.append(log_entry)
            if len(self._log_buffer) > 500:
                self._log_buffer = self._log_buffer[-250:]
    
    def get_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get buffered logs - empty if disabled"""
        if not self.config.enable_structured_logging:
            return []
        with self._lock:
            return list(self._log_buffer[-limit:])
    
    def export_logs_json(self, limit: int = 50) -> str:
        """Export as JSON - empty array if disabled"""
        logs = self.get_logs(limit)
        return json.dumps(logs, indent=2) if self.config.log_json_format else str(logs)


class CryptoOperationTracer:
    """
    Distributed tracing for cryptographic operations.
    NO KEY MATERIAL in trace context.
    ALL TRACING DISABLED BY DEFAULT.
    """
    
    def __init__(self, config: Optional[CryptoTelemetryConfig] = None):
        self.config = config or CryptoTelemetryConfig()
        self._thread_local = threading.local()
    
    def start_span(self, operation_name: str) -> Optional[str]:
        """Start trace span - None if disabled"""
        if not self.config.enable_tracing:
            return None
        
        import secrets
        span_id = secrets.token_hex(8)
        trace_id = getattr(self._thread_local, 'trace_id', secrets.token_hex(16))
        
        self._thread_local.trace_id = trace_id
        self._thread_local.current_span_id = span_id
        self._thread_local.span_start = time.perf_counter_ns()
        self._thread_local.span_operation = operation_name
        
        return span_id
    
    def end_span(self, span_id: Optional[str] = None, success: bool = True) -> Optional[Dict[str, Any]]:
        """End trace span - None if disabled"""
        if not self.config.enable_tracing:
            return None
        
        end_time = time.perf_counter_ns()
        start_time = getattr(self._thread_local, 'span_start', end_time)
        
        span_data = {
            "trace_id": getattr(self._thread_local, 'trace_id', None),
            "span_id": span_id or getattr(self._thread_local, 'current_span_id', None),
            "operation": getattr(self._thread_local, 'span_operation', 'unknown'),
            "duration_ns": end_time - start_time,
            "success": success,
        }
        
        # Cleanup
        for attr in ['trace_id', 'current_span_id', 'span_start', 'span_operation']:
            if hasattr(self._thread_local, attr):
                delattr(self._thread_local, attr)
        
        return span_data


class InstrumentedKeyOperationProtector:
    """
    OPT-IN instrumented wrapper for v17 KeyOperationProtector.
    Adds telemetry, metrics, tracing WITHOUT modifying core crypto logic.
    
    WHEN DISABLED (DEFAULT): Pure pass-through with ZERO overhead
    WHEN ENABLED: Full observability with NO key material exposure
    """
    
    def __init__(
        self,
        key_protector: Any = None,
        config: Optional[CryptoTelemetryConfig] = None
    ):
        self.config = config or CryptoTelemetryConfig()
        self._key_protector = key_protector
        
        # Initialize observability (all disabled by default)
        self._metrics = CryptoOperationMetrics(self.config)
        self._logger = StructuredCryptoLogger(self.config)
        self._tracer = CryptoOperationTracer(self.config)
    
    def _safe_hash_key(self, key_data: bytes) -> Optional[str]:
        """Get SHA-256 hash of key for tracking - ONLY if explicitly enabled"""
        if not self.config.enable_key_hash_tracking:
            return None
        return hashlib.sha256(key_data).hexdigest()[:16]  # First 16 chars only
    
    def _wrap_operation(
        self,
        operation_name: str,
        func: Callable,
        key_sensitivity: str = "HIGH",
        key_size: Optional[int] = None,
        *args,
        **kwargs
    ) -> Any:
        """Wrap operation - ZERO overhead when disabled"""
        if not self.config.enabled:
            return func(*args, **kwargs)
        
        start_time = time.perf_counter_ns()
        span_id = self._tracer.start_span(operation_name)
        success = True
        
        try:
            result = func(*args, **kwargs)
            return result
            
        except Exception as e:
            success = False
            self._logger.log_operation(
                operation_name,
                key_sensitivity=key_sensitivity,
                key_size=key_size,
                level="ERROR",
                error_type=type(e).__name__
            )
            raise
            
        finally:
            duration = time.perf_counter_ns() - start_time
            self._metrics.record_key_operation(
                operation_name, key_sensitivity, duration, success
            )
            self._tracer.end_span(span_id, success)
            
            if self.config.telemetry_level.value >= CryptoTelemetryLevel.DETAILED.value:
                self._logger.log_operation(
                    operation_name,
                    key_sensitivity=key_sensitivity,
                    key_size=key_size,
                    duration_ns=duration,
                    success=success
                )
    
    def protected_key_generation(
        self,
        key_gen_func: Callable,
        *args,
        **kwargs
    ) -> Tuple[Any, Any]:
        """Instrumented key generation - NO key material in telemetry"""
        if self._key_protector is not None:
            result = self._wrap_operation(
                "key_generation",
                self._key_protector.protected_key_generation,
                "HIGH", None,
                key_gen_func, *args, **kwargs
            )
            
            # Record creation metrics
            if self.config.enable_metrics:
                priv_key, pub_key = result
                self._metrics.record_key_creation(priv_key.size, "PRIVATE")
                self._metrics.record_key_creation(pub_key.size, "PUBLIC")
            
            return result
        
        # Fallback
        return key_gen_func(*args, **kwargs)
    
    def protected_sign(
        self,
        sign_func: Callable,
        private_key: Any,
        message: bytes,
        *args,
        **kwargs
    ) -> bytes:
        """Instrumented signing operation"""
        if self._key_protector is not None:
            return self._wrap_operation(
                "digital_sign",
                self._key_protector.protected_sign,
                "HIGH", private_key.size if hasattr(private_key, 'size') else None,
                sign_func, private_key, message, *args, **kwargs
            )
        return sign_func(private_key, message, *args, **kwargs)
    
    def protected_verify(
        self,
        verify_func: Callable,
        public_key: Any,
        message: bytes,
        signature: bytes,
        *args,
        **kwargs
    ) -> bool:
        """Instrumented signature verification"""
        if self._key_protector is not None:
            return self._wrap_operation(
                "signature_verify",
                self._key_protector.protected_verify,
                "LOW", public_key.size if hasattr(public_key, 'size') else None,
                verify_func, public_key, message, signature, *args, **kwargs
            )
        return verify_func(public_key, message, signature, *args, **kwargs)
    
    def protected_key_exchange(
        self,
        kex_func: Callable,
        private_key: Any,
        peer_public_key: Any,
        *args,
        **kwargs
    ) -> Any:
        """Instrumented key exchange"""
        if self._key_protector is not None:
            result = self._wrap_operation(
                "key_exchange",
                self._key_protector.protected_key_exchange,
                "CRITICAL", None,
                kex_func, private_key, peer_public_key, *args, **kwargs
            )
            
            if self.config.enable_metrics and hasattr(result, 'size'):
                self._metrics.record_key_creation(result.size, "SHARED_SECRET")
            
            return result
        return kex_func(private_key, peer_public_key, *args, **kwargs)
    
    def get_telemetry_summary(self) -> Dict[str, Any]:
        """Get telemetry summary - empty if disabled"""
        if not self.config.enabled:
            return {"enabled": False, "status": "telemetry_disabled"}
        
        return {
            "enabled": True,
            "config": {
                "enable_metrics": self.config.enable_metrics,
                "enable_tracing": self.config.enable_tracing,
                "enable_logging": self.config.enable_structured_logging,
                "enable_key_hash_tracking": self.config.enable_key_hash_tracking,
                "telemetry_level": self.config.telemetry_level.name,
            },
            "metrics": self._metrics.get_metrics_summary(),
            "crypto_module_loaded": CRYPTO_MODULE_AVAILABLE,
        }
    
    def get_health_status(self) -> Dict[str, Any]:
        """Health check - always available"""
        return {
            "status": "healthy" if CRYPTO_MODULE_AVAILABLE else "crypto_module_unavailable",
            "crypto_module_loaded": CRYPTO_MODULE_AVAILABLE,
            "telemetry_enabled": self.config.enabled,
            "version": "v14",
            "timestamp": time.time(),
        }


class InstrumentedSecureKeyBuffer:
    """
    OPT-IN instrumented wrapper for SecureKeyBuffer.
    Tracks key lifecycle (creation, zeroization) with metrics.
    ZERO overhead when disabled.
    """
    
    def __init__(
        self,
        key_buffer: Any,
        config: Optional[CryptoTelemetryConfig] = None,
        metrics: Optional[CryptoOperationMetrics] = None
    ):
        self._key_buffer = key_buffer
        self.config = config or CryptoTelemetryConfig()
        self._metrics = metrics
        
        if self.config.enable_metrics and self._metrics:
            sensitivity = getattr(self.config, 'key_sensitivity_level', 'HIGH')
            if hasattr(key_buffer, 'size'):
                sens_name = sensitivity.name if hasattr(sensitivity, 'name') else str(sensitivity)
                self._metrics.record_key_creation(key_buffer.size, sens_name)
    
    def __enter__(self):
        return self._key_buffer.__enter__()
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        result = self._key_buffer.__exit__(exc_type, exc_val, exc_tb)
        
        if self.config.enable_metrics and self._metrics:
            if hasattr(self._key_buffer, 'is_zeroized') and self._key_buffer.is_zeroized:
                sensitivity = getattr(self.config, 'key_sensitivity_level', 'HIGH')
                sens_name = sensitivity.name if hasattr(sensitivity, 'name') else str(sensitivity)
                self._metrics.record_key_zeroization(self._key_buffer.size, sens_name)
        
        return result
    
    def __getattr__(self, name):
        """Delegate all other attributes to wrapped buffer"""
        return getattr(self._key_buffer, name)


# Factory function
def create_instrumented_crypto_protector(
    enable_telemetry: bool = False,
    enable_metrics: bool = False,
    enable_tracing: bool = False,
    enable_logging: bool = False,
) -> InstrumentedKeyOperationProtector:
    """
    Factory to create instrumented crypto protector.
    ALL FEATURES DISABLED BY DEFAULT - explicit enable required.
    
    Example:
        # Default: NO telemetry, pure pass-through
        protector = create_instrumented_crypto_protector()
        
        # With full observability (OPT-IN)
        protector = create_instrumented_crypto_protector(
            enable_telemetry=True,
            enable_metrics=True,
            enable_tracing=True,
            enable_logging=True
        )
    """
    config = CryptoTelemetryConfig(
        enabled=enable_telemetry,
        enable_metrics=enable_metrics,
        enable_tracing=enable_tracing,
        enable_structured_logging=enable_logging,
        telemetry_level=CryptoTelemetryLevel.BASIC if enable_telemetry else CryptoTelemetryLevel.DISABLED,
    )
    
    crypto_protector = None
    if CRYPTO_MODULE_AVAILABLE:
        from .crypto_security_hardening_side_channel_key_protection_v17_2026_june import key_protector
        crypto_protector = key_protector
    
    return InstrumentedKeyOperationProtector(crypto_protector, config)


# Default instance - ALL TELEMETRY DISABLED, pure pass-through
default_instrumented_crypto = create_instrumented_crypto_protector(
    enable_telemetry=False,
    enable_metrics=False,
    enable_tracing=False,
    enable_logging=False,
)

__all__ = [
    'CryptoTelemetryLevel',
    'CryptoTelemetryConfig',
    'CryptoOperationMetrics',
    'StructuredCryptoLogger',
    'CryptoOperationTracer',
    'InstrumentedKeyOperationProtector',
    'InstrumentedSecureKeyBuffer',
    'create_instrumented_crypto_protector',
    'default_instrumented_crypto',
    'CRYPTO_MODULE_AVAILABLE',
]
