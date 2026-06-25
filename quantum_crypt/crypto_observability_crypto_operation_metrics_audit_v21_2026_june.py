"""
QuantumCrypt AI - Cryptographic Operation Metrics & Audit Logging
Dimension D: Observability & Instrumentation - V21

This module provides OPT-IN metrics collection and security audit logging
for cryptographic operations. All instrumentation is completely optional
and disabled by default. Wraps existing code - NO core modifications.

Stability: BETA
Opt-in: Yes (explicit enable required)
Backward Compatible: 100%
Crypto-specific: Yes - tracks key operations, latency, and security properties
"""

import time
import uuid
import json
import threading
import hashlib
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from collections import defaultdict


class CryptoOperationType(Enum):
    """Types of cryptographic operations"""
    KEY_GENERATION = "key_generation"
    KEY_ENCAPSULATION = "key_encapsulation"
    KEY_DECAPSULATION = "key_decapsulation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    HASHING = "hashing"
    KEY_DERIVATION = "key_derivation"
    RANDOM_GENERATION = "random_generation"
    KEY_EXCHANGE = "key_exchange"


class CryptoAlgorithm(Enum):
    """Cryptographic algorithms"""
    # Post-Quantum
    KYBER = "CRYSTALS-Kyber"
    DILITHIUM = "CRYSTALS-Dilithium"
    FALCON = "FALCON"
    SPHINCS = "SPHINCS+"
    NTRU = "NTRU"
    # Classical
    AES_256_GCM = "AES-256-GCM"
    RSA_4096 = "RSA-4096"
    ECDSA_P384 = "ECDSA-P384"
    SHA3_512 = "SHA3-512"
    HKDF = "HKDF"
    UNKNOWN = "unknown"


class SecurityLevel(Enum):
    """NIST security levels"""
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_2 = 2
    LEVEL_3 = 3  # AES-192 equivalent
    LEVEL_4 = 4
    LEVEL_5 = 5  # AES-256 equivalent


@dataclass
class CryptoOperationMetrics:
    """Metrics for a single cryptographic operation"""
    operation_id: str
    operation_type: CryptoOperationType
    algorithm: CryptoAlgorithm
    security_level: SecurityLevel
    start_time: float
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    success: bool = True
    error_type: Optional[str] = None
    input_size_bytes: Optional[int] = None
    output_size_bytes: Optional[int] = None
    key_id_hash: Optional[str] = None  # Hash only, never raw key material
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditLogEntry:
    """Security audit log entry"""
    audit_id: str
    timestamp: float
    operation_type: str
    algorithm: str
    security_level: int
    duration_ms: float
    success: bool
    caller_context: str
    key_fingerprint: Optional[str] = None
    input_hash: Optional[str] = None  # SHA-256 of input only
    additional_context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AlgorithmPerformanceStats:
    """Aggregated performance statistics per algorithm"""
    total_operations: int = 0
    total_success: int = 0
    total_errors: int = 0
    total_duration_ms: float = 0.0
    min_duration_ms: float = float('inf')
    max_duration_ms: float = 0.0
    total_bytes_processed: int = 0


class CryptoMetricsCollector:
    """
    OPT-IN metrics collector for cryptographic operations.
    
    All metrics collection is DISABLED by default.
    Does NOT store or log any sensitive key material - only hashes and metadata.
    """
    
    def __init__(self, service_name: str = "quantumcrypt-ai"):
        self.service_name = service_name
        self._enabled = False
        self._operations: List[CryptoOperationMetrics] = []
        self._audit_log: List[AuditLogEntry] = []
        self._stats: Dict[Tuple[str, str], AlgorithmPerformanceStats] = defaultdict(AlgorithmPerformanceStats)
        self._max_operations = 50000
        self._max_audit_entries = 10000
        self._lock = threading.Lock()
        self._on_operation_callback: Optional[Callable] = None
        self._on_audit_callback: Optional[Callable] = None
        self._caller_context_provider: Optional[Callable[[], str]] = None
    
    def enable(self) -> None:
        """Enable metrics collection (OPT-IN - must call explicitly)"""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable metrics collection completely"""
        self._enabled = False
    
    def is_enabled(self) -> bool:
        return self._enabled
    
    def set_operation_callback(self, callback: Callable) -> None:
        """Set optional callback for operation completion"""
        self._on_operation_callback = callback
    
    def set_audit_callback(self, callback: Callable) -> None:
        """Set optional callback for audit log entries"""
        self._on_audit_callback = callback
    
    def set_caller_context_provider(self, provider: Callable[[], str]) -> None:
        """Set provider for caller context (e.g., request ID, user ID)"""
        self._caller_context_provider = provider
    
    def _hash_sensitive(self, data: Optional[bytes]) -> Optional[str]:
        """Hash sensitive data - NEVER log raw material"""
        if data is None:
            return None
        return hashlib.sha256(data).hexdigest()[:16]  # First 16 chars only
    
    def start_operation(self,
                        operation_type: CryptoOperationType,
                        algorithm: CryptoAlgorithm,
                        security_level: SecurityLevel = SecurityLevel.LEVEL_1,
                        input_data: Optional[bytes] = None,
                        key_material: Optional[bytes] = None,
                        metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Start tracking a cryptographic operation.
        
        IMPORTANT: Never stores raw key material - only hashes!
        
        Returns operation_id if enabled, None otherwise.
        """
        if not self.is_enabled():
            return None
        
        with self._lock:
            if len(self._operations) >= self._max_operations:
                return None  # Graceful degradation
            
            operation = CryptoOperationMetrics(
                operation_id=str(uuid.uuid4()),
                operation_type=operation_type,
                algorithm=algorithm,
                security_level=security_level,
                start_time=time.time(),
                input_size_bytes=len(input_data) if input_data else None,
                key_id_hash=self._hash_sensitive(key_material),
                metadata=metadata or {}
            )
            
            self._operations.append(operation)
            return operation.operation_id
    
    def end_operation(self,
                      operation_id: Optional[str],
                      success: bool = True,
                      error_type: Optional[str] = None,
                      output_data: Optional[bytes] = None,
                      additional_metadata: Optional[Dict[str, Any]] = None) -> Optional[float]:
        """
        End operation tracking and record metrics.
        
        Returns duration in ms if enabled, None otherwise.
        """
        if not self.is_enabled() or operation_id is None:
            return None
        
        with self._lock:
            # Find operation
            operation = next((op for op in self._operations if op.operation_id == operation_id), None)
            if operation is None:
                return None
            
            operation.end_time = time.time()
            operation.duration_ms = (operation.end_time - operation.start_time) * 1000
            operation.success = success
            operation.error_type = error_type
            operation.output_size_bytes = len(output_data) if output_data else None
            
            if additional_metadata:
                operation.metadata.update(additional_metadata)
            
            # Update aggregated stats
            key = (operation.operation_type.value, operation.algorithm.value)
            stats = self._stats[key]
            stats.total_operations += 1
            if success:
                stats.total_success += 1
            else:
                stats.total_errors += 1
            stats.total_duration_ms += operation.duration_ms or 0
            stats.min_duration_ms = min(stats.min_duration_ms, operation.duration_ms or float('inf'))
            stats.max_duration_ms = max(stats.max_duration_ms, operation.duration_ms or 0)
            stats.total_bytes_processed += (operation.input_size_bytes or 0) + (operation.output_size_bytes or 0)
            
            # Create audit log entry
            if len(self._audit_log) < self._max_audit_entries:
                caller_context = "unknown"
                if self._caller_context_provider:
                    try:
                        caller_context = self._caller_context_provider()
                    except Exception:
                        pass
                
                audit = AuditLogEntry(
                    audit_id=str(uuid.uuid4()),
                    timestamp=operation.end_time,
                    operation_type=operation.operation_type.value,
                    algorithm=operation.algorithm.value,
                    security_level=operation.security_level.value,
                    duration_ms=operation.duration_ms or 0,
                    success=success,
                    caller_context=caller_context,
                    key_fingerprint=operation.key_id_hash,
                    input_hash=self._hash_sensitive(output_data),  # Hash only
                    additional_context=additional_metadata or {}
                )
                self._audit_log.append(audit)
                
                if self._on_audit_callback:
                    try:
                        self._on_audit_callback(audit)
                    except Exception:
                        pass  # Never break crypto operations
            
            # Trigger operation callback
            if self._on_operation_callback:
                try:
                    self._on_operation_callback(operation)
                except Exception:
                    pass
            
            return operation.duration_ms
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary across all operations"""
        if not self.is_enabled():
            return {"enabled": False}
        
        with self._lock:
            total_ops = len(self._operations)
            successful = sum(1 for op in self._operations if op.success)
            failed = total_ops - successful
            
            avg_duration = 0.0
            if total_ops > 0:
                total_dur = sum(op.duration_ms or 0 for op in self._operations)
                avg_duration = total_dur / total_ops
            
            return {
                "service": self.service_name,
                "total_operations": total_ops,
                "successful_operations": successful,
                "failed_operations": failed,
                "success_rate": (successful / total_ops * 100) if total_ops > 0 else 0,
                "average_duration_ms": avg_duration,
                "audit_log_entries": len(self._audit_log),
                "algorithm_breakdown": {
                    f"{op_type}:{algo}": {
                        "total": stats.total_operations,
                        "success_rate": (stats.total_success / stats.total_operations * 100) if stats.total_operations > 0 else 0,
                        "avg_duration_ms": (stats.total_duration_ms / stats.total_operations) if stats.total_operations > 0 else 0,
                        "min_duration_ms": stats.min_duration_ms if stats.min_duration_ms != float('inf') else 0,
                        "max_duration_ms": stats.max_duration_ms,
                        "throughput_mbps": (stats.total_bytes_processed / 1024 / 1024 / (stats.total_duration_ms / 1000)) if stats.total_duration_ms > 0 else 0
                    }
                    for (op_type, algo), stats in self._stats.items()
                }
            }
    
    def get_audit_log(self, limit: int = 100, min_security_level: int = 1) -> List[Dict[str, Any]]:
        """Get audit log entries"""
        if not self.is_enabled():
            return []
        
        with self._lock:
            return [
                {
                    "audit_id": entry.audit_id,
                    "timestamp": datetime.fromtimestamp(entry.timestamp, tz=timezone.utc).isoformat(),
                    "operation_type": entry.operation_type,
                    "algorithm": entry.algorithm,
                    "security_level": entry.security_level,
                    "duration_ms": entry.duration_ms,
                    "success": entry.success,
                    "caller_context": entry.caller_context,
                    "key_fingerprint": entry.key_fingerprint,
                    "additional_context": entry.additional_context
                }
                for entry in self._audit_log
                if entry.security_level >= min_security_level
            ][-limit:]
    
    def export_metrics_json(self) -> str:
        """Export all metrics as JSON"""
        if not self.is_enabled():
            return json.dumps({"enabled": False, "operations": [], "audit_log": []})
        
        with self._lock:
            return json.dumps({
                "service": self.service_name,
                "export_time": datetime.now(timezone.utc).isoformat(),
                "summary": self.get_performance_summary(),
                "operations": [
                    {
                        "operation_id": op.operation_id,
                        "type": op.operation_type.value,
                        "algorithm": op.algorithm.value,
                        "security_level": op.security_level.value,
                        "duration_ms": op.duration_ms,
                        "success": op.success,
                        "error_type": op.error_type,
                        "input_size_bytes": op.input_size_bytes,
                        "output_size_bytes": op.output_size_bytes,
                        "key_id_hash": op.key_id_hash
                    }
                    for op in self._operations[-1000:]  # Last 1000 only
                ],
                "audit_log": self.get_audit_log(1000)
            }, indent=2)
    
    def get_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format"""
        if not self.is_enabled():
            return "# Crypto metrics disabled\n"
        
        lines = [
            "# HELP crypto_operations_total Total cryptographic operations",
            "# TYPE crypto_operations_total counter",
            "# HELP crypto_operations_duration_seconds Crypto operation duration",
            "# TYPE crypto_operations_duration_seconds histogram",
            "# HELP crypto_operations_success_total Successful operations",
            "# TYPE crypto_operations_success_total counter",
        ]
        
        with self._lock:
            summary = self.get_performance_summary()
            lines.append(f'crypto_operations_total{{service="{self.service_name}"}} {summary["total_operations"]}')
            lines.append(f'crypto_operations_success_total{{service="{self.service_name}"}} {summary["successful_operations"]}')
            
            for key, breakdown in summary.get("algorithm_breakdown", {}).items():
                op_type, algo = key.split(":", 1)
                lines.append(
                    f'crypto_operations_total{{operation="{op_type}",algorithm="{algo}",service="{self.service_name}"}} '
                    f'{breakdown["total"]}'
                )
        
        return "\n".join(lines)
    
    def clear(self) -> None:
        """Clear all metrics and audit logs"""
        with self._lock:
            self._operations.clear()
            self._audit_log.clear()
            self._stats.clear()


# Global metrics instance - DISABLED BY DEFAULT
_global_metrics = CryptoMetricsCollector()


def get_crypto_metrics() -> CryptoMetricsCollector:
    """Get the global metrics collector (starts disabled)"""
    return _global_metrics


def tracked_crypto_operation(operation_type: CryptoOperationType,
                              algorithm: CryptoAlgorithm,
                              security_level: SecurityLevel = SecurityLevel.LEVEL_1):
    """
    Decorator for tracking cryptographic operations.
    
    OPT-IN - does nothing unless metrics enabled.
    NEVER captures sensitive key material - only hashes and metadata.
    
    Usage:
        @tracked_crypto_operation(CryptoOperationType.ENCRYPTION, CryptoAlgorithm.AES_256_GCM)
        def encrypt(data, key):
            ...
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            metrics = get_crypto_metrics()
            if not metrics.is_enabled():
                return func(*args, **kwargs)  # No overhead when disabled
            
            # Extract metadata without exposing keys
            input_data = None
            if args and isinstance(args[0], (bytes, bytearray)):
                input_data = args[0]
            
            op_id = metrics.start_operation(
                operation_type=operation_type,
                algorithm=algorithm,
                security_level=security_level,
                input_data=input_data,
                metadata={"function": func.__name__}
            )
            
            try:
                result = func(*args, **kwargs)
                output_data = result if isinstance(result, bytes) else None
                metrics.end_operation(op_id, success=True, output_data=output_data)
                return result
            except Exception as e:
                metrics.end_operation(op_id, success=False, error_type=type(e).__name__)
                raise
        return wrapper
    return decorator


# Export public API
__all__ = [
    "CryptoMetricsCollector",
    "CryptoOperationType",
    "CryptoAlgorithm",
    "SecurityLevel",
    "get_crypto_metrics",
    "tracked_crypto_operation"
]
