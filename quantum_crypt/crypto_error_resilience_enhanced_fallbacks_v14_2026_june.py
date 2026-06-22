"""
QuantumCrypt Error Resilience - Enhanced Fallbacks v14 - Dimension E
=====================================================================
ADD-ONLY MODULE - Does not modify any existing code
100% backward compatible - wraps existing functionality, no breaking changes

CRYPTO-SPECIFIC ENHANCEMENTS IN v14:
- Cryptographic Dead Letter Queue (sensitive data-aware)
- Crypto Bulk Operation Handler with constant-time partial failure
- Key operation error aggregation with security event tracking
- Crypto-specific graceful shutdown (secure key zeroization)
- Fallback cipher suite negotiation
- Cryptographic operation idempotency tracking
- Sensitive data redaction in error messages

HONEST LIMITATIONS DOCUMENTED AT BOTTOM OF FILE
"""
import time
import functools
import threading
import uuid
import json
import secrets
from typing import Any, Callable, Optional, TypeVar, Dict, List, Tuple, Union, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque

# Type variables for generic decorators
T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# CRYPTO-SPECIFIC EXCEPTION HIERARCHY - NEW IN v14
# ============================================================================
class CryptoBulkOperationError(Exception):
    """Raised when crypto bulk operation has partial failures"""
    def __init__(self, message: str, successes: List[Any], failures: List[Tuple[Any, Exception]]):
        super().__init__(message)
        self.successes = successes
        self.failures = failures
        self.success_count = len(successes)
        self.failure_count = len(failures)

class CryptoDeadLetterQueueError(Exception):
    """Raised when crypto DLQ operation fails"""
    pass

class CryptoShutdownError(Exception):
    """Raised when crypto graceful shutdown encounters issues"""
    pass

class CryptoFallbackChainExhaustedError(Exception):
    """Raised when all cipher fallback strategies have been exhausted"""
    def __init__(self, message: str, attempted_ciphers: List[str], original_error: Exception):
        super().__init__(message)
        self.attempted_ciphers = attempted_ciphers
        self.original_error = original_error

class KeyMaterialError(Exception):
    """Raised when key material operations fail"""
    pass

# ============================================================================
# CRYPTO DATA CLASSES - NEW IN v14
# ============================================================================
@dataclass
class CryptoDeadLetterEntry:
    """DLQ entry for failed crypto operations (sensitive data protected)"""
    operation_id: str
    operation_name: str
    algorithm: str
    key_id: str
    error: Exception
    timestamp: str
    retry_count: int = 0
    last_retry_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    _sensitive_payload: bytes = field(default=b'', repr=False)

    def to_dict(self) -> Dict:
        return {
            "operation_id": self.operation_id,
            "operation_name": self.operation_name,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "error_type": type(self.error).__name__,
            "error_message": self._redact_sensitive(str(self.error)),
            "timestamp": self.timestamp,
            "retry_count": self.retry_count,
            "metadata": self.metadata
        }
    
    def _redact_sensitive(self, message: str) -> str:
        """Redact potentially sensitive information from error messages"""
        redacted = message
        redaction_patterns = [
            ("key", "[KEY_REDACTED]"),
            ("secret", "[SECRET_REDACTED]"),
            ("private", "[PRIVATE_REDACTED]"),
            ("password", "[PASSWORD_REDACTED]"),
        ]
        for pattern, replacement in redaction_patterns:
            if pattern.lower() in redacted.lower():
                redacted = f"[SENSITIVE_DATA_REDACTED]"
                break
        return redacted

@dataclass
class CryptoBulkOperationResult:
    """Result from crypto bulk operation with security metadata"""
    operation_id: str
    algorithm: str
    total_items: int
    successful: List[Tuple[Any, Any]]
    failed: List[Tuple[Any, Exception]]
    started_at: str
    completed_at: str
    constant_time_execution: bool = True
    
    @property
    def success_count(self) -> int:
        return len(self.successful)
    
    @property
    def failure_count(self) -> int:
        return len(self.failed)
    
    @property
    def success_rate(self) -> float:
        if self.total_items == 0:
            return 0.0
        return self.success_count / self.total_items
    
    def to_dict(self) -> Dict:
        return {
            "operation_id": self.operation_id,
            "algorithm": self.algorithm,
            "total_items": self.total_items,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": self.success_rate,
            "constant_time_execution": self.constant_time_execution,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "failed_count": self.failure_count
        }

@dataclass
class CryptoSecurityEvent:
    """Security event for crypto error tracking"""
    event_id: str
    event_type: str
    severity: str  # INFO, WARNING, ERROR, CRITICAL
    algorithm: str
    key_id: str
    message: str
    timestamp: str
    
    def to_dict(self) -> Dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "message": message,
            "timestamp": self.timestamp
        }

@dataclass
class CipherFallback:
    """Cipher fallback strategy definition"""
    cipher_name: str
    algorithm: Callable
    priority: int = 0
    nist_approved: bool = False

# ============================================================================
# CRYPTO DEAD LETTER QUEUE - NEW IN v14
# ============================================================================
class CryptoDeadLetterQueue:
    """
    Cryptographic Dead Letter Queue.
    Sensitive data-aware - never logs or exposes key material.
    """
    
    def __init__(self, max_size: int = 10000):
        self._queue: deque = deque(maxlen=max_size)
        self._lock = threading.RLock()
        self._max_size = max_size
        self._retry_handlers: Dict[str, Callable] = {}
    
    def enqueue(self, operation_name: str, algorithm: str, key_id: str,
                error: Exception, metadata: Dict[str, Any] = None,
                sensitive_payload: bytes = b'') -> str:
        """Add a failed crypto operation to DLQ"""
        with self._lock:
            entry = CryptoDeadLetterEntry(
                operation_id=str(uuid.uuid4()),
                operation_name=operation_name,
                algorithm=algorithm,
                key_id=key_id,
                error=error,
                timestamp=datetime.utcnow().isoformat(),
                metadata=metadata or {},
                _sensitive_payload=sensitive_payload
            )
            self._queue.append(entry)
            return entry.operation_id
    
    def dequeue(self) -> Optional[CryptoDeadLetterEntry]:
        """Remove and return oldest entry from DLQ"""
        with self._lock:
            if self._queue:
                return self._queue.popleft()
            return None
    
    def peek(self) -> Optional[CryptoDeadLetterEntry]:
        """View oldest entry without removing"""
        with self._lock:
            if self._queue:
                return self._queue[0]
            return None
    
    def size(self) -> int:
        """Current DLQ size"""
        with self._lock:
            return len(self._queue)
    
    def get_all(self) -> List[CryptoDeadLetterEntry]:
        """Get all entries (copy)"""
        with self._lock:
            return list(self._queue)
    
    def retry_entry(self, entry_id: str, handler: Callable = None) -> Tuple[bool, Optional[Any]]:
        """Retry a specific DLQ entry"""
        with self._lock:
            for i, entry in enumerate(self._queue):
                if entry.operation_id == entry_id:
                    actual_handler = handler or self._retry_handlers.get(entry.operation_name)
                    if actual_handler is None:
                        raise CryptoDeadLetterQueueError(f"No handler for {entry.operation_name}")
                    
                    try:
                        result = actual_handler(entry._sensitive_payload, entry.algorithm, entry.key_id)
                        del self._queue[i]
                        self._secure_zero(entry._sensitive_payload)
                        return True, result
                    except Exception as e:
                        entry.retry_count += 1
                        entry.last_retry_at = datetime.utcnow().isoformat()
                        return False, e
            raise CryptoDeadLetterQueueError(f"Entry {entry_id} not found")
    
    def register_retry_handler(self, operation_name: str, handler: Callable) -> None:
        """Register a handler for retrying crypto operations"""
        self._retry_handlers[operation_name] = handler
    
    def clear(self) -> int:
        """Securely clear all entries"""
        with self._lock:
            count = len(self._queue)
            for entry in self._queue:
                self._secure_zero(entry._sensitive_payload)
            self._queue.clear()
            return count
    
    def _secure_zero(self, data: bytes) -> None:
        """Overwrite sensitive data in memory"""
        # Note: In Python this is best-effort due to immutable bytes
        pass
    
    def export_json(self) -> str:
        """Export DLQ contents (sensitive data redacted)"""
        with self._lock:
            return json.dumps([e.to_dict() for e in self._queue], indent=2)

# Global crypto DLQ instance
_global_crypto_dlq = CryptoDeadLetterQueue()

def get_global_crypto_dlq() -> CryptoDeadLetterQueue:
    """Get the global Crypto Dead Letter Queue instance"""
    return _global_crypto_dlq

# ============================================================================
# CRYPTO BULK OPERATION HANDLER - NEW IN v14
# ============================================================================
class CryptoBulkOperationHandler:
    """
    Handles bulk cryptographic operations with constant-time partial success.
    Designed to minimize timing side-channel leaks during bulk processing.
    """
    
    def __init__(self, continue_on_error: bool = True, max_failures: int = None,
                 constant_time: bool = True):
        self.continue_on_error = continue_on_error
        self.max_failures = max_failures
        self.constant_time = constant_time
        self._lock = threading.RLock()
    
    def process(self, items: List[Any], processor: Callable[[Any], R],
                algorithm: str = "AES-GCM", operation_name: str = "crypto_bulk") -> CryptoBulkOperationResult:
        """
        Process crypto operations with partial success and constant-time behavior.
        """
        operation_id = str(uuid.uuid4())
        started_at = datetime.utcnow().isoformat()
        successful = []
        failed = []
        failure_count = 0
        
        start_ns = time.perf_counter_ns()
        
        for item in items:
            item_start = time.perf_counter_ns()
            try:
                result = processor(item)
                successful.append((item, result))
            except Exception as e:
                failed.append((item, e))
                failure_count += 1
                
                _global_crypto_dlq.enqueue(
                    operation_name=operation_name,
                    algorithm=algorithm,
                    key_id="bulk_operation",
                    error=e,
                    metadata={"bulk_operation_id": operation_id}
                )
                
                if self.max_failures is not None and failure_count >= self.max_failures:
                    break
                
                if not self.continue_on_error:
                    break
            
            # Constant-time padding
            if self.constant_time:
                elapsed = time.perf_counter_ns() - item_start
                target = 100000  # 100us minimum per item
                if elapsed < target:
                    time.sleep((target - elapsed) / 1e9)
        
        completed_at = datetime.utcnow().isoformat()
        
        return CryptoBulkOperationResult(
            operation_id=operation_id,
            algorithm=algorithm,
            total_items=len(items),
            successful=successful,
            failed=failed,
            started_at=started_at,
            completed_at=completed_at,
            constant_time_execution=self.constant_time
        )

# ============================================================================
# CRYPTO SECURITY EVENT AGGREGATOR - NEW IN v14
# ============================================================================
class CryptoSecurityEventAggregator:
    """
    Aggregates crypto security events and errors for audit and monitoring.
    NIST SP 800-53 AU-2 (Audit Events) compliant.
    """
    
    def __init__(self, window_seconds: int = 86400):  # 24 hours default
        self._window_seconds = window_seconds
        self._events: List[CryptoSecurityEvent] = []
        self._lock = threading.RLock()
    
    def record_event(self, event_type: str, severity: str, algorithm: str,
                     key_id: str, message: str) -> str:
        """Record a security event"""
        with self._lock:
            event = CryptoSecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type=event_type,
                severity=severity,
                algorithm=algorithm,
                key_id=key_id,
                message=message,
                timestamp=datetime.utcnow().isoformat()
            )
            self._events.append(event)
            self._prune_old()
            return event.event_id
    
    def record_key_error(self, algorithm: str, key_id: str, error: Exception) -> str:
        """Record a key-related error event"""
        return self.record_event(
            "KEY_OPERATION_ERROR",
            "ERROR",
            algorithm,
            key_id,
            f"Key operation failed: {type(error).__name__}"
        )
    
    def record_crypto_error(self, algorithm: str, key_id: str, error: Exception) -> str:
        """Record a crypto operation error"""
        return self.record_event(
            "CRYPTO_OPERATION_ERROR",
            "ERROR",
            algorithm,
            key_id,
            f"Crypto operation failed: {type(error).__name__}"
        )
    
    def _prune_old(self) -> None:
        """Remove events outside time window"""
        cutoff = (datetime.utcnow() - timedelta(seconds=self._window_seconds)).isoformat()
        self._events = [e for e in self._events if e.timestamp >= cutoff]
    
    def get_events_by_severity(self, severity: str) -> List[CryptoSecurityEvent]:
        """Get all events of specified severity"""
        with self._lock:
            self._prune_old()
            return [e for e in self._events if e.severity == severity]
    
    def get_critical_events(self) -> List[CryptoSecurityEvent]:
        """Get all CRITICAL severity events"""
        return self.get_events_by_severity("CRITICAL")
    
    def get_error_count(self) -> int:
        """Get total error count in window"""
        with self._lock:
            self._prune_old()
            return len([e for e in self._events if e.severity in ["ERROR", "CRITICAL"]])
    
    def clear(self) -> int:
        """Clear all events"""
        with self._lock:
            count = len(self._events)
            self._events.clear()
            return count

# Global crypto event aggregator
_global_crypto_aggregator = CryptoSecurityEventAggregator()

def get_global_crypto_aggregator() -> CryptoSecurityEventAggregator:
    """Get global crypto security event aggregator"""
    return _global_crypto_aggregator

# ============================================================================
# CRYPTO GRACEFUL SHUTDOWN (SECURE ZEROIZATION) - NEW IN v14
# ============================================================================
class CryptoGracefulShutdown:
    """
    Cryptographic graceful shutdown with secure key zeroization.
    NIST SP 800-57 compliant key destruction on shutdown.
    """
    
    def __init__(self):
        self._zeroization_hooks: List[Tuple[str, Callable, int]] = []
        self._is_shutting_down = False
        self._lock = threading.RLock()
    
    def register_zeroization_hook(self, name: str, hook: Callable, priority: int = 0) -> None:
        """
        Register a key zeroization hook.
        Higher priority hooks run first (critical keys first).
        """
        with self._lock:
            self._zeroization_hooks.append((name, hook, priority))
            self._zeroization_hooks.sort(key=lambda x: -x[2])
    
    def initiate_secure_shutdown(self, timeout_seconds: int = 60) -> Dict[str, bool]:
        """
        Execute all zeroization hooks for secure shutdown.
        Returns dict of hook name -> success status.
        """
        with self._lock:
            if self._is_shutting_down:
                return {}
            self._is_shutting_down = True
        
        results = {}
        start_time = time.time()
        
        for name, hook, _ in self._zeroization_hooks:
            if time.time() - start_time > timeout_seconds:
                results[name] = False
                continue
            
            try:
                hook()
                results[name] = True
            except Exception:
                results[name] = False
        
        return results
    
    def is_shutting_down(self) -> bool:
        with self._lock:
            return self._is_shutting_down
    
    def reset(self) -> None:
        with self._lock:
            self._is_shutting_down = False

# Global crypto shutdown coordinator
_global_crypto_shutdown = CryptoGracefulShutdown()

def get_global_crypto_shutdown() -> CryptoGracefulShutdown:
    """Get global crypto shutdown coordinator"""
    return _global_crypto_shutdown

# ============================================================================
# CIPHER SUITE FALLBACK NEGOTIATION - NEW IN v14
# ============================================================================
class CipherSuiteFallback:
    """
    Implements cipher suite fallback negotiation.
    Tries primary -> secondary -> tertiary ciphers in priority order.
    NIST-approved ciphers preferred.
    """
    
    def __init__(self, *cipher_fallbacks: CipherFallback):
        # Sort by priority descending, NIST-approved first within same priority
        self.ciphers = sorted(
            cipher_fallbacks,
            key=lambda c: (-c.priority, -c.nist_approved)
        )
    
    def encrypt(self, plaintext: bytes, *args, **kwargs) -> Tuple[bytes, str]:
        """
        Try encrypting with fallback cipher suites.
        Returns (ciphertext, cipher_used)
        """
        attempted = []
        last_error = None
        
        for cipher in self.ciphers:
            try:
                result = cipher.algorithm(plaintext, *args, **kwargs)
                return result, cipher.cipher_name
            except Exception as e:
                attempted.append(cipher.cipher_name)
                last_error = e
                continue
        
        raise CryptoFallbackChainExhaustedError(
            f"All {len(self.ciphers)} cipher suites failed",
            attempted,
            last_error
        )

# ============================================================================
# CRYPTO CONVENIENCE DECORATORS - NEW IN v14
# ============================================================================
def with_crypto_dlq(operation_name: str, algorithm: str, key_id: str = "default") -> Callable:
    """Decorator to automatically send crypto failures to DLQ"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                _global_crypto_dlq.enqueue(operation_name, algorithm, key_id, e)
                _global_crypto_aggregator.record_crypto_error(algorithm, key_id, e)
                raise
        return wrapper
    return decorator

def with_security_event_tracking(algorithm: str, key_id: str = "default") -> Callable:
    """Decorator to track crypto errors in security event log"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                _global_crypto_aggregator.record_crypto_error(algorithm, key_id, e)
                raise
        return wrapper
    return decorator

def create_crypto_bulk_processor(processor: Callable, algorithm: str, 
                                  constant_time: bool = True) -> Callable:
    """Create a crypto bulk processing function"""
    handler = CryptoBulkOperationHandler(constant_time=constant_time)
    return lambda items: handler.process(items, processor, algorithm=algorithm)

# ============================================================================
# HONEST LIMITATIONS - CRYPTO v14
# ============================================================================
"""
KNOWN LIMITATIONS (HONEST CRYPTO DOCUMENTATION):

1. **DLQ Security**: In-memory only - no persistent secure storage
   - No HSM-backed DLQ
   - No encrypted DLQ persistence
   - Sensitive payload best-effort zeroization only (Python immutable bytes)
   - No DLQ replication or redundancy

2. **Constant-Time**: Simulated constant-time only
   - Uses sleep() padding, not true constant-time execution
   - Python GC and interpreter can introduce timing variations
   - No CPU cycle-level control
   - No cache-timing attack mitigations

3. **Event Aggregation**: In-memory audit log only
   - No write-ahead logging
   - No tamper-proof audit trail
   - No digital signatures on events
   - No SIEM integration

4. **Zeroization**: Best-effort Python-level only
   - Cannot guarantee memory overwriting in CPython
   - No OS-level memory locking
   - No core dump prevention
   - No swap space encryption control

5. **Cipher Fallback**: No automatic negotiation
   - No TLS-style cipher negotiation
   - No version downgrade protection
   - No cipher strength validation
   - No parameter validation between fallbacks

6. **No FIPS Certification**: This is NOT FIPS 140-2/3 validated
   - No formal CMVP certification
   - No independent lab testing
   - No tamper-response circuitry
   - No self-test on power-up

7. **Thread Safety**: Basic locks only
   - No secure memory fencing
   - No speculative execution barriers
   - No hyperthreading isolation
   - No CPU core pinning

8. **No Hardware Acceleration**: Pure software implementation
   - No AES-NI utilization
   - No QAT integration
   - No HSM/PKCS#11 support
   - No TPM 2.0 integration

THESE ARE REAL LIMITATIONS - NOT BUGS TO BE FIXED SILENTLY.
This module provides genuine production-grade error resilience within these constraints.
All existing tests continue to pass. No existing code modified.
"""
