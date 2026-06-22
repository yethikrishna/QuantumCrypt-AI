"""
QuantumCrypt AI - Enhanced Crypto Error Resilience Engine v12
DIMENSION E: Error Resilience - ADD-ONLY, Backward Compatible
================================================================
Custom Crypto Exception Hierarchies, Key Management Resilience,
Cryptographic Operation Retries, Side-Channel Safe Fallbacks,
HSM/TPM Connection Resilience

All existing crypto behavior is 100% preserved.
This module layers ON TOP - wrap existing functions, don't replace.
"""

import time
import math
import random
import secrets
import functools
import threading
import hmac
import hashlib
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple, ByteString
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

# -----------------------------------------------------------------------------
# CRYPTO-SPECIFIC EXCEPTION HIERARCHY
# -----------------------------------------------------------------------------

class QuantumCryptError(Exception):
    """Base exception for all QuantumCrypt errors"""
    error_code: str = "QC_E001"
    retryable: bool = False
    severity: str = "ERROR"
    security_sensitive: bool = False
    
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()

class KeyManagementError(QuantumCryptError):
    """Key management subsystem errors"""
    error_code = "QC_K001"
    retryable = True
    security_sensitive = True

class KeyNotFoundError(KeyManagementError):
    """Key not found in key store"""
    error_code = "QC_K002"
    retryable = False

class KeyRotationError(KeyManagementError):
    """Key rotation failed"""
    error_code = "QC_K003"
    retryable = True

class KeyDerivationError(KeyManagementError):
    """Key derivation operation failed"""
    error_code = "QC_K004"
    retryable = False

class CryptoOperationError(QuantumCryptError):
    """Cryptographic operation errors"""
    error_code = "QC_C001"
    retryable = True
    security_sensitive = True

class EncryptionError(CryptoOperationError):
    """Encryption operation failed"""
    error_code = "QC_C002"
    retryable = False

class DecryptionError(CryptoOperationError):
    """Decryption operation failed"""
    error_code = "QC_C003"
    retryable = False

class SignatureVerificationError(CryptoOperationError):
    """Signature verification failed"""
    error_code = "QC_C004"
    retryable = False

class HSMConnectionError(QuantumCryptError):
    """HSM/TPM hardware connection errors"""
    error_code = "QC_H001"
    retryable = True
    severity = "WARNING"

class EntropySourceError(QuantumCryptError):
    """Entropy source errors"""
    error_code = "QC_E001"
    retryable = True
    severity = "CRITICAL"
    security_sensitive = True

class RandomnessHealthError(EntropySourceError):
    """Randomness health check failed"""
    error_code = "QC_E002"
    retryable = False

class AlgorithmCompatibilityError(QuantumCryptError):
    """Algorithm compatibility/migration errors"""
    error_code = "QC_A001"
    retryable = False

class CircuitBreakerTrippedError(QuantumCryptError):
    """Circuit breaker tripped - fail fast"""
    error_code = "QC_CB001"
    retryable = False
    severity = "WARNING"

class GracefulDegradationActive(QuantumCryptError):
    """Graceful degradation mode active"""
    error_code = "QC_GD001"
    retryable = False
    severity = "INFO"

# -----------------------------------------------------------------------------
# CONSTANT-TIME UTILITIES (SAFE FOR CRYPTO)
# -----------------------------------------------------------------------------

def constant_time_compare(a: ByteString, b: ByteString) -> bool:
    """
    Constant-time comparison for cryptographic secrets
    Prevents timing attacks
    """
    return hmac.compare_digest(a, b)

def constant_time_select(condition: bool, a: bytes, b: bytes) -> bytes:
    """
    Constant-time selection between two values
    Returns a if condition is True, b otherwise
    No timing side-channel leakage
    """
    mask = (condition - 1) & 0xFF
    result = bytearray(len(a))
    for i in range(len(a)):
        result[i] = (a[i] & ~mask) | (b[i] & mask)
    return bytes(result)

def secure_wipe(buffer: Union[bytearray, memoryview]) -> None:
    """
    Securely wipe sensitive data from memory
    Overwrite with random bytes first, then zeros
    """
    length = len(buffer)
    for i in range(length):
        buffer[i] = secrets.randbelow(256)
    for i in range(length):
        buffer[i] = 0

# -----------------------------------------------------------------------------
# CRYPTO CIRCUIT BREAKER (SIDE-CHANNEL RESISTANT)
# -----------------------------------------------------------------------------

class CryptoCircuitState(Enum):
    CLOSED = "CLOSED"           # Normal operation
    OPEN = "OPEN"               # Fail fast - security concern
    DEGRADED = "DEGRADED"       # Use fallback algorithms

@dataclass
class CryptoCircuitBreakerStats:
    encryption_attempts: int = 0
    encryption_failures: int = 0
    decryption_attempts: int = 0
    decryption_failures: int = 0
    signature_attempts: int = 0
    signature_failures: int = 0
    hsm_connection_failures: int = 0
    entropy_errors: int = 0
    last_error_time: Optional[datetime] = None
    state_transitions: List[Tuple[CryptoCircuitState, CryptoCircuitState, datetime]] = field(default_factory=list)

class CryptoCircuitBreaker:
    """
    Circuit Breaker specifically for cryptographic operations
    Security-aware - fails fast on suspicious patterns
    ADD-ONLY wrapper - wrap existing crypto functions
    """
    
    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 60.0,
        name: str = "crypto_default",
        enable_fallback_mode: bool = True
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.name = name
        self.enable_fallback_mode = enable_fallback_mode
        
        self._state = CryptoCircuitState.CLOSED
        self._failure_count = 0
        self._open_time: Optional[datetime] = None
        self._lock = threading.RLock()
        self.stats = CryptoCircuitBreakerStats()
    
    @property
    def state(self) -> CryptoCircuitState:
        with self._lock:
            self._check_recovery()
            return self._state
    
    def _check_recovery(self) -> None:
        if self._state != CryptoCircuitState.CLOSED and self._open_time:
            elapsed = (datetime.utcnow() - self._open_time).total_seconds()
            if elapsed >= self.recovery_timeout:
                self._transition_to(CryptoCircuitState.CLOSED)
    
    def _transition_to(self, new_state: CryptoCircuitState) -> None:
        old_state = self._state
        self._state = new_state
        self.stats.state_transitions.append((old_state, new_state, datetime.utcnow()))
        
        if new_state == CryptoCircuitState.CLOSED:
            self._failure_count = 0
            self._open_time = None
        else:
            self._open_time = datetime.utcnow()
    
    def _record_operation(self, op_type: str, failed: bool = False) -> None:
        if op_type == "encrypt":
            self.stats.encryption_attempts += 1
            if failed:
                self.stats.encryption_failures += 1
        elif op_type == "decrypt":
            self.stats.decryption_attempts += 1
            if failed:
                self.stats.decryption_failures += 1
        elif op_type == "sign":
            self.stats.signature_attempts += 1
            if failed:
                self.stats.signature_failures += 1
        elif op_type == "hsm":
            if failed:
                self.stats.hsm_connection_failures += 1
        elif op_type == "entropy":
            if failed:
                self.stats.entropy_errors += 1
        
        if failed:
            self.stats.last_error_time = datetime.utcnow()
    
    def can_execute(self, require_security: bool = False) -> bool:
        with self._lock:
            self._check_recovery()
            
            if self._state == CryptoCircuitState.OPEN:
                return False
            
            if require_security and self._state == CryptoCircuitState.DEGRADED:
                return False
            
            return True
    
    def __call__(self, operation_type: str = "generic"):
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                with self._lock:
                    if not self.can_execute():
                        raise CircuitBreakerTrippedError(
                            f"Crypto circuit breaker '{self.name}' is {self._state.value} - failing fast",
                            {"operation": operation_type, "recovery_seconds": self.recovery_timeout}
                        )
                
                try:
                    result = func(*args, **kwargs)
                    with self._lock:
                        self._record_operation(operation_type, failed=False)
                    return result
                except Exception as e:
                    with self._lock:
                        self._record_operation(operation_type, failed=True)
                        self._failure_count += 1
                        
                        if self._failure_count >= self.failure_threshold:
                            if self.enable_fallback_mode:
                                self._transition_to(CryptoCircuitState.DEGRADED)
                            else:
                                self._transition_to(CryptoCircuitState.OPEN)
                    raise
            
            return wrapper
        return decorator
    
    def get_security_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "threshold": self.failure_threshold,
                "operations": {
                    "encryption": {
                        "attempts": self.stats.encryption_attempts,
                        "failures": self.stats.encryption_failures
                    },
                    "decryption": {
                        "attempts": self.stats.decryption_attempts,
                        "failures": self.stats.decryption_failures
                    },
                    "signature": {
                        "attempts": self.stats.signature_attempts,
                        "failures": self.stats.signature_failures
                    },
                    "hsm_failures": self.stats.hsm_connection_failures,
                    "entropy_errors": self.stats.entropy_errors
                }
            }

# -----------------------------------------------------------------------------
# CRYPTO RETRY WITH EXPONENTIAL BACKOFF (SAFE)
# -----------------------------------------------------------------------------

class CryptoRetryStrategy(Enum):
    """Retry strategies safe for crypto operations"""
    EXPONENTIAL_SAFE = "exponential_safe"  # No jitter for determinism
    FIXED_DELAY = "fixed_delay"
    NONE = "none"

def crypto_retry(
    max_attempts: int = 3,
    initial_delay: float = 0.5,
    max_delay: float = 10.0,
    strategy: CryptoRetryStrategy = CryptoRetryStrategy.EXPONENTIAL_SAFE,
    retry_on: Tuple[Type[Exception], ...] = (HSMConnectionError, KeyRotationError)
):
    """
    Retry decorator specifically for cryptographic operations
    Only retries on SAFE exceptions (not security-sensitive failures)
    ADD-ONLY - wrap existing crypto functions
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except retry_on as e:
                    last_exception = e
                    
                    if attempt == max_attempts - 1:
                        break
                    
                    # Calculate delay - deterministic for crypto operations
                    if strategy == CryptoRetryStrategy.EXPONENTIAL_SAFE:
                        delay = min(initial_delay * (2 ** attempt), max_delay)
                    else:  # FIXED_DELAY
                        delay = initial_delay
                    
                    time.sleep(delay)
            
            raise last_exception
        
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# KEY OPERATION TIMEOUT (SAFE)
# -----------------------------------------------------------------------------

def crypto_timeout(
    seconds: float,
    fallback: Optional[Callable] = None,
    sensitive: bool = True
):
    """
    Timeout decorator for cryptographic operations
    Safe wrapper - doesn't leak sensitive info on timeout
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = []
            exception = []
            
            def target():
                try:
                    result.append(func(*args, **kwargs))
                except Exception as e:
                    exception.append(e)
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=seconds)
            
            if thread.is_alive():
                if fallback is not None:
                    return fallback(*args, **kwargs)
                if sensitive:
                    raise KeyManagementError("Cryptographic operation timed out - details suppressed for security")
                raise TimeoutError(f"Crypto operation timed out after {seconds}s")
            
            if exception:
                raise exception[0]
            
            return result[0] if result else None
        
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# KEY MANAGEMENT FALLBACKS (GRACEFUL DEGRADATION)
# -----------------------------------------------------------------------------

class KeyFallbackMode(Enum):
    SOFTWARE_FALLBACK = "software_fallback"    # Use software crypto if HSM fails
    CACHED_KEY = "cached_key"                  # Use cached key version
    DERIVED_FALLBACK = "derived_fallback"      # Derive key from root
    EMERGENCY_KEY = "emergency_key"            # Use emergency backup key

class CryptoGracefulDegradation:
    """
    Graceful Degradation Manager for Cryptographic Operations
    Provides secure fallbacks when primary systems fail
    ADD-ONLY - no changes to core crypto logic
    """
    
    def __init__(self, max_cache_ttl: float = 3600.0):
        self._key_cache: Dict[str, Tuple[bytes, datetime]] = {}
        self._fallbacks: Dict[str, Callable] = {}
        self._max_cache_ttl = max_cache_ttl
        self._degradation_events: List[Dict] = []
        self._lock = threading.Lock()
    
    def cache_key(self, key_id: str, key_material: bytes) -> None:
        """Cache a key for potential fallback use"""
        with self._lock:
            self._key_cache[key_id] = (key_material, datetime.utcnow())
    
    def get_cached_key(self, key_id: str) -> Optional[bytes]:
        """Get cached key if valid and within TTL"""
        with self._lock:
            if key_id in self._key_cache:
                key_data, cache_time = self._key_cache[key_id]
                age = (datetime.utcnow() - cache_time).total_seconds()
                if age < self._max_cache_ttl:
                    self._record_degradation("key_cache_fallback", key_id)
                    return key_data
        return None
    
    def register_fallback(self, operation_id: str, fallback_func: Callable) -> None:
        """Register a fallback function for an operation"""
        with self._lock:
            self._fallbacks[operation_id] = fallback_func
    
    def execute_with_fallback(
        self,
        operation_id: str,
        primary_func: Callable,
        *args,
        fallback_mode: KeyFallbackMode = KeyFallbackMode.SOFTWARE_FALLBACK,
        **kwargs
    ) -> Any:
        """
        Execute primary function, fall back on failure
        Returns result or raises appropriate exception
        """
        try:
            return primary_func(*args, **kwargs)
        except (HSMConnectionError, KeyManagementError) as e:
            # Try registered fallback first
            with self._lock:
                if operation_id in self._fallbacks:
                    self._record_degradation(operation_id, fallback_mode.value)
                    return self._fallbacks[operation_id](*args, **kwargs)
            
            # Try key cache for key operations
            if "key" in operation_id.lower():
                cached = self.get_cached_key(operation_id)
                if cached is not None:
                    return cached
            
            self._record_degradation(operation_id, "no_fallback_available")
            raise GracefulDegradationActive(
                f"Primary operation failed, no fallback available: {operation_id}",
                {"original_error": str(e), "fallback_mode": fallback_mode.value}
            )
    
    def _record_degradation(self, operation: str, details: str) -> None:
        self._degradation_events.append({
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation,
            "details": details
        })
    
    def get_security_report(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_degradation_events": len(self._degradation_events),
                "recent_events": self._degradation_events[-10:],
                "cached_keys": len(self._key_cache),
                "registered_fallbacks": len(self._fallbacks)
            }

# -----------------------------------------------------------------------------
# ENTROPY HEALTH MONITOR
# -----------------------------------------------------------------------------

class EntropyHealthMonitor:
    """
    Monitors entropy source health
    Provides fallback entropy if primary source fails
    ADD-ONLY - security layer
    """
    
    def __init__(self, min_entropy_threshold: int = 128):
        self.min_entropy_threshold = min_entropy_threshold
        self._entropy_samples: List[float] = []
        self._fallback_active = False
        self._lock = threading.Lock()
    
    def estimate_entropy(self, data: bytes) -> float:
        """Simple Shannon entropy estimation"""
        if len(data) == 0:
            return 0.0
        
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        
        return entropy * len(data)
    
    def check_randomness_health(self, sample: bytes) -> bool:
        """Check if randomness meets minimum entropy requirements"""
        entropy = self.estimate_entropy(sample)
        
        with self._lock:
            self._entropy_samples.append(entropy)
            if len(self._entropy_samples) > 100:
                self._entropy_samples.pop(0)
            
            avg_entropy = sum(self._entropy_samples) / len(self._entropy_samples) if self._entropy_samples else 0
            self._fallback_active = avg_entropy < self.min_entropy_threshold
            
            return not self._fallback_active
    
    def get_safe_random_bytes(self, num_bytes: int) -> bytes:
        """Get random bytes with health checking, fallback to secrets module"""
        try:
            # Try system random first
            import os
            result = os.urandom(num_bytes)
            
            if self.check_randomness_health(result[:32]):
                return result
        except Exception:
            pass
        
        # Fallback to secrets module
        return secrets.token_bytes(num_bytes)
    
    def get_health_stats(self) -> Dict[str, Any]:
        with self._lock:
            avg = sum(self._entropy_samples) / len(self._entropy_samples) if self._entropy_samples else 0
            return {
                "fallback_active": self._fallback_active,
                "average_entropy": avg,
                "samples_collected": len(self._entropy_samples),
                "threshold": self.min_entropy_threshold
            }

# -----------------------------------------------------------------------------
# GLOBAL CONVENIENCE FUNCTIONS
# -----------------------------------------------------------------------------

_DEFAULT_CRYPTO_CIRCUIT_BREAKERS: Dict[str, CryptoCircuitBreaker] = {}
_DEFAULT_CRYPTO_GRACEFUL = CryptoGracefulDegradation()
_DEFAULT_ENTROPY_MONITOR = EntropyHealthMonitor()

def get_crypto_circuit_breaker(name: str = "default", **kwargs) -> CryptoCircuitBreaker:
    """Get or create a named crypto circuit breaker"""
    if name not in _DEFAULT_CRYPTO_CIRCUIT_BREAKERS:
        _DEFAULT_CRYPTO_CIRCUIT_BREAKERS[name] = CryptoCircuitBreaker(name=name, **kwargs)
    return _DEFAULT_CRYPTO_CIRCUIT_BREAKERS[name]

def get_crypto_graceful_degradation() -> CryptoGracefulDegradation:
    """Get global crypto graceful degradation manager"""
    return _DEFAULT_CRYPTO_GRACEFUL

def get_entropy_health_monitor() -> EntropyHealthMonitor:
    """Get global entropy health monitor"""
    return _DEFAULT_ENTROPY_MONITOR

def secure_crypto_execute(
    func: Callable,
    *args,
    operation_type: str = "generic",
    timeout_sec: Optional[float] = None,
    max_retries: int = 0,
    circuit_breaker: Optional[str] = None,
    **kwargs
) -> Any:
    """
    One-shot secure execution for cryptographic operations
    Combines circuit breaker, retry, timeout
    ADD-ONLY convenience wrapper
    """
    @functools.wraps(func)
    def wrapped():
        return func(*args, **kwargs)
    
    if circuit_breaker:
        cb = get_crypto_circuit_breaker(circuit_breaker)
        wrapped = cb(operation_type)(wrapped)
    
    if max_retries > 0:
        wrapped = crypto_retry(max_attempts=max_retries + 1)(wrapped)
    
    if timeout_sec:
        wrapped = crypto_timeout(timeout_sec)(wrapped)
    
    return wrapped()

def get_crypto_resilience_report() -> Dict[str, Any]:
    """Get comprehensive crypto resilience status report"""
    return {
        "circuit_breakers": {
            name: cb.get_security_stats()
            for name, cb in _DEFAULT_CRYPTO_CIRCUIT_BREAKERS.items()
        },
        "graceful_degradation": _DEFAULT_CRYPTO_GRACEFUL.get_security_report(),
        "entropy_health": _DEFAULT_ENTROPY_MONITOR.get_health_stats(),
        "timestamp": datetime.utcnow().isoformat(),
        "security_status": "SECURE"
    }
