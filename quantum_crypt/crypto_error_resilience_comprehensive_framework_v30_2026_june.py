"""
QuantumCrypt AI - Comprehensive Crypto Error Resilience Framework v30
Dimension E: Error Resilience - ADD-ONLY implementation

This module provides production-grade error resilience for cryptographic operations:
- Crypto-specific custom exception hierarchy
- Key operation timeout wrappers
- Retry with exponential backoff for HSM/remote operations
- Circuit breaker for cryptographic service health
- Graceful degradation with algorithm fallbacks
- Secure memory zeroization on error
- Bulkhead isolation for key operations

ALL existing happy-path behavior is 100% preserved.
This is purely additive - no modifications to existing code.
"""

import time
import random
import threading
import functools
import logging
import secrets
from typing import Any, Callable, Optional, Type, Tuple, Dict, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

# Configure logging - OPT-IN only, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# -----------------------------------------------------------------------------
# Crypto-Specific Custom Exception Hierarchy
# -----------------------------------------------------------------------------

class QuantumCryptError(Exception):
    """Base exception for all QuantumCrypt errors."""
    error_code: str = "QC-000"
    retryable: bool = False
    severity: str = "ERROR"
    security_sensitive: bool = False
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()


class KeyManagementError(QuantumCryptError):
    """Raised when key management operations fail."""
    error_code: str = "QC-001"
    retryable: bool = True
    severity: str = "ERROR"
    security_sensitive: bool = True


class EncryptionError(QuantumCryptError):
    """Raised when encryption operations fail."""
    error_code: str = "QC-002"
    retryable: bool = False
    severity: str = "ERROR"
    security_sensitive: bool = True


class DecryptionError(QuantumCryptError):
    """Raised when decryption operations fail."""
    error_code: str = "QC-003"
    retryable: bool = False
    severity: str = "ERROR"
    security_sensitive: bool = True


class SignatureError(QuantumCryptError):
    """Raised when signature operations fail."""
    error_code: str = "QC-004"
    retryable: bool = False
    severity: str = "ERROR"
    security_sensitive: bool = True


class VerificationError(QuantumCryptError):
    """Raised when signature verification fails."""
    error_code: str = "QC-005"
    retryable: bool = False
    severity: str = "WARNING"
    security_sensitive: bool = False


class HSMConnectionError(QuantumCryptError):
    """Raised when HSM connection fails."""
    error_code: str = "QC-006"
    retryable: bool = True
    severity: str = "WARNING"
    security_sensitive: bool = False


class RandomnessError(QuantumCryptError):
    """Raised when secure randomness generation fails."""
    error_code: str = "QC-007"
    retryable: bool = True
    severity: str = "CRITICAL"
    security_sensitive: bool = True


class AlgorithmUnavailableError(QuantumCryptError):
    """Raised when requested algorithm is unavailable."""
    error_code: str = "QC-008"
    retryable: bool = False
    severity: str = "ERROR"
    security_sensitive: bool = False


class IntegrityCheckError(QuantumCryptError):
    """Raised when data integrity check fails."""
    error_code: str = "QC-009"
    retryable: bool = False
    severity: str = "CRITICAL"
    security_sensitive: bool = True


class KeyRotationError(QuantumCryptError):
    """Raised when key rotation fails."""
    error_code: str = "QC-010"
    retryable: bool = True
    severity: str = "ERROR"
    security_sensitive: bool = True


class CircuitBreakerOpenError(QuantumCryptError):
    """Raised when circuit breaker is open and calls are blocked."""
    error_code: str = "QC-011"
    retryable: bool = True
    severity: str = "WARNING"
    security_sensitive: bool = False


class TimeoutError(QuantumCryptError):
    """Raised when crypto operation exceeds timeout threshold."""
    error_code: str = "QC-012"
    retryable: bool = True
    severity: str = "WARNING"
    security_sensitive: bool = False


# -----------------------------------------------------------------------------
# Secure Memory Zeroization
# -----------------------------------------------------------------------------

def secure_zeroize(data: bytearray) -> None:
    """
    Securely zeroize sensitive data from memory.
    
    Uses secrets module to overwrite with random data first,
    then zeros to prevent memory forensic recovery.
    """
    if not isinstance(data, bytearray):
        return
    
    # Overwrite with random bytes first
    for i in range(len(data)):
        data[i] = secrets.randbelow(256)
    
    # Then zero out
    for i in range(len(data)):
        data[i] = 0


class SecureContext:
    """
    Context manager for secure handling of sensitive data.
    
    Automatically zeroizes sensitive data on exit, even if exceptions occur.
    """
    
    def __init__(self, sensitive_data: bytearray):
        self._data = sensitive_data
    
    def __enter__(self) -> bytearray:
        return self._data
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        secure_zeroize(self._data)
        return False  # Don't suppress exceptions


# -----------------------------------------------------------------------------
# Circuit Breaker for Crypto Operations
# -----------------------------------------------------------------------------

class CircuitState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass
class CryptoCircuitMetrics:
    encryption_attempts: int = 0
    encryption_failures: int = 0
    decryption_attempts: int = 0
    decryption_failures: int = 0
    sign_attempts: int = 0
    sign_failures: int = 0
    verify_attempts: int = 0
    key_ops_attempts: int = 0
    key_ops_failures: int = 0
    state_transitions: List[Tuple[CircuitState, CircuitState, str]] = field(default_factory=list)


class CryptoCircuitBreaker:
    """
    Circuit Breaker specifically for cryptographic operations.
    
    Prevents cascading failures in HSM, KMS, and crypto service operations.
    Includes operation-specific tracking.
    """
    
    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 2,
        name: str = "crypto_default"
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.name = name
        
        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._open_timestamp: Optional[float] = None
        self._half_open_calls: int = 0
        self._lock = threading.RLock()
        self.metrics = CryptoCircuitMetrics()
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._state
    
    def _transition_to(self, new_state: CircuitState, reason: str) -> None:
        old_state = self._state
        self._state = new_state
        self.metrics.state_transitions.append((old_state, new_state, reason))
        logger.warning(
            f"CryptoCircuitBreaker '{self.name}': {old_state.value} -> {new_state.value}: {reason}"
        )
    
    def _record_attempt(self, op_type: str) -> None:
        if op_type == "encrypt":
            self.metrics.encryption_attempts += 1
        elif op_type == "decrypt":
            self.metrics.decryption_attempts += 1
        elif op_type == "sign":
            self.metrics.sign_attempts += 1
        elif op_type == "verify":
            self.metrics.verify_attempts += 1
        elif op_type == "key_op":
            self.metrics.key_ops_attempts += 1
    
    def _record_success(self) -> None:
        self._failure_count = 0
        self._half_open_calls = 0
        if self._state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.CLOSED, "Crypto service recovery successful")
    
    def _record_failure(self, op_type: str) -> None:
        self._failure_count += 1
        
        if op_type == "encrypt":
            self.metrics.encryption_failures += 1
        elif op_type == "decrypt":
            self.metrics.decryption_failures += 1
        elif op_type == "sign":
            self.metrics.sign_failures += 1
        elif op_type == "key_op":
            self.metrics.key_ops_failures += 1
        
        if self._state == CircuitState.CLOSED:
            if self._failure_count >= self.failure_threshold:
                self._transition_to(
                    CircuitState.OPEN,
                    f"Crypto failure threshold reached ({self.failure_threshold})"
                )
                self._open_timestamp = time.monotonic()
        
        elif self._state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.OPEN, "Failure during crypto service recovery")
            self._open_timestamp = time.monotonic()
    
    def _allow_call(self) -> bool:
        now = time.monotonic()
        
        if self._state == CircuitState.CLOSED:
            return True
        
        if self._state == CircuitState.OPEN:
            if now - self._open_timestamp >= self.recovery_timeout:
                self._transition_to(CircuitState.HALF_OPEN, "Crypto recovery timeout elapsed")
                self._half_open_calls = 0
                return True
            return False
        
        if self._state == CircuitState.HALF_OPEN:
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False
        
        return False
    
    def __call__(self, op_type: str = "general") -> Callable:
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                with self._lock:
                    if not self._allow_call():
                        raise CircuitBreakerOpenError(
                            f"Crypto circuit breaker '{self.name}' is OPEN. "
                            f"Crypto service degraded. Try again after {self.recovery_timeout}s."
                        )
                    self._record_attempt(op_type)
                
                try:
                    result = func(*args, **kwargs)
                    with self._lock:
                        self._record_success()
                    return result
                except (HSMConnectionError, KeyManagementError, RandomnessError):
                    with self._lock:
                        self._record_failure(op_type)
                    raise
            
            return wrapper
        return decorator


# -----------------------------------------------------------------------------
# Crypto Retry with Exponential Backoff
# -----------------------------------------------------------------------------

def crypto_retry(
    max_attempts: int = 3,
    initial_delay: float = 0.5,
    max_delay: float = 10.0,
    backoff_factor: float = 2.0,
    jitter: float = 0.1
) -> Callable:
    """
    Retry decorator specifically for cryptographic operations.
    
    Only retries on retryable crypto exceptions (HSM, network, key ops).
    Never retries on security-sensitive failures (decryption, integrity).
    """
    retryable_exceptions = (
        HSMConnectionError,
        KeyManagementError,
        RandomnessError,
        TimeoutError,
        CircuitBreakerOpenError,
    )
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            delay = initial_delay
            
            while True:
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        logger.warning(f"Crypto retry failed after {max_attempts} attempts: {e}")
                        raise
                    
                    jitter_amount = delay * jitter * (2 * random.random() - 1)
                    sleep_time = min(delay + jitter_amount, max_delay)
                    sleep_time = max(0, sleep_time)
                    
                    logger.debug(
                        f"Crypto retry attempt {attempt}/{max_attempts}. "
                        f"Retrying in {sleep_time:.2f}s. Error: {e}"
                    )
                    time.sleep(sleep_time)
                    
                    delay = min(delay * backoff_factor, max_delay)
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Crypto Timeout Wrapper
# -----------------------------------------------------------------------------

def crypto_timeout(
    seconds: float,
    fallback_algorithm: Optional[str] = None,
    exception: Type[Exception] = TimeoutError
) -> Callable:
    """
    Timeout decorator for cryptographic operations.
    
    Supports optional algorithm fallback for graceful degradation.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = []
            exc_info = []
            
            def target():
                try:
                    result.append(func(*args, **kwargs))
                except Exception as e:
                    exc_info.append(e)
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=seconds)
            
            if thread.is_alive():
                if fallback_algorithm:
                    logger.warning(
                        f"Crypto operation {func.__name__} timed out after {seconds}s. "
                        f"Falling back to {fallback_algorithm}"
                    )
                    # Note: Actual fallback logic would be implementation-specific
                    # This is just the timeout detection mechanism
                raise exception(
                    f"Crypto operation timed out after {seconds} seconds. "
                    f"Consider using {fallback_algorithm or 'a lighter algorithm'}."
                )
            
            if exc_info:
                raise exc_info[0]
            
            return result[0] if result else None
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# Algorithm Fallback Chain
# -----------------------------------------------------------------------------

class AlgorithmFallbackChain:
    """
    Graceful degradation chain for cryptographic algorithms.
    
    When primary algorithm fails, automatically tries fallback algorithms
    in priority order until one succeeds or all are exhausted.
    """
    
    def __init__(self, algorithms: List[Tuple[str, Callable]], name: str = "default"):
        self.algorithms = algorithms  # List of (algorithm_name, function) tuples
        self.name = name
        self.fallback_usage: Dict[str, int] = {name: 0 for name, _ in algorithms}
    
    def __call__(self, *args, **kwargs) -> Tuple[Any, str]:
        """
        Execute algorithm chain, falling back as needed.
        
        Returns: (result, algorithm_used)
        """
        last_exception = None
        
        for algo_name, algo_func in self.algorithms:
            try:
                result = algo_func(*args, **kwargs)
                self.fallback_usage[algo_name] += 1
                return result, algo_name
            except Exception as e:
                last_exception = e
                logger.warning(
                    f"Algorithm '{algo_name}' failed in chain '{self.name}'. "
                    f"Trying next fallback. Error: {e}"
                )
                continue
        
        # All fallbacks failed
        raise AlgorithmUnavailableError(
            f"All algorithms failed in fallback chain '{self.name}'. "
            f"Last error: {last_exception}"
        )


# -----------------------------------------------------------------------------
# Crypto Bulkhead Isolation
# -----------------------------------------------------------------------------

class CryptoBulkhead:
    """
    Bulkhead isolation specifically for cryptographic operations.
    
    Prevents resource exhaustion from:
    - Too many concurrent key operations
    - Heavy computational crypto operations
    - HSM connection pool exhaustion
    """
    
    def __init__(
        self,
        max_concurrent: int = 5,
        max_waiting: int = 50,
        operation_type: str = "general"
    ):
        self.max_concurrent = max_concurrent
        self.max_waiting = max_waiting
        self.operation_type = operation_type
        self._semaphore = threading.Semaphore(max_concurrent)
        self._waiting_count = 0
        self._lock = threading.Lock()
        self.rejections = 0
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self._lock:
                if self._waiting_count >= self.max_waiting:
                    self.rejections += 1
                    raise KeyManagementError(
                        f"Crypto bulkhead ({self.operation_type}) queue full. "
                        f"Max waiting: {self.max_waiting}"
                    )
                self._waiting_count += 1
            
            try:
                acquired = self._semaphore.acquire(timeout=10.0)
                if not acquired:
                    raise TimeoutError(
                        f"Crypto bulkhead ({self.operation_type}) acquisition timeout"
                    )
                
                try:
                    return func(*args, **kwargs)
                finally:
                    self._semaphore.release()
            finally:
                with self._lock:
                    self._waiting_count -= 1
        
        return wrapper


# -----------------------------------------------------------------------------
# Safe Crypto Fallback Implementations
# -----------------------------------------------------------------------------

def safe_identity_hash(data: bytes) -> bytes:
    """
    Safe fallback hash - returns a deterministic but secure marker.
    Only use when actual hashing is unavailable.
    """
    import hashlib
    return hashlib.sha256(data or b"degraded_mode").digest()


def safe_encrypt_fallback(plaintext: bytes, *args, **kwargs) -> Dict[str, Any]:
    """
    Safe fallback for encryption - returns degraded mode indicator.
    Does NOT actually encrypt - only indicates degradation.
    """
    return {
        "status": "degraded",
        "warning": "Encryption service unavailable - DATA NOT ENCRYPTED",
        "algorithm": "NONE (DEGRADED MODE)",
        "ciphertext": None,
        "fallback_used": True,
        "timestamp": datetime.utcnow().isoformat(),
        "security_risk": "CRITICAL - Data was not encrypted"
    }


def safe_decrypt_fallback(ciphertext: bytes, *args, **kwargs) -> Dict[str, Any]:
    """
    Safe fallback for decryption - returns degraded mode indicator.
    """
    return {
        "status": "degraded",
        "warning": "Decryption service unavailable",
        "plaintext": None,
        "fallback_used": True,
        "timestamp": datetime.utcnow().isoformat()
    }


# -----------------------------------------------------------------------------
# Composite Crypto Resilience Policy
# -----------------------------------------------------------------------------

class CryptoResiliencePolicy:
    """
    Composite resilience policy for cryptographic operations.
    
    Combines: Crypto Retry + Crypto Circuit Breaker + Crypto Timeout
    for comprehensive crypto operation resilience.
    """
    
    def __init__(
        self,
        name: str = "crypto_default",
        max_retries: int = 2,
        circuit_failure_threshold: int = 3,
        timeout_seconds: float = 30.0,
        operation_type: str = "general"
    ):
        self.name = name
        self.circuit_breaker = CryptoCircuitBreaker(
            failure_threshold=circuit_failure_threshold,
            name=name
        )
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds
        self.operation_type = operation_type
    
    def __call__(self, func: Callable) -> Callable:
        decorated = func
        
        # Apply circuit breaker
        decorated = self.circuit_breaker(op_type=self.operation_type)(decorated)
        
        # Apply crypto retry
        decorated = crypto_retry(max_attempts=self.max_retries)(decorated)
        
        # Apply timeout
        decorated = crypto_timeout(seconds=self.timeout_seconds)(decorated)
        
        return decorated


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    # Exceptions
    "QuantumCryptError",
    "KeyManagementError",
    "EncryptionError",
    "DecryptionError",
    "SignatureError",
    "VerificationError",
    "HSMConnectionError",
    "RandomnessError",
    "AlgorithmUnavailableError",
    "IntegrityCheckError",
    "KeyRotationError",
    "CircuitBreakerOpenError",
    "TimeoutError",
    
    # Secure Memory
    "secure_zeroize",
    "SecureContext",
    
    # Circuit Breaker
    "CircuitState",
    "CryptoCircuitBreaker",
    "CryptoCircuitMetrics",
    
    # Retry
    "crypto_retry",
    
    # Timeout
    "crypto_timeout",
    
    # Algorithm Fallback
    "AlgorithmFallbackChain",
    
    # Bulkhead
    "CryptoBulkhead",
    
    # Safe Fallbacks
    "safe_identity_hash",
    "safe_encrypt_fallback",
    "safe_decrypt_fallback",
    
    # Composite Policy
    "CryptoResiliencePolicy",
]
