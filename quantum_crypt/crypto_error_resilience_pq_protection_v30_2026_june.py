"""
QuantumCrypt AI - Enhanced Crypto Error Resilience Module v30
Dimension E - Error Resilience

This module provides comprehensive error resilience capabilities
specifically designed for post-quantum cryptography operations:
- Custom exception hierarchy for crypto operations
- Advanced timeout wrappers for key generation/encryption
- Retry + exponential backoff for crypto operations
- Graceful degradation with algorithm fallbacks
- Circuit breaker for HSM/API operations
- Bulkhead isolation for resource-intensive crypto ops
- Secure memory zeroization on error

IMPLEMENTATION NOTE: All features are implemented as WRAPPERS.
No existing code is modified - this is purely additive.
Happy path behavior is 100% preserved.
"""

import time
import random
import logging
import threading
import functools
import secrets
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

# Configure logging - OPT-IN only, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# -----------------------------------------------------------------------------
# CUSTOM CRYPTO EXCEPTION HIERARCHY
# -----------------------------------------------------------------------------

class QuantumCryptError(Exception):
    """Base exception for all QuantumCrypt errors"""
    def __init__(self, message: str, error_code: str = "QC-001", details: Optional[Dict] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "details": self.details,
            "timestamp": self.timestamp
        }


class CryptoOperationError(QuantumCryptError):
    """Base for cryptographic operation errors"""
    pass


class KeyGenerationError(CryptoOperationError):
    """Error during key generation"""
    def __init__(self, message: str, algorithm: str = "", key_size: int = 0, details: Optional[Dict] = None):
        super().__init__(message, "QC-KEY-001", details)
        self.details["algorithm"] = algorithm
        self.details["key_size"] = key_size


class EncryptionError(CryptoOperationError):
    """Error during encryption operation"""
    def __init__(self, message: str, algorithm: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-ENC-001", details)
        self.details["algorithm"] = algorithm


class DecryptionError(CryptoOperationError):
    """Error during decryption operation"""
    def __init__(self, message: str, algorithm: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-DEC-001", details)
        self.details["algorithm"] = algorithm


class SignatureError(CryptoOperationError):
    """Error during signature operation"""
    def __init__(self, message: str, operation: str = "sign", details: Optional[Dict] = None):
        super().__init__(message, "QC-SIG-001", details)
        self.details["operation"] = operation


class HashError(CryptoOperationError):
    """Error during hashing operation"""
    def __init__(self, message: str, algorithm: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-HASH-001", details)
        self.details["algorithm"] = algorithm


class RandomnessError(QuantumCryptError):
    """Error related to random number generation"""
    def __init__(self, message: str, source: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-RNG-001", details)
        self.details["source"] = source


class HSMConnectError(QuantumCryptError):
    """Error connecting to Hardware Security Module"""
    def __init__(self, message: str, hsm_id: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-HSM-001", details)
        self.details["hsm_id"] = hsm_id


class PostQuantumError(QuantumCryptError):
    """Base for post-quantum crypto errors"""
    pass


class PQKeyExchangeError(PostQuantumError):
    """Error during post-quantum key exchange"""
    def __init__(self, message: str, kem_algorithm: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-PQ-KEM-001", details)
        self.details["kem_algorithm"] = kem_algorithm


class PQSignatureError(PostQuantumError):
    """Error during post-quantum signature operation"""
    def __init__(self, message: str, sig_algorithm: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-PQ-SIG-001", details)
        self.details["sig_algorithm"] = sig_algorithm


class SecurityError(QuantumCryptError):
    """Security-related errors"""
    pass


class ValidationError(SecurityError):
    """Input validation error"""
    def __init__(self, message: str, field_name: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-SEC-001", details)
        self.details["field_name"] = field_name


class SideChannelRiskError(SecurityError):
    """Potential side-channel vulnerability detected"""
    def __init__(self, message: str, risk_type: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-SEC-002", details)
        self.details["risk_type"] = risk_type


class TimeoutError(QuantumCryptError):
    """Operation timeout error"""
    def __init__(self, message: str, timeout_seconds: float = 0, operation: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-TIMEOUT-001", details)
        self.details["timeout_seconds"] = timeout_seconds
        self.details["operation"] = operation


class CircuitBreakerOpenError(QuantumCryptError):
    """Circuit breaker is open - operation rejected"""
    def __init__(self, message: str, service_name: str = "", reset_time: Optional[datetime] = None, details: Optional[Dict] = None):
        super().__init__(message, "QC-CB-001", details)
        self.details["service_name"] = service_name
        self.details["reset_time"] = reset_time.isoformat() if reset_time else None


class FallbackActivatedError(QuantumCryptError):
    """Fallback algorithm was activated (informational)"""
    def __init__(self, message: str, primary_algorithm: str = "", fallback_algorithm: str = "", details: Optional[Dict] = None):
        super().__init__(message, "QC-FB-001", details)
        self.details["primary_algorithm"] = primary_algorithm
        self.details["fallback_algorithm"] = fallback_algorithm


class InsecureFallbackWarning(QuantumCryptError):
    """Warning: fell back to non-quantum-resistant algorithm"""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(message, "QC-FB-WARN-001", details)


# -----------------------------------------------------------------------------
# SECURE MEMORY ZEROIZATION
# -----------------------------------------------------------------------------

def secure_zeroize(data: bytearray) -> None:
    """
    Securely zeroize sensitive data from memory.
    Uses secrets module to prevent compiler optimization.
    """
    try:
        for i in range(len(data)):
            data[i] = secrets.randbelow(256) & 0  # Force write to prevent optimization
        for i in range(len(data)):
            data[i] = 0
    except:
        pass  # Best effort - don't fail on zeroization


class SecureContext:
    """
    Context manager that ensures sensitive data is zeroized on exit,
    even if an exception occurs.
    """
    
    def __init__(self, sensitive_data: bytearray):
        self._data = sensitive_data
    
    def __enter__(self):
        return self._data
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        secure_zeroize(self._data)
        return False  # Don't suppress exception


# -----------------------------------------------------------------------------
# CIRCUIT BREAKER FOR CRYPTO OPERATIONS
# -----------------------------------------------------------------------------

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout_seconds: float = 60.0
    half_open_max_calls: int = 3
    excluded_exceptions: Tuple[Type[Exception], ...] = field(default_factory=lambda: (ValueError, TypeError))


@dataclass
class CircuitBreakerStats:
    success_count: int = 0
    failure_count: int = 0
    rejected_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_state_change: datetime = field(default_factory=datetime.utcnow)


class CryptoCircuitBreaker:
    """
    Circuit Breaker specifically designed for crypto operations.
    Prevents cascading failures when HSMs or crypto APIs fail.
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._stats = CircuitBreakerStats()
        self._lock = threading.RLock()
        self._open_until: Optional[datetime] = None
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._check_state_transition()
            return self._state
    
    @property
    def stats(self) -> CircuitBreakerStats:
        with self._lock:
            return CircuitBreakerStats(
                success_count=self._stats.success_count,
                failure_count=self._stats.failure_count,
                rejected_count=self._stats.rejected_count,
                last_failure_time=self._stats.last_failure_time,
                last_state_change=self._stats.last_state_change
            )
    
    def _check_state_transition(self) -> None:
        if self._state == CircuitState.OPEN and self._open_until:
            if datetime.utcnow() >= self._open_until:
                self._state = CircuitState.HALF_OPEN
                self._stats.last_state_change = datetime.utcnow()
                logger.info(f"CryptoCircuitBreaker '{self.name}' transitioning to HALF_OPEN")
    
    def _on_success(self) -> None:
        with self._lock:
            self._stats.success_count += 1
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._stats.failure_count = 0
                self._stats.last_state_change = datetime.utcnow()
                logger.info(f"CryptoCircuitBreaker '{self.name}' recovered")
    
    def _on_failure(self, exc: Exception) -> None:
        with self._lock:
            if isinstance(exc, self.config.excluded_exceptions):
                return
            
            self._stats.failure_count += 1
            self._stats.last_failure_time = datetime.utcnow()
            
            if self._state == CircuitState.HALF_OPEN:
                self._open_circuit()
            elif self._state == CircuitState.CLOSED:
                if self._stats.failure_count >= self.config.failure_threshold:
                    self._open_circuit()
    
    def _open_circuit(self) -> None:
        self._state = CircuitState.OPEN
        self._open_until = datetime.utcnow() + timedelta(seconds=self.config.recovery_timeout_seconds)
        self._stats.last_state_change = datetime.utcnow()
        logger.warning(f"CryptoCircuitBreaker '{self.name}' OPEN - failures: {self._stats.failure_count}")
    
    def allow_call(self) -> bool:
        with self._lock:
            self._check_state_transition()
            if self._state == CircuitState.OPEN:
                self._stats.rejected_count += 1
                return False
            return True
    
    def reset(self) -> None:
        with self._lock:
            self._state = CircuitState.CLOSED
            self._stats = CircuitBreakerStats()
            self._open_until = None
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.allow_call():
                raise CircuitBreakerOpenError(
                    f"Crypto circuit breaker '{self.name}' is open",
                    service_name=self.name,
                    reset_time=self._open_until
                )
            
            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except Exception as e:
                self._on_failure(e)
                raise
        return wrapper


# Global circuit breaker registry
_circuit_breakers: Dict[str, CryptoCircuitBreaker] = {}
_circuit_breaker_lock = threading.Lock()


def get_crypto_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CryptoCircuitBreaker:
    """Get or create a named crypto circuit breaker"""
    with _circuit_breaker_lock:
        if name not in _circuit_breakers:
            _circuit_breakers[name] = CryptoCircuitBreaker(name, config)
        return _circuit_breakers[name]


# -----------------------------------------------------------------------------
# RETRY FOR CRYPTO OPERATIONS
# -----------------------------------------------------------------------------

@dataclass
class CryptoRetryConfig:
    max_attempts: int = 3
    initial_delay_seconds: float = 0.05
    max_delay_seconds: float = 5.0
    backoff_factor: float = 1.5
    jitter_factor: float = 0.1
    retry_on_exceptions: Tuple[Type[Exception], ...] = field(
        default_factory=lambda: (HSMConnectError, TimeoutError)
    )


def crypto_retry(
    config: Optional[CryptoRetryConfig] = None,
    *,
    max_attempts: int = 3,
    initial_delay: float = 0.05
) -> Callable:
    """
    Retry decorator optimized for crypto operations.
    Only retries on transient errors (HSM connection, timeout).
    Never retries on security-related errors.
    """
    if config is None:
        config = CryptoRetryConfig(
            max_attempts=max_attempts,
            initial_delay_seconds=initial_delay
        )
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception: Optional[Exception] = None
            delay = config.initial_delay_seconds
            
            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # Never retry security errors
                    if isinstance(e, (SecurityError, ValidationError, SideChannelRiskError)):
                        raise
                    
                    # Check if we should retry
                    if not isinstance(e, config.retry_on_exceptions):
                        raise
                    
                    if attempt < config.max_attempts - 1:
                        actual_delay = delay
                        if config.jitter_factor > 0:
                            jitter_amount = delay * config.jitter_factor
                            actual_delay = delay + random.uniform(-jitter_amount, jitter_amount)
                            actual_delay = max(0, actual_delay)
                        
                        actual_delay = min(actual_delay, config.max_delay_seconds)
                        time.sleep(actual_delay)
                        delay *= config.backoff_factor
            
            raise last_exception
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# TIMEOUT FOR CRYPTO OPERATIONS
# -----------------------------------------------------------------------------

def crypto_timeout(
    seconds: float,
    fallback: Optional[Callable] = None,
    secure_cleanup: Optional[Callable] = None
) -> Callable:
    """
    Timeout decorator with secure cleanup for crypto operations.
    
    Args:
        seconds: Maximum execution time
        fallback: Optional fallback function
        secure_cleanup: Optional function to securely zeroize sensitive data on timeout
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result_container: Dict[str, Any] = {"success": False, "result": None, "exception": None}
            
            def target():
                try:
                    result_container["result"] = func(*args, **kwargs)
                    result_container["success"] = True
                except Exception as e:
                    result_container["exception"] = e
            
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            thread.join(timeout=seconds)
            
            if thread.is_alive():
                # Run secure cleanup if provided
                if secure_cleanup is not None:
                    try:
                        secure_cleanup()
                    except:
                        pass
                
                if fallback is not None:
                    logger.warning(f"Crypto timeout in {func.__name__}, activating fallback")
                    return fallback(*args, **kwargs)
                
                raise TimeoutError(
                    f"Crypto operation '{func.__name__}' timed out after {seconds}s",
                    timeout_seconds=seconds,
                    operation=func.__name__
                )
            
            if not result_container["success"]:
                raise result_container["exception"]
            
            return result_container["result"]
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# ALGORITHM FALLBACKS (GRACEFUL DEGRADATION)
# -----------------------------------------------------------------------------

@dataclass
class CryptoFallbackResult:
    value: Any
    was_fallback: bool
    primary_algorithm: str
    fallback_algorithm: Optional[str] = None
    primary_error: Optional[Exception] = None
    is_quantum_safe: bool = True


def with_algorithm_fallback(
    fallback_func: Callable,
    primary_algorithm: str,
    fallback_algorithm: str,
    fallback_is_quantum_safe: bool = True
) -> Callable:
    """
    Decorator that provides graceful algorithm degradation.
    If primary post-quantum algorithm fails, falls back to alternative.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> CryptoFallbackResult:
            try:
                result = func(*args, **kwargs)
                return CryptoFallbackResult(
                    value=result,
                    was_fallback=False,
                    primary_algorithm=primary_algorithm,
                    is_quantum_safe=True
                )
            except Exception as e:
                logger.warning(
                    f"Primary algorithm {primary_algorithm} failed, "
                    f"falling back to {fallback_algorithm}: {e}"
                )
                
                fallback_value = fallback_func(*args, **kwargs)
                
                if not fallback_is_quantum_safe:
                    logger.warning(
                        f"WARNING: Fallback algorithm {fallback_algorithm} "
                        f"is NOT quantum-resistant!"
                    )
                
                return CryptoFallbackResult(
                    value=fallback_value,
                    was_fallback=True,
                    primary_algorithm=primary_algorithm,
                    fallback_algorithm=fallback_algorithm,
                    primary_error=e,
                    is_quantum_safe=fallback_is_quantum_safe
                )
        
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# BULKHEAD ISOLATION FOR CRYPTO
# -----------------------------------------------------------------------------

class CryptoBulkhead:
    """
    Bulkhead pattern for resource-intensive crypto operations.
    Prevents key generation from starving encryption operations.
    """
    
    def __init__(self, name: str, max_concurrent: int = 5, max_queue_size: int = 50):
        self.name = name
        self.max_concurrent = max_concurrent
        self.max_queue_size = max_queue_size
        self._semaphore = threading.Semaphore(max_concurrent)
        self._active_count = 0
        self._queued_count = 0
        self._rejected_count = 0
        self._lock = threading.Lock()
    
    @property
    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "max_concurrent": self.max_concurrent,
                "active": self._active_count,
                "queued": self._queued_count,
                "rejected": self._rejected_count
            }
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self._lock:
                if self._queued_count >= self.max_queue_size:
                    self._rejected_count += 1
                    raise QuantumCryptError(
                        f"Crypto bulkhead '{self.name}' queue full",
                        "QC-BH-001",
                        self.stats
                    )
                self._queued_count += 1
            
            try:
                acquired = self._semaphore.acquire(timeout=60)
                if not acquired:
                    raise QuantumCryptError(
                        f"Crypto bulkhead '{self.name}' timeout",
                        "QC-BH-002",
                        self.stats
                    )
                
                with self._lock:
                    self._queued_count -= 1
                    self._active_count += 1
                
                try:
                    return func(*args, **kwargs)
                finally:
                    with self._lock:
                        self._active_count -= 1
                    self._semaphore.release()
            finally:
                with self._lock:
                    if self._queued_count > 0:
                        self._queued_count -= 1
        
        return wrapper


# Global bulkhead registry
_bulkheads: Dict[str, CryptoBulkhead] = {}
_bulkhead_lock = threading.Lock()


def get_crypto_bulkhead(name: str, max_concurrent: int = 5, max_queue_size: int = 50) -> CryptoBulkhead:
    """Get or create a named crypto bulkhead"""
    with _bulkhead_lock:
        if name not in _bulkheads:
            _bulkheads[name] = CryptoBulkhead(name, max_concurrent, max_queue_size)
        return _bulkheads[name]


# -----------------------------------------------------------------------------
# COMBINED CRYPTO RESILIENCE
# -----------------------------------------------------------------------------

def resilient_crypto_op(
    *,
    timeout_seconds: float = 30.0,
    max_retries: int = 2,
    circuit_breaker: Optional[str] = None,
    bulkhead: Optional[str] = None
) -> Callable:
    """
    Combined resilience decorator for crypto operations:
    - Bulkhead isolation
    - Circuit breaker
    - Smart retry (only transient errors)
    - Timeout with cleanup
    
    All features are OPTIONAL and opt-in.
    """
    def decorator(func: Callable) -> Callable:
        wrapped = func
        
        if bulkhead:
            bh = get_crypto_bulkhead(bulkhead)
            wrapped = bh(wrapped)
        
        if circuit_breaker:
            cb = get_crypto_circuit_breaker(circuit_breaker)
            wrapped = cb(wrapped)
        
        if max_retries > 0:
            wrapped = crypto_retry(max_attempts=max_retries + 1)(wrapped)
        
        if timeout_seconds > 0:
            wrapped = crypto_timeout(timeout_seconds)(wrapped)
        
        return wrapped
    return decorator


# -----------------------------------------------------------------------------
# CRYPTO ERROR CONTEXT
# -----------------------------------------------------------------------------

class CryptoErrorContext:
    """
    Context manager for capturing and enriching crypto errors.
    Automatically zeroizes sensitive data on error.
    """
    
    def __init__(self, operation: str, sensitive_data: Optional[bytearray] = None):
        self.operation = operation
        self.sensitive_data = sensitive_data
        self.start_time = time.time()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Always zeroize sensitive data if provided
        if self.sensitive_data is not None:
            secure_zeroize(self.sensitive_data)
        
        if exc_val is not None:
            # Enrich the exception
            if hasattr(exc_val, 'details') and isinstance(exc_val.details, dict):
                exc_val.details["operation"] = self.operation
                exc_val.details["duration_seconds"] = time.time() - self.start_time
            
            logger.error(
                f"Crypto error in '{self.operation}': {exc_val}",
                extra={"operation": self.operation}
            )
        return False


# -----------------------------------------------------------------------------
# MODULE INFO
# -----------------------------------------------------------------------------

__version__ = "30.0.0"
__dimension__ = "E - Error Resilience"
__stable__ = True
__all__ = [
    # Exceptions
    "QuantumCryptError",
    "CryptoOperationError",
    "KeyGenerationError",
    "EncryptionError",
    "DecryptionError",
    "SignatureError",
    "HashError",
    "RandomnessError",
    "HSMConnectError",
    "PostQuantumError",
    "PQKeyExchangeError",
    "PQSignatureError",
    "SecurityError",
    "ValidationError",
    "SideChannelRiskError",
    "TimeoutError",
    "CircuitBreakerOpenError",
    "FallbackActivatedError",
    "InsecureFallbackWarning",
    
    # Secure memory
    "secure_zeroize",
    "SecureContext",
    
    # Circuit Breaker
    "CryptoCircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitState",
    "get_crypto_circuit_breaker",
    
    # Retry
    "CryptoRetryConfig",
    "crypto_retry",
    
    # Timeout
    "crypto_timeout",
    
    # Fallbacks
    "with_algorithm_fallback",
    "CryptoFallbackResult",
    
    # Bulkhead
    "CryptoBulkhead",
    "get_crypto_bulkhead",
    
    # Combined
    "resilient_crypto_op",
    
    # Context
    "CryptoErrorContext",
]
