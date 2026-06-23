"""
QuantumCrypt AI - Comprehensive Error Resilience Exception Hierarchy (v21)
DIMENSION E - Error Resilience
June 2026 Production Release

PHILOSOPHY: ADD-ONLY, wrap, extend, layer on top
- 100% backward compatible
- Happy path behavior preserved
- Graceful degradation enabled
- Layered ON TOP of existing code

Custom exception hierarchy for post-quantum cryptography modules
with retry, backoff, timeout, and graceful degradation capabilities.
"""

import time
import random
import logging
import functools
import threading
import secrets
from typing import Any, Callable, Optional, TypeVar, Union, Dict, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

# Type variables for decorators
T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])

# Configure module logger (OPT-IN, disabled by default)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# ============================================================================
# EXCEPTION SEVERITY ENUM
# ============================================================================

class CryptoExceptionSeverity(Enum):
    """Severity levels for structured crypto exception handling."""
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4
    FATAL = 5

# ============================================================================
# EXCEPTION CATEGORY ENUM
# ============================================================================

class CryptoExceptionCategory(Enum):
    """Category classification for crypto error handling routing."""
    TRANSIENT = "transient"                # Retry-eligible
    KEY_MANAGEMENT = "key_management"      # Key-related errors
    CRYPTOGRAPHIC = "cryptographic"        # Crypto operation failures
    VALIDATION = "validation"              # Input validation
    RANDOMNESS = "randomness"              # Entropy/DRBG issues
    TIMEOUT = "timeout"                    # Operation timeout
    RESOURCE = "resource"                  # Resource exhaustion
    NETWORK = "network"                    # Network for KEX
    INTEGRITY = "integrity"                # Hash/MAC verification
    CERTIFICATE = "certificate"            # X.509 issues
    COMPATIBILITY = "compatibility"        # Algorithm compatibility
    HARDWARE = "hardware"                  # HSM/TPM issues
    SIDE_CHANNEL = "side_channel"          # Timing attack vectors
    UNKNOWN = "unknown"

# ============================================================================
# BASE EXCEPTION HIERARCHY
# ============================================================================

class QuantumCryptBaseError(Exception):
    """
    Base exception for all QuantumCrypt AI errors.
    
    All custom exceptions inherit from this, providing:
    - Structured error codes
    - Severity levels
    - Category classification
    - Retry eligibility
    - Security-safe messages (no key material leakage)
    - Graceful degradation hints
    - Constant-time safe comparison helpers
    """
    
    def __init__(
        self,
        message: str,
        error_code: str = "QC-0001",
        severity: CryptoExceptionSeverity = CryptoExceptionSeverity.ERROR,
        category: CryptoExceptionCategory = CryptoExceptionCategory.UNKNOWN,
        retry_eligible: bool = False,
        graceful_fallback: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        safe_for_logging: bool = True
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.severity = severity
        self.category = category
        self.retry_eligible = retry_eligible
        self.graceful_fallback = graceful_fallback
        self.details = details or {}
        self.cause = cause
        self.safe_for_logging = safe_for_logging
        self.timestamp = datetime.utcnow()
        
    def __str__(self) -> str:
        """Security-safe string representation."""
        base = f"[{self.error_code}] {self.message}"
        if self.graceful_fallback:
            base += f" | FALLBACK: {self.graceful_fallback}"
        return base
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to structured dictionary - security-safe."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "severity": self.severity.name,
            "category": self.category.value,
            "retry_eligible": self.retry_eligible,
            "graceful_fallback": self.graceful_fallback,
            "safe_for_logging": self.safe_for_logging,
            "timestamp": self.timestamp.isoformat()
        }

# ----------------------------------------------------------------------------
# TRANSIENT ERRORS (Retry-eligible)
# ----------------------------------------------------------------------------

class QuantumCryptTransientError(QuantumCryptBaseError):
    """Base for transient, retry-eligible crypto errors."""
    def __init__(self, message: str, error_code: str = "QC-T001", **kwargs):
        # Allow child classes to override these values
        category = kwargs.pop("category", CryptoExceptionCategory.TRANSIENT)
        retry_eligible = kwargs.pop("retry_eligible", True)
        super().__init__(
            message,
            error_code=error_code,
            category=category,
            retry_eligible=retry_eligible,
            **kwargs
        )

class QuantumCryptTimeoutError(QuantumCryptTransientError):
    """Crypto operation timed out - safe to retry."""
    def __init__(self, message: str = "Cryptographic operation timed out", timeout_seconds: Optional[float] = None, **kwargs):
        details = kwargs.pop("details", {})
        if timeout_seconds is not None:
            details["timeout_seconds"] = timeout_seconds
        super().__init__(
            message,
            error_code="QC-T002",
            category=CryptoExceptionCategory.TIMEOUT,
            details=details,
            **kwargs
        )

class QuantumCryptNetworkError(QuantumCryptTransientError):
    """Network issue during key exchange - retry eligible."""
    def __init__(self, message: str = "Key exchange network error", **kwargs):
        super().__init__(
            message,
            error_code="QC-T003",
            category=CryptoExceptionCategory.NETWORK,
            **kwargs
        )

class QuantumCryptResourceTemporarilyUnavailableError(QuantumCryptTransientError):
    """HSM/TPM temporarily busy - retry later."""
    def __init__(self, message: str = "Crypto resource temporarily unavailable", **kwargs):
        super().__init__(
            message,
            error_code="QC-T004",
            category=CryptoExceptionCategory.RESOURCE,
            **kwargs
        )

# ----------------------------------------------------------------------------
# KEY MANAGEMENT ERRORS
# ----------------------------------------------------------------------------

class QuantumCryptKeyError(QuantumCryptBaseError):
    """Key management error base."""
    def __init__(self, message: str = "Key management error", **kwargs):
        # Allow child classes to override these values
        error_code = kwargs.pop("error_code", "QC-K001")
        category = kwargs.pop("category", CryptoExceptionCategory.KEY_MANAGEMENT)
        severity = kwargs.pop("severity", CryptoExceptionSeverity.ERROR)
        retry_eligible = kwargs.pop("retry_eligible", False)
        super().__init__(
            message,
            error_code=error_code,
            category=category,
            severity=severity,
            retry_eligible=retry_eligible,
            **kwargs
        )

class QuantumCryptKeyNotFoundError(QuantumCryptKeyError):
    """Key not found in key store."""
    def __init__(self, message: str = "Key not found", key_id: Optional[str] = None, **kwargs):
        details = kwargs.pop("details", {})
        if key_id:
            details["key_id_hash"] = hash(key_id)  # Hash for security
        super().__init__(
            message,
            error_code="QC-K002",
            details=details,
            **kwargs
        )

class QuantumCryptKeyExpiredError(QuantumCryptKeyError):
    """Key has expired."""
    def __init__(self, message: str = "Key has expired", **kwargs):
        super().__init__(
            message,
            error_code="QC-K003",
            **kwargs
        )

class QuantumCryptKeyRotationRequiredError(QuantumCryptKeyError):
    """Key rotation required per policy."""
    def __init__(self, message: str = "Key rotation required", **kwargs):
        super().__init__(
            message,
            error_code="QC-K004",
            severity=CryptoExceptionSeverity.WARNING,
            retry_eligible=True,
            **kwargs
        )

# ----------------------------------------------------------------------------
# CRYPTOGRAPHIC OPERATION ERRORS
# ----------------------------------------------------------------------------

class QuantumCryptOperationError(QuantumCryptBaseError):
    """Cryptographic operation failure."""
    def __init__(self, message: str = "Cryptographic operation failed", **kwargs):
        # Allow child classes to override these values
        error_code = kwargs.pop("error_code", "QC-C001")
        category = kwargs.pop("category", CryptoExceptionCategory.CRYPTOGRAPHIC)
        severity = kwargs.pop("severity", CryptoExceptionSeverity.ERROR)
        retry_eligible = kwargs.pop("retry_eligible", False)
        super().__init__(
            message,
            error_code=error_code,
            category=category,
            severity=severity,
            retry_eligible=retry_eligible,
            **kwargs
        )

class QuantumCryptDecryptionError(QuantumCryptOperationError):
    """Decryption failed - MAC/verification failure."""
    def __init__(self, message: str = "Decryption verification failed", **kwargs):
        super().__init__(
            message,
            error_code="QC-C002",
            category=CryptoExceptionCategory.INTEGRITY,
            **kwargs
        )

class QuantumCryptSignatureVerificationError(QuantumCryptOperationError):
    """Digital signature verification failed."""
    def __init__(self, message: str = "Signature verification failed", **kwargs):
        super().__init__(
            message,
            error_code="QC-C003",
            category=CryptoExceptionCategory.INTEGRITY,
            **kwargs
        )

class QuantumCryptRandomnessError(QuantumCryptOperationError):
    """Insufficient entropy or DRBG failure."""
    def __init__(self, message: str = "Randomness generation error", **kwargs):
        super().__init__(
            message,
            error_code="QC-C004",
            category=CryptoExceptionCategory.RANDOMNESS,
            severity=CryptoExceptionSeverity.CRITICAL,
            **kwargs
        )

# ----------------------------------------------------------------------------
# VALIDATION ERRORS
# ----------------------------------------------------------------------------

class QuantumCryptValidationError(QuantumCryptBaseError):
    """Input validation failed."""
    def __init__(self, message: str = "Crypto validation failed", **kwargs):
        # Allow child classes to override these values
        error_code = kwargs.pop("error_code", "QC-V001")
        category = kwargs.pop("category", CryptoExceptionCategory.VALIDATION)
        severity = kwargs.pop("severity", CryptoExceptionSeverity.WARNING)
        retry_eligible = kwargs.pop("retry_eligible", False)
        super().__init__(
            message,
            error_code=error_code,
            category=category,
            severity=severity,
            retry_eligible=retry_eligible,
            **kwargs
        )

class QuantumCryptAlgorithmNotSupportedError(QuantumCryptValidationError):
    """Algorithm not supported by this implementation."""
    def __init__(self, message: str = "Algorithm not supported", algorithm: Optional[str] = None, **kwargs):
        details = kwargs.pop("details", {})
        if algorithm:
            details["algorithm"] = algorithm
        super().__init__(
            message,
            error_code="QC-V002",
            category=CryptoExceptionCategory.COMPATIBILITY,
            details=details,
            **kwargs
        )

# ----------------------------------------------------------------------------
# CERTIFICATE ERRORS
# ----------------------------------------------------------------------------

class QuantumCryptCertificateError(QuantumCryptBaseError):
    """Certificate validation error."""
    def __init__(self, message: str = "Certificate error", **kwargs):
        # Allow child classes to override these values
        error_code = kwargs.pop("error_code", "QC-CERT001")
        category = kwargs.pop("category", CryptoExceptionCategory.CERTIFICATE)
        severity = kwargs.pop("severity", CryptoExceptionSeverity.ERROR)
        retry_eligible = kwargs.pop("retry_eligible", False)
        super().__init__(
            message,
            error_code=error_code,
            category=category,
            severity=severity,
            retry_eligible=retry_eligible,
            **kwargs
        )

class QuantumCryptCertificateExpiredError(QuantumCryptCertificateError):
    """Certificate has expired."""
    def __init__(self, message: str = "Certificate expired", **kwargs):
        super().__init__(
            message,
            error_code="QC-CERT002",
            **kwargs
        )

class QuantumCryptCertificateRevokedError(QuantumCryptCertificateError):
    """Certificate has been revoked."""
    def __init__(self, message: str = "Certificate revoked", **kwargs):
        super().__init__(
            message,
            error_code="QC-CERT003",
            severity=CryptoExceptionSeverity.CRITICAL,
            **kwargs
        )

# ----------------------------------------------------------------------------
# HARDWARE SECURITY MODULE ERRORS
# ----------------------------------------------------------------------------

class QuantumCryptHardwareSecurityError(QuantumCryptBaseError):
    """HSM/TPM related error."""
    def __init__(self, message: str = "Hardware security module error", **kwargs):
        super().__init__(
            message,
            error_code="QC-HW001",
            category=CryptoExceptionCategory.HARDWARE,
            severity=CryptoExceptionSeverity.ERROR,
            **kwargs
        )

# ============================================================================
# CONSTANT-TIME HELPER FUNCTIONS (Security Critical)
# ============================================================================

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time byte comparison to prevent timing attacks.
    
    IMPORTANT: This is security-critical.
    Uses HMAC-based comparison for true constant-time operation.
    """
    if len(a) != len(b):
        return False
    
    # Use secrets module compare_digest which is constant-time
    return secrets.compare_digest(a, b)

def constant_time_equals(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return constant_time_compare(a.encode('utf-8'), b.encode('utf-8'))

def secure_wipe(data: bytearray) -> None:
    """
    Securely wipe sensitive data from memory.
    
    Overwrites with random bytes then zeros.
    Best-effort - Python GC may have copies.
    """
    length = len(data)
    for i in range(length):
        data[i] = secrets.randbelow(256)
    for i in range(length):
        data[i] = 0

# ============================================================================
# RETRY + BACKOFF UTILITIES (Crypto-Safe)
# ============================================================================

class CryptoCircuitState(Enum):
    """Circuit breaker states for crypto operations."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CryptoBackoffStrategy(Enum):
    """Backoff strategies for crypto retry logic."""
    CONSTANT = "constant"
    EXPONENTIAL = "exponential"
    JITTERED = "jittered"

@dataclass
class CryptoRetryConfig:
    """Configuration for crypto retry behavior."""
    max_attempts: int = 3
    initial_delay: float = 0.1  # Faster for crypto ops
    max_delay: float = 5.0
    backoff_strategy: CryptoBackoffStrategy = CryptoBackoffStrategy.JITTERED
    jitter: bool = True
    retry_on_exceptions: Tuple[type, ...] = (QuantumCryptTransientError,)
    graceful_fallback: Optional[Callable[..., Any]] = None
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay - crypto-optimized."""
        if attempt <= 0:
            return 0.0
            
        delay = self.initial_delay
        
        if self.backoff_strategy == CryptoBackoffStrategy.CONSTANT:
            delay = self.initial_delay
        elif self.backoff_strategy == CryptoBackoffStrategy.EXPONENTIAL:
            delay = self.initial_delay * (2 ** (attempt - 1))
        elif self.backoff_strategy == CryptoBackoffStrategy.JITTERED:
            base = self.initial_delay * (2 ** (attempt - 1))
            delay = base * (0.5 + random.random())
            
        delay = min(delay, self.max_delay)
        
        if self.jitter and self.backoff_strategy != CryptoBackoffStrategy.JITTERED:
            delay = delay * (0.75 + 0.5 * random.random())
            
        return max(0, delay)

class CryptoRetryManager:
    """
    Crypto-safe retry manager with configurable backoff.
    
    Only retries transient errors - never security failures.
    """
    
    def __init__(self, config: Optional[CryptoRetryConfig] = None):
        self.config = config or CryptoRetryConfig()
        self.attempts = 0
        self.last_error: Optional[Exception] = None
        
    def should_retry(self, exception: Exception) -> bool:
        """Only retry explicitly transient crypto errors."""
        if self.attempts >= self.config.max_attempts:
            return False
            
        if isinstance(exception, self.config.retry_on_exceptions):
            return True
            
        if hasattr(exception, 'retry_eligible') and exception.retry_eligible:
            return True
            
        return False
        
    def wait(self) -> None:
        """Wait with jittered backoff."""
        delay = self.config.calculate_delay(self.attempts)
        if delay > 0:
            time.sleep(delay)
            
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute crypto function with safe retry logic."""
        while True:
            try:
                self.attempts += 1
                return func(*args, **kwargs)
            except Exception as e:
                self.last_error = e
                
                if not self.should_retry(e):
                    if self.config.graceful_fallback is not None:
                        logger.warning(f"Crypto fallback after {self.attempts} attempts: {type(e).__name__}")
                        return self.config.graceful_fallback(*args, **kwargs)
                    raise
                    
                logger.info(f"Crypto retry {self.attempts}/{self.config.max_attempts}: {type(e).__name__}")
                self.wait()

def crypto_retry(
    max_attempts: int = 3,
    initial_delay: float = 0.1,
    max_delay: float = 5.0,
    fallback: Optional[Callable[..., Any]] = None
) -> Callable[[F], F]:
    """
    Decorator for crypto-safe automatic retry.
    
    Happy path 100% preserved.
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            config = CryptoRetryConfig(
                max_attempts=max_attempts,
                initial_delay=initial_delay,
                max_delay=max_delay,
                graceful_fallback=fallback
            )
            manager = CryptoRetryManager(config)
            return manager.execute(func, *args, **kwargs)
        return wrapper  # type: ignore
    return decorator

# ============================================================================
# CRYPTO TIMEOUT WRAPPERS
# ============================================================================

class CryptoTimeoutManager:
    """
    Timeout wrapper for crypto operations.
    
    Falls back to algorithm downgrade when available.
    """
    
    def __init__(self, timeout_seconds: float, fallback: Optional[Callable[..., Any]] = None):
        self.timeout_seconds = timeout_seconds
        self.fallback = fallback
        self._result: Any = None
        self._exception: Optional[Exception] = None
        
    def _target(self, func: Callable, args, kwargs):
        try:
            self._result = func(*args, **kwargs)
        except Exception as e:
            self._exception = e
            
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute with timeout protection."""
        thread = threading.Thread(
            target=self._target,
            args=(func, args, kwargs)
        )
        thread.daemon = True
        thread.start()
        thread.join(timeout=self.timeout_seconds)
        
        if thread.is_alive():
            if self.fallback is not None:
                logger.warning(f"Crypto timeout after {self.timeout_seconds}s, downgrading algorithm")
                return self.fallback(*args, **kwargs)
            raise QuantumCryptTimeoutError(
                f"Crypto operation timed out after {self.timeout_seconds}s",
                timeout_seconds=self.timeout_seconds
            )
            
        if self._exception is not None:
            raise self._exception
            
        return self._result

def crypto_timeout(
    seconds: float,
    fallback: Optional[Callable[..., Any]] = None
) -> Callable[[F], F]:
    """Decorator for crypto timeout protection."""
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            manager = CryptoTimeoutManager(seconds, fallback)
            return manager.execute(func, *args, **kwargs)
        return wrapper  # type: ignore
    return decorator

# ============================================================================
# CRYPTO CIRCUIT BREAKER
# ============================================================================

@dataclass
class CryptoCircuitBreakerConfig:
    failure_threshold: int = 10
    reset_timeout: float = 60.0
    half_open_max_calls: int = 5
    tracked_exceptions: Tuple[type, ...] = (QuantumCryptTransientError,)

class CryptoCircuitBreaker:
    """
    Circuit breaker for crypto operations.
    
    Prevents DoS against HSM/TPM resources.
    """
    
    def __init__(self, config: Optional[CryptoCircuitBreakerConfig] = None):
        self.config = config or CryptoCircuitBreakerConfig()
        self.state = CryptoCircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.half_open_attempts = 0
        self._lock = threading.Lock()
        
    def _check_state_transition(self) -> None:
        with self._lock:
            now = datetime.utcnow()
            if self.state == CryptoCircuitState.OPEN:
                elapsed = (now - self.last_failure_time).total_seconds()
                if elapsed >= self.config.reset_timeout:
                    self.state = CryptoCircuitState.HALF_OPEN
                    self.half_open_attempts = 0
                    
    def on_success(self) -> None:
        with self._lock:
            if self.state == CryptoCircuitState.HALF_OPEN:
                self.half_open_attempts += 1
                if self.half_open_attempts >= self.config.half_open_max_calls:
                    self.state = CryptoCircuitState.CLOSED
                    self.failure_count = 0
            elif self.state == CryptoCircuitState.CLOSED:
                self.failure_count = max(0, self.failure_count - 1)
                
    def on_failure(self) -> None:
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = datetime.utcnow()
            if self.state == CryptoCircuitState.HALF_OPEN:
                self.state = CryptoCircuitState.OPEN
            elif self.state == CryptoCircuitState.CLOSED:
                if self.failure_count >= self.config.failure_threshold:
                    self.state = CryptoCircuitState.OPEN
                    
    def allow_call(self) -> bool:
        self._check_state_transition()
        return self.state != CryptoCircuitState.OPEN
        
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        if not self.allow_call():
            raise QuantumCryptTransientError(
                f"Crypto circuit breaker OPEN - HSM protection active",
                error_code="QC-CB001"
            )
        try:
            result = func(*args, **kwargs)
            self.on_success()
            return result
        except self.config.tracked_exceptions:
            self.on_failure()
            raise

_crypto_circuit_breakers: Dict[str, CryptoCircuitBreaker] = {}

def get_crypto_circuit_breaker(name: str) -> CryptoCircuitBreaker:
    """Get or create named crypto circuit breaker."""
    if name not in _crypto_circuit_breakers:
        _crypto_circuit_breakers[name] = CryptoCircuitBreaker()
    return _crypto_circuit_breakers[name]

# ============================================================================
# ALGORITHM DOWNGRADE FALLBACKS
# ============================================================================

@dataclass
class CryptoFallbackResult:
    """Result from crypto algorithm fallback."""
    value: Any
    is_fallback: bool = True
    algorithm_downgraded: bool = False
    original_algorithm: Optional[str] = None
    fallback_algorithm: Optional[str] = None
    original_error: Optional[Exception] = None

def crypto_algorithm_fallback(
    fallback_algorithm: Optional[Callable[..., Any]] = None,
    catch_exceptions: Tuple[type, ...] = (QuantumCryptTimeoutError, QuantumCryptTransientError)
) -> Callable[[F], F]:
    """
    Decorator for graceful algorithm downgrade.
    
    Falls back to classic crypto when post-quantum fails.
    Happy path 100% preserved.
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except catch_exceptions as e:
                if fallback_algorithm is not None:
                    logger.warning(f"Crypto algorithm downgrade: {type(e).__name__}")
                    result = fallback_algorithm(*args, **kwargs)
                    return CryptoFallbackResult(
                        value=result,
                        algorithm_downgraded=True,
                        original_algorithm=getattr(func, '__name__', 'unknown'),
                        fallback_algorithm=getattr(fallback_algorithm, '__name__', 'unknown'),
                        original_error=e
                    )
                raise
        return wrapper  # type: ignore
    return decorator

# ============================================================================
# CRYPTO BULKHEAD ISOLATION
# ============================================================================

class CryptoBulkhead:
    """
    Bulkhead for crypto resource isolation.
    
    Prevents resource exhaustion on HSM/TPM.
    """
    
    def __init__(self, max_concurrent: int = 5, max_queue_size: int = 50):
        self.max_concurrent = max_concurrent
        self.max_queue_size = max_queue_size
        self._semaphore = threading.Semaphore(max_concurrent)
        self._lock = threading.Lock()
        self._active = 0
        self._queued = 0
        
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        with self._lock:
            if self._queued >= self.max_queue_size:
                raise QuantumCryptTransientError(
                    "Crypto HSM queue full - throttling",
                    error_code="QC-BH001"
                )
            self._queued += 1
            
        try:
            acquired = self._semaphore.acquire(timeout=10)
            if not acquired:
                raise QuantumCryptTimeoutError("Crypto bulkhead timeout")
                
            with self._lock:
                self._queued -= 1
                self._active += 1
                
            try:
                return func(*args, **kwargs)
            finally:
                with self._lock:
                    self._active -= 1
                self._semaphore.release()
        finally:
            with self._lock:
                self._queued = max(0, self._queued - 1)

_crypto_bulkheads: Dict[str, CryptoBulkhead] = {}

def get_crypto_bulkhead(name: str, max_concurrent: int = 5) -> CryptoBulkhead:
    """Get or create named crypto bulkhead."""
    if name not in _crypto_bulkheads:
        _crypto_bulkheads[name] = CryptoBulkhead(max_concurrent)
    return _crypto_bulkheads[name]

# ============================================================================
# EXPORT PUBLIC API
# ============================================================================

__all__ = [
    # Enums
    'CryptoExceptionSeverity',
    'CryptoExceptionCategory',
    'CryptoBackoffStrategy',
    
    # Base Exceptions
    'QuantumCryptBaseError',
    'QuantumCryptTransientError',
    'QuantumCryptTimeoutError',
    'QuantumCryptNetworkError',
    'QuantumCryptResourceTemporarilyUnavailableError',
    'QuantumCryptKeyError',
    'QuantumCryptKeyNotFoundError',
    'QuantumCryptKeyExpiredError',
    'QuantumCryptKeyRotationRequiredError',
    'QuantumCryptOperationError',
    'QuantumCryptDecryptionError',
    'QuantumCryptSignatureVerificationError',
    'QuantumCryptRandomnessError',
    'QuantumCryptValidationError',
    'QuantumCryptAlgorithmNotSupportedError',
    'QuantumCryptCertificateError',
    'QuantumCryptCertificateExpiredError',
    'QuantumCryptCertificateRevokedError',
    'QuantumCryptHardwareSecurityError',
    
    # Constant-time helpers
    'constant_time_compare',
    'constant_time_equals',
    'secure_wipe',
    
    # Retry
    'CryptoRetryConfig',
    'CryptoRetryManager',
    'crypto_retry',
    
    # Timeout
    'CryptoTimeoutManager',
    'crypto_timeout',
    
    # Circuit Breaker
    'CryptoCircuitBreakerConfig',
    'CryptoCircuitBreaker',
    'get_crypto_circuit_breaker',
    
    # Fallback
    'CryptoFallbackResult',
    'crypto_algorithm_fallback',
    
    # Bulkhead
    'CryptoBulkhead',
    'get_crypto_bulkhead',
]
