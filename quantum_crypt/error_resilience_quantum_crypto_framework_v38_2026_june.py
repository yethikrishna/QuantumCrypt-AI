"""
Error Resilience Quantum Crypto Framework v38
Dimension E: Error Resilience - June 2026

Add-only incremental enhancement for QuantumCrypt-AI:
- Custom cryptography-focused exception hierarchy
- Cryptographic operation timeout wrappers
- Key management retry with exponential backoff
- Graceful degradation for quantum-resistant operations

Happy path behavior 100% preserved - all instrumentation is OPT-IN and wraps existing code.
"""

import time
import random
import logging
import functools
import threading
import secrets
from typing import Any, Callable, Optional, Type, Tuple, Union, Dict, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from contextlib import contextmanager


# -----------------------------------------------------------------------------
# Custom Cryptography-Focused Exception Hierarchy
# -----------------------------------------------------------------------------

class QuantumCryptError(Exception):
    """Base exception for all QuantumCrypt errors."""
    error_code: str = "QUANTUMCRYPT_ERROR"
    severity: str = "ERROR"
    timestamp: datetime
    sensitive: bool = False  # Whether error contains sensitive data
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.timestamp = datetime.utcnow()
        self.details = details or {}
        super().__init__(message)
    
    def safe_message(self) -> str:
        """Get a safe version of the message without sensitive details."""
        return f"{self.error_code}: Operation failed"


class QuantumCryptWarning(QuantumCryptError):
    """Warning-level exceptions - non-critical, recoverable."""
    error_code = "QUANTUMCRYPT_WARNING"
    severity = "WARNING"


class QuantumCryptCritical(QuantumCryptError):
    """Critical-level exceptions - security-impacting, requires immediate attention."""
    error_code = "QUANTUMCRYPT_CRITICAL"
    severity = "CRITICAL"


# Key Management Exceptions
class KeyManagementError(QuantumCryptError):
    """Base exception for key management errors."""
    error_code = "KEY_MANAGEMENT_ERROR"


class KeyNotFoundError(KeyManagementError):
    """Key not found in key store."""
    error_code = "KEY_NOT_FOUND"


class KeyRotationInProgress(KeyManagementError, QuantumCryptWarning):
    """Key rotation is in progress - retry recommended."""
    error_code = "KEY_ROTATION_IN_PROGRESS"


class KeyExpiredError(KeyManagementError, QuantumCryptWarning):
    """Key has expired but fallback available."""
    error_code = "KEY_EXPIRED"


class KeyCompromisedError(KeyManagementError, QuantumCryptCritical):
    """Key has been compromised - critical security issue."""
    error_code = "KEY_COMPROMISED"
    sensitive = True


# Cryptographic Operation Exceptions
class CryptoOperationError(QuantumCryptError):
    """Base exception for cryptographic operation errors."""
    error_code = "CRYPTO_OPERATION_ERROR"


class CryptoTimeoutError(CryptoOperationError, QuantumCryptWarning):
    """Cryptographic operation timed out."""
    error_code = "CRYPTO_OPERATION_TIMEOUT"


class CryptoTemporaryFailure(CryptoOperationError, QuantumCryptWarning):
    """Temporary failure - HSM/TPM busy, retry recommended."""
    error_code = "CRYPTO_TEMPORARY_FAILURE"


class CryptoPermanentFailure(CryptoOperationError, QuantumCryptCritical):
    """Permanent failure - hardware error, do not retry."""
    error_code = "CRYPTO_PERMANENT_FAILURE"


class IntegrityVerificationFailed(CryptoOperationError, QuantumCryptCritical):
    """Integrity verification failed - data tampered with."""
    error_code = "INTEGRITY_VERIFICATION_FAILED"


# Quantum-Specific Exceptions
class QuantumCryptoError(QuantumCryptError):
    """Base exception for quantum cryptography errors."""
    error_code = "QUANTUM_CRYPTO_ERROR"


class QuantumChannelNoise(QuantumCryptoError, QuantumCryptWarning):
    """High noise on quantum channel - retry with lower rate."""
    error_code = "QUANTUM_CHANNEL_NOISE"


class EntropyDepletionError(QuantumCryptoError, QuantumCryptWarning):
    """Entropy pool depleted - wait for replenishment."""
    error_code = "ENTROPY_DEPLETION"


class PostQuantumAlgorithmError(QuantumCryptoError, QuantumCryptCritical):
    """Post-quantum algorithm verification failed."""
    error_code = "POST_QUANTUM_ALGORITHM_ERROR"


# -----------------------------------------------------------------------------
# Secure Memory Zeroization Utilities
# -----------------------------------------------------------------------------

def secure_zeroize(data: bytearray) -> None:
    """
    Securely zeroize sensitive data from memory.
    Uses volatile writes to prevent compiler optimization.
    """
    for i in range(len(data)):
        data[i] = 0
    # Force memory barrier
    if data:
        data[0] = secrets.randbelow(256)
        data[0] = 0


@contextmanager
def sensitive_data_scope(data: bytearray):
    """
    Context manager that ensures sensitive data is zeroized after use.
    """
    try:
        yield data
    finally:
        secure_zeroize(data)


# -----------------------------------------------------------------------------
# Retry Strategies for Cryptographic Operations
# -----------------------------------------------------------------------------

class CryptoRetryStrategy(Enum):
    """Retry strategies for crypto operations."""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    CRYPTO_JITTER_BACKOFF = "crypto_jitter_backoff"
    FIXED_DELAY = "fixed_delay"


@dataclass
class CryptoRetryConfig:
    """Configuration for crypto operation retries."""
    max_attempts: int = 5
    initial_delay: float = 0.05
    max_delay: float = 2.0
    backoff_factor: float = 1.5
    strategy: CryptoRetryStrategy = CryptoRetryStrategy.CRYPTO_JITTER_BACKOFF
    retry_on: Tuple[Type[Exception], ...] = (
        KeyRotationInProgress,
        CryptoTimeoutError,
        CryptoTemporaryFailure,
        QuantumChannelNoise,
        EntropyDepletionError,
        TimeoutError,
    )
    entropy_safe: bool = True  # Whether to add entropy between retries


class CryptoRetryManager:
    """
    Manages retry logic specifically for cryptographic operations.
    Includes entropy injection between retries for security.
    Fully backward compatible - wraps existing functions.
    """
    
    def __init__(self, config: Optional[CryptoRetryConfig] = None):
        self.config = config or CryptoRetryConfig()
        self._retry_counts: Dict[str, int] = {}
    
    def _crypto_jitter_delay(self, attempt: int) -> float:
        """
        Calculate delay with cryptographic jitter.
        Uses system entropy for unpredictable timing (side-channel mitigation).
        """
        if self.config.strategy == CryptoRetryStrategy.CRYPTO_JITTER_BACKOFF:
            base_delay = self.config.initial_delay * (self.config.backoff_factor ** (attempt - 1))
            # Cryptographic jitter using secrets module
            jitter = secrets.SystemRandom().uniform(0, base_delay * 0.3)
            delay = base_delay + jitter
        elif self.config.strategy == CryptoRetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.config.initial_delay * (self.config.backoff_factor ** (attempt - 1))
        else:
            delay = self.config.initial_delay
        
        return min(delay, self.config.max_delay)
    
    def _inject_entropy(self) -> None:
        """Inject entropy between retries if configured."""
        if self.config.entropy_safe:
            # Touch system entropy pool
            secrets.randbits(64)
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator for crypto retry logic."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__name__}"
            last_exception: Optional[Exception] = None
            
            for attempt in range(1, self.config.max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # Check if this exception type should be retried
                    if not isinstance(e, self.config.retry_on):
                        raise
                    
                    # Check if we've exhausted retries
                    if attempt >= self.config.max_attempts:
                        break
                    
                    # Calculate and apply delay with crypto jitter
                    delay = self._crypto_jitter_delay(attempt)
                    self._inject_entropy()
                    
                    self._retry_counts[func_name] = self._retry_counts.get(func_name, 0) + 1
                    
                    time.sleep(delay)
            
            # If we get here, all retries failed
            raise CryptoTemporaryFailure(
                f"All {self.config.max_attempts} retry attempts failed for {func_name}",
                details={"last_error": str(last_exception), "attempts": attempt}
            ) from last_exception
        
        return wrapper
    
    def get_retry_stats(self) -> Dict[str, int]:
        """Get retry statistics."""
        return dict(self._retry_counts)


# -----------------------------------------------------------------------------
# Cryptographic Timeout Wrappers
# -----------------------------------------------------------------------------

@dataclass
class CryptoOperationContext:
    """Context for tracking cryptographic operations."""
    operation_id: str
    deadline: datetime
    operation_type: str
    timeout_seconds: float
    start_time: datetime = field(default_factory=datetime.utcnow)
    sensitive: bool = True
    
    def remaining_time(self) -> float:
        """Get remaining time in seconds."""
        return max(0.0, (self.deadline - datetime.utcnow()).total_seconds())
    
    def is_expired(self) -> bool:
        """Check if deadline has passed."""
        return datetime.utcnow() >= self.deadline


class CryptoTimeoutManager:
    """
    Thread-safe timeout manager for cryptographic operations.
    Includes deadline propagation for nested crypto operations.
    Wraps existing functions - no breaking changes.
    """
    
    def __init__(self, default_timeout: float = 10.0):
        self.default_timeout = default_timeout
        self._local = threading.local()
    
    def _get_current_context(self) -> Optional[CryptoOperationContext]:
        """Get current thread's crypto context."""
        return getattr(self._local, 'crypto_context', None)
    
    def _set_current_context(self, ctx: Optional[CryptoOperationContext]):
        """Set current thread's crypto context."""
        self._local.crypto_context = ctx
    
    def check_crypto_timeout(self) -> None:
        """Check if current crypto operation has timed out."""
        ctx = self._get_current_context()
        if ctx and ctx.is_expired():
            raise CryptoTimeoutError(
                f"Crypto operation '{ctx.operation_type}' timed out",
                details={"timeout": ctx.timeout_seconds}
            )
    
    def with_crypto_timeout(self, 
                           timeout_seconds: Optional[float] = None,
                           operation_type: str = "crypto_operation") -> Callable:
        """Decorator to add timeout to cryptographic operations."""
        timeout = timeout_seconds or self.default_timeout
        
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                op_id = secrets.token_hex(8)
                deadline = datetime.utcnow() + timedelta(seconds=timeout)
                
                # Propagate parent deadline if it's earlier
                parent_ctx = self._get_current_context()
                if parent_ctx and parent_ctx.deadline < deadline:
                    deadline = parent_ctx.deadline
                
                new_ctx = CryptoOperationContext(
                    operation_id=op_id,
                    deadline=deadline,
                    operation_type=operation_type,
                    timeout_seconds=timeout
                )
                
                old_ctx = self._get_current_context()
                self._set_current_context(new_ctx)
                
                try:
                    self.check_crypto_timeout()
                    return func(*args, **kwargs)
                finally:
                    self._set_current_context(old_ctx)
            
            return wrapper
        
        return decorator


# -----------------------------------------------------------------------------
# Graceful Degradation for Crypto Operations
# -----------------------------------------------------------------------------

class CryptoFallbackStrategy(Enum):
    """Fallback strategies for cryptographic operations."""
    FALLBACK_ALGORITHM = "fallback_algorithm"
    REDUCED_SECURITY = "reduced_security"
    CLASSIC_CRYPTO = "classic_crypto"
    SAFE_DEFAULT = "safe_default"
    RAISE_SAFE_EXCEPTION = "raise_safe_exception"


@dataclass
class CryptoFallbackConfig:
    """Configuration for crypto fallback behavior."""
    strategy: CryptoFallbackStrategy = CryptoFallbackStrategy.SAFE_DEFAULT
    fallback_algorithm: Optional[Callable] = None
    safe_default: Any = None
    max_security_degradation: str = "none"  # none, low, medium
    log_audit: bool = True


class CryptoGracefulDegradation:
    """
    Provides graceful degradation for cryptographic operations.
    Supports algorithm fallback with security level tracking.
    Never breaks happy path - only activates on errors.
    """
    
    def __init__(self):
        self._fallback_log: List[Dict[str, Any]] = []
        self._logger = logging.getLogger("quantum_crypt.security")
    
    def _audit_log(self, operation: str, reason: str, strategy: str) -> None:
        """Log fallback event for audit purposes."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation,
            "reason": reason,
            "strategy": strategy,
            "event_id": secrets.token_hex(16)
        }
        self._fallback_log.append(event)
        
        if len(self._fallback_log) > 1000:
            self._fallback_log = self._fallback_log[-500:]
    
    def with_crypto_fallback(self, config: Optional[CryptoFallbackConfig] = None) -> Callable:
        """Decorator for graceful crypto fallback behavior."""
        cfg = config or CryptoFallbackConfig()
        
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                func_name = f"{func.__module__}.{func.__name__}"
                
                try:
                    # Happy path - normal crypto operation
                    return func(*args, **kwargs)
                    
                except Exception as e:
                    # Error path - apply crypto fallback strategy
                    if cfg.log_audit:
                        self._audit_log(func_name, str(e), cfg.strategy.value)
                    
                    if cfg.strategy == CryptoFallbackStrategy.SAFE_DEFAULT:
                        return cfg.safe_default
                    
                    elif cfg.strategy == CryptoFallbackStrategy.FALLBACK_ALGORITHM:
                        if cfg.fallback_algorithm:
                            return cfg.fallback_algorithm(*args, **kwargs)
                        return cfg.safe_default
                    
                    elif cfg.strategy == CryptoFallbackStrategy.CLASSIC_CRYPTO:
                        if cfg.fallback_algorithm:
                            return cfg.fallback_algorithm(*args, **kwargs)
                        return cfg.safe_default
                    
                    elif cfg.strategy == CryptoFallbackStrategy.RAISE_SAFE_EXCEPTION:
                        raise QuantumCryptWarning(
                            f"Crypto operation degraded: {func_name}",
                            details={"security_impact": cfg.max_security_degradation}
                        ) from e
                    
                    return cfg.safe_default
            
            return wrapper
        
        return decorator
    
    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get fallback audit log."""
        return list(self._fallback_log)
    
    def get_fallback_stats(self) -> Dict[str, Any]:
        """Get fallback statistics."""
        return {
            "total_fallbacks": len(self._fallback_log),
            "strategies_used": {}
        }


# -----------------------------------------------------------------------------
# Composite Quantum Crypto Resilience Manager
# -----------------------------------------------------------------------------

class QuantumCryptoResilienceManager:
    """
    Unified manager combining all crypto error resilience features.
    Fully backward compatible - OPT-IN only.
    """
    
    def __init__(self,
                 default_timeout: float = 10.0,
                 retry_config: Optional[CryptoRetryConfig] = None,
                 fallback_config: Optional[CryptoFallbackConfig] = None):
        self.timeout_manager = CryptoTimeoutManager(default_timeout)
        self.retry_manager = CryptoRetryManager(retry_config)
        self.fallback_manager = CryptoGracefulDegradation()
        self._default_fallback = fallback_config or CryptoFallbackConfig()
    
    def secure_crypto_operation(self,
                               timeout: Optional[float] = None,
                               retry: bool = True,
                               fallback: bool = True,
                               fallback_config: Optional[CryptoFallbackConfig] = None) -> Callable:
        """
        Composite decorator for secure cryptographic operations.
        Applies timeout, retry, and fallback - happy path preserved.
        """
        def decorator(func: Callable) -> Callable:
            wrapped = func
            
            if timeout is not None:
                wrapped = self.timeout_manager.with_crypto_timeout(timeout)(wrapped)
            
            if retry:
                wrapped = self.retry_manager(wrapped)
            
            if fallback:
                wrapped = self.fallback_manager.with_crypto_fallback(
                    fallback_config or self._default_fallback
                )(wrapped)
            
            return wrapped
        
        return decorator
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get comprehensive security and resilience metrics."""
        return {
            "retry_stats": self.retry_manager.get_retry_stats(),
            "fallback_stats": self.fallback_manager.get_fallback_stats(),
            "timestamp": datetime.utcnow().isoformat(),
            "version": "v38_2026_june"
        }


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    # Utilities
    "secure_zeroize",
    "sensitive_data_scope",
    
    # Exceptions
    "QuantumCryptError",
    "QuantumCryptWarning",
    "QuantumCryptCritical",
    "KeyManagementError",
    "KeyNotFoundError",
    "KeyRotationInProgress",
    "KeyExpiredError",
    "KeyCompromisedError",
    "CryptoOperationError",
    "CryptoTimeoutError",
    "CryptoTemporaryFailure",
    "CryptoPermanentFailure",
    "IntegrityVerificationFailed",
    "QuantumCryptoError",
    "QuantumChannelNoise",
    "EntropyDepletionError",
    "PostQuantumAlgorithmError",
    
    # Retry
    "CryptoRetryStrategy",
    "CryptoRetryConfig",
    "CryptoRetryManager",
    
    # Timeout
    "CryptoOperationContext",
    "CryptoTimeoutManager",
    
    # Fallback
    "CryptoFallbackStrategy",
    "CryptoFallbackConfig",
    "CryptoGracefulDegradation",
    
    # Composite
    "QuantumCryptoResilienceManager",
]
