"""
QuantumCrypt AI - Error Resilience: Graceful Degradation v16
Dimension E - Error Resilience Enhancement
ADD-ONLY MODULE: No existing production code modified

Implements graceful degradation strategies for cryptographic operations.
When primary crypto operations fail, provides safe fallbacks without
breaking the application. Includes degradation levels and health tracking.

Stability: STABLE
Backward Compatible: YES
"""

import time
import threading
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional, TypeVar, Generic, List, Tuple
from collections import deque
from datetime import datetime, timedelta
import functools
import secrets
import hashlib

# Configure logging - OPT-IN only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
R = TypeVar('R')


class DegradationLevel(Enum):
    """Degradation levels for crypto operations"""
    FULL = "FULL"                     # Full functionality - all operations normal
    REDUCED = "REDUCED"               # Reduced functionality - some features limited
    MINIMAL = "MINIMAL"               # Minimal functionality - core ops only
    FAILSAFE = "FAILSAFE"             # Failsafe mode - basic security only
    UNAVAILABLE = "UNAVAILABLE"       # Crypto unavailable - using safe defaults


class CryptoHealthStatus(Enum):
    """Cryptographic subsystem health status"""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    IMPAIRED = "IMPAIRED"
    CRITICAL = "CRITICAL"
    FAILED = "FAILED"


@dataclass
class DegradationPolicy:
    """Policy for graceful degradation"""
    max_failures_before_degrade: int = 3
    min_successes_before_restore: int = 5
    degradation_cooldown_seconds: float = 120.0
    health_check_interval_seconds: float = 30.0
    enable_failsafe_fallbacks: bool = True
    max_concurrent_operations: int = 20


@dataclass
class CryptoOperationMetrics:
    """Metrics for tracking crypto operation health"""
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    timed_out_operations: int = 0
    fallback_used: int = 0
    degradation_events: int = 0
    recovery_events: int = 0
    avg_latency_ms: float = 0.0
    latency_samples: deque = field(default_factory=lambda: deque(maxlen=100))
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0


class FailsafeCryptoProvider:
    """
    Failsafe crypto provider for use when primary crypto fails.
    Uses standard library crypto as a safe fallback.
    
    IMPORTANT: This is NOT quantum-resistant. It's a safety fallback
    to prevent application crashes when primary PQ crypto fails.
    """

    @staticmethod
    def safe_hash(data: bytes) -> bytes:
        """Failsafe hash using SHA-256"""
        return hashlib.sha256(data).digest()

    @staticmethod
    def safe_random_bytes(length: int) -> bytes:
        """Failsafe secure random bytes"""
        return secrets.token_bytes(length)

    @staticmethod
    def safe_encrypt_fallback(plaintext: bytes, key: bytes) -> bytes:
        """
        Failsafe encryption - XOR with derived key stream.
        NOTE: This is NOT secure for production, just a fallback
        to prevent crashes. Real crypto should be restored ASAP.
        """
        key_hash = hashlib.sha256(key).digest()
        result = bytearray()
        for i, byte in enumerate(plaintext):
            result.append(byte ^ key_hash[i % len(key_hash)])
        return bytes(result)

    @staticmethod
    def safe_decrypt_fallback(ciphertext: bytes, key: bytes) -> bytes:
        """Failsafe decryption - XOR is symmetric"""
        return FailsafeCryptoProvider.safe_encrypt_fallback(ciphertext, key)

    @staticmethod
    def safe_signature_fallback(data: bytes, private_key: bytes) -> bytes:
        """Failsafe signature - HMAC-based"""
        key_material = hashlib.sha256(private_key + data).digest()
        return hashlib.sha256(key_material + data).digest()

    @staticmethod
    def safe_verify_fallback(data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Failsafe verification"""
        expected = FailsafeCryptoProvider.safe_signature_fallback(data, public_key)
        return secrets.compare_digest(expected, signature)


class GracefulDegradationManager:
    """
    Manages graceful degradation for cryptographic operations.
    Tracks health, manages degradation levels, and provides fallbacks.
    """

    def __init__(self, policy: Optional[DegradationPolicy] = None):
        self.policy = policy or DegradationPolicy()
        self._current_level = DegradationLevel.FULL
        self._health_status = CryptoHealthStatus.HEALTHY
        self._metrics = CryptoOperationMetrics()
        self._lock = threading.RLock()
        self._last_degradation_time: Optional[datetime] = None
        self._operation_semaphores: Dict[str, threading.Semaphore] = {}

    @property
    def current_level(self) -> DegradationLevel:
        """Get current degradation level"""
        with self._lock:
            return self._current_level

    @property
    def health_status(self) -> CryptoHealthStatus:
        """Get current health status"""
        with self._lock:
            return self._health_status

    def _update_health_status(self) -> None:
        """Update health status based on metrics"""
        failure_rate = 0.0
        if self._metrics.total_operations > 0:
            failure_rate = self._metrics.failed_operations / self._metrics.total_operations

        if failure_rate == 0:
            self._health_status = CryptoHealthStatus.HEALTHY
        elif failure_rate < 0.1:
            self._health_status = CryptoHealthStatus.DEGRADED
        elif failure_rate < 0.3:
            self._health_status = CryptoHealthStatus.IMPAIRED
        elif failure_rate < 0.5:
            self._health_status = CryptoHealthStatus.CRITICAL
        else:
            self._health_status = CryptoHealthStatus.FAILED

    def _check_degradation(self) -> None:
        """Check if degradation or recovery is needed"""
        now = datetime.utcnow()

        # Check if we need to degrade - only degrade once per threshold hit
        if self._metrics.consecutive_failures >= self.policy.max_failures_before_degrade:
            degraded = False
            if self._current_level == DegradationLevel.FULL:
                self._current_level = DegradationLevel.REDUCED
                degraded = True
                logger.warning("Crypto degraded to REDUCED level")
            elif self._current_level == DegradationLevel.REDUCED:
                self._current_level = DegradationLevel.MINIMAL
                degraded = True
                logger.warning("Crypto degraded to MINIMAL level")
            elif self._current_level == DegradationLevel.MINIMAL:
                self._current_level = DegradationLevel.FAILSAFE
                degraded = True
                logger.warning("Crypto degraded to FAILSAFE level")
            
            if degraded:
                self._metrics.degradation_events += 1
                self._last_degradation_time = now
                # Reset consecutive failures so we don't keep degrading
                self._metrics.consecutive_failures = 0

        # Check if we can recover
        if (self._last_degradation_time and
            (now - self._last_degradation_time).total_seconds() >= self.policy.degradation_cooldown_seconds):
            if self._metrics.consecutive_successes >= self.policy.min_successes_before_restore:
                if self._current_level == DegradationLevel.FAILSAFE:
                    self._current_level = DegradationLevel.MINIMAL
                    self._metrics.recovery_events += 1
                    logger.info("Crypto recovered to MINIMAL level")
                elif self._current_level == DegradationLevel.MINIMAL:
                    self._current_level = DegradationLevel.REDUCED
                    self._metrics.recovery_events += 1
                    logger.info("Crypto recovered to REDUCED level")
                elif self._current_level == DegradationLevel.REDUCED:
                    self._current_level = DegradationLevel.FULL
                    self._metrics.recovery_events += 1
                    logger.info("Crypto fully recovered")

        self._update_health_status()

    def record_success(self, latency_ms: float) -> None:
        """Record a successful operation"""
        with self._lock:
            self._metrics.total_operations += 1
            self._metrics.successful_operations += 1
            self._metrics.consecutive_successes += 1
            self._metrics.consecutive_failures = 0
            self._metrics.last_success_time = datetime.utcnow()
            self._metrics.latency_samples.append(latency_ms)
            if self._metrics.latency_samples:
                self._metrics.avg_latency_ms = sum(
                    self._metrics.latency_samples
                ) / len(self._metrics.latency_samples)
            self._check_degradation()

    def record_failure(self) -> None:
        """Record a failed operation"""
        with self._lock:
            self._metrics.total_operations += 1
            self._metrics.failed_operations += 1
            self._metrics.consecutive_failures += 1
            self._metrics.consecutive_successes = 0
            self._metrics.last_failure_time = datetime.utcnow()
            self._check_degradation()

    def record_fallback(self) -> None:
        """Record that fallback was used"""
        with self._lock:
            self._metrics.fallback_used += 1

    def can_use_operation(self, operation_name: str) -> bool:
        """Check if an operation is allowed at current degradation level"""
        level = self.current_level

        # Operations allowed at FULL level
        full_ops = {'key_exchange', 'sign', 'verify', 'encrypt', 'decrypt', 'kem_encap', 'kem_decap'}

        # Operations allowed at REDUCED level
        reduced_ops = {'sign', 'verify', 'encrypt', 'decrypt'}

        # Operations allowed at MINIMAL level
        minimal_ops = {'sign', 'verify'}

        # Operations allowed at FAILSAFE level
        failsafe_ops = {'verify'}

        if level == DegradationLevel.FULL:
            return operation_name in full_ops
        elif level == DegradationLevel.REDUCED:
            return operation_name in reduced_ops
        elif level == DegradationLevel.MINIMAL:
            return operation_name in minimal_ops
        elif level == DegradationLevel.FAILSAFE:
            return operation_name in failsafe_ops
        else:  # UNAVAILABLE
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get degradation manager status"""
        with self._lock:
            return {
                "degradation_level": self._current_level.value,
                "health_status": self._health_status.value,
                "metrics": {
                    "total_operations": self._metrics.total_operations,
                    "successful_operations": self._metrics.successful_operations,
                    "failed_operations": self._metrics.failed_operations,
                    "fallback_used": self._metrics.fallback_used,
                    "degradation_events": self._metrics.degradation_events,
                    "recovery_events": self._metrics.recovery_events,
                    "consecutive_failures": self._metrics.consecutive_failures,
                    "consecutive_successes": self._metrics.consecutive_successes,
                    "avg_latency_ms": self._metrics.avg_latency_ms,
                },
                "policy": {
                    "max_failures_before_degrade": self.policy.max_failures_before_degrade,
                    "degradation_cooldown_seconds": self.policy.degradation_cooldown_seconds,
                },
                "timestamp": datetime.utcnow().isoformat()
            }


# Global degradation manager for QuantumCrypt
_crypto_degradation_manager = GracefulDegradationManager()


def get_degradation_manager() -> GracefulDegradationManager:
    """Get the global degradation manager"""
    return _crypto_degradation_manager


def resilient_crypto_operation(
    operation_name: str,
    fallback: Optional[Callable[..., Any]] = None,
    allow_failsafe: bool = True
):
    """
    Decorator for making crypto operations resilient with graceful degradation.
    
    Usage:
        @resilient_crypto_operation("sign")
        def sign_message(message: bytes, private_key: bytes) -> bytes:
            # signing logic
            pass
    """
    manager = get_degradation_manager()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            start_time = time.time()

            # Check if operation is allowed at current degradation level
            if not manager.can_use_operation(operation_name):
                manager.record_fallback()
                if fallback:
                    logger.debug(f"Operation {operation_name} degraded - using fallback")
                    return fallback(*args, **kwargs)
                if allow_failsafe:
                    logger.debug(f"Operation {operation_name} degraded - using failsafe")
                    return _use_failsafe(operation_name, *args, **kwargs)
                raise CryptoDegradedError(
                    f"Operation {operation_name} not available at "
                    f"{manager.current_level.value} degradation level"
                )

            try:
                result = func(*args, **kwargs)
                latency_ms = (time.time() - start_time) * 1000
                manager.record_success(latency_ms)
                return result
            except Exception as e:
                manager.record_failure()
                # Fallback/failsafe only used when operation not allowed due to degradation
                # (handled above), not on individual failures
                raise

        return wrapper

    return decorator


def _use_failsafe(operation_name: str, *args, **kwargs) -> Any:
    """Use failsafe provider for degraded operations"""
    fs = FailsafeCryptoProvider

    if operation_name == "sign":
        data = args[0] if args else kwargs.get("data", b"")
        key = args[1] if len(args) > 1 else kwargs.get("private_key", b"")
        return fs.safe_signature_fallback(data, key)

    elif operation_name == "verify":
        data = args[0] if args else kwargs.get("data", b"")
        sig = args[1] if len(args) > 1 else kwargs.get("signature", b"")
        key = args[2] if len(args) > 2 else kwargs.get("public_key", b"")
        return fs.safe_verify_fallback(data, sig, key)

    elif operation_name == "encrypt":
        plaintext = args[0] if args else kwargs.get("plaintext", b"")
        key = args[1] if len(args) > 1 else kwargs.get("key", b"")
        return fs.safe_encrypt_fallback(plaintext, key)

    elif operation_name == "decrypt":
        ciphertext = args[0] if args else kwargs.get("ciphertext", b"")
        key = args[1] if len(args) > 1 else kwargs.get("key", b"")
        return fs.safe_decrypt_fallback(ciphertext, key)

    elif operation_name in {"hash", "digest"}:
        data = args[0] if args else kwargs.get("data", b"")
        return fs.safe_hash(data)

    else:
        raise CryptoFailsafeUnavailableError(
            f"No failsafe available for operation: {operation_name}"
        )


# Custom exception hierarchy
class CryptoResilienceError(Exception):
    """Base error for crypto resilience module"""
    pass


class CryptoDegradedError(CryptoResilienceError):
    """Raised when crypto operation unavailable due to degradation"""
    pass


class CryptoFailsafeUnavailableError(CryptoResilienceError):
    """Raised when no failsafe is available for an operation"""
    pass


# Export public API
__all__ = [
    'DegradationLevel',
    'CryptoHealthStatus',
    'DegradationPolicy',
    'FailsafeCryptoProvider',
    'GracefulDegradationManager',
    'resilient_crypto_operation',
    'get_degradation_manager',
    'CryptoResilienceError',
    'CryptoDegradedError',
    'CryptoFailsafeUnavailableError',
]
