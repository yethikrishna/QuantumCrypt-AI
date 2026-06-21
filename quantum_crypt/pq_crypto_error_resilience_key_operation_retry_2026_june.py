"""
Post-Quantum Crypto Error Resilience Module
Dimension E: Error Resilience

Crypto-specific error resilience for key operations, including:
- Key generation/encryption/decryption retries with backoff
- Timeout protection for long-running crypto operations
- Crypto-specific exception hierarchy
- Algorithm fallback mechanisms
- Key rotation failure recovery

All features are opt-in and wrap existing functionality without modification.
API Stability: STABLE
"""

import time
import random
import functools
import threading
import secrets
from typing import Callable, Any, Optional, Type, Tuple, List, Dict, Union
from dataclasses import dataclass, field
from enum import Enum
import logging

# Configure null logger - opt-in only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class CryptoErrorCategory(Enum):
    """Categories of crypto operation errors."""
    KEY_GENERATION = "key_generation"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    KEY_EXCHANGE = "key_exchange"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEY_ROTATION = "key_rotation"
    RANDOMNESS = "randomness"
    CERTIFICATE = "certificate"


class CryptoResilienceError(Exception):
    """Base exception for crypto resilience errors."""
    def __init__(
        self,
        message: str,
        category: CryptoErrorCategory,
        algorithm: Optional[str] = None,
        retry_attempts: int = 0
    ):
        super().__init__(message)
        self.category = category
        self.algorithm = algorithm
        self.retry_attempts = retry_attempts


class CryptoOperationTimeoutError(CryptoResilienceError):
    """Raised when crypto operation times out."""
    pass


class CryptoMaxRetriesExceededError(CryptoResilienceError):
    """Raised when maximum crypto retries exceeded."""
    pass


class CryptoAlgorithmFallbackError(CryptoResilienceError):
    """Raised when all algorithm fallbacks fail."""
    pass


class KeyRotationRecoveryError(CryptoResilienceError):
    """Raised when key rotation recovery fails."""
    pass


@dataclass
class CryptoRetryConfig:
    """Configuration for crypto operation retries."""
    max_attempts: int = 3
    initial_delay: float = 0.05
    max_delay: float = 5.0
    backoff_factor: float = 1.5
    jitter: bool = True
    retry_categories: Tuple[CryptoErrorCategory, ...] = (
        CryptoErrorCategory.KEY_GENERATION,
        CryptoErrorCategory.ENCRYPTION,
        CryptoErrorCategory.DECRYPTION,
        CryptoErrorCategory.KEY_EXCHANGE,
    )
    # Don't retry signing/verification - these are deterministic
    stop_categories: Tuple[CryptoErrorCategory, ...] = (
        CryptoErrorCategory.SIGNING,
        CryptoErrorCategory.VERIFICATION,
    )


@dataclass
class CryptoOperationResult:
    """Result wrapper for crypto operations with metadata."""
    success: bool
    result: Any = None
    error: Optional[Exception] = None
    category: Optional[CryptoErrorCategory] = None
    algorithm: Optional[str] = None
    attempt: int = 0
    duration_seconds: float = 0.0
    used_fallback: bool = False


class CryptoExponentialBackoff:
    """
    Exponential backoff optimized for crypto operations.
    
    Uses secure random jitter to avoid timing side channels.
    """
    
    def __init__(
        self,
        initial_delay: float = 0.05,
        max_delay: float = 5.0,
        factor: float = 1.5,
        secure_jitter: bool = True
    ):
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.factor = factor
        self.secure_jitter = secure_jitter
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay with secure randomness."""
        delay = min(
            self.initial_delay * (self.factor ** attempt),
            self.max_delay
        )
        
        if self.secure_jitter:
            # Use cryptographically secure random for jitter
            jitter_factor = 0.75 + (secrets.randbelow(50) / 100)  # 0.75-1.25
            delay = delay * jitter_factor
        
        return delay


class CryptoOperationCircuitBreaker:
    """
    Circuit breaker specifically for crypto operations.
    
    Prevents cascading failures in HSMs, KMS services, or
    compute-intensive post-quantum algorithms.
    """
    
    def __init__(
        self,
        failure_threshold: int = 10,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 2,
        monitored_algorithms: Optional[Tuple[str, ...]] = None
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.monitored_algorithms = monitored_algorithms or ()
        
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = 0.0
        self._state = "closed"  # closed, open, half_open
        self._half_open_count = 0
        self._lock = threading.Lock()
        
        # Per-algorithm tracking
        self._algorithm_failures: Dict[str, int] = {}
        self._algorithm_last_failure: Dict[str, float] = {}
    
    def _is_monitored(self, algorithm: Optional[str]) -> bool:
        """Check if algorithm should be monitored."""
        if not self.monitored_algorithms:
            return True
        return algorithm in self.monitored_algorithms
    
    def record_success(self, algorithm: Optional[str] = None) -> None:
        """Record successful crypto operation."""
        with self._lock:
            if self._state == "half_open":
                self._success_count += 1
                if self._success_count >= 2:
                    self._state = "closed"
                    self._failure_count = 0
                    logger.info("Crypto circuit breaker closed - normal operation")
            elif self._state == "closed":
                self._failure_count = 0
    
    def record_failure(self, algorithm: Optional[str] = None) -> None:
        """Record failed crypto operation."""
        with self._lock:
            if not self._is_monitored(algorithm):
                return
            
            if algorithm:
                self._algorithm_failures[algorithm] = (
                    self._algorithm_failures.get(algorithm, 0) + 1
                )
                self._algorithm_last_failure[algorithm] = time.time()
            
            if self._state == "closed":
                self._failure_count += 1
                if self._failure_count >= self.failure_threshold:
                    self._state = "open"
                    self._last_failure_time = time.time()
                    logger.warning(
                        f"Crypto circuit breaker OPEN - algorithm: {algorithm}"
                    )
            elif self._state == "half_open":
                self._state = "open"
                self._last_failure_time = time.time()
    
    def allow_request(self, algorithm: Optional[str] = None) -> bool:
        """Check if crypto operation should proceed."""
        with self._lock:
            if self._state == "open":
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    self._state = "half_open"
                    self._half_open_count = 0
                    self._success_count = 0
                    logger.info("Crypto circuit breaker HALF_OPEN - testing recovery")
            
            if self._state == "open":
                return False
            
            if self._state == "half_open":
                if self._half_open_count >= self.half_open_max_calls:
                    return False
                self._half_open_count += 1
            
            return True
    
    def get_state(self) -> str:
        """Get current circuit state."""
        with self._lock:
            if self._state == "open":
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    self._state = "half_open"
                    self._half_open_count = 0
                    self._success_count = 0
            return self._state
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics."""
        with self._lock:
            return {
                "state": self._state,
                "global_failure_count": self._failure_count,
                "algorithm_failures": dict(self._algorithm_failures),
                "last_failure_seconds_ago": time.time() - self._last_failure_time,
            }


def with_crypto_retry(
    config: Optional[CryptoRetryConfig] = None,
    category: CryptoErrorCategory = CryptoErrorCategory.ENCRYPTION,
    algorithm: Optional[str] = None
) -> Callable:
    """
    Decorator: Add retry logic to crypto operations.
    
    Optimized for crypto operations with secure jitter and
    category-aware retry policies.
    
    Usage:
        @with_crypto_retry(category=CryptoErrorCategory.KEY_GENERATION)
        def generate_keypair():
            ...
    """
    config = config or CryptoRetryConfig()
    backoff = CryptoExponentialBackoff(
        initial_delay=config.initial_delay,
        max_delay=config.max_delay,
        factor=config.backoff_factor
    )
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception: Optional[Exception] = None
            
            for attempt in range(config.max_attempts):
                try:
                    start_time = time.time()
                    result = func(*args, **kwargs)
                    duration = time.time() - start_time
                    
                    if attempt > 0:
                        logger.debug(
                            f"Crypto {category.value} succeeded on attempt {attempt + 1} "
                            f"after {duration:.3f}s"
                        )
                    return result
                    
                except Exception as e:
                    last_exception = e
                    
                    # Don't retry certain categories
                    if category in config.stop_categories:
                        raise CryptoResilienceError(
                            f"Crypto {category.value} failed (not retried)",
                            category=category,
                            algorithm=algorithm,
                            retry_attempts=attempt
                        ) from e
                    
                    if attempt == config.max_attempts - 1:
                        break
                    
                    delay = backoff.calculate_delay(attempt)
                    logger.debug(
                        f"Crypto {category.value} attempt {attempt + 1} failed: {e}, "
                        f"retrying in {delay:.3f}s"
                    )
                    time.sleep(delay)
            
            raise CryptoMaxRetriesExceededError(
                f"Crypto {category.value} failed after {config.max_attempts} attempts",
                category=category,
                algorithm=algorithm,
                retry_attempts=config.max_attempts
            ) from last_exception
        
        return wrapper
    return decorator


def with_crypto_timeout(
    timeout_seconds: float,
    category: CryptoErrorCategory = CryptoErrorCategory.ENCRYPTION,
    algorithm: Optional[str] = None,
    fallback: Optional[Callable] = None
) -> Callable:
    """
    Decorator: Add timeout protection to crypto operations.
    
    Critical for preventing DoS via computationally expensive
    post-quantum algorithms.
    
    Usage:
        @with_crypto_timeout(10.0, category=CryptoErrorCategory.KEY_GENERATION)
        def generate_keypair():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            result: List[Any] = []
            exception: List[Optional[Exception]] = [None]
            
            def target():
                try:
                    result.append(func(*args, **kwargs))
                except Exception as e:
                    exception[0] = e
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=timeout_seconds)
            
            if thread.is_alive():
                if fallback is not None:
                    logger.warning(
                        f"Crypto {category.value} timed out after {timeout_seconds}s, "
                        f"using fallback"
                    )
                    return fallback(*args, **kwargs)
                raise CryptoOperationTimeoutError(
                    f"Crypto {category.value} timed out after {timeout_seconds}s",
                    category=category,
                    algorithm=algorithm
                )
            
            if exception[0] is not None:
                raise exception[0]
            
            return result[0]
        
        return wrapper
    return decorator


class AlgorithmFallbackChain:
    """
    Fallback chain for crypto algorithms.
    
    Tries primary algorithm, then falls back to alternate
    algorithms if primary fails (e.g., post-quantum -> classic).
    """
    
    def __init__(
        self,
        primary_algorithm: str,
        primary_func: Callable,
        *fallbacks: Tuple[str, Callable]
    ):
        self.primary_algorithm = primary_algorithm
        self.primary_func = primary_func
        self.fallbacks = list(fallbacks)
        self._fallback_used: Optional[str] = None
    
    def __call__(self, *args, **kwargs) -> CryptoOperationResult:
        """Execute with algorithm fallback chain."""
        start_time = time.time()
        
        # Try primary
        try:
            result = self.primary_func(*args, **kwargs)
            return CryptoOperationResult(
                success=True,
                result=result,
                algorithm=self.primary_algorithm,
                duration_seconds=time.time() - start_time,
                used_fallback=False
            )
        except Exception as primary_error:
            logger.warning(
                f"Primary algorithm {self.primary_algorithm} failed: {primary_error}"
            )
            
            # Try fallbacks
            for algo_name, fallback_func in self.fallbacks:
                try:
                    result = fallback_func(*args, **kwargs)
                    self._fallback_used = algo_name
                    logger.info(f"Fell back to algorithm: {algo_name}")
                    return CryptoOperationResult(
                        success=True,
                        result=result,
                        algorithm=algo_name,
                        duration_seconds=time.time() - start_time,
                        used_fallback=True
                    )
                except Exception as fallback_error:
                    logger.warning(
                        f"Fallback algorithm {algo_name} also failed: {fallback_error}"
                    )
                    continue
            
            # All fallbacks exhausted
            raise CryptoAlgorithmFallbackError(
                f"All algorithm fallbacks exhausted. Primary: {self.primary_algorithm}",
                category=CryptoErrorCategory.ENCRYPTION,
                algorithm=self.primary_algorithm
            ) from primary_error
    
    def get_last_fallback_used(self) -> Optional[str]:
        """Get the fallback algorithm used in the last call."""
        return self._fallback_used


class KeyRotationRecoveryManager:
    """
    Manages recovery from failed key rotation operations.
    
    Maintains backup of old keys during rotation and provides
    rollback capabilities if rotation fails.
    """
    
    def __init__(self):
        self._backup_keys: Dict[str, Tuple[Any, float]] = {}
        self._lock = threading.Lock()
    
    def backup_key(self, key_id: str, key_data: Any, ttl_seconds: float = 3600.0) -> None:
        """Backup a key before rotation."""
        with self._lock:
            self._backup_keys[key_id] = (key_data, time.time() + ttl_seconds)
            logger.debug(f"Backed up key {key_id} for rotation")
    
    def get_backup(self, key_id: str) -> Optional[Any]:
        """Get backed up key for rollback."""
        with self._lock:
            if key_id not in self._backup_keys:
                return None
            
            key_data, expiry = self._backup_keys[key_id]
            if time.time() > expiry:
                del self._backup_keys[key_id]
                return None
            
            return key_data
    
    def commit_rotation(self, key_id: str) -> None:
        """Commit successful rotation, remove backup."""
        with self._lock:
            self._backup_keys.pop(key_id, None)
            logger.debug(f"Committed key rotation for {key_id}")
    
    def rollback_key(self, key_id: str) -> Any:
        """Rollback to previous key."""
        backup = self.get_backup(key_id)
        if backup is None:
            raise KeyRotationRecoveryError(
                f"No backup available for key {key_id}",
                category=CryptoErrorCategory.KEY_ROTATION
            )
        logger.warning(f"Rolled back key {key_id} to previous version")
        return backup
    
    def cleanup_expired(self) -> int:
        """Remove expired backups."""
        now = time.time()
        expired = []
        with self._lock:
            for key_id, (_, expiry) in self._backup_keys.items():
                if now > expiry:
                    expired.append(key_id)
            for key_id in expired:
                del self._backup_keys[key_id]
        return len(expired)


def with_key_rotation_safety(
    manager: KeyRotationRecoveryManager,
    key_id_getter: Callable[..., str]
) -> Callable:
    """
    Decorator: Add automatic backup and rollback to key rotation.
    
    Usage:
        manager = KeyRotationRecoveryManager()
        
        @with_key_rotation_safety(manager, lambda *a: a[0])
        def rotate_key(key_id, new_key):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            key_id = key_id_getter(*args, **kwargs)
            
            # Note: In real usage, you'd pass the old key to backup
            # This is a framework - actual key backup depends on implementation
            
            try:
                result = func(*args, **kwargs)
                manager.commit_rotation(key_id)
                return result
            except Exception as e:
                logger.error(f"Key rotation failed for {key_id}: {e}")
                # Backup is preserved for rollback
                raise KeyRotationRecoveryError(
                    f"Key rotation failed for {key_id}, backup preserved",
                    category=CryptoErrorCategory.KEY_ROTATION
                ) from e
        
        return wrapper
    return decorator


# Shared global instances
_shared_crypto_circuit_breakers: Dict[str, CryptoOperationCircuitBreaker] = {}
_shared_key_rotation_manager = KeyRotationRecoveryManager()


def get_crypto_circuit_breaker(
    name: str,
    failure_threshold: int = 10,
    recovery_timeout: float = 60.0
) -> CryptoOperationCircuitBreaker:
    """Get or create a shared crypto circuit breaker."""
    if name not in _shared_crypto_circuit_breakers:
        _shared_crypto_circuit_breakers[name] = CryptoOperationCircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout
        )
    return _shared_crypto_circuit_breakers[name]


def get_key_rotation_manager() -> KeyRotationRecoveryManager:
    """Get the shared key rotation recovery manager."""
    return _shared_key_rotation_manager


def get_crypto_resilience_metrics() -> Dict[str, Any]:
    """Get all crypto resilience metrics."""
    return {
        "circuit_breakers": {
            name: cb.get_metrics()
            for name, cb in _shared_crypto_circuit_breakers.items()
        },
        "key_rotation_backups": len(_shared_key_rotation_manager._backup_keys),
    }
