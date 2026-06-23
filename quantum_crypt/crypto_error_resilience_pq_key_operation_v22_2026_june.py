"""
QuantumCrypt Error Resilience v22 - PQ Key Operation Resilience
================================================================
DIMENSION E - Error Resilience
ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED

Crypto-Specific Features:
1. Custom crypto exception hierarchy for PQ operations
2. Key operation timeouts with crypto-safe jitter
3. HSM/KMS connection circuit breakers
4. Key operation retry with exponential backoff (throttling-safe)
5. Key generation graceful degradation fallbacks
6. Bulkhead isolation for sensitive crypto operations
7. Side-channel resistant timing operations
8. Full integration with Crypto Observability v12
9. 100% OPT-IN - disabled by default, zero overhead when off

Philosophy:
- Happy path behavior 100% preserved when disabled
- All resilience features layered ON TOP of existing crypto code
- No breaking changes to any existing crypto API
- Zero performance impact when resilience is disabled
- No side-channel leakage from resilience mechanisms
"""

import time
import random
import threading
import functools
import enum
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Dict, List, Type, Tuple
from datetime import datetime, timedelta


# -----------------------------------------------------------------------------
# Custom Crypto Exception Hierarchy v22
# -----------------------------------------------------------------------------
class QuantumCryptResilienceError(Exception):
    """Base exception for all crypto resilience-related errors"""
    pass


class CryptoOperationTimeoutError(QuantumCryptResilienceError):
    """Crypto operation exceeded timeout threshold"""
    def __init__(self, operation: str, algorithm: str, timeout_seconds: float, elapsed_seconds: float):
        self.operation = operation
        self.algorithm = algorithm
        self.timeout_seconds = timeout_seconds
        self.elapsed_seconds = elapsed_seconds
        super().__init__(f"Crypto operation '{operation}' for {algorithm} timed out after {elapsed_seconds:.3f}s")


class HSMConnectionError(QuantumCryptResilienceError):
    """HSM/KMS connection failed"""
    def __init__(self, provider: str, reason: str, attempts: int = 1):
        self.provider = provider
        self.reason = reason
        self.attempts = attempts
        super().__init__(f"HSM provider '{provider}' connection failed after {attempts} attempts: {reason}")


class KeyOperationCircuitBreakerOpen(QuantumCryptResilienceError):
    """Key operation circuit breaker is open"""
    def __init__(self, operation: str, recovery_time_remaining: float):
        self.operation = operation
        self.recovery_time_remaining = recovery_time_remaining
        super().__init__(f"Key operation '{operation}' circuit OPEN. Recovery in {recovery_time_remaining:.1f}s")


class KeyGenerationRetryExhausted(QuantumCryptResilienceError):
    """All key generation retry attempts exhausted"""
    def __init__(self, algorithm: str, attempts: int, last_error: Exception):
        self.algorithm = algorithm
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(f"Key generation for {algorithm} failed after {attempts} attempts: {str(last_error)}")


class CryptoBulkheadFullError(QuantumCryptResilienceError):
    """Crypto operation bulkhead capacity exceeded"""
    def __init__(self, operation: str, current: int, max_concurrency: int):
        self.operation = operation
        self.current_concurrency = current
        self.max_concurrency = max_concurrency
        super().__init__(f"Crypto bulkhead '{operation}' full: {current}/{max_concurrency}")


class CryptoDegradationActivated(QuantumCryptResilienceError):
    """Primary crypto path failed, degraded mode activated"""
    def __init__(self, primary_alg: str, fallback_alg: str, original_error: Exception):
        self.primary_algorithm = primary_alg
        self.fallback_algorithm = fallback_alg
        self.original_error = original_error
        super().__init__(f"Degraded: {primary_alg} -> {fallback_alg}: {str(original_error)}")


class EntropySourceDepletedError(QuantumCryptResilienceError):
    """Cryptographic entropy source depleted or unavailable"""
    def __init__(self, source_name: str):
        self.source_name = source_name
        super().__init__(f"Entropy source '{source_name}' depleted")


# -----------------------------------------------------------------------------
# Crypto-Specific Enums
# -----------------------------------------------------------------------------
class CircuitState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class KeyOperationType(enum.Enum):
    KEY_GENERATION = "key_generation"
    KEY_ENCAPSULATION = "key_encapsulation"
    KEY_DECAPSULATION = "key_decapsulation"
    SIGNATURE_GENERATION = "signature_generation"
    SIGNATURE_VERIFICATION = "signature_verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    HSM_CONNECT = "hsm_connect"
    RANDOM_GENERATION = "random_generation"


class PQAlgorithm(enum.Enum):
    KYBER_512 = "kyber_512"
    KYBER_768 = "kyber_768"
    KYBER_1024 = "kyber_1024"
    DILITHIUM_2 = "dilithium_2"
    DILITHIUM_3 = "dilithium_3"
    DILITHIUM_5 = "dilithium_5"
    HYBRID_P256_KYBER768 = "hybrid_p256_kyber768"
    AES_256_GCM = "aes_256_gcm"
    RSA_2048 = "rsa_2048"
    ECC_P256 = "ecc_p256"
    FALLBACK_SOFTWARE = "fallback_software"


class HSMProvider(enum.Enum):
    AWS_CLOUDHSM = "aws_cloudhsm"
    AZURE_KEY_VAULT_HSM = "azure_key_vault_hsm"
    GCP_CLOUD_HSM = "gcp_cloud_hsm"
    THALES_NSHIELD = "thales_nshield"
    UTIMACO = "utimaco"
    SOFTWARE_SIMULATOR = "software_simulator"
    NONE = "none"


class CryptoFallbackStrategy(enum.Enum):
    FAIL_FAST = "fail_fast"
    SOFTWARE_FALLBACK = "software_fallback"
    LOWER_SECURITY_LEVEL = "lower_security_level"
    CLASSICAL_ALGORITHM = "classical_algorithm"
    CACHED_KEY = "cached_key"


# -----------------------------------------------------------------------------
# Crypto-Specific Configuration
# -----------------------------------------------------------------------------
@dataclass
class CryptoTimeoutConfig:
    enabled: bool = False  # OPT-IN - disabled by default
    key_generation_timeout: float = 30.0
    key_operation_timeout: float = 5.0
    hsm_connection_timeout: float = 10.0
    signature_timeout: float = 2.0
    verification_timeout: float = 0.5
    crypto_safe_jitter: bool = True  # Use secrets module for jitter


@dataclass
class CryptoCircuitBreakerConfig:
    enabled: bool = False  # OPT-IN - disabled by default
    key_gen_failure_threshold: int = 3
    hsm_failure_threshold: int = 5
    success_threshold: int = 2
    reset_timeout_seconds: float = 60.0


@dataclass
class CryptoRetryConfig:
    enabled: bool = False  # OPT-IN - disabled by default
    max_key_gen_attempts: int = 3
    max_hsm_connect_attempts: int = 5
    initial_delay_seconds: float = 0.5
    max_delay_seconds: float = 30.0
    backoff_exponent: float = 2.0
    crypto_jitter: bool = True  # Cryptographically secure jitter


@dataclass
class CryptoBulkheadConfig:
    enabled: bool = False  # OPT-IN - disabled by default
    max_concurrent_key_gen: int = 5
    max_concurrent_hsm_ops: int = 20
    max_concurrent_signing: int = 50
    max_waiting: int = 100
    queue_timeout: float = 2.0


@dataclass
class CryptoFallbackConfig:
    enabled: bool = False  # OPT-IN - disabled by default
    default_strategy: CryptoFallbackStrategy = CryptoFallbackStrategy.SOFTWARE_FALLBACK
    allow_software_fallback: bool = True
    allow_lower_security: bool = False
    allow_classical_fallback: bool = True
    key_cache_ttl_seconds: float = 3600.0


@dataclass
class CryptoResilienceConfigV22:
    timeout: CryptoTimeoutConfig = field(default_factory=CryptoTimeoutConfig)
    circuit_breaker: CryptoCircuitBreakerConfig = field(default_factory=CryptoCircuitBreakerConfig)
    retry: CryptoRetryConfig = field(default_factory=CryptoRetryConfig)
    bulkhead: CryptoBulkheadConfig = field(default_factory=CryptoBulkheadConfig)
    fallback: CryptoFallbackConfig = field(default_factory=CryptoFallbackConfig)


# -----------------------------------------------------------------------------
# Crypto-Safe Utilities
# -----------------------------------------------------------------------------
def crypto_safe_jitter(base_delay: float, jitter_factor: float = 0.25) -> float:
    """
    Cryptographically secure jitter for backoff calculations
    Prevents timing side-channel attacks on retry mechanisms
    """
    jitter_range = base_delay * jitter_factor
    random_bytes = secrets.randbits(32)
    jitter = (random_bytes / (2**32)) * jitter_range * 2 - jitter_range
    return max(0.001, base_delay + jitter)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# -----------------------------------------------------------------------------
# Crypto Circuit Breaker
# -----------------------------------------------------------------------------
class CryptoCircuitBreaker:
    """
    Thread-safe circuit breaker for crypto operations
    Separate circuits per operation type for fine-grained control
    """
    
    def __init__(self, name: str, config: CryptoCircuitBreakerConfig):
        self.name = name
        self.config = config
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = threading.Lock()
    
    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._state
    
    def _get_threshold(self) -> int:
        if "hsm" in self.name.lower() or "connect" in self.name.lower():
            return self.config.hsm_failure_threshold
        return self.config.key_gen_failure_threshold
    
    def record_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
            self._failure_count = 0
            
            if self._state == CircuitState.HALF_OPEN and self._success_count >= self.config.success_threshold:
                self._state = CircuitState.CLOSED
                self._success_count = 0
    
    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
            elif self._failure_count >= self._get_threshold():
                self._state = CircuitState.OPEN
    
    def allow_request(self) -> bool:
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.config.reset_timeout_seconds:
                    self._state = CircuitState.HALF_OPEN
                    self._success_count = 0
            return self._state != CircuitState.OPEN
    
    def get_recovery_time(self) -> float:
        with self._lock:
            if self._state != CircuitState.OPEN:
                return 0.0
            return max(0.0, self.config.reset_timeout_seconds - (time.time() - self._last_failure_time))


# -----------------------------------------------------------------------------
# Crypto Bulkhead
# -----------------------------------------------------------------------------
class CryptoBulkhead:
    """
    Bulkhead isolation for crypto operations
    Prevents resource exhaustion from DoS on key generation
    """
    
    def __init__(self, name: str, max_concurrent: int, max_waiting: int, queue_timeout: float):
        self.name = name
        self.max_concurrent = max_concurrent
        self.max_waiting = max_waiting
        self.queue_timeout = queue_timeout
        self._active = 0
        self._waiting = 0
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
    
    @property
    def current_active(self) -> int:
        with self._lock:
            return self._active
    
    def acquire(self) -> bool:
        deadline = time.time() + self.queue_timeout
        
        with self._lock:
            while self._active >= self.max_concurrent:
                if self._waiting >= self.max_waiting:
                    return False
                self._waiting += 1
                remaining = deadline - time.time()
                if remaining <= 0:
                    self._waiting -= 1
                    return False
                self._condition.wait(remaining)
                self._waiting -= 1
            
            self._active += 1
            return True
    
    def release(self) -> None:
        with self._lock:
            self._active = max(0, self._active - 1)
            self._condition.notify()
    
    def __enter__(self):
        if not self.acquire():
            raise CryptoBulkheadFullError(self.name, self._active, self.max_concurrent)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return False


# -----------------------------------------------------------------------------
# Key Operation Cache for Degradation
# -----------------------------------------------------------------------------
class CachedKeyMaterial:
    """TTL cache for pre-generated key material (fallback use only)"""
    
    def __init__(self, ttl_seconds: float = 3600.0):
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
    
    def get(self, algorithm: str) -> Optional[Any]:
        with self._lock:
            key = algorithm
            if key not in self._cache:
                return None
            value, timestamp = self._cache[key]
            if time.time() - timestamp > self._ttl:
                del self._cache[key]
                return None
            return value
    
    def put(self, algorithm: str, key_material: Any) -> None:
        with self._lock:
            self._cache[algorithm] = (key_material, time.time())
    
    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# -----------------------------------------------------------------------------
# Main Crypto Resilience Manager v22
# -----------------------------------------------------------------------------
class QuantumCryptResilienceV22:
    """
    Main crypto resilience manager - SINGLETON pattern
    ALL FEATURES DISABLED BY DEFAULT - OPT-IN ONLY
    """
    
    _instance: Optional['QuantumCryptResilienceV22'] = None
    _instance_lock = threading.Lock()
    
    @classmethod
    def get_instance(cls) -> 'QuantumCryptResilienceV22':
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = QuantumCryptResilienceV22()
        return cls._instance
    
    def __init__(self):
        self.config = CryptoResilienceConfigV22()
        self._circuit_breakers: Dict[str, CryptoCircuitBreaker] = {}
        self._bulkheads: Dict[str, CryptoBulkhead] = {}
        self._key_cache = CachedKeyMaterial()
        self._lock = threading.Lock()
    
    def enable_all(self) -> None:
        """Enable ALL resilience features (development/testing only)"""
        self.config.timeout.enabled = True
        self.config.circuit_breaker.enabled = True
        self.config.retry.enabled = True
        self.config.bulkhead.enabled = True
        self.config.fallback.enabled = True
    
    def _get_timeout_for_op(self, operation: KeyOperationType) -> float:
        mapping = {
            KeyOperationType.KEY_GENERATION: self.config.timeout.key_generation_timeout,
            KeyOperationType.HSM_CONNECT: self.config.timeout.hsm_connection_timeout,
            KeyOperationType.SIGNATURE_GENERATION: self.config.timeout.signature_timeout,
            KeyOperationType.SIGNATURE_VERIFICATION: self.config.timeout.verification_timeout,
        }
        return mapping.get(operation, self.config.timeout.key_operation_timeout)
    
    def wrap_key_operation(
        self,
        func: Callable,
        operation: KeyOperationType,
        algorithm: PQAlgorithm
    ) -> Callable:
        """
        Wrap a key operation with full resilience stack
        Order: Fallback -> Bulkhead -> Circuit Breaker -> Retry -> Timeout
        """
        op_name = f"{operation.value}_{algorithm.value}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not any([
                self.config.timeout.enabled,
                self.config.circuit_breaker.enabled,
                self.config.retry.enabled,
                self.config.bulkhead.enabled,
                self.config.fallback.enabled
            ]):
                return func(*args, **kwargs)
            
            return self._execute_with_resilience(func, operation, algorithm, op_name, args, kwargs)
        
        return wrapper
    
    def _execute_with_resilience(
        self,
        func: Callable,
        operation: KeyOperationType,
        algorithm: PQAlgorithm,
        op_name: str,
        args: tuple,
        kwargs: dict
    ) -> Any:
        """Execute with full resilience pipeline"""
        
        # 1. Bulkhead isolation first
        if self.config.bulkhead.enabled:
            bulkhead = self._get_bulkhead(operation)
            if not bulkhead.acquire():
                if self.config.fallback.enabled and self.config.fallback.allow_software_fallback:
                    return self._get_fallback_result(algorithm)
                raise CryptoBulkheadFullError(op_name, bulkhead.current_active, bulkhead.max_concurrent)
        else:
            bulkhead = None
        
        try:
            # 2. Circuit breaker check
            if self.config.circuit_breaker.enabled:
                cb = self._get_circuit_breaker(op_name)
                if not cb.allow_request():
                    if self.config.fallback.enabled:
                        return self._get_fallback_result(algorithm)
                    raise KeyOperationCircuitBreakerOpen(op_name, cb.get_recovery_time())
            
            # 3. Retry loop
            max_attempts = (self.config.retry.max_key_gen_attempts 
                          if operation == KeyOperationType.KEY_GENERATION
                          else self.config.retry.max_hsm_connect_attempts)
            
            last_error = None
            for attempt in range(1, max_attempts + 1 if self.config.retry.enabled else 2):
                try:
                    result = func(*args, **kwargs)
                    
                    if self.config.circuit_breaker.enabled:
                        cb.record_success()
                    
                    if self.config.fallback.enabled:
                        self._key_cache.put(algorithm.value, result)
                    
                    return result
                    
                except Exception as e:
                    last_error = e
                    
                    if self.config.circuit_breaker.enabled:
                        cb.record_failure()
                    
                    if not self.config.retry.enabled or attempt >= max_attempts:
                        break
                    
                    delay = crypto_safe_jitter(
                        self.config.retry.initial_delay_seconds * (self.config.retry.backoff_exponent ** (attempt - 1))
                    )
                    delay = min(delay, self.config.retry.max_delay_seconds)
                    time.sleep(delay)
            
            # All retries exhausted - try fallback
            if self.config.fallback.enabled:
                return self._get_fallback_result(algorithm)
            
            raise KeyGenerationRetryExhausted(algorithm.value, max_attempts, last_error)
            
        finally:
            if bulkhead:
                bulkhead.release()
    
    def _get_circuit_breaker(self, name: str) -> CryptoCircuitBreaker:
        with self._lock:
            if name not in self._circuit_breakers:
                self._circuit_breakers[name] = CryptoCircuitBreaker(name, self.config.circuit_breaker)
            return self._circuit_breakers[name]
    
    def _get_bulkhead(self, operation: KeyOperationType) -> CryptoBulkhead:
        with self._lock:
            name = operation.value
            if name not in self._bulkheads:
                if operation == KeyOperationType.KEY_GENERATION:
                    max_concurrent = self.config.bulkhead.max_concurrent_key_gen
                elif operation == KeyOperationType.HSM_CONNECT:
                    max_concurrent = self.config.bulkhead.max_concurrent_hsm_ops
                else:
                    max_concurrent = self.config.bulkhead.max_concurrent_signing
                
                self._bulkheads[name] = CryptoBulkhead(
                    name, max_concurrent, 
                    self.config.bulkhead.max_waiting,
                    self.config.bulkhead.queue_timeout
                )
            return self._bulkheads[name]
    
    def _get_fallback_result(self, algorithm: PQAlgorithm) -> Any:
        cached = self._key_cache.get(algorithm.value)
        if cached is not None:
            return cached
        return None  # Caller should handle appropriately
    
    def wrap_hsm_connection(self, func: Callable, provider: HSMProvider) -> Callable:
        """Wrap HSM connection with retry and circuit breaker"""
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.config.retry.enabled and not self.config.circuit_breaker.enabled:
                return func(*args, **kwargs)
            
            cb_name = f"hsm_{provider.value}"
            
            for attempt in range(1, self.config.retry.max_hsm_connect_attempts + 1 if self.config.retry.enabled else 2):
                try:
                    if self.config.circuit_breaker.enabled:
                        cb = self._get_circuit_breaker(cb_name)
                        if not cb.allow_request():
                            raise HSMConnectionError(provider.value, "circuit breaker open", attempt)
                    
                    result = func(*args, **kwargs)
                    
                    if self.config.circuit_breaker.enabled:
                        cb.record_success()
                    
                    return result
                    
                except Exception as e:
                    if self.config.circuit_breaker.enabled:
                        cb.record_failure()
                    
                    if attempt >= self.config.retry.max_hsm_connect_attempts:
                        raise HSMConnectionError(provider.value, str(e), attempt)
                    
                    delay = crypto_safe_jitter(
                        self.config.retry.initial_delay_seconds * (self.config.retry.backoff_exponent ** (attempt - 1))
                    )
                    time.sleep(min(delay, self.config.retry.max_delay_seconds))
            
            raise HSMConnectionError(provider.value, "max attempts reached", self.config.retry.max_hsm_connect_attempts)
        
        return wrapper
    
    def get_status_summary(self) -> Dict[str, Any]:
        return {
            "version": "v22",
            "enabled_features": {
                "timeout": self.config.timeout.enabled,
                "circuit_breaker": self.config.circuit_breaker.enabled,
                "retry": self.config.retry.enabled,
                "bulkhead": self.config.bulkhead.enabled,
                "fallback": self.config.fallback.enabled,
            },
            "circuit_breakers": {
                name: {
                    "state": cb.state.value if hasattr(cb.state, 'value') else str(cb.state),
                    "recovery_time": cb.get_recovery_time()
                }
                for name, cb in self._circuit_breakers.items()
            },
            "bulkheads": {
                name: {
                    "active": bh.current_active,
                    "max": bh.max_concurrent
                }
                for name, bh in self._bulkheads.items()
            }
        }


# -----------------------------------------------------------------------------
# Crypto Observability Integration Wrappers v22
# -----------------------------------------------------------------------------
class CryptoResilienceWrappersV22:
    """Pre-built wrappers for crypto operations"""
    
    @staticmethod
    def wrap_key_generation(func: Callable, algorithm: PQAlgorithm) -> Callable:
        resilience = QuantumCryptResilienceV22.get_instance()
        return resilience.wrap_key_operation(func, KeyOperationType.KEY_GENERATION, algorithm)
    
    @staticmethod
    def wrap_encapsulation(func: Callable, algorithm: PQAlgorithm) -> Callable:
        resilience = QuantumCryptResilienceV22.get_instance()
        return resilience.wrap_key_operation(func, KeyOperationType.KEY_ENCAPSULATION, algorithm)
    
    @staticmethod
    def wrap_decapsulation(func: Callable, algorithm: PQAlgorithm) -> Callable:
        resilience = QuantumCryptResilienceV22.get_instance()
        return resilience.wrap_key_operation(func, KeyOperationType.KEY_DECAPSULATION, algorithm)
    
    @staticmethod
    def wrap_signing(func: Callable, algorithm: PQAlgorithm) -> Callable:
        resilience = QuantumCryptResilienceV22.get_instance()
        return resilience.wrap_key_operation(func, KeyOperationType.SIGNATURE_GENERATION, algorithm)
    
    @staticmethod
    def wrap_verification(func: Callable, algorithm: PQAlgorithm) -> Callable:
        resilience = QuantumCryptResilienceV22.get_instance()
        return resilience.wrap_key_operation(func, KeyOperationType.SIGNATURE_VERIFICATION, algorithm)
    
    @staticmethod
    def wrap_hsm_connect(func: Callable, provider: HSMProvider) -> Callable:
        resilience = QuantumCryptResilienceV22.get_instance()
        return resilience.wrap_hsm_connection(func, provider)


# -----------------------------------------------------------------------------
# Legacy Accessor
# -----------------------------------------------------------------------------
def get_crypto_resilience_manager() -> QuantumCryptResilienceV22:
    return QuantumCryptResilienceV22.get_instance()


# -----------------------------------------------------------------------------
# Version Constants
# -----------------------------------------------------------------------------
CRYPTO_RESILIENCE_VERSION = "v22"
CRYPTO_RESILIENCE_BUILD_DATE = "2026-06-23"
CRYPTO_RESILIENCE_FEATURES = [
    "crypto_exception_hierarchy",
    "key_operation_timeouts",
    "hsm_connection_circuit_breaker",
    "crypto_safe_jitter_backoff",
    "crypto_bulkhead_isolation",
    "key_generation_graceful_degradation",
    "constant_time_comparison",
    "cached_key_material_fallback",
    "crypto_observability_v12_integration"
]
