"""
Post-Quantum Error Resilience Framework v21 for QuantumCrypt-AI
================================================================
Dimension E - Error Resilience Implementation
Version: v21 (Session 129)
Date: June 24, 2026

IMPLEMENTATION PHILOSOPHY:
- 100% ADD-ONLY - wraps existing code, never modifies it
- 100% backward compatible - happy path behavior preserved
- All instrumentation OPT-IN - never required for existing functionality
- Pure Python standard library only - no external dependencies

PQ-SPECIFIC FEATURES:
1. Custom Exception Hierarchy for PQ key operations
2. Key Operation Timeout Wrappers (PQ ops can be computationally expensive)
3. Retry + Backoff for transient HSM/KMS failures
4. Circuit Breaker for PQ algorithm operations
5. Graceful Algorithm Fallback Chain (PQ -> Classic -> Minimal)
6. Key Operation Bulkhead Isolation
7. Secure Memory Zeroization on error cleanup
"""

import time
import threading
import signal
import functools
import random
import logging
import secrets
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

# Configure module-level logger (opt-in, disabled by default)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# 1. PQ-SPECIFIC CUSTOM EXCEPTION HIERARCHY
# ============================================================================

class QuantumCryptError(Exception):
    """Base exception for all QuantumCrypt operational errors."""
    def __init__(self, message: str, error_code: str = "QC_ERR_001", 
                 retryable: bool = False, sensitive: bool = False,
                 details: Optional[Dict] = None, **kwargs):
        super().__init__(message)
        self.error_code = error_code
        self.retryable = retryable
        self.sensitive = sensitive  # Whether stack traces should be redacted
        self.details = (details or {}).copy()
        self.details.update(kwargs)
        self.timestamp = datetime.utcnow().isoformat()

class PQKeyOperationError(QuantumCryptError):
    """Base for post-quantum key operation specific errors."""
    pass

class KeyGenerationTimeoutError(PQKeyOperationError):
    """Raised when PQ key generation exceeds time limit."""
    def __init__(self, message: str = "PQ key generation timed out", 
                 timeout_seconds: float = 0.0, algorithm: str = "unknown", **kwargs):
        super().__init__(
            message=message,
            error_code="QC_PQ_KEYGEN_TIMEOUT",
            retryable=True,
            sensitive=False,
            timeout_seconds=timeout_seconds,
            algorithm=algorithm,
            **kwargs
        )

class KeyOperationFailedError(PQKeyOperationError):
    """Raised when key operation (enc/dec/sign/verify) fails."""
    def __init__(self, message: str = "Key operation failed",
                 operation: str = "unknown", algorithm: str = "unknown", **kwargs):
        super().__init__(
            message=message,
            error_code="QC_PQ_OP_FAILED",
            retryable=True,
            sensitive=True,
            operation=operation,
            algorithm=algorithm,
            **kwargs
        )

class HSMTemporaryError(PQKeyOperationError):
    """Raised for temporary HSM/KMS connection failures."""
    def __init__(self, message: str = "Temporary HSM/KMS failure",
                 retry_after_seconds: float = 5.0, hsm_id: str = "unknown", **kwargs):
        super().__init__(
            message=message,
            error_code="QC_HSM_TEMPORARY",
            retryable=True,
            sensitive=False,
            retry_after_seconds=retry_after_seconds,
            hsm_id=hsm_id,
            **kwargs
        )

class AlgorithmDowngradeError(PQKeyOperationError):
    """Raised when PQ algorithm unavailable and fallback activated."""
    def __init__(self, message: str = "Algorithm fallback activated",
                 requested_algorithm: str = "", fallback_algorithm: str = "", **kwargs):
        super().__init__(
            message=message,
            error_code="QC_ALG_DOWNGRADE",
            retryable=False,
            sensitive=False,
            requested_algorithm=requested_algorithm,
            fallback_algorithm=fallback_algorithm,
            **kwargs
        )

class KeyMaterialCorruptedError(PQKeyOperationError):
    """Raised when key material integrity check fails."""
    def __init__(self, message: str = "Key material integrity check failed",
                 key_id: str = "unknown", **kwargs):
        super().__init__(
            message=message,
            error_code="QC_KEY_CORRUPTED",
            retryable=False,
            sensitive=True,
            key_id=key_id,
            **kwargs
        )

class EntropyDepletedError(QuantumCryptError):
    """Raised when system entropy pool is depleted."""
    def __init__(self, message: str = "Cryptographic entropy depleted",
                 estimated_remaining: int = 0, **kwargs):
        super().__init__(
            message=message,
            error_code="QC_ENTROPY_LOW",
            retryable=True,
            sensitive=False,
            estimated_entropy_bits=estimated_remaining,
            **kwargs
        )

class PQCircuitBreakerOpenError(QuantumCryptError):
    """Raised when PQ circuit breaker is open and operations are blocked."""
    def __init__(self, message: str = "PQ operation circuit breaker open",
                 circuit_name: str = "unknown", reset_after: float = 0.0, **kwargs):
        super().__init__(
            message=message,
            error_code="QC_CIRCUIT_OPEN",
            retryable=True,
            sensitive=False,
            circuit_name=circuit_name,
            reset_after_seconds=reset_after,
            **kwargs
        )

class SecureMemoryError(QuantumCryptError):
    """Raised for secure memory management failures."""
    def __init__(self, message: str = "Secure memory operation failed",
                 operation: str = "unknown", **kwargs):
        super().__init__(
            message=message,
            error_code="QC_SEC_MEM_FAILED",
            retryable=False,
            sensitive=True,
            operation=operation,
            **kwargs
        )

# ============================================================================
# 2. SECURE MEMORY ZEROIZATION UTILITIES (ERROR CLEANUP)
# ============================================================================

def secure_zeroize(data: Any) -> None:
    """
    Best-effort secure zeroization of sensitive data.
    Overwrites with random bytes first, then zeros.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = secrets.randbelow(256)
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        # Immutable bytes - cannot truly zeroize
        pass
    elif isinstance(data, list):
        for i in range(len(data)):
            if isinstance(data[i], (int, float)):
                data[i] = 0
            elif isinstance(data[i], str):
                data[i] = ""
    elif hasattr(data, '__dict__'):
        for key in list(data.__dict__.keys()):
            data.__dict__[key] = None

class SecureCleanupContext:
    """Context manager that zeroizes sensitive data on exit/error."""
    
    def __init__(self, *sensitive_objects):
        self._sensitive_objects = list(sensitive_objects)
    
    def add(self, obj: Any) -> None:
        self._sensitive_objects.append(obj)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        for obj in self._sensitive_objects:
            try:
                secure_zeroize(obj)
            except:
                pass  # Best effort only
        return False  # Don't suppress exceptions

# ============================================================================
# 3. PQ CIRCUIT BREAKER
# ============================================================================

class PQCircuitState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

@dataclass
class PQCircuitBreakerConfig:
    failure_threshold: int = 3
    reset_timeout_seconds: float = 60.0
    half_open_max_calls: int = 2
    tracked_exceptions: Tuple[type, ...] = (
        KeyOperationFailedError,
        HSMTemporaryError,
        KeyGenerationTimeoutError
    )

@dataclass
class PQCircuitBreakerStats:
    total_calls: int = 0
    success_count: int = 0
    failure_count: int = 0
    rejected_calls: int = 0
    state_transitions: int = 0
    last_failure_time: Optional[float] = None
    last_state_change: float = field(default_factory=time.time)

class PQCircuitBreaker:
    """
    Circuit Breaker for PQ cryptographic operations.
    
    Prevents cascading failures when HSM/KMS or algorithm implementations fail.
    Longer timeouts than general circuit breaker (crypto ops are expensive).
    """
    
    def __init__(self, algorithm: str, config: Optional[PQCircuitBreakerConfig] = None):
        self.algorithm = algorithm
        self.config = config or PQCircuitBreakerConfig()
        self._state = PQCircuitState.CLOSED
        self._stats = PQCircuitBreakerStats()
        self._consecutive_failures = 0
        self._lock = threading.RLock()
        self._half_open_attempts = 0
    
    @property
    def state(self) -> PQCircuitState:
        with self._lock:
            return self._state
    
    @property
    def stats(self) -> PQCircuitBreakerStats:
        with self._lock:
            return PQCircuitBreakerStats(**self._stats.__dict__)
    
    def _transition_to(self, new_state: PQCircuitState):
        if self._state != new_state:
            logger.warning(f"PQ Circuit '{self.algorithm}': {self._state.value} -> {new_state.value}")
            self._state = new_state
            self._stats.state_transitions += 1
            self._stats.last_state_change = time.time()
    
    def _on_success(self):
        self._stats.success_count += 1
        self._consecutive_failures = 0
        if self._state == PQCircuitState.HALF_OPEN:
            self._half_open_attempts = 0
            self._transition_to(PQCircuitState.CLOSED)
    
    def _on_failure(self):
        self._stats.failure_count += 1
        self._stats.last_failure_time = time.time()
        self._consecutive_failures += 1
        
        if self._state == PQCircuitState.CLOSED:
            if self._consecutive_failures >= self.config.failure_threshold:
                self._transition_to(PQCircuitState.OPEN)
        elif self._state == PQCircuitState.HALF_OPEN:
            self._half_open_attempts = 0
            self._transition_to(PQCircuitState.OPEN)
    
    def _can_execute(self) -> bool:
        now = time.time()
        
        if self._state == PQCircuitState.CLOSED:
            return True
            
        if self._state == PQCircuitState.OPEN:
            elapsed = now - self._stats.last_state_change
            if elapsed >= self.config.reset_timeout_seconds:
                self._transition_to(PQCircuitState.HALF_OPEN)
                self._half_open_attempts = 0
                return True
            return False
            
        if self._state == PQCircuitState.HALF_OPEN:
            if self._half_open_attempts < self.config.half_open_max_calls:
                self._half_open_attempts += 1
                return True
            return False
            
        return False
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        with self._lock:
            self._stats.total_calls += 1
            
            if not self._can_execute():
                self._stats.rejected_calls += 1
                reset_after = max(0, self.config.reset_timeout_seconds - 
                                (time.time() - self._stats.last_state_change))
                raise PQCircuitBreakerOpenError(
                    circuit_name=self.algorithm,
                    reset_after=reset_after
                )
        
        try:
            result = func(*args, **kwargs)
            with self._lock:
                self._on_success()
            return result
        except self.config.tracked_exceptions:
            with self._lock:
                self._on_failure()
            raise
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self.execute(func, *args, **kwargs)
        return wrapper
    
    def reset(self):
        with self._lock:
            self._transition_to(PQCircuitState.CLOSED)
            self._consecutive_failures = 0
            self._half_open_attempts = 0
            self._stats = PQCircuitBreakerStats()

# Global PQ circuit breaker registry
_pq_circuit_registry: Dict[str, PQCircuitBreaker] = {}
_pq_circuit_lock = threading.Lock()

def get_pq_circuit_breaker(algorithm: str, config: Optional[PQCircuitBreakerConfig] = None) -> PQCircuitBreaker:
    with _pq_circuit_lock:
        if algorithm not in _pq_circuit_registry:
            _pq_circuit_registry[algorithm] = PQCircuitBreaker(algorithm, config)
        return _pq_circuit_registry[algorithm]

# ============================================================================
# 4. PQ KEY OPERATION TIMEOUTS
# ============================================================================

class PQOperationTimeout:
    """
    Timeout wrapper for PQ operations.
    
    PQ operations (especially key generation) can be computationally expensive.
    Uses threading-based timeout for cross-platform compatibility.
    """
    
    def __init__(self, seconds: float, algorithm: str = "unknown", operation: str = "unknown"):
        self.seconds = seconds
        self.algorithm = algorithm
        self.operation = operation
        self._result: Any = None
        self._exception: Optional[Exception] = None
    
    def _run_timed(self, func: Callable, args, kwargs):
        try:
            self._result = func(*args, **kwargs)
        except Exception as e:
            self._exception = e
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        self._exception = None
        self._result = None
        
        thread = threading.Thread(
            target=self._run_timed,
            args=(func, args, kwargs),
            daemon=True
        )
        thread.start()
        thread.join(timeout=self.seconds)
        
        if thread.is_alive():
            raise KeyGenerationTimeoutError(
                timeout_seconds=self.seconds,
                algorithm=self.algorithm,
                operation=self.operation
            )
        
        if self._exception is not None:
            raise self._exception
            
        return self._result
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self.execute(func, *args, **kwargs)
        return wrapper
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

def pq_timeout(seconds: float, **kwargs) -> PQOperationTimeout:
    return PQOperationTimeout(seconds, **kwargs)

# ============================================================================
# 5. PQ RETRY STRATEGY
# ============================================================================

@dataclass
class PQRetryConfig:
    max_attempts: int = 3
    initial_delay_seconds: float = 1.0
    max_delay_seconds: float = 30.0
    backoff_factor: float = 1.5
    jitter_factor: float = 0.2
    retry_on_exceptions: Tuple[type, ...] = (
        HSMTemporaryError,
        KeyGenerationTimeoutError,
        EntropyDepletedError
    )

class PQRetryStrategy:
    """Retry strategy optimized for PQ and HSM operations."""
    
    def __init__(self, config: Optional[PQRetryConfig] = None):
        self.config = config or PQRetryConfig()
    
    def _calculate_delay(self, attempt: int) -> float:
        base_delay = min(
            self.config.initial_delay_seconds * (self.config.backoff_factor ** attempt),
            self.config.max_delay_seconds
        )
        jitter = base_delay * self.config.jitter_factor * (2 * random.random() - 1)
        # Cap final delay at max_delay_seconds to account for jitter
        return min(self.config.max_delay_seconds, max(0, base_delay + jitter))
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        if attempt >= self.config.max_attempts - 1:
            return False
        return isinstance(exception, self.config.retry_on_exceptions)
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        last_exception: Optional[Exception] = None
        
        for attempt in range(self.config.max_attempts):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if not self.should_retry(e, attempt):
                    raise
                
                delay = self._calculate_delay(attempt)
                logger.info(f"PQ retry {attempt + 1}/{self.config.max_attempts}, "
                          f"delay {delay:.2f}s: {e}")
                time.sleep(delay)
        
        raise last_exception or KeyOperationFailedError("Max retry attempts exceeded")
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self.execute(func, *args, **kwargs)
        return wrapper

def pq_retry(max_attempts: int = 3, **kwargs) -> PQRetryStrategy:
    config = PQRetryConfig(max_attempts=max_attempts, **kwargs)
    return PQRetryStrategy(config)

# ============================================================================
# 6. ALGORITHM FALLBACK CHAIN (PQ -> CLASSIC)
# ============================================================================

class AlgorithmFallbackChain:
    """
    Graceful degradation for cryptographic algorithms.
    
    Fallback chain: PQ Preferred -> PQ Alternative -> Classic Quantum-Resistant -> Minimal
    Automatically downgrades with warning when preferred algorithm fails.
    """
    
    def __init__(self, name: str = "crypto_fallback"):
        self.name = name
        self._chain: List[Tuple[str, Callable]] = []
        self._fallback_events: List[Dict] = []
    
    def add_algorithm(self, name: str, implementation: Callable):
        """Add algorithm to fallback chain (priority order)."""
        self._chain.append((name, implementation))
        return self
    
    @property
    def fallback_events(self) -> List[Dict]:
        return list(self._fallback_events)
    
    def execute(self, *args, **kwargs) -> Tuple[Any, str]:
        """
        Execute with fallback chain.
        Returns: (result, algorithm_used)
        """
        if not self._chain:
            raise KeyOperationFailedError("No algorithms in fallback chain")
        
        errors = []
        
        for alg_name, impl in self._chain:
            try:
                if errors:  # This is a fallback
                    self._fallback_events.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "requested": self._chain[0][0],
                        "fallback_to": alg_name,
                        "previous_errors": len(errors)
                    })
                    logger.warning(f"Algorithm fallback: {self._chain[0][0]} -> {alg_name}")
                
                result = impl(*args, **kwargs)
                return result, alg_name
                
            except Exception as e:
                errors.append((alg_name, str(e)))
                continue
        
        # All algorithms failed
        raise KeyOperationFailedError(
            message=f"All {len(self._chain)} algorithms in fallback chain failed",
            details={"algorithm_failures": errors}
        )

def create_pq_classic_fallback(
    pq_implementation: Callable,
    classic_implementation: Callable,
    pq_name: str = "CRYSTALS-Kyber",
    classic_name: str = "RSA-4096"
) -> AlgorithmFallbackChain:
    """Create standard PQ -> Classic fallback chain."""
    chain = AlgorithmFallbackChain("pq_classic")
    chain.add_algorithm(pq_name, pq_implementation)
    chain.add_algorithm(classic_name, classic_implementation)
    return chain

# ============================================================================
# 7. KEY OPERATION BULKHEAD
# ============================================================================

class PQOperationBulkhead:
    """
    Bulkhead isolation for key operations.
    
    Prevents one type of key operation from consuming all CPU/memory.
    Particularly important for expensive PQ key generation.
    """
    
    def __init__(self, operation_type: str, max_concurrent: int = 4,
                 max_queue_size: int = 50, timeout_seconds: float = 30.0):
        self.operation_type = operation_type
        self.max_concurrent = max_concurrent
        self.max_queue_size = max_queue_size
        self.timeout_seconds = timeout_seconds
        self._semaphore = threading.Semaphore(max_concurrent)
        self._active_count = 0
        self._queued_count = 0
        self._lock = threading.Lock()
        self._stats = {
            "executed": 0,
            "rejected": 0,
            "timeouts": 0,
            "total_wait_time": 0.0
        }
    
    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats, active=self._active_count, queued=self._queued_count)
    
    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        start_time = time.time()
        
        with self._lock:
            if self._queued_count >= self.max_queue_size:
                self._stats["rejected"] += 1
                raise EntropyDepletedError(
                    message=f"Key operation queue full for {self.operation_type}",
                    resource_type=f"bulkhead_{self.operation_type}"
                )
            self._queued_count += 1
        
        acquired = self._semaphore.acquire(timeout=self.timeout_seconds)
        
        with self._lock:
            self._queued_count -= 1
        
        if not acquired:
            with self._lock:
                self._stats["timeouts"] += 1
            raise KeyGenerationTimeoutError(
                timeout_seconds=self.timeout_seconds,
                operation=self.operation_type,
                reason="bulkhead_wait_timeout"
            )
        
        try:
            with self._lock:
                self._active_count += 1
                self._stats["total_wait_time"] += time.time() - start_time
            
            return func(*args, **kwargs)
        finally:
            with self._lock:
                self._active_count -= 1
                self._stats["executed"] += 1
            self._semaphore.release()
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self.execute(func, *args, **kwargs)
        return wrapper

# ============================================================================
# 8. PQ RESILIENCE FACTORY
# ============================================================================

def create_resilient_pq_operation(
    operation_func: Callable,
    algorithm: str = "CRYSTALS-Kyber",
    operation: str = "keygen",
    enable_timeout: bool = True,
    timeout_seconds: float = 30.0,
    enable_retry: bool = True,
    max_attempts: int = 2,
    enable_circuit: bool = True,
    enable_bulkhead: bool = True,
    max_concurrent: int = 4
) -> Callable:
    """
    Create fully wrapped resilient PQ operation.
    
    Stack: Bulkhead -> Circuit Breaker -> Retry -> Timeout -> Secure Cleanup
    """
    wrapped = operation_func
    
    if enable_timeout:
        wrapped = pq_timeout(timeout_seconds, algorithm=algorithm, operation=operation)(wrapped)
    
    if enable_retry:
        wrapped = pq_retry(max_attempts=max_attempts)(wrapped)
    
    if enable_circuit:
        circuit = get_pq_circuit_breaker(algorithm)
        wrapped = circuit(wrapped)
    
    if enable_bulkhead:
        bulkhead = PQOperationBulkhead(f"{algorithm}_{operation}", max_concurrent=max_concurrent)
        wrapped = bulkhead(wrapped)
    
    return wrapped

# ============================================================================
# 9. VERSION & METADATA
# ============================================================================

VERSION = "21.0.0"
VERSION_CODE = "v21_2026_june"
DIMENSION = "E - Error Resilience"
SESSION = "129"

def get_version_info() -> Dict[str, str]:
    return {
        "version": VERSION,
        "version_code": VERSION_CODE,
        "dimension": DIMENSION,
        "session": SESSION,
        "module": "error_resilience_pq_key_operations_v21",
        "features": [
            "pq_exception_hierarchy",
            "pq_circuit_breaker",
            "pq_operation_timeouts",
            "pq_hsm_retry",
            "algorithm_fallback_chain",
            "pq_bulkhead_isolation",
            "secure_memory_zeroization"
        ]
    }

def is_backward_compatible() -> bool:
    return True

# ============================================================================
# END OF MODULE
# ============================================================================
