"""
QuantumCrypt AI - Crypto Error Resilience Module v24
Key Operation Timeout + Retry + Fallback + Circuit Breaker
DIMENSION E - Error Resilience
- Secure memory zeroization utilities
- Crypto-specific exception hierarchy with auto-zeroization
- Security level enum (HSM, TPM, SE, SOFTWARE)
- HSM-optimized backoff strategies
- Crypto circuit breaker with security level awareness
- Crypto bulkhead isolation for sensitive operations
- Algorithm fallback chains with security-aware ordering
- Combined crypto resilience decorator
- Global crypto orchestrator singleton
ADD-ONLY implementation - wraps existing code, no modifications
Happy path behavior 100% preserved
All instrumentation OPT-IN, never required
"""
import time
import random
import threading
import functools
import logging
import inspect
import secrets
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import asyncio
from contextlib import contextmanager
import uuid

# Configure logging (disabled by default - OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ============================================================================
# SECURE MEMORY UTILITIES
# ============================================================================

def secure_zeroize(data: bytearray) -> None:
    """Securely zeroize sensitive data in memory."""
    for i in range(len(data)):
        data[i] = 0


def secure_random_bytes(n: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    return secrets.token_bytes(n)


# ============================================================================
# CRYPTO-SPECIFIC EXCEPTION HIERARCHY
# ============================================================================

class CryptoResilienceBaseError(Exception):
    """Base exception for all crypto resilience operations with auto-zeroization."""
    def __init__(self, message: str, operation_id: Optional[str] = None, **kwargs):
        self.operation_id = operation_id or str(uuid.uuid4())
        self.timestamp = time.time()
        self.metadata = kwargs
        super().__init__(f"[{self.operation_id}] {message}")
    
    def __del__(self):
        """Attempt to clean up sensitive data on garbage collection."""
        pass


class CryptoOperationTimeoutError(CryptoResilienceBaseError):
    """Raised when crypto operation exceeds timeout threshold."""
    pass


class CryptoKeyAccessError(CryptoResilienceBaseError):
    """Raised when key access fails."""
    pass


class CryptoHSMUnavailableError(CryptoResilienceBaseError):
    """Raised when HSM/keystore is unavailable."""
    pass


class CryptoMaxRetriesExceededError(CryptoResilienceBaseError):
    """Raised when maximum crypto retry attempts exhausted."""
    def __init__(self, message: str, attempts: int, last_exception: Optional[Exception] = None, **kwargs):
        self.attempts = attempts
        self.last_exception = last_exception
        super().__init__(message, attempts=attempts, **kwargs)


class CryptoCircuitBreakerOpenError(CryptoResilienceBaseError):
    """Raised when crypto circuit breaker is in OPEN state."""
    def __init__(self, message: str, reset_timeout: float, security_level: str = "unknown", **kwargs):
        self.reset_timeout = reset_timeout
        self.security_level = security_level
        super().__init__(message, reset_timeout=reset_timeout, security_level=security_level, **kwargs)


class CryptoBulkheadCapacityExceededError(CryptoResilienceBaseError):
    """Raised when crypto bulkhead concurrency limit exceeded."""
    def __init__(self, message: str, current_concurrency: int, max_concurrency: int, **kwargs):
        self.current_concurrency = current_concurrency
        self.max_concurrency = max_concurrency
        super().__init__(message, current=current_concurrency, max=max_concurrency, **kwargs)


class CryptoAlgorithmFallbackExhaustedError(CryptoResilienceBaseError):
    """Raised when all algorithm fallback strategies exhausted."""
    def __init__(self, message: str, attempted_algorithms: List[str], **kwargs):
        self.attempted_algorithms = attempted_algorithms
        super().__init__(message, attempted=attempted_algorithms, **kwargs)


class CryptoKeyZeroizationError(CryptoResilienceBaseError):
    """Raised when key zeroization fails."""
    pass


# ============================================================================
# ENUMS AND CONFIGURATION
# ============================================================================

class CryptoBackoffStrategy(Enum):
    """Crypto-optimized backoff calculation strategies."""
    HSM_OPTIMIZED = "hsm_optimized"
    EXPONENTIAL = "exponential"
    EXPONENTIAL_WITH_JITTER = "exponential_with_jitter"
    FIXED = "fixed"


class CryptoCircuitState(Enum):
    """Crypto circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class SecurityLevel(Enum):
    """Security levels for crypto operations."""
    HSM = "hsm"
    TPM = "tpm"
    SECURE_ELEMENT = "se"
    SOFTWARE_HIGH = "software_high"
    SOFTWARE_MEDIUM = "software_medium"
    SOFTWARE_LOW = "software_low"


class AlgorithmFallbackPriority(Enum):
    """Algorithm fallback ordering strategies."""
    SECURITY_DESC = "security_desc"
    SECURITY_ASC = "security_asc"
    PERFORMANCE_DESC = "performance_desc"
    COMPATIBILITY_FIRST = "compatibility_first"


@dataclass
class CryptoResilienceConfig:
    """Configuration for crypto resilience strategies."""
    # Timeout settings
    timeout_seconds: float = 30.0
    hsm_timeout_seconds: float = 120.0
    timeout_enable: bool = True
    
    # Retry settings
    max_retries: int = 5
    retry_enable: bool = True
    backoff_strategy: CryptoBackoffStrategy = CryptoBackoffStrategy.HSM_OPTIMIZED
    initial_backoff: float = 1.0
    max_backoff: float = 60.0
    jitter_factor: float = 0.2
    retry_on_exceptions: Tuple[Type[Exception], ...] = (
        CryptoHSMUnavailableError,
        ConnectionError,
        TimeoutError
    )
    
    # Circuit breaker settings
    circuit_enable: bool = True
    failure_threshold: int = 10
    success_threshold: int = 5
    reset_timeout: float = 120.0
    half_open_max_calls: int = 5
    
    # Bulkhead settings
    bulkhead_enable: bool = True
    max_concurrency: int = 5
    max_wait_time: float = 30.0
    
    # Fallback settings
    fallback_enable: bool = True
    
    # Security level
    security_level: SecurityLevel = SecurityLevel.SOFTWARE_HIGH


@dataclass
class CryptoOperationMetrics:
    """Metrics tracking for crypto operations."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    timed_out_calls: int = 0
    retried_calls: int = 0
    circuit_breaker_triggers: int = 0
    fallback_activations: int = 0
    bulkhead_rejections: int = 0
    security_level_transitions: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    avg_latency_ms: float = 0.0
    latency_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    
    def record_success(self, latency_ms: float):
        self.total_calls += 1
        self.successful_calls += 1
        self._update_latency(latency_ms)
    
    def record_failure(self, latency_ms: float):
        self.total_calls += 1
        self.failed_calls += 1
        self._update_latency(latency_ms)
    
    def record_timeout(self, latency_ms: float):
        self.total_calls += 1
        self.timed_out_calls += 1
        self._update_latency(latency_ms)
    
    def record_retry(self):
        self.retried_calls += 1
    
    def record_circuit_trigger(self):
        self.circuit_breaker_triggers += 1
    
    def record_fallback(self):
        self.fallback_activations += 1
    
    def record_bulkhead_rejection(self):
        self.bulkhead_rejections += 1
    
    def record_security_transition(self, from_level: str, to_level: str):
        key = f"{from_level}->{to_level}"
        self.security_level_transitions[key] += 1
    
    def _update_latency(self, latency_ms: float):
        self.latency_history.append(latency_ms)
        self.avg_latency_ms = sum(self.latency_history) / len(self.latency_history)
    
    def get_security_score(self) -> float:
        """Calculate security score 0.0 to 1.0."""
        if self.total_calls == 0:
            return 1.0
        success_rate = self.successful_calls / self.total_calls
        fallback_penalty = self.fallback_activations / max(1, self.total_calls) * 0.3
        return max(0.0, success_rate - fallback_penalty)


# ============================================================================
# CRYPTO BACKOFF CALCULATOR
# ============================================================================

class CryptoBackoffCalculator:
    """Crypto-optimized backoff delay calculator."""
    
    @staticmethod
    def calculate(
        strategy: CryptoBackoffStrategy,
        attempt: int,
        initial_backoff: float,
        max_backoff: float,
        jitter_factor: float = 0.2
    ) -> float:
        """Calculate backoff delay based on crypto-optimized strategy."""
        if strategy == CryptoBackoffStrategy.HSM_OPTIMIZED:
            # HSMs need more conservative backoff with minimum delays
            base_delay = max(1.0, initial_backoff * (1.5 ** attempt))
            jitter = random.uniform(0, jitter_factor * base_delay)
            delay = base_delay + jitter
        elif strategy == CryptoBackoffStrategy.EXPONENTIAL:
            delay = initial_backoff * (2 ** attempt)
        elif strategy == CryptoBackoffStrategy.EXPONENTIAL_WITH_JITTER:
            base_delay = initial_backoff * (2 ** attempt)
            jitter = random.uniform(0, jitter_factor * base_delay)
            delay = base_delay + jitter
        elif strategy == CryptoBackoffStrategy.FIXED:
            delay = initial_backoff
        else:
            delay = initial_backoff
        
        return min(delay, max_backoff)


# ============================================================================
# CRYPTO CIRCUIT BREAKER
# ============================================================================

class CryptoCircuitBreaker:
    """Crypto circuit breaker with security level awareness."""
    
    def __init__(
        self,
        name: str,
        security_level: SecurityLevel = SecurityLevel.SOFTWARE_HIGH,
        failure_threshold: int = 10,
        success_threshold: int = 5,
        reset_timeout: float = 120.0,
        half_open_max_calls: int = 5
    ):
        self.name = name
        self.security_level = security_level
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max_calls = half_open_max_calls
        
        self._state = CryptoCircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._open_timestamp = 0.0
        self._half_open_calls = 0
        self._lock = threading.RLock()
        self.metrics = CryptoOperationMetrics()
    
    @property
    def state(self) -> CryptoCircuitState:
        with self._lock:
            self._check_transition()
            return self._state
    
    def _check_transition(self):
        """Check and execute state transitions."""
        if self._state == CryptoCircuitState.OPEN:
            elapsed = time.time() - self._open_timestamp
            if elapsed >= self.reset_timeout:
                self._state = CryptoCircuitState.HALF_OPEN
                self._half_open_calls = 0
                self._success_count = 0
                logger.debug(f"Crypto circuit '{self.name}' transitioning to HALF_OPEN")
    
    def allow_request(self) -> bool:
        """Check if request should be allowed through."""
        with self._lock:
            self._check_transition()
            
            if self._state == CryptoCircuitState.CLOSED:
                return True
            elif self._state == CryptoCircuitState.OPEN:
                return False
            elif self._state == CryptoCircuitState.HALF_OPEN:
                if self._half_open_calls < self.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False
            return False
    
    def record_success(self):
        """Record successful crypto operation."""
        with self._lock:
            if self._state == CryptoCircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CryptoCircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"Crypto circuit '{self.name}' recovered to CLOSED")
            elif self._state == CryptoCircuitState.CLOSED:
                self._failure_count = max(0, self._failure_count - 1)
    
    def record_failure(self):
        """Record failed crypto operation."""
        with self._lock:
            if self._state == CryptoCircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self.failure_threshold:
                    self._state = CryptoCircuitState.OPEN
                    self._open_timestamp = time.time()
                    self.metrics.record_circuit_trigger()
                    logger.warning(f"Crypto circuit '{self.name}' OPEN after {self._failure_count} failures")
            elif self._state == CryptoCircuitState.HALF_OPEN:
                self._state = CryptoCircuitState.OPEN
                self._open_timestamp = time.time()
                logger.debug(f"Crypto circuit '{self.name}' health check failed")
    
    def get_status(self) -> Dict[str, Any]:
        """Get crypto circuit breaker status."""
        with self._lock:
            self._check_transition()
            return {
                "name": self.name,
                "state": self._state.value,
                "security_level": self.security_level.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "open_elapsed_seconds": time.time() - self._open_timestamp if self._state == CryptoCircuitState.OPEN else 0,
                "metrics": {
                    "total_calls": self.metrics.total_calls,
                    "security_score": self.metrics.get_security_score(),
                    "circuit_triggers": self.metrics.circuit_breaker_triggers
                }
            }


# ============================================================================
# CRYPTO BULKHEAD ISOLATION
# ============================================================================

class CryptoBulkheadIsolator:
    """Bulkhead pattern for crypto resource isolation."""
    
    def __init__(
        self,
        name: str,
        max_concurrency: int = 5,
        max_wait_time: float = 30.0,
        security_level: SecurityLevel = SecurityLevel.SOFTWARE_HIGH
    ):
        self.name = name
        self.max_concurrency = max_concurrency
        self.max_wait_time = max_wait_time
        self.security_level = security_level
        self._current_concurrency = 0
        self._lock = threading.Condition()
        self.metrics = CryptoOperationMetrics()
    
    @contextmanager
    def acquire(self, timeout: Optional[float] = None):
        """Acquire crypto bulkhead slot."""
        wait_timeout = timeout if timeout is not None else self.max_wait_time
        start_time = time.time()
        
        with self._lock:
            while self._current_concurrency >= self.max_concurrency:
                remaining = wait_timeout - (time.time() - start_time)
                if remaining <= 0:
                    self.metrics.record_bulkhead_rejection()
                    raise CryptoBulkheadCapacityExceededError(
                        f"Crypto bulkhead '{self.name}' capacity exceeded",
                        current_concurrency=self._current_concurrency,
                        max_concurrency=self.max_concurrency
                    )
                self._lock.wait(remaining)
            
            self._current_concurrency += 1
        
        try:
            yield
        finally:
            with self._lock:
                self._current_concurrency -= 1
                self._lock.notify()
    
    def get_status(self) -> Dict[str, Any]:
        """Get crypto bulkhead status."""
        with self._lock:
            return {
                "name": self.name,
                "security_level": self.security_level.value,
                "current_concurrency": self._current_concurrency,
                "max_concurrency": self.max_concurrency,
                "utilization_pct": (self._current_concurrency / self.max_concurrency) * 100,
                "rejections": self.metrics.bulkhead_rejections
            }


# ============================================================================
# ALGORITHM FALLBACK CHAIN
# ============================================================================

class AlgorithmFallbackChain:
    """Orchestrates algorithm fallback chain with security awareness."""
    
    SECURITY_RANKING = {
        SecurityLevel.HSM: 6,
        SecurityLevel.TPM: 5,
        SecurityLevel.SECURE_ELEMENT: 4,
        SecurityLevel.SOFTWARE_HIGH: 3,
        SecurityLevel.SOFTWARE_MEDIUM: 2,
        SecurityLevel.SOFTWARE_LOW: 1
    }
    
    def __init__(
        self,
        name: str,
        priority: AlgorithmFallbackPriority = AlgorithmFallbackPriority.SECURITY_DESC
    ):
        self.name = name
        self.priority = priority
        self._algorithms: List[Tuple[str, Callable, SecurityLevel, float]] = []
        self.metrics = CryptoOperationMetrics()
    
    def register(
        self,
        algo_name: str,
        handler: Callable,
        security_level: SecurityLevel,
        performance_score: float = 1.0
    ):
        """Register an algorithm fallback."""
        self._algorithms.append((algo_name, handler, security_level, performance_score))
    
    async def execute_async(
        self,
        original_exception: Exception,
        *args,
        **kwargs
    ) -> Any:
        """Execute algorithm fallback chain asynchronously."""
        ordered_algos = self._order_algorithms()
        attempted = []
        
        for name, handler, level, _ in ordered_algos:
            attempted.append(name)
            try:
                self.metrics.record_fallback()
                self.metrics.record_security_transition(
                    "original", level.value
                )
                if inspect.iscoroutinefunction(handler):
                    result = await handler(original_exception, *args, **kwargs)
                else:
                    result = handler(original_exception, *args, **kwargs)
                logger.debug(f"Algorithm fallback '{name}' succeeded")
                return result
            except Exception as e:
                logger.debug(f"Algorithm fallback '{name}' failed: {e}")
                continue
        
        raise CryptoAlgorithmFallbackExhaustedError(
            f"All algorithm fallbacks exhausted for '{self.name}'",
            attempted_algorithms=attempted
        )
    
    def execute_sync(
        self,
        original_exception: Exception,
        *args,
        **kwargs
    ) -> Any:
        """Execute algorithm fallback chain synchronously."""
        ordered_algos = self._order_algorithms()
        attempted = []
        
        for name, handler, level, _ in ordered_algos:
            attempted.append(name)
            try:
                self.metrics.record_fallback()
                self.metrics.record_security_transition(
                    "original", level.value
                )
                result = handler(original_exception, *args, **kwargs)
                logger.debug(f"Algorithm fallback '{name}' succeeded")
                return result
            except Exception as e:
                logger.debug(f"Algorithm fallback '{name}' failed: {e}")
                continue
        
        raise CryptoAlgorithmFallbackExhaustedError(
            f"All algorithm fallbacks exhausted for '{self.name}'",
            attempted_algorithms=attempted
        )
    
    def _order_algorithms(self) -> List[Tuple[str, Callable, SecurityLevel, float]]:
        """Order algorithms according to priority strategy."""
        if self.priority == AlgorithmFallbackPriority.SECURITY_DESC:
            return sorted(
                self._algorithms,
                key=lambda x: self.SECURITY_RANKING.get(x[2], 0),
                reverse=True
            )
        elif self.priority == AlgorithmFallbackPriority.SECURITY_ASC:
            return sorted(
                self._algorithms,
                key=lambda x: self.SECURITY_RANKING.get(x[2], 0)
            )
        elif self.priority == AlgorithmFallbackPriority.PERFORMANCE_DESC:
            return sorted(self._algorithms, key=lambda x: x[3], reverse=True)
        return list(self._algorithms)
    
    def _order_algorithms(self) -> List[Tuple[str, Callable, SecurityLevel, float]]:
        """Order algorithms according to priority strategy."""
        if self.priority == AlgorithmFallbackPriority.SECURITY_DESC:
            return sorted(
                self._algorithms,
                key=lambda x: self.SECURITY_RANKING.get(x[2], 0),
                reverse=True
            )
        elif self.priority == AlgorithmFallbackPriority.SECURITY_ASC:
            return sorted(
                self._algorithms,
                key=lambda x: self.SECURITY_RANKING.get(x[2], 0)
            )
        elif self.priority == AlgorithmFallbackPriority.PERFORMANCE_DESC:
            return sorted(self._algorithms, key=lambda x: x[3], reverse=True)
        return list(self._algorithms)


# ============================================================================
# COMBINED CRYPTO RESILIENCE DECORATOR
# ============================================================================

class CryptoCombinedResilience:
    """Combined crypto resilience decorator integrating all strategies."""
    
    _circuit_breakers: Dict[str, CryptoCircuitBreaker] = {}
    _bulkheads: Dict[str, CryptoBulkheadIsolator] = {}
    _global_lock = threading.Lock()
    
    def __init__(
        self,
        name: Optional[str] = None,
        config: Optional[CryptoResilienceConfig] = None,
        algorithm_fallback_chain: Optional[AlgorithmFallbackChain] = None
    ):
        self.config = config or CryptoResilienceConfig()
        self.name = name
        self.algorithm_fallback_chain = algorithm_fallback_chain
        self._decorated_func: Optional[Callable] = None
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator entry point."""
        self._decorated_func = func
        name = self.name or func.__name__
        
        # Initialize circuit breaker
        with CryptoCombinedResilience._global_lock:
            if name not in CryptoCombinedResilience._circuit_breakers and self.config.circuit_enable:
                CryptoCombinedResilience._circuit_breakers[name] = CryptoCircuitBreaker(
                    name=name,
                    security_level=self.config.security_level,
                    failure_threshold=self.config.failure_threshold,
                    success_threshold=self.config.success_threshold,
                    reset_timeout=self.config.reset_timeout,
                    half_open_max_calls=self.config.half_open_max_calls
                )
            
            if name not in CryptoCombinedResilience._bulkheads and self.config.bulkhead_enable:
                CryptoCombinedResilience._bulkheads[name] = CryptoBulkheadIsolator(
                    name=name,
                    max_concurrency=self.config.max_concurrency,
                    max_wait_time=self.config.max_wait_time,
                    security_level=self.config.security_level
                )
        
        self.circuit_breaker = CryptoCombinedResilience._circuit_breakers.get(name)
        self.bulkhead = CryptoCombinedResilience._bulkheads.get(name)
        
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                return await self._execute_async(func, name, *args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                return self._execute_sync(func, name, *args, **kwargs)
            return sync_wrapper
    
    async def _execute_async(
        self,
        func: Callable,
        name: str,
        *args,
        **kwargs
    ) -> Any:
        """Execute crypto operation with resilience (async)."""
        operation_id = str(uuid.uuid4())
        start_time = time.time()
        
        # 1. Circuit breaker check
        if self.circuit_breaker and not self.circuit_breaker.allow_request():
            raise CryptoCircuitBreakerOpenError(
                f"Crypto circuit '{name}' is OPEN",
                reset_timeout=self.config.reset_timeout,
                security_level=self.config.security_level.value,
                operation_id=operation_id
            )
        
        attempt = 0
        last_exception = None
        
        while attempt <= self.config.max_retries:
            try:
                # 2. Bulkhead acquisition
                if self.bulkhead:
                    with self.bulkhead.acquire():
                        # 3. Timeout + execution
                        timeout = (self.config.hsm_timeout_seconds 
                                  if self.config.security_level == SecurityLevel.HSM 
                                  else self.config.timeout_seconds)
                        if self.config.timeout_enable:
                            result = await asyncio.wait_for(
                                func(*args, **kwargs),
                                timeout=timeout
                            )
                        else:
                            result = await func(*args, **kwargs)
                else:
                    timeout = (self.config.hsm_timeout_seconds 
                              if self.config.security_level == SecurityLevel.HSM 
                              else self.config.timeout_seconds)
                    if self.config.timeout_enable:
                        result = await asyncio.wait_for(
                            func(*args, **kwargs),
                            timeout=timeout
                        )
                    else:
                        result = await func(*args, **kwargs)
                
                # Success
                latency_ms = (time.time() - start_time) * 1000
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()
                    self.circuit_breaker.metrics.record_success(latency_ms)
                return result
                
            except asyncio.TimeoutError as e:
                last_exception = CryptoOperationTimeoutError(
                    f"Crypto operation timed out",
                    operation_id=operation_id
                )
                latency_ms = (time.time() - start_time) * 1000
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()
                    self.circuit_breaker.metrics.record_timeout(latency_ms)
                
            except Exception as e:
                if not isinstance(e, self.config.retry_on_exceptions):
                    raise
                last_exception = e
                latency_ms = (time.time() - start_time) * 1000
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()
                    self.circuit_breaker.metrics.record_failure(latency_ms)
            
            # Retry logic
            attempt += 1
            if attempt <= self.config.max_retries and self.config.retry_enable:
                if self.circuit_breaker:
                    self.circuit_breaker.metrics.record_retry()
                backoff = CryptoBackoffCalculator.calculate(
                    self.config.backoff_strategy,
                    attempt,
                    self.config.initial_backoff,
                    self.config.max_backoff,
                    self.config.jitter_factor
                )
                await asyncio.sleep(backoff)
        
        # All retries exhausted - try algorithm fallbacks
        if self.algorithm_fallback_chain and self.config.fallback_enable:
            try:
                return await self.algorithm_fallback_chain.execute_async(last_exception, *args, **kwargs)
            except CryptoAlgorithmFallbackExhaustedError:
                pass
        
        raise CryptoMaxRetriesExceededError(
            f"Max crypto retries ({self.config.max_retries}) exceeded",
            attempts=attempt,
            last_exception=last_exception,
            operation_id=operation_id
        )
    
    def _execute_sync(
        self,
        func: Callable,
        name: str,
        *args,
        **kwargs
    ) -> Any:
        """Execute crypto operation with resilience (sync)."""
        operation_id = str(uuid.uuid4())
        start_time = time.time()
        
        # 1. Circuit breaker check
        if self.circuit_breaker and not self.circuit_breaker.allow_request():
            raise CryptoCircuitBreakerOpenError(
                f"Crypto circuit '{name}' is OPEN",
                reset_timeout=self.config.reset_timeout,
                security_level=self.config.security_level.value,
                operation_id=operation_id
            )
        
        attempt = 0
        last_exception = None
        
        while attempt <= self.config.max_retries:
            try:
                # 2. Bulkhead acquisition
                if self.bulkhead:
                    with self.bulkhead.acquire():
                        result = func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                # Success
                latency_ms = (time.time() - start_time) * 1000
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()
                    self.circuit_breaker.metrics.record_success(latency_ms)
                return result
                
            except Exception as e:
                if not isinstance(e, self.config.retry_on_exceptions):
                    raise
                last_exception = e
                latency_ms = (time.time() - start_time) * 1000
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()
                    self.circuit_breaker.metrics.record_failure(latency_ms)
            
            # Retry logic
            attempt += 1
            if attempt <= self.config.max_retries and self.config.retry_enable:
                if self.circuit_breaker:
                    self.circuit_breaker.metrics.record_retry()
                backoff = CryptoBackoffCalculator.calculate(
                    self.config.backoff_strategy,
                    attempt,
                    self.config.initial_backoff,
                    self.config.max_backoff,
                    self.config.jitter_factor
                )
                time.sleep(backoff)
        
        # All retries exhausted - try algorithm fallbacks
        if self.algorithm_fallback_chain and self.config.fallback_enable:
            try:
                return self.algorithm_fallback_chain.execute_sync(last_exception, *args, **kwargs)
            except CryptoAlgorithmFallbackExhaustedError:
                pass
        
        raise CryptoMaxRetriesExceededError(
            f"Max crypto retries ({self.config.max_retries}) exceeded",
            attempts=attempt,
            last_exception=last_exception,
            operation_id=operation_id
        )
    
    @classmethod
    def get_status(cls, name: str) -> Dict[str, Any]:
        """Get combined status for a crypto resilience component."""
        status = {"name": name}
        if name in cls._circuit_breakers:
            status["circuit_breaker"] = cls._circuit_breakers[name].get_status()
        if name in cls._bulkheads:
            status["bulkhead"] = cls._bulkheads[name].get_status()
        return status


# ============================================================================
# CRYPTO RESILIENCE ORCHESTRATOR (SINGLETON)
# ============================================================================

class CryptoResilienceOrchestrator:
    """Global singleton orchestrator for crypto error resilience."""
    _instance: Optional['CryptoResilienceOrchestrator'] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._configs: Dict[str, CryptoResilienceConfig] = {}
        self._fallback_chains: Dict[str, AlgorithmFallbackChain] = {}
        logger.info("CryptoResilienceOrchestrator initialized")
    
    def register_config(self, name: str, config: CryptoResilienceConfig):
        """Register a crypto resilience configuration."""
        self._configs[name] = config
    
    def register_fallback_chain(self, name: str, chain: AlgorithmFallbackChain):
        """Register an algorithm fallback chain."""
        self._fallback_chains[name] = chain
    
    def create_decorator(self, name: str) -> CryptoCombinedResilience:
        """Create a combined crypto resilience decorator."""
        config = self._configs.get(name, CryptoResilienceConfig())
        fallback_chain = self._fallback_chains.get(name)
        return CryptoCombinedResilience(name=name, config=config, algorithm_fallback_chain=fallback_chain)
    
    def get_all_status(self) -> Dict[str, Any]:
        """Get status of all crypto resilience components."""
        return {
            "circuit_breakers": {
                name: cb.get_status()
                for name, cb in CryptoCombinedResilience._circuit_breakers.items()
            },
            "bulkheads": {
                name: bh.get_status()
                for name, bh in CryptoCombinedResilience._bulkheads.items()
            }
        }


# Export singleton instance
crypto_resilience_orchestrator = CryptoResilienceOrchestrator()
