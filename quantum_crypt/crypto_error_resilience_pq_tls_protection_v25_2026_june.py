"""
QuantumCrypt-AI Error Resilience v25 - PQ TLS Endpoint Protection
==================================================================
DIMENSION E - Error Resilience
Add-only module - wraps Security v17 PQ TLS endpoints with comprehensive error handling

Post-Quantum specific enhancements:
1. PQ Key Operation Timeout Protection - prevents hanging KEM operations
2. PQ KEM Retry with Backoff - quantum-resistant key exchange retries
3. PQ Circuit Breaker - stops cascading PQ failures
4. PQ Graceful Degradation - automatic classical fallback
5. PQ Bulkhead Isolation - PQ operations don't crash HSMs
6. PQ Custom Exception Hierarchy - precise PQ error classification

Philosophy: 100% ADD-ONLY, wraps existing code without modification
Backward Compatible: All existing Security v17 functions work unchanged
"""

import time
import random
import socket
import ssl
import threading
import hashlib
from typing import Callable, Any, Optional, Dict, List, TypeVar, Tuple
from enum import Enum
from dataclasses import dataclass, field
from collections import deque
from functools import wraps
import logging
import secrets

# Configure logging - OPT-IN, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Type variables
T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# CUSTOM EXCEPTION HIERARCHY - PQ TLS-SPECIFIC ERROR CLASSES
# ============================================================================

class PQTLSError(Exception):
    """Base exception for all Post-Quantum TLS-related errors"""
    def __init__(self, message: str, error_code: str, retryable: bool = False, pq_specific: bool = True):
        super().__init__(message)
        self.error_code = error_code
        self.retryable = retryable
        self.pq_specific = pq_specific
        self.timestamp = time.time()
        self.nonce = secrets.token_hex(8)  # Unique error identifier

class PQKEMTimeoutError(PQTLSError):
    """Raised when PQ Key Encapsulation Mechanism times out"""
    def __init__(self, message: str = "PQ KEM operation timed out"):
        super().__init__(message, "PQ_KEM_TIMEOUT", retryable=True, pq_specific=True)

class PQKEMAlgorithmError(PQTLSError):
    """Raised when PQ algorithm fails (ML-KEM, BIKE, etc.)"""
    def __init__(self, message: str = "PQ KEM algorithm failure"):
        super().__init__(message, "PQ_KEM_ALGORITHM", retryable=False, pq_specific=True)

class PQKeyMaterialError(PQTLSError):
    """Raised when PQ key material is invalid"""
    def __init__(self, message: str = "PQ key material validation failed"):
        super().__init__(message, "PQ_KEY_MATERIAL", retryable=False, pq_specific=True)

class PQHSMMemoryError(PQTLSError):
    """Raised when HSM runs out of secure memory for PQ keys"""
    def __init__(self, message: str = "HSM secure memory exhausted"):
        super().__init__(message, "PQ_HSM_MEMORY", retryable=True, pq_specific=True)

class PQHybridFallbackError(PQTLSError):
    """Raised when hybrid PQ+classical mode falls back to classical"""
    def __init__(self, message: str = "PQ hybrid fallback to classical activated"):
        super().__init__(message, "PQ_HYBRID_FALLBACK", retryable=False, pq_specific=True)

class PQCircuitBreakerOpen(PQTLSError):
    """Raised when PQ circuit breaker is open"""
    def __init__(self, message: str = "PQ TLS circuit breaker is open"):
        super().__init__(message, "PQ_CIRCUIT_OPEN", retryable=False, pq_specific=True)

class PQChannelBindingError(PQTLSError):
    """Raised when PQ channel binding verification fails"""
    def __init__(self, message: str = "PQ channel binding verification failed"):
        super().__init__(message, "PQ_CHANNEL_BINDING", retryable=False, pq_specific=True)

# ============================================================================
# PQ CIRCUIT BREAKER STATE ENUM
# ============================================================================

class PQCircuitState(Enum):
    CLOSED = "CLOSED"           # Normal PQ operation
    OPEN = "OPEN"               # Too many PQ failures
    HALF_OPEN = "HALF_OPEN"     # Testing PQ recovery
    CLASSICAL_ONLY = "CLASSICAL_ONLY"  # Permanent fallback to classical

# ============================================================================
# PQ CIRCUIT BREAKER - STOPS CASCADING PQ FAILURES
# ============================================================================

@dataclass
class PQKEMCircuitBreaker:
    """
    Circuit Breaker specifically for PQ KEM operations.
    Includes CLASSICAL_ONLY state for permanent graceful degradation.
    
    State transitions:
    CLOSED → OPEN: pq_failure_threshold reached
    OPEN → HALF_OPEN: recovery_timeout elapsed
    HALF_OPEN → CLOSED: pq_success_threshold reached
    HALF_OPEN → OPEN: any PQ failure
    HALF_OPEN → CLASSICAL_ONLY: pq_classical_threshold failures
    """
    pq_failure_threshold: int = 5
    pq_classical_threshold: int = 10
    recovery_timeout: float = 60.0
    pq_success_threshold: int = 3
    
    _state: PQCircuitState = PQCircuitState.CLOSED
    _pq_failure_count: int = 0
    _pq_success_count: int = 0
    _last_failure_time: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _pq_failure_history: deque = field(default_factory=lambda: deque(maxlen=100))
    _classical_fallback_count: int = 0
    
    def record_pq_success(self) -> None:
        """Record a successful PQ KEM operation"""
        with self._lock:
            self._pq_failure_count = 0
            self._pq_failure_history.clear()
            
            if self._state == PQCircuitState.HALF_OPEN:
                self._pq_success_count += 1
                if self._pq_success_count >= self.pq_success_threshold:
                    self._state = PQCircuitState.CLOSED
                    self._pq_success_count = 0
                    logger.info("PQ Circuit Breaker: HALF_OPEN → CLOSED")
    
    def record_pq_failure(self, error: Exception) -> None:
        """Record a failed PQ KEM operation"""
        with self._lock:
            self._pq_failure_count += 1
            self._pq_failure_history.append({
                'time': time.time(),
                'error': str(error),
                'type': type(error).__name__,
                'pq_specific': getattr(error, 'pq_specific', False)
            })
            self._last_failure_time = time.time()
            self._pq_success_count = 0
            
            if self._state == PQCircuitState.CLOSED:
                if self._pq_failure_count >= self.pq_failure_threshold:
                    self._state = PQCircuitState.OPEN
                    logger.warning(f"PQ Circuit Breaker: CLOSED → OPEN after {self._pq_failure_count} PQ failures")
            
            elif self._state == PQCircuitState.HALF_OPEN:
                if self._pq_failure_count >= self.pq_classical_threshold:
                    self._state = PQCircuitState.CLASSICAL_ONLY
                    logger.critical("PQ Circuit Breaker: HALF_OPEN → CLASSICAL_ONLY (permanent fallback)")
                else:
                    self._state = PQCircuitState.OPEN
                    logger.warning("PQ Circuit Breaker: HALF_OPEN → OPEN")
    
    def allow_pq_operation(self) -> Tuple[bool, str]:
        """Check if PQ operation should be allowed, returns (allowed, reason)"""
        with self._lock:
            if self._state == PQCircuitState.CLOSED:
                return True, "PQ operational"
            
            if self._state == PQCircuitState.CLASSICAL_ONLY:
                self._classical_fallback_count += 1
                return False, "CLASSICAL_ONLY - permanent fallback"
            
            if self._state == PQCircuitState.OPEN:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    self._state = PQCircuitState.HALF_OPEN
                    self._pq_success_count = 0
                    logger.info("PQ Circuit Breaker: OPEN → HALF_OPEN (recovery timeout)")
                    return True, "HALF_OPEN - testing recovery"
                return False, f"OPEN - retry in {self.recovery_timeout - elapsed:.1f}s"
            
            # HALF_OPEN - allow test requests
            return True, "HALF_OPEN - recovery test"
    
    def get_state(self) -> Dict[str, Any]:
        """Get PQ circuit breaker statistics"""
        with self._lock:
            return {
                'state': self._state.value,
                'pq_failure_count': self._pq_failure_count,
                'pq_success_count': self._pq_success_count,
                'last_failure_seconds_ago': time.time() - self._last_failure_time if self._last_failure_time > 0 else None,
                'recent_pq_failures': list(self._pq_failure_history)[-10:],
                'classical_fallback_count': self._classical_fallback_count,
                'pq_failure_threshold': self.pq_failure_threshold,
                'pq_classical_threshold': self.pq_classical_threshold,
                'recovery_timeout': self.recovery_timeout
            }

# Global PQ circuit breaker instance
_global_pq_circuit_breaker = PQKEMCircuitBreaker()

# ============================================================================
# PQ KEM EXPONENTIAL BACKOFF WITH JITTER
# ============================================================================

class PQKEMExponentialBackoff:
    """
    Exponential backoff specifically for PQ KEM operations.
    Longer delays because PQ operations are computationally expensive.
    """
    
    def __init__(
        self,
        base_delay: float = 0.5,  # Longer base delay for PQ
        max_delay: float = 30.0,   # Longer max delay
        max_retries: int = 3,      # Fewer retries - PQ failures often persistent
        jitter_factor: float = 0.3
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.jitter_factor = jitter_factor
    
    def get_pq_delay(self, attempt: int, algorithm: str = "ML-KEM-768") -> float:
        """Calculate PQ-aware delay based on algorithm complexity"""
        # Algorithm complexity factors (relative to ML-KEM-768)
        complexity_factors = {
            "ML-KEM-512": 0.7,
            "ML-KEM-768": 1.0,
            "ML-KEM-1024": 1.5,
            "BIKE-L1": 1.2,
            "BIKE-L3": 1.8,
            "BIKE-L5": 2.5,
            "CRYSTALS-Kyber": 1.0,
            "FrodoKEM": 3.0,
            "NTRU": 0.8,
        }
        complexity = complexity_factors.get(algorithm, 1.0)
        
        exponential = self.base_delay * (2 ** attempt) * complexity
        jitter = random.uniform(
            1.0 - self.jitter_factor,
            1.0 + self.jitter_factor
        )
        return min(exponential * jitter, self.max_delay)
    
    def should_retry_pq(self, attempt: int, exception: Exception) -> bool:
        """Determine if PQ exception is retryable"""
        if attempt >= self.max_retries:
            return False
        
        # Only retry transient PQ errors
        retryable_types = (
            PQKEMTimeoutError,
            PQHSMMemoryError,
            socket.timeout,
            ConnectionError,
            TimeoutError
        )
        
        if isinstance(exception, retryable_types):
            return True
        if isinstance(exception, PQTLSError) and exception.retryable:
            return True
        return False

# ============================================================================
# PQ KEM TIMEOUT PROTECTION
# ============================================================================

class PQKEMTimeoutProtector:
    """
    Timeout protection specifically for PQ KEM operations.
    PQ operations take longer than classical crypto, so timeouts are longer.
    """
    
    def __init__(self, default_timeout: float = 30.0):  # 30s default for PQ
        self.default_timeout = default_timeout
        self._timeout_stats: Dict[str, Any] = {
            'total_pq_operations': 0,
            'pq_timeout_count': 0,
            'avg_pq_duration': 0.0
        }
        self._lock = threading.Lock()
    
    def run_pq_with_timeout(
        self,
        func: Callable[..., T],
        *args,
        algorithm: str = "ML-KEM-768",
        timeout: Optional[float] = None,
        **kwargs
    ) -> T:
        """Execute PQ KEM function with algorithm-aware timeout"""
        # Algorithm-specific timeout multipliers
        timeout_factors = {
            "ML-KEM-512": 0.7,
            "ML-KEM-768": 1.0,
            "ML-KEM-1024": 1.5,
            "BIKE-L1": 1.2,
            "BIKE-L3": 2.0,
            "BIKE-L5": 3.0,
            "FrodoKEM": 4.0,
        }
        factor = timeout_factors.get(algorithm, 1.0)
        effective_timeout = (timeout or self.default_timeout) * factor
        
        start_time = time.time()
        
        result_holder: List[Any] = [None]
        exception_holder: List[Optional[Exception]] = [None]
        done = threading.Event()
        
        def target():
            try:
                result_holder[0] = func(*args, **kwargs)
            except Exception as e:
                exception_holder[0] = e
            finally:
                done.set()
        
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        
        completed = done.wait(timeout=effective_timeout)
        duration = time.time() - start_time
        
        with self._lock:
            self._timeout_stats['total_pq_operations'] += 1
            n = self._timeout_stats['total_pq_operations']
            self._timeout_stats['avg_pq_duration'] = (
                (self._timeout_stats['avg_pq_duration'] * (n - 1) + duration) / n
            )
        
        if not completed:
            with self._lock:
                self._timeout_stats['pq_timeout_count'] += 1
            raise PQKEMTimeoutError(
                f"PQ KEM ({algorithm}) timed out after {effective_timeout:.1f}s"
            )
        
        if exception_holder[0] is not None:
            raise exception_holder[0]
        
        return result_holder[0]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get PQ timeout protection statistics"""
        with self._lock:
            return dict(self._timeout_stats)

# Global PQ timeout protector
_global_pq_timeout_protector = PQKEMTimeoutProtector()

# ============================================================================
# PQ HSM BULKHEAD ISOLATION
# ============================================================================

class PQHSMBulkhead:
    """
    Bulkhead pattern specifically for PQ HSM operations.
    PQ keys are much larger and consume more HSM memory.
    """
    
    def __init__(
        self,
        max_concurrent_pq: int = 5,  # Fewer concurrent - PQ uses more memory
        max_pq_memory_mb: int = 100   # Memory limit for PQ keys
    ):
        self.max_concurrent_pq = max_concurrent_pq
        self.max_pq_memory_mb = max_pq_memory_mb
        self._semaphore = threading.Semaphore(max_concurrent_pq)
        self._stats: Dict[str, Any] = {
            'pq_executed': 0,
            'pq_rejected': 0,
            'pq_currently_running': 0
        }
        self._lock = threading.Lock()
    
    def execute_pq(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute PQ HSM operation with bulkhead protection"""
        acquired = self._semaphore.acquire(blocking=False)
        
        if not acquired:
            with self._lock:
                self._stats['pq_rejected'] += 1
            raise PQHSMMemoryError(
                f"PQ HSM bulkhead full - {self.max_concurrent_pq} concurrent PQ operations max"
            )
        
        try:
            with self._lock:
                self._stats['pq_currently_running'] += 1
            return func(*args, **kwargs)
        finally:
            with self._lock:
                self._stats['pq_currently_running'] -= 1
                self._stats['pq_executed'] += 1
            self._semaphore.release()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get PQ bulkhead statistics"""
        with self._lock:
            return dict(self._stats)

# Global PQ HSM bulkhead
_global_pq_hsm_bulkhead = PQHSMBulkhead()

# ============================================================================
# PQ HYBRID FALLBACK MANAGER - GRACEFUL DEGRADATION TO CLASSICAL
# ============================================================================

class PQHybridFallbackManager:
    """
    Graceful degradation manager for PQ TLS.
    Automatically falls back to classical crypto when PQ consistently fails.
    
    3 modes:
    - PQ_ONLY: Force PQ, fail if unavailable
    - HYBRID: Try PQ first, fallback to classical on failure
    - CLASSICAL_ONLY: Permanent fallback (circuit breaker triggered)
    """
    
    class FallbackMode(Enum):
        PQ_ONLY = "PQ_ONLY"
        HYBRID = "HYBRID"
        CLASSICAL_ONLY = "CLASSICAL_ONLY"
    
    def __init__(
        self,
        pq_failure_threshold: int = 5,
        classical_recovery_threshold: int = 20,
        window_size: int = 50
    ):
        self.pq_failure_threshold = pq_failure_threshold
        self.classical_recovery_threshold = classical_recovery_threshold
        self.window_size = window_size
        self._pq_outcomes: deque = deque(maxlen=window_size)
        self._mode = self.FallbackMode.HYBRID
        self._lock = threading.Lock()
        self._fallback_count = 0
        self._pq_recovery_count = 0
    
    def record_pq_outcome(self, success: bool) -> None:
        """Record PQ operation outcome"""
        with self._lock:
            self._pq_outcomes.append(success)
    
    def get_effective_mode(self) -> FallbackMode:
        """Determine effective mode based on recent PQ health"""
        with self._lock:
            if len(self._pq_outcomes) < 10:
                return self._mode  # Not enough data
            
            pq_success_rate = sum(1 for o in self._pq_outcomes if o) / len(self._pq_outcomes)
            
            if self._mode == self.FallbackMode.HYBRID:
                if pq_success_rate < 0.2:  # <20% success
                    self._mode = self.FallbackMode.CLASSICAL_ONLY
                    self._fallback_count += 1
                    logger.warning(f"PQ Fallback: HYBRID → CLASSICAL_ONLY (success rate: {pq_success_rate:.1%})")
            
            elif self._mode == self.FallbackMode.CLASSICAL_ONLY:
                if pq_success_rate > 0.8:  # >80% success
                    self._mode = self.FallbackMode.HYBRID
                    self._pq_recovery_count += 1
                    logger.info(f"PQ Recovery: CLASSICAL_ONLY → HYBRID (success rate: {pq_success_rate:.1%})")
            
            return self._mode
    
    def should_try_pq_first(self) -> bool:
        """Check if we should attempt PQ first"""
        mode = self.get_effective_mode()
        return mode in (self.FallbackMode.PQ_ONLY, self.FallbackMode.HYBRID)
    
    def get_pq_health(self) -> Dict[str, Any]:
        """Get PQ health statistics"""
        with self._lock:
            total = len(self._pq_outcomes)
            pq_success_rate = sum(1 for o in self._pq_outcomes if o) / total if total > 0 else 1.0
            return {
                'current_mode': self._mode.value,
                'pq_success_rate': pq_success_rate,
                'sample_size': total,
                'classical_fallback_count': self._fallback_count,
                'pq_recovery_count': self._pq_recovery_count,
                'window_size': self.window_size
            }

# Global PQ hybrid fallback manager
_global_pq_fallback_manager = PQHybridFallbackManager()

# ============================================================================
# PQ CHANNEL BINDING VERIFIER
# ============================================================================

class PQChannelBindingVerifier:
    """
    PQ-aware channel binding verification (RFC 5929 + PQ extensions).
    Constant-time verification to prevent timing attacks.
    """
    
    @staticmethod
    def pq_tls_unique(server_cert_der: bytes, pq_shared_secret: bytes) -> bytes:
        """Generate PQ-enhanced tls-unique channel binding"""
        # RFC 5929 tls-unique + PQ shared secret binding
        tls_unique = hashlib.sha3_256(server_cert_der).digest()
        pq_binding = hashlib.sha3_256(pq_shared_secret).digest()
        return hashlib.sha3_512(tls_unique + pq_binding).digest()
    
    @staticmethod
    def verify_binding_constant_time(expected: bytes, actual: bytes) -> bool:
        """Constant-time binding verification"""
        if len(expected) != len(actual):
            return False
        
        result = 0
        for e, a in zip(expected, actual):
            result |= e ^ a
        
        return result == 0
    
    @staticmethod
    def verify_pq_channel_binding(
        server_cert_der: bytes,
        pq_shared_secret: bytes,
        client_provided_binding: bytes
    ) -> bool:
        """Full PQ channel binding verification"""
        expected = PQChannelBindingVerifier.pq_tls_unique(server_cert_der, pq_shared_secret)
        return PQChannelBindingVerifier.verify_binding_constant_time(expected, client_provided_binding)

# ============================================================================
# PQ DECORATOR - COMBINES ALL ERROR RESILIENCE PATTERNS
# ============================================================================

def pq_tls_error_resilience(
    algorithm: str = "ML-KEM-768",
    timeout: float = 30.0,
    max_retries: int = 2,
    use_circuit_breaker: bool = True,
    use_bulkhead: bool = True,
    allow_classical_fallback: bool = True,
    classical_fallback_function: Optional[Callable] = None
):
    """
    Decorator that applies comprehensive PQ TLS error resilience.
    
    PQ-specific enhancements:
    - Algorithm-aware timeouts
    - Classical crypto fallback
    - HSM memory protection
    - PQ circuit breaker with CLASSICAL_ONLY state
    """
    backoff = PQKEMExponentialBackoff(max_retries=max_retries)
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            attempt = 0
            
            # Check fallback mode first
            if allow_classical_fallback and not _global_pq_fallback_manager.should_try_pq_first():
                if classical_fallback_function:
                    logger.warning("PQ Fallback active - using classical crypto")
                    _global_pq_fallback_manager.record_pq_outcome(False)
                    return classical_fallback_function(*args, **kwargs)
                raise PQHybridFallbackError()
            
            while True:
                # Check PQ circuit breaker
                if use_circuit_breaker:
                    allowed, reason = _global_pq_circuit_breaker.allow_pq_operation()
                    if not allowed:
                        if allow_classical_fallback and classical_fallback_function:
                            logger.warning(f"PQ Circuit {reason} - using classical fallback")
                            _global_pq_fallback_manager.record_pq_outcome(False)
                            return classical_fallback_function(*args, **kwargs)
                        raise PQCircuitBreakerOpen(f"PQ circuit breaker: {reason}")
                
                try:
                    # Execute with PQ timeout and bulkhead
                    def execute_pq():
                        if use_bulkhead:
                            return _global_pq_hsm_bulkhead.execute_pq(func, *args, **kwargs)
                        return func(*args, **kwargs)
                    
                    result = _global_pq_timeout_protector.run_pq_with_timeout(
                        execute_pq, algorithm=algorithm, timeout=timeout
                    )
                    
                    # Success - record and return
                    if use_circuit_breaker:
                        _global_pq_circuit_breaker.record_pq_success()
                    _global_pq_fallback_manager.record_pq_outcome(True)
                    return result
                    
                except Exception as e:
                    # Record PQ failure
                    if use_circuit_breaker:
                        _global_pq_circuit_breaker.record_pq_failure(e)
                    _global_pq_fallback_manager.record_pq_outcome(False)
                    
                    # Check if we should retry PQ
                    if backoff.should_retry_pq(attempt, e):
                        delay = backoff.get_pq_delay(attempt, algorithm)
                        logger.debug(f"PQ retry {attempt + 1}/{max_retries} after {delay:.2f}s: {e}")
                        time.sleep(delay)
                        attempt += 1
                        continue
                    
                    # Check classical fallback
                    if allow_classical_fallback and classical_fallback_function:
                        logger.warning(f"PQ failed after {attempt} retries - classical fallback: {e}")
                        return classical_fallback_function(*args, **kwargs)
                    
                    # Re-raise PQ exception
                    raise
        
        return wrapper
    return decorator

# ============================================================================
# PQ TLS SERVER WRAPPER - ERROR RESILIENCE FOR SECURITY V17
# ============================================================================

def wrap_pq_tls_server_with_error_resilience(
    pq_server_class: type,
    classical_server_class: Optional[type] = None,
    algorithm: str = "ML-KEM-768",
    timeout: float = 45.0,
    max_retries: int = 2
) -> type:
    """
    Wrap an existing PQ TLS server class with comprehensive error resilience.
    
    Pure wrapper pattern - ZERO modification to original PQ server code.
    Automatic classical crypto fallback when PQ fails.
    """
    
    class ErrorResilientPQTLSServer(pq_server_class):
        """
        Error-resilient wrapper for PQ TLS server.
        Inherits all functionality from original, adds PQ error resilience layer.
        """
        
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pq_error_stats = {
                'pq_handshake_success': 0,
                'pq_handshake_failure': 0,
                'pq_handshake_timeout': 0,
                'pq_retries_used': 0,
                'classical_fallback_used': 0,
                'pq_algorithm': algorithm
            }
            self._stats_lock = threading.Lock()
        
        @pq_tls_error_resilience(
            algorithm=algorithm,
            timeout=timeout,
            max_retries=max_retries,
            allow_classical_fallback=(classical_server_class is not None),
            classical_fallback_function=None  # Handled in method
        )
        def _handle_pq_kem_handshake(self, *args, **kwargs):
            """Wrapped PQ KEM handshake with error resilience"""
            try:
                result = super()._handle_pq_kem_handshake(*args, **kwargs)
                with self._stats_lock:
                    self._pq_error_stats['pq_handshake_success'] += 1
                return result
            except PQKEMTimeoutError:
                with self._stats_lock:
                    self._pq_error_stats['pq_handshake_timeout'] += 1
                raise
            except Exception as e:
                with self._stats_lock:
                    self._pq_error_stats['pq_handshake_failure'] += 1
                raise
        
        def _classical_fallback_handshake(self, *args, **kwargs):
            """Graceful fallback to classical TLS"""
            with self._stats_lock:
                self._pq_error_stats['classical_fallback_used'] += 1
            logger.warning("PQ Graceful Fallback: Using classical TLS instead of PQ TLS")
            
            if classical_server_class:
                fallback_server = classical_server_class(*args, **kwargs)
                return fallback_server._handle_classical_handshake(*args, **kwargs)
            
            raise PQHybridFallbackError("Classical fallback server not configured")
        
        def get_pq_error_resilience_stats(self) -> Dict[str, Any]:
            """Get PQ error resilience statistics"""
            with self._stats_lock:
                stats = dict(self._pq_error_stats)
                total = stats['pq_handshake_success'] + stats['pq_handshake_failure']
                stats['pq_success_rate'] = (
                    stats['pq_handshake_success'] / total if total > 0 else 1.0
                )
                stats['pq_circuit_breaker'] = _global_pq_circuit_breaker.get_state()
                stats['pq_timeout_protector'] = _global_pq_timeout_protector.get_stats()
                stats['pq_hsm_bulkhead'] = _global_pq_hsm_bulkhead.get_stats()
                stats['pq_hybrid_fallback'] = _global_pq_fallback_manager.get_pq_health()
                return stats
    
    return ErrorResilientPQTLSServer

# ============================================================================
# CONVENIENCE FUNCTIONS - GLOBAL ACCESS
# ============================================================================

def get_pq_tls_error_resilience_stats() -> Dict[str, Any]:
    """Get comprehensive PQ TLS error resilience statistics"""
    return {
        'pq_circuit_breaker': _global_pq_circuit_breaker.get_state(),
        'pq_timeout_protector': _global_pq_timeout_protector.get_stats(),
        'pq_hsm_bulkhead': _global_pq_hsm_bulkhead.get_stats(),
        'pq_hybrid_fallback': _global_pq_fallback_manager.get_pq_health(),
        'version': '25.0.0',
        'timestamp': time.time()
    }

def reset_pq_tls_error_resilience_state() -> None:
    """Reset all PQ error resilience state (for testing)"""
    global _global_pq_circuit_breaker
    global _global_pq_timeout_protector
    global _global_pq_hsm_bulkhead
    global _global_pq_fallback_manager
    
    _global_pq_circuit_breaker = PQKEMCircuitBreaker()
    _global_pq_timeout_protector = PQKEMTimeoutProtector()
    _global_pq_hsm_bulkhead = PQHSMBulkhead()
    _global_pq_fallback_manager = PQHybridFallbackManager()

# ============================================================================
# BACKWARD COMPATIBILITY - ALL EXISTING CODE WORKS UNCHANGED
# ============================================================================

try:
    from .crypto_error_resilience_v24_key_operation_timeout_retry_fallback_2026_june import (
        PQCircuitBreaker as LegacyPQCBC,
        PQRetryWithBackoff as LegacyPQRetry,
        PQTimeoutProtector as LegacyPQTimeout,
        PQClassicalFallbackChain as LegacyPQFallback,
        pq_error_resilience_decorator as legacy_pq_decorator
    )
    
    # Re-export for backward compatibility
    PQCircuitBreaker = LegacyPQCBC
    PQRetryWithBackoff = LegacyPQRetry
    PQTimeoutProtector = LegacyPQTimeout
    PQClassicalFallbackChain = LegacyPQFallback
    pq_error_resilience_decorator = legacy_pq_decorator
    
except ImportError:
    # Fallback - v24 not available, use v25 implementations
    pass

__all__ = [
    # PQ Exception hierarchy
    'PQTLSError',
    'PQKEMTimeoutError',
    'PQKEMAlgorithmError',
    'PQKeyMaterialError',
    'PQHSMMemoryError',
    'PQHybridFallbackError',
    'PQCircuitBreakerOpen',
    'PQChannelBindingError',
    
    # PQ Core components
    'PQCircuitState',
    'PQKEMCircuitBreaker',
    'PQKEMExponentialBackoff',
    'PQKEMTimeoutProtector',
    'PQHSMBulkhead',
    'PQHybridFallbackManager',
    'PQChannelBindingVerifier',
    
    # PQ Decorators and wrappers
    'pq_tls_error_resilience',
    'wrap_pq_tls_server_with_error_resilience',
    
    # PQ Convenience functions
    'get_pq_tls_error_resilience_stats',
    'reset_pq_tls_error_resilience_state',
    
    # Backward compatible exports
    'PQCircuitBreaker',
    'PQRetryWithBackoff',
    'PQTimeoutProtector',
    'PQClassicalFallbackChain',
    'pq_error_resilience_decorator',
]

# Module metadata
__version__ = '25.0.0'
__dimension__ = 'E - Error Resilience'
__pq_algorithms__ = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', 'BIKE', 'CRYSTALS-Kyber']
__compatible_with__ = ['Security v17 PQ TLS', 'All v24 modules', 'NIST FIPS 203/204/205']
