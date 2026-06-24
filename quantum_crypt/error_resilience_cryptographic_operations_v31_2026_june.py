"""
Error Resilience - Cryptographic Operations Framework v31
Dimension E: Error Resilience
Session 132 - June 24, 2026

ADD-ONLY implementation - wraps existing cryptographic operations
with comprehensive error resilience patterns.
"""

import time
import random
import logging
import threading
import secrets
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic, Union
from functools import wraps
from collections import deque
from datetime import datetime, timedelta

# Configure logging - OPT-IN only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
R = TypeVar('R')

# ============================================================================
# CUSTOM EXCEPTION HIERARCHY - Cryptographic Operations Specific
# ============================================================================

class CryptographicError(Exception):
    """Base exception for all cryptographic operation errors."""
    def __init__(self, message: str, error_code: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()
        self._secure_wipe()
    
    def _secure_wipe(self) -> None:
        """Securely wipe sensitive data from exception details."""
        sensitive_keys = ['key', 'secret', 'private', 'password', 'token']
        for key in list(self.details.keys()):
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                self.details[key] = '[REDACTED]'

class CryptoKeyManagementError(CryptographicError):
    """Key management operation failed."""
    def __init__(self, message: str, key_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CRYPTO_KEY_001", details)
        self.key_id = key_id or "unknown"

class CryptoAlgorithmError(CryptographicError):
    """Algorithm operation failed."""
    def __init__(self, message: str, algorithm_name: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CRYPTO_ALG_001", details)
        self.algorithm_name = algorithm_name

class CryptoTimeoutError(CryptographicError):
    """Cryptographic operation timed out."""
    def __init__(self, message: str, timeout_seconds: float, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CRYPTO_TIMEOUT_001", details)
        self.timeout_seconds = timeout_seconds

class CryptoEntropyError(CryptographicError):
    """Insufficient entropy available."""
    def __init__(self, message: str, available_entropy: int, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CRYPTO_ENTROPY_001", details)
        self.available_entropy = available_entropy

class CryptoCircuitOpenError(CryptographicError):
    """Circuit breaker is open - cryptographic operation rejected."""
    def __init__(self, message: str, recovery_time: float, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CRYPTO_CIRCUIT_001", details)
        self.recovery_time = recovery_time

class CryptoTLSConnectionError(CryptographicError):
    """TLS connection failed."""
    def __init__(self, message: str, endpoint: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CRYPTO_TLS_001", details)
        self.endpoint = endpoint

# ============================================================================
# RESILIENCE STATES AND ENUMS
# ============================================================================

class CircuitState(Enum):
    CLOSED = "CLOSED"           # Normal operation
    OPEN = "OPEN"               # Circuit tripped - reject requests
    HALF_OPEN = "HALF_OPEN"     # Testing recovery

class CryptoOperationType(Enum):
    KEY_GENERATION = "KEY_GENERATION"
    ENCRYPTION = "ENCRYPTION"
    DECRYPTION = "DECRYPTION"
    SIGNING = "SIGNING"
    VERIFICATION = "VERIFICATION"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    HASHING = "HASHING"
    RANDOM_GENERATION = "RANDOM_GENERATION"
    TLS_HANDSHAKE = "TLS_HANDSHAKE"

class DegradationLevel(Enum):
    FULL = "FULL"
    REDUCED_STRENGTH = "REDUCED_STRENGTH"
    SOFTWARE_ONLY = "SOFTWARE_ONLY"
    SAFE_DEFAULT = "SAFE_DEFAULT"
    EMERGENCY = "EMERGENCY"

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class CryptoResilienceConfig:
    """Configuration for cryptographic error resilience behavior."""
    timeout_seconds: float = 60.0
    max_retries: int = 3
    initial_backoff_ms: float = 200.0
    max_backoff_ms: float = 10000.0
    jitter_factor: float = 0.15
    circuit_failure_threshold: int = 10
    circuit_reset_timeout: float = 60.0
    circuit_half_open_max_calls: int = 5
    bulkhead_max_concurrent: int = 20
    bulkhead_max_waiting: int = 200
    enable_graceful_degradation: bool = True
    fallback_timeout_seconds: float = 10.0
    allow_algorithm_fallback: bool = True
    minimum_security_level: int = 128
    enable_secure_wipe: bool = True

@dataclass
class RetryMetrics:
    """Metrics for retry operations."""
    total_attempts: int = 0
    successful_on_first: int = 0
    successful_after_retry: int = 0
    total_failures: int = 0
    total_retries: int = 0
    backoff_times_ms: List[float] = field(default_factory=list)

@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker."""
    state_transitions: int = 0
    total_failures: int = 0
    total_successes: int = 0
    total_rejections: int = 0
    last_state_change: Optional[str] = None

@dataclass
class CryptoOperationResult(Generic[T]):
    """Result wrapper with resilience metadata for crypto operations."""
    success: bool
    result: Optional[T] = None
    error: Optional[Exception] = None
    attempt_count: int = 1
    total_time_ms: float = 0.0
    used_fallback: bool = False
    fallback_algorithm: Optional[str] = None
    fallback_level: Optional[DegradationLevel] = None
    circuit_state: Optional[CircuitState] = None
    security_level: int = 256
    warnings: List[str] = field(default_factory=list)
    operation_type: Optional[CryptoOperationType] = None

# ============================================================================
# SECURE MEMORY MANAGEMENT
# ============================================================================

class SecureMemoryManager:
    """
    Secure memory management for sensitive cryptographic data.
    Provides secure wipe and zeroization capabilities.
    """
    
    @staticmethod
    def secure_wipe_bytes(data: bytearray) -> None:
        """Securely wipe bytearray data with multiple passes."""
        length = len(data)
        # Pass 1: Zero fill
        for i in range(length):
            data[i] = 0
        # Pass 2: One fill
        for i in range(length):
            data[i] = 0xFF
        # Pass 3: Random fill
        random_bytes = secrets.token_bytes(length)
        for i in range(length):
            data[i] = random_bytes[i]
        # Pass 4: Final zero
        for i in range(length):
            data[i] = 0
    
    @staticmethod
    def secure_wipe_string(s: str) -> str:
        """Return a safely wiped string placeholder."""
        return "[SECURE_WIPED_" + secrets.token_hex(4) + "]"

# ============================================================================
# ADAPTIVE RETRY WITH EXPONENTIAL BACKOFF AND JITTER
# ============================================================================

class CryptoAdaptiveRetryBackoff:
    """
    Adaptive retry with exponential backoff and jitter for cryptographic operations.
    Prevents thundering herd and provides crypto-specific timing.
    """
    
    def __init__(self, config: Optional[CryptoResilienceConfig] = None):
        self.config = config or CryptoResilienceConfig()
        self.metrics = RetryMetrics()
        self._lock = threading.Lock()
    
    def calculate_backoff(self, attempt: int, operation_type: CryptoOperationType) -> float:
        """Calculate backoff with jitter and operation-specific adjustments."""
        # Operation-specific base multipliers
        op_multipliers = {
            CryptoOperationType.KEY_GENERATION: 2.0,
            CryptoOperationType.TLS_HANDSHAKE: 1.5,
            CryptoOperationType.SIGNING: 1.2,
            CryptoOperationType.ENCRYPTION: 1.0,
            CryptoOperationType.DECRYPTION: 1.0,
        }
        multiplier = op_multipliers.get(operation_type, 1.0)
        
        base_backoff = min(
            self.config.initial_backoff_ms * multiplier * (2 ** (attempt - 1)),
            self.config.max_backoff_ms
        )
        jitter = base_backoff * self.config.jitter_factor * random.uniform(-1, 1)
        backoff = max(0.0, base_backoff + jitter)
        
        with self._lock:
            self.metrics.backoff_times_ms.append(backoff)
        
        return backoff / 1000.0
    
    def execute_with_retry(
        self,
        operation: Callable[[], T],
        operation_type: CryptoOperationType,
        fallback: Optional[Callable[[], T]] = None
    ) -> CryptoOperationResult[T]:
        """Execute crypto operation with retry and backoff."""
        start_time = time.time()
        attempt = 0
        last_error: Optional[Exception] = None
        
        while attempt < self.config.max_retries:
            attempt += 1
            with self._lock:
                self.metrics.total_attempts += 1
            
            try:
                result = operation()
                total_time = (time.time() - start_time) * 1000
                
                with self._lock:
                    if attempt == 1:
                        self.metrics.successful_on_first += 1
                    else:
                        self.metrics.successful_after_retry += 1
                
                return CryptoOperationResult[T](
                    success=True,
                    result=result,
                    attempt_count=attempt,
                    total_time_ms=total_time,
                    operation_type=operation_type
                )
                
            except Exception as e:
                last_error = e
                with self._lock:
                    self.metrics.total_failures += 1
                    if attempt < self.config.max_retries:
                        self.metrics.total_retries += 1
                
                if attempt < self.config.max_retries:
                    backoff = self.calculate_backoff(attempt, operation_type)
                    time.sleep(backoff)
                else:
                    break
        
        # All retries failed - try fallback
        total_time = (time.time() - start_time) * 1000
        
        if fallback is not None and self.config.enable_graceful_degradation:
            try:
                fallback_result = fallback()
                return CryptoOperationResult[T](
                    success=True,
                    error=last_error,
                    attempt_count=attempt,
                    total_time_ms=total_time,
                    used_fallback=True,
                    fallback_level=DegradationLevel.SAFE_DEFAULT,
                    operation_type=operation_type,
                    warnings=["Primary operation failed, using fallback"]
                )
            except Exception as fallback_error:
                return CryptoOperationResult[T](
                    success=False,
                    error=last_error,
                    attempt_count=attempt,
                    total_time_ms=total_time,
                    used_fallback=True,
                    operation_type=operation_type,
                    warnings=["Fallback also failed: " + str(fallback_error)]
                )
        
        return CryptoOperationResult[T](
            success=False,
            error=last_error,
            attempt_count=attempt,
            total_time_ms=total_time,
            operation_type=operation_type
        )
    
    def get_metrics(self) -> RetryMetrics:
        """Get current retry metrics."""
        with self._lock:
            return RetryMetrics(**self.metrics.__dict__)

# ============================================================================
# CRYPTOGRAPHIC CIRCUIT BREAKER
# ============================================================================

class CryptoCircuitBreaker:
    """
    Circuit breaker specifically for cryptographic operations.
    Prevents cascading failures in HSM, TPM, or network crypto services.
    """
    
    def __init__(self, config: Optional[CryptoResilienceConfig] = None):
        self.config = config or CryptoResilienceConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._open_timestamp: Optional[float] = None
        self._half_open_attempts = 0
        self._metrics = CircuitBreakerMetrics()
        self._lock = threading.Lock()
    
    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            return self._state
    
    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to new circuit state."""
        if self._state != new_state:
            logger.warning(f"Crypto circuit transitioning {self._state.value} -> {new_state.value}")
            self._state = new_state
            self._metrics.state_transitions += 1
            self._metrics.last_state_change = datetime.utcnow().isoformat()
            self._failure_count = 0
            self._success_count = 0
            self._half_open_attempts = 0
    
    def _check_state(self) -> None:
        """Check and update circuit state based on timeout."""
        now = time.time()
        if self._state == CircuitState.OPEN:
            if self._open_timestamp and (now - self._open_timestamp) >= self.config.circuit_reset_timeout:
                self._transition_to(CircuitState.HALF_OPEN)
    
    def record_success(self) -> None:
        """Record successful crypto operation."""
        with self._lock:
            self._check_state()
            self._metrics.total_successes += 1
            
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.circuit_half_open_max_calls:
                    self._transition_to(CircuitState.CLOSED)
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0
    
    def record_failure(self) -> None:
        """Record failed crypto operation."""
        with self._lock:
            self._check_state()
            self._metrics.total_failures += 1
            
            if self._state == CircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self.config.circuit_failure_threshold:
                    self._transition_to(CircuitState.OPEN)
                    self._open_timestamp = time.time()
            elif self._state == CircuitState.HALF_OPEN:
                self._transition_to(CircuitState.OPEN)
                self._open_timestamp = time.time()
    
    def allow_request(self) -> bool:
        """Check if crypto request should be allowed."""
        with self._lock:
            self._check_state()
            
            if self._state == CircuitState.OPEN:
                self._metrics.total_rejections += 1
                return False
            elif self._state == CircuitState.HALF_OPEN:
                self._half_open_attempts += 1
                return True
            return True
    
    def execute(
        self,
        operation: Callable[[], T],
        operation_type: CryptoOperationType,
        fallback: Optional[Callable[[], T]] = None
    ) -> CryptoOperationResult[T]:
        """Execute operation with circuit breaker protection."""
        start_time = time.time()
        
        if not self.allow_request():
            recovery_time = max(0.0, self.config.circuit_reset_timeout - 
                              (time.time() - (self._open_timestamp or time.time())))
            error = CryptoCircuitOpenError(
                "Cryptographic circuit breaker OPEN",
                recovery_time,
                {"operation_type": operation_type.value}
            )
            
            if fallback is not None and self.config.enable_graceful_degradation:
                try:
                    fallback_result = fallback()
                    return CryptoOperationResult[T](
                        success=True,
                        error=error,
                        total_time_ms=(time.time() - start_time) * 1000,
                        used_fallback=True,
                        fallback_level=DegradationLevel.SOFTWARE_ONLY,
                        circuit_state=CircuitState.OPEN,
                        operation_type=operation_type,
                        warnings=["Circuit open, using software fallback"]
                    )
                except Exception:
                    pass
            
            return CryptoOperationResult[T](
                success=False,
                error=error,
                total_time_ms=(time.time() - start_time) * 1000,
                circuit_state=CircuitState.OPEN,
                operation_type=operation_type
            )
        
        try:
            result = operation()
            self.record_success()
            return CryptoOperationResult[T](
                success=True,
                result=result,
                total_time_ms=(time.time() - start_time) * 1000,
                circuit_state=self.state,
                operation_type=operation_type
            )
        except Exception as e:
            self.record_failure()
            
            if fallback is not None and self.config.enable_graceful_degradation:
                try:
                    fallback_result = fallback()
                    return CryptoOperationResult[T](
                        success=True,
                        error=e,
                        total_time_ms=(time.time() - start_time) * 1000,
                        used_fallback=True,
                        fallback_level=DegradationLevel.SOFTWARE_ONLY,
                        circuit_state=self.state,
                        operation_type=operation_type,
                        warnings=["Operation failed, using fallback"]
                    )
                except Exception:
                    pass
            
            return CryptoOperationResult[T](
                success=False,
                error=e,
                total_time_ms=(time.time() - start_time) * 1000,
                circuit_state=self.state,
                operation_type=operation_type
            )

# ============================================================================
# TLS CONNECTION RETRY WITH EXPONENTIAL BACKOFF
# ============================================================================

class TLSConnectionResilience:
    """
    Resilience handler specifically for TLS connections.
    Implements retry with exponential backoff and endpoint health tracking.
    """
    
    def __init__(self, config: Optional[CryptoResilienceConfig] = None):
        self.config = config or CryptoResilienceConfig()
        self._endpoint_health: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
    
    def record_connection_success(self, endpoint: str) -> None:
        """Record successful TLS connection."""
        with self._lock:
            if endpoint not in self._endpoint_health:
                self._endpoint_health[endpoint] = {
                    "successes": 0,
                    "failures": 0,
                    "consecutive_failures": 0,
                    "last_success": None,
                    "last_failure": None
                }
            health = self._endpoint_health[endpoint]
            health["successes"] += 1
            health["consecutive_failures"] = 0
            health["last_success"] = datetime.utcnow().isoformat()
    
    def record_connection_failure(self, endpoint: str) -> None:
        """Record failed TLS connection."""
        with self._lock:
            if endpoint not in self._endpoint_health:
                self._endpoint_health[endpoint] = {
                    "successes": 0,
                    "failures": 0,
                    "consecutive_failures": 0,
                    "last_success": None,
                    "last_failure": None
                }
            health = self._endpoint_health[endpoint]
            health["failures"] += 1
            health["consecutive_failures"] += 1
            health["last_failure"] = datetime.utcnow().isoformat()
    
    def get_endpoint_health(self, endpoint: str) -> Dict[str, Any]:
        """Get health status for endpoint."""
        with self._lock:
            return dict(self._endpoint_health.get(endpoint, {
                "successes": 0,
                "failures": 0,
                "consecutive_failures": 0,
                "health_score": 1.0
            }))
    
    def execute_tls_operation(
        self,
        operation: Callable[[], T],
        endpoint: str,
        fallback: Optional[Callable[[], T]] = None
    ) -> CryptoOperationResult[T]:
        """Execute TLS operation with resilience."""
        start_time = time.time()
        max_attempts = self.config.max_retries
        
        for attempt in range(max_attempts):
            try:
                result = operation()
                self.record_connection_success(endpoint)
                return CryptoOperationResult[T](
                    success=True,
                    result=result,
                    attempt_count=attempt + 1,
                    total_time_ms=(time.time() - start_time) * 1000,
                    operation_type=CryptoOperationType.TLS_HANDSHAKE
                )
            except Exception as e:
                self.record_connection_failure(endpoint)
                
                if attempt < max_attempts - 1:
                    # Exponential backoff
                    backoff = min(0.2 * (2 ** attempt), 5.0)
                    time.sleep(backoff + random.uniform(0, 0.1))
                else:
                    # Final attempt failed
                    if fallback is not None and self.config.enable_graceful_degradation:
                        try:
                            fallback_result = fallback()
                            return CryptoOperationResult[T](
                                success=True,
                                error=e,
                                attempt_count=max_attempts,
                                total_time_ms=(time.time() - start_time) * 1000,
                                used_fallback=True,
                                fallback_level=DegradationLevel.SAFE_DEFAULT,
                                operation_type=CryptoOperationType.TLS_HANDSHAKE,
                                warnings=["TLS connection failed, using fallback"]
                            )
                        except Exception:
                            pass
                    
                    return CryptoOperationResult[T](
                        success=False,
                        error=e,
                        attempt_count=max_attempts,
                        total_time_ms=(time.time() - start_time) * 1000,
                        operation_type=CryptoOperationType.TLS_HANDSHAKE
                    )
        
        # Should never reach here
        return CryptoOperationResult[T](
            success=False,
            error=CryptoTLSConnectionError("All TLS attempts exhausted", endpoint),
            total_time_ms=(time.time() - start_time) * 1000,
            operation_type=CryptoOperationType.TLS_HANDSHAKE
        )

# ============================================================================
# ALGORITHM FALLBACK CHAIN
# ============================================================================

class AlgorithmFallbackChain:
    """
    Manages algorithm fallback chain for graceful degradation.
    Falls back to progressively weaker but more available algorithms.
    """
    
    def __init__(self, config: Optional[CryptoResilienceConfig] = None):
        self.config = config or CryptoResilienceConfig()
        self._fallback_chains: Dict[CryptoOperationType, List[Dict[str, Any]]] = {}
        self._degradation_events: deque = deque(maxlen=100)
        self._lock = threading.Lock()
    
    def register_fallback_chain(
        self,
        operation_type: CryptoOperationType,
        algorithms: List[Dict[str, Any]]
    ) -> None:
        """Register fallback chain for operation type.
        
        Each algorithm entry should have:
        - name: algorithm identifier
        - security_level: bits of security
        - level: DegradationLevel
        - handler: callable
        """
        with self._lock:
            # Sort by security level descending
            sorted_algs = sorted(algorithms, key=lambda a: -a.get("security_level", 0))
            self._fallback_chains[operation_type] = sorted_algs
    
    def execute_with_fallback_chain(
        self,
        operation_type: CryptoOperationType,
        primary_handler: Callable[[], T],
        *args, **kwargs
    ) -> CryptoOperationResult[T]:
        """Execute operation with full algorithm fallback chain."""
        start_time = time.time()
        warnings: List[str] = []
        last_error: Optional[Exception] = None
        
        # Try primary first
        try:
            result = primary_handler(*args, **kwargs)
            return CryptoOperationResult[T](
                success=True,
                result=result,
                total_time_ms=(time.time() - start_time) * 1000,
                operation_type=operation_type,
                security_level=256
            )
        except Exception as e:
            last_error = e
            warnings.append(f"Primary algorithm failed: {str(e)}")
        
        # Try fallback chain
        with self._lock:
            chain = self._fallback_chains.get(operation_type, [])
        
        for fallback in chain:
            if fallback["security_level"] < self.config.minimum_security_level:
                warnings.append(f"Skipping {fallback['name']}: below minimum security level")
                continue
            
            try:
                fallback_result = fallback["handler"](*args, **kwargs)
                
                self._degradation_events.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "operation_type": operation_type.value,
                    "primary_error": str(last_error),
                    "fallback_algorithm": fallback["name"],
                    "fallback_level": fallback["level"].value,
                    "security_level": fallback["security_level"]
                })
                
                warnings.append(f"Using fallback: {fallback['name']} ({fallback['level'].value})")
                
                return CryptoOperationResult[T](
                    success=True,
                    error=last_error,
                    total_time_ms=(time.time() - start_time) * 1000,
                    used_fallback=True,
                    fallback_algorithm=fallback["name"],
                    fallback_level=fallback["level"],
                    operation_type=operation_type,
                    security_level=fallback["security_level"],
                    warnings=warnings
                )
            except Exception as e:
                warnings.append(f"Fallback {fallback['name']} failed: {str(e)}")
                continue
        
        # All fallbacks failed
        return CryptoOperationResult[T](
            success=False,
            error=last_error,
            total_time_ms=(time.time() - start_time) * 1000,
            operation_type=operation_type,
            warnings=warnings + ["All algorithm fallbacks exhausted"]
        )

# ============================================================================
# COMPREHENSIVE CRYPTO RESILIENCE WRAPPER
# ============================================================================

class ComprehensiveCryptoResilience:
    """
    Combined error resilience wrapper for all cryptographic operations.
    Integrates: Retry + Circuit Breaker + TLS Resilience + Algorithm Fallback Chain
    """
    
    def __init__(self, config: Optional[CryptoResilienceConfig] = None):
        self.config = config or CryptoResilienceConfig()
        self.retry_handler = CryptoAdaptiveRetryBackoff(self.config)
        self.circuit_breaker = CryptoCircuitBreaker(self.config)
        self.tls_handler = TLSConnectionResilience(self.config)
        self.algorithm_fallback = AlgorithmFallbackChain(self.config)
        self.secure_memory = SecureMemoryManager()
    
    def wrap_crypto_operation(
        self,
        operation: Callable[..., T],
        operation_type: CryptoOperationType,
        fallback: Optional[Callable[..., T]] = None
    ) -> Callable[..., CryptoOperationResult[T]]:
        """Wrap cryptographic operation with full resilience stack."""
        
        def resilient_operation(*args, **kwargs) -> CryptoOperationResult[T]:
            def primary_op():
                return operation(*args, **kwargs)
            
            def fallback_op():
                if fallback:
                    return fallback(*args, **kwargs)
                return None
            
            # Circuit Breaker -> Retry with Fallback
            return self.circuit_breaker.execute(
                lambda: self.retry_handler.execute_with_retry(
                    primary_op, operation_type, fallback_op
                ).result if self.retry_handler.execute_with_retry(
                    primary_op, operation_type, fallback_op
                ).success else None,
                operation_type,
                fallback_op
            )
        
        return resilient_operation
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "circuit_breaker": {
                "state": self.circuit_breaker.state.value,
                "metrics": self.circuit_breaker._metrics.__dict__
            },
            "retry_metrics": self.retry_handler.get_metrics().__dict__,
            "security_config": {
                "minimum_security_level": self.config.minimum_security_level,
                "enable_secure_wipe": self.config.enable_secure_wipe,
                "enable_graceful_degradation": self.config.enable_graceful_degradation
            }
        }

# ============================================================================
# MODULE EXPORTS
# ============================================================================

__all__ = [
    # Exceptions
    "CryptographicError",
    "CryptoKeyManagementError",
    "CryptoAlgorithmError",
    "CryptoTimeoutError",
    "CryptoEntropyError",
    "CryptoCircuitOpenError",
    "CryptoTLSConnectionError",
    
    # Enums
    "CircuitState",
    "CryptoOperationType",
    "DegradationLevel",
    
    # Data Structures
    "CryptoResilienceConfig",
    "RetryMetrics",
    "CircuitBreakerMetrics",
    "CryptoOperationResult",
    
    # Resilience Components
    "SecureMemoryManager",
    "CryptoAdaptiveRetryBackoff",
    "CryptoCircuitBreaker",
    "TLSConnectionResilience",
    "AlgorithmFallbackChain",
    "ComprehensiveCryptoResilience",
]
