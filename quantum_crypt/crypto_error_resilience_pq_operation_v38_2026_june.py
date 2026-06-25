"""
QuantumCrypt AI - PQ Crypto Operation Error Resilience v38
Dimension E: Error Resilience - Post-Quantum Crypto Specific Resilience

Implements:
- PQ key operation deadline propagation with cancellation
- Crypto-specific fallback chains (algorithm agility)
- HSM graceful degradation and fallback
- Batch operation resilience with partial failure handling
- Happy path behavior 100% preserved - all OPT-IN

STABILITY: STABLE
BACKWARD COMPATIBLE: YES
"""

import time
import threading
import functools
import logging
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, Union
from abc import ABC, abstractmethod

# Configure logging - disabled by default (OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')


class CryptoOperationType(Enum):
    """Types of cryptographic operations."""
    KEY_GENERATION = "key_gen"
    KEY_ENCAPSULATION = "encap"
    KEY_DECAPSULATION = "decap"
    SIGNATURE = "sign"
    VERIFICATION = "verify"
    KEY_EXCHANGE = "key_exchange"
    ENCRYPTION = "encrypt"
    DECRYPTION = "decrypt"
    BATCH_OPERATION = "batch"


class CryptoSecurityLevel(Enum):
    """Security levels for crypto operations."""
    QUANTUM_RESISTANT = 0    # NIST PQC Level 5
    HIGH_ASSURANCE = 1       # NIST PQC Level 3
    STANDARD = 2             # NIST PQC Level 1
    LEGACY_COMPAT = 3        # Classic crypto fallback
    BEST_EFFORT = 4          # Informational only


class CryptoFallbackStrategy(Enum):
    """Fallback strategies specific to cryptographic operations."""
    FAIL_SECURE = "fail_secure"          # Return error, don't proceed
    FALLBACK_ALGORITHM = "fallback_algo"  # Use alternative PQ algorithm
    FALLBACK_CLASSIC = "fallback_classic" # Use classic crypto
    FALLBACK_HSM_SOFTWARE = "hsm_soft"    # Fallback from HSM to software
    PARTIAL_BATCH = "partial_batch"       # Continue batch with successes
    REGENERATE_KEY = "regenerate_key"     # Regenerate and retry


@dataclass
class CryptoOperationDeadline:
    """Deadline tracking for crypto operations with budget allocation."""
    deadline_time: float
    operation_type: CryptoOperationType
    operation_name: str
    budget_allocation: Dict[str, float] = field(default_factory=dict)
    parent_deadline: Optional['CryptoOperationDeadline'] = None
    created_at: float = field(default_factory=time.time)
    
    @property
    def remaining_ms(self) -> float:
        """Get remaining time in milliseconds."""
        return max(0.0, (self.deadline_time - time.time()) * 1000)
    
    @property
    def expired(self) -> bool:
        """Check if deadline has expired."""
        return time.time() > self.deadline_time
    
    @classmethod
    def from_timeout(cls, timeout_ms: float, 
                     operation_type: CryptoOperationType,
                     operation_name: str,
                     parent: Optional['CryptoOperationDeadline'] = None) -> 'CryptoOperationDeadline':
        """Create deadline from timeout."""
        deadline = time.time() + (timeout_ms / 1000.0)
        if parent and parent.deadline_time < deadline:
            deadline = parent.deadline_time
        return cls(deadline, operation_type, operation_name, parent_deadline=parent)
    
    def allocate_budget(self, sub_operation: str, budget_ms: float) -> float:
        """Allocate time budget for sub-operation, returns actual allocation."""
        available = self.remaining_ms
        actual = min(budget_ms, available * 0.8)  # Never allocate more than 80% remaining
        self.budget_allocation[sub_operation] = actual
        return actual


class CryptoOperationError(Exception):
    """Base exception for crypto operation errors."""
    def __init__(self, operation: str, message: str, recoverable: bool = True):
        self.operation = operation
        self.recoverable = recoverable
        super().__init__(f"Crypto operation '{operation}': {message}")


class CryptoDeadlineExceededError(CryptoOperationError):
    """Raised when crypto operation exceeds deadline."""
    def __init__(self, operation: str, remaining_ms: float, allocated_ms: float):
        super().__init__(operation, f"Deadline exceeded by {abs(remaining_ms):.1f}ms", recoverable=False)
        self.remaining_ms = remaining_ms
        self.allocated_ms = allocated_ms


class HSMUnavailableError(CryptoOperationError):
    """Raised when HSM is unavailable."""
    def __init__(self, hsm_id: str):
        super().__init__(f"HSM_{hsm_id}", "HSM hardware unavailable", recoverable=True)


@dataclass
class CryptoOperationResult:
    """Result from resilient crypto operation."""
    success: bool
    result: Any
    fallback_used: Optional[CryptoFallbackStrategy]
    fallback_level: int
    total_time_ms: float
    algorithm_used: Optional[str] = None
    deadline_expired: bool = False
    partial_results: List[Any] = field(default_factory=list)
    errors: List[Exception] = field(default_factory=list)
    security_level_achieved: Optional[CryptoSecurityLevel] = None


class PQCryptoFallbackOrchestrator:
    """
    Orchestrates resilience for Post-Quantum cryptographic operations.
    
    All features OPT-IN - existing crypto code works unchanged.
    Happy path behavior 100% preserved.
    """
    
    def __init__(self, default_timeout_ms: float = 30000.0):
        self.default_timeout_ms = default_timeout_ms
        self._algorithm_chains: Dict[str, List[Tuple[CryptoFallbackStrategy, Callable, str]]] = {}
        self._security_configs: Dict[CryptoSecurityLevel, Dict] = {}
        self._lock = threading.RLock()
        self._initialize_security_configs()
    
    def _initialize_security_configs(self) -> None:
        """Initialize security level configurations."""
        self._security_configs = {
            CryptoSecurityLevel.QUANTUM_RESISTANT: {
                "timeout_ms": 60000.0,
                "max_retries": 2,
                "allow_classic_fallback": False,
                "strategy": CryptoFallbackStrategy.FAIL_SECURE,
                "retry_backoff_ms": [500, 1000]
            },
            CryptoSecurityLevel.HIGH_ASSURANCE: {
                "timeout_ms": 30000.0,
                "max_retries": 2,
                "allow_classic_fallback": False,
                "strategy": CryptoFallbackStrategy.FALLBACK_ALGORITHM,
                "retry_backoff_ms": [200, 500]
            },
            CryptoSecurityLevel.STANDARD: {
                "timeout_ms": 10000.0,
                "max_retries": 2,
                "allow_classic_fallback": True,
                "strategy": CryptoFallbackStrategy.FALLBACK_ALGORITHM,
                "retry_backoff_ms": [100, 200]
            },
            CryptoSecurityLevel.LEGACY_COMPAT: {
                "timeout_ms": 5000.0,
                "max_retries": 1,
                "allow_classic_fallback": True,
                "strategy": CryptoFallbackStrategy.FALLBACK_CLASSIC,
                "retry_backoff_ms": [100]
            },
            CryptoSecurityLevel.BEST_EFFORT: {
                "timeout_ms": 2000.0,
                "max_retries": 0,
                "allow_classic_fallback": True,
                "strategy": CryptoFallbackStrategy.FALLBACK_CLASSIC,
                "retry_backoff_ms": []
            }
        }
    
    def register_algorithm_chain(self,
                                  operation_name: str,
                                  primary_algo: Tuple[str, Callable],
                                  fallback_algos: List[Tuple[CryptoFallbackStrategy, str, Callable]]) -> None:
        """
        Register algorithm fallback chain for an operation.
        
        Args:
            operation_name: Name of the operation
            primary_algo: (algorithm_name, callable) for primary implementation
            fallback_algos: List of (strategy, algorithm_name, callable) fallbacks
        """
        with self._lock:
            chain = [(CryptoFallbackStrategy.REGENERATE_KEY, primary_algo[1], primary_algo[0])]
            for strategy, algo_name, func in fallback_algos:
                chain.append((strategy, func, algo_name))
            self._algorithm_chains[operation_name] = chain
            logger.debug(f"Registered algorithm chain for {operation_name} with {len(chain)} levels")
    
    def get_config_for_security_level(self, level: CryptoSecurityLevel) -> Dict:
        """Get configuration for a security level."""
        return self._security_configs.get(level, self._security_configs[CryptoSecurityLevel.STANDARD])
    
    def execute_pq_operation(self,
                              operation_name: str,
                              operation_type: CryptoOperationType,
                              security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD,
                              deadline: Optional[CryptoOperationDeadline] = None,
                              *args, **kwargs) -> CryptoOperationResult:
        """
        Execute PQ crypto operation with algorithm agility and resilience.
        
        Happy path: Primary algorithm executes normally with zero overhead.
        Error path: Falls through algorithm chain gracefully.
        """
        start_time = time.time()
        config = self.get_config_for_security_level(security_level)
        
        if deadline is None:
            deadline = CryptoOperationDeadline.from_timeout(
                config["timeout_ms"], operation_type, operation_name
            )
        
        # Check deadline first
        if deadline.expired:
            logger.warning(f"Deadline already exceeded for {operation_name}")
            return CryptoOperationResult(
                success=False,
                result=self._get_secure_fallback(security_level, config["strategy"]),
                fallback_used=config["strategy"],
                fallback_level=0,
                total_time_ms=(time.time() - start_time) * 1000,
                deadline_expired=True,
                errors=[CryptoDeadlineExceededError(operation_name, deadline.remaining_ms, config["timeout_ms"])]
            )
        
        chain = self._algorithm_chains.get(operation_name, [])
        if not chain:
            # No chain registered - execute directly
            try:
                result = args[0](*args[1:], **kwargs) if args else None
                return CryptoOperationResult(
                    success=True,
                    result=result,
                    fallback_used=None,
                    fallback_level=0,
                    total_time_ms=(time.time() - start_time) * 1000
                )
            except Exception as e:
                return CryptoOperationResult(
                    success=False,
                    result=None,
                    fallback_used=None,
                    fallback_level=0,
                    total_time_ms=(time.time() - start_time) * 1000,
                    errors=[e]
                )
        
        errors: List[Exception] = []
        
        for level, (strategy, handler, algo_name) in enumerate(chain):
            if deadline.expired:
                logger.warning(f"Deadline exceeded for {operation_name} at algorithm {algo_name}")
                return CryptoOperationResult(
                    success=False,
                    result=None,
                    fallback_used=strategy,
                    fallback_level=level,
                    total_time_ms=(time.time() - start_time) * 1000,
                    deadline_expired=True,
                    errors=errors + [CryptoDeadlineExceededError(operation_name, deadline.remaining_ms, config["timeout_ms"])]
                )
            
            try:
                if strategy == CryptoFallbackStrategy.REGENERATE_KEY:
                    result = self._execute_with_key_regeneration(
                        handler, config, deadline, *args, **kwargs
                    )
                else:
                    result = handler(*args, **kwargs)
                
                if level > 0:
                    logger.info(f"Operation {operation_name} succeeded with fallback {algo_name} at level {level}")
                
                return CryptoOperationResult(
                    success=True,
                    result=result,
                    fallback_used=strategy if level > 0 else None,
                    fallback_level=level,
                    total_time_ms=(time.time() - start_time) * 1000,
                    algorithm_used=algo_name,
                    security_level_achieved=security_level
                )
            
            except CryptoDeadlineExceededError:
                raise
            except (HSMUnavailableError, CryptoOperationError) as e:
                if not e.recoverable:
                    errors.append(e)
                    break
                errors.append(e)
                logger.debug(f"Algorithm {algo_name} failed: {e}")
                continue
            except Exception as e:
                errors.append(e)
                logger.debug(f"Algorithm {algo_name} failed unexpectedly: {e}")
                continue
        
        # All algorithms failed - apply final strategy
        final_strategy = config["strategy"]
        logger.warning(f"All algorithms failed for {operation_name}, applying {final_strategy}")
        
        return CryptoOperationResult(
            success=False,
            result=self._get_secure_fallback(security_level, final_strategy),
            fallback_used=final_strategy,
            fallback_level=len(chain),
            total_time_ms=(time.time() - start_time) * 1000,
            errors=errors,
            security_level_achieved=self._get_fallback_security_level(final_strategy)
        )
    
    def _execute_with_key_regeneration(self, handler: Callable, config: Dict,
                                        deadline: CryptoOperationDeadline, *args, **kwargs) -> Any:
        """Execute with key regeneration retry logic."""
        max_retries = config["max_retries"]
        backoffs = config["retry_backoff_ms"]
        
        last_error = None
        for attempt in range(max_retries + 1):
            if deadline.expired:
                raise CryptoDeadlineExceededError(
                    handler.__name__ if hasattr(handler, '__name__') else 'unknown',
                    deadline.remaining_ms, config["timeout_ms"]
                )
            
            try:
                return handler(*args, **kwargs)
            except (HSMUnavailableError, CryptoOperationError) as e:
                last_error = e
                if not e.recoverable:
                    raise
                if attempt < max_retries and attempt < len(backoffs):
                    sleep_ms = min(backoffs[attempt], deadline.remaining_ms * 0.5)
                    if sleep_ms > 0:
                        time.sleep(sleep_ms / 1000.0)
                    # Regenerate key material for retry
                    kwargs['key_nonce'] = secrets.token_bytes(16)
                    continue
                raise
            except Exception as e:
                last_error = e
                if attempt < max_retries and attempt < len(backoffs):
                    sleep_ms = min(backoffs[attempt], deadline.remaining_ms * 0.5)
                    if sleep_ms > 0:
                        time.sleep(sleep_ms / 1000.0)
                    continue
                raise
        
        raise last_error
    
    def _get_secure_fallback(self, security_level: CryptoSecurityLevel, 
                              strategy: CryptoFallbackStrategy) -> Any:
        """Get secure fallback result for failed operations."""
        if strategy == CryptoFallbackStrategy.FAIL_SECURE:
            # Don't return sensitive data on failure
            return None
        return None
    
    def _get_fallback_security_level(self, strategy: CryptoFallbackStrategy) -> CryptoSecurityLevel:
        """Get security level achieved by fallback strategy."""
        if strategy == CryptoFallbackStrategy.FALLBACK_CLASSIC:
            return CryptoSecurityLevel.LEGACY_COMPAT
        return CryptoSecurityLevel.BEST_EFFORT
    
    def execute_batch_operation(self,
                                 operation_name: str,
                                 items: List[Any],
                                 item_processor: Callable[[Any], Any],
                                 security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD,
                                 deadline: Optional[CryptoOperationDeadline] = None) -> CryptoOperationResult:
        """
        Execute batch operation with partial failure resilience.
        
        Returns successes even if some items fail.
        """
        start_time = time.time()
        config = self.get_config_for_security_level(security_level)
        
        if deadline is None:
            deadline = CryptoOperationDeadline.from_timeout(
                config["timeout_ms"], CryptoOperationType.BATCH_OPERATION, operation_name
            )
        
        results: List[Any] = []
        errors: List[Exception] = []
        
        for i, item in enumerate(items):
            if deadline.expired:
                break
            
            try:
                result = item_processor(item)
                results.append((i, result, True))
            except Exception as e:
                errors.append((i, e))
                results.append((i, None, False))
        
        all_success = len(errors) == 0 and not deadline.expired
        
        return CryptoOperationResult(
            success=all_success,
            result=None,
            fallback_used=CryptoFallbackStrategy.PARTIAL_BATCH if errors else None,
            fallback_level=0,
            total_time_ms=(time.time() - start_time) * 1000,
            partial_results=results,
            errors=[e for _, e in errors],
            deadline_expired=deadline.expired
        )


def with_crypto_deadline(timeout_ms: float = 10000.0,
                          operation_type: CryptoOperationType = CryptoOperationType.KEY_GENERATION):
    """
    Decorator for crypto deadline enforcement.
    
    OPT-IN: Only applies to decorated functions.
    Happy path 100% preserved.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            deadline = kwargs.pop('crypto_deadline', None)
            
            if deadline is None:
                deadline = CryptoOperationDeadline.from_timeout(
                    timeout_ms, operation_type, func.__name__
                )
            else:
                deadline = CryptoOperationDeadline.from_timeout(
                    timeout_ms, operation_type, func.__name__, deadline
                )
            
            if deadline.expired:
                raise CryptoDeadlineExceededError(func.__name__, deadline.remaining_ms, timeout_ms)
            
            kwargs['crypto_deadline'] = deadline
            return func(*args, **kwargs)
        return wrapper
    return decorator


def with_hsm_fallback(software_fallback: Optional[Callable] = None):
    """
    Decorator for HSM-to-software fallback.
    
    OPT-IN: Falls back to software implementation if HSM unavailable.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except HSMUnavailableError:
                if software_fallback is not None:
                    logger.debug(f"HSM unavailable, falling back to software for {func.__name__}")
                    return software_fallback(*args, **kwargs)
                raise
        return wrapper
    return decorator


# Global orchestrator instance
_global_pq_orchestrator: Optional[PQCryptoFallbackOrchestrator] = None


def get_pq_orchestrator() -> PQCryptoFallbackOrchestrator:
    """Get the global PQ crypto fallback orchestrator."""
    global _global_pq_orchestrator
    if _global_pq_orchestrator is None:
        _global_pq_orchestrator = PQCryptoFallbackOrchestrator()
    return _global_pq_orchestrator


# Export public API
__all__ = [
    'CryptoOperationType',
    'CryptoSecurityLevel',
    'CryptoFallbackStrategy',
    'CryptoOperationDeadline',
    'CryptoOperationError',
    'CryptoDeadlineExceededError',
    'HSMUnavailableError',
    'CryptoOperationResult',
    'PQCryptoFallbackOrchestrator',
    'with_crypto_deadline',
    'with_hsm_fallback',
    'get_pq_orchestrator',
]
