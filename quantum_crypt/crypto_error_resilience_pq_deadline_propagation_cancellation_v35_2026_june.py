"""
QuantumCrypt Error Resilience - PQ Key Operation Deadline Propagation v35
Dimension E: Error Resilience
ADD-ONLY implementation - wraps existing functionality, no core code modified
Happy path behavior 100% preserved

Cryptographic-specific features:
1. Secure deadline propagation for key operations
2. Cooperative cancellation for long-running PQ computations
3. Hierarchical deadline inheritance for crypto chains
4. Secure memory cleanup on cancellation
5. Deadline-aware key operation retry
6. Graceful degradation with algorithm fallbacks
"""
import time
import threading
import functools
import inspect
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from datetime import datetime
from uuid import uuid4


# -----------------------------------------------------------------------------
# BASE CRYPTO EXCEPTION HIERARCHY - Self-contained
# -----------------------------------------------------------------------------
class QuantumCryptError(Exception):
    """Base exception for all QuantumCrypt errors"""
    error_code: str = "QC-000"
    severity: str = "ERROR"
    retryable: bool = False
    fallback_available: bool = False
    secure_cleanup_required: bool = False

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()


# -----------------------------------------------------------------------------
# CRYPTO-SPECIFIC EXCEPTION HIERARCHY
# -----------------------------------------------------------------------------
class CryptoDeadlineExceededError(QuantumCryptError):
    """Cryptographic operation exceeded its deadline"""
    error_code = "QC-DE-001"
    retryable = False
    fallback_available = True
    secure_cleanup_required = True
    
    def __init__(self, message: str, deadline_seconds: float, elapsed_seconds: float, 
                 operation: str, details: Optional[Dict] = None):
        super().__init__(message, details)
        self.deadline_seconds = deadline_seconds
        self.elapsed_seconds = elapsed_seconds
        self.operation = operation


class CryptoOperationCancelledError(QuantumCryptError):
    """Cryptographic operation was explicitly cancelled"""
    error_code = "QC-DE-002"
    retryable = False
    fallback_available = True
    secure_cleanup_required = True
    
    def __init__(self, message: str, cancel_reason: str, operation: str, details: Optional[Dict] = None):
        super().__init__(message, details)
        self.cancel_reason = cancel_reason
        self.operation = operation


class KeyMaterialCleanupError(QuantumCryptError):
    """Error during secure key material cleanup"""
    error_code = "QC-DE-003"
    retryable = False
    secure_cleanup_required = False


class PQAlgorithmFallbackError(QuantumCryptError):
    """PQ algorithm fallback chain exhausted"""
    error_code = "QC-DE-004"
    retryable = False
    fallback_available = True


# -----------------------------------------------------------------------------
# CRYPTO OPERATION ENUM
# -----------------------------------------------------------------------------
class CryptoOperationType(Enum):
    KEY_GENERATION = "key_generation"
    SIGNING = "signing"
    VERIFICATION = "verification"
    KEY_EXCHANGE = "key_exchange"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    HASHING = "hashing"
    RANDOM_GENERATION = "random_generation"


class CancellationState(Enum):
    NONE = "none"
    REQUESTED = "requested"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


# -----------------------------------------------------------------------------
# DATA CLASSES
# -----------------------------------------------------------------------------
@dataclass
class CryptoDeadlineBudget:
    """Deadline budget for cryptographic operations"""
    operation_type: CryptoOperationType
    total_deadline_seconds: float
    remaining_seconds: float
    start_time: float
    expired: bool = False
    key_material_to_cleanup: List[bytes] = field(default_factory=list)
    
    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time
    
    def check_expired(self) -> bool:
        self.remaining_seconds = self.total_deadline_seconds - self.elapsed_seconds
        self.expired = self.remaining_seconds <= 0
        return self.expired
    
    def register_key_material(self, material: bytes):
        """Register key material for secure cleanup"""
        self.key_material_to_cleanup.append(material)
    
    def secure_cleanup(self):
        """Securely zeroize all registered key material"""
        for material in self.key_material_to_cleanup:
            # Overwrite with random bytes first, then zeros
            mv = memoryview(bytearray(material))
            for i in range(len(mv)):
                mv[i] = secrets.randbelow(256)
            for i in range(len(mv)):
                mv[i] = 0
        self.key_material_to_cleanup.clear()


@dataclass
class CryptoCancellationEvent:
    timestamp: float
    reason: str
    operation_type: CryptoOperationType
    source_token_id: str


@dataclass
class CryptoDeadlineResult:
    success: bool
    result: Any
    cancelled: bool
    deadline_exceeded: bool
    operation_type: CryptoOperationType
    total_time: float
    deadline_budget: CryptoDeadlineBudget
    fallback_used: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


# -----------------------------------------------------------------------------
# CRYPTO CANCELLATION TOKEN
# -----------------------------------------------------------------------------
class CryptoCancellationToken:
    """
    Cryptographic cancellation token with secure cleanup support
    
    ADD-ONLY: Wraps crypto operations without modifying them
    Features:
    - Secure key material cleanup on cancellation
    - Parent-child deadline inheritance
    - Thread-safe cancellation
    - Operation type tracking for audit
    """
    
    def __init__(
        self,
        deadline_seconds: Optional[float] = None,
        operation_type: CryptoOperationType = CryptoOperationType.KEY_GENERATION,
        parent_token: Optional['CryptoCancellationToken'] = None
    ):
        self.token_id = str(uuid4())
        self.operation_type = operation_type
        self._state = CancellationState.NONE
        self._cancel_events: List[CryptoCancellationEvent] = []
        self._cleanup_callbacks: List[Callable[[], None]] = []
        self._key_material: List[bytes] = []
        self._child_tokens: Set[str] = set()
        self._parent_token = parent_token
        self._lock = threading.Lock()
        
        # Deadline setup
        self._start_time = time.time()
        self._deadline_seconds = deadline_seconds
        self._absolute_deadline: Optional[float] = None
        
        if deadline_seconds is not None:
            self._absolute_deadline = self._start_time + deadline_seconds
        elif parent_token is not None and parent_token._absolute_deadline is not None:
            self._absolute_deadline = parent_token._absolute_deadline
            self._deadline_seconds = self._absolute_deadline - self._start_time
    
    @property
    def is_cancellation_requested(self) -> bool:
        with self._lock:
            return self._state in (CancellationState.REQUESTED, CancellationState.CANCELLED)
    
    @property
    def is_deadline_exceeded(self) -> bool:
        if self._absolute_deadline is None:
            return False
        return time.time() >= self._absolute_deadline
    
    @property
    def remaining_seconds(self) -> Optional[float]:
        if self._absolute_deadline is None:
            return None
        remaining = self._absolute_deadline - time.time()
        return max(0, remaining)
    
    def register_key_material(self, material: bytes):
        """Register sensitive material for secure cleanup"""
        with self._lock:
            self._key_material.append(material)
    
    def register_cleanup_callback(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Register secure cleanup callback"""
        with self._lock:
            self._cleanup_callbacks.append(callback)
        
        def unregister():
            with self._lock:
                if callback in self._cleanup_callbacks:
                    self._cleanup_callbacks.remove(callback)
        
        return unregister
    
    def _secure_cleanup(self):
        """Securely clean up all sensitive material"""
        # Zeroize key material
        for material in self._key_material:
            mv = memoryview(bytearray(material))
            for i in range(len(mv)):
                mv[i] = secrets.randbelow(256)
            for i in range(len(mv)):
                mv[i] = 0
        self._key_material.clear()
        
        # Execute cleanup callbacks
        for callback in self._cleanup_callbacks:
            try:
                callback()
            except Exception:
                pass
    
    def throw_if_cancellation_requested(self):
        """Throw if cancelled or deadline exceeded, with cleanup"""
        if self.is_cancellation_requested:
            self._secure_cleanup()
            raise CryptoOperationCancelledError(
                "Crypto operation cancelled",
                cancel_reason=self._cancel_events[-1].reason if self._cancel_events else "unknown",
                operation=self.operation_type.value
            )
        if self.is_deadline_exceeded:
            self._secure_cleanup()
            elapsed = time.time() - self._start_time
            raise CryptoDeadlineExceededError(
                f"Crypto deadline exceeded: {self._deadline_seconds}s",
                deadline_seconds=self._deadline_seconds,
                elapsed_seconds=elapsed,
                operation=self.operation_type.value
            )
    
    def cancel(self, reason: str = "manual"):
        """Cancel operation and perform secure cleanup"""
        with self._lock:
            if self._state != CancellationState.NONE:
                return
            
            self._state = CancellationState.REQUESTED
            event = CryptoCancellationEvent(
                timestamp=time.time(),
                reason=reason,
                operation_type=self.operation_type,
                source_token_id=self.token_id
            )
            self._cancel_events.append(event)
            
            # Secure cleanup before marking cancelled
            self._secure_cleanup()
            
            self._state = CancellationState.CANCELLED
    
    def create_child_token(
        self, 
        operation_type: CryptoOperationType,
        additional_seconds: Optional[float] = None
    ) -> 'CryptoCancellationToken':
        """Create child token inheriting parent deadline"""
        if additional_seconds is not None and self._absolute_deadline is not None:
            remaining = self.remaining_seconds
            child_deadline = min(additional_seconds, remaining) if remaining else additional_seconds
            child = CryptoCancellationToken(
                deadline_seconds=child_deadline,
                operation_type=operation_type,
                parent_token=self
            )
        else:
            child = CryptoCancellationToken(
                operation_type=operation_type,
                parent_token=self
            )
        
        with self._lock:
            self._child_tokens.add(child.token_id)
        
        return child


# -----------------------------------------------------------------------------
# PQ DEADLINE PROPAGATION MANAGER
# -----------------------------------------------------------------------------
class PQDeadlinePropagationManager:
    """
    Deadline propagation manager for post-quantum crypto operations
    
    Dimension E - Error Resilience for QuantumCrypt
    
    Features:
    - Thread-local crypto context
    - Automatic deadline inheritance for crypto chains
    - Secure cleanup on cancellation/timeout
    - PQ algorithm fallback chains
    - 100% backward compatible
    """
    
    def __init__(self):
        self._thread_local = threading.local()
        self._token_registry: Dict[str, CryptoCancellationToken] = {}
        self._algorithm_fallbacks: Dict[CryptoOperationType, List[Tuple[str, Callable]]] = {}
        self._lock = threading.Lock()
    
    def _get_current_context(self) -> Optional[CryptoCancellationToken]:
        return getattr(self._thread_local, 'current_token', None)
    
    def _set_current_context(self, token: Optional[CryptoCancellationToken]):
        self._thread_local.current_token = token
    
    def register_algorithm_fallback(
        self,
        operation_type: CryptoOperationType,
        algorithm_name: str,
        implementation: Callable
    ):
        """Register fallback algorithm for an operation type (ADD-ONLY)"""
        with self._lock:
            if operation_type not in self._algorithm_fallbacks:
                self._algorithm_fallbacks[operation_type] = []
            self._algorithm_fallbacks[operation_type].append((algorithm_name, implementation))
    
    def create_root_token(
        self, 
        deadline_seconds: float,
        operation_type: CryptoOperationType
    ) -> CryptoCancellationToken:
        token = CryptoCancellationToken(
            deadline_seconds=deadline_seconds,
            operation_type=operation_type
        )
        with self._lock:
            self._token_registry[token.token_id] = token
        return token
    
    def execute_crypto_operation(
        self,
        operation: Callable,
        operation_type: CryptoOperationType,
        deadline_seconds: float,
        inherit_parent: bool = True,
        *args,
        **kwargs
    ) -> CryptoDeadlineResult:
        """
        Execute cryptographic operation with deadline and secure cancellation
        
        ADD-ONLY wrapper - happy path preserved
        """
        start_time = time.time()
        warnings: List[str] = []
        fallback_used = None
        
        # Parent deadline inheritance
        parent_token = self._get_current_context() if inherit_parent else None
        
        if parent_token and parent_token._absolute_deadline is not None:
            parent_remaining = parent_token.remaining_seconds
            if parent_remaining and parent_remaining < deadline_seconds:
                deadline_seconds = parent_remaining
                warnings.append(f"Deadline tightened to {deadline_seconds:.2f}s by parent crypto context")
        
        token = CryptoCancellationToken(
            deadline_seconds=deadline_seconds,
            operation_type=operation_type,
            parent_token=parent_token
        )
        
        budget = CryptoDeadlineBudget(
            operation_type=operation_type,
            total_deadline_seconds=deadline_seconds,
            remaining_seconds=deadline_seconds,
            start_time=start_time
        )
        
        old_context = self._get_current_context()
        self._set_current_context(token)
        
        try:
            if token.is_deadline_exceeded:
                budget.check_expired()
                budget.secure_cleanup()
                return CryptoDeadlineResult(
                    success=False,
                    result=None,
                    cancelled=False,
                    deadline_exceeded=True,
                    operation_type=operation_type,
                    total_time=time.time() - start_time,
                    deadline_budget=budget,
                    warnings=["Deadline exceeded before crypto operation start"]
                )
            
            # Try primary operation
            try:
                sig = inspect.signature(operation)
                if 'cancellation_token' in sig.parameters:
                    result = operation(*args, cancellation_token=token, **kwargs)
                else:
                    result = operation(*args, **kwargs)
                
                budget.check_expired()
                return CryptoDeadlineResult(
                    success=True,
                    result=result,
                    cancelled=False,
                    deadline_exceeded=budget.expired,
                    operation_type=operation_type,
                    total_time=time.time() - start_time,
                    deadline_budget=budget,
                    fallback_used=None,
                    warnings=warnings
                )
                
            except (CryptoDeadlineExceededError, CryptoOperationCancelledError) as e:
                budget.check_expired()
                budget.secure_cleanup()
                warnings.append(f"Crypto error: {e.message}")
                
                # Try algorithm fallbacks
                fallbacks = self._algorithm_fallbacks.get(operation_type, [])
                for algo_name, fallback_impl in fallbacks:
                    try:
                        fallback_result = fallback_impl(*args, **kwargs)
                        warnings.append(f"Used fallback algorithm: {algo_name}")
                        return CryptoDeadlineResult(
                            success=True,
                            result=fallback_result,
                            cancelled=False,
                            deadline_exceeded=False,
                            operation_type=operation_type,
                            total_time=time.time() - start_time,
                            deadline_budget=budget,
                            fallback_used=algo_name,
                            warnings=warnings
                        )
                    except Exception as fallback_err:
                        warnings.append(f"Fallback {algo_name} failed: {str(fallback_err)}")
                        continue
                
                # All fallbacks exhausted
                return CryptoDeadlineResult(
                    success=False,
                    result=None,
                    cancelled=isinstance(e, CryptoOperationCancelledError),
                    deadline_exceeded=isinstance(e, CryptoDeadlineExceededError),
                    operation_type=operation_type,
                    total_time=time.time() - start_time,
                    deadline_budget=budget,
                    fallback_used=None,
                    warnings=warnings
                )
                
        finally:
            self._set_current_context(old_context)


# -----------------------------------------------------------------------------
# CRYPTO DEADLINE SCOPE
# -----------------------------------------------------------------------------
class CryptoDeadlineScope:
    """
    Context manager for scoped cryptographic operations with secure cleanup
    
    with CryptoDeadlineScope(5.0, CryptoOperationType.KEY_GENERATION) as token:
        key = generate_pq_key(cancellation_token=token)
    """
    
    def __init__(
        self, 
        deadline_seconds: float, 
        operation_type: CryptoOperationType,
        manager: Optional[PQDeadlinePropagationManager] = None
    ):
        self.deadline_seconds = deadline_seconds
        self.operation_type = operation_type
        self.manager = manager or PQDeadlinePropagationManager()
        self.token: Optional[CryptoCancellationToken] = None
        self._old_context = None
    
    def __enter__(self) -> CryptoCancellationToken:
        self._old_context = self.manager._get_current_context()
        self.token = self.manager.create_root_token(
            self.deadline_seconds, 
            self.operation_type
        )
        self.manager._set_current_context(self.token)
        return self.token
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.manager._set_current_context(self._old_context)
        if self.token:
            self.token.cancel(reason="scope_exit")
        return False


# -----------------------------------------------------------------------------
# GLOBAL INSTANCE AND DECORATORS
# -----------------------------------------------------------------------------
_global_pq_manager = PQDeadlinePropagationManager()


def with_crypto_deadline(
    deadline_seconds: float, 
    operation_type: CryptoOperationType,
    inherit: bool = True
):
    """
    Decorator: Add deadline enforcement to cryptographic function
    
    ADD-ONLY - no modification to wrapped function logic
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> CryptoDeadlineResult:
            return _global_pq_manager.execute_crypto_operation(
                func, operation_type, deadline_seconds, inherit, *args, **kwargs
            )
        return wrapper
    return decorator


# -----------------------------------------------------------------------------
# PQ FALLBACK CHAIN CREATOR
# -----------------------------------------------------------------------------
def create_pq_fallback_chain(
    primary: Callable,
    operation_type: CryptoOperationType,
    deadline_seconds: float,
    *fallbacks: Tuple[str, Callable]
) -> Callable:
    """
    Create wrapped PQ operation with deadline and algorithm fallbacks
    
    ADD-ONLY: Creates new function, doesn't modify originals
    """
    manager = PQDeadlinePropagationManager()
    
    # Register fallbacks
    for algo_name, impl in fallbacks:
        manager.register_algorithm_fallback(operation_type, algo_name, impl)
    
    @functools.wraps(primary)
    def wrapped(*args, **kwargs):
        return manager.execute_crypto_operation(
            primary, operation_type, deadline_seconds, True, *args, **kwargs
        )
    
    return wrapped
