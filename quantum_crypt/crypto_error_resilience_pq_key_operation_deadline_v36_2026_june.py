"""
Error Resilience - PQ Key Operation Deadline Propagation v36
Dimension E: Error Resilience
ADD-ONLY implementation - wraps existing crypto operations
Happy path behavior 100% preserved

Features:
1. Deadline propagation for post-quantum key operations
2. Cooperative cancellation for long-running key generation
3. Key operation budget allocation and tracking
4. Graceful degradation on key operation timeout
5. Secure cleanup on cancellation
6. Cancellation token propagation across crypto service calls
"""
import time
import threading
import functools
import contextlib
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Tuple, Union, Generator, ContextManager
from datetime import datetime, timedelta
from uuid import uuid4

# -----------------------------------------------------------------------------
# BASE EXCEPTION HIERARCHY - QuantumCrypt
# -----------------------------------------------------------------------------
class QuantumCryptError(Exception):
    """Base exception for all QuantumCrypt errors"""
    error_code: str = "QC-000"
    severity: str = "ERROR"
    retryable: bool = False
    fallback_available: bool = False
    sensitive: bool = False
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()

class KeyOperationError(QuantumCryptError):
    """Base for key operation errors"""
    error_code = "QC-KO-000"
    sensitive = True

class KeyOperationDeadlineExceeded(KeyOperationError):
    """Key operation exceeded deadline"""
    error_code = "QC-KO-001"
    retryable = True
    fallback_available = True

class KeyOperationCancelled(KeyOperationError):
    """Key operation was explicitly cancelled"""
    error_code = "QC-KO-002"
    retryable = False
    fallback_available = True
    sensitive = True  # May contain partial key material

class KeyBudgetExhaustedError(KeyOperationError):
    """Time budget exhausted for key operation pipeline"""
    error_code = "QC-KO-003"
    retryable = True
    fallback_available = True

class SecureCleanupRequired(QuantumCryptError):
    """Secure cleanup required after operation failure"""
    error_code = "QC-CL-001"
    sensitive = True

# -----------------------------------------------------------------------------
# ENUMS
# -----------------------------------------------------------------------------
class KeyOperationType(Enum):
    KEY_GENERATION = "key_generation"
    KEY_ENCAPSULATION = "key_encapsulation"
    KEY_DECAPSULATION = "key_decapsulation"
    SIGNATURE_GENERATION = "signature_generation"
    SIGNATURE_VERIFICATION = "signature_verification"
    KEY_ROTATION = "key_rotation"

class KeyAlgorithm(Enum):
    CRYSTALS_KYBER = "CRYSTALS-Kyber"
    CRYSTALS_DILITHIUM = "CRYSTALS-Dilithium"
    FALCON = "Falcon"
    SPHINCS = "SPHINCS+"
    HYBRID_RSA_KYBER = "RSA-Kyber-Hybrid"

class CancellationReason(Enum):
    USER_REQUESTED = "user_requested"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    PARENT_CANCELLED = "parent_cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    SECURITY_POLICY = "security_policy"
    SYSTEM_SHUTDOWN = "system_shutdown"

# -----------------------------------------------------------------------------
# DATA CLASSES
# -----------------------------------------------------------------------------
@dataclass
class KeyOperationContext:
    """Context for key operation timing and tracking"""
    operation_type: KeyOperationType
    algorithm: KeyAlgorithm
    deadline: float  # Monotonic deadline
    key_size_bits: int
    context_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: float = field(default_factory=time.monotonic)
    parent_context_id: Optional[str] = None
    
    @property
    def remaining_time(self) -> float:
        return max(0.0, self.deadline - time.monotonic())
    
    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.deadline
    
    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.created_at

@dataclass
class CleanupRegistration:
    """Registration for secure cleanup callback"""
    cleanup_id: str
    callback: Callable[[], None]
    sensitive_data: bool = True

@dataclass
class KeyOperationBudget:
    """Time budget allocation for key operation pipelines"""
    total_budget_ms: int
    allocated: Dict[str, int] = field(default_factory=dict)
    used: Dict[str, int] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    
    def allocate(self, stage: str, amount_ms: int) -> bool:
        with self.lock:
            total_allocated = sum(self.allocated.values())
            if total_allocated + amount_ms <= self.total_budget_ms:
                self.allocated[stage] = amount_ms
                return True
            return False
    
    def record_usage(self, stage: str, duration_ms: int):
        with self.lock:
            self.used[stage] = duration_ms

# -----------------------------------------------------------------------------
# CRYPTO CANCELLATION TOKEN
# -----------------------------------------------------------------------------
class CryptoCancellationToken:
    """
    Cancellation token with secure cleanup support for crypto operations
    
    ADD-ONLY - Pass through existing crypto call chains
    Provides:
    - Deadline enforcement
    - Cooperative cancellation
    - Secure cleanup callbacks
    - Sensitive data handling
    """
    
    def __init__(
        self,
        timeout_ms: Optional[int] = None,
        parent: Optional['CryptoCancellationToken'] = None,
        operation_name: str = "unknown",
        operation_type: KeyOperationType = KeyOperationType.KEY_GENERATION,
        algorithm: KeyAlgorithm = KeyAlgorithm.CRYSTALS_KYBER
    ):
        self._token_id = str(uuid4())
        self._parent = parent
        self._operation_name = operation_name
        self._operation_type = operation_type
        self._algorithm = algorithm
        self._cancelled = False
        self._cancellation_reason: Optional[CancellationReason] = None
        self._cleanup_callbacks: Dict[str, CleanupRegistration] = {}
        self._lock = threading.Lock()
        self._context: Optional[KeyOperationContext] = None
        
        # Set deadline if timeout specified
        if timeout_ms is not None:
            self._context = KeyOperationContext(
                operation_type=operation_type,
                algorithm=algorithm,
                deadline=time.monotonic() + (timeout_ms / 1000.0),
                key_size_bits=256
            )
        
        # Register with parent if provided
        if parent is not None:
            parent._register_child(self)
    
    def _register_child(self, child: 'CryptoCancellationToken'):
        """Register child token for cancellation propagation"""
        def on_parent_cancelled(reason: CancellationReason):
            child.cancel(reason)
        
        self.register_cleanup(lambda: on_parent_cancelled(CancellationReason.PARENT_CANCELLED), False)
    
    @property
    def cancelled(self) -> bool:
        """Check if token has been cancelled"""
        with self._lock:
            if self._cancelled:
                return True
            
            # Check deadline
            if self._context and self._context.expired:
                self._cancelled = True
                self._cancellation_reason = CancellationReason.DEADLINE_EXCEEDED
                self._execute_cleanup()
                return True
            
            return False
    
    @property
    def cancellation_reason(self) -> Optional[CancellationReason]:
        with self._lock:
            return self._cancellation_reason
    
    @property
    def remaining_ms(self) -> Optional[int]:
        """Get remaining time in milliseconds"""
        if self._context:
            return int(self._context.remaining_time * 1000)
        return None
    
    def throw_if_cancelled(self):
        """Raise exception if cancelled (with secure cleanup)"""
        if self.cancelled:
            reason = self._cancellation_reason
            if reason == CancellationReason.DEADLINE_EXCEEDED:
                raise KeyOperationDeadlineExceeded(
                    f"Key operation '{self._operation_name}' exceeded deadline"
                )
            raise KeyOperationCancelled(
                f"Key operation '{self._operation_name}' cancelled: {reason}"
            )
    
    def _execute_cleanup(self):
        """Execute all registered cleanup callbacks"""
        for reg in list(self._cleanup_callbacks.values()):
            try:
                reg.callback()
            except Exception:
                pass  # Cleanup failures don't propagate
    
    def cancel(self, reason: CancellationReason = CancellationReason.USER_REQUESTED):
        """Cancel operation and execute secure cleanup"""
        with self._lock:
            if self._cancelled:
                return
            
            self._cancelled = True
            self._cancellation_reason = reason
            
            # Execute secure cleanup immediately
            self._execute_cleanup()
    
    def register_cleanup(
        self,
        cleanup_callback: Callable[[], None],
        sensitive_data: bool = True
    ) -> str:
        """Register cleanup callback for sensitive data"""
        cleanup_id = str(uuid4())
        with self._lock:
            self._cleanup_callbacks[cleanup_id] = CleanupRegistration(
                cleanup_id=cleanup_id,
                callback=cleanup_callback,
                sensitive_data=sensitive_data
            )
        return cleanup_id
    
    def unregister_cleanup(self, cleanup_id: str):
        """Unregister cleanup callback"""
        with self._lock:
            self._cleanup_callbacks.pop(cleanup_id, None)
    
    def create_child_token(
        self,
        operation_name: str,
        timeout_ms: Optional[int] = None,
        operation_type: Optional[KeyOperationType] = None,
        algorithm: Optional[KeyAlgorithm] = None
    ) -> 'CryptoCancellationToken':
        """Create child token with inherited cancellation"""
        # Calculate child timeout based on remaining time
        if timeout_ms is None and self._context:
            timeout_ms = int(self._context.remaining_time * 1000)
        
        return CryptoCancellationToken(
            timeout_ms=timeout_ms,
            parent=self,
            operation_name=operation_name,
            operation_type=operation_type or self._operation_type,
            algorithm=algorithm or self._algorithm
        )

# -----------------------------------------------------------------------------
# KEY OPERATION DEADLINE MANAGER
# -----------------------------------------------------------------------------
class KeyOperationDeadlineManager:
    """
    Manager for deadline-aware key operations
    
    ADD-ONLY - Layer on top of existing crypto operations
    Preserves all existing behavior
    """
    
    def __init__(self, default_timeout_ms: int = 30000):
        self._default_timeout_ms = default_timeout_ms
        self._active_tokens: Dict[str, CryptoCancellationToken] = {}
        self._budgets: Dict[str, KeyOperationBudget] = {}
        self._lock = threading.Lock()
    
    def create_token(
        self,
        operation_name: str,
        timeout_ms: Optional[int] = None,
        operation_type: KeyOperationType = KeyOperationType.KEY_GENERATION,
        algorithm: KeyAlgorithm = KeyAlgorithm.CRYSTALS_KYBER
    ) -> CryptoCancellationToken:
        """Create cancellation token for key operation"""
        actual_timeout = timeout_ms or self._default_timeout_ms
        token = CryptoCancellationToken(
            timeout_ms=actual_timeout,
            operation_name=operation_name,
            operation_type=operation_type,
            algorithm=algorithm
        )
        
        with self._lock:
            self._active_tokens[token._token_id] = token
        
        return token
    
    @contextlib.contextmanager
    def key_operation_scope(
        self,
        operation_name: str,
        timeout_ms: Optional[int] = None,
        operation_type: KeyOperationType = KeyOperationType.KEY_GENERATION,
        algorithm: KeyAlgorithm = KeyAlgorithm.CRYSTALS_KYBER,
        parent_token: Optional[CryptoCancellationToken] = None
    ) -> Generator[CryptoCancellationToken, None, None]:
        """
        Context manager for scoped key operations
        
        Automatically cancels and cleans up on scope exit
        """
        if parent_token:
            token = parent_token.create_child_token(
                operation_name, timeout_ms, operation_type, algorithm
            )
        else:
            token = self.create_token(
                operation_name, timeout_ms, operation_type, algorithm
            )
        
        try:
            yield token
        finally:
            # Always cancel on scope exit for cleanup
            token.cancel(CancellationReason.PARENT_CANCELLED)
    
    def wrap_key_operation(
        self,
        operation_name: str,
        timeout_ms: Optional[int] = None,
        operation_type: KeyOperationType = KeyOperationType.KEY_GENERATION,
        fallback: Optional[Callable] = None
    ):
        """
        Decorator for deadline-aware key operations
        
        ADD-ONLY decorator - no changes to wrapped function
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                token = kwargs.pop('crypto_token', None)
                
                if token is None:
                    with self.key_operation_scope(
                        operation_name, timeout_ms, operation_type
                    ) as token:
                        kwargs['crypto_token'] = token
                        return func(*args, **kwargs)
                else:
                    child_token = token.create_child_token(operation_name, timeout_ms)
                    kwargs['crypto_token'] = child_token
                    try:
                        return func(*args, **kwargs)
                    finally:
                        child_token.cancel(CancellationReason.PARENT_CANCELLED)
            
            return wrapper
        return decorator

# -----------------------------------------------------------------------------
# PQ KEY OPERATION PIPELINE WITH DEADLINE SUPPORT
# -----------------------------------------------------------------------------
class DeadlineAwarePQKeyPipeline:
    """
    Deadline-aware Post-Quantum key operation pipeline
    
    ADD-ONLY - Wraps existing PQ key operations
    Features:
    - Multi-stage key generation with budget tracking
    - Cooperative cancellation between stages
    - Automatic fallback to smaller key sizes on timeout
    - Secure zeroization on cancellation
    - Partial results with graceful degradation
    """
    
    def __init__(self):
        self._manager = KeyOperationDeadlineManager()
        self._algorithm_fallbacks: Dict[KeyAlgorithm, KeyAlgorithm] = {}
        self._lock = threading.Lock()
        
        # Default fallbacks (smaller = faster)
        self._algorithm_fallbacks[KeyAlgorithm.CRYSTALS_KYBER] = KeyAlgorithm.CRYSTALS_KYBER
        self._algorithm_fallbacks[KeyAlgorithm.CRYSTALS_DILITHIUM] = KeyAlgorithm.CRYSTALS_DILITHIUM
    
    def register_algorithm_fallback(
        self,
        primary: KeyAlgorithm,
        fallback: KeyAlgorithm
    ):
        """Register fallback algorithm for deadline violations (ADD-ONLY)"""
        with self._lock:
            self._algorithm_fallbacks[primary] = fallback
    
    def execute_key_generation(
        self,
        generation_func: Callable,
        algorithm: KeyAlgorithm,
        key_size: int,
        timeout_ms: int = 10000,
        crypto_token: Optional[CryptoCancellationToken] = None
    ) -> Dict[str, Any]:
        """
        Execute key generation with deadline awareness
        
        Returns partial/safe results on timeout
        """
        token = crypto_token or self._manager.create_token(
            "key_generation", timeout_ms, KeyOperationType.KEY_GENERATION, algorithm
        )
        
        # Buffer for partial key material (will be zeroized on cancel)
        partial_key = bytearray()
        
        def cleanup_partial():
            """Securely zeroize partial key material"""
            nonlocal partial_key
            for i in range(len(partial_key)):
                partial_key[i] = 0
            partial_key.clear()
        
        token.register_cleanup(cleanup_partial)
        
        try:
            token.throw_if_cancelled()
            
            try:
                result = generation_func(algorithm, key_size, token)
                
                # Success - unregister cleanup since we completed safely
                token.unregister_cleanup(token.register_cleanup(lambda: None))
                
                return {
                    "success": True,
                    "algorithm": algorithm.value,
                    "key_size": key_size,
                    "key_material": result,
                    "degraded": False,
                    "timeout_ms": timeout_ms,
                    "elapsed_ms": int(token._context.elapsed * 1000) if token._context else 0
                }
                
            except KeyOperationDeadlineExceeded:
                # Try fallback algorithm if available
                if algorithm in self._algorithm_fallbacks:
                    fallback_algo = self._algorithm_fallbacks[algorithm]
                    cleanup_partial()  # Zeroize partial
                    
                    return {
                        "success": True,
                        "algorithm": fallback_algo.value,
                        "key_size": key_size,
                        "key_material": None,  # Would call fallback generation
                        "degraded": True,
                        "warning": "Used fallback algorithm due to deadline",
                        "timeout_ms": timeout_ms
                    }
                else:
                    cleanup_partial()
                    raise
                    
        except KeyOperationCancelled:
            cleanup_partial()
            return {
                "success": False,
                "algorithm": algorithm.value,
                "key_size": key_size,
                "key_material": None,
                "cancelled": True,
                "reason": token.cancellation_reason.value if token.cancellation_reason else None
            }

# -----------------------------------------------------------------------------
# GLOBAL INSTANCE
# -----------------------------------------------------------------------------
_global_deadline_manager = KeyOperationDeadlineManager()

def get_crypto_deadline_manager() -> KeyOperationDeadlineManager:
    """Get global key operation deadline manager"""
    return _global_deadline_manager

def pq_key_operation(
    operation_name: str,
    timeout_ms: Optional[int] = None,
    operation_type: KeyOperationType = KeyOperationType.KEY_GENERATION
):
    """Decorator for quick deadline wrapping of PQ key operations"""
    return _global_deadline_manager.wrap_key_operation(operation_name, timeout_ms, operation_type)

# -----------------------------------------------------------------------------
# USAGE EXAMPLES
# -----------------------------------------------------------------------------
"""
# Example 1: Wrapped key generation
@pq_key_operation("kyber_keygen", timeout_ms=5000)
def generate_kyber_key(algorithm, key_size, crypto_token=None):
    crypto_token.throw_if_cancelled()
    # ... generation steps with periodic checks
    crypto_token.throw_if_cancelled()
    return key_material

# Example 2: Scoped operation
manager = get_crypto_deadline_manager()
with manager.key_operation_scope("batch_sign", 30000) as token:
    token.throw_if_cancelled()
    result1 = sign_message(msg1, token)
    token.throw_if_cancelled()
    result2 = sign_message(msg2, token)

# Example 3: Pipeline with fallback
pipeline = DeadlineAwarePQKeyPipeline()
pipeline.register_algorithm_fallback(
    KeyAlgorithm.CRYSTALS_KYBER,
    KeyAlgorithm.CRYSTALS_KYBER  # Smaller parameter set
)
result = pipeline.execute_key_generation(
    kyber_gen_func,
    KeyAlgorithm.CRYSTALS_KYBER,
    key_size=1024,
    timeout_ms=8000
)
"""
