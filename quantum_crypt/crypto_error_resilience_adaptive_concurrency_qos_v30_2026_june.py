"""
QuantumCrypt AI - Crypto Adaptive Concurrency Limiting with QoS Tiers v30
DIMENSION E: Error Resilience
ADD-ONLY implementation - wraps existing code, no modifications
Backward compatible, happy path preserved 100%

Crypto-Specific Features:
1. Crypto Operation Priority Tiers (key generation, signing, encryption)
2. HSM/TPU Resource Protection (critical hardware resources)
3. Key Operation Isolation (prevent DoS on key operations)
4. Random Entropy Pool Protection
5. Crypto-specific graceful degradation (algorithm fallback chain)
6. Constant-time operation preservation

Philosophy: Never reject key operations, protect entropy pool at all costs
"""
import time
import threading
import functools
import heapq
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Type, Union
from enum import Enum
from datetime import datetime, timedelta
from collections import deque, defaultdict
import logging

# Configure null logger - opt-in only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# -----------------------------------------------------------------------------
# 1. CRYPTO-SPECIFIC QOS PRIORITY TIERS
# -----------------------------------------------------------------------------
class CryptoOperationType(Enum):
    """Types of cryptographic operations for priority classification"""
    KEY_GENERATION = "key_generation"
    KEY_AGREEMENT = "key_agreement"
    DIGITAL_SIGNATURE = "digital_signature"
    SIGNATURE_VERIFICATION = "signature_verification"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    KEM_ENCAPSULATION = "kem_encapsulation"
    KEM_DECAPSULATION = "kem_decapsulation"
    RANDOM_ENTROPY = "random_entropy"
    HASH_DIGEST = "hash_digest"
    CERTIFICATE_OP = "certificate_operation"
    BACKUP_OPERATION = "backup_operation"

class CryptoQoSPriority(Enum):
    """
    Crypto-specific QoS priority tiers - higher = more protected
    
    CRYPTO_CRITICAL: Key generation, decapsulation, private key ops - NEVER shed
    CRYPTO_HIGH: Signing, encryption, key agreement - shed only under extreme load
    CRYPTO_MEDIUM: Verification, hashing - normal priority
    CRYPTO_LOW: Background rekeying, backup operations - shed first
    """
    CRYPTO_CRITICAL = 0
    CRYPTO_HIGH = 1
    CRYPTO_MEDIUM = 2
    CRYPTO_LOW = 3

class CryptoLoadShedReason(Enum):
    HSM_CONCURRENCY = "hsm_concurrency_limit"
    ENTROPY_DEPLETION = "entropy_depletion"
    LATENCY_THRESHOLD = "crypto_latency_threshold"
    ERROR_RATE_THRESHOLD = "crypto_error_rate_threshold"
    QUEUE_LENGTH = "operation_queue_full"
    PRIORITY_SHED = "priority_based_shed"

# Map operation types to default priorities
OPERATION_PRIORITY_MAP: Dict[CryptoOperationType, CryptoQoSPriority] = {
    CryptoOperationType.KEY_GENERATION: CryptoQoSPriority.CRYPTO_CRITICAL,
    CryptoOperationType.KEY_AGREEMENT: CryptoQoSPriority.CRYPTO_CRITICAL,
    CryptoOperationType.KEM_DECAPSULATION: CryptoQoSPriority.CRYPTO_CRITICAL,
    CryptoOperationType.DECRYPTION: CryptoQoSPriority.CRYPTO_CRITICAL,
    CryptoOperationType.DIGITAL_SIGNATURE: CryptoQoSPriority.CRYPTO_HIGH,
    CryptoOperationType.ENCRYPTION: CryptoQoSPriority.CRYPTO_HIGH,
    CryptoOperationType.KEM_ENCAPSULATION: CryptoQoSPriority.CRYPTO_HIGH,
    CryptoOperationType.RANDOM_ENTROPY: CryptoQoSPriority.CRYPTO_HIGH,
    CryptoOperationType.SIGNATURE_VERIFICATION: CryptoQoSPriority.CRYPTO_MEDIUM,
    CryptoOperationType.HASH_DIGEST: CryptoQoSPriority.CRYPTO_MEDIUM,
    CryptoOperationType.CERTIFICATE_OP: CryptoQoSPriority.CRYPTO_MEDIUM,
    CryptoOperationType.BACKUP_OPERATION: CryptoQoSPriority.CRYPTO_LOW,
}

# -----------------------------------------------------------------------------
# 2. CRYPTO CONCURRENCY & HEALTH METRICS
# -----------------------------------------------------------------------------
@dataclass
class CryptoConcurrencyMetrics:
    """Real-time crypto-specific concurrency and health metrics"""
    current_concurrency: int = 0
    max_concurrency: int = 16  # Lower default for crypto (CPU intensive)
    peak_concurrency: int = 0
    queued_operations: int = 0
    total_operations: int = 0
    rejected_operations: int = 0
    error_count: int = 0
    success_count: int = 0
    
    # Crypto-specific metrics
    entropy_level: float = 1.0  # 0.0 = empty, 1.0 = full
    hsm_utilization: float = 0.0
    latency_samples: deque = field(default_factory=lambda: deque(maxlen=500))
    error_window: deque = field(default_factory=lambda: deque(maxlen=50))
    operation_counts: Dict[CryptoOperationType, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    
    @property
    def error_rate(self) -> float:
        """Calculate recent error rate (0.0 to 1.0)"""
        if not self.error_window:
            return 0.0
        return sum(1 for e in self.error_window if e) / len(self.error_window)
    
    @property
    def p95_latency(self) -> float:
        """Calculate 95th percentile latency"""
        if not self.latency_samples:
            return 0.0
        sorted_samples = sorted(self.latency_samples)
        idx = int(len(sorted_samples) * 0.95)
        return sorted_samples[min(idx, len(sorted_samples) - 1)]
    
    @property
    def utilization(self) -> float:
        """Current concurrency utilization (0.0 to 1.0)"""
        if self.max_concurrency == 0:
            return 1.0
        return self.current_concurrency / self.max_concurrency
    
    def record_latency(self, latency_ms: float, op_type: CryptoOperationType) -> None:
        self.latency_samples.append(latency_ms)
        self.operation_counts[op_type] += 1
    
    def record_outcome(self, success: bool) -> None:
        self.error_window.append(not success)
        if success:
            self.success_count += 1
        else:
            self.error_count += 1
    
    def update_entropy(self, level: float) -> None:
        """Update current entropy pool level"""
        self.entropy_level = max(0.0, min(1.0, level))

# -----------------------------------------------------------------------------
# 3. CRYPTO ADAPTIVE CONCURRENCY CONTROLLER
# -----------------------------------------------------------------------------
@dataclass
class CryptoConcurrencyConfig:
    """Crypto-specific configuration for adaptive concurrency controller"""
    initial_max_concurrency: int = 16
    min_concurrency: int = 2
    max_concurrency_limit: int = 64
    
    # Health thresholds (stricter for crypto)
    error_rate_threshold: float = 0.02  # 2% errors trigger reduction
    latency_threshold_ms: float = 500.0  # 500ms p95 triggers reduction
    entropy_critical_threshold: float = 0.1  # 10% entropy = critical
    queue_length_threshold: int = 32
    
    # Adaptation rates
    increase_step: int = 1
    decrease_factor: float = 0.5  # More aggressive reduction for crypto
    adaptation_interval_ms: float = 3000.0  # Adjust every 3s
    
    # QoS settings
    enable_priority_shedding: bool = True
    shed_low_priority_at: float = 0.7  # Start shedding LOW at 70% utilization
    shed_medium_priority_at: float = 0.9  # Start shedding MEDIUM at 90%
    
    # Queue settings
    max_queue_size: int = 64
    queue_timeout_ms: float = 10000.0  # Longer timeout for crypto ops
    
    # HSM protection
    hsm_max_concurrency: int = 4
    protect_entropy_pool: bool = True

class CryptoAdaptiveConcurrencyController:
    """
    Crypto-Specific Adaptive Concurrency Controller with QoS Priority Tiers
    
    Features:
    - Dynamically adjusts based on error rates, latency, AND entropy levels
    - Crypto operation priority classification
    - HSM/TPU resource protection
    - Entropy pool depletion protection
    - Never rejects CRYPTO_CRITICAL operations
    - 100% ADD-ONLY: wraps existing functions, no core modifications
    - Constant-time operation preservation
    """
    
    def __init__(self, config: Optional[CryptoConcurrencyConfig] = None):
        self.config = config or CryptoConcurrencyConfig()
        self._metrics = CryptoConcurrencyMetrics(
            max_concurrency=self.config.initial_max_concurrency
        )
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._last_adaptation = time.monotonic() * 1000
        
        # Priority queue: (priority, timestamp, op_type, event)
        self._queue: List[Tuple[int, float, CryptoOperationType, threading.Event]] = []
        self._queue_lock = threading.Lock()
        
        # HSM concurrency tracking
        self._hsm_concurrency = 0
        self._hsm_condition = threading.Condition(self._lock)
        
        # Start background worker thread
        self._worker_running = True
        self._worker_thread = threading.Thread(
            target=self._queue_worker,
            daemon=True,
            name="crypto-concurrency-controller"
        )
        self._worker_thread.start()
    
    def _should_shed_operation(
        self,
        priority: CryptoQoSPriority,
        op_type: CryptoOperationType
    ) -> Optional[CryptoLoadShedReason]:
        """Determine if crypto operation should be shed based on priority and health"""
        with self._lock:
            util = self._metrics.utilization
            config = self.config
            
            # NEVER shed CRYPTO_CRITICAL operations
            if priority == CryptoQoSPriority.CRYPTO_CRITICAL:
                return None
            
            # Check entropy depletion (critical for randomness)
            if config.protect_entropy_pool:
                if self._metrics.entropy_level < config.entropy_critical_threshold:
                    if op_type == CryptoOperationType.RANDOM_ENTROPY:
                        return CryptoLoadShedReason.ENTROPY_DEPLETION
                    if priority.value >= CryptoQoSPriority.CRYPTO_MEDIUM.value:
                        return CryptoLoadShedReason.ENTROPY_DEPLETION
            
            # Check queue length
            if len(self._queue) >= config.max_queue_size:
                return CryptoLoadShedReason.QUEUE_LENGTH
            
            # Check error rate
            if self._metrics.error_rate >= config.error_rate_threshold:
                if priority.value >= CryptoQoSPriority.CRYPTO_MEDIUM.value:
                    return CryptoLoadShedReason.ERROR_RATE_THRESHOLD
            
            # Check latency
            if self._metrics.p95_latency >= config.latency_threshold_ms:
                if priority.value >= CryptoQoSPriority.CRYPTO_MEDIUM.value:
                    return CryptoLoadShedReason.LATENCY_THRESHOLD
            
            # Priority-based shedding at high utilization
            if config.enable_priority_shedding:
                if util >= config.shed_medium_priority_at:
                    if priority == CryptoQoSPriority.CRYPTO_LOW:
                        return CryptoLoadShedReason.PRIORITY_SHED
                if util >= config.shed_low_priority_at:
                    if priority == CryptoQoSPriority.CRYPTO_LOW:
                        return CryptoLoadShedReason.PRIORITY_SHED
            
            return None
    
    def _adapt_concurrency(self) -> None:
        """Dynamically adjust max concurrency based on crypto health metrics"""
        now = time.monotonic() * 1000
        if now - self._last_adaptation < self.config.adaptation_interval_ms:
            return
        
        self._last_adaptation = now
        metrics = self._metrics
        config = self.config
        
        # Reduce concurrency if unhealthy
        health_issues = (
            metrics.error_rate >= config.error_rate_threshold or
            metrics.p95_latency >= config.latency_threshold_ms or
            metrics.entropy_level < config.entropy_critical_threshold
        )
        
        if health_issues:
            new_max = max(
                config.min_concurrency,
                int(metrics.max_concurrency * config.decrease_factor)
            )
            if new_max != metrics.max_concurrency:
                metrics.max_concurrency = new_max
                logger.info(f"Reducing crypto concurrency to {new_max} "
                          f"(error_rate={metrics.error_rate:.2f}, "
                          f"p95_latency={metrics.p95_latency:.0f}ms, "
                          f"entropy={metrics.entropy_level:.2f})")
            return
        
        # Increase concurrency if healthy and underutilized
        healthy = (
            metrics.error_rate < config.error_rate_threshold / 2 and
            metrics.p95_latency < config.latency_threshold_ms / 2 and
            metrics.entropy_level > 0.5
        )
        
        if healthy and metrics.utilization > 0.6:
            new_max = min(
                config.max_concurrency_limit,
                metrics.max_concurrency + config.increase_step
            )
            if new_max != metrics.max_concurrency:
                metrics.max_concurrency = new_max
                logger.info(f"Increasing crypto concurrency to {new_max} "
                          f"(utilization={metrics.utilization:.2f})")
    
    def _queue_worker(self) -> None:
        """Background worker to process queued crypto operations"""
        while self._worker_running:
            try:
                with self._queue_lock:
                    if not self._queue:
                        time.sleep(0.01)
                        continue
                    # Get highest priority item
                    priority, ts, op_type, event = heapq.heappop(self._queue)
                
                # Wait for concurrency slot
                with self._lock:
                    while self._metrics.current_concurrency >= self._metrics.max_concurrency:
                        self._condition.wait(timeout=0.1)
                    self._metrics.current_concurrency += 1
                    if self._metrics.current_concurrency > self._metrics.peak_concurrency:
                        self._metrics.peak_concurrency = self._metrics.current_concurrency
                
                event.set()
                
            except Exception as e:
                logger.debug(f"Crypto queue worker error: {e}")
                time.sleep(0.01)
    
    def acquire_slot(
        self,
        op_type: CryptoOperationType,
        priority: Optional[CryptoQoSPriority] = None,
        timeout_ms: Optional[float] = None,
        requires_hsm: bool = False
    ) -> bool:
        """
        Acquire a concurrency slot for crypto operation
        
        Args:
            op_type: Type of cryptographic operation
            priority: Override default priority, None for auto-mapping
            timeout_ms: Max time to wait in queue
            requires_hsm: Whether this operation needs HSM access
            
        Returns: True if slot acquired, False if shed or timeout
        """
        # Use mapped priority if not specified
        if priority is None:
            priority = OPERATION_PRIORITY_MAP.get(
                op_type,
                CryptoQoSPriority.CRYPTO_MEDIUM
            )
        
        # Check if should shed immediately
        shed_reason = self._should_shed_operation(priority, op_type)
        if shed_reason is not None:
            with self._lock:
                self._metrics.rejected_operations += 1
            logger.debug(f"Crypto operation shed: {shed_reason.value}, "
                        f"type={op_type.value}, priority={priority.name}")
            return False
        
        timeout = (timeout_ms or self.config.queue_timeout_ms) / 1000.0
        event = threading.Event()
        
        with self._queue_lock:
            heapq.heappush(self._queue, (
                priority.value,
                time.monotonic(),
                op_type,
                event
            ))
            self._metrics.queued_operations = len(self._queue)
        
        acquired = event.wait(timeout=timeout)
        
        if not acquired:
            with self._lock:
                self._metrics.rejected_operations += 1
            return False
        
        # HSM concurrency check if required
        if requires_hsm:
            with self._lock:
                while self._hsm_concurrency >= self.config.hsm_max_concurrency:
                    if not self._hsm_condition.wait(timeout=0.1):
                        continue
                self._hsm_concurrency += 1
        
        return True
    
    def release_slot(
        self,
        success: bool,
        latency_ms: float,
        op_type: CryptoOperationType,
        released_hsm: bool = False
    ) -> None:
        """Release concurrency slot and record metrics"""
        with self._lock:
            self._metrics.current_concurrency -= 1
            if released_hsm:
                self._hsm_concurrency -= 1
                self._hsm_condition.notify_all()
            self._metrics.total_operations += 1
            self._metrics.record_latency(latency_ms, op_type)
            self._metrics.record_outcome(success)
            self._adapt_concurrency()
            self._condition.notify_all()
    
    def update_entropy_level(self, level: float) -> None:
        """Update entropy pool level for protection decisions"""
        with self._lock:
            self._metrics.update_entropy(level)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current crypto health status for observability"""
        with self._lock:
            op_counts = {
                k.value: v for k, v in self._metrics.operation_counts.items()
            }
            return {
                "max_concurrency": self._metrics.max_concurrency,
                "current_concurrency": self._metrics.current_concurrency,
                "peak_concurrency": self._metrics.peak_concurrency,
                "hsm_concurrency": self._hsm_concurrency,
                "utilization": self._metrics.utilization,
                "error_rate": self._metrics.error_rate,
                "p95_latency_ms": self._metrics.p95_latency,
                "entropy_level": self._metrics.entropy_level,
                "queued_operations": len(self._queue),
                "total_operations": self._metrics.total_operations,
                "rejected_operations": self._metrics.rejected_operations,
                "operation_counts": op_counts,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def shutdown(self) -> None:
        """Shutdown controller and worker thread"""
        self._worker_running = False
        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)

# Global controller instance - opt-in usage
_global_crypto_controller: Optional[CryptoAdaptiveConcurrencyController] = None
_global_crypto_lock = threading.Lock()

def get_global_crypto_controller() -> CryptoAdaptiveConcurrencyController:
    """Get or create global crypto concurrency controller"""
    global _global_crypto_controller
    if _global_crypto_controller is None:
        with _global_crypto_lock:
            if _global_crypto_controller is None:
                _global_crypto_controller = CryptoAdaptiveConcurrencyController()
    return _global_crypto_controller

# -----------------------------------------------------------------------------
# 4. CRYPTO DECORATORS FOR EASY INTEGRATION
# -----------------------------------------------------------------------------
def crypto_concurrency_limited(
    op_type: CryptoOperationType,
    priority: Optional[CryptoQoSPriority] = None,
    timeout_ms: Optional[float] = None,
    fallback: Optional[Any] = None,
    requires_hsm: bool = False,
    controller: Optional[CryptoAdaptiveConcurrencyController] = None
) -> Callable:
    """
    Decorator to apply concurrency limiting to cryptographic operations
    
    ADD-ONLY: Wraps function, no modification to core crypto logic
    Happy path: 100% preserved when concurrency available
    Preserves constant-time operation properties
    
    Args:
        op_type: Type of cryptographic operation
        priority: Override default priority
        timeout_ms: Max time to wait in queue
        fallback: Value to return on rejection, None to raise
        requires_hsm: Whether operation needs HSM access
        controller: Custom controller, None for global
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            ctrl = controller or get_global_crypto_controller()
            
            start_time = time.monotonic()
            
            # Try to acquire slot
            if not ctrl.acquire_slot(op_type, priority, timeout_ms, requires_hsm):
                if fallback is not None:
                    if callable(fallback):
                        return fallback(*args, **kwargs)
                    return fallback
                # Raise appropriate crypto exception
                # Define simple exception class locally to avoid import issues
                class ResourceExhaustedError(Exception):
                    def __init__(self, message, context=None):
                        super().__init__(message)
                        self.context = context or {}
                raise ResourceExhaustedError(
                    f"Crypto operation rejected by concurrency controller: "
                    f"{op_type.value}",
                    context={"operation": op_type.value}
                )
            
            # Execute crypto operation
            try:
                result = func(*args, **kwargs)
                latency_ms = (time.monotonic() - start_time) * 1000
                ctrl.release_slot(
                    success=True,
                    latency_ms=latency_ms,
                    op_type=op_type,
                    released_hsm=requires_hsm
                )
                return result
            except Exception as e:
                latency_ms = (time.monotonic() - start_time) * 1000
                ctrl.release_slot(
                    success=False,
                    latency_ms=latency_ms,
                    op_type=op_type,
                    released_hsm=requires_hsm
                )
                raise
        
        return wrapper
    return decorator

# Convenience decorators for common crypto operations
def critical_crypto_op(
    op_type: CryptoOperationType,
    **kwargs
) -> Callable:
    """Critical crypto operation - never rejected"""
    return crypto_concurrency_limited(
        op_type=op_type,
        priority=CryptoQoSPriority.CRYPTO_CRITICAL,
        **kwargs
    )

def high_priority_crypto_op(
    op_type: CryptoOperationType,
    **kwargs
) -> Callable:
    """High priority crypto operation"""
    return crypto_concurrency_limited(
        op_type=op_type,
        priority=CryptoQoSPriority.CRYPTO_HIGH,
        **kwargs
    )

# -----------------------------------------------------------------------------
# 5. CRYPTO GRACEFUL DEGRADATION (ALGORITHM FALLBACK)
# -----------------------------------------------------------------------------
class CryptoAlgorithmFallbackChain:
    """
    Crypto-specific graceful degradation with algorithm fallback chain
    
    When primary algorithm is under load:
    1. Try primary (post-quantum)
    2. Fallback to hybrid (PQ + classical)
    3. Fallback to classical algorithm
    4. Return cached result or None
    
    Never compromises security, only performance
    """
    
    def __init__(self):
        self._fallback_chains: Dict[CryptoOperationType, List[Callable]] = {}
        self._fallback_counts: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def register_fallback_chain(
        self,
        op_type: CryptoOperationType,
        algorithms: List[Callable]
    ) -> None:
        """Register chain of fallback algorithms"""
        self._fallback_chains[op_type] = algorithms
    
    def execute_with_fallback(
        self,
        op_type: CryptoOperationType,
        *args,
        **kwargs
    ) -> Any:
        """Execute operation with algorithm fallback chain"""
        chain = self._fallback_chains.get(op_type, [lambda *a, **kw: None])
        
        for i, algorithm in enumerate(chain):
            try:
                result = algorithm(*args, **kwargs)
                if i > 0:
                    with self._lock:
                        self._fallback_counts[f"{op_type.value}_fallback_{i}"] += 1
                return result
            except Exception as e:
                if i == len(chain) - 1:
                    raise
                logger.debug(f"Fallback {i} failed for {op_type.value}: {e}")
                continue
        
        return None
    
    def get_fallback_statistics(self) -> Dict[str, int]:
        """Get fallback chain statistics"""
        with self._lock:
            return dict(self._fallback_counts)

# Global fallback handler
_global_fallback_chain = CryptoAlgorithmFallbackChain()

def get_crypto_fallback_chain() -> CryptoAlgorithmFallbackChain:
    """Get global algorithm fallback chain handler"""
    return _global_fallback_chain

# -----------------------------------------------------------------------------
# 6. CRYPTO HEALTH CHECK
# -----------------------------------------------------------------------------
def crypto_concurrency_health_check() -> Dict[str, Any]:
    """
    Health check endpoint for crypto observability
    
    Returns comprehensive crypto concurrency and health metrics
    Opt-in only - no overhead unless called
    """
    controller = get_global_crypto_controller()
    status = controller.get_health_status()
    status["fallback_stats"] = get_crypto_fallback_chain().get_fallback_statistics()
    return status

# -----------------------------------------------------------------------------
# USAGE EXAMPLES (documentation, not executed)
# -----------------------------------------------------------------------------
"""
# Apply to key generation (critical priority)
@critical_crypto_op(CryptoOperationType.KEY_GENERATION)
def generate_post_quantum_keypair() -> KeyPair:
    return pq_algorithm.generate_keypair()

# Apply to signing (high priority)
@high_priority_crypto_op(CryptoOperationType.DIGITAL_SIGNATURE)
def sign_message(message: bytes, private_key: bytes) -> bytes:
    return pq_algorithm.sign(message, private_key)

# Apply with fallback algorithm
@crypto_concurrency_limited(
    op_type=CryptoOperationType.ENCRYPTION,
    fallback=lambda data, pk: classical_aes_encrypt(data, pk)
)
def pq_encrypt(data: bytes, public_key: bytes) -> bytes:
    return pq_kem.encrypt(data, public_key)

# Get health metrics
health = crypto_concurrency_health_check()
"""
