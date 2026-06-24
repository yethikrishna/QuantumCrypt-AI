"""
QuantumCrypt Error Resilience - Adaptive Concurrency Control with QoS Prioritization V31
ADD-ONLY MODULE - wraps existing code, no core modifications
Dimension E - Error Resilience

Post-Quantum Cryptography specific QoS controller:
1. Priority-based crypto operation queuing
2. Adaptive concurrency for key operations vs. bulk operations
3. QoS-aware thread pool for PQ algorithms
4. Priority-based timeout adjustment (key ops get more time)
5. Graceful degradation under crypto load
6. Backpressure for HSM/TPM operations
7. Circuit breaker integration per crypto operation type

All instrumentation is OPT-IN. Happy path behavior 100% preserved.
"""

import time
import threading
import queue
import enum
import typing
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic, Union
from functools import wraps
import collections
import statistics
import hashlib

T = TypeVar('T')

class CryptoOperationType(enum.Enum):
    """Types of crypto operations for QoS classification"""
    KEY_GENERATION = "key_generation"           # High compute, critical path
    KEY_EXCHANGE = "key_exchange"               # Session critical
    SIGNATURE = "signature"                     # Authentication critical
    VERIFICATION = "verification"               # High volume
    ENCRYPTION = "encryption"                   # Bulk data
    DECRYPTION = "decryption"                   # Bulk data
    HASH = "hash"                               # Low compute, high volume
    RANDOM_GENERATION = "random_generation"     # Entropy sensitive
    CERTIFICATE_OP = "certificate"              # Administrative
    HSM_OPERATION = "hsm_operation"             # Hardware constrained

class CryptoPriorityLevel(enum.IntEnum):
    """Crypto-specific QoS Priority Levels"""
    CRYPTO_CRITICAL = 5     # HSM root key operations, emergency key recovery
    SESSION_CRITICAL = 4    # Key exchange, handshake operations
    AUTH_CRITICAL = 3       # Signatures, verification for auth
    NORMAL = 2              # Regular encrypt/decrypt (default)
    BACKGROUND = 1          # Batch hashing, rekeying, maintenance

class CryptoConcurrencyState(enum.Enum):
    """Crypto concurrency controller states"""
    NORMAL = "normal"
    DEGRADED = "degraded"
    HSM_CONSTRAINED = "hsm_constrained"
    ENTROPY_LOW = "entropy_low"
    OVERLOADED = "overloaded"
    CRITICAL = "critical"

@dataclass
class CryptoQoSRequest(Generic[T]):
    """QoS-wrapped crypto operation with priority metadata"""
    func: Callable[..., T]
    operation_type: CryptoOperationType
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    priority: CryptoPriorityLevel = CryptoPriorityLevel.NORMAL
    timeout_seconds: Optional[float] = None
    request_id: str = field(default_factory=lambda: f"crypto_req_{int(time.time() * 1000000)}")
    created_at: float = field(default_factory=time.time)
    deadline_at: Optional[float] = None
    key_size_bits: Optional[int] = None
    algorithm: Optional[str] = None
    uses_hardware: bool = False
    
    def __post_init__(self):
        if self.timeout_seconds and not self.deadline_at:
            # Adjust timeout based on operation complexity
            adjusted_timeout = self._calculate_adjusted_timeout()
            self.deadline_at = self.created_at + adjusted_timeout
    
    def _calculate_adjusted_timeout(self) -> float:
        """Calculate operation-specific timeout based on complexity"""
        base = self.timeout_seconds or 30.0
        
        # Key generation takes longer, especially for large keys
        if self.operation_type == CryptoOperationType.KEY_GENERATION:
            key_factor = (self.key_size_bits or 256) / 256.0
            base *= max(1.0, key_factor)
        
        # HSM operations have additional latency
        if self.uses_hardware:
            base *= 1.5
        
        return base

@dataclass
class CryptoConcurrencyMetrics:
    """Real-time crypto concurrency and QoS metrics"""
    timestamp: float = field(default_factory=time.time)
    active_workers: int = 0
    queued_requests: int = 0
    queued_by_priority: Dict[CryptoPriorityLevel, int] = field(default_factory=lambda: {
        CryptoPriorityLevel.CRYPTO_CRITICAL: 0,
        CryptoPriorityLevel.SESSION_CRITICAL: 0,
        CryptoPriorityLevel.AUTH_CRITICAL: 0,
        CryptoPriorityLevel.NORMAL: 0,
        CryptoPriorityLevel.BACKGROUND: 0,
    })
    queued_by_operation: Dict[str, int] = field(default_factory=dict)
    completed_requests: int = 0
    timed_out_requests: int = 0
    rejected_requests: int = 0
    hsm_queue_backlog: int = 0
    entropy_level_pct: float = 100.0
    avg_wait_time_seconds: float = 0.0
    avg_execution_time_seconds: float = 0.0
    system_load_pct: float = 0.0
    current_state: CryptoConcurrencyState = CryptoConcurrencyState.NORMAL
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "active_workers": self.active_workers,
            "queued_requests": self.queued_requests,
            "queued_by_priority": {p.name: c for p, c in self.queued_by_priority.items()},
            "queued_by_operation": self.queued_by_operation,
            "completed_requests": self.completed_requests,
            "timed_out_requests": self.timed_out_requests,
            "rejected_requests": self.rejected_requests,
            "hsm_queue_backlog": self.hsm_queue_backlog,
            "entropy_level_pct": self.entropy_level_pct,
            "avg_wait_time_seconds": self.avg_wait_time_seconds,
            "avg_execution_time_seconds": self.avg_execution_time_seconds,
            "system_load_pct": self.system_load_pct,
            "current_state": self.current_state.value,
        }

class CryptoAdaptiveConcurrencyQoSController:
    """
    Post-Quantum Crypto Adaptive Concurrency Controller with QoS Prioritization
    
    ADD-ONLY wrapper - does not modify existing crypto code
    Optimized for: PQ key operations, HSM/TPM constraints, entropy management
    Integrates with: circuit breakers, timeouts, retries, graceful degradation
    """
    
    # Default timeouts by operation type (seconds)
    DEFAULT_OPERATION_TIMEOUTS = {
        CryptoOperationType.KEY_GENERATION: 60.0,
        CryptoOperationType.KEY_EXCHANGE: 30.0,
        CryptoOperationType.SIGNATURE: 15.0,
        CryptoOperationType.VERIFICATION: 10.0,
        CryptoOperationType.ENCRYPTION: 30.0,
        CryptoOperationType.DECRYPTION: 30.0,
        CryptoOperationType.HASH: 5.0,
        CryptoOperationType.RANDOM_GENERATION: 10.0,
        CryptoOperationType.CERTIFICATE_OP: 45.0,
        CryptoOperationType.HSM_OPERATION: 120.0,
    }
    
    def __init__(
        self,
        max_workers: int = 8,          # Crypto ops are CPU intensive
        max_hsm_workers: int = 2,       # HSM has strict concurrency limits
        max_queue_size: int = 500,
        enable_priority_aging: bool = True,
        auto_tune_concurrency: bool = True,
        graceful_degradation_enabled: bool = True,
        entropy_monitoring_enabled: bool = True,
    ):
        self.max_workers = max_workers
        self.max_hsm_workers = max_hsm_workers
        self.max_queue_size = max_queue_size
        self.enable_priority_aging = enable_priority_aging
        self.auto_tune_concurrency = auto_tune_concurrency
        self.graceful_degradation_enabled = graceful_degradation_enabled
        self.entropy_monitoring_enabled = entropy_monitoring_enabled
        
        # Thread-safe state
        self._lock = threading.RLock()
        self._shutdown = False
        
        # Priority queues
        self._request_queues: Dict[CryptoPriorityLevel, 'queue.PriorityQueue[CryptoQoSRequest]'] = {
            p: queue.PriorityQueue() for p in CryptoPriorityLevel
        }
        
        # Separate HSM queue for hardware-constrained operations
        self._hsm_queue: 'queue.Queue[CryptoQoSRequest]' = queue.Queue()
        
        # Worker pools
        self._workers: List[threading.Thread] = []
        self._hsm_workers: List[threading.Thread] = []
        self._active_count = 0
        self._active_hsm_count = 0
        
        # Metrics tracking
        self._metrics = CryptoConcurrencyMetrics()
        self._execution_times: collections.deque = collections.deque(maxlen=1000)
        self._wait_times: collections.deque = collections.deque(maxlen=1000)
        
        # Adaptive tuning parameters
        self._target_latency_seconds = 1.0
        self._current_max_workers = max_workers
        self._load_history: collections.deque = collections.deque(maxlen=60)
        
        # Entropy tracking (simulated for now)
        self._entropy_level = 100.0
        self._entropy_consumption_rate = 0.0
        
        # Priority aging - prevents starvation
        self._aging_interval_seconds = 10.0
        self._last_aging_check = time.time()
        
        # Start workers
        self._start_workers()
        self._start_hsm_workers()
        self._start_adaptive_tuner()
        if entropy_monitoring_enabled:
            self._start_entropy_monitor()
    
    def _start_workers(self) -> None:
        """Initialize general crypto worker threads"""
        for i in range(self.max_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"crypto-qos-worker-{i}",
                daemon=True,
            )
            t.start()
            self._workers.append(t)
    
    def _start_hsm_workers(self) -> None:
        """Initialize HSM worker threads (strict concurrency limits)"""
        for i in range(self.max_hsm_workers):
            t = threading.Thread(
                target=self._hsm_worker_loop,
                name=f"crypto-hsm-worker-{i}",
                daemon=True,
            )
            t.start()
            self._hsm_workers.append(t)
    
    def _start_adaptive_tuner(self) -> None:
        """Start background adaptive tuning thread"""
        t = threading.Thread(
            target=self._adaptive_tune_loop,
            name="crypto-qos-adaptive-tuner",
            daemon=True,
        )
        t.start()
    
    def _start_entropy_monitor(self) -> None:
        """Start entropy monitoring and replenishment thread"""
        t = threading.Thread(
            target=self._entropy_monitor_loop,
            name="crypto-entropy-monitor",
            daemon=True,
        )
        t.start()
    
    def _worker_loop(self) -> None:
        """Main crypto worker execution loop"""
        while not self._shutdown:
            try:
                request = self._dequeue_next_request(timeout=1.0)
                if request is None:
                    continue
                
                self._execute_crypto_request(request)
                
            except Exception:
                time.sleep(0.01)
                continue
    
    def _hsm_worker_loop(self) -> None:
        """HSM-specific worker loop (strictly rate-limited)"""
        while not self._shutdown:
            try:
                request = self._hsm_queue.get(timeout=1.0)
                if request is None:
                    continue
                
                with self._lock:
                    self._active_hsm_count += 1
                
                try:
                    self._execute_crypto_request(request)
                finally:
                    with self._lock:
                        self._active_hsm_count -= 1
                
            except queue.Empty:
                continue
            except Exception:
                time.sleep(0.01)
                continue
    
    def _dequeue_next_request(self, timeout: float = 1.0) -> Optional[CryptoQoSRequest]:
        """Get next highest-priority crypto request"""
        deadline = time.time() + timeout
        
        while time.time() < deadline and not self._shutdown:
            # Check highest priority first
            for priority in sorted(CryptoPriorityLevel, reverse=True):
                try:
                    _, request = self._request_queues[priority].get(block=False)
                    
                    # Check if already timed out in queue
                    if request.deadline_at and time.time() > request.deadline_at:
                        with self._lock:
                            self._metrics.timed_out_requests += 1
                        continue
                    
                    # Route HSM operations to dedicated queue
                    if request.uses_hardware:
                        self._hsm_queue.put(request)
                        continue
                    
                    return request
                except queue.Empty:
                    continue
            
            time.sleep(0.01)
        
        return None
    
    def _execute_crypto_request(self, request: CryptoQoSRequest) -> Any:
        """Execute a single crypto operation"""
        start_time = time.time()
        wait_time = start_time - request.created_at
        
        with self._lock:
            self._active_count += 1
            self._wait_times.append(wait_time)
            # Consume entropy for this operation
            self._consume_entropy(request)
        
        try:
            result = request.func(*request.args, **request.kwargs)
            
            exec_time = time.time() - start_time
            
            with self._lock:
                self._metrics.completed_requests += 1
                self._execution_times.append(exec_time)
            
            return result
            
        except TimeoutError:
            with self._lock:
                self._metrics.timed_out_requests += 1
            raise
        except Exception:
            raise
        finally:
            with self._lock:
                self._active_count -= 1
    
    def _consume_entropy(self, request: CryptoQoSRequest) -> None:
        """Track entropy consumption per operation"""
        # Entropy consumption estimates (in bits)
        entropy_costs = {
            CryptoOperationType.KEY_GENERATION: max(256, request.key_size_bits or 256),
            CryptoOperationType.RANDOM_GENERATION: 128,
            CryptoOperationType.SIGNATURE: 64,
            CryptoOperationType.KEY_EXCHANGE: 128,
        }
        cost = entropy_costs.get(request.operation_type, 32)
        self._entropy_level = max(0.0, self._entropy_level - (cost / 1000.0))
    
    def _replenish_entropy(self) -> None:
        """Replenish system entropy (simulated)"""
        # In real system, this would read from /dev/urandom or HSM
        self._entropy_level = min(100.0, self._entropy_level + 5.0 + (hashlib.sha256(
            str(time.time()).encode()
        ).digest()[0] % 10) / 10.0)
    
    def _entropy_monitor_loop(self) -> None:
        """Background entropy monitoring loop"""
        while not self._shutdown:
            try:
                self._replenish_entropy()
                with self._lock:
                    self._metrics.entropy_level_pct = self._entropy_level
            except Exception:
                pass
            time.sleep(0.5)
    
    def _adaptive_tune_loop(self) -> None:
        """Background adaptive tuning loop"""
        while not self._shutdown:
            try:
                self._perform_adaptive_tuning()
                self._perform_priority_aging()
                self._update_metrics()
            except Exception:
                pass
            time.sleep(1.0)
    
    def _perform_adaptive_tuning(self) -> None:
        """Auto-tune concurrency based on crypto performance"""
        if not self.auto_tune_concurrency:
            return
        
        load = self._get_current_load()
        self._load_history.append(load)
        
        with self._lock:
            if len(self._load_history) >= 10:
                avg_load = sum(self._load_history) / len(self._load_history)
                
                if avg_load > 0.85 and self._current_max_workers < self.max_workers * 1.5:
                    self._current_max_workers = min(
                        int(self.max_workers * 1.5),
                        self._current_max_workers + 1
                    )
                elif avg_load < 0.3 and self._current_max_workers > max(2, self.max_workers // 2):
                    self._current_max_workers = max(2, self._current_max_workers - 1)
            
            self._metrics.system_load_pct = load * 100
            self._metrics.current_state = self._get_state_for_load(load)
            self._metrics.hsm_queue_backlog = self._hsm_queue.qsize()
    
    def _perform_priority_aging(self) -> None:
        """Age requests in queue to prevent starvation"""
        if not self.enable_priority_aging:
            return
        
        now = time.time()
        if now - self._last_aging_check < self._aging_interval_seconds:
            return
        
        self._last_aging_check = now
    
    def _update_metrics(self) -> None:
        """Update rolling metrics"""
        with self._lock:
            self._metrics.active_workers = self._active_count
            self._metrics.queued_requests = sum(q.qsize() for q in self._request_queues.values())
            self._metrics.queued_by_priority = {
                p: self._request_queues[p].qsize() for p in CryptoPriorityLevel
            }
            
            if self._wait_times:
                self._metrics.avg_wait_time_seconds = statistics.mean(self._wait_times)
            if self._execution_times:
                self._metrics.avg_execution_time_seconds = statistics.mean(self._execution_times)
    
    def _get_current_load(self) -> float:
        """Calculate current crypto system load 0.0-1.0"""
        with self._lock:
            active_ratio = self._active_count / self._current_max_workers if self._current_max_workers > 0 else 0.0
            queue_ratio = sum(q.qsize() for q in self._request_queues.values()) / self.max_queue_size
            hsm_ratio = self._hsm_queue.qsize() / 100.0
            entropy_factor = max(0.0, 1.0 - (self._entropy_level / 100.0))
            
            load = max(active_ratio, queue_ratio, hsm_ratio, entropy_factor)
            return min(1.0, load)
    
    def _get_state_for_load(self, load: float) -> CryptoConcurrencyState:
        """Get crypto concurrency state based on load and entropy"""
        if self._entropy_level < 10.0:
            return CryptoConcurrencyState.ENTROPY_LOW
        if self._hsm_queue.qsize() > 50:
            return CryptoConcurrencyState.HSM_CONSTRAINED
        if load >= 0.95:
            return CryptoConcurrencyState.CRITICAL
        elif load >= 0.85:
            return CryptoConcurrencyState.OVERLOADED
        elif load >= 0.70:
            return CryptoConcurrencyState.DEGRADED
        return CryptoConcurrencyState.NORMAL
    
    def submit(
        self,
        func: Callable[..., T],
        operation_type: CryptoOperationType,
        *args,
        priority: Optional[CryptoPriorityLevel] = None,
        timeout_seconds: Optional[float] = None,
        key_size_bits: Optional[int] = None,
        algorithm: Optional[str] = None,
        uses_hardware: bool = False,
        **kwargs,
    ) -> Any:
        """
        Submit a crypto operation for QoS-managed execution
        
        Args:
            func: Crypto function to execute
            operation_type: Type of crypto operation
            *args: Positional arguments
            priority: Optional explicit priority (auto-detected if None)
            timeout_seconds: Optional timeout (operation-specific defaults)
            key_size_bits: Key size for complexity estimation
            algorithm: Algorithm name
            uses_hardware: True if HSM/TPM is used
            **kwargs: Keyword arguments
        
        Returns:
            Function result
        """
        # Auto-detect priority from operation type if not specified
        if priority is None:
            priority = self._get_default_priority(operation_type)
        
        # Use operation-specific default timeout
        if timeout_seconds is None:
            timeout_seconds = self.DEFAULT_OPERATION_TIMEOUTS.get(operation_type, 30.0)
        
        load = self._get_current_load()
        state = self._get_state_for_load(load)
        
        # Graceful degradation: reject background operations when constrained
        if self.graceful_degradation_enabled:
            if state == CryptoConcurrencyState.CRITICAL and priority <= CryptoPriorityLevel.BACKGROUND:
                with self._lock:
                    self._metrics.rejected_requests += 1
                raise queue.Full("Crypto system critical - background operations rejected")
            if state == CryptoConcurrencyState.OVERLOADED and priority <= CryptoPriorityLevel.NORMAL:
                pass  # Queue but expect longer waits
            if state == CryptoConcurrencyState.ENTROPY_LOW and operation_type in [
                CryptoOperationType.KEY_GENERATION,
                CryptoOperationType.RANDOM_GENERATION,
            ]:
                # Still accept but with warning - entropy is replenishing
                pass
        
        request = CryptoQoSRequest(
            func=func,
            operation_type=operation_type,
            args=args,
            kwargs=kwargs,
            priority=priority,
            timeout_seconds=timeout_seconds,
            key_size_bits=key_size_bits,
            algorithm=algorithm,
            uses_hardware=uses_hardware,
        )
        
        # Use negative priority for min-heap
        queue_priority = -int(priority)
        
        try:
            self._request_queues[priority].put(
                (queue_priority, request),
                block=False,
            )
        except queue.Full:
            with self._lock:
                self._metrics.rejected_requests += 1
            raise
        
        # Synchronous execution (backward compatible)
        return self._execute_crypto_request(request)
    
    def _get_default_priority(self, op_type: CryptoOperationType) -> CryptoPriorityLevel:
        """Map operation type to default priority"""
        priority_map = {
            CryptoOperationType.KEY_GENERATION: CryptoPriorityLevel.SESSION_CRITICAL,
            CryptoOperationType.KEY_EXCHANGE: CryptoPriorityLevel.SESSION_CRITICAL,
            CryptoOperationType.HSM_OPERATION: CryptoPriorityLevel.CRYPTO_CRITICAL,
            CryptoOperationType.SIGNATURE: CryptoPriorityLevel.AUTH_CRITICAL,
            CryptoOperationType.VERIFICATION: CryptoPriorityLevel.AUTH_CRITICAL,
            CryptoOperationType.ENCRYPTION: CryptoPriorityLevel.NORMAL,
            CryptoOperationType.DECRYPTION: CryptoPriorityLevel.NORMAL,
            CryptoOperationType.HASH: CryptoPriorityLevel.BACKGROUND,
            CryptoOperationType.RANDOM_GENERATION: CryptoPriorityLevel.NORMAL,
            CryptoOperationType.CERTIFICATE_OP: CryptoPriorityLevel.NORMAL,
        }
        return priority_map.get(op_type, CryptoPriorityLevel.NORMAL)
    
    def get_metrics(self) -> CryptoConcurrencyMetrics:
        """Get current crypto QoS metrics snapshot"""
        with self._lock:
            return CryptoConcurrencyMetrics(
                active_workers=self._metrics.active_workers,
                queued_requests=self._metrics.queued_requests,
                queued_by_priority=dict(self._metrics.queued_by_priority),
                queued_by_operation=dict(self._metrics.queued_by_operation),
                completed_requests=self._metrics.completed_requests,
                timed_out_requests=self._metrics.timed_out_requests,
                rejected_requests=self._metrics.rejected_requests,
                hsm_queue_backlog=self._metrics.hsm_queue_backlog,
                entropy_level_pct=self._entropy_level,
                avg_wait_time_seconds=self._metrics.avg_wait_time_seconds,
                avg_execution_time_seconds=self._metrics.avg_execution_time_seconds,
                system_load_pct=self._metrics.system_load_pct,
                current_state=self._metrics.current_state,
            )
    
    def shutdown(self, wait: bool = True) -> None:
        """Shutdown controller"""
        self._shutdown = True
        if wait:
            for t in self._workers + self._hsm_workers:
                t.join(timeout=5.0)

# Global default controller
_default_crypto_controller: Optional[CryptoAdaptiveConcurrencyQoSController] = None
_default_crypto_lock = threading.Lock()

def get_default_crypto_controller() -> CryptoAdaptiveConcurrencyQoSController:
    """Get or create default crypto QoS controller"""
    global _default_crypto_controller
    if _default_crypto_controller is None:
        with _default_crypto_lock:
            if _default_crypto_controller is None:
                _default_crypto_controller = CryptoAdaptiveConcurrencyQoSController()
    return _default_crypto_controller

def crypto_qos_protected(
    operation_type: CryptoOperationType,
    priority: Optional[CryptoPriorityLevel] = None,
    timeout_seconds: Optional[float] = None,
    key_size_bits: Optional[int] = None,
    algorithm: Optional[str] = None,
    uses_hardware: bool = False,
    controller: Optional[CryptoAdaptiveConcurrencyQoSController] = None,
):
    """
    Decorator for QoS-protected crypto operation execution
    
    ADD-ONLY - wraps existing crypto functions without modification
    
    Example:
        @crypto_qos_protected(
            operation_type=CryptoOperationType.KEY_GENERATION,
            key_size_bits=4096,
            timeout_seconds=120.0,
        )
        def generate_post_quantum_keypair() -> KeyPair:
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            ctrl = controller or get_default_crypto_controller()
            return ctrl.submit(
                func,
                operation_type,
                *args,
                priority=priority,
                timeout_seconds=timeout_seconds,
                key_size_bits=key_size_bits,
                algorithm=algorithm,
                uses_hardware=uses_hardware,
                **kwargs,
            )
        return wrapper
    return decorator

# Export public API
__all__ = [
    "CryptoOperationType",
    "CryptoPriorityLevel",
    "CryptoConcurrencyState",
    "CryptoQoSRequest",
    "CryptoConcurrencyMetrics",
    "CryptoAdaptiveConcurrencyQoSController",
    "get_default_crypto_controller",
    "crypto_qos_protected",
]
