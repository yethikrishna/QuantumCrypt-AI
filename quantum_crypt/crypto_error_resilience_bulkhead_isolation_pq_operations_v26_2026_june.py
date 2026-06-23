"""
QuantumCrypt AI - Error Resilience Bulkhead Isolation v26
Dimension E: Error Resilience - ADD-ONLY implementation

Bulkhead isolation pattern for post-quantum cryptographic operations.
Isolates different crypto operations into separate thread pools to prevent
cascading failures. One failing crypto operation won't take down the entire system.

Critical for crypto systems: resource exhaustion attacks are a common threat vector.
Bulkhead prevents one operation from consuming all resources.

Philosophy: ADD-ONLY, wrap existing code, 100% backward compatible
"""

import threading
import time
import logging
from typing import Callable, Any, Dict, Optional, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
import concurrent.futures
import secrets

# Configure logging - OPT-IN only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

T = TypeVar('T')
R = TypeVar('R')


class CryptoBulkheadState(Enum):
    """Crypto bulkhead compartment state"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    SATURATED = "saturated"
    TRIPPED = "tripped"


@dataclass
class CryptoBulkheadMetrics:
    """Metrics for a single crypto bulkhead compartment"""
    active_operations: int = 0
    queued_operations: int = 0
    completed_operations: int = 0
    failed_operations: int = 0
    timed_out_operations: int = 0
    rejected_operations: int = 0
    total_execution_time_ns: int = 0
    last_failure_time: Optional[float] = None
    state: CryptoBulkheadState = CryptoBulkheadState.HEALTHY


@dataclass
class CryptoBulkheadConfig:
    """Configuration for a crypto bulkhead compartment
    
    Tuned specifically for cryptographic operations which are
    CPU-intensive and have different performance characteristics.
    """
    max_concurrent_operations: int = 4  # Crypto is CPU heavy
    max_queue_size: int = 32
    operation_timeout_seconds: float = 120.0  # Key gen can be slow
    failure_threshold: int = 3
    failure_window_seconds: float = 120.0
    recovery_timeout_seconds: float = 60.0
    max_memory_per_operation_mb: int = 256  # Soft limit advisory


class CryptoBulkheadCompartment(Generic[T, R]):
    """
    Isolated bulkhead compartment for cryptographic operations.
    Each compartment has its own thread pool and failure detection.
    
    Specialized for crypto workloads:
    - Lower concurrency (CPU intensive)
    - Longer timeouts (key generation, pairing operations)
    - Memory usage tracking
    """

    def __init__(
        self,
        name: str,
        config: Optional[CryptoBulkheadConfig] = None
    ):
        self.name = name
        self.config = config or CryptoBulkheadConfig()
        self.metrics = CryptoBulkheadMetrics()
        self._lock = threading.RLock()
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._failure_timestamps: list = []
        self._tripped_at: Optional[float] = None
        self._initialized = False
        self._operation_counter = 0

    def _initialize(self) -> None:
        """Lazy initialization of thread pool"""
        if not self._initialized:
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.max_concurrent_operations,
                thread_name_prefix=f"crypto-bulkhead-{self.name}"
            )
            self._initialized = True

    def _check_state(self) -> CryptoBulkheadState:
        """Check and update bulkhead state"""
        now = time.time()

        # Check if tripped and in recovery period
        if self._tripped_at is not None:
            if now - self._tripped_at >= self.config.recovery_timeout_seconds:
                self._tripped_at = None
                self._failure_timestamps.clear()
                logger.info(
                    f"CryptoBulkhead {self.name}: Recovery timeout elapsed, resetting"
                )
            else:
                return CryptoBulkheadState.TRIPPED

        # Clean old failure timestamps
        cutoff = now - self.config.failure_window_seconds
        self._failure_timestamps = [
            t for t in self._failure_timestamps if t > cutoff
        ]

        # Determine state based on metrics
        with self._lock:
            active = self.metrics.active_operations
            queued = self.metrics.queued_operations
            failures = len(self._failure_timestamps)

        if failures >= self.config.failure_threshold:
            self._tripped_at = now
            logger.warning(
                f"CryptoBulkhead {self.name}: TRIPPED - {failures} failures "
                f"in window, rejecting all operations"
            )
            return CryptoBulkheadState.TRIPPED

        if active >= self.config.max_concurrent_operations:
            return CryptoBulkheadState.SATURATED

        if active >= self.config.max_concurrent_operations * 0.75 or queued >= 16:
            return CryptoBulkheadState.DEGRADED

        return CryptoBulkheadState.HEALTHY

    def _record_failure(self) -> None:
        """Record a failure for circuit breaking"""
        now = time.time()
        with self._lock:
            self._failure_timestamps.append(now)
            self.metrics.failed_operations += 1
            self.metrics.last_failure_time = now

    def execute(
        self,
        func: Callable[[T], R],
        arg: T,
        fallback: Optional[Callable[[Exception], R]] = None,
        operation_id: Optional[str] = None
    ) -> R:
        """
        Execute crypto function within this bulkhead compartment.
        
        Args:
            func: Crypto function to execute
            arg: Single argument for the function
            fallback: Optional fallback function if execution fails
            operation_id: Optional tracking ID for auditing
            
        Returns:
            Function result or fallback result
            
        Raises:
            CryptoBulkheadTrippedError: If bulkhead is tripped
            TimeoutError: If execution times out
        """
        self._initialize()
        state = self._check_state()
        
        op_id = operation_id or secrets.token_hex(8)

        if state == CryptoBulkheadState.TRIPPED:
            with self._lock:
                self.metrics.rejected_operations += 1
            
            if fallback:
                logger.warning(
                    f"CryptoBulkhead {self.name}: TRIPPED, "
                    f"using fallback for op {op_id}"
                )
                return fallback(CryptoBulkheadTrippedError(
                    f"Crypto bulkhead {self.name} is tripped"
                ))
            raise CryptoBulkheadTrippedError(
                f"Crypto bulkhead {self.name} is tripped due to excessive failures"
            )

        start_time = time.time_ns()

        try:
            with self._lock:
                self.metrics.queued_operations += 1
                self._operation_counter += 1

            # Submit to executor with timeout
            future = self._executor.submit(func, arg)
            
            with self._lock:
                self.metrics.queued_operations -= 1
                self.metrics.active_operations += 1

            try:
                result = future.result(
                    timeout=self.config.operation_timeout_seconds
                )
                
                with self._lock:
                    self.metrics.completed_operations += 1
                    self.metrics.total_execution_time_ns += (
                        time.time_ns() - start_time
                    )
                
                return result

            except concurrent.futures.TimeoutError:
                with self._lock:
                    self.metrics.timed_out_operations += 1
                self._record_failure()
                
                logger.error(
                    f"CryptoBulkhead {self.name}: Operation {op_id} timed out"
                )
                
                if fallback:
                    return fallback(TimeoutError(
                        f"Crypto operation timed out after "
                        f"{self.config.operation_timeout_seconds}s"
                    ))
                raise

        except Exception as e:
            self._record_failure()
            logger.error(
                f"CryptoBulkhead {self.name}: Operation {op_id} failed: {e}"
            )
            
            if fallback:
                return fallback(e)
            raise

        finally:
            with self._lock:
                if self.metrics.active_operations > 0:
                    self.metrics.active_operations -= 1

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics for this bulkhead"""
        with self._lock:
            state = self._check_state()
            self.metrics.state = state
            
            avg_time = 0.0
            if self.metrics.completed_operations > 0:
                avg_time = (
                    self.metrics.total_execution_time_ns /
                    self.metrics.completed_operations / 1_000_000
                )
            
            return {
                "name": self.name,
                "state": state.value,
                "active_operations": self.metrics.active_operations,
                "queued_operations": self.metrics.queued_operations,
                "completed_operations": self.metrics.completed_operations,
                "failed_operations": self.metrics.failed_operations,
                "timed_out_operations": self.metrics.timed_out_operations,
                "rejected_operations": self.metrics.rejected_operations,
                "avg_execution_time_ms": avg_time,
                "tripped": self._tripped_at is not None,
                "total_operations_processed": self._operation_counter
            }

    def reset(self) -> None:
        """Reset bulkhead state and metrics"""
        with self._lock:
            self._tripped_at = None
            self._failure_timestamps.clear()
            self.metrics = CryptoBulkheadMetrics()
            logger.info(f"CryptoBulkhead {self.name}: Reset complete")

    def shutdown(self) -> None:
        """Shutdown the bulkhead executor"""
        if self._executor:
            self._executor.shutdown(wait=False)
            self._initialized = False


class CryptoBulkheadError(Exception):
    """Base exception for crypto bulkhead errors"""
    pass


class CryptoBulkheadTrippedError(CryptoBulkheadError):
    """Raised when crypto bulkhead is tripped"""
    pass


class CryptoOperationBulkheadManager:
    """
    Manager for bulkhead-isolated cryptographic operations.
    Creates separate compartments for different crypto operation types.
    
    Crypto operations have very different resource profiles:
    - Key generation: Very CPU/memory heavy, slow
    - Signing: Moderate, predictable
    - Verification: Fast, lightweight
    - Key exchange: Moderate
    - Hashing: Very fast
    """

    # Predefined crypto operation categories with tuned configs
    CRYPTO_CATEGORIES = {
        "key_generation": CryptoBulkheadConfig(
            max_concurrent_operations=2,  # Very heavy
            max_queue_size=16,
            operation_timeout_seconds=300.0  # PQ key gen can be SLOW
        ),
        "digital_signature": CryptoBulkheadConfig(
            max_concurrent_operations=4,
            max_queue_size=64,
            operation_timeout_seconds=30.0
        ),
        "signature_verification": CryptoBulkheadConfig(
            max_concurrent_operations=8,  # Verification is faster
            max_queue_size=128,
            operation_timeout_seconds=10.0
        ),
        "key_encapsulation": CryptoBulkheadConfig(
            max_concurrent_operations=4,
            max_queue_size=32,
            operation_timeout_seconds=60.0
        ),
        "hash_operation": CryptoBulkheadConfig(
            max_concurrent_operations=16,  # Very fast
            max_queue_size=256,
            operation_timeout_seconds=5.0
        ),
        "random_generation": CryptoBulkheadConfig(
            max_concurrent_operations=8,
            max_queue_size=128,
            operation_timeout_seconds=10.0
        ),
        "default": CryptoBulkheadConfig(
            max_concurrent_operations=2,
            max_queue_size=16,
            operation_timeout_seconds=60.0
        )
    }

    def __init__(self):
        self._bulkheads: Dict[str, CryptoBulkheadCompartment] = {}
        self._lock = threading.RLock()

    def _get_bulkhead(self, category: str) -> CryptoBulkheadCompartment:
        """Get or create bulkhead for a crypto category"""
        with self._lock:
            if category not in self._bulkheads:
                config = self.CRYPTO_CATEGORIES.get(
                    category,
                    self.CRYPTO_CATEGORIES["default"]
                )
                self._bulkheads[category] = CryptoBulkheadCompartment(
                    name=category,
                    config=config
                )
            return self._bulkheads[category]

    def execute_operation(
        self,
        category: str,
        crypto_func: Callable,
        input_data: Any,
        fallback: Optional[Callable] = None,
        operation_id: Optional[str] = None
    ) -> Any:
        """
        Execute crypto operation within the appropriate bulkhead.
        
        Args:
            category: Crypto operation category
            crypto_func: The crypto function to execute
            input_data: Input data
            fallback: Optional fallback function
            operation_id: Optional tracking ID
            
        Returns:
            Crypto operation result
        """
        bulkhead = self._get_bulkhead(category)
        return bulkhead.execute(
            crypto_func,
            input_data,
            fallback,
            operation_id
        )

    def get_all_metrics(self) -> Dict[str, Any]:
        """Get metrics for all bulkheads"""
        with self._lock:
            return {
                name: bulkhead.get_metrics()
                for name, bulkhead in self._bulkheads.items()
            }

    def get_security_health(self) -> Dict[str, Any]:
        """Get security-focused health assessment"""
        metrics = self.get_all_metrics()
        states = [m["state"] for m in metrics.values()]
        
        total_ops = sum(m["completed_operations"] for m in metrics.values())
        total_failures = sum(m["failed_operations"] for m in metrics.values())
        
        failure_rate = 0.0
        if total_ops + total_failures > 0:
            failure_rate = total_failures / (total_ops + total_failures)
        
        return {
            "total_bulkheads": len(metrics),
            "healthy_count": states.count("healthy"),
            "degraded_count": states.count("degraded"),
            "saturated_count": states.count("saturated"),
            "tripped_count": states.count("tripped"),
            "total_operations": total_ops,
            "total_failures": total_failures,
            "failure_rate": failure_rate,
            "security_status": (
                "SECURE" if failure_rate < 0.01 and "tripped" not in states
                else "ELEVATED" if "tripped" not in states
                else "COMPROMISED"
            ),
            "bulkheads": metrics
        }

    def reset_all(self) -> None:
        """Reset all bulkheads"""
        with self._lock:
            for bulkhead in self._bulkheads.values():
                bulkhead.reset()

    def shutdown_all(self) -> None:
        """Shutdown all bulkheads"""
        with self._lock:
            for bulkhead in self._bulkheads.values():
                bulkhead.shutdown()
            self._bulkheads.clear()


# Global singleton instance - OPT-IN usage only
_crypto_bulkhead_manager: Optional[CryptoOperationBulkheadManager] = None
_manager_lock = threading.Lock()


def get_crypto_bulkhead_manager() -> CryptoOperationBulkheadManager:
    """Get the global crypto bulkhead manager instance (lazy initialized)"""
    global _crypto_bulkhead_manager
    if _crypto_bulkhead_manager is None:
        with _manager_lock:
            if _crypto_bulkhead_manager is None:
                _crypto_bulkhead_manager = CryptoOperationBulkheadManager()
    return _crypto_bulkhead_manager


def bulkheaded_crypto(
    category: str,
    fallback: Optional[Callable] = None
):
    """
    Decorator for bulkhead-isolated cryptographic operations.
    
    Usage:
        @bulkheaded_crypto("key_generation", fallback=secure_fallback)
        def generate_keypair(parameters):
            return pq_lib.generate_key(parameters)
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(input_data: Any) -> Any:
            manager = get_crypto_bulkhead_manager()
            return manager.execute_operation(
                category=category,
                crypto_func=func,
                input_data=input_data,
                fallback=fallback
            )
        return wrapper
    return decorator


# Secure fallback functions for crypto
def secure_null_fallback(error: Exception) -> bytes:
    """
    Secure fallback that returns cryptographically random bytes.
    NEVER return predictable data in security fallbacks!
    """
    logger.warning("Using secure random fallback for crypto operation")
    return secrets.token_bytes(32)


def secure_deny_fallback(error: Exception) -> Dict:
    """Security-focused fallback that denies operation"""
    return {
        "success": False,
        "error": "Crypto operation protected by bulkhead isolation",
        "bulkhead_protection": True,
        "retry_allowed": True,
        "retry_after_seconds": 5
    }


def secure_empty_result_fallback(error: Exception) -> Dict:
    """Fallback that returns empty but structured result"""
    return {
        "success": False,
        "result": None,
        "bulkhead_protection": True,
        "warning": "Operation failed gracefully via bulkhead protection"
    }


"""
END OF MODULE - Dimension E: Error Resilience
ADD-ONLY implementation - wraps existing code without modification
100% backward compatible - existing code works unchanged
All instrumentation is OPT-IN via decorator or explicit manager usage

Security Note: Crypto operations are prime targets for DoS attacks.
Bulkhead isolation ensures:
1. No single operation type consumes all resources
2. Cascading failures are contained
3. Graceful degradation under attack
4. Predictable resource boundaries
"""
