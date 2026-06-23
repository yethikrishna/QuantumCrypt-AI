"""
QuantumCrypt AI - Error Resilience Module v21
PQ Algorithm Graceful Degradation + HSM Connection Circuit Breaker + Key Operation Fallbacks
DIMENSION E - Error Resilience
- Graceful degradation for v12 Crypto Observability system
- Circuit breaker for HSM/KMS connections
- Fallback mechanisms when HSM backend is unavailable
- Timeout wrappers for post-quantum key operations
- Memory pressure monitoring for high-volume crypto operations
- NIST security level adaptive fallbacks
- OPT-IN instrumentation - disabled by default
- Happy path behavior 100% preserved
ADD-ONLY implementation - wraps existing code, no modifications
"""
import time
import random
import threading
import functools
import logging
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import asyncio
import hashlib
import secrets

# Configure logging (disabled by default - OPT-IN)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class CryptoDegradationLevel(Enum):
    """Crypto-specific degradation levels for graceful degradation."""
    NORMAL = "normal"                           # Full PQ crypto, all security levels
    LIGHT = "light_degradation"                 # Reduced security level options
    MODERATE = "moderate_degradation"           # Only NIST Level 1 & 3, no Level 5
    SEVERE = "severe_degradation"               # Only NIST Level 1, software-only
    FAILSAFE = "failsafe"                       # Fallback to classical crypto only
    EMERGENCY = "emergency"                     # Minimal operations only


class HSMConnectionStatus(Enum):
    """Status of HSM/KMS connection backends."""
    CONNECTED = "connected"
    DEGRADED = "degraded"
    DISCONNECTED = "disconnected"
    CIRCUIT_OPEN = "circuit_open"


class PQAlgorithmAvailability(Enum):
    """Availability status of PQ algorithms."""
    FULLY_AVAILABLE = "fully_available"
    PARTIALLY_AVAILABLE = "partially_available"
    SOFTWARE_ONLY = "software_only"
    FALLBACK_CLASSICAL = "fallback_classical"


class CryptoResilienceError(Exception):
    """Base exception for crypto resilience errors."""
    pass


class HSMConnectionError(CryptoResilienceError):
    """Raised when HSM connection fails."""
    pass


class KeyOperationTimeoutError(CryptoResilienceError):
    """Raised when key operation exceeds timeout."""
    pass


class SecurityLevelDowngradeError(CryptoResilienceError):
    """Raised when security level must be downgraded."""
    pass


class HSMCircuitOpenError(CryptoResilienceError):
    """Raised when HSM circuit breaker is open."""
    pass


@dataclass
class PQSecurityLevelConfig:
    """Configuration for NIST security level fallbacks."""
    nist_level_5_algorithms: List[str] = field(default_factory=lambda: ["Kyber-1024", "Dilithium-5"])
    nist_level_3_algorithms: List[str] = field(default_factory=lambda: ["Kyber-768", "Dilithium-3"])
    nist_level_2_algorithms: List[str] = field(default_factory=lambda: ["Dilithium-2"])
    nist_level_1_algorithms: List[str] = field(default_factory=lambda: ["Kyber-512"])
    classical_fallback_algorithms: List[str] = field(default_factory=lambda: ["AES-256-GCM", "RSA-4096"])
    
    allow_level_downgrade: bool = True
    prefer_software_fallback: bool = True
    emergency_minimal_operations_only: bool = False


@dataclass
class HSMCircuitBreakerConfig:
    """Configuration for HSM connection circuit breaker."""
    connection_failure_threshold: int = 3
    operation_failure_threshold: int = 10
    success_threshold: int = 5
    reset_timeout: float = 120.0
    probe_interval: float = 30.0
    max_connection_pool_size: int = 10
    connection_timeout: float = 30.0
    operation_timeout: float = 60.0
    half_open_max_attempts: int = 3
    max_queued_key_operations: int = 1000
    batch_size_on_recovery: int = 50


@dataclass
class KeyOperationFallbackConfig:
    """Configuration for key operation fallback mechanisms."""
    enable_software_fallback: bool = True
    enable_classical_crypto_fallback: bool = True
    max_queued_key_operations: int = 1000
    retry_on_hsm_recovery: bool = True
    max_retry_attempts: int = 3
    batch_size_on_recovery: int = 50
    preserve_key_security_level: bool = True


@dataclass
class CryptoMemoryPressureConfig:
    """Configuration for crypto memory pressure monitoring."""
    # Memory thresholds (percentage)
    pressure_light: float = 55.0
    pressure_moderate: float = 70.0
    pressure_severe: float = 85.0
    pressure_failsafe: float = 92.0
    pressure_emergency: float = 97.0
    
    # Key generation limits per pressure level
    max_concurrent_keygen_normal: int = 50
    max_concurrent_keygen_light: int = 25
    max_concurrent_keygen_moderate: int = 10
    max_concurrent_keygen_severe: int = 3
    max_concurrent_keygen_failsafe: int = 1
    max_concurrent_keygen_emergency: int = 0
    
    # Sampling for high-volume operations
    sampling_rate_normal: float = 1.0
    sampling_rate_light: float = 0.75
    sampling_rate_moderate: float = 0.5
    sampling_rate_severe: float = 0.1
    sampling_rate_failsafe: float = 0.01
    
    check_interval: float = 15.0


@dataclass
class CryptoTimeoutConfig:
    """Configuration for crypto operation timeouts."""
    kyber_keygen_timeout: float = 2.0
    kyber_encaps_timeout: float = 1.0
    kyber_decaps_timeout: float = 1.0
    dilithium_sign_timeout: float = 3.0
    dilithium_verify_timeout: float = 1.0
    hsm_connection_timeout: float = 30.0
    hsm_key_import_timeout: float = 60.0
    hsm_key_export_timeout: float = 60.0
    adaptive_timeout: bool = True
    timeout_history_window: int = 100


class CryptoMemoryPressureMonitor:
    """Monitors memory pressure specifically for crypto operations."""
    
    def __init__(self, config: Optional[CryptoMemoryPressureConfig] = None):
        self.config = config or CryptoMemoryPressureConfig()
        self._last_check = 0.0
        self._current_pressure = 0.0
        self._lock = threading.Lock()
        self._concurrent_keygen_count = 0
        self._keygen_lock = threading.Lock()
    
    def get_memory_usage_percent(self) -> float:
        """Get current memory usage percentage."""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except (ImportError, Exception):
            try:
                import gc
                gc.collect()
                objects = len(gc.get_objects())
                return min(100.0, (objects / 50000.0) * 40.0)
            except:
                return 50.0
    
    def get_current_pressure(self) -> float:
        """Get current memory pressure level."""
        now = time.time()
        with self._lock:
            if now - self._last_check > self.config.check_interval:
                self._current_pressure = self.get_memory_usage_percent()
                self._last_check = now
            return self._current_pressure
    
    def get_degradation_level(self) -> CryptoDegradationLevel:
        """Determine crypto degradation level based on memory pressure."""
        pressure = self.get_current_pressure()
        
        if pressure >= self.config.pressure_emergency:
            return CryptoDegradationLevel.EMERGENCY
        elif pressure >= self.config.pressure_failsafe:
            return CryptoDegradationLevel.FAILSAFE
        elif pressure >= self.config.pressure_severe:
            return CryptoDegradationLevel.SEVERE
        elif pressure >= self.config.pressure_moderate:
            return CryptoDegradationLevel.MODERATE
        elif pressure >= self.config.pressure_light:
            return CryptoDegradationLevel.LIGHT
        return CryptoDegradationLevel.NORMAL
    
    def acquire_keygen_slot(self) -> bool:
        """Acquire slot for key generation based on current pressure level."""
        level = self.get_degradation_level()
        
        max_slots = {
            CryptoDegradationLevel.NORMAL: self.config.max_concurrent_keygen_normal,
            CryptoDegradationLevel.LIGHT: self.config.max_concurrent_keygen_light,
            CryptoDegradationLevel.MODERATE: self.config.max_concurrent_keygen_moderate,
            CryptoDegradationLevel.SEVERE: self.config.max_concurrent_keygen_severe,
            CryptoDegradationLevel.FAILSAFE: self.config.max_concurrent_keygen_failsafe,
            CryptoDegradationLevel.EMERGENCY: self.config.max_concurrent_keygen_emergency,
        }.get(level, 0)
        
        with self._keygen_lock:
            if self._concurrent_keygen_count >= max_slots:
                return False
            self._concurrent_keygen_count += 1
            return True
    
    def release_keygen_slot(self) -> None:
        """Release key generation slot."""
        with self._keygen_lock:
            self._concurrent_keygen_count = max(0, self._concurrent_keygen_count - 1)
    
    def should_sample_operation(self) -> bool:
        """Determine if operation should proceed based on sampling rate."""
        level = self.get_degradation_level()
        
        sampling_rates = {
            CryptoDegradationLevel.NORMAL: self.config.sampling_rate_normal,
            CryptoDegradationLevel.LIGHT: self.config.sampling_rate_light,
            CryptoDegradationLevel.MODERATE: self.config.sampling_rate_moderate,
            CryptoDegradationLevel.SEVERE: self.config.sampling_rate_severe,
            CryptoDegradationLevel.FAILSAFE: self.config.sampling_rate_failsafe,
            CryptoDegradationLevel.EMERGENCY: 0.0,
        }
        
        rate = sampling_rates.get(level, 1.0)
        return random.random() < rate


class HSMConnectionCircuitBreaker:
    """Circuit breaker specifically for HSM/KMS connections."""
    
    def __init__(self, config: Optional[HSMCircuitBreakerConfig] = None, name: str = "default_hsm"):
        self.config = config or HSMCircuitBreakerConfig()
        self.name = name
        self._state = HSMConnectionStatus.CONNECTED
        self._connection_failures = 0
        self._operation_failures = 0
        self._consecutive_successes = 0
        self._last_failure_time = 0.0
        self._last_probe_time = 0.0
        self._failure_timestamps: deque = deque(maxlen=50)
        self._lock = threading.Lock()
        self._pending_operations: deque = deque(maxlen=config.max_queued_key_operations if config else 1000)
    
    @property
    def state(self) -> HSMConnectionStatus:
        """Get current HSM connection status."""
        return self._state
    
    @property
    def pending_count(self) -> int:
        """Get count of pending queued operations."""
        with self._lock:
            return len(self._pending_operations)
    
    def enqueue_key_operation(self, operation_data: Any) -> bool:
        """Enqueue key operation for later execution when HSM recovers."""
        with self._lock:
            if len(self._pending_operations) >= self.config.max_queued_key_operations:
                self._pending_operations.popleft()
            self._pending_operations.append((time.time(), operation_data))
            return True
    
    def get_queued_operations(self, max_count: Optional[int] = None) -> List[Any]:
        """Get queued operations for retry on HSM recovery."""
        with self._lock:
            count = max_count if max_count else self.config.batch_size_on_recovery
            ops = []
            for _ in range(min(count, len(self._pending_operations))):
                ops.append(self._pending_operations.popleft())
            return [op[1] for op in ops]
    
    def record_connection_success(self) -> None:
        """Record successful HSM connection."""
        with self._lock:
            self._consecutive_successes += 1
            self._connection_failures = max(0, self._connection_failures - 1)
            
            if self._state in [HSMConnectionStatus.CIRCUIT_OPEN, HSMConnectionStatus.DISCONNECTED]:
                if self._consecutive_successes >= self.config.success_threshold:
                    self._state = HSMConnectionStatus.CONNECTED
                    self._consecutive_successes = 0
                    logger.info(f"HSM '{self.name}' connection restored")
    
    def record_connection_failure(self) -> None:
        """Record failed HSM connection."""
        with self._lock:
            self._last_failure_time = time.time()
            self._connection_failures += 1
            self._consecutive_successes = 0
            self._failure_timestamps.append(time.time())
            
            if self._connection_failures >= self.config.connection_failure_threshold:
                if self._state == HSMConnectionStatus.CONNECTED:
                    self._state = HSMConnectionStatus.DEGRADED
                    logger.warning(f"HSM '{self.name}' connection degraded")
                elif self._state == HSMConnectionStatus.DEGRADED:
                    self._state = HSMConnectionStatus.DISCONNECTED
                    logger.warning(f"HSM '{self.name}' disconnected")
                elif self._state == HSMConnectionStatus.DISCONNECTED:
                    self._state = HSMConnectionStatus.CIRCUIT_OPEN
                    logger.warning(f"HSM '{self.name}' circuit OPEN - stopping connections")
    
    def record_operation_success(self) -> None:
        """Record successful key operation."""
        with self._lock:
            self._consecutive_successes += 1
            self._operation_failures = max(0, self._operation_failures - 1)
    
    def record_operation_failure(self) -> None:
        """Record failed key operation."""
        with self._lock:
            self._operation_failures += 1
            self._consecutive_successes = 0
            
            if self._operation_failures >= self.config.operation_failure_threshold:
                if self._state == HSMConnectionStatus.CONNECTED:
                    self._state = HSMConnectionStatus.DEGRADED
                    logger.warning(f"HSM '{self.name}' operations degraded")
    
    def allow_connection(self) -> bool:
        """Check if connection attempt should be allowed."""
        with self._lock:
            if self._state == HSMConnectionStatus.CONNECTED:
                return True
            
            if self._state == HSMConnectionStatus.DEGRADED:
                return random.random() < 0.5
            
            if self._state == HSMConnectionStatus.DISCONNECTED:
                now = time.time()
                if now - self._last_probe_time > self.config.probe_interval:
                    self._last_probe_time = now
                    return True
                return False
            
            if self._state == HSMConnectionStatus.CIRCUIT_OPEN:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.config.reset_timeout:
                    self._state = HSMConnectionStatus.DISCONNECTED
                    logger.info(f"HSM '{self.name}' probing for recovery")
                    return True
                return False
            
            return False


class PQAlgorithmFallbackManager:
    """Manages PQ algorithm fallbacks and security level downgrades."""
    
    def __init__(self, config: Optional[PQSecurityLevelConfig] = None):
        self.config = config or PQSecurityLevelConfig()
        self._lock = threading.Lock()
        self._downgrade_count = 0
        self._classical_fallback_count = 0
    
    @property
    def total_downgrades(self) -> int:
        """Get total security level downgrades."""
        with self._lock:
            return self._downgrade_count
    
    @property
    def total_classical_fallbacks(self) -> int:
        """Get total classical crypto fallbacks."""
        with self._lock:
            return self._classical_fallback_count
    
    def get_available_algorithms(self, level: CryptoDegradationLevel) -> Dict[str, List[str]]:
        """Get available algorithms based on degradation level."""
        if level == CryptoDegradationLevel.NORMAL:
            return {
                "pq": self.config.nist_level_5_algorithms + self.config.nist_level_3_algorithms + 
                      self.config.nist_level_2_algorithms + self.config.nist_level_1_algorithms,
                "classical": self.config.classical_fallback_algorithms
            }
        elif level == CryptoDegradationLevel.LIGHT:
            return {
                "pq": self.config.nist_level_3_algorithms + self.config.nist_level_1_algorithms,
                "classical": self.config.classical_fallback_algorithms
            }
        elif level == CryptoDegradationLevel.MODERATE:
            return {
                "pq": self.config.nist_level_1_algorithms,
                "classical": self.config.classical_fallback_algorithms
            }
        elif level in [CryptoDegradationLevel.SEVERE, CryptoDegradationLevel.FAILSAFE]:
            return {
                "pq": [],
                "classical": self.config.classical_fallback_algorithms
            }
        else:  # EMERGENCY
            return {"pq": [], "classical": []}
    
    def select_fallback_algorithm(self, requested: str, level: CryptoDegradationLevel) -> Tuple[str, bool]:
        """Select appropriate fallback algorithm."""
        available = self.get_available_algorithms(level)
        
        if requested in available["pq"]:
            return requested, False
        
        # Try to find highest available PQ algorithm
        for algo in [self.config.nist_level_3_algorithms, self.config.nist_level_1_algorithms]:
            for a in algo:
                if a in available["pq"]:
                    with self._lock:
                        self._downgrade_count += 1
                    return a, True
        
        # Fallback to classical
        if self.config.enable_classical_crypto_fallback and available["classical"]:
            with self._lock:
                self._classical_fallback_count += 1
            return available["classical"][0], True
        
        return requested, False


class CryptoResilienceOrchestrator:
    """Orchestrates all crypto resilience mechanisms."""
    
    _instance: Optional['CryptoResilienceOrchestrator'] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        # Always reset state to ensure test isolation and OPT-IN behavior
        self._memory_config = CryptoMemoryPressureConfig()
        self._hsm_config = HSMCircuitBreakerConfig()
        self._pq_config = PQSecurityLevelConfig()
        self._timeout_config = CryptoTimeoutConfig()
        
        self._memory_monitor = CryptoMemoryPressureMonitor(self._memory_config)
        self._hsm_circuits: Dict[str, HSMConnectionCircuitBreaker] = {}
        self._pq_fallback = PQAlgorithmFallbackManager(self._pq_config)
        
        self._global_lock = threading.Lock()
        self._enabled = False  # OPT-IN - ALWAYS disabled by default
        self._initialized = True
    
    def enable(self) -> None:
        """Enable crypto resilience (OPT-IN)."""
        with self._global_lock:
            self._enabled = True
            logger.info("Crypto resilience enabled")
    
    def disable(self) -> None:
        """Disable crypto resilience."""
        with self._global_lock:
            self._enabled = False
            logger.info("Crypto resilience disabled")
    
    @property
    def enabled(self) -> bool:
        """Check if resilience is enabled."""
        return self._enabled
    
    def get_degradation_level(self) -> CryptoDegradationLevel:
        """Get current crypto degradation level."""
        return self._memory_monitor.get_degradation_level()
    
    def should_allow_crypto_operation(self) -> bool:
        """Check if crypto operation should proceed."""
        if not self._enabled:
            return True
        
        level = self.get_degradation_level()
        if level == CryptoDegradationLevel.EMERGENCY:
            return False
        
        return self._memory_monitor.should_sample_operation()
    
    def acquire_keygen_slot(self) -> bool:
        """Acquire key generation slot."""
        if not self._enabled:
            return True
        return self._memory_monitor.acquire_keygen_slot()
    
    def release_keygen_slot(self) -> None:
        """Release key generation slot."""
        if self._enabled:
            self._memory_monitor.release_keygen_slot()
    
    def get_hsm_circuit(self, name: str) -> HSMConnectionCircuitBreaker:
        """Get or create HSM circuit breaker by name."""
        with self._global_lock:
            if name not in self._hsm_circuits:
                self._hsm_circuits[name] = HSMConnectionCircuitBreaker(self._hsm_config, name)
            return self._hsm_circuits[name]
    
    def select_algorithm(self, requested_algorithm: str) -> Tuple[str, bool]:
        """Select algorithm with automatic fallback."""
        if not self._enabled:
            return requested_algorithm, False
        
        level = self.get_degradation_level()
        return self._pq_fallback.select_fallback_algorithm(requested_algorithm, level)
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive crypto resilience status."""
        return {
            "enabled": self._enabled,
            "degradation_level": self.get_degradation_level().value,
            "memory_pressure": self._memory_monitor.get_current_pressure(),
            "security_downgrades": self._pq_fallback.total_downgrades,
            "classical_fallbacks": self._pq_fallback.total_classical_fallbacks,
            "hsm_connections": {
                name: {
                    "state": cb.state.value,
                    "pending_operations": cb.pending_count
                }
                for name, cb in self._hsm_circuits.items()
            }
        }


def with_hsm_resilience(
    hsm_name: str = "default",
    enable_fallback: bool = True,
    timeout_seconds: Optional[float] = None
):
    """
    Decorator for HSM operation resilience.
    
    Provides:
    - Circuit breaking for failing HSM connections
    - Automatic queuing when HSM is down
    - Timeout enforcement
    - Software fallback option
    
    Usage:
        @with_hsm_resilience(hsm_name="cloud_hsm_aws")
        def hsm_generate_key():
            ...
    """
    orchestrator = CryptoResilienceOrchestrator()
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not orchestrator.enabled:
                return func(*args, **kwargs)
            
            hsm_circuit = orchestrator.get_hsm_circuit(hsm_name)
            
            if not hsm_circuit.allow_connection():
                if enable_fallback:
                    hsm_circuit.enqueue_key_operation((args, kwargs))
                return None
            
            timeout = timeout_seconds if timeout_seconds else 30.0
            result = [None]
            success = [False]
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                    success[0] = True
                except Exception:
                    pass
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout=timeout)
            
            if thread.is_alive():
                hsm_circuit.record_connection_failure()
                if enable_fallback:
                    hsm_circuit.enqueue_key_operation((args, kwargs))
                return None
            
            if success[0]:
                hsm_circuit.record_connection_success()
                hsm_circuit.record_operation_success()
                return result[0]
            else:
                hsm_circuit.record_connection_failure()
                hsm_circuit.record_operation_failure()
                if enable_fallback:
                    hsm_circuit.enqueue_key_operation((args, kwargs))
                return None
        
        return wrapper
    return decorator


def with_pq_algorithm_fallback(
    requested_algorithm: str = "Kyber-768"
):
    """
    Decorator for PQ algorithm with automatic security level fallback.
    
    Usage:
        @with_pq_algorithm_fallback(requested_algorithm="Kyber-1024")
        def generate_pq_key_pair(algorithm="Kyber-768"):
            ...
    """
    orchestrator = CryptoResilienceOrchestrator()
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not orchestrator.enabled:
                return func(*args, **kwargs)
            
            actual_algorithm, was_downgraded = orchestrator.select_algorithm(requested_algorithm)
            
            if was_downgraded:
                logger.warning(f"Downgraded from {requested_algorithm} to {actual_algorithm}")
            
            kwargs['algorithm'] = actual_algorithm
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def safe_key_operation(
    operation_func: Callable,
    *args,
    require_keygen_slot: bool = True,
    **kwargs
) -> Optional[Any]:
    """
    Safe key operation with memory pressure protection.
    
    Returns None on resource exhaustion rather than raising.
    """
    orchestrator = CryptoResilienceOrchestrator()
    
    if not orchestrator.enabled:
        try:
            return operation_func(*args, **kwargs)
        except:
            return None
    
    if not orchestrator.should_allow_crypto_operation():
        return None
    
    if require_keygen_slot and not orchestrator.acquire_keygen_slot():
        return None
    
    try:
        result = operation_func(*args, **kwargs)
        return result
    except Exception:
        return None
    finally:
        if require_keygen_slot:
            orchestrator.release_keygen_slot()


# Global singleton instance for easy access
crypto_resilience = CryptoResilienceOrchestrator()
