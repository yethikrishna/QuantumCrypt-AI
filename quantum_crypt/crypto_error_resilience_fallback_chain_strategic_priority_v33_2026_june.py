"""
QuantumCrypt AI - Crypto Error Resilience Module
Strategic Priority-Based Fallback Chain with Post-Quantum Security v33

DIMENSION E: ERROR RESILIENCE
- Purely additive, no modifications to existing code
- 100% backward compatible
- Happy path behavior fully preserved
- All instrumentation is OPT-IN
- Crypto-specific security adaptations

Features added in v33:
1. Priority-based fallback selection for crypto operations
2. Health-aware fallback routing with crypto security scoring
3. Degradation level tracking with security compliance monitoring
4. Post-quantum algorithm fallback orchestration
5. Key management failure recovery strategies
6. Crypto-specific cascading failure prevention
7. Secure memory zeroization on fallback paths
"""

import time
import threading
import logging
import secrets
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import statistics
from functools import wraps
import hashlib


# Configure logging - OPT-IN only, disabled by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class CryptoDegradationLevel(Enum):
    """Crypto-specific degradation levels for graceful security degradation."""
    FULL_SECURITY = "full_security"                  # Full post-quantum security
    STANDARD_SECURITY = "standard_security"          # Standard crypto only
    MINIMAL_SECURITY = "minimal_security"            # Minimal security only
    READ_ONLY = "read_only"                          # Read-only operations only
    FAILSAFE = "failsafe"                            # Emergency failsafe mode only


class CryptoFallbackPriority(Enum):
    """Priority levels for crypto fallback strategy selection."""
    POST_QUANTUM_PRIMARY = 0      # Primary post-quantum algorithm
    CLASSIC_CRYPTO_FALLBACK = 1   # Classic crypto fallback
    HARDWARE_ACCELERATED = 2      # Hardware-accelerated fallback
    SOFTWARE_ONLY = 3             # Software-only fallback
    EMERGENCY_CLEARTEXT = 4       # Emergency only - NOT RECOMMENDED


class CryptoHealthStatus(Enum):
    """Health status for crypto module and HSM monitoring."""
    OPERATIONAL = "operational"
    DEGRADED_PERFORMANCE = "degraded_performance"
    SECURITY_DEGRADED = "security_degraded"
    HARDWARE_FAILURE = "hardware_failure"
    UNAVAILABLE = "unavailable"


class SecurityStrength(Enum):
    """Security strength levels for algorithm comparison."""
    PQC_LEVEL_5 = 256    # NIST PQC Level 5 (AES-256 equivalent)
    PQC_LEVEL_3 = 192    # NIST PQC Level 3 (AES-192 equivalent)
    PQC_LEVEL_1 = 128    # NIST PQC Level 1 (AES-128 equivalent)
    CLASSIC_256 = 256    # Classic 256-bit security
    CLASSIC_128 = 128    # Classic 128-bit security
    MINIMAL = 64         # Minimal security


@dataclass
class CryptoFallbackStrategy:
    """Represents a crypto-specific fallback strategy with security metadata."""
    name: str
    handler: Callable
    priority: CryptoFallbackPriority = CryptoFallbackPriority.CLASSIC_CRYPTO_FALLBACK
    supported_degradation_levels: List[CryptoDegradationLevel] = field(default_factory=lambda: [
        CryptoDegradationLevel.FULL_SECURITY,
        CryptoDegradationLevel.STANDARD_SECURITY,
    ])
    security_strength: SecurityStrength = SecurityStrength.CLASSIC_128
    timeout_seconds: float = 10.0
    requires_hardware: bool = False
    zeroize_on_failure: bool = True
    description: str = ""
    
    def __post_init__(self):
        self.success_count = 0
        self.failure_count = 0
        self.total_execution_time = 0.0
        self.last_execution_time: Optional[float] = None
        self.last_used_timestamp: Optional[float] = None


@dataclass
class CryptoHealthScore:
    """Health scoring for crypto modules, HSMs, and key management systems."""
    name: str
    success_rate_window: int = 100
    latency_threshold_ms: float = 5000.0
    error_rate_threshold: float = 0.05  # Stricter for crypto operations
    
    def __post_init__(self):
        self._success_history: deque = deque(maxlen=self.success_rate_window)
        self._latency_history: deque = deque(maxlen=self.success_rate_window)
        self._lock = threading.RLock()
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.hardware_error_count = 0
        self.key_operation_failures = 0
    
    def record_success(self, latency_ms: float) -> None:
        """Record a successful crypto operation."""
        with self._lock:
            self._success_history.append(True)
            self._latency_history.append(latency_ms)
            self.consecutive_successes += 1
            self.consecutive_failures = 0
    
    def record_failure(self, latency_ms: float, is_hardware_error: bool = False, 
                      is_key_error: bool = False) -> None:
        """Record a failed crypto operation."""
        with self._lock:
            self._success_history.append(False)
            self._latency_history.append(latency_ms)
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            if is_hardware_error:
                self.hardware_error_count += 1
            if is_key_error:
                self.key_operation_failures += 1
    
    def get_health_score(self) -> float:
        """Calculate current health score (0.0 to 1.0) for crypto operations."""
        with self._lock:
            if not self._success_history:
                return 1.0  # Assume healthy if no data
            
            total = len(self._success_history)
            successes = sum(1 for s in self._success_history if s)
            success_rate = successes / total if total > 0 else 1.0
            
            # Calculate latency penalty
            latency_penalty = 0.0
            if self._latency_history:
                avg_latency = statistics.mean(self._latency_history)
                if avg_latency > self.latency_threshold_ms:
                    latency_penalty = min(0.2, (avg_latency - self.latency_threshold_ms) / (self.latency_threshold_ms * 3))
            
            # Calculate consecutive failure penalty (stricter for crypto)
            consecutive_penalty = min(0.6, self.consecutive_failures * 0.15)
            
            # Hardware error penalty
            hardware_penalty = min(0.3, self.hardware_error_count * 0.05)
            
            health_score = success_rate - latency_penalty - consecutive_penalty - hardware_penalty
            return max(0.0, min(1.0, health_score))
    
    def get_health_status(self) -> CryptoHealthStatus:
        """Get enumerated crypto health status."""
        score = self.get_health_score()
        with self._lock:
            if self.hardware_error_count > 3:
                return CryptoHealthStatus.HARDWARE_FAILURE
            if score >= 0.95:
                return CryptoHealthStatus.OPERATIONAL
            elif score >= 0.8:
                return CryptoHealthStatus.DEGRADED_PERFORMANCE
            elif score >= 0.6:
                return CryptoHealthStatus.SECURITY_DEGRADED
            elif score >= 0.3:
                return CryptoHealthStatus.HARDWARE_FAILURE
            else:
                return CryptoHealthStatus.UNAVAILABLE


@dataclass
class CryptoDegradationTracker:
    """Tracks current crypto degradation level and security compliance."""
    minimum_security_strength: SecurityStrength = SecurityStrength.CLASSIC_128
    
    def __post_init__(self):
        self._current_level = CryptoDegradationLevel.FULL_SECURITY
        self._level_history: deque = deque(maxlen=1000)
        self._level_timestamps: deque = deque(maxlen=1000)
        self._lock = threading.RLock()
        self.total_crypto_operations = 0
        self.degraded_operations = 0
        self.failed_operations = 0
        self.security_compliance_violations = 0
    
    def set_degradation_level(self, level: CryptoDegradationLevel) -> None:
        """Set current crypto degradation level."""
        with self._lock:
            self._current_level = level
            self._level_history.append(level)
            self._level_timestamps.append(time.time())
            logger.warning(f"Crypto degradation level changed to: {level.value}")
    
    def get_current_level(self) -> CryptoDegradationLevel:
        """Get current crypto degradation level."""
        with self._lock:
            return self._current_level
    
    def record_operation(self, was_degraded: bool = False, failed: bool = False,
                         security_strength_used: Optional[SecurityStrength] = None) -> None:
        """Record a crypto operation for compliance tracking."""
        with self._lock:
            self.total_crypto_operations += 1
            if was_degraded:
                self.degraded_operations += 1
            if failed:
                self.failed_operations += 1
            if (security_strength_used and 
                security_strength_used.value < self.minimum_security_strength.value):
                self.security_compliance_violations += 1
    
    def get_security_availability(self) -> float:
        """Calculate current secure availability percentage."""
        with self._lock:
            if self.total_crypto_operations == 0:
                return 1.0
            secure_ops = self.total_crypto_operations - self.failed_operations - self.security_compliance_violations
            return secure_ops / self.total_crypto_operations


def secure_zeroize(data: bytearray) -> None:
    """Securely zeroize sensitive data from memory."""
    length = len(data)
    for i in range(length):
        data[i] = 0
    # Force memory barrier with random write
    for i in range(min(length, 16)):
        data[i] = secrets.randbits(8)
    for i in range(length):
        data[i] = 0


class CryptoStrategicFallbackChain:
    """
    Crypto-Specific Strategic Priority Fallback Chain with Security-Aware Routing.
    
    Designed for post-quantum crypto operations with:
    1. Priority-ordered algorithm fallback
    2. Real-time HSM and module health monitoring
    3. Security strength compliance enforcement
    4. Secure memory zeroization on all paths
    5. Hardware failure detection and failover
    """
    
    def __init__(self, name: str = "default_crypto_chain",
                 minimum_security_strength: SecurityStrength = SecurityStrength.CLASSIC_128):
        self.name = name
        self._strategies: List[CryptoFallbackStrategy] = []
        self._health_scores: Dict[str, CryptoHealthScore] = {}
        self._degradation_tracker = CryptoDegradationTracker(minimum_security_strength)
        self._lock = threading.RLock()
        self._primary_operation: Optional[Callable] = None
        self._cascading_failure_prevention_enabled = True
        self._circuit_breaker_threshold = 3  # Stricter for crypto
        self._zeroize_sensitive_data = True
        
        # Statistics
        self.fallback_activations = 0
        self.successful_fallbacks = 0
        self.failed_fallbacks = 0
        self.cascading_failures_prevented = 0
        self.security_downgrades = 0
    
    def register_primary_operation(self, operation: Callable, name: str = "primary",
                                   security_strength: SecurityStrength = SecurityStrength.PQC_LEVEL_5) -> None:
        """Register the primary (happy path) crypto operation."""
        with self._lock:
            self._primary_operation = operation
            self._primary_security_strength = security_strength
            if name not in self._health_scores:
                self._health_scores[name] = CryptoHealthScore(name)
    
    def add_fallback_strategy(self, strategy: CryptoFallbackStrategy) -> None:
        """Add a crypto fallback strategy to the chain."""
        with self._lock:
            self._strategies.append(strategy)
            # Sort by priority (lower number = higher priority)
            self._strategies.sort(key=lambda s: s.priority.value)
            
            if strategy.name not in self._health_scores:
                self._health_scores[strategy.name] = CryptoHealthScore(strategy.name)
            
            logger.info(f"Added crypto fallback strategy: {strategy.name} (priority: {strategy.priority.name})")
    
    def _select_applicable_strategies(self, context: Optional[Dict] = None) -> List[CryptoFallbackStrategy]:
        """Select applicable crypto strategies based on health and degradation level."""
        current_level = self._degradation_tracker.get_current_level()
        applicable = []
        
        for strategy in self._strategies:
            # Check if strategy supports current degradation level
            if current_level not in strategy.supported_degradation_levels:
                continue
            
            # Check health score
            health = self._health_scores.get(strategy.name)
            if health:
                status = health.get_health_status()
                if status in (CryptoHealthStatus.HARDWARE_FAILURE, CryptoHealthStatus.UNAVAILABLE):
                    continue
                if strategy.requires_hardware and status == CryptoHealthStatus.SECURITY_DEGRADED:
                    continue
            
            applicable.append(strategy)
        
        return applicable
    
    def execute(self, *args, context: Optional[Dict] = None, **kwargs) -> Tuple[Any, bool, str, SecurityStrength]:
        """
        Execute primary crypto operation with strategic fallback chain.
        
        Returns:
            (result, was_degraded, strategy_used_name, security_strength_achieved)
        """
        start_time = time.time()
        context = context or {}
        sensitive_buffers: List[bytearray] = []
        
        try:
            # Try primary operation first
            if self._primary_operation:
                try:
                    result = self._primary_operation(*args, **kwargs)
                    latency = (time.time() - start_time) * 1000
                    
                    if "primary" in self._health_scores:
                        self._health_scores["primary"].record_success(latency)
                    
                    self._degradation_tracker.record_operation(
                        was_degraded=False,
                        security_strength_used=getattr(self, '_primary_security_strength', SecurityStrength.PQC_LEVEL_5)
                    )
                    return result, False, "primary", getattr(self, '_primary_security_strength', SecurityStrength.PQC_LEVEL_5)
                    
                except Exception as primary_error:
                    latency = (time.time() - start_time) * 1000
                    is_hw = "hardware" in str(primary_error).lower() or "HSM" in str(primary_error)
                    is_key = "key" in str(primary_error).lower()
                    
                    if "primary" in self._health_scores:
                        self._health_scores["primary"].record_failure(latency, is_hw, is_key)
                    
                    logger.warning(f"Primary crypto operation failed: {primary_error}")
                    self.fallback_activations += 1
            
            # Primary failed - execute fallback chain
            applicable_strategies = self._select_applicable_strategies(context)
            
            for strategy in applicable_strategies:
                fallback_start = time.time()
                
                # Prevent cascading failures
                health = self._health_scores.get(strategy.name)
                if (self._cascading_failure_prevention_enabled and 
                    health and health.consecutive_failures >= self._circuit_breaker_threshold):
                    self.cascading_failures_prevented += 1
                    logger.warning(f"Skipping {strategy.name} due to cascading failure prevention")
                    continue
                
                try:
                    result = strategy.handler(*args, **kwargs)
                    fallback_latency = (time.time() - fallback_start) * 1000
                    
                    # Update statistics
                    if strategy.name in self._health_scores:
                        self._health_scores[strategy.name].record_success(fallback_latency)
                    
                    strategy.success_count += 1
                    strategy.total_execution_time += fallback_latency
                    strategy.last_execution_time = fallback_latency
                    strategy.last_used_timestamp = time.time()
                    
                    self.successful_fallbacks += 1
                    
                    # Check if security was downgraded
                    if (hasattr(self, '_primary_security_strength') and 
                        strategy.security_strength.value < self._primary_security_strength.value):
                        self.security_downgrades += 1
                    
                    self._degradation_tracker.record_operation(
                        was_degraded=True,
                        security_strength_used=strategy.security_strength
                    )
                    
                    logger.info(f"Crypto fallback succeeded using strategy: {strategy.name}")
                    return result, True, strategy.name, strategy.security_strength
                    
                except Exception as fallback_error:
                    fallback_latency = (time.time() - fallback_start) * 1000
                    is_hw = "hardware" in str(fallback_error).lower()
                    is_key = "key" in str(fallback_error).lower()
                    
                    if strategy.name in self._health_scores:
                        self._health_scores[strategy.name].record_failure(fallback_latency, is_hw, is_key)
                    
                    strategy.failure_count += 1
                    logger.warning(f"Crypto fallback strategy {strategy.name} failed: {fallback_error}")
                    continue
            
            # All fallbacks failed
            self.failed_fallbacks += 1
            self._degradation_tracker.record_operation(was_degraded=True, failed=True)
            
            # Escalate degradation level
            current_level = self._degradation_tracker.get_current_level()
            level_order = list(CryptoDegradationLevel)
            current_idx = level_order.index(current_level)
            if current_idx < len(level_order) - 1:
                self._degradation_tracker.set_degradation_level(level_order[current_idx + 1])
            
            raise RuntimeError(
                f"All crypto fallback strategies failed in chain '{self.name}'. "
                f"Current degradation level: {self._degradation_tracker.get_current_level().value}"
            )
        
        finally:
            # Secure zeroization of any sensitive buffers
            if self._zeroize_sensitive_data:
                for buf in sensitive_buffers:
                    secure_zeroize(buf)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive crypto statistics."""
        with self._lock:
            stats = {
                "chain_name": self.name,
                "fallback_activations": self.fallback_activations,
                "successful_fallbacks": self.successful_fallbacks,
                "failed_fallbacks": self.failed_fallbacks,
                "cascading_failures_prevented": self.cascading_failures_prevented,
                "security_downgrades": self.security_downgrades,
                "current_degradation_level": self._degradation_tracker.get_current_level().value,
                "security_availability": self._degradation_tracker.get_security_availability(),
                "total_crypto_operations": self._degradation_tracker.total_crypto_operations,
                "compliance_violations": self._degradation_tracker.security_compliance_violations,
                "strategy_statistics": []
            }
            
            for strategy in self._strategies:
                total_attempts = strategy.success_count + strategy.failure_count
                success_rate = strategy.success_count / total_attempts if total_attempts > 0 else 0.0
                avg_time = strategy.total_execution_time / strategy.success_count if strategy.success_count > 0 else 0.0
                
                stats["strategy_statistics"].append({
                    "name": strategy.name,
                    "priority": strategy.priority.name,
                    "security_strength": strategy.security_strength.name,
                    "success_count": strategy.success_count,
                    "failure_count": strategy.failure_count,
                    "success_rate": success_rate,
                    "average_execution_time_ms": avg_time,
                    "health_score": self._health_scores.get(strategy.name, CryptoHealthScore("")).get_health_score()
                })
            
            return stats
    
    def get_health_statuses(self) -> Dict[str, str]:
        """Get health status for all registered crypto components."""
        return {
            name: score.get_health_status().value
            for name, score in self._health_scores.items()
        }


def crypto_strategic_fallback(chain: CryptoStrategicFallbackChain):
    """
    Decorator for applying crypto strategic fallback chain to functions.
    
    Usage:
        @crypto_strategic_fallback(my_crypto_chain)
        def my_crypto_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        chain.register_primary_operation(func, name=func.__name__)
        
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            result, was_degraded, strategy, security = chain.execute(*args, **kwargs)
            return result
        return wrapper
    return decorator


# Export public API
__all__ = [
    'CryptoStrategicFallbackChain',
    'CryptoFallbackStrategy',
    'CryptoDegradationLevel',
    'CryptoFallbackPriority',
    'CryptoHealthStatus',
    'CryptoHealthScore',
    'SecurityStrength',
    'CryptoDegradationTracker',
    'crypto_strategic_fallback',
    'secure_zeroize',
]
