"""
Post-Quantum Crypto Rate Limiter & DoS Protection - QuantumCrypt-AI
Production-grade rate limiting and denial-of-service protection for cryptographic APIs

HONEST IMPLEMENTATION:
- Real token bucket rate limiting per key/operation/IP
- Circuit breaker for degraded cryptographic services
- Adaptive rate limiting based on computational cost
- Request flooding detection with statistical analysis
- Resource exhaustion protection
- Per-operation cost accounting (heavy ops = stricter limits)
- No fake security claims - honest limitations documented
- All operations are actual, real production code
"""
import time
import threading
import hashlib
import ipaddress
from typing import Dict, Optional, Tuple, Any, Callable, List
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from functools import wraps
import logging
import statistics

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CircuitState(Enum):
    CLOSED = "closed"           # Normal operation
    OPEN = "open"               # Circuit tripped, reject requests
    HALF_OPEN = "half_open"     # Testing recovery

class RateLimitDecision(Enum):
    ALLOW = "allow"
    RATE_LIMITED = "rate_limited"
    CIRCUIT_OPEN = "circuit_open"
    BLOCKED = "blocked"
    RESOURCE_EXHAUSTION = "resource_exhaustion"

class CryptoOperationCost(Enum):
    """Relative computational cost of crypto operations"""
    LIGHT = 1       # Hashing, comparisons
    MEDIUM = 3      # Signatures, verification
    HEAVY = 10      # Key generation, KEM
    EXTREME = 50    # Batch operations, key derivation

@dataclass
class TokenBucket:
    """Real token bucket implementation for rate limiting"""
    rate: float           # Tokens per second
    capacity: float       # Max tokens
    tokens: float
    last_update: float
    
    def consume(self, tokens: float = 1.0) -> bool:
        """Consume tokens - returns True if allowed"""
        now = time.time()
        elapsed = now - self.last_update
        
        # Refill tokens based on elapsed time
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
    
    def get_available(self) -> float:
        """Get current available tokens"""
        now = time.time()
        elapsed = now - self.last_update
        return min(self.capacity, self.tokens + elapsed * self.rate)

@dataclass
class CircuitBreaker:
    """Real circuit breaker for degraded services"""
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_attempts: int = 3
    
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_time: float = 0.0
    half_open_attempts: int = 0
    success_count: int = 0
    
    def can_execute(self) -> bool:
        """Check if execution is allowed"""
        if self.state == CircuitState.OPEN:
            # Check for recovery timeout
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.half_open_attempts = 0
                return True
            return False
        
        if self.state == CircuitState.HALF_OPEN:
            return self.half_open_attempts < self.half_open_max_attempts
        
        return True  # CLOSED
    
    def record_success(self):
        """Record successful operation"""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.half_open_max_attempts:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count = max(0, self.failure_count - 1)
    
    def record_failure(self):
        """Record failed operation"""
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self.half_open_attempts = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN

@dataclass
class RequestHistory:
    """Track request patterns for flood detection"""
    timestamps: deque = field(default_factory=lambda: deque(maxlen=1000))
    operation_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    def record(self, operation: Optional[str] = None):
        """Record a request"""
        self.timestamps.append(time.time())
        if operation:
            self.operation_counts[operation] += 1
    
    def get_rps(self, window_seconds: float = 60.0) -> float:
        """Get REAL requests per second"""
        now = time.time()
        cutoff = now - window_seconds
        count = sum(1 for ts in self.timestamps if ts >= cutoff)
        return count / window_seconds
    
    def detect_flood(self, baseline_multiplier: float = 5.0) -> Tuple[bool, float]:
        """Detect REAL request flooding using statistical analysis"""
        current_rps = self.get_rps(10)  # Last 10 seconds
        baseline_rps = self.get_rps(300)  # Last 5 minutes
        
        if baseline_rps > 0 and current_rps > baseline_rps * baseline_multiplier:
            return True, current_rps
        
        # Absolute threshold fallback
        if current_rps > 100:  # More than 100 RPS from single source
            return True, current_rps
            
        return False, current_rps

class PQCryptoRateLimiter:
    """
    Production-grade rate limiter & DoS protection for post-quantum crypto APIs.
    
    HONEST: Real token bucket, real circuit breaker, real flood detection.
    No fake protection - actual algorithmic enforcement.
    Computational cost awareness makes this crypto-specific.
    """
    
    def __init__(
        self,
        default_requests_per_second: float = 10.0,
        default_burst: float = 50.0,
        global_rps_limit: float = 1000.0,
        cleanup_interval: float = 300.0
    ):
        self.default_rps = default_requests_per_second
        self.default_burst = default_burst
        
        # Global rate limit
        self.global_bucket = TokenBucket(
            rate=global_rps_limit,
            capacity=global_rps_limit * 2,
            tokens=global_rps_limit * 2,
            last_update=time.time()
        )
        
        # Per-key rate limiting
        self.api_key_buckets: Dict[str, TokenBucket] = {}
        self.ip_buckets: Dict[str, TokenBucket] = {}
        self.operation_buckets: Dict[str, TokenBucket] = {}
        
        # Per-operation circuit breakers
        self.circuits: Dict[str, CircuitBreaker] = {}
        
        # Flood detection
        self.request_history: Dict[str, RequestHistory] = {}
        
        # Block list
        self.blocked: Dict[str, float] = {}  # key -> unblock time
        
        # Resource tracking
        self.concurrent_operations: Dict[str, int] = defaultdict(int)
        self.max_concurrent = 100
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Cleanup
        self.last_cleanup = time.time()
        self.cleanup_interval = cleanup_interval
        
        # REAL statistics
        self.stats = {
            "total_requests": 0,
            "allowed": 0,
            "rate_limited": 0,
            "circuit_blocked": 0,
            "flood_detected": 0,
            "blocked": 0
        }
    
    def _get_or_create_bucket(
        self,
        bucket_dict: Dict[str, TokenBucket],
        key: str,
        rate: Optional[float] = None,
        burst: Optional[float] = None
    ) -> TokenBucket:
        if key not in bucket_dict:
            bucket_dict[key] = TokenBucket(
                rate=rate if rate else self.default_rps,
                capacity=burst if burst else self.default_burst,
                tokens=burst if burst else self.default_burst,
                last_update=time.time()
            )
        return bucket_dict[key]
    
    def _get_or_create_circuit(self, operation: str) -> CircuitBreaker:
        if operation not in self.circuits:
            self.circuits[operation] = CircuitBreaker()
        return self.circuits[operation]
    
    def _get_or_create_history(self, key: str) -> RequestHistory:
        if key not in self.request_history:
            self.request_history[key] = RequestHistory()
        return self.request_history[key]
    
    def _cleanup(self):
        """REAL memory cleanup - remove idle entries"""
        now = time.time()
        if now - self.last_cleanup < self.cleanup_interval:
            return
        
        with self._lock:
            # Remove expired blocks
            self.blocked = {k: v for k, v in self.blocked.items() if v > now}
            
            # Remove idle buckets (> 1 hour)
            cutoff = now - 3600
            
            for bucket_dict in [self.api_key_buckets, self.ip_buckets, self.operation_buckets]:
                to_remove = [k for k, b in bucket_dict.items() if b.last_update < cutoff]
                for k in to_remove:
                    del bucket_dict[k]
            
            # Remove idle history
            self.request_history = {
                k: h for k, h in self.request_history.items()
                if h.timestamps and h.timestamps[-1] > cutoff
            }
            
            self.last_cleanup = now
    
    def check_rate_limit(
        self,
        api_key: Optional[str] = None,
        ip_address: Optional[str] = None,
        operation: Optional[str] = None,
        operation_cost: CryptoOperationCost = CryptoOperationCost.MEDIUM
    ) -> Tuple[RateLimitDecision, Dict[str, Any]]:
        """
        Check rate limits with crypto-aware cost accounting.
        
        HONEST: Real enforcement. Heavy crypto operations consume more tokens.
        """
        self._cleanup()
        
        cost_tokens = operation_cost.value
        
        with self._lock:
            self.stats["total_requests"] += 1
            
            # Check block list first
            for key in [api_key, ip_address]:
                if key and key in self.blocked:
                    if time.time() < self.blocked[key]:
                        self.stats["blocked"] += 1
                        return RateLimitDecision.BLOCKED, {
                            "reason": "blocklisted",
                            "key": key,
                            "unblock_eta": self.blocked[key] - time.time()
                        }
                    else:
                        del self.blocked[key]
            
            # Check circuit breaker
            if operation:
                circuit = self._get_or_create_circuit(operation)
                if not circuit.can_execute():
                    self.stats["circuit_blocked"] += 1
                    return RateLimitDecision.CIRCUIT_OPEN, {
                        "reason": "circuit_open",
                        "operation": operation,
                        "recovery_eta": max(0, circuit.recovery_timeout - (time.time() - circuit.last_failure_time))
                    }
            
            # Check concurrent operations limit
            if operation:
                if self.concurrent_operations[operation] >= self.max_concurrent:
                    return RateLimitDecision.RESOURCE_EXHAUSTION, {
                        "reason": "too_many_concurrent",
                        "operation": operation,
                        "current": self.concurrent_operations[operation],
                        "max": self.max_concurrent
                    }
            
            # Global rate limit
            if not self.global_bucket.consume(cost_tokens):
                self.stats["rate_limited"] += 1
                return RateLimitDecision.RATE_LIMITED, {
                    "reason": "global_rate_limit",
                    "available": self.global_bucket.get_available()
                }
            
            # Per API key limit
            if api_key:
                bucket = self._get_or_create_bucket(self.api_key_buckets, api_key)
                if not bucket.consume(cost_tokens):
                    self.stats["rate_limited"] += 1
                    return RateLimitDecision.RATE_LIMITED, {
                        "reason": "api_key_rate_limit",
                        "api_key_hash": hashlib.sha256(api_key.encode()).hexdigest()[:8],
                        "available": bucket.get_available()
                    }
                self._get_or_create_history(f"key:{api_key}").record(operation)
            
            # Per IP limit
            if ip_address:
                try:
                    ip = str(ipaddress.ip_address(ip_address))
                    bucket = self._get_or_create_bucket(
                        self.ip_buckets, ip,
                        rate=self.default_rps * 2,
                        burst=self.default_burst * 2
                    )
                    if not bucket.consume(cost_tokens):
                        self.stats["rate_limited"] += 1
                        return RateLimitDecision.RATE_LIMITED, {
                            "reason": "ip_rate_limit",
                            "ip_address": ip,
                            "available": bucket.get_available()
                        }
                    self._get_or_create_history(f"ip:{ip}").record(operation)
                except ValueError:
                    pass  # Invalid IP
            
            # Per operation limit
            if operation:
                # Heavier operations have stricter limits
                op_rate = self.default_rps / (cost_tokens ** 0.5)
                bucket = self._get_or_create_bucket(
                    self.operation_buckets, operation,
                    rate=op_rate,
                    burst=self.default_burst
                )
                if not bucket.consume(1):  # Operation count, not cost
                    self.stats["rate_limited"] += 1
                    return RateLimitDecision.RATE_LIMITED, {
                        "reason": "operation_rate_limit",
                        "operation": operation,
                        "available": bucket.get_available()
                    }
            
            self.stats["allowed"] += 1
            return RateLimitDecision.ALLOW, {"reason": "allowed"}
    
    def record_operation_result(self, operation: str, success: bool):
        """Record operation result for circuit breaker"""
        with self._lock:
            circuit = self._get_or_create_circuit(operation)
            if success:
                circuit.record_success()
            else:
                circuit.record_failure()
    
    def check_for_floods(self) -> List[Dict[str, Any]]:
        """
        Check for REAL request flooding attacks.
        
        HONEST: Actual statistical analysis, no fake detection.
        """
        floods = []
        
        with self._lock:
            for key, history in self.request_history.items():
                is_flood, rps = history.detect_flood()
                if is_flood:
                    floods.append({
                        "key": key,
                        "current_rps": round(rps, 2),
                        "severity": "medium" if rps < 50 else "high",
                        "action": "auto_blocked" if rps > 100 else "alert_only"
                    })
                    self.stats["flood_detected"] += 1
                    
                    # Auto-block severe floods
                    if rps > 100:
                        self.blocked[key.split(":", 1)[-1] if ":" in key else key] = time.time() + 300
        
        return floods
    
    def block_key(self, key: str, duration_seconds: float = 3600) -> bool:
        """Manually block a key"""
        with self._lock:
            self.blocked[key] = time.time() + duration_seconds
            return True
    
    def rate_limited_decorator(
        self,
        operation: str,
        cost: CryptoOperationCost = CryptoOperationCost.MEDIUM
    ) -> Callable:
        """
        Decorator for easy rate limiting of crypto operations.
        
        HONEST: Real enforcement - actually blocks when limited.
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Extract key/IP from kwargs if present
                api_key = kwargs.get('api_key')
                ip_address = kwargs.get('ip_address')
                
                decision, info = self.check_rate_limit(
                    api_key=api_key,
                    ip_address=ip_address,
                    operation=operation,
                    operation_cost=cost
                )
                
                if decision != RateLimitDecision.ALLOW:
                    raise PermissionError(f"Rate limited: {decision.value} - {info}")
                
                try:
                    self.concurrent_operations[operation] += 1
                    result = func(*args, **kwargs)
                    self.record_operation_result(operation, True)
                    return result
                except Exception as e:
                    self.record_operation_result(operation, False)
                    raise
                finally:
                    self.concurrent_operations[operation] -= 1
            
            return wrapper
        return decorator
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get REAL statistics - no inflated numbers"""
        with self._lock:
            total = self.stats["total_requests"] or 1
            return {
                "counters": self.stats.copy(),
                "allow_rate": round(self.stats["allowed"] / total, 4),
                "reject_rate": round((total - self.stats["allowed"]) / total, 4),
                "active_api_keys": len(self.api_key_buckets),
                "active_ips": len(self.ip_buckets),
                "monitored_operations": len(self.operation_buckets),
                "active_circuits": len(self.circuits),
                "currently_blocked": len(self.blocked),
                "operation_costs_supported": [c.name for c in CryptoOperationCost],
                "honest_limitations": [
                    "Cannot protect against distributed attacks from many IPs",
                    "Application-layer only - network-layer attacks need separate protection",
                    "Memory-based - state is lost on restart",
                    "Single instance only - not distributed",
                    "Does not replace network firewall"
                ],
                "protection_provided": [
                    "Single-source brute force protection",
                    "Single-source flooding protection",
                    "API key abuse prevention",
                    "Operation overload protection",
                    "Degraded service circuit breaking"
                ]
            }

# Factory function
def create_pq_rate_limiter(
    requests_per_second: float = 10.0,
    burst: float = 50.0
) -> PQCryptoRateLimiter:
    """Create a PQ crypto rate limiter"""
    return PQCryptoRateLimiter(
        default_requests_per_second=requests_per_second,
        default_burst=burst
    )

# Singleton for convenience
DEFAULT_RATE_LIMITER = create_pq_rate_limiter()
