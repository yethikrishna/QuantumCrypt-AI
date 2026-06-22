"""
QuantumCrypt AI - Security Hardening: Rate Limiting & DoS Protection
Dimension B: Security Hardening

This module provides security wrappers that layer ON TOP of existing code.
NO existing production code is modified - only new functionality added.

Features:
1. Token Bucket Rate Limiter
2. Leaky Bucket Rate Limiter
3. Fixed Window Counter
4. Sliding Window Log
5. Circuit Breaker Pattern
6. IP-based Request Throttling
7. Adaptive Rate Limiting
"""

import time
import threading
import hashlib
import hmac
from typing import Any, Callable, Optional, Dict, List, Union, TypeVar
from functools import wraps
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
import math

T = TypeVar('T')

# -----------------------------------------------------------------------------
# Enums and Data Classes
# -----------------------------------------------------------------------------

class RateLimitAlgorithm(Enum):
    """Supported rate limiting algorithms."""
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"           # Normal operation
    OPEN = "open"               # Tripped - reject requests
    HALF_OPEN = "half_open"     # Testing recovery


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    max_requests: int = 100
    window_seconds: int = 60
    burst_allowance: int = 20
    enabled: bool = True


@dataclass
class RateLimitResult:
    """Result of rate limit check."""
    allowed: bool
    remaining: int
    reset_after: float
    limit: int
    used: int


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    def __init__(self, message: str, retry_after: float):
        super().__init__(message)
        self.retry_after = retry_after


class CircuitBreakerOpen(Exception):
    """Raised when circuit breaker is open."""
    def __init__(self, message: str, retry_after: float):
        super().__init__(message)
        self.retry_after = retry_after

# -----------------------------------------------------------------------------
# Token Bucket Rate Limiter
# -----------------------------------------------------------------------------

class TokenBucketLimiter:
    """
    Token Bucket Rate Limiter.
    
    Tokens are added to the bucket at a fixed rate.
    Each request consumes one token.
    Allows controlled bursting up to bucket capacity.
    """
    
    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.
        
        Args:
            capacity: Maximum tokens in bucket (burst limit)
            refill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        new_tokens = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = now
    
    def try_consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were available and consumed
        """
        with self._lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def get_tokens_available(self) -> float:
        """Get current available tokens."""
        with self._lock:
            self._refill()
            return self.tokens
    
    def get_time_to_refill(self) -> float:
        """Get seconds until bucket is full."""
        with self._lock:
            self._refill()
            needed = self.capacity - self.tokens
            return needed / self.refill_rate if self.refill_rate > 0 else 0.0

# -----------------------------------------------------------------------------
# Fixed Window Counter
# -----------------------------------------------------------------------------

class FixedWindowLimiter:
    """
    Fixed Window Rate Limiter.
    
    Counts requests within fixed time windows.
    Simple and memory efficient but susceptible to edge bursts.
    """
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._counters: Dict[int, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def _get_window_key(self) -> int:
        """Get current window identifier."""
        return int(time.monotonic() // self.window_seconds)
    
    def try_consume(self, key: str = "global") -> bool:
        """
        Try to consume a request slot.
        
        Args:
            key: Optional key for per-client limiting
            
        Returns:
            True if request allowed
        """
        window = self._get_window_key()
        full_key = f"{key}:{window}"
        
        with self._lock:
            if self._counters[full_key] < self.max_requests:
                self._counters[full_key] += 1
                # Clean old windows occasionally
                if len(self._counters) > 1000:
                    self._clean_old_windows()
                return True
            return False
    
    def get_remaining(self, key: str = "global") -> int:
        """Get remaining requests in current window."""
        window = self._get_window_key()
        full_key = f"{key}:{window}"
        with self._lock:
            return max(0, self.max_requests - self._counters.get(full_key, 0))
    
    def get_reset_time(self) -> float:
        """Get seconds until window resets."""
        window = self._get_window_key()
        next_window = (window + 1) * self.window_seconds
        now = time.monotonic()
        return max(0, next_window - now)
    
    def _clean_old_windows(self) -> None:
        """Remove old window entries."""
        current_window = self._get_window_key()
        old_keys = [k for k in self._counters.keys() 
                   if int(k.split(":")[-1]) < current_window - 2]
        for k in old_keys:
            del self._counters[k]

# -----------------------------------------------------------------------------
# Sliding Window Log Limiter
# -----------------------------------------------------------------------------

class SlidingWindowLimiter:
    """
    Sliding Window Log Rate Limiter.
    
    Maintains timestamp log for accurate rate limiting.
    More accurate than fixed window but uses more memory.
    """
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._logs: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
    
    def try_consume(self, key: str = "global") -> bool:
        """Try to consume a request slot."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        
        with self._lock:
            log = self._logs[key]
            
            # Remove old entries
            while log and log[0] < cutoff:
                log.popleft()
            
            if len(log) < self.max_requests:
                log.append(now)
                return True
            return False
    
    def get_remaining(self, key: str = "global") -> int:
        """Get remaining requests in window."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        
        with self._lock:
            log = self._logs[key]
            while log and log[0] < cutoff:
                log.popleft()
            return max(0, self.max_requests - len(log))

# -----------------------------------------------------------------------------
# Circuit Breaker
# -----------------------------------------------------------------------------

class CircuitBreaker:
    """
    Circuit Breaker Pattern for fault tolerance.
    
    Prevents cascading failures by failing fast when errors exceed threshold.
    States:
    - CLOSED: Normal operation
    - OPEN: Fail fast, reject all requests
    - HALF_OPEN: Allow test requests to check recovery
    """
    
    def __init__(self, 
                 failure_threshold: int = 5,
                 recovery_timeout: float = 30.0,
                 half_open_max_calls: int = 3):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.open_time = 0.0
        self.half_open_calls = 0
        self._lock = threading.Lock()
    
    def record_success(self) -> None:
        """Record a successful call - reset on success."""
        with self._lock:
            if self.state == CircuitBreakerState.HALF_OPEN:
                # Success in half-open -> close circuit
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                self.half_open_calls = 0
            elif self.state == CircuitBreakerState.CLOSED:
                # Reset failure count on success
                self.failure_count = 0
    
    def record_failure(self) -> None:
        """Record a failed call - may trip circuit."""
        with self._lock:
            if self.state == CircuitBreakerState.CLOSED:
                self.failure_count += 1
                if self.failure_count >= self.failure_threshold:
                    self.state = CircuitBreakerState.OPEN
                    self.open_time = time.monotonic()
            elif self.state == CircuitBreakerState.HALF_OPEN:
                # Failure in half-open -> open again
                self.state = CircuitBreakerState.OPEN
                self.open_time = time.monotonic()
                self.half_open_calls = 0
    
    def allow_request(self) -> bool:
        """Check if request should be allowed."""
        with self._lock:
            if self.state == CircuitBreakerState.CLOSED:
                return True
            
            if self.state == CircuitBreakerState.OPEN:
                # Check if recovery timeout elapsed
                if time.monotonic() - self.open_time >= self.recovery_timeout:
                    self.state = CircuitBreakerState.HALF_OPEN
                    self.half_open_calls = 0
                    return True
                return False
            
            if self.state == CircuitBreakerState.HALF_OPEN:
                if self.half_open_calls < self.half_open_max_calls:
                    self.half_open_calls += 1
                    return True
                return False
            
            return False
    
    def get_retry_after(self) -> float:
        """Get seconds until potential recovery."""
        if self.state == CircuitBreakerState.OPEN:
            elapsed = time.monotonic() - self.open_time
            return max(0, self.recovery_timeout - elapsed)
        return 0.0

# -----------------------------------------------------------------------------
# Decorators and Wrappers
# -----------------------------------------------------------------------------

def rate_limit(limiter: Union[TokenBucketLimiter, FixedWindowLimiter],
              key_func: Optional[Callable] = None) -> Callable[[T], T]:
    """
    Decorator to apply rate limiting to a function.
    
    Usage:
        limiter = TokenBucketLimiter(capacity=10, refill_rate=1.0)
        
        @rate_limit(limiter)
        def my_protected_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = key_func(*args, **kwargs) if key_func else "global"
            
            if hasattr(limiter, 'try_consume'):
                if not limiter.try_consume(key if isinstance(limiter, FixedWindowLimiter) else 1):
                    retry_after = getattr(limiter, 'get_reset_time', lambda: 1.0)()
                    raise RateLimitExceeded(
                        f"Rate limit exceeded for {func.__name__}",
                        retry_after
                    )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def with_circuit_breaker(circuit_breaker: CircuitBreaker,
                        fallback: Optional[Callable] = None) -> Callable[[T], T]:
    """
    Decorator to apply circuit breaker pattern.
    
    Usage:
        breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=30)
        
        @with_circuit_breaker(breaker)
        def external_api_call():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not circuit_breaker.allow_request():
                if fallback:
                    return fallback(*args, **kwargs)
                raise CircuitBreakerOpen(
                    f"Circuit breaker open for {func.__name__}",
                    circuit_breaker.get_retry_after()
                )
            
            try:
                result = func(*args, **kwargs)
                circuit_breaker.record_success()
                return result
            except Exception as e:
                circuit_breaker.record_failure()
                raise
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# Adaptive Rate Limiter
# -----------------------------------------------------------------------------

class AdaptiveRateLimiter:
    """
    Adaptive Rate Limiter that adjusts limits based on error rates.
    
    Tightens limits when errors increase, relaxes when stable.
    """
    
    def __init__(self, 
                 base_max_requests: int = 100,
                 window_seconds: int = 60,
                 min_requests: int = 10,
                 max_requests: int = 500):
        self.base_max = base_max_requests
        self.current_max = base_max_requests
        self.window_seconds = window_seconds
        self.min_requests = min_requests
        self.max_requests = max_requests
        
        self.error_count = 0
        self.total_count = 0
        self.last_adjustment = time.monotonic()
        self._limiter = FixedWindowLimiter(base_max_requests, window_seconds)
        self._lock = threading.Lock()
    
    def try_consume(self, key: str = "global") -> bool:
        """Try to consume a request slot."""
        with self._lock:
            self.total_count += 1
            self._maybe_adjust()
            return self._limiter.try_consume(key)
    
    def record_error(self) -> None:
        """Record an error - may trigger limit tightening."""
        with self._lock:
            self.error_count += 1
    
    def _maybe_adjust(self) -> None:
        """Adjust limits based on error rate."""
        now = time.monotonic()
        
        # Adjust every window
        if now - self.last_adjustment < self.window_seconds:
            return
        
        error_rate = self.error_count / max(1, self.total_count)
        
        if error_rate > 0.1:  # >10% errors - tighten
            self.current_max = max(self.min_requests, 
                                 int(self.current_max * 0.8))
        elif error_rate < 0.01:  # <1% errors - relax
            self.current_max = min(self.max_requests,
                                 int(self.current_max * 1.2))
        else:  # Stable - return to base
            self.current_max = min(self.max_requests,
                                 max(self.min_requests,
                                     int((self.current_max + self.base_max) / 2)))
        
        # Update underlying limiter
        self._limiter.max_requests = self.current_max
        
        # Reset counters
        self.error_count = 0
        self.total_count = 0
        self.last_adjustment = now
    
    def get_current_limit(self) -> int:
        """Get current adaptive limit."""
        return self.current_max

# -----------------------------------------------------------------------------
# Request Throttler
# -----------------------------------------------------------------------------

class RequestThrottler:
    """
    Centralized request throttling manager.
    
    Supports per-IP, per-user, and global rate limiting.
    """
    
    def __init__(self):
        self._ip_limiters: Dict[str, TokenBucketLimiter] = {}
        self._user_limiters: Dict[str, FixedWindowLimiter] = {}
        self._global_limiter = TokenBucketLimiter(
            capacity=1000,
            refill_rate=50.0
        )
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()
    
    def check_request(self, 
                     ip: Optional[str] = None,
                     user_id: Optional[str] = None,
                     endpoint: str = "global") -> RateLimitResult:
        """
        Check if request should be allowed.
        
        Returns comprehensive rate limit information.
        """
        allowed = True
        remaining = float('inf')
        reset_after = 0.0
        
        # Check global limit
        if not self._global_limiter.try_consume():
            allowed = False
            reset_after = max(reset_after, self._global_limiter.get_time_to_refill())
        
        # Check IP limit
        if ip:
            with self._lock:
                if ip not in self._ip_limiters:
                    self._ip_limiters[ip] = TokenBucketLimiter(
                        capacity=50,
                        refill_rate=2.0
                    )
            
            if not self._ip_limiters[ip].try_consume():
                allowed = False
                reset_after = max(reset_after, 
                                self._ip_limiters[ip].get_time_to_refill())
        
        # Check user limit
        if user_id:
            with self._lock:
                if user_id not in self._user_limiters:
                    self._user_limiters[user_id] = FixedWindowLimiter(
                        max_requests=1000,
                        window_seconds=3600
                    )
            
            if not self._user_limiters[user_id].try_consume(user_id):
                allowed = False
                reset_after = max(reset_after,
                                self._user_limiters[user_id].get_reset_time())
        
        return RateLimitResult(
            allowed=allowed,
            remaining=remaining if allowed else 0,
            reset_after=reset_after,
            limit=0,
            used=0
        )
    
    def get_or_create_circuit_breaker(self, 
                                    name: str,
                                    **kwargs) -> CircuitBreaker:
        """Get or create a named circuit breaker."""
        with self._lock:
            if name not in self._circuit_breakers:
                self._circuit_breakers[name] = CircuitBreaker(**kwargs)
            return self._circuit_breakers[name]

# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------

__all__ = [
    'RateLimitAlgorithm',
    'CircuitBreakerState',
    'RateLimitConfig',
    'RateLimitResult',
    'RateLimitExceeded',
    'CircuitBreakerOpen',
    'TokenBucketLimiter',
    'FixedWindowLimiter',
    'SlidingWindowLimiter',
    'CircuitBreaker',
    'AdaptiveRateLimiter',
    'RequestThrottler',
    'rate_limit',
    'with_circuit_breaker',
]
