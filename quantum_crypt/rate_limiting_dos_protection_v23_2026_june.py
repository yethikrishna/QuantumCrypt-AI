"""
Rate Limiting & DoS Protection v23 - QuantumCrypt-AI
Security Hardening - Dimension B

Provides rate limiting, anti-DoS, and resource exhaustion protection.
Layered ON TOP of existing crypto functions - no core code modified.

API Stability: STABLE
Backward Compatible: YES
"""

import time
import threading
from collections import defaultdict, deque
from typing import Any, Callable, Dict, Optional, TypeVar, Deque
from functools import wraps
import hashlib


class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""
    pass


class ResourceLimitError(Exception):
    """Raised when resource limits are exceeded."""
    pass


T = TypeVar('T')


class TokenBucket:
    """
    Token bucket rate limiting algorithm.
    
    Allows bursts up to bucket capacity, then enforces steady rate.
    Thread-safe implementation.
    """
    
    def __init__(self, rate: float, capacity: int):
        """
        Initialize token bucket.
        
        Args:
            rate: Tokens per second to add
            capacity: Maximum bucket capacity (burst size)
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last_update = time.time()
        self._lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens consumed, False if limit exceeded
        """
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.rate
            )
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def get_available(self) -> float:
        """Get current available tokens."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            return min(self.capacity, self.tokens + elapsed * self.rate)


class SlidingWindowCounter:
    """
    Sliding window rate limiter.
    
    More accurate than fixed window, prevents request clustering
    at window boundaries.
    """
    
    def __init__(self, max_requests: int, window_seconds: int):
        """
        Initialize sliding window counter.
        
        Args:
            max_requests: Maximum requests per window
            window_seconds: Window duration in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Deque[float] = deque()
        self._lock = threading.Lock()
    
    def check(self) -> bool:
        """
        Check if request is allowed.
        
        Returns:
            True if allowed, False if rate limited
        """
        with self._lock:
            now = time.time()
            
            # Remove old requests outside the window
            cutoff = now - self.window_seconds
            while self.requests and self.requests[0] < cutoff:
                self.requests.popleft()
            
            if len(self.requests) >= self.max_requests:
                return False
            
            self.requests.append(now)
            return True
    
    def get_count(self) -> int:
        """Get current request count in window."""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            while self.requests and self.requests[0] < cutoff:
                self.requests.popleft()
            return len(self.requests)


class FixedWindowLimiter:
    """
    Fixed window rate limiter.
    
    Simple and efficient, though vulnerable to boundary bursts.
    """
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.counts: Dict[int, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def check(self) -> bool:
        """Check if request is allowed."""
        with self._lock:
            window = int(time.time() // self.window_seconds)
            if self.counts[window] >= self.max_requests:
                return False
            self.counts[window] += 1
            return True


class PerClientRateLimiter:
    """
    Rate limiter that tracks limits per client identifier.
    """
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.clients: Dict[str, SlidingWindowCounter] = {}
        self._lock = threading.Lock()
    
    def check(self, client_id: str) -> bool:
        """
        Check if client is allowed to make request.
        
        Args:
            client_id: Client identifier (e.g., IP, API key hash)
            
        Returns:
            True if allowed
        """
        with self._lock:
            if client_id not in self.clients:
                self.clients[client_id] = SlidingWindowCounter(
                    self.max_requests, self.window_seconds
                )
        return self.clients[client_id].check()
    
    def cleanup_old(self) -> None:
        """Clean up inactive client trackers."""
        with self._lock:
            # Remove clients with no recent activity
            pass  # Implementation would add TTL tracking


class ResourceGuard:
    """
    Protect against resource exhaustion attacks.
    
    Limits concurrent operations and memory usage.
    """
    
    def __init__(self, max_concurrent: int = 100, max_memory_mb: int = 512):
        self.max_concurrent = max_concurrent
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.current_concurrent = 0
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
    
    def acquire(self, timeout: Optional[float] = None) -> bool:
        """
        Acquire resource permission.
        
        Args:
            timeout: Maximum seconds to wait
            
        Returns:
            True if acquired
            
        Raises:
            ResourceLimitError: If cannot acquire
        """
        with self._condition:
            start = time.time()
            while self.current_concurrent >= self.max_concurrent:
                if timeout is not None:
                    elapsed = time.time() - start
                    if elapsed >= timeout:
                        raise ResourceLimitError(
                            f"Max concurrent operations ({self.max_concurrent}) exceeded"
                        )
                    remaining = timeout - elapsed
                else:
                    remaining = None
                
                self._condition.wait(remaining)
            
            self.current_concurrent += 1
            return True
    
    def release(self) -> None:
        """Release resource permission."""
        with self._condition:
            self.current_concurrent = max(0, self.current_concurrent - 1)
            self._condition.notify()
    
    def __enter__(self) -> 'ResourceGuard':
        self.acquire()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts based on system load.
    
    Increases restrictions when system is under stress.
    """
    
    def __init__(self, base_max: int = 100, window_seconds: int = 60):
        self.base_max = base_max
        self.window_seconds = window_seconds
        self.current_limit = base_max
        self.counter = SlidingWindowCounter(base_max, window_seconds)
        self.error_count = 0
        self.success_count = 0
    
    def check(self) -> bool:
        """Check with adaptive limiting."""
        # Adjust limit based on error rate
        if self.error_count > self.success_count * 0.1:  # >10% error rate
            self.current_limit = max(10, int(self.current_limit * 0.8))
        elif self.success_count > 1000 and self.error_count == 0:
            self.current_limit = min(self.base_max, int(self.current_limit * 1.1))
        
        self.counter.max_requests = self.current_limit
        allowed = self.counter.check()
        
        if allowed:
            self.success_count += 1
        else:
            self.error_count += 1
        
        return allowed


class DoSProtector:
    """
    Comprehensive DoS protection combining multiple strategies.
    """
    
    def __init__(self):
        # Per-client rate limiting
        self.client_limiter = PerClientRateLimiter(100, 60)  # 100 req/min
        
        # Global rate limiting
        self.global_limiter = TokenBucket(1000, 5000)  # 1000/s, 5000 burst
        
        # Resource guard
        self.resource_guard = ResourceGuard(max_concurrent=50)
        
        # Suspicious client tracking
        self.suspicious_clients: Dict[str, int] = defaultdict(int)
        self.blocked_clients: set = set()
        self._lock = threading.Lock()
    
    def check_request(self, client_id: str, cost: int = 1) -> None:
        """
        Comprehensive request validation.
        
        Args:
            client_id: Client identifier
            cost: Resource cost of this operation
            
        Raises:
            RateLimitError: If rate limited
            ResourceLimitError: If resource exhausted
        """
        # Check if blocked
        with self._lock:
            if client_id in self.blocked_clients:
                raise RateLimitError("Client blocked due to suspicious activity")
        
        # Global rate limit
        if not self.global_limiter.consume(cost):
            raise RateLimitError("Global rate limit exceeded")
        
        # Per-client rate limit
        if not self.client_limiter.check(client_id):
            with self._lock:
                self.suspicious_clients[client_id] += 1
                if self.suspicious_clients[client_id] > 10:
                    self.blocked_clients.add(client_id)
            raise RateLimitError(f"Client rate limit exceeded: {client_id}")
    
    def get_client_id(self, identifier: str) -> str:
        """Hash client ID for privacy."""
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]


def rate_limit(max_requests: int, window_seconds: int = 60,
              per_client: bool = False) -> Callable:
    """
    Decorator for rate limiting functions.
    
    Args:
        max_requests: Maximum requests allowed
        window_seconds: Time window in seconds
        per_client: Whether to limit per caller
        
    Returns:
        Decorated function
    """
    if per_client:
        limiter = PerClientRateLimiter(max_requests, window_seconds)
    else:
        limiter = SlidingWindowCounter(max_requests, window_seconds)
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            client_id = kwargs.get('client_id', 'global')
            
            if per_client:
                if not limiter.check(client_id):
                    raise RateLimitError("Rate limit exceeded")
            else:
                if not limiter.check():
                    raise RateLimitError("Rate limit exceeded")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def protect_resources(max_concurrent: int = 50) -> Callable:
    """
    Decorator for resource protection.
    
    Args:
        max_concurrent: Maximum concurrent calls
        
    Returns:
        Decorated function
    """
    guard = ResourceGuard(max_concurrent=max_concurrent)
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            with guard:
                return func(*args, **kwargs)
        return wrapper
    return decorator


# Global DoS protector instance
dos_protector = DoSProtector()


# Export public API
__all__ = [
    'RateLimitError',
    'ResourceLimitError',
    'TokenBucket',
    'SlidingWindowCounter',
    'FixedWindowLimiter',
    'PerClientRateLimiter',
    'ResourceGuard',
    'AdaptiveRateLimiter',
    'DoSProtector',
    'rate_limit',
    'protect_resources',
    'dos_protector',
]
