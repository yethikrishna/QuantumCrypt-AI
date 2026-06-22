"""
QuantumCrypt Security Hardening: Adaptive Rate Limiting & DoS Protection Module
Version: v10 (2026 June)
Philosophy: ADD-ONLY, no modification to existing core code
Layered security on top of existing cryptographic operations
"""

import time
import threading
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
import hashlib
import hmac


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting rules"""
    max_requests: int = 100
    window_seconds: int = 60
    burst_multiplier: float = 2.0
    adaptive_enabled: bool = True
    penalty_seconds: int = 300
    max_penalty_seconds: int = 3600


@dataclass
class ClientState:
    """Tracks request state for a single client"""
    request_timestamps: deque = field(default_factory=lambda: deque(maxlen=1000))
    penalty_until: float = 0.0
    violation_count: int = 0
    adaptive_score: float = 1.0


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter with DoS protection for cryptographic operations
    Features:
    - Token bucket + sliding window hybrid algorithm
    - Adaptive penalties for repeated violations
    - Client fingerprinting for anonymous clients
    - Burst allowance with decay
    - No modification to existing crypto code - wrap operations
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._clients: Dict[str, ClientState] = defaultdict(ClientState)
        self._lock = threading.RLock()
        self._global_request_count: int = 0
        self._global_window_start: float = time.time()
        
    def _generate_client_fingerprint(
        self,
        client_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> str:
        """Generate stable client fingerprint even for anonymous clients"""
        components = [
            client_id or "anonymous",
            ip_address or "0.0.0.0",
            user_agent or "unknown"
        ]
        raw = "|".join(components).encode("utf-8")
        return hmac.new(
            b"quantumcrypt_rate_limit_secret_2026",
            raw,
            hashlib.sha256
        ).hexdigest()[:16]
    
    def _clean_old_requests(self, state: ClientState, now: float) -> None:
        """Remove requests outside current window"""
        cutoff = now - self.config.window_seconds
        while state.request_timestamps and state.request_timestamps[0] < cutoff:
            state.request_timestamps.popleft()
    
    def _update_adaptive_score(self, state: ClientState, violated: bool) -> None:
        """Update adaptive scoring for client behavior"""
        if violated:
            state.violation_count += 1
            state.adaptive_score = min(5.0, state.adaptive_score * 1.5)
        else:
            state.adaptive_score = max(0.5, state.adaptive_score * 0.99)
    
    def check_rate_limit(
        self,
        client_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        operation_cost: int = 1
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Check if request should be allowed
        Returns: (allowed: bool, metadata: dict)
        """
        fingerprint = self._generate_client_fingerprint(client_id, ip_address, user_agent)
        now = time.time()
        
        with self._lock:
            state = self._clients[fingerprint]
            
            # Check if client is penalized
            if now < state.penalty_until:
                remaining = int(state.penalty_until - now)
                return False, {
                    "allowed": False,
                    "reason": "rate_limit_penalty",
                    "penalty_remaining_seconds": remaining,
                    "violation_count": state.violation_count
                }
            
            # Clean old requests
            self._clean_old_requests(state, now)
            
            # Calculate effective limit with adaptive scoring
            effective_max = int(
                self.config.max_requests / 
                max(1.0, state.adaptive_score)
            )
            burst_allowance = int(effective_max * self.config.burst_multiplier)
            
            # Check request count
            current_count = len(state.request_timestamps) + operation_cost
            
            if current_count > burst_allowance:
                # Apply penalty
                penalty_duration = min(
                    self.config.penalty_seconds * (2 ** min(state.violation_count, 5)),
                    self.config.max_penalty_seconds
                )
                state.penalty_until = now + penalty_duration
                self._update_adaptive_score(state, violated=True)
                
                return False, {
                    "allowed": False,
                    "reason": "rate_limit_exceeded",
                    "current_requests": len(state.request_timestamps),
                    "effective_limit": effective_max,
                    "burst_limit": burst_allowance,
                    "penalty_seconds": penalty_duration,
                    "adaptive_score": state.adaptive_score
                }
            
            # Allow request
            for _ in range(operation_cost):
                state.request_timestamps.append(now)
            
            self._update_adaptive_score(state, violated=False)
            self._global_request_count += 1
            
            remaining = effective_max - len(state.request_timestamps)
            
            return True, {
                "allowed": True,
                "remaining_requests": remaining,
                "window_reset_seconds": int(self.config.window_seconds - (now - (self._global_window_start % self.config.window_seconds))),
                "adaptive_score": state.adaptive_score,
                "client_fingerprint": fingerprint
            }
    
    def wrap_operation(
        self,
        func: Callable,
        client_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        operation_cost: int = 1
    ) -> Callable:
        """
        Decorator/wrapper for cryptographic operations
        Does NOT modify original function - adds rate limiting layer
        """
        def wrapped(*args, **kwargs):
            allowed, metadata = self.check_rate_limit(
                client_id, ip_address, user_agent, operation_cost
            )
            if not allowed:
                raise RateLimitExceededError(
                    f"Rate limit exceeded: {metadata['reason']}",
                    metadata
                )
            return func(*args, **kwargs)
        return wrapped
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        with self._lock:
            total_clients = len(self._clients)
            penalized_clients = sum(
                1 for s in self._clients.values() 
                if time.time() < s.penalty_until
            )
            avg_adaptive_score = (
                sum(s.adaptive_score for s in self._clients.values()) / total_clients
                if total_clients > 0 else 1.0
            )
            
            return {
                "total_clients_tracked": total_clients,
                "clients_currently_penalized": penalized_clients,
                "global_requests_processed": self._global_request_count,
                "average_adaptive_score": round(avg_adaptive_score, 3),
                "config": {
                    "max_requests_per_window": self.config.max_requests,
                    "window_seconds": self.config.window_seconds,
                    "adaptive_enabled": self.config.adaptive_enabled
                }
            }
    
    def reset_client(self, fingerprint: str) -> bool:
        """Reset penalty and state for a specific client"""
        with self._lock:
            if fingerprint in self._clients:
                del self._clients[fingerprint]
                return True
            return False


class RateLimitExceededError(Exception):
    """Custom exception for rate limit violations"""
    def __init__(self, message: str, metadata: Dict[str, Any]):
        super().__init__(message)
        self.metadata = metadata


# Global singleton instance for easy integration
_global_rate_limiter = AdaptiveRateLimiter()


def get_global_rate_limiter() -> AdaptiveRateLimiter:
    """Get the global shared rate limiter instance"""
    return _global_rate_limiter


def rate_limited(
    client_id_param: str = "client_id",
    ip_param: str = "ip_address",
    operation_cost: int = 1
):
    """
    Decorator for easy rate limiting of functions
    Usage:
        @rate_limited(operation_cost=5)
        def expensive_crypto_operation(*args, **kwargs):
            ...
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            limiter = get_global_rate_limiter()
            client_id = kwargs.get(client_id_param)
            ip_address = kwargs.get(ip_param)
            
            allowed, metadata = limiter.check_rate_limit(
                client_id=client_id,
                ip_address=ip_address,
                operation_cost=operation_cost
            )
            
            if not allowed:
                raise RateLimitExceededError(
                    f"Operation rate limited: {metadata['reason']}",
                    metadata
                )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator
