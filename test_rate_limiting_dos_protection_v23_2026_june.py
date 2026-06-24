"""
Tests for Rate Limiting & DoS Protection v23 - QuantumCrypt-AI
Security Hardening - Dimension B
"""

import pytest
import time
import threading
from quantum_crypt.rate_limiting_dos_protection_v23_2026_june import (
    TokenBucket,
    SlidingWindowCounter,
    FixedWindowLimiter,
    PerClientRateLimiter,
    ResourceGuard,
    AdaptiveRateLimiter,
    DoSProtector,
    rate_limit,
    protect_resources,
    dos_protector,
    RateLimitError,
    ResourceLimitError,
)


class TestTokenBucket:
    """Tests for TokenBucket rate limiter."""
    
    def test_initialization(self):
        """Test bucket initialization."""
        bucket = TokenBucket(rate=10, capacity=100)
        assert bucket.rate == 10
        assert bucket.capacity == 100
        assert bucket.tokens == 100
    
    def test_consume_success(self):
        """Test successful token consumption."""
        bucket = TokenBucket(rate=10, capacity=100)
        assert bucket.consume(1) is True
        assert bucket.tokens == 99
    
    def test_consume_multiple(self):
        """Test consuming multiple tokens."""
        bucket = TokenBucket(rate=10, capacity=100)
        assert bucket.consume(50) is True
        assert bucket.tokens == 50
    
    def test_consume_exhausted(self):
        """Test consuming when bucket is empty."""
        bucket = TokenBucket(rate=10, capacity=10)
        for _ in range(10):
            bucket.consume(1)
        assert bucket.consume(1) is False
    
    def test_get_available(self):
        """Test getting available tokens."""
        bucket = TokenBucket(rate=10, capacity=100)
        bucket.consume(50)
        available = bucket.get_available()
        assert 50 <= available <= 51  # Account for tiny time passing


class TestSlidingWindowCounter:
    """Tests for SlidingWindowCounter."""
    
    def test_initialization(self):
        """Test counter initialization."""
        counter = SlidingWindowCounter(max_requests=10, window_seconds=60)
        assert counter.max_requests == 10
        assert counter.window_seconds == 60
    
    def test_check_allow(self):
        """Test allowing requests within limit."""
        counter = SlidingWindowCounter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert counter.check() is True
    
    def test_check_deny(self):
        """Test denying requests over limit."""
        counter = SlidingWindowCounter(max_requests=3, window_seconds=60)
        for _ in range(3):
            counter.check()
        assert counter.check() is False
    
    def test_get_count(self):
        """Test getting current request count."""
        counter = SlidingWindowCounter(max_requests=10, window_seconds=60)
        for _ in range(5):
            counter.check()
        assert counter.get_count() == 5
    
    def test_window_expiry(self):
        """Test requests expire after window."""
        counter = SlidingWindowCounter(max_requests=5, window_seconds=1)
        for _ in range(5):
            counter.check()
        time.sleep(1.1)
        # After window passes, should allow again
        assert counter.check() is True


class TestFixedWindowLimiter:
    """Tests for FixedWindowLimiter."""
    
    def test_check_allow(self):
        """Test allowing requests within limit."""
        limiter = FixedWindowLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert limiter.check() is True
    
    def test_check_deny(self):
        """Test denying requests over limit."""
        limiter = FixedWindowLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.check()
        assert limiter.check() is False


class TestPerClientRateLimiter:
    """Tests for PerClientRateLimiter."""
    
    def test_check_per_client(self):
        """Test per-client rate limiting."""
        limiter = PerClientRateLimiter(max_requests=3, window_seconds=60)
        
        # Client A can make 3 requests
        for _ in range(3):
            assert limiter.check("client_A") is True
        
        # Client A is now limited
        assert limiter.check("client_A") is False
        
        # Client B can still make requests
        for _ in range(3):
            assert limiter.check("client_B") is True


class TestResourceGuard:
    """Tests for ResourceGuard."""
    
    def test_initialization(self):
        """Test guard initialization."""
        guard = ResourceGuard(max_concurrent=10)
        assert guard.max_concurrent == 10
        assert guard.current_concurrent == 0
    
    def test_acquire_release(self):
        """Test acquire and release."""
        guard = ResourceGuard(max_concurrent=10)
        guard.acquire()
        assert guard.current_concurrent == 1
        guard.release()
        assert guard.current_concurrent == 0
    
    def test_context_manager(self):
        """Test context manager usage."""
        guard = ResourceGuard(max_concurrent=10)
        with guard:
            assert guard.current_concurrent == 1
        assert guard.current_concurrent == 0
    
    def test_concurrent_limit(self):
        """Test concurrent limit enforcement."""
        guard = ResourceGuard(max_concurrent=1)
        guard.acquire()
        
        # Second acquire should timeout
        with pytest.raises(ResourceLimitError):
            guard.acquire(timeout=0.01)
        
        guard.release()
    
    def test_nested_context_managers(self):
        """Test nested context managers."""
        guard = ResourceGuard(max_concurrent=2)
        with guard:
            assert guard.current_concurrent == 1
            with guard:
                assert guard.current_concurrent == 2
            assert guard.current_concurrent == 1
        assert guard.current_concurrent == 0


class TestAdaptiveRateLimiter:
    """Tests for AdaptiveRateLimiter."""
    
    def test_initialization(self):
        """Test adaptive limiter initialization."""
        limiter = AdaptiveRateLimiter(base_max=100)
        assert limiter.base_max == 100
        assert limiter.current_limit == 100
    
    def test_check_basic(self):
        """Test basic check functionality."""
        limiter = AdaptiveRateLimiter(base_max=10, window_seconds=60)
        for _ in range(10):
            assert limiter.check() is True


class TestDoSProtector:
    """Tests for DoSProtector."""
    
    def test_initialization(self):
        """Test DoS protector initialization."""
        protector = DoSProtector()
        assert protector.client_limiter is not None
        assert protector.global_limiter is not None
        assert protector.resource_guard is not None
    
    def test_check_request_allow(self):
        """Test allowing valid requests."""
        protector = DoSProtector()
        # Should not raise
        protector.check_request("test_client")
    
    def test_get_client_id(self):
        """Test client ID hashing."""
        protector = DoSProtector()
        client_id = protector.get_client_id("192.168.1.1")
        assert len(client_id) == 16  # 16 hex chars = 64 bits


class TestDecorators:
    """Tests for rate limit decorators."""
    
    def test_rate_limit_decorator(self):
        """Test rate_limit decorator."""
        @rate_limit(max_requests=5, window_seconds=60)
        def protected_func():
            return "success"
        
        # Should work 5 times
        for _ in range(5):
            assert protected_func() == "success"
        
        # Should raise on 6th
        with pytest.raises(RateLimitError):
            protected_func()
    
    def test_protect_resources_decorator(self):
        """Test protect_resources decorator."""
        @protect_resources(max_concurrent=2)
        def protected_func():
            return "success"
        
        # Should work
        assert protected_func() == "success"


class TestGlobalInstance:
    """Tests for global dos_protector instance."""
    
    def test_global_instance_exists(self):
        """Test global protector instance exists."""
        assert dos_protector is not None
        assert isinstance(dos_protector, DoSProtector)


class TestThreadSafety:
    """Tests for thread safety."""
    
    def test_token_bucket_thread_safety(self):
        """Test token bucket is thread safe."""
        bucket = TokenBucket(rate=100, capacity=1000)
        
        def consume_many():
            for _ in range(100):
                bucket.consume(1)
        
        threads = [threading.Thread(target=consume_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have consumed ~500 tokens (allow small delta for time passing)
        assert 499 <= bucket.tokens <= 501


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
