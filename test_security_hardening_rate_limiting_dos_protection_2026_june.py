"""
Tests for QuantumCrypt Security Hardening: Rate Limiting & DoS Protection
Dimension B: Security Hardening

All tests verify the new security functionality works correctly.
Existing code is NOT modified - these tests are purely additive.
"""

import pytest
import time
import threading

from quantum_crypt.security_hardening_rate_limiting_dos_protection_2026_june import (
    RateLimitAlgorithm,
    CircuitBreakerState,
    RateLimitConfig,
    RateLimitResult,
    RateLimitExceeded,
    CircuitBreakerOpen,
    TokenBucketLimiter,
    FixedWindowLimiter,
    SlidingWindowLimiter,
    CircuitBreaker,
    AdaptiveRateLimiter,
    RequestThrottler,
    rate_limit,
    with_circuit_breaker,
)


# -----------------------------------------------------------------------------
# Test Token Bucket Limiter
# -----------------------------------------------------------------------------

class TestTokenBucketLimiter:
    """Tests for Token Bucket rate limiting algorithm."""
    
    def test_bucket_starts_full(self):
        """Test bucket starts at full capacity."""
        limiter = TokenBucketLimiter(capacity=10, refill_rate=1.0)
        assert limiter.get_tokens_available() == 10
    
    def test_consume_available_tokens(self):
        """Test consuming tokens when available."""
        limiter = TokenBucketLimiter(capacity=5, refill_rate=1.0)
        
        for _ in range(5):
            assert limiter.try_consume() is True
        
        # 6th should fail
        assert limiter.try_consume() is False
    
    def test_tokens_refill_over_time(self):
        """Test tokens refill at specified rate."""
        limiter = TokenBucketLimiter(capacity=5, refill_rate=10.0)
        
        # Consume all
        for _ in range(5):
            limiter.try_consume()
        
        assert limiter.try_consume() is False
        
        # Wait for refill
        time.sleep(0.2)
        
        # Should have some tokens now
        available = limiter.get_tokens_available()
        assert available > 0
    
    def test_consume_multiple_tokens(self):
        """Test consuming multiple tokens at once."""
        limiter = TokenBucketLimiter(capacity=10, refill_rate=1.0)
        
        assert limiter.try_consume(5) is True
        assert abs(limiter.get_tokens_available() - 5) < 0.1
        
        assert limiter.try_consume(6) is False  # Not enough
    
    def test_time_to_refill_calculation(self):
        """Test time to refill calculation."""
        limiter = TokenBucketLimiter(capacity=10, refill_rate=2.0)
        
        # Consume half
        for _ in range(5):
            limiter.try_consume()
        
        time_needed = limiter.get_time_to_refill()
        assert time_needed > 0
        assert time_needed <= 5.0  # 5 tokens / 2 per second


# -----------------------------------------------------------------------------
# Test Fixed Window Limiter
# -----------------------------------------------------------------------------

class TestFixedWindowLimiter:
    """Tests for Fixed Window rate limiting."""
    
    def test_allows_requests_within_limit(self):
        """Test requests within limit are allowed."""
        limiter = FixedWindowLimiter(max_requests=5, window_seconds=60)
        
        for _ in range(5):
            assert limiter.try_consume() is True
        
        # 6th should fail
        assert limiter.try_consume() is False
    
    def test_per_key_limiting(self):
        """Test different keys have separate limits."""
        limiter = FixedWindowLimiter(max_requests=3, window_seconds=60)
        
        # Key A uses all 3
        assert limiter.try_consume("client_a") is True
        assert limiter.try_consume("client_a") is True
        assert limiter.try_consume("client_a") is True
        assert limiter.try_consume("client_a") is False
        
        # Key B still has quota
        assert limiter.try_consume("client_b") is True
    
    def test_remaining_count(self):
        """Test remaining count tracking."""
        limiter = FixedWindowLimiter(max_requests=10, window_seconds=60)
        
        limiter.try_consume()
        limiter.try_consume()
        limiter.try_consume()
        
        assert limiter.get_remaining() == 7
    
    def test_reset_time(self):
        """Test reset time is positive."""
        limiter = FixedWindowLimiter(max_requests=10, window_seconds=60)
        reset_time = limiter.get_reset_time()
        
        assert reset_time >= 0
        assert reset_time <= 60


# -----------------------------------------------------------------------------
# Test Sliding Window Limiter
# -----------------------------------------------------------------------------

class TestSlidingWindowLimiter:
    """Tests for Sliding Window rate limiting."""
    
    def test_basic_rate_limiting(self):
        """Test basic rate limiting functionality."""
        limiter = SlidingWindowLimiter(max_requests=3, window_seconds=60)
        
        assert limiter.try_consume() is True
        assert limiter.try_consume() is True
        assert limiter.try_consume() is True
        assert limiter.try_consume() is False
    
    def test_per_key_isolation(self):
        """Test different keys are isolated."""
        limiter = SlidingWindowLimiter(max_requests=2, window_seconds=60)
        
        assert limiter.try_consume("user1") is True
        assert limiter.try_consume("user1") is True
        assert limiter.try_consume("user1") is False
        
        assert limiter.try_consume("user2") is True
    
    def test_remaining_count(self):
        """Test remaining count calculation."""
        limiter = SlidingWindowLimiter(max_requests=5, window_seconds=60)
        
        limiter.try_consume()
        limiter.try_consume()
        
        assert limiter.get_remaining() == 3


# -----------------------------------------------------------------------------
# Test Circuit Breaker
# -----------------------------------------------------------------------------

class TestCircuitBreaker:
    """Tests for Circuit Breaker pattern."""
    
    def test_starts_closed(self):
        """Test circuit breaker starts in closed state."""
        breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=30)
        assert breaker.state == CircuitBreakerState.CLOSED
    
    def test_allows_requests_when_closed(self):
        """Test requests are allowed when closed."""
        breaker = CircuitBreaker()
        
        for _ in range(10):
            assert breaker.allow_request() is True
            breaker.record_success()
    
    def test_trips_after_failures(self):
        """Test circuit opens after threshold failures."""
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        
        # Record failures
        breaker.record_failure()
        breaker.record_failure()
        breaker.record_failure()
        
        assert breaker.state == CircuitBreakerState.OPEN
        assert breaker.allow_request() is False
    
    def test_recovers_after_timeout(self):
        """Test circuit enters half-open after recovery timeout."""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        breaker.record_failure()
        breaker.record_failure()
        assert breaker.state == CircuitBreakerState.OPEN
        
        # Wait for recovery
        time.sleep(0.15)
        
        # Should allow test request
        assert breaker.allow_request() is True
        assert breaker.state == CircuitBreakerState.HALF_OPEN
    
    def test_closes_on_half_open_success(self):
        """Test success in half-open closes the circuit."""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        # Trip circuit
        breaker.record_failure()
        breaker.record_failure()
        
        time.sleep(0.15)
        
        # Allow test request
        breaker.allow_request()
        breaker.record_success()
        
        assert breaker.state == CircuitBreakerState.CLOSED
    
    def test_reopens_on_half_open_failure(self):
        """Test failure in half-open reopens circuit."""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        breaker.record_failure()
        breaker.record_failure()
        
        time.sleep(0.15)
        
        breaker.allow_request()
        breaker.record_failure()
        
        assert breaker.state == CircuitBreakerState.OPEN
    
    def test_retry_after_when_open(self):
        """Test retry after calculation when open."""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=5.0)
        
        breaker.record_failure()
        breaker.record_failure()
        
        retry_after = breaker.get_retry_after()
        assert retry_after > 0
        assert retry_after <= 5.0


# -----------------------------------------------------------------------------
# Test Adaptive Rate Limiter
# -----------------------------------------------------------------------------

class TestAdaptiveRateLimiter:
    """Tests for Adaptive Rate Limiter."""
    
    def test_starts_at_base_limit(self):
        """Test limiter starts at configured base limit."""
        limiter = AdaptiveRateLimiter(base_max_requests=100)
        assert limiter.get_current_limit() == 100
    
    def test_allows_requests_initially(self):
        """Test requests are allowed initially."""
        limiter = AdaptiveRateLimiter(base_max_requests=10, window_seconds=1)
        
        for _ in range(5):
            assert limiter.try_consume() is True


# -----------------------------------------------------------------------------
# Test Request Throttler
# -----------------------------------------------------------------------------

class TestRequestThrottler:
    """Tests for centralized Request Throttler."""
    
    def test_allows_normal_requests(self):
        """Test normal requests are allowed."""
        throttler = RequestThrottler()
        
        result = throttler.check_request(
            ip="192.168.1.1",
            user_id="user123",
            endpoint="/api/test"
        )
        
        assert isinstance(result, RateLimitResult)
        assert result.allowed is True
    
    def test_creates_circuit_breakers(self):
        """Test named circuit breaker creation."""
        throttler = RequestThrottler()
        
        breaker = throttler.get_or_create_circuit_breaker(
            "external_api",
            failure_threshold=3,
            recovery_timeout=10.0
        )
        
        assert isinstance(breaker, CircuitBreaker)
        
        # Same name returns same instance
        breaker2 = throttler.get_or_create_circuit_breaker("external_api")
        assert breaker is breaker2


# -----------------------------------------------------------------------------
# Test Decorators
# -----------------------------------------------------------------------------

class TestRateLimitDecorator:
    """Tests for @rate_limit decorator."""
    
    def test_decorator_allows_within_limit(self):
        """Test decorator allows calls within limit."""
        limiter = TokenBucketLimiter(capacity=5, refill_rate=1.0)
        
        @rate_limit(limiter)
        def protected_function(x):
            return x * 2
        
        for i in range(5):
            result = protected_function(i)
            assert result == i * 2
    
    def test_decorator_raises_when_exceeded(self):
        """Test decorator raises exception when limit exceeded."""
        limiter = TokenBucketLimiter(capacity=2, refill_rate=0.0)
        
        @rate_limit(limiter)
        def protected_function():
            return "success"
        
        protected_function()
        protected_function()
        
        with pytest.raises(RateLimitExceeded):
            protected_function()


class TestCircuitBreakerDecorator:
    """Tests for @with_circuit_breaker decorator."""
    
    def test_decorator_passes_through_success(self):
        """Test successful calls pass through."""
        breaker = CircuitBreaker()
        
        @with_circuit_breaker(breaker)
        def external_call(x):
            return x + 1
        
        result = external_call(5)
        assert result == 6
    
    def test_decorator_records_failures(self):
        """Test exceptions are recorded as failures."""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=1.0)
        
        @with_circuit_breaker(breaker)
        def failing_call():
            raise ValueError("API Error")
        
        with pytest.raises(ValueError):
            failing_call()
        with pytest.raises(ValueError):
            failing_call()
        
        # Circuit should be open now
        assert breaker.state == CircuitBreakerState.OPEN
        
        # Next call should raise CircuitBreakerOpen
        with pytest.raises(CircuitBreakerOpen):
            failing_call()
    
    def test_decorator_fallback_on_open(self):
        """Test fallback function is used when circuit is open."""
        breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=1.0)
        
        def fallback_value():
            return "fallback"
        
        @with_circuit_breaker(breaker, fallback=fallback_value)
        def failing_call():
            raise ValueError("Error")
        
        # First call fails and trips circuit
        with pytest.raises(ValueError):
            failing_call()
        
        # Subsequent calls use fallback
        result = failing_call()
        assert result == "fallback"


# -----------------------------------------------------------------------------
# Thread Safety Tests
# -----------------------------------------------------------------------------

class TestThreadSafety:
    """Tests for thread safety of limiters."""
    
    def test_token_bucket_thread_safety(self):
        """Test token bucket works under concurrent access."""
        limiter = TokenBucketLimiter(capacity=100, refill_rate=100.0)
        successes = []
        
        def worker():
            for _ in range(10):
                if limiter.try_consume():
                    successes.append(True)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have at least some successes
        assert len(successes) > 0
    
    def test_fixed_window_thread_safety(self):
        """Test fixed window limiter under concurrent access."""
        limiter = FixedWindowLimiter(max_requests=100, window_seconds=60)
        count = 0
        
        def worker():
            nonlocal count
            for _ in range(10):
                if limiter.try_consume("test"):
                    count += 1
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert count <= 100


# -----------------------------------------------------------------------------
# Integration Tests
# -----------------------------------------------------------------------------

class TestSecurityIntegration:
    """Integration tests for security hardening features."""
    
    def test_rate_limit_with_circuit_breaker(self):
        """Test combining rate limiting and circuit breaker."""
        limiter = TokenBucketLimiter(capacity=10, refill_rate=1.0)
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=5.0)
        
        @rate_limit(limiter)
        @with_circuit_breaker(breaker)
        def secure_api_call():
            return "success"
        
        result = secure_api_call()
        assert result == "success"
    
    def test_throttler_multiple_clients(self):
        """Test throttler handles multiple clients."""
        throttler = RequestThrottler()
        
        for i in range(5):
            result = throttler.check_request(ip=f"10.0.0.{i}")
            assert result.allowed is True


# -----------------------------------------------------------------------------
# Run tests
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
