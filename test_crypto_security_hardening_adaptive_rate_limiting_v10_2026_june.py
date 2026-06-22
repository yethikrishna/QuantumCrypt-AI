"""
Test Suite for Enhanced Adaptive Rate Limiting & DoS Protection v10
Dimension B - Security Hardening
June 22, 2026
"""

import pytest
import time
import threading
from quantum_crypt import (
    EnhancedRateLimitConfig,
    EnhancedAdaptiveRateLimiter,
    RateLimitExceededError,
    get_global_rate_limiter,
    rate_limited,
)


class TestRateLimitConfig:
    """Test rate limit configuration"""
    
    def test_default_config(self):
        config = EnhancedRateLimitConfig()
        assert config.max_requests == 100
        assert config.window_seconds == 60
        assert config.burst_multiplier == 2.0
        assert config.adaptive_enabled is True
    
    def test_custom_config(self):
        config = EnhancedRateLimitConfig(
            max_requests=50,
            window_seconds=30,
            burst_multiplier=1.5
        )
        assert config.max_requests == 50
        assert config.window_seconds == 30
        assert config.burst_multiplier == 1.5


class TestAdaptiveRateLimiter:
    """Test core rate limiter functionality"""
    
    def test_basic_rate_limiting(self):
        config = EnhancedRateLimitConfig(max_requests=5, window_seconds=60)
        limiter = EnhancedAdaptiveRateLimiter(config)
        
        # Same client for all requests
        client_id = "test_client_single"
        
        # Allow first 10 requests (burst = 5 * 2 = 10)
        for i in range(10):
            allowed, meta = limiter.check_rate_limit(client_id=client_id)
            assert allowed is True
        
        # 11th request should be blocked
        allowed, meta = limiter.check_rate_limit(client_id=client_id)
        assert allowed is False
        assert meta["reason"] == "rate_limit_exceeded"
    
    def test_client_fingerprinting(self):
        limiter = EnhancedAdaptiveRateLimiter()
        
        # Same client should get same fingerprint
        fp1 = limiter._generate_client_fingerprint(
            client_id="user123",
            ip_address="192.168.1.1",
            user_agent="test/1.0"
        )
        fp2 = limiter._generate_client_fingerprint(
            client_id="user123",
            ip_address="192.168.1.1",
            user_agent="test/1.0"
        )
        assert fp1 == fp2
        
        # Different clients get different fingerprints
        fp3 = limiter._generate_client_fingerprint(
            client_id="user456",
            ip_address="192.168.1.2"
        )
        assert fp1 != fp3
    
    def test_operation_cost_weighting(self):
        config = EnhancedRateLimitConfig(max_requests=10, window_seconds=60)
        limiter = EnhancedAdaptiveRateLimiter(config)
        
        # Operation with cost 5 counts as 5 requests
        allowed, meta = limiter.check_rate_limit(
            client_id="cost_test",
            operation_cost=5
        )
        assert allowed is True
        assert meta["remaining_requests"] == 5  # 10 - 5 = 5
    
    def test_penalty_system(self):
        config = EnhancedRateLimitConfig(
            max_requests=2,
            window_seconds=60,
            penalty_seconds=2
        )
        limiter = EnhancedAdaptiveRateLimiter(config)
        
        # Exceed limit (burst = 4, so 5th triggers penalty)
        for _ in range(5):
            limiter.check_rate_limit(client_id="penalty_test")
        
        # Should be penalized
        allowed, meta = limiter.check_rate_limit(client_id="penalty_test")
        assert allowed is False
        assert meta["reason"] == "rate_limit_penalty"
        # Penalty should be active
        assert meta["penalty_remaining_seconds"] >= 0
        assert limiter._clients[limiter._generate_client_fingerprint("penalty_test")].penalty_until > time.time()
    
    def test_adaptive_scoring(self):
        config = EnhancedRateLimitConfig(max_requests=10, window_seconds=60)
        limiter = EnhancedAdaptiveRateLimiter(config)
        
        # Well-behaved client should have lower score (more allowance)
        for _ in range(5):
            limiter.check_rate_limit(client_id="good_client")
        
        # Violate once
        for _ in range(25):  # exceed limit
            limiter.check_rate_limit(client_id="bad_client")
        
        stats = limiter.get_stats()
        assert stats["average_adaptive_score"] > 1.0  # bad client increases average
    
    def test_thread_safety(self):
        config = EnhancedRateLimitConfig(max_requests=100, window_seconds=60)
        limiter = EnhancedAdaptiveRateLimiter(config)
        
        errors = []
        
        def worker():
            try:
                for _ in range(10):
                    limiter.check_rate_limit(client_id=f"thread_{threading.get_ident()}")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
    
    def test_stats_collection(self):
        limiter = EnhancedAdaptiveRateLimiter()
        
        # Make some requests
        for i in range(10):
            limiter.check_rate_limit(client_id=f"stats_client_{i}")
        
        stats = limiter.get_stats()
        assert stats["total_clients_tracked"] == 10
        assert stats["global_requests_processed"] == 10
        assert "config" in stats
    
    def test_client_reset(self):
        limiter = EnhancedAdaptiveRateLimiter()
        
        # Add a client
        allowed, meta = limiter.check_rate_limit(client_id="reset_client")
        fingerprint = meta["client_fingerprint"]
        
        # Reset should work
        assert limiter.reset_client(fingerprint) is True
        
        # Reset non-existent should return False
        assert limiter.reset_client("non_existent_fingerprint") is False


class TestDecoratorIntegration:
    """Test decorator and wrapper functionality"""
    
    def test_rate_limited_decorator(self):
        # Reset global limiter state first
        global_limiter = get_global_rate_limiter()
        global_limiter._clients.clear()
        
        # Override global limiter config for testing
        original_config = global_limiter.config
        global_limiter.config = EnhancedRateLimitConfig(max_requests=3, window_seconds=60)
        
        @rate_limited(operation_cost=1)
        def test_function(client_id=None, ip_address=None):
            return "success"
        
        try:
            # Should work 3 times (burst = 6, so 6 allowed, need 7th to trigger)
            for _ in range(6):
                result = test_function(client_id="decorator_test", ip_address="1.2.3.4")
                assert result == "success"
            
            # 7th should raise exception
            with pytest.raises(RateLimitExceededError):
                test_function(client_id="decorator_test", ip_address="1.2.3.4")
        finally:
            # Restore original config
            global_limiter.config = original_config
            global_limiter._clients.clear()
    
    def test_wrap_operation(self):
        config = EnhancedRateLimitConfig(max_requests=2, window_seconds=60)
        limiter = EnhancedAdaptiveRateLimiter(config)
        
        def original_func(x):
            return x * 2
        
        wrapped = limiter.wrap_operation(original_func, client_id="wrap_test")
        
        # Burst allowance = 2 * 2 = 4, so first 4 calls allowed
        assert wrapped(5) == 10
        assert wrapped(10) == 20
        assert wrapped(15) == 30
        assert wrapped(20) == 40
        
        # 5th call should fail
        with pytest.raises(RateLimitExceededError):
            wrapped(25)


class TestGlobalInstance:
    """Test global singleton instance"""
    
    def test_global_instance_exists(self):
        limiter = get_global_rate_limiter()
        assert limiter is not None
        assert isinstance(limiter, EnhancedAdaptiveRateLimiter)
    
    def test_global_instance_is_singleton(self):
        limiter1 = get_global_rate_limiter()
        limiter2 = get_global_rate_limiter()
        assert limiter1 is limiter2


class TestBackwardCompatibility:
    """Verify no breakage of existing code"""
    
    def test_existing_imports_still_work(self):
        # Verify existing rate limiter imports still work
        from quantum_crypt import (
            RateLimitAlgorithm,
            TokenBucketLimiter,
            AdaptiveRateLimiter as OldAdaptiveRateLimiter,
        )
        assert RateLimitAlgorithm is not None
        assert TokenBucketLimiter is not None
        assert OldAdaptiveRateLimiter is not None
    
    def test_new_and_old_coexist(self):
        # Both old and new rate limiters should work independently
        from quantum_crypt import AdaptiveRateLimiter as OldLimiter
        new_limiter = EnhancedAdaptiveRateLimiter()
        
        assert OldLimiter is not EnhancedAdaptiveRateLimiter
        assert isinstance(new_limiter, EnhancedAdaptiveRateLimiter)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
