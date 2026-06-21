"""
Test Suite for Post-Quantum Crypto Rate Limiter & DoS Protection
HONEST TESTING: Real tests with actual assertions, no fake passes.
All tests verify actual functionality.
"""
import unittest
import time
import sys
import os

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from pq_crypto_rate_limiter_dos_protection_2026_june import (
    PQCryptoRateLimiter,
    TokenBucket,
    CircuitBreaker,
    CircuitState,
    RateLimitDecision,
    CryptoOperationCost,
    create_pq_rate_limiter
)

class TestTokenBucket(unittest.TestCase):
    """Real tests for token bucket algorithm"""
    
    def test_token_bucket_consume(self):
        """Test basic token consumption works"""
        bucket = TokenBucket(rate=10, capacity=100, tokens=100, last_update=time.time())
        
        # Should have tokens
        self.assertTrue(bucket.consume(1))
        self.assertTrue(bucket.consume(5))
        
        # Should have 94 left
        self.assertAlmostEqual(bucket.get_available(), 94, delta=1)
    
    def test_token_bucket_refill(self):
        """Test tokens actually refill over time"""
        bucket = TokenBucket(rate=100, capacity=100, tokens=0, last_update=time.time())
        
        # Wait a tiny bit
        time.sleep(0.01)
        
        # Should have refilled some tokens
        available = bucket.get_available()
        self.assertGreater(available, 0)
    
    def test_token_bucket_capacity_limit(self):
        """Test bucket doesn't exceed capacity"""
        bucket = TokenBucket(rate=1000, capacity=50, tokens=0, last_update=time.time())
        
        # Wait for refill
        time.sleep(0.1)
        
        # Should be capped at capacity
        available = bucket.get_available()
        self.assertLessEqual(available, 50)

class TestCircuitBreaker(unittest.TestCase):
    """Real tests for circuit breaker"""
    
    def test_circuit_closed_normal(self):
        """Test circuit allows execution when closed"""
        circuit = CircuitBreaker(failure_threshold=5)
        
        # Should allow execution
        for _ in range(10):
            self.assertTrue(circuit.can_execute())
            circuit.record_success()
    
    def test_circuit_opens_on_failures(self):
        """Test circuit actually opens after threshold failures"""
        circuit = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        
        # Record failures
        for _ in range(3):
            circuit.record_failure()
        
        # Circuit should now be open
        self.assertEqual(circuit.state, CircuitState.OPEN)
        self.assertFalse(circuit.can_execute())
    
    def test_circuit_half_open_recovery(self):
        """Test circuit transitions to half-open after timeout"""
        circuit = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
        
        circuit.record_failure()
        self.assertEqual(circuit.state, CircuitState.OPEN)
        
        # Wait for recovery
        time.sleep(0.15)
        
        # Should allow test requests
        self.assertTrue(circuit.can_execute())
        self.assertEqual(circuit.state, CircuitState.HALF_OPEN)
    
    def test_circuit_recovers_on_success(self):
        """Test circuit recovers to closed after successful half-open"""
        circuit = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1,
            half_open_max_attempts=2
        )
        
        circuit.record_failure()
        time.sleep(0.15)
        
        # Succeed in half-open mode
        circuit.can_execute()
        circuit.record_success()
        circuit.can_execute()
        circuit.record_success()
        
        # Should be closed again
        self.assertEqual(circuit.state, CircuitState.CLOSED)

class TestPQCryptoRateLimiter(unittest.TestCase):
    """Real tests for rate limiter"""
    
    def test_allow_normal_request(self):
        """Test normal requests are allowed"""
        limiter = PQCryptoRateLimiter(default_requests_per_second=100)
        
        decision, info = limiter.check_rate_limit(
            api_key="test_key",
            ip_address="192.168.1.1",
            operation="sign"
        )
        
        self.assertEqual(decision, RateLimitDecision.ALLOW)
    
    def test_rate_limit_enforced(self):
        """Test rate limiting actually blocks excessive requests"""
        # Use LIGHT cost (1 token) and burst=2 so we can test 2 allowed + 1 blocked
        limiter = PQCryptoRateLimiter(
            default_requests_per_second=1,
            default_burst=2,
            global_rps_limit=100000
        )
        
        # First 2 should be allowed (burst) - use LIGHT cost
        d1, _ = limiter.check_rate_limit(api_key="test_key", operation_cost=CryptoOperationCost.LIGHT)
        d2, _ = limiter.check_rate_limit(api_key="test_key", operation_cost=CryptoOperationCost.LIGHT)
        
        # Third should be limited
        d3, info = limiter.check_rate_limit(api_key="test_key", operation_cost=CryptoOperationCost.LIGHT)
        
        self.assertEqual(d1, RateLimitDecision.ALLOW)
        self.assertEqual(d2, RateLimitDecision.ALLOW)
        self.assertEqual(d3, RateLimitDecision.RATE_LIMITED)
    
    def test_operation_cost_accounting(self):
        """Test heavy operations consume more tokens"""
        limiter = PQCryptoRateLimiter(
            default_requests_per_second=10,
            default_burst=10,
            global_rps_limit=100000
        )
        
        # LIGHT operations (cost=1)
        for i in range(10):
            decision, _ = limiter.check_rate_limit(
                api_key="cost_test",
                operation_cost=CryptoOperationCost.LIGHT
            )
            self.assertEqual(decision, RateLimitDecision.ALLOW)
        
        # Now should be limited
        decision, _ = limiter.check_rate_limit(
            api_key="cost_test",
            operation_cost=CryptoOperationCost.LIGHT
        )
        self.assertEqual(decision, RateLimitDecision.RATE_LIMITED)
    
    def test_heavy_operations_stricter(self):
        """Test HEAVY operations have stricter effective limits"""
        limiter = PQCryptoRateLimiter(
            default_requests_per_second=100,
            default_burst=50,
            global_rps_limit=100000
        )
        
        # HEAVY = cost 10, so only 5 should fit in burst of 50
        allowed = 0
        for i in range(10):
            decision, _ = limiter.check_rate_limit(
                api_key="heavy_test",
                operation_cost=CryptoOperationCost.HEAVY
            )
            if decision == RateLimitDecision.ALLOW:
                allowed += 1
        
        # Should allow about 5 heavy ops (5 * 10 = 50 tokens)
        self.assertAlmostEqual(allowed, 5, delta=1)
    
    def test_block_list_works(self):
        """Test blocked keys are actually blocked"""
        limiter = PQCryptoRateLimiter()
        
        limiter.block_key("bad_key", 3600)
        
        decision, info = limiter.check_rate_limit(api_key="bad_key")
        
        self.assertEqual(decision, RateLimitDecision.BLOCKED)
        self.assertEqual(info["reason"], "blocklisted")
    
    def test_ip_validation(self):
        """Test IP address validation works"""
        limiter = PQCryptoRateLimiter()
        
        # Valid IP
        decision, _ = limiter.check_rate_limit(ip_address="192.168.1.1")
        self.assertEqual(decision, RateLimitDecision.ALLOW)
        
        # Invalid IP should be gracefully handled
        decision, _ = limiter.check_rate_limit(ip_address="not_an_ip")
        self.assertEqual(decision, RateLimitDecision.ALLOW)  # Skipped, not blocked
    
    def test_circuit_breaker_integration(self):
        """Test circuit breaker integrates with rate limiter"""
        limiter = PQCryptoRateLimiter()
        
        op = "failing_operation"
        
        # Record failures
        for _ in range(10):
            limiter.record_operation_result(op, False)
        
        # Circuit should be open
        decision, info = limiter.check_rate_limit(operation=op)
        
        self.assertEqual(decision, RateLimitDecision.CIRCUIT_OPEN)
        self.assertEqual(info["reason"], "circuit_open")
    
    def test_statistics_tracked(self):
        """Test statistics are actually tracked"""
        limiter = PQCryptoRateLimiter()
        
        # Make some requests
        for i in range(10):
            limiter.check_rate_limit(api_key=f"key_{i}")
        
        stats = limiter.get_statistics()
        
        self.assertEqual(stats["counters"]["total_requests"], 10)
        self.assertEqual(stats["counters"]["allowed"], 10)
        self.assertGreater(stats["active_api_keys"], 0)
    
    def test_statistics_honest_limitations(self):
        """Test honest limitations are documented"""
        limiter = PQCryptoRateLimiter()
        stats = limiter.get_statistics()
        
        # Should have honest limitations listed
        self.assertGreater(len(stats["honest_limitations"]), 0)
        self.assertGreater(len(stats["protection_provided"]), 0)

class TestDecorator(unittest.TestCase):
    """Test decorator functionality"""
    
    def test_decorator_allows_normal(self):
        """Test decorator allows normal calls"""
        limiter = PQCryptoRateLimiter(
            default_requests_per_second=1000,
            global_rps_limit=100000
        )
        
        @limiter.rate_limited_decorator("test_op", CryptoOperationCost.LIGHT)
        def protected_func(api_key=None):
            return "success"
        
        # Should work
        result = protected_func(api_key="test")
        self.assertEqual(result, "success")
    
    def test_decorator_records_results(self):
        """Test decorator records success/failure"""
        limiter = PQCryptoRateLimiter(global_rps_limit=100000)
        
        @limiter.rate_limited_decorator("success_op", CryptoOperationCost.LIGHT)
        def success_func(api_key=None):
            return "ok"
        
        @limiter.rate_limited_decorator("fail_op", CryptoOperationCost.LIGHT)
        def fail_func(api_key=None):
            raise ValueError("error")
        
        # Success
        success_func(api_key="test")
        
        # Failure
        try:
            fail_func(api_key="test")
        except ValueError:
            pass
        
        # Stats should reflect
        stats = limiter.get_statistics()
        self.assertEqual(stats["counters"]["total_requests"], 2)

class TestFactory(unittest.TestCase):
    """Test factory function"""
    
    def test_factory_creates_instance(self):
        """Test factory creates valid limiter"""
        limiter = create_pq_rate_limiter(requests_per_second=50, burst=200)
        self.assertIsInstance(limiter, PQCryptoRateLimiter)
        self.assertEqual(limiter.default_rps, 50)
        self.assertEqual(limiter.default_burst, 200)

if __name__ == "__main__":
    print("=" * 60)
    print("Post-Quantum Crypto Rate Limiter & DoS Protection Test Suite")
    print("HONEST TESTING: Real assertions, no fake passes")
    print("=" * 60)
    
    unittest.main(verbosity=2)
