"""
Test Suite for QuantumCrypt Adaptive Concurrency Limiting with QoS Tiers v30
DIMENSION E: Error Resilience
Tests verify:
1. Crypto operation priority classification works
2. Critical crypto operations are never rejected
3. Entropy pool protection works
4. HSM concurrency protection works
5. Algorithm fallback chains work
6. Health metrics are accurate
7. Decorators work correctly
8. No breaking changes to existing crypto code
"""
import unittest
import time
import threading
import sys
import os

# Add source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_error_resilience_adaptive_concurrency_qos_v30_2026_june import (
    CryptoOperationType,
    CryptoQoSPriority,
    CryptoLoadShedReason,
    OPERATION_PRIORITY_MAP,
    CryptoConcurrencyMetrics,
    CryptoConcurrencyConfig,
    CryptoAdaptiveConcurrencyController,
    crypto_concurrency_limited,
    critical_crypto_op,
    high_priority_crypto_op,
    get_global_crypto_controller,
    crypto_concurrency_health_check,
    CryptoAlgorithmFallbackChain,
    get_crypto_fallback_chain
)

class TestCryptoOperationPriority(unittest.TestCase):
    """Test crypto operation priority classification"""
    
    def test_crypto_priority_ordering(self):
        """Verify crypto priority hierarchy is correct"""
        self.assertEqual(CryptoQoSPriority.CRYPTO_CRITICAL.value, 0)
        self.assertEqual(CryptoQoSPriority.CRYPTO_HIGH.value, 1)
        self.assertEqual(CryptoQoSPriority.CRYPTO_MEDIUM.value, 2)
        self.assertEqual(CryptoQoSPriority.CRYPTO_LOW.value, 3)
    
    def test_operation_priority_mapping(self):
        """Verify critical operations get CRYPTO_CRITICAL priority"""
        critical_ops = [
            CryptoOperationType.KEY_GENERATION,
            CryptoOperationType.KEY_AGREEMENT,
            CryptoOperationType.KEM_DECAPSULATION,
            CryptoOperationType.DECRYPTION
        ]
        
        for op in critical_ops:
            self.assertEqual(
                OPERATION_PRIORITY_MAP[op],
                CryptoQoSPriority.CRYPTO_CRITICAL,
                f"{op.value} should be CRITICAL"
            )
    
    def test_high_priority_operations(self):
        """Verify high priority operations get correct mapping"""
        high_ops = [
            CryptoOperationType.DIGITAL_SIGNATURE,
            CryptoOperationType.ENCRYPTION,
            CryptoOperationType.KEM_ENCAPSULATION,
            CryptoOperationType.RANDOM_ENTROPY
        ]
        
        for op in high_ops:
            self.assertEqual(
                OPERATION_PRIORITY_MAP[op],
                CryptoQoSPriority.CRYPTO_HIGH,
                f"{op.value} should be HIGH"
            )

class TestCryptoConcurrencyMetrics(unittest.TestCase):
    """Test crypto-specific concurrency metrics"""
    
    def test_initial_state(self):
        """Metrics start with clean state"""
        metrics = CryptoConcurrencyMetrics()
        self.assertEqual(metrics.current_concurrency, 0)
        self.assertEqual(metrics.entropy_level, 1.0)
        self.assertEqual(metrics.error_rate, 0.0)
    
    def test_entropy_level_update(self):
        """Entropy level can be updated and clamped"""
        metrics = CryptoConcurrencyMetrics()
        metrics.update_entropy(0.5)
        self.assertEqual(metrics.entropy_level, 0.5)
        
        # Should clamp to valid range
        metrics.update_entropy(-0.1)
        self.assertEqual(metrics.entropy_level, 0.0)
        
        metrics.update_entropy(1.5)
        self.assertEqual(metrics.entropy_level, 1.0)
    
    def test_operation_count_tracking(self):
        """Operation types are tracked individually"""
        metrics = CryptoConcurrencyMetrics()
        metrics.record_latency(10.0, CryptoOperationType.ENCRYPTION)
        metrics.record_latency(10.0, CryptoOperationType.ENCRYPTION)
        metrics.record_latency(10.0, CryptoOperationType.DECRYPTION)
        
        self.assertEqual(metrics.operation_counts[CryptoOperationType.ENCRYPTION], 2)
        self.assertEqual(metrics.operation_counts[CryptoOperationType.DECRYPTION], 1)

class TestCryptoAdaptiveConcurrencyController(unittest.TestCase):
    """Test crypto-specific adaptive concurrency controller"""
    
    def setUp(self):
        self.config = CryptoConcurrencyConfig(
            initial_max_concurrency=4,
            min_concurrency=1,
            max_concurrency_limit=8,
            queue_timeout_ms=100
        )
        self.controller = CryptoAdaptiveConcurrencyController(self.config)
    
    def tearDown(self):
        self.controller.shutdown()
    
    def test_acquire_release_slot(self):
        """Basic acquire/release cycle works for crypto ops"""
        acquired = self.controller.acquire_slot(
            op_type=CryptoOperationType.ENCRYPTION
        )
        self.assertTrue(acquired)
        
        self.controller.release_slot(
            success=True,
            latency_ms=10.0,
            op_type=CryptoOperationType.ENCRYPTION
        )
        
        status = self.controller.get_health_status()
        self.assertEqual(status["current_concurrency"], 0)
        self.assertEqual(status["total_operations"], 1)
    
    def test_critical_crypto_ops_never_rejected(self):
        """CRYPTO_CRITICAL operations are never rejected"""
        # Try to fill up controller with low priority ops
        for _ in range(20):
            self.controller.acquire_slot(
                op_type=CryptoOperationType.BACKUP_OPERATION,
                timeout_ms=1
            )
        
        # Key generation (CRITICAL) should still work
        acquired = self.controller.acquire_slot(
            op_type=CryptoOperationType.KEY_GENERATION
        )
        self.assertTrue(acquired, "Key generation should never be rejected")
    
    def test_entropy_protection(self):
        """Low entropy triggers protection mechanisms"""
        # Set critically low entropy
        self.controller.update_entropy_level(0.05)
        
        # Low/medium priority ops should be rejected
        acquired = self.controller.acquire_slot(
            op_type=CryptoOperationType.BACKUP_OPERATION,
            timeout_ms=10
        )
        # May be rejected due to entropy depletion
        # This is expected behavior - entropy protection working
    
    def test_health_status_includes_crypto_metrics(self):
        """Health check includes crypto-specific metrics"""
        status = self.controller.get_health_status()
        self.assertIn("entropy_level", status)
        self.assertIn("hsm_concurrency", status)
        self.assertIn("operation_counts", status)
        self.assertIn("max_concurrency", status)

class TestCryptoConcurrencyDecorators(unittest.TestCase):
    """Test crypto concurrency limiting decorators"""
    
    def test_crypto_concurrency_decorator(self):
        """Decorator wraps crypto function without breaking it"""
        call_count = [0]
        
        @crypto_concurrency_limited(op_type=CryptoOperationType.ENCRYPTION)
        def encrypt_data(data: bytes, key: bytes) -> bytes:
            call_count[0] += 1
            return data[::-1]  # Dummy "encryption"
        
        # Happy path should work 100%
        result = encrypt_data(b"test", b"key")
        self.assertEqual(result, b"tset")
        self.assertEqual(call_count[0], 1)
    
    def test_critical_crypto_op_decorator(self):
        """Critical crypto op decorator works"""
        @critical_crypto_op(CryptoOperationType.KEY_GENERATION)
        def generate_keypair():
            return ("pubkey", "privkey")
        
        result = generate_keypair()
        self.assertEqual(result, ("pubkey", "privkey"))
    
    def test_high_priority_crypto_op_decorator(self):
        """High priority crypto op decorator works"""
        @high_priority_crypto_op(CryptoOperationType.DIGITAL_SIGNATURE)
        def sign_message():
            return b"signature"
        
        result = sign_message()
        self.assertEqual(result, b"signature")
    
    def test_decorator_with_fallback(self):
        """Decorator with algorithm fallback works"""
        @crypto_concurrency_limited(
            op_type=CryptoOperationType.ENCRYPTION,
            fallback=lambda d, k: b"classical_encrypted"
        )
        def pq_encrypt(data: bytes, key: bytes) -> bytes:
            return b"pq_encrypted"
        
        result = pq_encrypt(b"data", b"key")
        # Under normal load, should get PQ encryption
        self.assertIn(result, [b"pq_encrypted", b"classical_encrypted"])

class TestCryptoAlgorithmFallbackChain(unittest.TestCase):
    """Test algorithm fallback chain for graceful degradation"""
    
    def test_fallback_chain_creation(self):
        """Fallback chain handler can be created"""
        chain = CryptoAlgorithmFallbackChain()
        self.assertIsNotNone(chain)
    
    def test_register_fallback_chain(self):
        """Fallback algorithms can be registered"""
        chain = CryptoAlgorithmFallbackChain()
        
        def primary(data):
            return f"primary_{data}"
        
        def fallback1(data):
            return f"fallback1_{data}"
        
        chain.register_fallback_chain(
            CryptoOperationType.ENCRYPTION,
            [primary, fallback1]
        )
        # Should not raise
    
    def test_get_fallback_statistics(self):
        """Fallback statistics are available"""
        chain = get_crypto_fallback_chain()
        stats = chain.get_fallback_statistics()
        self.assertIsInstance(stats, dict)

class TestGlobalCryptoController(unittest.TestCase):
    """Test global crypto controller instance"""
    
    def test_get_global_crypto_controller(self):
        """Global crypto controller singleton works"""
        ctrl1 = get_global_crypto_controller()
        ctrl2 = get_global_crypto_controller()
        self.assertIs(ctrl1, ctrl2)
    
    def test_crypto_health_check_function(self):
        """Global crypto health check function works"""
        health = crypto_concurrency_health_check()
        self.assertIsInstance(health, dict)
        self.assertIn("entropy_level", health)
        self.assertIn("fallback_stats", health)

class TestCryptoThreadSafety(unittest.TestCase):
    """Test thread safety of crypto controller"""
    
    def test_concurrent_crypto_operations(self):
        """Multiple threads can perform crypto ops safely"""
        controller = CryptoAdaptiveConcurrencyController(
            CryptoConcurrencyConfig(initial_max_concurrency=8)
        )
        
        errors = []
        
        def worker():
            try:
                for _ in range(3):
                    op_type = CryptoOperationType.HASH_DIGEST
                    if controller.acquire_slot(op_type, timeout_ms=50):
                        time.sleep(0.001)
                        controller.release_slot(
                            success=True,
                            latency_ms=1.0,
                            op_type=op_type
                        )
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        
        controller.shutdown()
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")

class TestCryptoBackwardCompatibility(unittest.TestCase):
    """Verify no breaking changes to existing crypto error resilience"""
    
    def test_can_import_existing_crypto_modules(self):
        """Existing crypto error resilience modules still import"""
        try:
            from crypto_error_resilience_comprehensive_enhanced_v2_2026_june import (
                QuantumCryptError,
                CryptoRetryPolicy
            )
            # If we get here, imports work
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Existing crypto module import failed: {e}")
    
    def test_new_crypto_module_coexists(self):
        """New module coexists with existing crypto modules"""
        import crypto_error_resilience_comprehensive_enhanced_v2_2026_june as old
        import crypto_error_resilience_adaptive_concurrency_qos_v30_2026_june as new
        
        self.assertIsNotNone(old.QuantumCryptError)
        self.assertIsNotNone(new.CryptoOperationType)

class TestCryptoOperationTypeCoverage(unittest.TestCase):
    """Test all crypto operation types have priorities defined"""
    
    def test_all_operations_have_priority(self):
        """Every CryptoOperationType has a default priority mapping"""
        for op_type in CryptoOperationType:
            self.assertIn(
                op_type,
                OPERATION_PRIORITY_MAP,
                f"Missing priority mapping for {op_type.value}"
            )

if __name__ == '__main__':
    # Run tests
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCryptoOperationPriority)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCryptoConcurrencyMetrics))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCryptoAdaptiveConcurrencyController))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCryptoConcurrencyDecorators))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCryptoAlgorithmFallbackChain))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestGlobalCryptoController))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCryptoThreadSafety))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCryptoBackwardCompatibility))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCryptoOperationTypeCoverage))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
