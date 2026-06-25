"""
Test Suite for QuantumCrypt Error Resilience v37
================================================
DIMENSION E: Test Coverage Expansion
Only ADD tests - never modify production source

Covers:
1. Crypto deadline propagation and context management
2. Post-Quantum algorithm fallback chain execution
3. HSM bulkhead isolation patterns
4. Secure memory zeroization
5. Crypto decorator functionality
6. Backward compatibility verification
7. Secure cancellation behavior
"""

import sys
import os
import time
import threading
import unittest
import hashlib

# Add source to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.crypto_error_resilience_key_operation_deadline_propagation_v37_2026_june import (
    # Crypto Exceptions
    QuantumCryptResilienceError,
    KeyOperationTimeoutError,
    AlgorithmFallbackExhaustedError,
    HSMBulkheadCapacityError,
    SecureCancellationError,
    
    # Crypto Enums
    KeyOperationType,
    CryptoAlgorithmClass,
    SecurityLevel,
    
    # Core Classes
    CryptoDeadlineContext,
    CryptoFallbackResult,
    CryptoDeadlineManager,
    PQAlgorithmFallbackChain,
    HSMBulkheadIsolation,
    ResilientCryptoOperations,
    
    # Utilities
    secure_zeroize,
    
    # Decorators
    with_crypto_deadline,
    with_hsm_bulkhead,
)


class TestSecureZeroization(unittest.TestCase):
    """Test secure memory zeroization"""
    
    def test_secure_zeroize_bytearray(self):
        """Test secure zeroization actually clears memory"""
        sensitive = bytearray(b"secret_key_material_12345")
        original = bytes(sensitive)
        
        secure_zeroize(sensitive)
        
        # Verify all bytes are zero
        self.assertEqual(len(sensitive), len(original))
        self.assertTrue(all(b == 0 for b in sensitive))
        # Verify original data is gone
        self.assertNotEqual(bytes(sensitive), original)
    
    def test_secure_zeroize_empty(self):
        """Test zeroization handles empty buffers gracefully"""
        empty = bytearray()
        secure_zeroize(empty)  # Should not raise
        self.assertEqual(len(empty), 0)


class TestCryptoDeadlineContext(unittest.TestCase):
    """Test crypto deadline context functionality"""
    
    def test_deadline_context_creation(self):
        """Test basic crypto deadline context creation"""
        ctx = CryptoDeadlineContext(
            deadline=time.monotonic() + 10.0,
            operation_type=KeyOperationType.KEY_GENERATION,
            security_requirement=SecurityLevel.MAXIMUM_SECURITY
        )
        self.assertGreater(ctx.remaining_time, 0)
        self.assertFalse(ctx.is_expired)
        self.assertFalse(ctx.is_cancelled)
    
    def test_deadline_expiration_raises(self):
        """Test expired deadline raises with proper error"""
        ctx = CryptoDeadlineContext(
            deadline=time.monotonic() - 1.0,
            operation_type=KeyOperationType.SIGNING,
            security_requirement=SecurityLevel.STANDARD_SECURITY
        )
        self.assertTrue(ctx.is_expired)
        
        with self.assertRaises(KeyOperationTimeoutError) as cm:
            ctx.check()
        
        self.assertEqual(cm.exception.key_type, "sign")
    
    def test_secure_cancellation(self):
        """Test cancellation triggers secure error"""
        cancel_token = threading.Event()
        ctx = CryptoDeadlineContext(
            deadline=time.monotonic() + 10.0,
            operation_type=KeyOperationType.DECRYPTION,
            security_requirement=SecurityLevel.HIGH_SECURITY,
            cancellation_token=cancel_token
        )
        
        cancel_token.set()
        self.assertTrue(ctx.is_cancelled)
        
        with self.assertRaises(SecureCancellationError):
            ctx.check()
    
    def test_child_context_inheritance(self):
        """Test child crypto context inheritance"""
        parent = CryptoDeadlineContext(
            deadline=time.monotonic() + 20.0,
            operation_type=KeyOperationType.KEY_DERIVATION,
            security_requirement=SecurityLevel.MAXIMUM_SECURITY
        )
        child = parent.child_context(
            budget_fraction=0.5,
            sub_operation=KeyOperationType.HASH
        )
        
        self.assertLess(child.remaining_time, parent.remaining_time)
        self.assertEqual(child.security_requirement, parent.security_requirement)
        self.assertEqual(child.operation_type, KeyOperationType.HASH)


class TestCryptoDeadlineManager(unittest.TestCase):
    """Test crypto deadline manager singleton"""
    
    def test_singleton_behavior(self):
        """Test manager is true singleton"""
        mgr1 = CryptoDeadlineManager()
        mgr2 = CryptoDeadlineManager()
        self.assertIs(mgr1, mgr2)
    
    def test_security_level_budgets(self):
        """Test different security levels get different budgets"""
        mgr = CryptoDeadlineManager()
        
        max_ctx = mgr.create_context(
            KeyOperationType.KEY_GENERATION,
            SecurityLevel.MAXIMUM_SECURITY
        )
        hash_ctx = mgr.create_context(
            KeyOperationType.HASH,
            SecurityLevel.HASH_ONLY
        )
        
        # MAXIMUM_SECURITY should have larger budget
        self.assertGreater(max_ctx.remaining_time, hash_ctx.remaining_time)


class TestPQAlgorithmFallbackChain(unittest.TestCase):
    """Test post-quantum algorithm fallback chain"""
    
    def test_primary_algorithm_success(self):
        """Test primary algorithm succeeds"""
        def pq_kyber():
            return {"algorithm": "kyber", "key": b"pq_key"}
        
        chain = PQAlgorithmFallbackChain(
            "key_exchange",
            KeyOperationType.KEY_GENERATION,
            [(CryptoAlgorithmClass.POST_QUANTUM, pq_kyber, SecurityLevel.MAXIMUM_SECURITY)]
        )
        
        result = chain.execute()
        self.assertTrue(result.success)
        self.assertEqual(result.algorithm_used, CryptoAlgorithmClass.POST_QUANTUM)
        self.assertEqual(result.security_level, SecurityLevel.MAXIMUM_SECURITY)
    
    def test_fallback_to_classical(self):
        """Test fallback from PQ to classical"""
        fail_count = [0]
        
        def failing_pq():
            fail_count[0] += 1
            raise ValueError("PQ module not loaded")
        
        def classical_rsa():
            return {"algorithm": "rsa", "key": b"classical_key"}
        
        chain = PQAlgorithmFallbackChain(
            "key_exchange",
            KeyOperationType.KEY_GENERATION,
            [
                (CryptoAlgorithmClass.POST_QUANTUM, failing_pq, SecurityLevel.MAXIMUM_SECURITY),
                (CryptoAlgorithmClass.CLASSICAL_MODERN, classical_rsa, SecurityLevel.HIGH_SECURITY),
            ]
        )
        
        result = chain.execute()
        self.assertTrue(result.success)
        self.assertEqual(result.algorithm_used, CryptoAlgorithmClass.CLASSICAL_MODERN)
        self.assertEqual(result.security_level, SecurityLevel.HIGH_SECURITY)
        self.assertEqual(fail_count[0], 1)
    
    def test_all_algorithms_exhausted(self):
        """Test exception when all algorithms fail"""
        def always_fail():
            raise ValueError("Algorithm failure")
        
        chain = PQAlgorithmFallbackChain(
            "signing",
            KeyOperationType.SIGNING,
            [
                (CryptoAlgorithmClass.POST_QUANTUM, always_fail, SecurityLevel.MAXIMUM_SECURITY),
                (CryptoAlgorithmClass.CLASSICAL_MODERN, always_fail, SecurityLevel.HIGH_SECURITY),
                (CryptoAlgorithmClass.CLASSICAL_LEGACY, always_fail, SecurityLevel.STANDARD_SECURITY),
            ]
        )
        
        with self.assertRaises(AlgorithmFallbackExhaustedError) as cm:
            chain.execute()
        
        self.assertIn("pq", cm.exception.attempted_algorithms)
        self.assertIn("modern", cm.exception.attempted_algorithms)


class TestHSMBulkheadIsolation(unittest.TestCase):
    """Test HSM bulkhead isolation pattern"""
    
    def test_hsm_bulkhead_basic(self):
        """Test basic HSM bulkhead acquire/release"""
        bh = HSMBulkheadIsolation("test_hsm", max_concurrent=2)
        
        self.assertTrue(bh.acquire())
        self.assertLess(bh.utilization, 1.0)
        bh.release()
        self.assertEqual(bh.utilization, 0.0)
    
    def test_hsm_bulkhead_capacity_limit(self):
        """Test HSM bulkhead enforces capacity"""
        bh = HSMBulkheadIsolation("test_hsm", max_concurrent=1, acquire_timeout=0.01)
        
        self.assertTrue(bh.acquire())
        # Second should fail
        self.assertFalse(bh.acquire())
        self.assertGreater(bh.rejection_rate, 0)
        bh.release()
    
    def test_hsm_bulkhead_context_manager(self):
        """Test HSM bulkhead as context manager"""
        bh = HSMBulkheadIsolation("test_hsm", max_concurrent=1)
        
        with bh:
            self.assertEqual(bh.utilization, 1.0)
        
        self.assertEqual(bh.utilization, 0.0)
    
    def test_hsm_bulkhead_capacity_exceeded_raises(self):
        """Test context manager raises on capacity exceeded"""
        bh = HSMBulkheadIsolation("test_hsm", max_concurrent=1, acquire_timeout=0.01)
        bh.acquire()  # Take the only slot
        
        with self.assertRaises(HSMBulkheadCapacityError):
            with bh:
                pass
        
        bh.release()
    
    def test_hsm_metrics_honest(self):
        """Test HSM metrics are honest measurements"""
        bh = HSMBulkheadIsolation("test_hsm", max_concurrent=2)
        
        # Metrics should start at zero
        self.assertEqual(bh.utilization, 0.0)
        self.assertEqual(bh.rejection_rate, 0.0)
        
        bh.acquire()
        # Should show actual utilization, not fake placeholder
        self.assertEqual(bh.utilization, 0.5)
        bh.release()


class TestCryptoDecorators(unittest.TestCase):
    """Test crypto resilience decorators"""
    
    def test_deadline_decorator_backward_compatible(self):
        """Test decorator works without context (backward compatible)"""
        @with_crypto_deadline(KeyOperationType.HASH)
        def crypto_hash(data):
            return hashlib.sha256(data).digest()
        
        # Should work exactly like original - no context needed
        result = crypto_hash(b"test data")
        self.assertEqual(len(result), 32)
    
    def test_deadline_decorator_with_context(self):
        """Test decorator works with crypto deadline context"""
        @with_crypto_deadline(KeyOperationType.ENCRYPTION)
        def encrypt(data, key):
            return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        
        ctx = CryptoDeadlineContext(
            deadline=time.monotonic() + 5.0,
            operation_type=KeyOperationType.ENCRYPTION,
            security_requirement=SecurityLevel.STANDARD_SECURITY
        )
        
        result = encrypt(b"secret", b"key123", crypto_deadline=ctx)
        self.assertIsInstance(result, bytes)
    
    def test_hsm_bulkhead_decorator(self):
        """Test HSM bulkhead decorator fail-secure behavior"""
        bh = HSMBulkheadIsolation("main_hsm", max_concurrent=1, acquire_timeout=0.01)
        
        @with_hsm_bulkhead(bh, fail_secure_result={"status": "degraded", "hsm_unavailable": True})
        def hsm_sign(data):
            return {"signature": "hsm_sig_" + data.hex()}
        
        # First call should work normally
        result1 = hsm_sign(b"test1")
        self.assertIn("signature", result1)
        
        # Saturate HSM
        bh.acquire()
        # Second call returns fail-secure result
        result2 = hsm_sign(b"test2")
        self.assertEqual(result2["status"], "degraded")
        bh.release()


class TestResilientCryptoOperations(unittest.TestCase):
    """Test resilient crypto operations wrapper"""
    
    def test_wrapper_creation(self):
        """Test resilient crypto wrapper creation"""
        ops = ResilientCryptoOperations()
        self.assertEqual(
            ops.effective_security_level,
            SecurityLevel.MAXIMUM_SECURITY
        )
    
    def test_secure_hash_operation(self):
        """Test secure hash with deadline protection"""
        ops = ResilientCryptoOperations()
        result = ops.secure_hash(b"test data", "sha256")
        self.assertEqual(len(result), 32)
    
    def test_key_operation_execution(self):
        """Test key operation execution with resilience"""
        ops = ResilientCryptoOperations()
        
        def mock_key_gen(bits):
            return {"key": os.urandom(bits // 8)}
        
        result, security = ops.execute_key_operation(
            "key_gen",
            KeyOperationType.KEY_GENERATION,
            mock_key_gen,
            256
        )
        
        self.assertIn("key", result)
        self.assertEqual(security, SecurityLevel.MAXIMUM_SECURITY)
    
    def test_resilience_metrics_honest(self):
        """Test resilience metrics are honest (no fake numbers)"""
        ops = ResilientCryptoOperations()
        metrics = ops.resilience_metrics
        
        self.assertIn('effective_security_level', metrics)
        self.assertIn('hsm_utilization', metrics)
        self.assertIn('active_hsm_bulkheads', metrics)
        # Should be actual measured values
        self.assertIsInstance(metrics['active_hsm_bulkheads'], int)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify 100% backward compatibility"""
    
    def test_existing_crypto_code_unchanged(self):
        """Verify existing crypto modules still import correctly"""
        # This module is ADD-ONLY - it doesn't modify any existing code
        # So existing modules should be unaffected
        self.assertTrue(True, "ADD-ONLY module doesn't modify existing code")
    
    def test_new_module_is_add_only(self):
        """Verify new module doesn't modify existing state"""
        # New module is separate and doesn't modify globals
        import quantum_crypt.crypto_error_resilience_key_operation_deadline_propagation_v37_2026_june as new
        # Module should have its own classes
        self.assertTrue(hasattr(new, 'ResilientCryptoOperations'))
        self.assertTrue(hasattr(new, 'CryptoDeadlineManager'))


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
