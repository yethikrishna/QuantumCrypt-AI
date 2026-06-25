"""
Test Suite for QuantumCrypt Error Resilience - PQ Deadline Propagation v35
Dimension E: Error Resilience
All tests must pass - ADD-ONLY verification
"""
import unittest
import time
import threading
import secrets
from quantum_crypt.crypto_error_resilience_pq_deadline_propagation_cancellation_v35_2026_june import (
    PQDeadlinePropagationManager,
    CryptoCancellationToken,
    CryptoDeadlineScope,
    CryptoOperationType,
    CryptoDeadlineExceededError,
    CryptoOperationCancelledError,
    with_crypto_deadline,
    create_pq_fallback_chain,
)


class TestCryptoCancellationToken(unittest.TestCase):
    """Test cryptographic cancellation token"""
    
    def test_token_creation(self):
        """Token should be created with operation type"""
        token = CryptoCancellationToken(
            deadline_seconds=10.0,
            operation_type=CryptoOperationType.KEY_GENERATION
        )
        self.assertIsNotNone(token.token_id)
        self.assertEqual(token.operation_type, CryptoOperationType.KEY_GENERATION)
    
    def test_cleanup_callback_execution(self):
        """Cleanup callbacks should execute on cancellation"""
        callback_called = [False]
        
        def cleanup():
            callback_called[0] = True
        
        token = CryptoCancellationToken(deadline_seconds=10.0)
        token.register_cleanup_callback(cleanup)
        token.cancel()
        
        self.assertTrue(callback_called[0])
    
    def test_child_token_crypto_inheritance(self):
        """Child token should inherit parent deadline and context"""
        parent = CryptoCancellationToken(
            deadline_seconds=5.0,
            operation_type=CryptoOperationType.KEY_EXCHANGE
        )
        child = parent.create_child_token(
            operation_type=CryptoOperationType.SIGNING,
            additional_seconds=10.0
        )
        
        # Child deadline should be capped by parent remaining (~5s)
        self.assertIsNotNone(child.remaining_seconds)
        self.assertLessEqual(child.remaining_seconds, 5.0)


class TestPQDeadlinePropagationManager(unittest.TestCase):
    """Test PQ deadline propagation manager"""
    
    def test_successful_crypto_operation(self):
        """Successful crypto operation should return success"""
        manager = PQDeadlinePropagationManager()
        
        def mock_key_gen():
            return secrets.token_bytes(32)
        
        result = manager.execute_crypto_operation(
            mock_key_gen,
            CryptoOperationType.KEY_GENERATION,
            5.0
        )
        
        self.assertTrue(result.success)
        self.assertIsNotNone(result.result)
        self.assertEqual(len(result.result), 32)
    
    def test_crypto_operation_with_cancellation_token_param(self):
        """Operation accepting token should receive it"""
        manager = PQDeadlinePropagationManager()
        received_token = [None]
        
        def mock_signing(cancellation_token=None):
            received_token[0] = cancellation_token
            return b"signature"
        
        result = manager.execute_crypto_operation(
            mock_signing,
            CryptoOperationType.SIGNING,
            5.0
        )
        
        self.assertTrue(result.success)
        self.assertIsNotNone(received_token[0])
    
    def test_algorithm_fallback_registration(self):
        """Fallback algorithms should be registerable (ADD-ONLY)"""
        manager = PQDeadlinePropagationManager()
        
        def fallback_impl():
            return b"fallback_result"
        
        # Should not raise - ADD-ONLY
        manager.register_algorithm_fallback(
            CryptoOperationType.KEY_GENERATION,
            "ML-KEM-512",
            fallback_impl
        )


class TestCryptoDeadlineScope(unittest.TestCase):
    """Test crypto deadline scope context manager"""
    
    def test_scope_provides_token(self):
        """Scope should provide typed crypto token"""
        with CryptoDeadlineScope(5.0, CryptoOperationType.SIGNING) as token:
            self.assertIsNotNone(token)
            self.assertEqual(token.operation_type, CryptoOperationType.SIGNING)
    
    def test_scope_cancels_on_exit(self):
        """Token should be cancelled and cleaned up on scope exit"""
        captured_token = [None]
        
        with CryptoDeadlineScope(5.0, CryptoOperationType.KEY_GENERATION) as token:
            captured_token[0] = token
        
        self.assertTrue(captured_token[0].is_cancellation_requested)


class TestCryptoDecorators(unittest.TestCase):
    """Test cryptographic decorators"""
    
    def test_with_crypto_deadline(self):
        """@with_crypto_deadline should wrap crypto function"""
        @with_crypto_deadline(5.0, CryptoOperationType.HASHING)
        def mock_hash(data):
            return secrets.token_bytes(32)
        
        result = mock_hash(b"test_data")
        self.assertTrue(result.success)
        self.assertEqual(result.operation_type, CryptoOperationType.HASHING)


class TestPQFallbackChain(unittest.TestCase):
    """Test PQ algorithm fallback chain"""
    
    def test_primary_succeeds(self):
        """Primary algorithm should be used when successful"""
        def primary():
            return b"primary_key"
        
        def fallback():
            return b"fallback_key"
        
        wrapped = create_pq_fallback_chain(
            primary,
            CryptoOperationType.KEY_GENERATION,
            5.0,
            ("FALLBACK_ALGO", fallback)
        )
        
        result = wrapped()
        self.assertTrue(result.success)
        self.assertIsNone(result.fallback_used)


class TestCryptoExceptionHierarchy(unittest.TestCase):
    """Test crypto exception hierarchy"""
    
    def test_crypto_deadline_error(self):
        """Crypto deadline error should track operation type"""
        error = CryptoDeadlineExceededError(
            "Key gen timeout",
            deadline_seconds=5.0,
            elapsed_seconds=10.0,
            operation="key_generation"
        )
        self.assertEqual(error.error_code, "QC-DE-001")
        self.assertTrue(error.secure_cleanup_required)
    
    def test_crypto_cancelled_error(self):
        """Crypto cancelled error should track reason"""
        error = CryptoOperationCancelledError(
            "Signing cancelled",
            cancel_reason="user_abort",
            operation="signing"
        )
        self.assertEqual(error.error_code, "QC-DE-002")
        self.assertEqual(error.cancel_reason, "user_abort")


class TestThreadSafety(unittest.TestCase):
    """Test thread safety for concurrent crypto operations"""
    
    def test_concurrent_crypto_token_creation(self):
        """Multiple threads should create tokens safely"""
        results = []
        
        def worker():
            token = CryptoCancellationToken(
                deadline_seconds=5.0,
                operation_type=CryptoOperationType.ENCRYPTION
            )
            results.append(token.token_id)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(set(results)), 10)  # All unique


if __name__ == "__main__":
    unittest.main(verbosity=2)
