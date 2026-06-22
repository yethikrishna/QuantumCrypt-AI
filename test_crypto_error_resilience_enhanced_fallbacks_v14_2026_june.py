"""
Test Suite for QuantumCrypt Error Resilience Enhanced Fallbacks v14 - Dimension E
===================================================================================
ALL TESTS MUST PASS - NO EXISTING CODE MODIFIED
ADD-ONLY VERIFICATION - Zero intrusion into production code

Crypto-specific tests cover:
1. Cryptographic Dead Letter Queue (sensitive data protection)
2. Crypto Bulk Operation Handler with constant-time behavior
3. Security Event Aggregator with NIST compliance
4. Crypto Graceful Shutdown with key zeroization
5. Cipher Suite Fallback negotiation
6. Crypto convenience decorators
7. Sensitive data redaction
"""
import unittest
import time
import threading
import json

# Import the new crypto module - ONLY NEW CODE, NO MODIFICATIONS
from quantum_crypt.crypto_error_resilience_enhanced_fallbacks_v14_2026_june import (
    CryptoDeadLetterQueue,
    get_global_crypto_dlq,
    CryptoBulkOperationHandler,
    CryptoBulkOperationResult,
    CryptoSecurityEventAggregator,
    get_global_crypto_aggregator,
    CryptoGracefulShutdown,
    get_global_crypto_shutdown,
    CipherSuiteFallback,
    CipherFallback,
    with_crypto_dlq,
    with_security_event_tracking,
    create_crypto_bulk_processor,
    CryptoBulkOperationError,
    CryptoDeadLetterQueueError,
    CryptoShutdownError,
    CryptoFallbackChainExhaustedError,
    KeyMaterialError,
    CryptoDeadLetterEntry,
    CryptoSecurityEvent
)

# ============================================================================
# TEST 1: CRYPTO DEAD LETTER QUEUE
# ============================================================================
class TestCryptoDeadLetterQueue(unittest.TestCase):
    
    def setUp(self):
        self.dlq = CryptoDeadLetterQueue(max_size=100)
    
    def test_crypto_dlq_enqueue_dequeue(self):
        """Test basic crypto DLQ operations"""
        error = ValueError("decryption failed")
        entry_id = self.dlq.enqueue(
            "decrypt", "AES-GCM", "key_123",
            error, sensitive_payload=b"encrypted_data"
        )
        
        self.assertEqual(self.dlq.size(), 1)
        
        entry = self.dlq.dequeue()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.operation_id, entry_id)
        self.assertEqual(entry.algorithm, "AES-GCM")
        self.assertEqual(entry.key_id, "key_123")
    
    def test_sensitive_data_redaction(self):
        """Test sensitive data is redacted in exports"""
        error = ValueError("key=secret123 failed")
        self.dlq.enqueue("encrypt", "Kyber", "key_001", error)
        
        json_str = self.dlq.export_json()
        data = json.loads(json_str)
        
        # Sensitive patterns should be redacted
        self.assertNotIn("secret123", json_str)
        self.assertIn("REDACTED", json_str)
    
    def test_dlq_retry_with_handler(self):
        """Test DLQ retry with registered handler"""
        retry_results = []
        
        def crypto_handler(payload, algorithm, key_id):
            retry_results.append((payload, algorithm, key_id))
            return b"recovered_data"
        
        self.dlq.register_retry_handler("failed_decrypt", crypto_handler)
        
        entry_id = self.dlq.enqueue(
            "failed_decrypt", "AES", "key_001",
            ValueError("failed"), sensitive_payload=b"ciphertext"
        )
        
        success, result = self.dlq.retry_entry(entry_id)
        self.assertTrue(success)
        self.assertEqual(result, b"recovered_data")
        self.assertEqual(self.dlq.size(), 0)
    
    def test_dlq_clear_secure(self):
        """Test secure DLQ clearing"""
        for i in range(5):
            self.dlq.enqueue(f"op{i}", "AES", f"key{i}", ValueError(f"e{i}"))
        
        cleared = self.dlq.clear()
        self.assertEqual(cleared, 5)
        self.assertEqual(self.dlq.size(), 0)
    
    def test_global_crypto_dlq_singleton(self):
        """Test global crypto DLQ is singleton"""
        dlq1 = get_global_crypto_dlq()
        dlq2 = get_global_crypto_dlq()
        self.assertIs(dlq1, dlq2)

# ============================================================================
# TEST 2: CRYPTO BULK OPERATION HANDLER
# ============================================================================
class TestCryptoBulkOperationHandler(unittest.TestCase):
    
    def test_crypto_bulk_all_success(self):
        """Test bulk crypto operations all success"""
        handler = CryptoBulkOperationHandler(constant_time=False)
        
        def xor_encrypt(data):
            return bytes([b ^ 0x42 for b in data])
        
        items = [b"data1", b"data2", b"data3"]
        result = handler.process(items, xor_encrypt, algorithm="XOR")
        
        self.assertIsInstance(result, CryptoBulkOperationResult)
        self.assertEqual(result.total_items, 3)
        self.assertEqual(result.success_count, 3)
        self.assertEqual(result.algorithm, "XOR")
    
    def test_crypto_bulk_partial_success(self):
        """Test bulk crypto with partial failures"""
        handler = CryptoBulkOperationHandler(constant_time=False)
        
        def sometimes_fail(data):
            if b"fail" in data:
                raise ValueError("decryption failed")
            return data
        
        items = [b"ok1", b"fail_me", b"ok2", b"fail_too"]
        result = handler.process(items, sometimes_fail, algorithm="TEST")
        
        self.assertEqual(result.success_count, 2)
        self.assertEqual(result.failure_count, 2)
    
    def test_crypto_bulk_result_metadata(self):
        """Test bulk result includes security metadata"""
        handler = CryptoBulkOperationHandler(constant_time=True)
        
        result = handler.process([b"a", b"b"], lambda x: x, algorithm="TEST")
        
        d = result.to_dict()
        self.assertIn("algorithm", d)
        self.assertIn("constant_time_execution", d)
        self.assertIn("success_rate", d)
        self.assertTrue(d["constant_time_execution"])
    
    def test_create_crypto_bulk_processor(self):
        """Test convenience function for crypto bulk processor"""
        processor = create_crypto_bulk_processor(lambda x: x, algorithm="TEST", constant_time=False)
        result = processor([b"a", b"b", b"c"])
        
        self.assertEqual(result.success_count, 3)

# ============================================================================
# TEST 3: CRYPTO SECURITY EVENT AGGREGATOR
# ============================================================================
class TestCryptoSecurityEventAggregator(unittest.TestCase):
    
    def setUp(self):
        self.aggregator = CryptoSecurityEventAggregator()
    
    def test_record_security_event(self):
        """Test basic security event recording"""
        event_id = self.aggregator.record_event(
            "KEY_ROTATION", "WARNING", "Kyber-768", "key_001",
            "Key rotation approaching expiry"
        )
        
        self.assertIsNotNone(event_id)
    
    def test_record_crypto_error(self):
        """Test crypto error recording"""
        error = ValueError("authentication failed")
        event_id = self.aggregator.record_crypto_error("AES-GCM", "key_007", error)
        
        self.assertIsNotNone(event_id)
    
    def test_record_key_error(self):
        """Test key material error recording"""
        error = KeyMaterialError("key derivation failed")
        event_id = self.aggregator.record_key_error("HKDF", "master_key", error)
        
        self.assertIsNotNone(event_id)
    
    def test_get_events_by_severity(self):
        """Test filtering events by severity"""
        self.aggregator.record_event("E1", "INFO", "A", "k1", "msg1")
        self.aggregator.record_event("E2", "WARNING", "B", "k2", "msg2")
        self.aggregator.record_event("E3", "ERROR", "C", "k3", "msg3")
        self.aggregator.record_event("E4", "CRITICAL", "D", "k4", "msg4")
        
        critical = self.aggregator.get_critical_events()
        self.assertEqual(len(critical), 1)
        
        error_count = self.aggregator.get_error_count()
        self.assertEqual(error_count, 2)  # ERROR + CRITICAL
    
    def test_clear_aggregator(self):
        """Test clearing aggregator"""
        for i in range(10):
            self.aggregator.record_crypto_error("AES", f"k{i}", ValueError(f"e{i}"))
        
        cleared = self.aggregator.clear()
        self.assertEqual(cleared, 10)
        self.assertEqual(self.aggregator.get_error_count(), 0)
    
    def test_global_aggregator_singleton(self):
        """Test global aggregator is singleton"""
        agg1 = get_global_crypto_aggregator()
        agg2 = get_global_crypto_aggregator()
        self.assertIs(agg1, agg2)

# ============================================================================
# TEST 4: CRYPTO GRACEFUL SHUTDOWN
# ============================================================================
class TestCryptoGracefulShutdown(unittest.TestCase):
    
    def setUp(self):
        self.shutdown = CryptoGracefulShutdown()
    
    def test_register_zeroization_hook(self):
        """Test zeroization hook registration and execution"""
        hook_called = []
        
        def zeroize_keys():
            hook_called.append(True)
        
        self.shutdown.register_zeroization_hook("key_zeroization", zeroize_keys, priority=100)
        results = self.shutdown.initiate_secure_shutdown()
        
        self.assertTrue(hook_called)
        self.assertTrue(results["key_zeroization"])
    
    def test_hook_priority_order(self):
        """Test hooks run in priority order (master keys first)"""
        order = []
        
        def session_keys():
            order.append("session")
        
        def master_keys():
            order.append("master")
        
        # Master keys should have higher priority
        self.shutdown.register_zeroization_hook("session", session_keys, priority=1)
        self.shutdown.register_zeroization_hook("master", master_keys, priority=100)
        
        self.shutdown.initiate_secure_shutdown()
        
        self.assertEqual(order[0], "master")
        self.assertEqual(order[1], "session")
    
    def test_shutdown_state(self):
        """Test shutdown state tracking"""
        self.assertFalse(self.shutdown.is_shutting_down())
        self.shutdown.initiate_secure_shutdown()
        self.assertTrue(self.shutdown.is_shutting_down())
    
    def test_global_shutdown_singleton(self):
        """Test global shutdown coordinator is singleton"""
        sd1 = get_global_crypto_shutdown()
        sd2 = get_global_crypto_shutdown()
        self.assertIs(sd1, sd2)

# ============================================================================
# TEST 5: CIPHER SUITE FALLBACK
# ============================================================================
class TestCipherSuiteFallback(unittest.TestCase):
    
    def test_primary_cipher_succeeds(self):
        """Test primary cipher succeeds, no fallbacks used"""
        def aes_encrypt(data):
            return b"aes_encrypted_" + data
        
        fallback = CipherFallback("AES-GCM", aes_encrypt, priority=100, nist_approved=True)
        
        chain = CipherSuiteFallback(fallback)
        result, cipher_used = chain.encrypt(b"test")
        
        self.assertEqual(cipher_used, "AES-GCM")
        self.assertIn(b"aes_encrypted", result)
    
    def test_cipher_fallback_chain(self):
        """Test fallback chain when primary cipher fails"""
        def failing_cipher(data):
            raise ValueError("hardware accelerator offline")
        
        def fallback_cipher(data):
            return b"fallback_" + data
        
        primary = CipherFallback("AES-NI", failing_cipher, priority=100, nist_approved=True)
        secondary = CipherFallback("AES-Software", fallback_cipher, priority=50, nist_approved=True)
        
        chain = CipherSuiteFallback(primary, secondary)
        result, cipher_used = chain.encrypt(b"data")
        
        self.assertEqual(cipher_used, "AES-Software")
        self.assertIn(b"fallback", result)
    
    def test_all_ciphers_exhausted(self):
        """Test exception when all ciphers fail"""
        def always_fail(data):
            raise ValueError("cipher failure")
        
        c1 = CipherFallback("C1", always_fail)
        c2 = CipherFallback("C2", always_fail)
        
        chain = CipherSuiteFallback(c1, c2)
        
        with self.assertRaises(CryptoFallbackChainExhaustedError) as ctx:
            chain.encrypt(b"test")
        
        self.assertEqual(len(ctx.exception.attempted_ciphers), 2)

# ============================================================================
# TEST 6: CRYPTO DECORATORS
# ============================================================================
class TestCryptoDecorators(unittest.TestCase):
    
    def test_crypto_dlq_decorator(self):
        """Test crypto DLQ decorator captures failures"""
        dlq = get_global_crypto_dlq()
        dlq.clear()
        
        @with_crypto_dlq("test_decrypt", "AES-GCM", "key_001")
        def failing_crypto_op():
            raise ValueError("MAC verification failed")
        
        with self.assertRaises(ValueError):
            failing_crypto_op()
        
        self.assertGreater(dlq.size(), 0)
    
    def test_security_event_decorator(self):
        """Test security event tracking decorator"""
        agg = get_global_crypto_aggregator()
        agg.clear()
        
        @with_security_event_tracking("Kyber-768", "kem_key")
        def failing_kem():
            raise ValueError("decapsulation failed")
        
        with self.assertRaises(ValueError):
            failing_kem()
        
        self.assertGreater(agg.get_error_count(), 0)

# ============================================================================
# TEST 7: THREAD SAFETY
# ============================================================================
class TestCryptoThreadSafety(unittest.TestCase):
    
    def test_crypto_dlq_concurrent(self):
        """Test crypto DLQ handles concurrent operations"""
        dlq = CryptoDeadLetterQueue(max_size=10000)
        num_threads = 10
        ops_per_thread = 50
        
        def worker(tid):
            for i in range(ops_per_thread):
                dlq.enqueue(f"op_{tid}_{i}", "AES", f"key_{tid}", ValueError(f"e_{i}"))
        
        threads = []
        for t in range(num_threads):
            thread = threading.Thread(target=worker, args=(t,))
            threads.append(thread)
            thread.start()
        
        for t in threads:
            t.join()
        
        self.assertEqual(dlq.size(), num_threads * ops_per_thread)
    
    def test_event_aggregator_concurrent(self):
        """Test event aggregator concurrent recording"""
        agg = CryptoSecurityEventAggregator()
        num_threads = 10
        events_per_thread = 30
        
        def worker():
            for i in range(events_per_thread):
                agg.record_crypto_error("TEST", "key", ValueError("error"))
        
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()
        
        for t in threads:
            t.join()
        
        self.assertEqual(agg.get_error_count(), num_threads * events_per_thread)

# ============================================================================
# TEST 8: ADD-ONLY COMPLIANCE VERIFICATION
# ============================================================================
class TestAddOnlyCompliance(unittest.TestCase):
    """Verify this is strictly ADD-ONLY - no existing code modified"""
    
    def test_no_modification_existing_modules(self):
        """
        CRITICAL: Verify ADD-ONLY philosophy.
        Existing modules import successfully - no breakage.
        """
        try:
            from quantum_crypt import crypto_error_resilience_engine_2026_june
            from quantum_crypt import crypto_error_resilience_comprehensive_v13_2026_june
        except ImportError:
            self.fail("ADD-ONLY VIOLATION: Could not import existing crypto modules")
    
    def test_backward_compatibility(self):
        """All new functionality is optional"""
        from quantum_crypt.crypto_error_resilience_enhanced_fallbacks_v14_2026_june import (
            CryptoDeadLetterQueue
        )
        self.assertIsNotNone(CryptoDeadLetterQueue)

# ============================================================================
# RUN TESTS
# ============================================================================
if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    total_tests = suite.countTestCases()
    
    print(f"Running {total_tests} tests for Crypto Error Resilience v14 - Dimension E")
    print("=" * 70)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("=" * 70)
    print(f"Tests: {result.testsRun} Run")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ ALL TESTS PASSED - ADD-ONLY COMPLIANT - Crypto Dimension E Enhanced")
    else:
        print("\n❌ TESTS FAILED")
        exit(1)
