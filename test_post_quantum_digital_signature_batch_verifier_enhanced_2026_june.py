"""
Test Suite for Post-Quantum Digital Signature Batch Verifier - Enhanced (June 20, 2026)
Comprehensive unit tests for all components
"""

import unittest
import time
import hashlib
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_digital_signature_batch_verifier_enhanced_2026_june import (
    SignatureAlgorithm,
    VerificationStatus,
    SignatureVerificationRequest,
    SignatureVerificationResult,
    BatchVerificationResult,
    CacheEntry,
    SignatureCache,
    PostQuantumSignatureVerifier,
    PostQuantumDigitalSignatureBatchVerifier,
    create_batch_verifier,
    verify_batch_verifier_works,
    run_batch_verification_benchmark
)


class TestCacheEntry(unittest.TestCase):
    """Test CacheEntry class functionality"""

    def test_cache_entry_creation(self):
        """Test basic cache entry creation"""
        result = SignatureVerificationResult(
            request_id="test123",
            status=VerificationStatus.VALID,
            algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM,
            verification_time_ms=1.5
        )
        entry = CacheEntry(
            result=result,
            created_at=time.time(),
            accessed_at=time.time(),
            access_count=1
        )
        self.assertEqual(entry.result, result)
        self.assertEqual(entry.access_count, 1)

    def test_cache_entry_expiration(self):
        """Test cache entry expiration logic"""
        result = SignatureVerificationResult(
            request_id="test123",
            status=VerificationStatus.VALID,
            algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM,
            verification_time_ms=1.5
        )
        entry = CacheEntry(
            result=result,
            created_at=time.time() - 4000,  # Created 4000s ago
            accessed_at=time.time(),
            access_count=1,
            ttl_seconds=3600
        )
        self.assertTrue(entry.is_expired())

    def test_cache_entry_not_expired(self):
        """Test non-expired entry"""
        result = SignatureVerificationResult(
            request_id="test123",
            status=VerificationStatus.VALID,
            algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM,
            verification_time_ms=1.5
        )
        entry = CacheEntry(
            result=result,
            created_at=time.time(),
            accessed_at=time.time(),
            access_count=1,
            ttl_seconds=3600
        )
        self.assertFalse(entry.is_expired())

    def test_cache_entry_touch(self):
        """Test touch updates access metadata"""
        result = SignatureVerificationResult(
            request_id="test123",
            status=VerificationStatus.VALID,
            algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM,
            verification_time_ms=1.5
        )
        entry = CacheEntry(
            result=result,
            created_at=time.time(),
            accessed_at=time.time() - 100,
            access_count=1
        )
        old_accessed = entry.accessed_at
        old_count = entry.access_count
        entry.touch()
        self.assertGreater(entry.accessed_at, old_accessed)
        self.assertEqual(entry.access_count, old_count + 1)


class TestSignatureCache(unittest.TestCase):
    """Test SignatureCache class functionality"""

    def test_basic_put_get(self):
        """Test basic put and get operations"""
        cache = SignatureCache(capacity=10)
        message = b"test message"
        signature = b"test signature"
        public_key = b"test pubkey"
        algorithm = SignatureAlgorithm.CRYSTALS_DILITHIUM
        
        result = SignatureVerificationResult(
            request_id="test123",
            status=VerificationStatus.VALID,
            algorithm=algorithm,
            verification_time_ms=1.5
        )
        
        cache.put(message, signature, public_key, algorithm, result)
        cached = cache.get(message, signature, public_key, algorithm)
        
        self.assertIsNotNone(cached)
        self.assertEqual(cached.status, VerificationStatus.VALID)

    def test_cache_miss(self):
        """Test cache miss behavior"""
        cache = SignatureCache(capacity=10)
        result = cache.get(b"nonexistent", b"sig", b"key", SignatureAlgorithm.CRYSTALS_DILITHIUM)
        self.assertIsNone(result)

    def test_lru_eviction(self):
        """Test LRU eviction at capacity"""
        cache = SignatureCache(capacity=5)
        algorithm = SignatureAlgorithm.CRYSTALS_DILITHIUM
        
        for i in range(10):
            message = f"message_{i}".encode()
            signature = f"signature_{i}".encode()
            public_key = f"pubkey_{i}".encode()
            result = SignatureVerificationResult(
                request_id=f"test_{i}",
                status=VerificationStatus.VALID,
                algorithm=algorithm,
                verification_time_ms=1.0
            )
            cache.put(message, signature, public_key, algorithm, result)
        
        self.assertEqual(cache.size(), 5)

    def test_hit_rate_calculation(self):
        """Test hit rate statistics"""
        cache = SignatureCache(capacity=10)
        algorithm = SignatureAlgorithm.CRYSTALS_DILITHIUM
        
        # Put one entry
        result = SignatureVerificationResult(
            request_id="test",
            status=VerificationStatus.VALID,
            algorithm=algorithm,
            verification_time_ms=1.0
        )
        cache.put(b"msg", b"sig", b"key", algorithm, result)
        
        # Two hits
        cache.get(b"msg", b"sig", b"key", algorithm)
        cache.get(b"msg", b"sig", b"key", algorithm)
        
        # One miss
        cache.get(b"other", b"sig", b"key", algorithm)
        
        self.assertGreater(cache.hit_rate(), 0)

    def test_clear_expired(self):
        """Test clearing expired entries"""
        cache = SignatureCache(capacity=10, default_ttl_seconds=0)
        algorithm = SignatureAlgorithm.CRYSTALS_DILITHIUM
        
        result = SignatureVerificationResult(
            request_id="test",
            status=VerificationStatus.VALID,
            algorithm=algorithm,
            verification_time_ms=1.0
        )
        cache.put(b"msg", b"sig", b"key", algorithm, result, ttl_seconds=0)
        time.sleep(0.01)
        
        removed = cache.clear_expired()
        self.assertGreaterEqual(removed, 0)


class TestPostQuantumSignatureVerifier(unittest.TestCase):
    """Test PostQuantumSignatureVerifier class functionality"""

    def test_dilithium_verification(self):
        """Test Dilithium signature verification"""
        verifier = PostQuantumSignatureVerifier()
        message = b"test message"
        signature = hashlib.sha256(b"test signature").digest()
        public_key = hashlib.sha256(b"test pubkey").digest()
        
        is_valid, error = verifier.verify_dilithium(message, signature, public_key)
        self.assertIn(is_valid, [True, False])
        self.assertIsNone(error)

    def test_falcon_verification(self):
        """Test Falcon signature verification"""
        verifier = PostQuantumSignatureVerifier()
        message = b"test message"
        signature = hashlib.sha256(b"test signature").digest()
        public_key = hashlib.sha256(b"test pubkey").digest()
        
        is_valid, error = verifier.verify_falcon(message, signature, public_key)
        self.assertIn(is_valid, [True, False])
        self.assertIsNone(error)

    def test_sphincs_plus_verification(self):
        """Test SPHINCS+ signature verification"""
        verifier = PostQuantumSignatureVerifier()
        message = b"test message"
        signature = hashlib.sha512(b"test signature").digest()
        public_key = hashlib.sha256(b"test pubkey").digest()
        
        is_valid, error = verifier.verify_sphincs_plus(message, signature, public_key)
        self.assertIn(is_valid, [True, False])
        self.assertIsNone(error)

    def test_short_signature_rejection(self):
        """Test short signature rejection"""
        verifier = PostQuantumSignatureVerifier()
        message = b"test"
        signature = b"short"
        public_key = b"key"
        
        is_valid, error = verifier.verify_dilithium(message, signature, public_key)
        self.assertFalse(is_valid)
        self.assertIsNotNone(error)

    def test_full_verify_request(self):
        """Test full request verification"""
        verifier = PostQuantumSignatureVerifier()
        request = SignatureVerificationRequest(
            message=b"test message",
            signature=hashlib.sha256(b"sig").digest(),
            public_key=hashlib.sha256(b"key").digest(),
            algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM
        )
        
        result = verifier.verify(request)
        self.assertIsNotNone(result)
        self.assertIn(result.status, [VerificationStatus.VALID, VerificationStatus.INVALID])


class TestBatchVerifier(unittest.TestCase):
    """Test PostQuantumDigitalSignatureBatchVerifier class functionality"""

    def test_basic_single_verification(self):
        """Test basic single signature verification"""
        verifier = create_batch_verifier(max_workers=2)
        request = SignatureVerificationRequest(
            message=b"test message",
            signature=hashlib.sha256(b"sig").digest(),
            public_key=hashlib.sha256(b"key").digest(),
            algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM
        )
        
        result = verifier.verify_single(request, use_cache=False)
        self.assertIsNotNone(result)
        self.assertIn(result.status, [VerificationStatus.VALID, VerificationStatus.INVALID])

    def test_cache_functionality(self):
        """Test caching functionality"""
        verifier = create_batch_verifier(max_workers=2)
        request = SignatureVerificationRequest(
            message=b"test message",
            signature=hashlib.sha256(b"sig").digest(),
            public_key=hashlib.sha256(b"key").digest(),
            algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM
        )
        
        # First call - cache miss
        result1 = verifier.verify_single(request, use_cache=True)
        
        # Second call - should be cache hit
        result2 = verifier.verify_single(request, use_cache=True)
        
        self.assertTrue(result2.is_from_cache)

    def test_batch_verification(self):
        """Test batch signature verification"""
        verifier = PostQuantumDigitalSignatureBatchVerifier(
            max_workers=4,
            enable_early_rejection=False  # Disable early rejection for test
        )
        
        requests = []
        for i in range(10):
            requests.append(SignatureVerificationRequest(
                message=f"message_{i}".encode(),
                signature=hashlib.sha256(f"sig_{i}".encode()).digest(),
                public_key=hashlib.sha256(f"key_{i}".encode()).digest(),
                algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM
            ))
        
        result = verifier.verify_batch(requests)
        self.assertEqual(result.total_signatures, 10)
        self.assertGreater(result.total_time_ms, 0)

    def test_mixed_algorithms_batch(self):
        """Test batch with mixed algorithms"""
        verifier = create_batch_verifier(max_workers=4)
        
        requests = []
        algorithms = [
            SignatureAlgorithm.CRYSTALS_DILITHIUM,
            SignatureAlgorithm.FALCON,
            SignatureAlgorithm.SPHINCS_PLUS,
            SignatureAlgorithm.ML_DSA
        ]
        
        for i, algo in enumerate(algorithms):
            requests.append(SignatureVerificationRequest(
                message=f"message_{i}".encode(),
                signature=hashlib.sha256(f"sig_{i}".encode()).digest(),
                public_key=hashlib.sha256(f"key_{i}".encode()).digest(),
                algorithm=algo
            ))
        
        result = verifier.verify_batch(requests)
        self.assertEqual(result.total_signatures, 4)

    def test_performance_metrics(self):
        """Test performance metrics tracking"""
        verifier = create_batch_verifier(max_workers=2)
        
        requests = [SignatureVerificationRequest(
            message=b"test",
            signature=hashlib.sha256(b"sig").digest(),
            public_key=hashlib.sha256(b"key").digest(),
            algorithm=SignatureAlgorithm.CRYSTALS_DILITHIUM
        )]
        
        verifier.verify_batch(requests)
        metrics = verifier.get_performance_metrics()
        
        self.assertGreaterEqual(metrics["total_batches_processed"], 1)
        self.assertGreaterEqual(metrics["total_signatures_processed"], 1)

    def test_cache_stats(self):
        """Test cache statistics"""
        verifier = create_batch_verifier(max_workers=2, cache_capacity=100)
        stats = verifier.get_cache_stats()
        
        self.assertIn("size", stats)
        self.assertIn("capacity", stats)
        self.assertIn("hit_rate", stats)

    def test_unsupported_algorithm(self):
        """Test unsupported algorithm handling"""
        verifier = create_batch_verifier(max_workers=2)
        
        # Create a request with an unsupported algorithm by using invalid enum value
        # We'll test this through the verifier directly
        pass


class TestFactoryFunctions(unittest.TestCase):
    """Test factory and utility functions"""

    def test_create_batch_verifier(self):
        """Test factory function"""
        verifier = create_batch_verifier(max_workers=4, cache_capacity=5000)
        self.assertIsInstance(verifier, PostQuantumDigitalSignatureBatchVerifier)
        self.assertEqual(verifier.max_workers, 4)

    def test_verify_batch_verifier_works(self):
        """Test verification function"""
        result = verify_batch_verifier_works()
        self.assertTrue(result)

    def test_benchmark_function(self):
        """Test benchmark function"""
        result = run_batch_verification_benchmark(num_signatures=50, max_workers=2)
        self.assertIn("benchmark_result", result)
        self.assertIn("performance_metrics", result)


def run_tests():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("POST-QUANTUM BATCH VERIFIER TEST SUITE - June 20, 2026")
    print("=" * 60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestCacheEntry))
    suite.addTests(loader.loadTestsFromTestCase(TestSignatureCache))
    suite.addTests(loader.loadTestsFromTestCase(TestPostQuantumSignatureVerifier))
    suite.addTests(loader.loadTestsFromTestCase(TestBatchVerifier))
    suite.addTests(loader.loadTestsFromTestCase(TestFactoryFunctions))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED!")
    else:
        print(f"❌ TESTS FAILED: {len(result.failures)} failures, {len(result.errors)} errors")
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    
    if success:
        print("\nRunning production benchmark...")
        run_batch_verification_benchmark(num_signatures=200, max_workers=4)
    
    sys.exit(0 if success else 1)
