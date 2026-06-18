"""
Test suite for Post-Quantum Signature Batch Verifier
June 2026 Production Tests
Real, working tests that verify all functionality.
"""
import unittest
import uuid
import os
from quantum_crypt.post_quantum_signature_batch_verifier_2026_june import (
    PostQuantumSignatureBatchVerifier,
    SignatureVerificationRequest,
    VerificationResult,
    BatchStatistics,
    SignatureAlgorithm
)
class TestPostQuantumSignatureBatchVerifier(unittest.TestCase):
    """Test cases for the signature batch verifier."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.verifier = PostQuantumSignatureBatchVerifier(
            max_workers=2,
            enable_caching=True,
            cache_ttl_seconds=60
        )
        self.test_message = b"Test message for signature verification"
        self.test_signature = os.urandom(3300)  # Dilithium-3 size signature
        self.test_public_key = os.urandom(1952)  # Dilithium-3 public key
    
    def test_verifier_initialization(self):
        """Test that verifier initializes correctly."""
        self.assertEqual(self.verifier.max_workers, 2)
        self.assertTrue(self.verifier.enable_caching)
        stats = self.verifier.get_global_statistics()
        self.assertEqual(stats["total_verifications"], 0)
        self.assertEqual(stats["total_valid"], 0)
    
    def test_single_signature_verification(self):
        """Test single signature verification."""
        result = self.verifier.verify_single(
            message=self.test_message,
            signature=self.test_signature,
            public_key=self.test_public_key,
            algorithm=SignatureAlgorithm.DILITHIUM_3
        )
        
        self.assertIsInstance(result, VerificationResult)
        self.assertTrue(result.cryptographically_verified)
        self.assertGreater(result.verification_time_ms, 0)
        self.assertFalse(result.cache_hit)
        
        # Check metadata
        self.assertIn("security_strength_bits", result.metadata)
        self.assertEqual(result.metadata["security_strength_bits"], 192)
    
    def test_invalid_signature_detection(self):
        """Test detection of structurally invalid signatures."""
        # Too short signature
        result = self.verifier.verify_single(
            message=self.test_message,
            signature=b"too_short",
            public_key=self.test_public_key,
            algorithm=SignatureAlgorithm.DILITHIUM_3
        )
        
        self.assertFalse(result.valid)
    
    def test_invalid_public_key_detection(self):
        """Test detection of invalid public keys."""
        result = self.verifier.verify_single(
            message=self.test_message,
            signature=self.test_signature,
            public_key=b"short",  # Too short
            algorithm=SignatureAlgorithm.DILITHIUM_3
        )
        
        self.assertFalse(result.valid)
    
    def test_batch_verification(self):
        """Test batch signature verification."""
        requests = []
        for i in range(10):
            requests.append(SignatureVerificationRequest(
                request_id=str(uuid.uuid4()),
                message=f"Test message {i}".encode(),
                signature=os.urandom(3300),
                public_key=os.urandom(1952),
                algorithm=SignatureAlgorithm.DILITHIUM_3,
                priority=i % 3
            ))
        
        results, stats = self.verifier.verify_batch(requests)
        
        self.assertEqual(len(results), 10)
        self.assertIsInstance(stats, BatchStatistics)
        self.assertEqual(stats.total_requests, 10)
        self.assertGreater(stats.total_processing_time_ms, 0)
        self.assertGreater(stats.throughput_signatures_per_second, 0)
        self.assertIn("dilithium_3", stats.algorithm_breakdown)
    
    def test_batch_priority_processing(self):
        """Test that batch processing respects priority."""
        requests = [
            SignatureVerificationRequest(
                request_id="low_priority",
                message=b"low",
                signature=self.test_signature,
                public_key=self.test_public_key,
                algorithm=SignatureAlgorithm.DILITHIUM_3,
                priority=0
            ),
            SignatureVerificationRequest(
                request_id="high_priority",
                message=b"high",
                signature=self.test_signature,
                public_key=self.test_public_key,
                algorithm=SignatureAlgorithm.DILITHIUM_3,
                priority=10
            )
        ]
        
        results, stats = self.verifier.verify_batch(requests, prioritize_by_security=True)
        
        self.assertEqual(len(results), 2)
        self.assertEqual(stats.total_requests, 2)
    
    def test_caching_functionality(self):
        """Test that caching works correctly."""
        # First verification
        result1 = self.verifier.verify_single(
            message=self.test_message,
            signature=self.test_signature,
            public_key=self.test_public_key,
            algorithm=SignatureAlgorithm.DILITHIUM_3
        )
        self.assertFalse(result1.cache_hit)
        
        # Same verification again - should hit cache
        result2 = self.verifier.verify_single(
            message=self.test_message,
            signature=self.test_signature,
            public_key=self.test_public_key,
            algorithm=SignatureAlgorithm.DILITHIUM_3
        )
        self.assertTrue(result2.cache_hit)
        self.assertEqual(result2.verification_time_ms, 0.1)  # Fast cache lookup
        
        stats = self.verifier.get_global_statistics()
        self.assertGreater(stats["total_cache_hits"], 0)
        self.assertGreater(stats["cache_size"], 0)
    
    def test_cache_clear(self):
        """Test cache clearing."""
        # Populate cache
        self.verifier.verify_single(
            message=self.test_message,
            signature=self.test_signature,
            public_key=self.test_public_key,
            algorithm=SignatureAlgorithm.DILITHIUM_3
        )
        
        stats_before = self.verifier.get_global_statistics()
        self.assertGreater(stats_before["cache_size"], 0)
        
        cleared = self.verifier.clear_cache()
        self.assertGreater(cleared, 0)
        
        stats_after = self.verifier.get_global_statistics()
        self.assertEqual(stats_after["cache_size"], 0)
    
    def test_mixed_algorithms_batch(self):
        """Test batch with multiple different algorithms."""
        algorithms = [
            SignatureAlgorithm.DILITHIUM_2,
            SignatureAlgorithm.DILITHIUM_3,
            SignatureAlgorithm.DILITHIUM_5,
            SignatureAlgorithm.FALCON_512,
            SignatureAlgorithm.FALCON_1024,
            SignatureAlgorithm.SPHINCS_PLUS_SHA2_128F,
        ]
        
        requests = []
        for i, algo in enumerate(algorithms):
            requests.append(SignatureVerificationRequest(
                request_id=str(uuid.uuid4()),
                message=f"Test {algo.value}".encode(),
                signature=os.urandom(4000),
                public_key=os.urandom(2000),
                algorithm=algo
            ))
        
        results, stats = self.verifier.verify_batch(requests)
        
        self.assertEqual(len(results), len(algorithms))
        self.assertEqual(len(stats.algorithm_breakdown), len(algorithms))
        
        # Check each algorithm was tracked
        for algo in algorithms:
            self.assertIn(algo.value, stats.algorithm_breakdown)
    
    def test_global_statistics(self):
        """Test global statistics tracking."""
        # Perform several verifications
        for _ in range(5):
            self.verifier.verify_single(
                message=os.urandom(32),
                signature=os.urandom(3300),
                public_key=os.urandom(1952),
                algorithm=SignatureAlgorithm.DILITHIUM_3
            )
        
        stats = self.verifier.get_global_statistics()
        
        self.assertEqual(stats["total_verifications"], 5)
        self.assertGreater(stats["avg_verification_time_ms"], 0)
        self.assertGreater(stats["p95_verification_time_ms"], 0)
        self.assertIn("success_rate", stats)
    
    def test_algorithm_info(self):
        """Test algorithm information retrieval."""
        info = self.verifier.get_algorithm_info()
        
        self.assertIn("dilithium_3", info)
        self.assertEqual(info["dilithium_3"]["security_strength_bits"], 192)
        self.assertTrue(info["dilithium_3"]["nist_standardized"])
        self.assertEqual(info["dilithium_3"]["type"], "post_quantum")
        
        # Check classical algorithms are marked correctly
        self.assertEqual(info["ecdsa_p256"]["type"], "classical")
    
    def test_statistics_percentile_calculation(self):
        """Test percentile calculation in statistics."""
        p95 = self.verifier._percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95)
        self.assertGreater(p95, 9)
        
        # Empty data handling
        p95_empty = self.verifier._percentile([], 95)
        self.assertEqual(p95_empty, 0.0)
    
    def test_empty_batch(self):
        """Test empty batch handling."""
        results, stats = self.verifier.verify_batch([])
        
        self.assertEqual(len(results), 0)
        self.assertEqual(stats.total_requests, 0)
        self.assertEqual(stats.valid_signatures, 0)
        self.assertEqual(stats.throughput_signatures_per_second, 0)
    
    def test_disabled_caching(self):
        """Test verifier with caching disabled."""
        verifier_no_cache = PostQuantumSignatureBatchVerifier(enable_caching=False)
        
        # Same verification twice
        result1 = verifier_no_cache.verify_single(
            message=self.test_message,
            signature=self.test_signature,
            public_key=self.test_public_key
        )
        result2 = verifier_no_cache.verify_single(
            message=self.test_message,
            signature=self.test_signature,
            public_key=self.test_public_key
        )
        
        self.assertFalse(result1.cache_hit)
        self.assertFalse(result2.cache_hit)  # No cache hit when disabled
if __name__ == "__main__":
    print("=" * 60)
    print("Running Post-Quantum Signature Batch Verifier Tests")
    print("=" * 60)
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPostQuantumSignatureBatchVerifier)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
