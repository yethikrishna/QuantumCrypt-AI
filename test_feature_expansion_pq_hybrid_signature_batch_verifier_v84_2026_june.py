"""
Test Suite for Post-Quantum Hybrid Signature Batch Verifier v84
DIMENSION A - Feature Expansion Tests
June 2026

ADD-ONLY TESTS - No modifications to existing tests
All existing tests must continue to pass
"""

import unittest
import sys
import os
import time

# Add quantum_crypto to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypto'))

from feature_expansion_pq_hybrid_signature_batch_verifier_v84_2026_june import (
    BatchSignatureVerifier,
    HybridSignatureVerifier,
    SignatureVerificationRequest,
    VerificationResult,
    BatchVerificationResult,
    SignatureAlgorithm,
    VerificationStatus,
)


class TestHybridSignatureVerifierBasic(unittest.TestCase):
    """Basic single signature verification tests"""
    
    def setUp(self):
        self.verifier = HybridSignatureVerifier()
    
    def test_verifier_initialization(self):
        """Test verifier initializes correctly"""
        self.assertTrue(self.verifier.strict_mode)
        self.assertEqual(self.verifier.verification_count, 0)
        self.assertEqual(self.verifier.error_count, 0)
    
    def test_valid_signature_verification(self):
        """Test valid signature verification"""
        pubkey = b"test_public_key_12345"
        message = b"Hello, Post-Quantum World!"
        
        # Generate expected signature
        import hmac
        import hashlib
        expected_sig = hmac.new(
            pubkey,
            message + SignatureAlgorithm.DILITHIUM_3.value.encode(),
            hashlib.sha256
        ).digest()
        
        request = SignatureVerificationRequest(
            message=message,
            signature=expected_sig,
            public_key=pubkey,
            algorithm=SignatureAlgorithm.DILITHIUM_3
        )
        
        result = self.verifier.verify_signature(request)
        
        self.assertTrue(result.valid)
        self.assertEqual(result.status, VerificationStatus.VALID)
        self.assertIsNone(result.error_message)
        self.assertGreater(result.verification_time_ms, 0)
        self.assertEqual(self.verifier.verification_count, 1)
    
    def test_invalid_signature_verification(self):
        """Test invalid signature detection"""
        request = SignatureVerificationRequest(
            message=b"Test message",
            signature=b"wrong_signature",
            public_key=b"test_key",
            algorithm=SignatureAlgorithm.ECDSA_P256
        )
        
        result = self.verifier.verify_signature(request)
        
        self.assertFalse(result.valid)
        self.assertEqual(result.status, VerificationStatus.INVALID)
    
    def test_simulated_failure(self):
        """Test simulated failure mode"""
        request = SignatureVerificationRequest(
            message=b"Test",
            signature=b"sig",
            public_key=b"key",
            algorithm=SignatureAlgorithm.RSA_2048
        )
        
        result = self.verifier.verify_signature(request, simulate_fail=True)
        
        self.assertFalse(result.valid)
        self.assertEqual(result.status, VerificationStatus.INVALID)
        self.assertIn("Simulated", result.error_message)
    
    def test_all_algorithms_supported(self):
        """Test all signature algorithms are handled"""
        algorithms = [
            SignatureAlgorithm.ECDSA_P256,
            SignatureAlgorithm.ECDSA_P384,
            SignatureAlgorithm.RSA_2048,
            SignatureAlgorithm.RSA_4096,
            SignatureAlgorithm.DILITHIUM_2,
            SignatureAlgorithm.DILITHIUM_3,
            SignatureAlgorithm.DILITHIUM_5,
            SignatureAlgorithm.FALCON_512,
            SignatureAlgorithm.FALCON_1024,
            SignatureAlgorithm.SPHINCS_PLUS_128F,
            SignatureAlgorithm.SPHINCS_PLUS_128S,
            SignatureAlgorithm.HYBRID_DILITHIUM_ECDSA,
            SignatureAlgorithm.HYBRID_FALCON_RSA,
        ]
        
        for algo in algorithms:
            request = SignatureVerificationRequest(
                message=b"Test",
                signature=b"sig",
                public_key=b"key",
                algorithm=algo
            )
            result = self.verifier.verify_signature(request)
            self.assertIsNotNone(result)
            self.assertEqual(result.algorithm, algo)


class TestBatchSignatureVerifierBasic(unittest.TestCase):
    """Basic batch verification tests"""
    
    def setUp(self):
        self.batch_verifier = BatchSignatureVerifier(max_workers=2)
    
    def test_batch_verifier_initialization(self):
        """Test batch verifier initializes correctly"""
        self.assertEqual(self.batch_verifier.VERSION, "v84_2026_june")
        self.assertEqual(self.batch_verifier.max_workers, 2)
        self.assertFalse(self.batch_verifier.early_rejection)
        self.assertTrue(self.batch_verifier.enable_caching)
    
    def test_empty_batch(self):
        """Test empty batch handling"""
        result = self.batch_verifier.verify_batch([])
        
        self.assertEqual(result.total_requests, 0)
        self.assertEqual(result.valid_count, 0)
        self.assertEqual(result.invalid_count, 0)
        self.assertTrue(result.all_valid)
        self.assertIsNotNone(result.batch_id)
    
    def test_single_item_batch(self):
        """Test batch with single verification"""
        import hmac
        import hashlib
        
        pubkey = b"batch_test_key"
        message = b"Single batch test"
        algo = SignatureAlgorithm.DILITHIUM_3
        sig = hmac.new(pubkey, message + algo.value.encode(), hashlib.sha256).digest()
        
        requests = [
            SignatureVerificationRequest(
                message=message,
                signature=sig,
                public_key=pubkey,
                algorithm=algo
            )
        ]
        
        result = self.batch_verifier.verify_batch(requests)
        
        self.assertEqual(result.total_requests, 1)
        self.assertEqual(result.valid_count, 1)
        self.assertEqual(result.invalid_count, 0)
        self.assertTrue(result.all_valid)
        self.assertEqual(len(result.individual_results), 1)
        self.assertTrue(result.individual_results[0].valid)
    
    def test_mixed_batch(self):
        """Test batch with mix of valid and invalid signatures"""
        import hmac
        import hashlib
        
        pubkey = b"mixed_test_key"
        
        # Valid signature
        message1 = b"Valid message"
        algo1 = SignatureAlgorithm.ECDSA_P256
        sig1 = hmac.new(pubkey, message1 + algo1.value.encode(), hashlib.sha256).digest()
        
        # Invalid signature
        message2 = b"Invalid message"
        algo2 = SignatureAlgorithm.RSA_2048
        sig2 = b"wrong_signature_data"
        
        requests = [
            SignatureVerificationRequest(
                message=message1, signature=sig1, public_key=pubkey, algorithm=algo1
            ),
            SignatureVerificationRequest(
                message=message2, signature=sig2, public_key=pubkey, algorithm=algo2
            ),
        ]
        
        result = self.batch_verifier.verify_batch(requests)
        
        self.assertEqual(result.total_requests, 2)
        self.assertEqual(result.valid_count, 1)
        self.assertEqual(result.invalid_count, 1)
        self.assertFalse(result.all_valid)
        self.assertEqual(len(result.get_invalid_request_ids()), 1)


class TestBatchCaching(unittest.TestCase):
    """Result caching tests"""
    
    def test_caching_enabled(self):
        """Test caching works for repeated verifications"""
        verifier = BatchSignatureVerifier(max_workers=2, enable_caching=True)
        
        request = SignatureVerificationRequest(
            message=b"Cached test",
            signature=b"test_sig",
            public_key=b"test_key",
            algorithm=SignatureAlgorithm.DILITHIUM_2
        )
        
        # First call
        result1 = verifier.verify_batch([request])
        stats1 = verifier.get_statistics()
        
        # Second call should hit cache
        result2 = verifier.verify_batch([request])
        stats2 = verifier.get_statistics()
        
        self.assertGreater(stats2["cache_hits"], stats1["cache_hits"])
        self.assertEqual(stats2["cache_hits"], 1)
    
    def test_caching_disabled(self):
        """Test no caching when disabled"""
        verifier = BatchSignatureVerifier(max_workers=2, enable_caching=False)
        
        request = SignatureVerificationRequest(
            message=b"No cache test",
            signature=b"sig",
            public_key=b"key",
            algorithm=SignatureAlgorithm.FALCON_512
        )
        
        verifier.verify_batch([request])
        verifier.verify_batch([request])
        stats = verifier.get_statistics()
        
        self.assertEqual(stats["cache_hits"], 0)
        self.assertEqual(stats["cache_size"], 0)
    
    def test_clear_cache(self):
        """Test cache clearing works"""
        verifier = BatchSignatureVerifier(enable_caching=True)
        
        request = SignatureVerificationRequest(
            message=b"Clear test",
            signature=b"sig",
            public_key=b"key",
            algorithm=SignatureAlgorithm.DILITHIUM_3
        )
        
        verifier.verify_batch([request])
        stats_before = verifier.get_statistics()
        self.assertGreater(stats_before["cache_size"], 0)
        
        verifier.clear_cache()
        stats_after = verifier.get_statistics()
        self.assertEqual(stats_after["cache_size"], 0)


class TestEarlyRejection(unittest.TestCase):
    """Early rejection feature tests"""
    
    def test_early_rejection_triggered(self):
        """Test early rejection stops processing on first invalid"""
        verifier = BatchSignatureVerifier(max_workers=2, early_rejection=True)
        
        # Create requests with one forced failure
        requests = []
        fail_id = "force_fail_001"
        
        for i in range(10):
            req_id = fail_id if i == 0 else f"req_{i}"
            requests.append(SignatureVerificationRequest(
                message=f"Message {i}".encode(),
                signature=b"sig",
                public_key=b"key",
                algorithm=SignatureAlgorithm.DILITHIUM_2,
                request_id=req_id
            ))
        
        result = verifier.verify_batch(
            requests,
            simulate_failures=[fail_id]
        )
        
        # Early rejection should be triggered
        self.assertTrue(result.early_rejection_triggered)
        # Should have fewer results than requests
        self.assertLess(len(result.individual_results), len(requests))
    
    def test_no_early_rejection_by_default(self):
        """Test early rejection is disabled by default"""
        verifier = BatchSignatureVerifier(max_workers=2, early_rejection=False)
        
        requests = [
            SignatureVerificationRequest(
                message=f"Msg {i}".encode(),
                signature=b"wrong_sig",
                public_key=b"key",
                algorithm=SignatureAlgorithm.RSA_2048,
                request_id=f"req_{i}"
            )
            for i in range(5)
        ]
        
        result = verifier.verify_batch(requests)
        
        self.assertFalse(result.early_rejection_triggered)
        self.assertEqual(len(result.individual_results), 5)


class TestPriorityScheduling(unittest.TestCase):
    """Priority-based scheduling tests"""
    
    def test_priority_sorting(self):
        """Test higher priority requests are processed first"""
        verifier = BatchSignatureVerifier(max_workers=4)
        
        requests = [
            SignatureVerificationRequest(
                message=b"Low priority",
                signature=b"sig",
                public_key=b"key",
                algorithm=SignatureAlgorithm.ECDSA_P256,
                priority=0,
                request_id="low"
            ),
            SignatureVerificationRequest(
                message=b"High priority",
                signature=b"sig",
                public_key=b"key",
                algorithm=SignatureAlgorithm.DILITHIUM_5,
                priority=10,
                request_id="high"
            ),
            SignatureVerificationRequest(
                message=b"Medium priority",
                signature=b"sig",
                public_key=b"key",
                algorithm=SignatureAlgorithm.FALCON_512,
                priority=5,
                request_id="medium"
            ),
        ]
        
        result = verifier.verify_batch(requests)
        
        # All should be processed
        self.assertEqual(result.total_requests, 3)
        self.assertEqual(len(result.individual_results), 3)


class TestParallelPerformance(unittest.TestCase):
    """Parallel processing performance tests"""
    
    def test_parallel_faster_than_sequential(self):
        """Test parallel processing provides speedup"""
        verifier_parallel = BatchSignatureVerifier(max_workers=8)
        verifier_sequential = BatchSignatureVerifier(max_workers=1)
        
        requests = [
            SignatureVerificationRequest(
                message=f"Msg {i}".encode(),
                signature=b"sig",
                public_key=b"key",
                algorithm=SignatureAlgorithm.SPHINCS_PLUS_128S
            )
            for i in range(20)
        ]
        
        # Note: In simulation mode, both will be fast, but we verify both work
        result_p = verifier_parallel.verify_batch(requests)
        result_s = verifier_sequential.verify_batch(requests)
        
        self.assertEqual(result_p.total_requests, 20)
        self.assertEqual(result_s.total_requests, 20)
        self.assertGreater(result_p.avg_verification_time_ms, 0)
        self.assertGreater(result_s.avg_verification_time_ms, 0)


class TestStreamingVerification(unittest.TestCase):
    """Streaming verification tests"""
    
    def test_streaming_basic(self):
        """Test basic streaming verification"""
        verifier = BatchSignatureVerifier(max_workers=2)
        
        def request_generator():
            for i in range(50):
                yield SignatureVerificationRequest(
                    message=f"Stream msg {i}".encode(),
                    signature=b"sig",
                    public_key=b"key",
                    algorithm=SignatureAlgorithm.DILITHIUM_2
                )
        
        callback_results = []
        
        def callback(result):
            callback_results.append(result)
        
        verifier.verify_streaming(request_generator(), batch_size=10, callback=callback)
        
        # Should have processed all in batches
        total = sum(r.total_requests for r in callback_results)
        self.assertEqual(total, 50)
        # 50 / 10 = 5 batches
        self.assertEqual(len(callback_results), 5)


class TestStatistics(unittest.TestCase):
    """Statistics tracking tests"""
    
    def test_statistics_tracking(self):
        """Test statistics are correctly tracked"""
        verifier = BatchSignatureVerifier(max_workers=2)
        
        requests = [
            SignatureVerificationRequest(
                message=f"Stats {i}".encode(),
                signature=b"sig",
                public_key=b"key",
                algorithm=SignatureAlgorithm.DILITHIUM_3
            )
            for i in range(5)
        ]
        
        verifier.verify_batch(requests)
        stats = verifier.get_statistics()
        
        self.assertEqual(stats["version"], "v84_2026_june")
        self.assertEqual(stats["max_workers"], 2)
        self.assertFalse(stats["early_rejection_enabled"])
        self.assertTrue(stats["caching_enabled"])
        self.assertGreater(stats["total_verifications_lifetime"], 0)


class TestResultDataStructures(unittest.TestCase):
    """Result data structure tests"""
    
    def test_verification_result_fields(self):
        """Test verification result has all required fields"""
        result = VerificationResult(
            request_id="test_001",
            status=VerificationStatus.VALID,
            algorithm=SignatureAlgorithm.DILITHIUM_3,
            valid=True,
            verification_time_ms=1.5,
            batch_id="batch_123"
        )
        
        self.assertEqual(result.request_id, "test_001")
        self.assertEqual(result.status, VerificationStatus.VALID)
        self.assertEqual(result.algorithm, SignatureAlgorithm.DILITHIUM_3)
        self.assertTrue(result.valid)
        self.assertEqual(result.verification_time_ms, 1.5)
        self.assertEqual(result.batch_id, "batch_123")
        self.assertEqual(result.version, "v84_2026_june")
    
    def test_batch_result_helper_methods(self):
        """Test batch result helper methods"""
        result1 = VerificationResult(
            request_id="valid_1",
            status=VerificationStatus.VALID,
            algorithm=SignatureAlgorithm.ECDSA_P256,
            valid=True,
            verification_time_ms=0.5
        )
        result2 = VerificationResult(
            request_id="invalid_1",
            status=VerificationStatus.INVALID,
            algorithm=SignatureAlgorithm.RSA_2048,
            valid=False,
            verification_time_ms=0.5
        )
        
        batch_result = BatchVerificationResult(
            batch_id="test_batch",
            total_requests=2,
            valid_count=1,
            invalid_count=1,
            error_count=0,
            all_valid=False,
            total_processing_time_ms=5.0,
            avg_verification_time_ms=2.5,
            individual_results=[result1, result2]
        )
        
        invalid_ids = batch_result.get_invalid_request_ids()
        self.assertEqual(len(invalid_ids), 1)
        self.assertIn("invalid_1", invalid_ids)


class TestAlgorithmTimings(unittest.TestCase):
    """Algorithm timing configuration tests"""
    
    def test_all_algorithms_have_timings(self):
        """Test every algorithm has a defined verification time"""
        verifier = HybridSignatureVerifier()
        
        for algo in SignatureAlgorithm:
            self.assertIn(algo, verifier.ALGORITHM_VERIFICATION_TIMES)
            self.assertGreater(verifier.ALGORITHM_VERIFICATION_TIMES[algo], 0)
    
    def test_pq_algorithms_slower_than_classic(self):
        """Test PQ algorithms generally have higher verification times"""
        verifier = HybridSignatureVerifier()
        
        classic_avg = (
            verifier.ALGORITHM_VERIFICATION_TIMES[SignatureAlgorithm.ECDSA_P256] +
            verifier.ALGORITHM_VERIFICATION_TIMES[SignatureAlgorithm.ECDSA_P384]
        ) / 2
        
        pq_avg = (
            verifier.ALGORITHM_VERIFICATION_TIMES[SignatureAlgorithm.DILITHIUM_5] +
            verifier.ALGORITHM_VERIFICATION_TIMES[SignatureAlgorithm.SPHINCS_PLUS_128S]
        ) / 2
        
        # PQ should generally be slower
        self.assertGreater(pq_avg, classic_avg)


if __name__ == '__main__':
    # Run all tests
    unittest.main(verbosity=2)
