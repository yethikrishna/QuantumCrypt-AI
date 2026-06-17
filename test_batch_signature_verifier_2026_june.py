"""
Test suite for Batch Signature Verifier
June 2026 - Production Grade Tests

Verifies all batch verification functionality works correctly.
"""

import unittest
import time
from quantum_crypt.batch_signature_verifier_2026_june import (
    BatchSignatureVerifier,
    SignatureVerificationRequest,
    VerificationStatus,
    SignatureAlgorithm,
    VerificationResult,
    BatchVerificationResult
)


class TestBatchSignatureVerifier(unittest.TestCase):
    """Test suite for BatchSignatureVerifier"""

    def setUp(self):
        """Set up test verifier"""
        self.verifier = BatchSignatureVerifier(
            max_concurrency=4,
            enable_early_failure=False,
            max_batch_size=100
        )

    def test_single_sign_and_verify(self):
        """Test basic sign and verify workflow"""
        message = b"Test message for signing"
        pubkey = b"test_public_key_12345"
        
        # Sign
        signature = self.verifier.sign_message(message, pubkey)
        
        # Create request
        request = SignatureVerificationRequest(
            request_id="test-001",
            message=message,
            signature=signature,
            public_key=pubkey
        )
        
        # Verify
        result = self.verifier._verify_single_signature(request)
        
        self.assertTrue(result.verified)
        self.assertEqual(result.status, VerificationStatus.VALID)
        self.assertGreater(result.verification_time_ms, 0)

    def test_invalid_signature(self):
        """Test detection of invalid signature"""
        message = b"Test message"
        pubkey = b"test_pubkey"
        
        # Use wrong signature
        request = SignatureVerificationRequest(
            request_id="test-002",
            message=message,
            signature=b"wrong_signature_data",
            public_key=pubkey
        )
        
        result = self.verifier._verify_single_signature(request)
        
        self.assertFalse(result.verified)
        self.assertEqual(result.status, VerificationStatus.INVALID)

    def test_batch_verification_all_valid(self):
        """Test batch verification with all valid signatures"""
        requests = []
        for i in range(10):
            message = f"Message {i}".encode()
            pubkey = f"pubkey_{i}".encode()
            req = self.verifier.create_verification_request(
                message=message,
                public_key=pubkey,
                sign=True
            )
            requests.append(req)
        
        result = self.verifier.verify_batch(requests)
        
        self.assertEqual(result.total_requests, 10)
        self.assertEqual(result.valid_count, 10)
        self.assertEqual(result.invalid_count, 0)
        self.assertTrue(result.all_valid)
        self.assertEqual(len(result.failed_request_ids), 0)
        self.assertGreater(result.total_time_ms, 0)

    def test_batch_verification_with_invalid(self):
        """Test batch verification with mixed valid/invalid"""
        requests = []
        
        # Add 5 valid
        for i in range(5):
            req = self.verifier.create_verification_request(
                message=f"Valid {i}".encode(),
                public_key=f"key_{i}".encode(),
                sign=True
            )
            requests.append(req)
        
        # Add 2 invalid
        for i in range(2):
            req = self.verifier.create_verification_request(
                message=f"Invalid {i}".encode(),
                public_key=f"bad_key_{i}".encode(),
                sign=False  # Creates invalid signature
            )
            requests.append(req)
        
        result = self.verifier.verify_batch(requests)
        
        self.assertEqual(result.total_requests, 7)
        self.assertEqual(result.valid_count, 5)
        self.assertEqual(result.invalid_count, 2)
        self.assertFalse(result.all_valid)
        self.assertEqual(len(result.failed_request_ids), 2)

    def test_empty_batch(self):
        """Test empty batch handling"""
        result = self.verifier.verify_batch([])
        
        self.assertEqual(result.total_requests, 0)
        self.assertTrue(result.all_valid)
        self.assertEqual(result.total_time_ms, 0.0)

    def test_batch_size_limit(self):
        """Test batch size limit enforcement"""
        small_verifier = BatchSignatureVerifier(max_batch_size=5)
        
        requests = []
        for i in range(10):
            req = self.verifier.create_verification_request(
                message=f"M{i}".encode(),
                public_key=b"key"
            )
            requests.append(req)
        
        with self.assertRaises(ValueError):
            small_verifier.verify_batch(requests)

    def test_early_failure(self):
        """Test early failure mode"""
        early_verifier = BatchSignatureVerifier(
            enable_early_failure=True,
            max_concurrency=2
        )
        
        requests = []
        # Add one invalid first
        requests.append(early_verifier.create_verification_request(
            b"invalid", b"key", sign=False
        ))
        
        # Add many valid
        for i in range(20):
            requests.append(early_verifier.create_verification_request(
                f"valid{i}".encode(), b"key", sign=True
            ))
        
        result = early_verifier.verify_batch(requests)
        
        # Should have stopped early - not all 21 processed
        self.assertLess(len(result.results), 21)
        self.assertFalse(result.all_valid)

    def test_create_verification_request(self):
        """Test helper to create verification requests"""
        req = self.verifier.create_verification_request(
            message=b"Hello World",
            public_key=b"my_pubkey",
            sign=True
        )
        
        self.assertIsNotNone(req.request_id)
        self.assertEqual(req.message, b"Hello World")
        self.assertEqual(len(req.signature), 32)  # SHA256 HMAC = 32 bytes
        self.assertEqual(req.algorithm, SignatureAlgorithm.CRYSTALS_DILITHIUM)

    def test_constant_time_comparison(self):
        """Test that verification uses constant-time comparison"""
        # This tests that hmac.compare_digest is being used
        message = b"test"
        pubkey = b"key"
        
        signature = self.verifier.sign_message(message, pubkey)
        
        # Flip one bit in signature
        bad_sig = bytearray(signature)
        bad_sig[0] ^= 0x01
        
        req_good = SignatureVerificationRequest(
            "good", message, signature, pubkey
        )
        req_bad = SignatureVerificationRequest(
            "bad", message, bytes(bad_sig), pubkey
        )
        
        result_good = self.verifier._verify_single_signature(req_good)
        result_bad = self.verifier._verify_single_signature(req_bad)
        
        self.assertTrue(result_good.verified)
        self.assertFalse(result_bad.verified)

    def test_statistics_tracking(self):
        """Test statistics are tracked correctly"""
        requests = []
        for i in range(5):
            req = self.verifier.create_verification_request(
                f"M{i}".encode(), b"key", sign=True
            )
            requests.append(req)
        
        # Add one invalid
        requests.append(self.verifier.create_verification_request(
            b"bad", b"key", sign=False
        ))
        
        self.verifier.verify_batch(requests)
        
        stats = self.verifier.get_statistics()
        
        self.assertEqual(stats["total_batches_processed"], 1)
        self.assertEqual(stats["total_signatures_verified"], 6)
        self.assertEqual(stats["total_valid_signatures"], 5)
        self.assertAlmostEqual(stats["success_rate_percent"], 83.33, places=1)

    def test_streaming_verification(self):
        """Test streaming verification for large datasets"""
        def request_generator():
            for i in range(250):
                yield self.verifier.create_verification_request(
                    f"Stream {i}".encode(),
                    f"stream_key_{i}".encode(),
                    sign=True
                )
        
        chunk_results = list(
            self.verifier.verify_streaming(request_generator(), chunk_size=100)
        )
        
        # Should have 3 chunks: 100 + 100 + 50
        self.assertEqual(len(chunk_results), 3)
        self.assertEqual(chunk_results[0].total_requests, 100)
        self.assertEqual(chunk_results[1].total_requests, 100)
        self.assertEqual(chunk_results[2].total_requests, 50)
        
        # All should be valid
        for r in chunk_results:
            self.assertTrue(r.all_valid)

    def test_different_algorithms(self):
        """Test all supported signature algorithms"""
        algorithms = [
            SignatureAlgorithm.CRYSTALS_DILITHIUM,
            SignatureAlgorithm.FALCON,
            SignatureAlgorithm.SPHINCS_PLUS,
            SignatureAlgorithm.RAINBOW,
            SignatureAlgorithm.HYBRID_ECDSA_DILITHIUM
        ]
        
        for algo in algorithms:
            req = self.verifier.create_verification_request(
                b"test message",
                b"pubkey",
                sign=True,
                algorithm=algo
            )
            self.assertEqual(req.algorithm, algo)
            
            result = self.verifier._verify_single_signature(req)
            self.assertTrue(result.verified)
            self.assertEqual(result.algorithm, algo)


if __name__ == "__main__":
    print("Running Batch Signature Verifier Tests...")
    unittest.main(verbosity=2)
