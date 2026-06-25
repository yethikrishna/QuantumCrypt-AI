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

# Add quantum_crypto to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypto'))

from feature_expansion_pq_batch_verifier_v84 import (
    BatchSignatureVerifier,
    HybridSignatureVerifier,
    SignatureVerificationRequest,
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
    
    def test_valid_signature_verification(self):
        """Test valid signature verification"""
        import hmac
        import hashlib
        
        pubkey = b"test_public_key_12345"
        message = b"Hello, Post-Quantum World!"
        algo = SignatureAlgorithm.DILITHIUM_3
        
        expected_sig = hmac.new(
            pubkey,
            message + algo.value.encode(),
            hashlib.sha256
        ).digest()
        
        request = SignatureVerificationRequest(
            message=message,
            signature=expected_sig,
            public_key=pubkey,
            algorithm=algo
        )
        
        result = self.verifier.verify_signature(request)
        self.assertTrue(result.valid)
        self.assertEqual(result.status, VerificationStatus.VALID)
    
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


class TestBatchSignatureVerifierBasic(unittest.TestCase):
    """Basic batch verification tests"""
    
    def setUp(self):
        self.batch_verifier = BatchSignatureVerifier(max_workers=2)
    
    def test_batch_verifier_initialization(self):
        """Test batch verifier initializes correctly"""
        self.assertEqual(self.batch_verifier.VERSION, "v84_2026_june")
    
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
        self.assertTrue(result.all_valid)


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
        
        verifier.verify_batch([request])
        verifier.verify_batch([request])
        stats = verifier.get_statistics()
        
        self.assertEqual(stats["cache_hits"], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
