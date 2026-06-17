"""
Test suite for Post-Quantum API Request Signer - QuantumCrypt-AI
June 2026 Production Release
"""

import unittest
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.post_quantum_api_request_signer_2026_june import (
    PostQuantumAPISigner,
    create_api_signer,
    SignatureAlgorithm,
    VerificationResult,
    SignedRequest,
    SigningResult,
    VerificationOutput
)


class TestPostQuantumAPISigner(unittest.TestCase):
    """Test cases for API request signer."""

    def setUp(self):
        """Set up test fixtures."""
        self.signer = PostQuantumAPISigner(tolerance_seconds=300)

    def test_signer_initialization(self):
        """Test signer initialization."""
        self.assertIsNotNone(self.signer)
        self.assertEqual(self.signer.tolerance_seconds, 300)

    def test_factory_function(self):
        """Test factory function creates signer correctly."""
        signer = create_api_signer(tolerance_seconds=600)
        self.assertIsNotNone(signer)
        self.assertEqual(signer.tolerance_seconds, 600)

    def test_generate_api_key(self):
        """Test API key generation."""
        key_id, secret = self.signer.generate_api_key()

        self.assertIsNotNone(key_id)
        self.assertIsNotNone(secret)
        self.assertTrue(key_id.startswith("pk_"))
        self.assertEqual(len(secret), 128)  # 64 bytes = 128 hex chars

    def test_register_api_key(self):
        """Test API key registration."""
        key_id = "test_key_123"
        secret = "a" * 128  # 64 bytes hex

        result = self.signer.register_api_key(key_id, secret)
        self.assertTrue(result)

    def test_sign_request_success(self):
        """Test successful request signing."""
        key_id, _ = self.signer.generate_api_key()

        result = self.signer.sign_request(
            api_key_id=key_id,
            method="POST",
            endpoint="/api/v1/data",
            body='{"data": "test"}'
        )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.signed_request)
        self.assertEqual(result.signed_request.method, "POST")
        self.assertEqual(result.signed_request.endpoint, "/api/v1/data")
        self.assertIsNotNone(result.signed_request.signature)
        self.assertIsNotNone(result.signed_request.nonce)

    def test_sign_request_unknown_key(self):
        """Test signing with unknown key."""
        result = self.signer.sign_request(
            api_key_id="unknown_key",
            method="GET",
            endpoint="/api/test"
        )

        self.assertFalse(result.success)
        self.assertIsNone(result.signed_request)
        self.assertIn("Unknown API key", result.error_message)

    def test_verify_request_valid(self):
        """Test valid request verification."""
        key_id, _ = self.signer.generate_api_key()

        # Sign request
        sign_result = self.signer.sign_request(
            api_key_id=key_id,
            method="POST",
            endpoint="/api/v1/data",
            body='{"data": "test"}'
        )

        self.assertTrue(sign_result.success)
        req = sign_result.signed_request

        # Verify request
        verify_result = self.signer.verify_request(
            method=req.method,
            endpoint=req.endpoint,
            body=req.body,
            api_key_id=req.api_key_id,
            timestamp=req.timestamp,
            nonce=req.nonce,
            signature=req.signature
        )

        self.assertTrue(verify_result.is_valid)
        self.assertEqual(verify_result.result, VerificationResult.VALID)

    def test_verify_request_invalid_signature(self):
        """Test verification with invalid signature."""
        key_id, _ = self.signer.generate_api_key()

        sign_result = self.signer.sign_request(
            api_key_id=key_id,
            method="GET",
            endpoint="/api/test"
        )

        req = sign_result.signed_request

        # Verify with wrong signature
        verify_result = self.signer.verify_request(
            method=req.method,
            endpoint=req.endpoint,
            body=req.body,
            api_key_id=req.api_key_id,
            timestamp=req.timestamp,
            nonce=req.nonce,
            signature="wrong_signature"
        )

        self.assertFalse(verify_result.is_valid)
        self.assertEqual(verify_result.result, VerificationResult.INVALID_SIGNATURE)

    def test_verify_request_expired_timestamp(self):
        """Test verification with expired timestamp."""
        key_id, _ = self.signer.generate_api_key()

        sign_result = self.signer.sign_request(
            api_key_id=key_id,
            method="GET",
            endpoint="/api/test"
        )

        req = sign_result.signed_request

        # Verify with old timestamp (10 minutes ago)
        old_timestamp = int(time.time()) - 600
        verify_result = self.signer.verify_request(
            method=req.method,
            endpoint=req.endpoint,
            body=req.body,
            api_key_id=req.api_key_id,
            timestamp=old_timestamp,
            nonce=req.nonce,
            signature=req.signature
        )

        self.assertFalse(verify_result.is_valid)
        self.assertEqual(verify_result.result, VerificationResult.TIMESTAMP_EXPIRED)

    def test_verify_request_nonce_reuse(self):
        """Test nonce reuse detection."""
        key_id, _ = self.signer.generate_api_key()

        sign_result = self.signer.sign_request(
            api_key_id=key_id,
            method="GET",
            endpoint="/api/test"
        )

        req = sign_result.signed_request

        # First verification should pass
        result1 = self.signer.verify_request(
            method=req.method,
            endpoint=req.endpoint,
            body=req.body,
            api_key_id=req.api_key_id,
            timestamp=req.timestamp,
            nonce=req.nonce,
            signature=req.signature
        )
        self.assertTrue(result1.is_valid)

        # Second verification with same nonce should fail
        result2 = self.signer.verify_request(
            method=req.method,
            endpoint=req.endpoint,
            body=req.body,
            api_key_id=req.api_key_id,
            timestamp=req.timestamp,
            nonce=req.nonce,
            signature=req.signature
        )
        self.assertFalse(result2.is_valid)
        self.assertEqual(result2.result, VerificationResult.NONCE_REUSED)

    def test_verify_request_missing_fields(self):
        """Test verification with missing fields."""
        result = self.signer.verify_request(
            method="GET",
            endpoint="/test",
            body=None,
            api_key_id="",
            timestamp=0,
            nonce="",
            signature=""
        )

        self.assertFalse(result.is_valid)
        self.assertEqual(result.result, VerificationResult.MISSING_HEADERS)

    def test_signed_request_to_headers(self):
        """Test signed request header conversion."""
        key_id, _ = self.signer.generate_api_key()

        sign_result = self.signer.sign_request(
            api_key_id=key_id,
            method="POST",
            endpoint="/api/data",
            body="test"
        )

        headers = sign_result.signed_request.to_headers()

        self.assertIn("X-API-Key-ID", headers)
        self.assertIn("X-Request-Timestamp", headers)
        self.assertIn("X-Request-Nonce", headers)
        self.assertIn("X-Signature-Algorithm", headers)
        self.assertIn("X-Request-Signature", headers)

    def test_revoke_api_key(self):
        """Test API key revocation."""
        key_id, _ = self.signer.generate_api_key()

        # Revoke key
        result = self.signer.revoke_api_key(key_id)
        self.assertTrue(result)

        # Try to sign with revoked key
        sign_result = self.signer.sign_request(
            api_key_id=key_id,
            method="GET",
            endpoint="/test"
        )
        self.assertFalse(sign_result.success)

    def test_get_statistics(self):
        """Test statistics tracking."""
        key_id, _ = self.signer.generate_api_key()

        # Perform some operations
        for _ in range(3):
            self.signer.sign_request(key_id, "GET", "/test")

        stats = self.signer.get_statistics()

        self.assertIn("signing_operations", stats)
        self.assertIn("verification_operations", stats)
        self.assertIn("active_api_keys", stats)
        self.assertGreaterEqual(stats["signing_operations"], 3)

    def test_empty_body_signing(self):
        """Test signing requests with empty body."""
        key_id, _ = self.signer.generate_api_key()

        result = self.signer.sign_request(
            api_key_id=key_id,
            method="GET",
            endpoint="/api/data",
            body=None
        )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.signed_request.signature)

    def test_different_endpoints_different_signatures(self):
        """Test that different endpoints produce different signatures."""
        key_id, _ = self.signer.generate_api_key()

        result1 = self.signer.sign_request(key_id, "GET", "/api/endpoint1")
        result2 = self.signer.sign_request(key_id, "GET", "/api/endpoint2")

        self.assertNotEqual(
            result1.signed_request.signature,
            result2.signed_request.signature
        )


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPostQuantumAPISigner)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("Post-Quantum API Request Signer - Test Suite")
    print("QuantumCrypt-AI June 2026 Production Release")
    print("=" * 60)
    print()

    result = run_tests()

    print()
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
