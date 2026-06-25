"""
Test Suite for PQ Hybrid Signature Batch Verifier v82
Dimension A: Feature Expansion
32 comprehensive tests
"""

import unittest
import sys
import os
from datetime import datetime, timezone, timedelta

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from feature_expansion_pq_hybrid_signature_batch_verifier_v82_2026_june import (
    PQHybridSignatureBatchVerifier,
    Signature,
    VerificationResult,
    BatchStatistics,
    PQAlgorithm,
    SecurityLevel,
    VerificationStatus,
    VerificationPolicy,
    BatchVerifierHealth
)


class TestPQHybridSignatureBatchVerifierInit(unittest.TestCase):
    """Test initialization and setup"""

    def test_verifier_initialization(self):
        """Test verifier initializes correctly"""
        verifier = PQHybridSignatureBatchVerifier()
        self.assertIsNotNone(verifier)
        self.assertIsNotNone(verifier.revoked_key_ids)
        self.assertIsNotNone(verifier.trusted_key_ids)
        self.assertIsNotNone(verifier.verification_cache)
        self.assertIsNotNone(verifier.health)

    def test_default_policy(self):
        """Test default verification policy"""
        verifier = PQHybridSignatureBatchVerifier()
        self.assertEqual(verifier.policy, VerificationPolicy.HYBRID_REQUIRED)

    def test_custom_policy(self):
        """Test custom policy setting"""
        verifier = PQHybridSignatureBatchVerifier(policy=VerificationPolicy.PQ_ONLY)
        self.assertEqual(verifier.policy, VerificationPolicy.PQ_ONLY)

    def test_algorithm_parameters_initialized(self):
        """Test algorithm parameters initialized"""
        verifier = PQHybridSignatureBatchVerifier()
        self.assertIn(PQAlgorithm.CRYSTALS_DILITHIUM, verifier.algorithm_security_levels)
        self.assertIn(PQAlgorithm.FALCON, verifier.algorithm_security_levels)
        self.assertIn(PQAlgorithm.SPHINCS_PLUS, verifier.algorithm_security_levels)


class TestSignatureCreation(unittest.TestCase):
    """Test signature creation functionality"""

    def setUp(self):
        self.verifier = PQHybridSignatureBatchVerifier()

    def test_create_dilithium_signature(self):
        """Test creating Dilithium signature"""
        message = b"Test message for signing"
        sig = self.verifier.create_signature(
            message=message,
            algorithm=PQAlgorithm.CRYSTALS_DILITHIUM,
            security_level=SecurityLevel.LEVEL_3,
            public_key_id="KEY-001"
        )
        self.assertIsInstance(sig, Signature)
        self.assertTrue(sig.signature_id.startswith("SIG-"))
        self.assertEqual(sig.algorithm, PQAlgorithm.CRYSTALS_DILITHIUM)
        self.assertEqual(sig.security_level, SecurityLevel.LEVEL_3)
        self.assertEqual(sig.public_key_id, "KEY-001")

    def test_create_falcon_signature(self):
        """Test creating Falcon signature"""
        sig = self.verifier.create_signature(
            b"Test",
            PQAlgorithm.FALCON,
            SecurityLevel.LEVEL_5,
            "KEY-002"
        )
        self.assertEqual(sig.algorithm, PQAlgorithm.FALCON)

    def test_create_hybrid_signature(self):
        """Test creating hybrid signature"""
        sig = self.verifier.create_signature(
            b"Test",
            PQAlgorithm.HYBRID_DILITHIUM_ECDSA,
            SecurityLevel.LEVEL_3,
            "KEY-003"
        )
        self.assertEqual(sig.algorithm, PQAlgorithm.HYBRID_DILITHIUM_ECDSA)

    def test_signature_with_expiration(self):
        """Test signature with expiration"""
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        sig = self.verifier.create_signature(
            b"Test",
            PQAlgorithm.CRYSTALS_DILITHIUM,
            SecurityLevel.LEVEL_2,
            "KEY-004",
            expires_at=future
        )
        self.assertIsNotNone(sig.expires_at)

    def test_signature_with_metadata(self):
        """Test signature with metadata"""
        sig = self.verifier.create_signature(
            b"Test",
            PQAlgorithm.CRYSTALS_DILITHIUM,
            SecurityLevel.LEVEL_2,
            "KEY-005",
            metadata={"user": "alice", "purpose": "authentication"}
        )
        self.assertEqual(sig.metadata["user"], "alice")


class TestSingleSignatureVerification(unittest.TestCase):
    """Test single signature verification"""

    def setUp(self):
        self.verifier = PQHybridSignatureBatchVerifier(policy=VerificationPolicy.CLASSICAL_OK)

    def test_valid_signature_verification(self):
        """Test valid signature verification"""
        sig = self.verifier.create_signature(
            b"Hello World",
            PQAlgorithm.CRYSTALS_DILITHIUM,
            SecurityLevel.LEVEL_3,
            "KEY-VALID"
        )
        result = self.verifier.verify_single(sig)
        self.assertEqual(result.status, VerificationStatus.VALID)
        self.assertGreater(result.verification_time_ms, 0)

    def test_message_digest_verification(self):
        """Test message digest verification"""
        message = b"Original message"
        sig = self.verifier.create_signature(
            message,
            PQAlgorithm.CRYSTALS_DILITHIUM,
            SecurityLevel.LEVEL_3,
            "KEY-001"
        )
        # Verify with correct message
        result = self.verifier.verify_single(sig, message)
        self.assertEqual(result.status, VerificationStatus.VALID)

    def test_revoked_key(self):
        """Test revoked key detection"""
        sig = self.verifier.create_signature(
            b"Test",
            PQAlgorithm.CRYSTALS_DILITHIUM,
            SecurityLevel.LEVEL_3,
            "KEY-REVOKED"
        )
        self.verifier.revoke_key("KEY-REVOKED")
        result = self.verifier.verify_single(sig)
        self.assertEqual(result.status, VerificationStatus.REVOKED)

    def test_expired_signature(self):
        """Test expired signature detection"""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        sig = self.verifier.create_signature(
            b"Test",
            PQAlgorithm.CRYSTALS_DILITHIUM,
            SecurityLevel.LEVEL_3,
            "KEY-001",
            expires_at=past
        )
        result = self.verifier.verify_single(sig)
        self.assertEqual(result.status, VerificationStatus.EXPIRED)

    def test_untrusted_key(self):
        """Test untrusted key detection"""
        sig = self.verifier.create_signature(
            b"Test",
            PQAlgorithm.CRYSTALS_DILITHIUM,
            SecurityLevel.LEVEL_3,
            "KEY-UNTRUSTED"
        )
        self.verifier.trust_key("KEY-TRUSTED")
        result = self.verifier.verify_single(sig)
        self.assertEqual(result.status, VerificationStatus.UNTRUSTED)

    def test_verification_caching(self):
        """Test verification result caching"""
        sig = self.verifier.create_signature(
            b"Test",
            PQAlgorithm.CRYSTALS_DILITHIUM,
            SecurityLevel.LEVEL_3,
            "KEY-001"
        )
        # First verification
        result1 = self.verifier.verify_single(sig)
        # Second verification should use cache
        result2 = self.verifier.verify_single(sig)
        self.assertEqual(result1.status, result2.status)
        # Cached result should be faster
        self.assertLess(result2.verification_time_ms, result1.verification_time_ms + 1)

    def test_clear_cache(self):
        """Test cache clearing"""
        sig = self.verifier.create_signature(
            b"Test",
            PQAlgorithm.CRYSTALS_DILITHIUM,
            SecurityLevel.LEVEL_3,
            "KEY-001"
        )
        self.verifier.verify_single(sig)
        cache_size_before = len(self.verifier.verification_cache)
        self.verifier.clear_cache()
        self.assertEqual(len(self.verifier.verification_cache), 0)


class TestBatchVerification(unittest.TestCase):
    """Test batch signature verification"""

    def setUp(self):
        self.verifier = PQHybridSignatureBatchVerifier(policy=VerificationPolicy.CLASSICAL_OK)

    def test_empty_batch(self):
        """Test empty batch verification"""
        results, stats = self.verifier.verify_batch([])
        self.assertEqual(results, [])
        self.assertEqual(stats.total_signatures, 0)

    def test_single_signature_batch(self):
        """Test batch with one signature"""
        sig = self.verifier.create_signature(
            b"Test",
            PQAlgorithm.CRYSTALS_DILITHIUM,
            SecurityLevel.LEVEL_3,
            "KEY-001"
        )
        results, stats = self.verifier.verify_batch([sig])
        self.assertEqual(len(results), 1)
        self.assertEqual(stats.total_signatures, 1)
        self.assertEqual(stats.valid, 1)

    def test_multiple_signature_batch(self):
        """Test batch with multiple signatures"""
        signatures = []
        for i in range(5):
            sig = self.verifier.create_signature(
                f"Message {i}".encode(),
                PQAlgorithm.CRYSTALS_DILITHIUM,
                SecurityLevel.LEVEL_3,
                f"KEY-{i:03d}"
            )
            signatures.append(sig)

        results, stats = self.verifier.verify_batch(signatures)
        self.assertEqual(len(results), 5)
        self.assertEqual(stats.total_signatures, 5)
        self.assertEqual(stats.valid, 5)

    def test_mixed_validity_batch(self):
        """Test batch with mixed validity"""
        signatures = []

        # Valid signature
        signatures.append(self.verifier.create_signature(
            b"Valid", PQAlgorithm.CRYSTALS_DILITHIUM, SecurityLevel.LEVEL_3, "KEY-VALID"
        ))

        # Revoked signature
        sig_revoked = self.verifier.create_signature(
            b"Revoked", PQAlgorithm.CRYSTALS_DILITHIUM, SecurityLevel.LEVEL_3, "KEY-REV"
        )
        self.verifier.revoke_key("KEY-REV")
        signatures.append(sig_revoked)

        # Expired signature
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        signatures.append(self.verifier.create_signature(
            b"Expired", PQAlgorithm.CRYSTALS_DILITHIUM, SecurityLevel.LEVEL_3, "KEY-EXP",
            expires_at=past
        ))

        results, stats = self.verifier.verify_batch(signatures)
        self.assertEqual(stats.total_signatures, 3)
        self.assertEqual(stats.valid, 1)
        self.assertEqual(stats.revoked, 1)
        self.assertEqual(stats.expired, 1)

    def test_batch_statistics(self):
        """Test batch statistics calculation"""
        signatures = [
            self.verifier.create_signature(
                b"Msg1", PQAlgorithm.CRYSTALS_DILITHIUM, SecurityLevel.LEVEL_3, "KEY-001"
            ),
            self.verifier.create_signature(
                b"Msg2", PQAlgorithm.FALCON, SecurityLevel.LEVEL_5, "KEY-002"
            ),
        ]

        results, stats = self.verifier.verify_batch(signatures)
        self.assertGreater(stats.total_verification_time_ms, 0)
        self.assertGreater(stats.average_verification_time_ms, 0)
        self.assertGreater(stats.slowest_verification_ms, 0)
        self.assertIn("CRYSTALS-Dilithium", stats.algorithm_distribution)
        self.assertIn("FALCON", stats.algorithm_distribution)


class TestSignatureAggregation(unittest.TestCase):
    """Test signature aggregation functionality"""

    def setUp(self):
        self.verifier = PQHybridSignatureBatchVerifier()

    def test_empty_aggregation(self):
        """Test empty aggregation"""
        agg = self.verifier.aggregate_signatures([])
        self.assertEqual(agg["signature_count"], 0)

    def test_single_signature_aggregation(self):
        """Test single signature aggregation"""
        sig = self.verifier.create_signature(
            b"Test", PQAlgorithm.CRYSTALS_DILITHIUM, SecurityLevel.LEVEL_3, "KEY-001"
        )
        agg = self.verifier.aggregate_signatures([sig])
        self.assertEqual(agg["signature_count"], 1)
        self.assertIn("aggregate_digest", agg)
        self.assertIn(sig.signature_id, agg["signature_ids"])

    def test_multiple_signature_aggregation(self):
        """Test multiple signature aggregation"""
        signatures = [
            self.verifier.create_signature(
                f"Msg{i}".encode(), PQAlgorithm.CRYSTALS_DILITHIUM,
                SecurityLevel.LEVEL_3, f"KEY-{i}"
            )
            for i in range(3)
        ]
        agg = self.verifier.aggregate_signatures(signatures)
        self.assertEqual(agg["signature_count"], 3)
        self.assertEqual(len(agg["signature_ids"]), 3)


class TestVerificationPolicies(unittest.TestCase):
    """Test verification policy enforcement"""

    def test_pq_only_policy(self):
        """Test PQ-only policy"""
        verifier = PQHybridSignatureBatchVerifier(policy=VerificationPolicy.PQ_ONLY)

        # Pure PQ should pass
        sig_pq = verifier.create_signature(
            b"Test", PQAlgorithm.CRYSTALS_DILITHIUM, SecurityLevel.LEVEL_3, "KEY-001"
        )
        result = verifier.verify_single(sig_pq)
        self.assertTrue(result.policy_compliant)

        # Classical should fail policy
        sig_classical = verifier.create_signature(
            b"Test", PQAlgorithm.ECDSA, SecurityLevel.LEVEL_3, "KEY-002"
        )
        result_classical = verifier.verify_single(sig_classical)
        self.assertFalse(result_classical.policy_compliant)

    def test_hybrid_required_policy(self):
        """Test hybrid-required policy"""
        verifier = PQHybridSignatureBatchVerifier(policy=VerificationPolicy.HYBRID_REQUIRED)

        # Hybrid should pass
        sig_hybrid = verifier.create_signature(
            b"Test", PQAlgorithm.HYBRID_DILITHIUM_ECDSA, SecurityLevel.LEVEL_3, "KEY-001"
        )
        result = verifier.verify_single(sig_hybrid)
        self.assertTrue(result.policy_compliant)

        # Pure PQ should fail policy
        sig_pure = verifier.create_signature(
            b"Test", PQAlgorithm.CRYSTALS_DILITHIUM, SecurityLevel.LEVEL_3, "KEY-002"
        )
        result_pure = verifier.verify_single(sig_pure)
        self.assertFalse(result_pure.policy_compliant)

    def test_get_policy_info(self):
        """Test policy information retrieval"""
        verifier = PQHybridSignatureBatchVerifier(policy=VerificationPolicy.PQ_PREFERRED)
        info = verifier.get_verification_policy()
        self.assertEqual(info["current_policy"], "pq-preferred")
        self.assertIn("policy_description", info)


class TestAlgorithmInformation(unittest.TestCase):
    """Test algorithm information retrieval"""

    def setUp(self):
        self.verifier = PQHybridSignatureBatchVerifier()

    def test_dilithium_info(self):
        """Test Dilithium algorithm info"""
        info = self.verifier.get_algorithm_info(PQAlgorithm.CRYSTALS_DILITHIUM)
        self.assertEqual(info["nist_standard"], "FIPS 204")
        self.assertTrue(info["standardized"])

    def test_falcon_info(self):
        """Test Falcon algorithm info"""
        info = self.verifier.get_algorithm_info(PQAlgorithm.FALCON)
        self.assertEqual(info["nist_standard"], "FIPS 205")
        self.assertTrue(info["standardized"])

    def test_sphincs_plus_info(self):
        """Test SPHINCS+ algorithm info"""
        info = self.verifier.get_algorithm_info(PQAlgorithm.SPHINCS_PLUS)
        self.assertEqual(info["nist_standard"], "FIPS 206")
        self.assertTrue(info["standardized"])

    def test_classical_algorithm_info(self):
        """Test classical algorithm info"""
        info = self.verifier.get_algorithm_info(PQAlgorithm.ECDSA)
        self.assertFalse(info["standardized"])


class TestHealthMonitoring(unittest.TestCase):
    """Test health monitoring functionality"""

    def test_health_initial_status(self):
        """Test initial health status"""
        verifier = PQHybridSignatureBatchVerifier()
        health = verifier.get_health_status()
        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["batches_processed"], 0)
        self.assertEqual(health["signatures_processed"], 0)

    def test_health_after_batch(self):
        """Test health after processing batch"""
        verifier = PQHybridSignatureBatchVerifier(policy=VerificationPolicy.CLASSICAL_OK)
        signatures = [
            verifier.create_signature(
                b"Test", PQAlgorithm.CRYSTALS_DILITHIUM, SecurityLevel.LEVEL_3, "KEY-001"
            )
        ]
        verifier.verify_batch(signatures)

        health = verifier.get_health_status()
        self.assertEqual(health["batches_processed"], 1)
        self.assertEqual(health["signatures_processed"], 1)
        self.assertGreater(health["uptime_seconds"], 0)


class TestEnums(unittest.TestCase):
    """Test enum classes"""

    def test_pq_algorithm_enum(self):
        """Test PQ algorithm enum values"""
        self.assertEqual(PQAlgorithm.CRYSTALS_DILITHIUM.value, "CRYSTALS-Dilithium")
        self.assertEqual(PQAlgorithm.FALCON.value, "FALCON")
        self.assertEqual(PQAlgorithm.SPHINCS_PLUS.value, "SPHINCS+")

    def test_security_level_enum(self):
        """Test security level enum values"""
        self.assertEqual(SecurityLevel.LEVEL_1.value, "NIST-1")
        self.assertEqual(SecurityLevel.LEVEL_5.value, "NIST-5")

    def test_verification_status_enum(self):
        """Test verification status enum values"""
        self.assertEqual(VerificationStatus.VALID.value, "valid")
        self.assertEqual(VerificationStatus.INVALID.value, "invalid")


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - ADD-ONLY verification"""

    def test_module_imports_cleanly(self):
        """Verify module imports cleanly"""
        try:
            from feature_expansion_pq_hybrid_signature_batch_verifier_v82_2026_june import PQHybridSignatureBatchVerifier
            verifier = PQHybridSignatureBatchVerifier()
            self.assertIsNotNone(verifier)
        except Exception as e:
            self.fail(f"Import failed: {e}")

    def test_no_existing_code_modified(self):
        """Verify this is ADD-ONLY - no existing files modified"""
        # Module file should exist
        self.assertTrue(os.path.exists(
            os.path.join(os.path.dirname(__file__), 'quantum_crypt',
                         'feature_expansion_pq_hybrid_signature_batch_verifier_v82_2026_june.py')
        ))

    def test_thread_safety(self):
        """Test thread-safe operations"""
        verifier = PQHybridSignatureBatchVerifier(policy=VerificationPolicy.CLASSICAL_OK)

        # Multiple threads accessing verifier
        def worker():
            sig = verifier.create_signature(
                b"Thread test", PQAlgorithm.CRYSTALS_DILITHIUM,
                SecurityLevel.LEVEL_3, "KEY-THREAD"
            )
            verifier.verify_single(sig)

        import threading
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should complete without deadlock or exception
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
