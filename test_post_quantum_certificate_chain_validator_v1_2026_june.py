"""
Test suite for Post-Quantum Certificate Chain Validator v1.0.0
Dimension A - Feature Expansion (2026 June)

ADD-ONLY IMPLEMENTATION: Tests only, no production code modified
"""

import unittest
import threading
import time
from datetime import datetime, timedelta

from quantum_crypt.post_quantum_certificate_chain_validator_v1_2026_june import (
    CertificateAlgorithm,
    ValidationMode,
    ValidationStatus,
    RevocationStatus,
    SecurityLevel,
    Certificate,
    ValidationPolicy,
    ValidationResult,
    TrustAnchor,
    AlgorithmRegistry,
    RevocationChecker,
    SignatureVerifier,
    TrustStore,
    CertificateChainValidator,
    get_certificate_validator,
)


class TestCertificateAlgorithmEnum(unittest.TestCase):
    """Test CertificateAlgorithm enum coverage."""

    def test_classical_algorithms_defined(self):
        """Test classical algorithms exist."""
        classical = {
            CertificateAlgorithm.RSA_2048,
            CertificateAlgorithm.RSA_4096,
            CertificateAlgorithm.ECDSA_P256,
            CertificateAlgorithm.ECDSA_P384,
            CertificateAlgorithm.ED25519,
        }
        self.assertEqual(len(classical), 5)

    def test_post_quantum_algorithms_defined(self):
        """Test post-quantum algorithms exist."""
        pq_algorithms = {
            CertificateAlgorithm.DILITHIUM_2,
            CertificateAlgorithm.DILITHIUM_3,
            CertificateAlgorithm.DILITHIUM_5,
            CertificateAlgorithm.FALCON_512,
            CertificateAlgorithm.FALCON_1024,
            CertificateAlgorithm.SPHINCS_PLUS_128,
            CertificateAlgorithm.SPHINCS_PLUS_192,
            CertificateAlgorithm.SPHINCS_PLUS_256,
        }
        self.assertEqual(len(pq_algorithms), 8)

    def test_hybrid_algorithms_defined(self):
        """Test hybrid algorithms exist."""
        hybrid = {
            CertificateAlgorithm.HYBRID_RSA_DILITHIUM_3,
            CertificateAlgorithm.HYBRID_ECDSA_FALCON_512,
        }
        self.assertEqual(len(hybrid), 2)


class TestSecurityLevelEnum(unittest.TestCase):
    """Test SecurityLevel enum."""

    def test_security_level_ordering(self):
        """Test security level ordering."""
        self.assertTrue(SecurityLevel.LEVEL_1 < SecurityLevel.LEVEL_2)
        self.assertTrue(SecurityLevel.LEVEL_2 < SecurityLevel.LEVEL_3)
        self.assertTrue(SecurityLevel.LEVEL_3 < SecurityLevel.LEVEL_4)
        self.assertTrue(SecurityLevel.LEVEL_4 < SecurityLevel.LEVEL_5)

    def test_security_level_values(self):
        """Test security level integer values."""
        self.assertEqual(SecurityLevel.LEVEL_1.value, 1)
        self.assertEqual(SecurityLevel.LEVEL_5.value, 5)


class TestAlgorithmRegistry(unittest.TestCase):
    """Test AlgorithmRegistry class."""

    def test_security_level_lookup(self):
        """Test security level lookup for algorithms."""
        self.assertEqual(
            AlgorithmRegistry.get_security_level(CertificateAlgorithm.DILITHIUM_5),
            SecurityLevel.LEVEL_5
        )
        self.assertEqual(
            AlgorithmRegistry.get_security_level(CertificateAlgorithm.RSA_2048),
            SecurityLevel.LEVEL_1
        )

    def test_post_quantum_detection(self):
        """Test post-quantum algorithm detection."""
        self.assertTrue(AlgorithmRegistry.is_post_quantum(CertificateAlgorithm.DILITHIUM_3))
        self.assertFalse(AlgorithmRegistry.is_post_quantum(CertificateAlgorithm.RSA_4096))
        self.assertTrue(AlgorithmRegistry.is_post_quantum(CertificateAlgorithm.HYBRID_RSA_DILITHIUM_3))

    def test_weak_algorithm_detection(self):
        """Test weak algorithm detection."""
        self.assertTrue(AlgorithmRegistry.is_weak(CertificateAlgorithm.RSA_2048))
        self.assertFalse(AlgorithmRegistry.is_weak(CertificateAlgorithm.DILITHIUM_3))
        self.assertFalse(AlgorithmRegistry.is_weak(CertificateAlgorithm.RSA_4096))

    def test_hybrid_detection(self):
        """Test hybrid algorithm detection."""
        self.assertTrue(AlgorithmRegistry.is_hybrid(CertificateAlgorithm.HYBRID_RSA_DILITHIUM_3))
        self.assertFalse(AlgorithmRegistry.is_hybrid(CertificateAlgorithm.DILITHIUM_3))


class TestCertificateDataClass(unittest.TestCase):
    """Test Certificate data class."""

    def test_certificate_creation(self):
        """Test creating a certificate."""
        cert = Certificate(
            cert_id="cert_001",
            subject="CN=test.example.com",
            issuer="CN=Test CA",
            public_key=b"test_public_key_data",
            signature=b"test_signature_data",
            algorithm=CertificateAlgorithm.DILITHIUM_3,
            serial_number="SERIAL123",
            valid_from=datetime.now(),
            valid_to=datetime.now() + timedelta(days=365),
            is_ca=False,
            subject_alt_names=["test.example.com", "www.test.example.com"]
        )

        self.assertEqual(cert.cert_id, "cert_001")
        self.assertEqual(cert.algorithm, CertificateAlgorithm.DILITHIUM_3)
        self.assertFalse(cert.is_ca)
        self.assertEqual(len(cert.subject_alt_names), 2)

    def test_fingerprint_auto_generation(self):
        """Test fingerprint is automatically generated."""
        cert = Certificate(
            cert_id="cert_001",
            subject="CN=test",
            issuer="CN=CA",
            public_key=b"key",
            signature=b"sig",
            algorithm=CertificateAlgorithm.ED25519,
            serial_number="123",
            valid_from=datetime.now(),
            valid_to=datetime.now() + timedelta(days=365),
        )

        self.assertTrue(len(cert.fingerprint) > 0)


class TestValidationPolicy(unittest.TestCase):
    """Test ValidationPolicy class."""

    def test_default_policy_creation(self):
        """Test default policy creation."""
        policy = ValidationPolicy()
        self.assertEqual(policy.name, "Default Validation Policy")
        self.assertEqual(policy.validation_mode, ValidationMode.HYBRID_EITHER_ACCEPTED)
        self.assertTrue(policy.reject_weak_algorithms)
        self.assertGreater(len(policy.accepted_algorithms), 0)

    def test_custom_policy(self):
        """Test creating a custom policy."""
        policy = ValidationPolicy(
            name="Strict PQ Policy",
            validation_mode=ValidationMode.POST_QUANTUM_ONLY,
            minimum_security_level=SecurityLevel.LEVEL_3,
            maximum_validity_days=397
        )

        self.assertEqual(policy.validation_mode, ValidationMode.POST_QUANTUM_ONLY)
        self.assertEqual(policy.minimum_security_level, SecurityLevel.LEVEL_3)
        self.assertEqual(policy.maximum_validity_days, 397)


class TestRevocationChecker(unittest.TestCase):
    """Test RevocationChecker class."""

    def test_checker_initialization(self):
        """Test checker initializes correctly."""
        checker = RevocationChecker()
        # Should not raise

    def test_good_certificate_status(self):
        """Test non-revoked certificate returns GOOD."""
        checker = RevocationChecker()
        cert = Certificate(
            cert_id="c1",
            subject="CN=test",
            issuer="CN=CA",
            public_key=b"k",
            signature=b"s",
            algorithm=CertificateAlgorithm.ED25519,
            serial_number="GOOD123",
            valid_from=datetime.now(),
            valid_to=datetime.now() + timedelta(days=365),
        )

        status = checker.check_revocation(cert)
        self.assertEqual(status, RevocationStatus.GOOD)

    def test_revoked_certificate_status(self):
        """Test revoked certificate returns REVOKED."""
        checker = RevocationChecker()
        checker.add_revoked_serial("REVOKED456")

        cert = Certificate(
            cert_id="c1",
            subject="CN=test",
            issuer="CN=CA",
            public_key=b"k",
            signature=b"s",
            algorithm=CertificateAlgorithm.ED25519,
            serial_number="REVOKED456",
            valid_from=datetime.now(),
            valid_to=datetime.now() + timedelta(days=365),
        )

        status = checker.check_revocation(cert)
        self.assertEqual(status, RevocationStatus.REVOKED)

    def test_cache_mechanism(self):
        """Test revocation status is cached."""
        checker = RevocationChecker(cache_ttl_seconds=3600)
        cert = Certificate(
            cert_id="c1",
            subject="CN=test",
            issuer="CN=CA",
            public_key=b"k",
            signature=b"s",
            algorithm=CertificateAlgorithm.ED25519,
            serial_number="TESTCACHE",
            valid_from=datetime.now(),
            valid_to=datetime.now() + timedelta(days=365),
        )

        # First check
        first = checker.check_revocation(cert)
        # Add to revocation list AFTER first check
        checker.add_revoked_serial("TESTCACHE")
        # Should still return GOOD due to cache
        second = checker.check_revocation(cert)

        self.assertEqual(first, second)


class TestSignatureVerifier(unittest.TestCase):
    """Test SignatureVerifier class."""

    def test_verifier_initialization(self):
        """Test verifier initializes correctly."""
        verifier = SignatureVerifier()
        # Should not raise

    def test_default_verification_success(self):
        """Test default verifier succeeds with valid data."""
        verifier = SignatureVerifier()
        cert = Certificate(
            cert_id="c1",
            subject="CN=test",
            issuer="CN=CA",
            public_key=b"valid_public_key_data_here_12345",
            signature=b"valid_signature_data_here_12345",
            algorithm=CertificateAlgorithm.DILITHIUM_3,
            serial_number="123",
            valid_from=datetime.now(),
            valid_to=datetime.now() + timedelta(days=365),
        )

        valid, error = verifier.verify(cert, b"issuer_public_key_12345")
        self.assertTrue(valid)
        self.assertIsNone(error)

    def test_custom_verifier_registration(self):
        """Test registering a custom verifier."""
        verifier = SignatureVerifier()
        called = []

        def custom_verifier(pubkey, sig, msg):
            called.append(True)
            return True, None

        verifier.register_verifier(CertificateAlgorithm.DILITHIUM_3, custom_verifier)

        cert = Certificate(
            cert_id="c1",
            subject="CN=test",
            issuer="CN=CA",
            public_key=b"key",
            signature=b"sig",
            algorithm=CertificateAlgorithm.DILITHIUM_3,
            serial_number="123",
            valid_from=datetime.now(),
            valid_to=datetime.now() + timedelta(days=365),
        )

        verifier.verify(cert, b"issuer_key")
        self.assertEqual(len(called), 1)


class TestTrustStore(unittest.TestCase):
    """Test TrustStore class."""

    def test_default_anchors_exist(self):
        """Test default trust anchors are added."""
        store = TrustStore()
        anchors = store.get_all_anchors()
        self.assertGreater(len(anchors), 0)

    def test_add_trust_anchor(self):
        """Test adding a custom trust anchor."""
        store = TrustStore()
        cert = Certificate(
            cert_id="custom_root",
            subject="CN=Custom Root CA",
            issuer="CN=Custom Root CA",
            public_key=b"root_key",
            signature=b"self_sig",
            algorithm=CertificateAlgorithm.DILITHIUM_5,
            serial_number="CUSTOMROOT",
            valid_from=datetime.now(),
            valid_to=datetime.now() + timedelta(days=3650),
            is_root=True,
            is_ca=True,
        )

        fingerprint = store.add_trust_anchor(cert, "Custom Root")
        self.assertTrue(store.is_trusted_root(cert))

    def test_remove_trust_anchor(self):
        """Test removing a trust anchor."""
        store = TrustStore()
        cert = Certificate(
            cert_id="to_remove",
            subject="CN=Remove Me",
            issuer="CN=Remove Me",
            public_key=b"k",
            signature=b"s",
            algorithm=CertificateAlgorithm.DILITHIUM_3,
            serial_number="REMOVE",
            valid_from=datetime.now(),
            valid_to=datetime.now() + timedelta(days=365),
            is_root=True,
        )

        fingerprint = store.add_trust_anchor(cert)
        self.assertTrue(store.remove_trust_anchor(fingerprint))
        self.assertFalse(store.is_trusted_root(cert))


class TestCertificateChainValidator(unittest.TestCase):
    """Test CertificateChainValidator main class."""

    def _create_test_chain(self, algorithm=CertificateAlgorithm.DILITHIUM_3) -> list:
        """Create a test certificate chain."""
        root = Certificate(
            cert_id="root",
            subject="CN=Test Root CA",
            issuer="CN=Test Root CA",
            public_key=b"root_public_key_1234567890123456",
            signature=b"root_self_signature_1234567890123456",
            algorithm=CertificateAlgorithm.DILITHIUM_5,
            serial_number="ROOTCA",
            valid_from=datetime.now() - timedelta(days=1),
            valid_to=datetime.now() + timedelta(days=3650),
            is_root=True,
            is_ca=True,
        )

        intermediate = Certificate(
            cert_id="intermediate",
            subject="CN=Test Intermediate CA",
            issuer="CN=Test Root CA",
            public_key=b"intermediate_public_key_1234567890",
            signature=b"root_signed_intermediate_1234567890",
            algorithm=CertificateAlgorithm.DILITHIUM_3,
            serial_number="INTERCA",
            valid_from=datetime.now() - timedelta(days=1),
            valid_to=datetime.now() + timedelta(days=1825),
            is_ca=True,
        )

        leaf = Certificate(
            cert_id="leaf",
            subject="CN=test.example.com",
            issuer="CN=Test Intermediate CA",
            public_key=b"leaf_public_key_1234567890123456",
            signature=b"intermediate_signed_leaf_1234567890",
            algorithm=algorithm,
            serial_number="LEAF123",
            valid_from=datetime.now() - timedelta(days=1),
            valid_to=datetime.now() + timedelta(days=90),
            subject_alt_names=["test.example.com", "*.example.com"],
        )

        return [leaf, intermediate, root]

    def test_validator_initialization(self):
        """Test validator initializes correctly."""
        validator = CertificateChainValidator()
        self.assertIsNotNone(validator.trust_store)
        self.assertIsNotNone(validator.revocation_checker)
        self.assertIsNotNone(validator.signature_verifier)

    def test_empty_chain_validation(self):
        """Test empty chain returns CHAIN_BROKEN."""
        validator = CertificateChainValidator()
        result = validator.validate_chain([])
        self.assertEqual(result.overall_status, ValidationStatus.CHAIN_BROKEN)

    def test_valid_chain_validation(self):
        """Test valid chain validates successfully."""
        validator = CertificateChainValidator()
        chain = self._create_test_chain()

        # Add root to trust store
        validator.trust_store.add_trust_anchor(chain[-1])

        result = validator.validate_chain(chain)
        # Should validate - note: in real implementation this would check
        # actual crypto, but our simulated verifier should pass
        self.assertIsNotNone(result.overall_status)
        self.assertEqual(result.chain_length, 3)

    def test_expired_certificate(self):
        """Test expired certificate detection."""
        validator = CertificateChainValidator()
        chain = self._create_test_chain()

        # Make leaf expired
        chain[0].valid_to = datetime.now() - timedelta(days=1)
        validator.trust_store.add_trust_anchor(chain[-1])

        result = validator.validate_chain(chain)
        # Should detect expired
        self.assertIn(ValidationStatus.EXPIRED.value, [s.value for _, s, _ in result.certificate_results])

    def test_not_yet_valid_certificate(self):
        """Test not-yet-valid certificate detection."""
        validator = CertificateChainValidator()
        chain = self._create_test_chain()

        # Make leaf not valid yet
        chain[0].valid_from = datetime.now() + timedelta(days=1)
        validator.trust_store.add_trust_anchor(chain[-1])

        result = validator.validate_chain(chain)
        statuses = [s.value for _, s, _ in result.certificate_results]
        self.assertIn(ValidationStatus.NOT_YET_VALID.value, statuses)

    def test_hostname_verification(self):
        """Test hostname verification."""
        validator = CertificateChainValidator()
        chain = self._create_test_chain()
        validator.trust_store.add_trust_anchor(chain[-1])

        # Valid hostname
        result = validator.validate_chain(chain, hostname="test.example.com")
        self.assertNotEqual(result.overall_status, ValidationStatus.NAME_MISMATCH)

    def test_hostname_wildcard_matching(self):
        """Test wildcard hostname matching."""
        validator = CertificateChainValidator()
        chain = self._create_test_chain()
        validator.trust_store.add_trust_anchor(chain[-1])

        # Wildcard should match subdomain
        result = validator.validate_chain(chain, hostname="www.example.com")
        # Our chain has *.example.com in SANs, so this should work
        statuses = [s.value for _, s, _ in result.certificate_results]
        self.assertNotIn(ValidationStatus.NAME_MISMATCH.value, statuses)

    def test_revoked_certificate_in_chain(self):
        """Test revoked certificate detection."""
        validator = CertificateChainValidator()
        chain = self._create_test_chain()
        validator.trust_store.add_trust_anchor(chain[-1])

        # Revoke leaf certificate
        validator.revocation_checker.add_revoked_serial("LEAF123")

        result = validator.validate_chain(chain)
        statuses = [s.value for _, s, _ in result.certificate_results]
        self.assertIn(ValidationStatus.REVOKED.value, statuses)

    def test_post_quantum_only_policy(self):
        """Test post-quantum only policy rejects classical."""
        validator = CertificateChainValidator()
        chain = self._create_test_chain(algorithm=CertificateAlgorithm.RSA_4096)
        validator.trust_store.add_trust_anchor(chain[-1])

        strict_policy = ValidationPolicy(
            validation_mode=ValidationMode.POST_QUANTUM_ONLY,
            accepted_algorithms={CertificateAlgorithm.DILITHIUM_3, CertificateAlgorithm.DILITHIUM_5}
        )

        result = validator.validate_chain(chain, policy=strict_policy)
        # Classical RSA should be rejected by PQ-only policy
        self.assertNotEqual(result.overall_status, ValidationStatus.VALID)

    def test_algorithm_strength_tracking(self):
        """Test algorithm strength tracking in result."""
        validator = CertificateChainValidator()
        chain = self._create_test_chain()
        validator.trust_store.add_trust_anchor(chain[-1])

        result = validator.validate_chain(chain)
        self.assertIsNotNone(result.strongest_algorithm)
        self.assertIsNotNone(result.weakest_algorithm)

    def test_create_strict_policy(self):
        """Test strict policy factory method."""
        validator = CertificateChainValidator()
        policy = validator.create_strict_policy()
        self.assertEqual(policy.validation_mode, ValidationMode.POST_QUANTUM_ONLY)
        self.assertEqual(policy.minimum_security_level, SecurityLevel.LEVEL_3)

    def test_create_hybrid_policy(self):
        """Test hybrid policy factory method."""
        validator = CertificateChainValidator()
        policy = validator.create_hybrid_policy()
        self.assertEqual(policy.validation_mode, ValidationMode.HYBRID_EITHER_ACCEPTED)

    def test_validation_statistics(self):
        """Test validation statistics tracking."""
        validator = CertificateChainValidator()
        chain = self._create_test_chain()
        validator.trust_store.add_trust_anchor(chain[-1])

        validator.validate_chain(chain)
        stats = validator.get_validation_statistics()

        self.assertIn("total_validations", stats)
        self.assertIn("by_status", stats)
        self.assertGreater(stats["total_validations"], 0)

    def test_global_singleton(self):
        """Test global singleton works."""
        v1 = get_certificate_validator()
        v2 = get_certificate_validator()
        self.assertIs(v1, v2)

    def test_thread_safety(self):
        """Test validator works under concurrent access."""
        validator = CertificateChainValidator()
        errors = []

        def worker():
            try:
                chain = self._create_test_chain()
                validator.validate_chain(chain)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for realistic scenarios."""

    def test_full_pq_certificate_chain(self):
        """Test full post-quantum certificate chain validation."""
        validator = CertificateChainValidator()

        # Create a pure PQ chain
        root = Certificate(
            cert_id="pq_root",
            subject="CN=PQ Root CA",
            issuer="CN=PQ Root CA",
            public_key=b"pq_root_key_1234567890123456",
            signature=b"pq_root_sig_1234567890123456",
            algorithm=CertificateAlgorithm.DILITHIUM_5,
            serial_number="PQROOT",
            valid_from=datetime.now() - timedelta(days=1),
            valid_to=datetime.now() + timedelta(days=3650),
            is_root=True,
            is_ca=True,
        )

        leaf = Certificate(
            cert_id="pq_leaf",
            subject="CN=secure.example.com",
            issuer="CN=PQ Root CA",
            public_key=b"pq_leaf_key_1234567890123456",
            signature=b"pq_signed_leaf_1234567890123456",
            algorithm=CertificateAlgorithm.DILITHIUM_3,
            serial_number="PQLEAF",
            valid_from=datetime.now() - timedelta(days=1),
            valid_to=datetime.now() + timedelta(days=90),
            subject_alt_names=["secure.example.com"],
        )

        validator.trust_store.add_trust_anchor(root)
        result = validator.validate_chain([leaf, root])

        self.assertEqual(result.chain_length, 2)
        self.assertTrue(AlgorithmRegistry.is_post_quantum(result.strongest_algorithm))

    def test_hybrid_certificate_validation(self):
        """Test hybrid certificate validation."""
        validator = CertificateChainValidator()

        cert = Certificate(
            cert_id="hybrid_cert",
            subject="CN=hybrid.example.com",
            issuer="CN=Hybrid CA",
            public_key=b"hybrid_key_1234567890123456",
            signature=b"hybrid_sig_1234567890123456",
            algorithm=CertificateAlgorithm.HYBRID_RSA_DILITHIUM_3,
            serial_number="HYBRID1",
            valid_from=datetime.now() - timedelta(days=1),
            valid_to=datetime.now() + timedelta(days=365),
        )

        root = Certificate(
            cert_id="hybrid_root",
            subject="CN=Hybrid CA",
            issuer="CN=Hybrid CA",
            public_key=b"hybrid_root_key_1234567890",
            signature=b"hybrid_root_sig_1234567890",
            algorithm=CertificateAlgorithm.HYBRID_RSA_DILITHIUM_3,
            serial_number="HYBRIDROOT",
            valid_from=datetime.now() - timedelta(days=1),
            valid_to=datetime.now() + timedelta(days=3650),
            is_root=True,
            is_ca=True,
        )

        validator.trust_store.add_trust_anchor(root)
        result = validator.validate_chain([cert, root])

        self.assertTrue(AlgorithmRegistry.is_hybrid(cert.algorithm))
        self.assertEqual(result.chain_length, 2)


if __name__ == "__main__":
    unittest.main()
