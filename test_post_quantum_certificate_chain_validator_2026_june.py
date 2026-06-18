#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Certificate Chain Validator
Production-Grade Tests - June 19, 2026
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

import unittest
from datetime import datetime, timedelta

from post_quantum_certificate_chain_validator_2026_june import (
    PostQuantumCertificateValidator,
    Certificate,
    ValidationResult,
    CertificateStatus,
    ValidationLevel,
    PQSignatureAlgorithm,
)


class TestPostQuantumCertificateChainValidator(unittest.TestCase):
    """Test suite for post-quantum certificate validation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.validator_hybrid = PostQuantumCertificateValidator(
            validation_level=ValidationLevel.HYBRID
        )
        self.validator_strict = PostQuantumCertificateValidator(
            validation_level=ValidationLevel.STRICT
        )
        self.validator_compat = PostQuantumCertificateValidator(
            validation_level=ValidationLevel.COMPATIBILITY
        )
    
    def _create_test_certificate(
        self,
        subject: str,
        issuer: str,
        algorithm: PQSignatureAlgorithm,
        is_ca: bool = False,
        days_valid: int = 365,
    ) -> Certificate:
        """Helper to create test certificates."""
        return Certificate(
            subject=subject,
            issuer=issuer,
            serial_number=f"TEST-{subject.replace(' ', '')}",
            not_before=datetime.now() - timedelta(days=1),
            not_after=datetime.now() + timedelta(days=days_valid),
            public_key=b"test_public_key_data_1234567890",
            signature_algorithm=algorithm,
            signature=b"test_signature_data_" + os.urandom(32),
            is_ca=is_ca,
            key_usage=["key_cert_sign", "digital_signature"] if is_ca else ["digital_signature"],
            subject_alternative_names=[f"www.{subject.lower().replace(' ', '')}.com"],
            crl_distribution_points=["http://crl.example.com"],
        )
    
    def test_validator_initialization(self):
        """Test validator initializes correctly."""
        self.assertIsNotNone(self.validator_hybrid.trust_anchors)
        self.assertIsNotNone(self.validator_hybrid.revocation_cache)
        self.assertIsNotNone(self.validator_hybrid.validation_cache)
        self.assertEqual(self.validator_hybrid.validation_level, ValidationLevel.HYBRID)
    
    def test_certificate_creation(self):
        """Test certificate creation and properties."""
        cert = self._create_test_certificate(
            "Test Server",
            "Test CA",
            PQSignatureAlgorithm.DILITHIUM_3
        )
        
        self.assertEqual(cert.subject, "Test Server")
        self.assertTrue(cert.is_valid_at_time())
        self.assertGreater(cert.get_days_until_expiry(), 300)
        self.assertTrue(cert.is_post_quantum)
        self.assertTrue(cert.fingerprint)
    
    def test_certificate_pq_detection(self):
        """Test post-quantum algorithm detection."""
        # PQ algorithm
        pq_cert = self._create_test_certificate(
            "PQ Server", "CA", PQSignatureAlgorithm.DILITHIUM_5
        )
        self.assertTrue(pq_cert.is_post_quantum)
        
        # Hybrid algorithm
        hybrid_cert = self._create_test_certificate(
            "Hybrid Server", "CA", PQSignatureAlgorithm.RSA_4096_DILITHIUM_3
        )
        self.assertTrue(hybrid_cert.is_post_quantum)
        
        # Classical algorithm
        classical_cert = self._create_test_certificate(
            "Classical Server", "CA", PQSignatureAlgorithm.RSA_4096
        )
        self.assertFalse(classical_cert.is_post_quantum)
    
    def test_certificate_temporal_validation(self):
        """Test certificate temporal validation."""
        # Valid certificate
        valid_cert = self._create_test_certificate("Valid", "CA", PQSignatureAlgorithm.DILITHIUM_3)
        self.assertTrue(valid_cert.is_valid_at_time())
        
        # Expired certificate
        expired_cert = self._create_test_certificate(
            "Expired", "CA", PQSignatureAlgorithm.DILITHIUM_3, days_valid=-1
        )
        self.assertFalse(expired_cert.is_valid_at_time())
        self.assertLess(expired_cert.get_days_until_expiry(), 0)
        
        # Not yet valid
        future_cert = Certificate(
            subject="Future",
            issuer="CA",
            serial_number="FUTURE",
            not_before=datetime.now() + timedelta(days=10),
            not_after=datetime.now() + timedelta(days=365),
            public_key=b"key",
            signature_algorithm=PQSignatureAlgorithm.DILITHIUM_3,
            signature=b"sig",
        )
        self.assertFalse(future_cert.is_valid_at_time())
    
    def test_security_strength_mapping(self):
        """Test security strength level mappings."""
        strengths = PostQuantumCertificateValidator.PQ_SECURITY_STRENGTH
        
        # PQ algorithms
        self.assertEqual(strengths[PQSignatureAlgorithm.DILITHIUM_2], 128)
        self.assertEqual(strengths[PQSignatureAlgorithm.DILITHIUM_3], 192)
        self.assertEqual(strengths[PQSignatureAlgorithm.DILITHIUM_5], 256)
        self.assertEqual(strengths[PQSignatureAlgorithm.FALCON_512], 128)
        self.assertEqual(strengths[PQSignatureAlgorithm.FALCON_1024], 256)
        
        # Classical algorithms
        self.assertEqual(strengths[PQSignatureAlgorithm.RSA_2048], 112)
        self.assertEqual(strengths[PQSignatureAlgorithm.RSA_4096], 152)
        self.assertEqual(strengths[PQSignatureAlgorithm.ECDSA_P256], 128)
        self.assertEqual(strengths[PQSignatureAlgorithm.ECDSA_P384], 192)
    
    def test_validate_single_pq_certificate_hybrid_mode(self):
        """Test validation of PQ certificate in HYBRID mode."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.DILITHIUM_5, is_ca=True
        )
        
        server_cert = self._create_test_certificate(
            "Server", "Root CA", PQSignatureAlgorithm.DILITHIUM_3
        )
        
        result = self.validator_hybrid.validate_chain(
            end_entity=server_cert,
            trust_anchors=[root_ca]
        )
        
        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.post_quantum_enabled)
        self.assertFalse(result.classical_fallback_used)
    
    def test_validate_classical_certificate_compatibility_mode(self):
        """Test classical certificate validation in COMPATIBILITY mode."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.RSA_4096, is_ca=True
        )
        
        server_cert = self._create_test_certificate(
            "Server", "Root CA", PQSignatureAlgorithm.ECDSA_P256
        )
        
        result = self.validator_compat.validate_chain(
            end_entity=server_cert,
            trust_anchors=[root_ca]
        )
        
        self.assertFalse(result.post_quantum_enabled)
        self.assertTrue(result.classical_fallback_used)
        # Should have warnings about classical
        self.assertTrue(any("classical" in w.lower() for w in result.warnings))
    
    def test_validate_classical_certificate_strict_mode_rejected(self):
        """Test that classical certificates are rejected in STRICT mode."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.RSA_4096, is_ca=True
        )
        
        server_cert = self._create_test_certificate(
            "Server", "Root CA", PQSignatureAlgorithm.RSA_4096
        )
        
        result = self.validator_strict.validate_chain(
            end_entity=server_cert,
            trust_anchors=[root_ca]
        )
        
        # Should have errors about requiring PQ
        self.assertTrue(any("STRICT mode" in e for e in result.errors))
    
    def test_hybrid_certificate_chain(self):
        """Test hybrid PQ-classical certificate chain."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.RSA_4096_DILITHIUM_3, is_ca=True
        )
        
        intermediate_ca = self._create_test_certificate(
            "Intermediate CA", "Root CA", PQSignatureAlgorithm.DILITHIUM_3, is_ca=True
        )
        
        server_cert = self._create_test_certificate(
            "Server", "Intermediate CA", PQSignatureAlgorithm.DILITHIUM_2
        )
        
        result = self.validator_hybrid.validate_chain(
            end_entity=server_cert,
            intermediate_certs=[intermediate_ca],
            trust_anchors=[root_ca]
        )
        
        self.assertTrue(result.post_quantum_enabled)
        self.assertGreater(result.chain_length, 1)
    
    def test_expired_certificate_validation(self):
        """Test expired certificate detection."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.DILITHIUM_5, is_ca=True
        )
        
        expired_cert = self._create_test_certificate(
            "Expired Server", "Root CA", PQSignatureAlgorithm.DILITHIUM_3, days_valid=-10
        )
        
        result = self.validator_hybrid.validate_chain(
            end_entity=expired_cert,
            trust_anchors=[root_ca]
        )
        
        self.assertEqual(result.overall_status, CertificateStatus.EXPIRED)
        self.assertFalse(result.is_valid())
    
    def test_name_constraints_validation(self):
        """Test name constraints enforcement."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.DILITHIUM_5, is_ca=True
        )
        root_ca.name_constraints = {
            "permitted": [r".*\.example\.com"],
            "excluded": [r".*\.malicious\.com"]
        }
        
        # Valid certificate
        good_cert = self._create_test_certificate(
            "Good Server", "Root CA", PQSignatureAlgorithm.DILITHIUM_3
        )
        good_cert.subject_alternative_names = ["www.example.com"]
        
        result = self.validator_hybrid.validate_chain(
            end_entity=good_cert,
            trust_anchors=[root_ca]
        )
        # Should not have name constraint errors
        constraint_errors = [
            e for e in result.errors 
            if "constraint" in e.lower() or "SAN" in e
        ]
        self.assertEqual(len(constraint_errors), 0)
    
    def test_revocation_check(self):
        """Test revocation checking."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.DILITHIUM_5, is_ca=True
        )
        
        revoked_cert = self._create_test_certificate(
            "Revoked Server", "Root CA", PQSignatureAlgorithm.DILITHIUM_3
        )
        revoked_cert.serial_number = "REVOKED-12345"
        
        result = self.validator_hybrid.validate_chain(
            end_entity=revoked_cert,
            trust_anchors=[root_ca]
        )
        
        self.assertEqual(result.overall_status, CertificateStatus.REVOKED)
    
    def test_path_length_constraint(self):
        """Test path length constraint enforcement."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.DILITHIUM_5, is_ca=True
        )
        root_ca.path_length_constraint = 0  # No intermediates allowed
        
        intermediate = self._create_test_certificate(
            "Intermediate", "Root CA", PQSignatureAlgorithm.DILITHIUM_3, is_ca=True
        )
        
        server_cert = self._create_test_certificate(
            "Server", "Intermediate", PQSignatureAlgorithm.DILITHIUM_2
        )
        
        result = self.validator_hybrid.validate_chain(
            end_entity=server_cert,
            intermediate_certs=[intermediate],
            trust_anchors=[root_ca]
        )
        
        # Should have path length exceeded error
        path_errors = [e for e in result.errors if "path length" in e.lower()]
        self.assertGreater(len(path_errors), 0)
    
    def test_non_ca_issuer_rejected(self):
        """Test that non-CA certificates cannot issue."""
        non_ca = self._create_test_certificate(
            "Non-CA Server", "Root", PQSignatureAlgorithm.DILITHIUM_3, is_ca=False
        )
        
        server_cert = self._create_test_certificate(
            "Server", "Non-CA Server", PQSignatureAlgorithm.DILITHIUM_2
        )
        
        result = self.validator_hybrid.validate_chain(
            end_entity=server_cert,
            trust_anchors=[non_ca]
        )
        
        ca_errors = [e for e in result.errors if "not a CA" in e]
        self.assertGreater(len(ca_errors), 0)
    
    def test_security_summary_generation(self):
        """Test security summary generation."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.DILITHIUM_5, is_ca=True
        )
        
        server_cert = self._create_test_certificate(
            "Server", "Root CA", PQSignatureAlgorithm.DILITHIUM_3
        )
        
        result = self.validator_hybrid.validate_chain(
            end_entity=server_cert,
            trust_anchors=[root_ca]
        )
        
        summary = self.validator_hybrid.get_security_summary(result)
        
        self.assertIn("is_valid", summary)
        self.assertIn("overall_status", summary)
        self.assertIn("chain_length", summary)
        self.assertIn("post_quantum_enabled", summary)
        self.assertIn("minimum_security_strength_bits", summary)
        self.assertIn("recommendation", summary)
        self.assertGreater(summary["minimum_security_strength_bits"], 100)
        self.assertTrue(
            "EXCELLENT" in summary["recommendation"] or 
            "GOOD" in summary["recommendation"]
        )
    
    def test_security_recommendations(self):
        """Test recommendation generation for different scenarios."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.DILITHIUM_5, is_ca=True
        )
        
        # Full PQ chain
        pq_cert = self._create_test_certificate(
            "PQ Server", "Root CA", PQSignatureAlgorithm.DILITHIUM_5
        )
        result = self.validator_hybrid.validate_chain(pq_cert, trust_anchors=[root_ca])
        summary = self.validator_hybrid.get_security_summary(result)
        self.assertIn("EXCELLENT", summary["recommendation"])
    
    def test_cache_operations(self):
        """Test cache clearing functionality."""
        validator = PostQuantumCertificateValidator()
        
        # Add something to caches
        validator.revocation_cache["test"] = (False, datetime.now())
        validator.validation_cache["test"] = None  # type: ignore
        
        self.assertGreater(len(validator.revocation_cache), 0)
        
        validator.clear_caches()
        
        self.assertEqual(len(validator.revocation_cache), 0)
        self.assertEqual(len(validator.validation_cache), 0)
    
    def test_soon_to_expire_warning(self):
        """Test warning for certificates expiring soon."""
        root_ca = self._create_test_certificate(
            "Root CA", "Root CA", PQSignatureAlgorithm.DILITHIUM_5, is_ca=True
        )
        
        expiring_soon = self._create_test_certificate(
            "Expiring Soon", "Root CA", PQSignatureAlgorithm.DILITHIUM_3, days_valid=15
        )
        
        result = self.validator_hybrid.validate_chain(
            end_entity=expiring_soon,
            trust_anchors=[root_ca]
        )
        
        expiry_warnings = [w for w in result.warnings if "expiring soon" in w.lower()]
        self.assertGreater(len(expiry_warnings), 0)
    
    def test_validation_level_enum(self):
        """Test validation level enum values."""
        levels = [
            ValidationLevel.STRICT,
            ValidationLevel.HYBRID,
            ValidationLevel.COMPATIBILITY,
            ValidationLevel.LENIENT,
        ]
        
        for level in levels:
            self.assertIsInstance(level.value, str)
    
    def test_certificate_status_enum(self):
        """Test certificate status enum values."""
        statuses = [
            CertificateStatus.VALID,
            CertificateStatus.EXPIRED,
            CertificateStatus.REVOKED,
            CertificateStatus.SIGNATURE_INVALID,
        ]
        
        for status in statuses:
            self.assertIsInstance(status.value, str)


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPostQuantumCertificateChainValidator)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


if __name__ == "__main__":
    print("=" * 70)
    print("Post-Quantum Certificate Chain Validator - Test Suite")
    print("Production-Grade Implementation - June 19, 2026")
    print("=" * 70)
    print()
    
    result = run_tests()
    
    print()
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {'PASS' if result.wasSuccessful() else 'FAIL'}")
    print("=" * 70)
    
    sys.exit(0 if result.wasSuccessful() else 1)
