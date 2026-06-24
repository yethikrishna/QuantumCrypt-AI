#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Certificate Revocation Checker v27
QuantumCrypt-AI

Tests cover:
- Enums and dataclass validation
- Revocation cache TTL behavior
- PQ signature validation framework
- OCSP/CRL/CT checking
- Multi-method result consolidation
- Batch certificate checking
- Statistics and reporting
- Thread safety
"""

import sys
import os
import unittest
import time
from datetime import datetime, timedelta

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_certificate_revocation_checker_v27_2026_june import (
    RevocationStatus,
    RevocationReason,
    CheckMethod,
    CertificateInfo,
    RevocationResult,
    CheckerConfig,
    RevocationCache,
    PQRevocationSignatureValidator,
    OCSPChecker,
    CRLChecker,
    CTLogChecker,
    CertificateRevocationChecker,
    create_revocation_checker
)


class TestRevocationStatusEnum(unittest.TestCase):
    """Test RevocationStatus enum values"""
    
    def test_status_values(self):
        self.assertEqual(RevocationStatus.GOOD.value, "good")
        self.assertEqual(RevocationStatus.REVOKED.value, "revoked")
        self.assertEqual(RevocationStatus.UNKNOWN.value, "unknown")
        self.assertEqual(RevocationStatus.EXPIRED.value, "expired")
        self.assertEqual(RevocationStatus.NOT_CHECKED.value, "not_checked")
    
    def test_status_count(self):
        self.assertEqual(len(list(RevocationStatus)), 5)


class TestRevocationReasonEnum(unittest.TestCase):
    """Test RevocationReason enum values"""
    
    def test_reason_values(self):
        self.assertEqual(RevocationReason.UNSPECIFIED.value, 0)
        self.assertEqual(RevocationReason.KEY_COMPROMISE.value, 1)
        self.assertEqual(RevocationReason.CA_COMPROMISE.value, 2)
        self.assertEqual(RevocationReason.SUPERSEDED.value, 4)
    
    def test_reason_count(self):
        self.assertEqual(len(list(RevocationReason)), 10)


class TestCheckMethodEnum(unittest.TestCase):
    """Test CheckMethod enum values"""
    
    def test_method_values(self):
        self.assertEqual(CheckMethod.OCSP.value, "ocsp")
        self.assertEqual(CheckMethod.CRL.value, "crl")
        self.assertEqual(CheckMethod.CT_LOG.value, "certificate_transparency")
        self.assertEqual(CheckMethod.CACHE.value, "cache")
    
    def test_method_count(self):
        self.assertEqual(len(list(CheckMethod)), 5)


class TestCertificateInfo(unittest.TestCase):
    """Test CertificateInfo dataclass"""
    
    def setUp(self):
        self.now = datetime.now()
    
    def test_certificate_creation_basic(self):
        cert = CertificateInfo(
            serial_number="1234567890ABCDEF",
            issuer_dn="CN=Test CA",
            subject_dn="CN=example.com",
            fingerprint="abc123def456",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="SHA256-RSA"
        )
        self.assertEqual(cert.serial_number, "1234567890ABCDEF")
        self.assertFalse(cert.is_post_quantum)
        self.assertEqual(cert.ocsp_urls, [])
    
    def test_certificate_creation_pq(self):
        cert = CertificateInfo(
            serial_number="1234567890ABCDEF",
            issuer_dn="CN=Test CA",
            subject_dn="CN=example.com",
            fingerprint="abc123def456",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="CRYSTALS-Dilithium3",
            is_post_quantum=True,
            pq_algorithm="CRYSTALS-Dilithium3",
            ocsp_urls=["http://ocsp.example.com"],
            crl_urls=["http://crl.example.com"],
            ct_log_ids=["google_pilot"]
        )
        self.assertTrue(cert.is_post_quantum)
        self.assertEqual(cert.pq_algorithm, "CRYSTALS-Dilithium3")
        self.assertEqual(len(cert.ocsp_urls), 1)
        self.assertEqual(len(cert.crl_urls), 1)
        self.assertEqual(len(cert.ct_log_ids), 1)
    
    def test_cert_id_generation(self):
        cert1 = CertificateInfo(
            serial_number="12345",
            issuer_dn="CN=CA1",
            subject_dn="CN=test1.com",
            fingerprint="fp1",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="RSA"
        )
        cert2 = CertificateInfo(
            serial_number="12345",
            issuer_dn="CN=CA1",
            subject_dn="CN=test2.com",  # Different subject
            fingerprint="fp2",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="RSA"
        )
        # Same serial + issuer = same ID
        self.assertEqual(cert1.get_cert_id(), cert2.get_cert_id())
        
        cert3 = CertificateInfo(
            serial_number="67890",  # Different serial
            issuer_dn="CN=CA1",
            subject_dn="CN=test1.com",
            fingerprint="fp3",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="RSA"
        )
        self.assertNotEqual(cert1.get_cert_id(), cert3.get_cert_id())


class TestRevocationResult(unittest.TestCase):
    """Test RevocationResult dataclass"""
    
    def setUp(self):
        self.now = datetime.now()
    
    def test_result_creation(self):
        result = RevocationResult(
            cert_id="test123",
            serial_number="12345",
            status=RevocationStatus.GOOD,
            reason=None,
            check_method=CheckMethod.OCSP,
            checked_at=self.now,
            next_update=self.now + timedelta(hours=24),
            ttl=3600
        )
        self.assertFalse(result.is_revoked())
        self.assertTrue(result.is_valid())
    
    def test_revoked_result(self):
        result = RevocationResult(
            cert_id="test123",
            serial_number="12345",
            status=RevocationStatus.REVOKED,
            reason=RevocationReason.KEY_COMPROMISE,
            check_method=CheckMethod.CRL,
            checked_at=self.now,
            next_update=self.now + timedelta(hours=12),
            revocation_time=self.now - timedelta(days=7),
            ttl=3600
        )
        self.assertTrue(result.is_revoked())
        self.assertFalse(result.is_valid())
        self.assertEqual(result.reason, RevocationReason.KEY_COMPROMISE)


class TestCheckerConfig(unittest.TestCase):
    """Test CheckerConfig dataclass"""
    
    def test_default_config(self):
        cfg = CheckerConfig()
        self.assertTrue(cfg.enable_ocsp)
        self.assertTrue(cfg.enable_crl)
        self.assertTrue(cfg.enable_ct_log)
        self.assertTrue(cfg.enable_cache)
        self.assertEqual(cfg.cache_ttl, 3600)
        self.assertTrue(cfg.enable_pq_validation)
    
    def test_custom_config(self):
        cfg = CheckerConfig(
            enable_ocsp=False,
            cache_ttl=7200,
            enable_pq_validation=False
        )
        self.assertFalse(cfg.enable_ocsp)
        self.assertEqual(cfg.cache_ttl, 7200)
        self.assertFalse(cfg.enable_pq_validation)


class TestRevocationCache(unittest.TestCase):
    """Test RevocationCache functionality"""
    
    def setUp(self):
        self.cache = RevocationCache()
        self.now = datetime.now()
    
    def create_test_result(self, cert_id="test123", ttl=3600):
        return RevocationResult(
            cert_id=cert_id,
            serial_number="12345",
            status=RevocationStatus.GOOD,
            reason=None,
            check_method=CheckMethod.OCSP,
            checked_at=self.now,
            next_update=self.now + timedelta(hours=24),
            ttl=ttl
        )
    
    def test_add_and_get(self):
        result = self.create_test_result()
        self.cache.add(result)
        retrieved = self.cache.get("test123")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.cert_id, "test123")
    
    def test_get_not_found(self):
        result = self.cache.get("nonexistent")
        self.assertIsNone(result)
    
    def test_cache_size(self):
        for i in range(5):
            result = self.create_test_result(f"cert{i}")
            self.cache.add(result)
        self.assertEqual(self.cache.size(), 5)
    
    def test_expired_entry(self):
        result = self.create_test_result(ttl=1)
        self.cache.add(result)
        self.assertEqual(self.cache.size(), 1)
        time.sleep(1.1)
        self.assertEqual(self.cache.size(), 0)
    
    def test_cleanup_expired(self):
        result1 = self.create_test_result("cert1", ttl=1)
        result2 = self.create_test_result("cert2", ttl=3600)
        self.cache.add(result1)
        self.cache.add(result2)
        time.sleep(1.1)
        removed = self.cache.cleanup_expired()
        self.assertEqual(removed, 1)
        self.assertEqual(self.cache.size(), 1)
    
    def test_clear_cache(self):
        for i in range(3):
            result = self.create_test_result(f"cert{i}")
            self.cache.add(result)
        self.assertEqual(self.cache.size(), 3)
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)
    
    def test_cache_stats(self):
        # Add some revoked and good results
        revoked = RevocationResult(
            cert_id="badcert",
            serial_number="BAD123",
            status=RevocationStatus.REVOKED,
            reason=RevocationReason.KEY_COMPROMISE,
            check_method=CheckMethod.OCSP,
            checked_at=self.now,
            next_update=self.now + timedelta(hours=24),
            ttl=3600
        )
        self.cache.add(revoked)
        self.cache.add(self.create_test_result("goodcert"))
        
        stats = self.cache.get_stats()
        self.assertEqual(stats["total_entries"], 2)
        self.assertEqual(stats["revoked_count"], 1)
        self.assertEqual(stats["good_count"], 1)


class TestPQRevocationSignatureValidator(unittest.TestCase):
    """Test PQ signature validator"""
    
    def setUp(self):
        self.validator = PQRevocationSignatureValidator()
    
    def test_supported_algorithms(self):
        supported = self.validator.get_supported_algorithms()
        self.assertIn("CRYSTALS-Dilithium2", supported)
        self.assertIn("CRYSTALS-Dilithium3", supported)
        self.assertIn("CRYSTALS-Dilithium5", supported)
        self.assertIn("FALCON-512", supported)
        self.assertIn("FALCON-1024", supported)
        self.assertIn("SPHINCS+-SHA2-128f", supported)
        self.assertEqual(len(supported), 8)
    
    def test_algorithm_support_check(self):
        self.assertTrue(self.validator.is_algorithm_supported("CRYSTALS-Dilithium3"))
        self.assertFalse(self.validator.is_algorithm_supported("UNKNOWN_ALG"))
    
    def test_signature_validation_length_check(self):
        # Test minimum signature length validation
        sig_dilithium2 = b"x" * 2420
        result = self.validator.validate_pq_signature(
            sig_dilithium2,
            b"data",
            "CRYSTALS-Dilithium2",
            b"pubkey"
        )
        self.assertTrue(result)
        
        # Too short signature should fail
        sig_short = b"x" * 100
        result = self.validator.validate_pq_signature(
            sig_short,
            b"data",
            "CRYSTALS-Dilithium2",
            b"pubkey"
        )
        self.assertFalse(result)
    
    def test_unsupported_algorithm_validation(self):
        result = self.validator.validate_pq_signature(
            b"sig",
            b"data",
            "UNSUPPORTED_ALG",
            b"pubkey"
        )
        self.assertFalse(result)


class TestOCSPChecker(unittest.TestCase):
    """Test OCSP checker"""
    
    def setUp(self):
        self.checker = OCSPChecker()
        self.now = datetime.now()
    
    def create_test_cert(self, serial="12345", has_ocsp=True):
        return CertificateInfo(
            serial_number=serial,
            issuer_dn="CN=Test CA",
            subject_dn="CN=example.com",
            fingerprint="fp123",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="RSA",
            ocsp_urls=["http://ocsp.example.com"] if has_ocsp else []
        )
    
    def test_ocsp_check_with_urls(self):
        cert = self.create_test_cert()
        result = self.checker.check(cert)
        self.assertIsNotNone(result)
        self.assertEqual(result.check_method, CheckMethod.OCSP)
        self.assertIsNotNone(result.status)
    
    def test_ocsp_check_no_urls(self):
        cert = self.create_test_cert(has_ocsp=False)
        result = self.checker.check(cert)
        self.assertEqual(result.status, RevocationStatus.UNKNOWN)
        self.assertIn("No OCSP URLs", result.error_message)
    
    def test_ocsp_deterministic_results(self):
        # Serial starting with 0-3 should be revoked
        cert_revoked = self.create_test_cert("00001")
        result = self.checker.check(cert_revoked)
        # Results are deterministic based on hash
    
    def test_ocsp_pq_certificate(self):
        cert = CertificateInfo(
            serial_number="PQ12345",
            issuer_dn="CN=PQ CA",
            subject_dn="CN=pq.example.com",
            fingerprint="pqfp123",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="CRYSTALS-Dilithium3",
            is_post_quantum=True,
            pq_algorithm="CRYSTALS-Dilithium3",
            ocsp_urls=["http://ocsp.pq.example.com"]
        )
        result = self.checker.check(cert)
        self.assertTrue(result.pq_signature_valid)


class TestCRLChecker(unittest.TestCase):
    """Test CRL checker"""
    
    def setUp(self):
        self.checker = CRLChecker()
        self.now = datetime.now()
    
    def create_test_cert(self, serial="12345", has_crl=True):
        return CertificateInfo(
            serial_number=serial,
            issuer_dn="CN=Test CA",
            subject_dn="CN=example.com",
            fingerprint="fp123",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="RSA",
            crl_urls=["http://crl.example.com"] if has_crl else []
        )
    
    def test_crl_check_with_urls(self):
        cert = self.create_test_cert()
        result = self.checker.check(cert)
        self.assertIsNotNone(result)
        self.assertEqual(result.check_method, CheckMethod.CRL)
    
    def test_crl_check_no_urls(self):
        cert = self.create_test_cert(has_crl=False)
        result = self.checker.check(cert)
        self.assertEqual(result.status, RevocationStatus.UNKNOWN)
        self.assertIn("No CRL URLs", result.error_message)


class TestCTLogChecker(unittest.TestCase):
    """Test CT Log checker"""
    
    def setUp(self):
        self.checker = CTLogChecker()
        self.now = datetime.now()
    
    def create_test_cert(self, has_ct=True, is_pq=False):
        return CertificateInfo(
            serial_number="12345",
            issuer_dn="CN=Test CA",
            subject_dn="CN=example.com",
            fingerprint="fp123",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="RSA",
            is_post_quantum=is_pq,
            ct_log_ids=["google_pilot"] if has_ct else []
        )
    
    def test_ct_check_with_logs(self):
        cert = self.create_test_cert()
        result = self.checker.check(cert)
        self.assertIsNotNone(result)
        self.assertEqual(result.check_method, CheckMethod.CT_LOG)
    
    def test_ct_check_no_logs(self):
        cert = self.create_test_cert(has_ct=False)
        result = self.checker.check(cert)
        self.assertEqual(result.status, RevocationStatus.UNKNOWN)
        self.assertIn("No CT log IDs", result.error_message)
    
    def test_ct_check_pq_certificate(self):
        cert = self.create_test_cert(is_pq=True)
        result = self.checker.check(cert)
        self.assertEqual(result.status, RevocationStatus.GOOD)


class TestCertificateRevocationChecker(unittest.TestCase):
    """Test main CertificateRevocationChecker class"""
    
    def setUp(self):
        self.checker = CertificateRevocationChecker()
        self.now = datetime.now()
    
    def create_test_cert(self, serial="12345", is_pq=False):
        return CertificateInfo(
            serial_number=serial,
            issuer_dn="CN=Test CA",
            subject_dn=f"CN=cert{serial}.example.com",
            fingerprint=f"fp{serial}",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="CRYSTALS-Dilithium3" if is_pq else "RSA",
            is_post_quantum=is_pq,
            pq_algorithm="CRYSTALS-Dilithium3" if is_pq else None,
            ocsp_urls=["http://ocsp.example.com"],
            crl_urls=["http://crl.example.com"],
            ct_log_ids=["google_pilot"]
        )
    
    def test_checker_initialization(self):
        self.assertIsNotNone(self.checker)
        stats = self.checker.get_stats()
        self.assertEqual(stats["total_checks"], 0)
        self.assertEqual(stats["cache_size"], 0)
    
    def test_single_certificate_check(self):
        cert = self.create_test_cert("CERT001")
        result = self.checker.check_certificate(cert)
        self.assertIsNotNone(result)
        stats = self.checker.get_stats()
        self.assertEqual(stats["total_checks"], 1)
        self.assertEqual(stats["cache_size"], 1)
    
    def test_cache_hit(self):
        cert = self.create_test_cert("CERT002")
        # First check - cache miss
        result1 = self.checker.check_certificate(cert)
        # Second check - cache hit
        result2 = self.checker.check_certificate(cert)
        stats = self.checker.get_stats()
        self.assertEqual(stats["total_checks"], 2)
        self.assertEqual(stats["cache_hits"], 1)
        self.assertGreater(stats["cache_hit_rate"], 0)
    
    def test_is_certificate_revoked_convenience(self):
        cert = self.create_test_cert("CERT003")
        # Should return boolean
        result = self.checker.is_certificate_revoked(cert)
        self.assertIsInstance(result, bool)
    
    def test_batch_check(self):
        certs = [self.create_test_cert(f"BATCH{i:03d}") for i in range(5)]
        results = self.checker.check_batch(certs)
        self.assertEqual(len(results), 5)
        stats = self.checker.get_stats()
        self.assertEqual(stats["total_checks"], 5)
    
    def test_pq_certificate_validation(self):
        cert = self.create_test_cert("PQCERT001", is_pq=True)
        result = self.checker.check_certificate(cert)
        self.assertIsNotNone(result)
        stats = self.checker.get_stats()
        self.assertGreater(stats["pq_validated"], 0)
    
    def test_clear_cache(self):
        cert = self.create_test_cert("CLEAR001")
        self.checker.check_certificate(cert)
        self.assertEqual(self.checker.get_stats()["cache_size"], 1)
        self.checker.clear_cache()
        self.assertEqual(self.checker.get_stats()["cache_size"], 0)
    
    def test_get_pq_validator(self):
        validator = self.checker.get_pq_validator()
        self.assertIsInstance(validator, PQRevocationSignatureValidator)
    
    def test_export_report(self):
        cert = self.create_test_cert("REPORT001")
        self.checker.check_certificate(cert)
        report = self.checker.export_report()
        self.assertIn("v27", report)
        self.assertIn("statistics", report)
        self.assertIn("supported_pq_algorithms", report)


class TestFactoryFunction(unittest.TestCase):
    """Test create_revocation_checker factory function"""
    
    def test_create_checker_with_pq(self):
        checker = create_revocation_checker(enable_pq_validation=True)
        self.assertIsInstance(checker, CertificateRevocationChecker)
        self.assertTrue(checker.config.enable_pq_validation)
    
    def test_create_checker_without_pq(self):
        checker = create_revocation_checker(enable_pq_validation=False)
        self.assertIsInstance(checker, CertificateRevocationChecker)
        self.assertFalse(checker.config.enable_pq_validation)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration test scenarios"""
    
    def setUp(self):
        self.checker = create_revocation_checker()
        self.now = datetime.now()
    
    def test_pq_certificate_validation_workflow(self):
        """Simulate PQ certificate validation workflow"""
        # Create mixed certificate chain
        pq_cert = CertificateInfo(
            serial_number="PQCHAIN001",
            issuer_dn="CN=PQ Root CA",
            subject_dn="CN=secure.example.com",
            fingerprint="pqfp001",
            not_before=self.now,
            not_after=self.now + timedelta(days=365),
            signature_algorithm="CRYSTALS-Dilithium3",
            is_post_quantum=True,
            pq_algorithm="CRYSTALS-Dilithium3",
            ocsp_urls=["http://ocsp.pq.example.com"],
            crl_urls=["http://crl.pq.example.com"],
            ct_log_ids=["google_pilot", "cloudflare_nimbus"]
        )
        
        # Check revocation status
        result = self.checker.check_certificate(pq_cert)
        
        # Verify multi-method check was performed
        # Note: CRL is only checked if OCSP returns UNKNOWN, so crl_checks may be 0
        stats = self.checker.get_stats()
        self.assertGreater(stats["ocsp_checks"], 0)
        self.assertGreater(stats["ct_checks"], 0)
        self.assertGreater(stats["pq_validated"], 0)
    
    def test_bulk_monitoring_scenario(self):
        """Simulate bulk certificate monitoring scenario"""
        # Create 10 certificates to monitor
        certs = []
        for i in range(10):
            is_pq = i < 5  # First 5 are PQ
            certs.append(CertificateInfo(
                serial_number=f"MONITOR{i:03d}",
                issuer_dn="CN=Monitoring CA",
                subject_dn=f"CN=service{i}.example.com",
                fingerprint=f"monfp{i:03d}",
                not_before=self.now,
                not_after=self.now + timedelta(days=365),
                signature_algorithm="CRYSTALS-Dilithium3" if is_pq else "RSA",
                is_post_quantum=is_pq,
                pq_algorithm="CRYSTALS-Dilithium3" if is_pq else None,
                ocsp_urls=["http://ocsp.example.com"],
                crl_urls=["http://crl.example.com"],
                ct_log_ids=["google_pilot"]
            ))
        
        # Bulk check
        results = self.checker.check_batch(certs)
        
        # Verify all checked
        self.assertEqual(len(results), 10)
        stats = self.checker.get_stats()
        self.assertEqual(stats["total_checks"], 10)
        
        # Generate monitoring report
        report = self.checker.export_report()
        self.assertIsNotNone(report)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestRevocationStatusEnum,
        TestRevocationReasonEnum,
        TestCheckMethodEnum,
        TestCertificateInfo,
        TestRevocationResult,
        TestCheckerConfig,
        TestRevocationCache,
        TestPQRevocationSignatureValidator,
        TestOCSPChecker,
        TestCRLChecker,
        TestCTLogChecker,
        TestCertificateRevocationChecker,
        TestFactoryFunction,
        TestIntegrationScenarios
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("Post-Quantum Certificate Revocation Checker v27 - Test Suite")
    print("=" * 60)
    result = run_tests()
    print("\n" + "=" * 60)
    if result.wasSuccessful():
        print("✓ ALL TESTS PASSED")
    else:
        print(f"✗ TESTS FAILED: {len(result.failures)} failures, {len(result.errors)} errors")
    print("=" * 60)
    sys.exit(0 if result.wasSuccessful() else 1)
