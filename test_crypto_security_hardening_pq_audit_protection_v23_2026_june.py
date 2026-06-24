"""
Test Suite for Security Hardening v23 - PQ Audit Protection
QuantumCrypt-AI | June 24, 2026
Session 127 - Dimension B: Security Hardening v23
"""

import unittest
import secrets
from quantum_crypt.crypto_security_hardening_pq_audit_protection_v23_2026_june import (
    CryptoSecurityLevelV23,
    ValidationSeverityV23,
    SecureKeyMemoryV23,
    KeyOperationRateLimiterV23,
    KeyOperationRateLimitConfigV23,
    AuditLogTamperProtectorV23,
    CertificateValidatorV23,
    AlgorithmParameterValidatorV23,
    secure_pq_audit_v23,
    get_crypto_security_hardening_v23_info,
)


class TestSecureKeyMemoryV23(unittest.TestCase):
    def test_key_material_zeroization(self):
        key_data = bytearray(b'private key material super secret')
        original = bytes(key_data)
        SecureKeyMemoryV23.zeroize_key_material(key_data)
        self.assertNotEqual(bytes(key_data), original)
    
    def test_constant_time_compare(self):
        self.assertTrue(SecureKeyMemoryV23.constant_time_bytes_compare(b'abc', b'abc'))
        self.assertFalse(SecureKeyMemoryV23.constant_time_bytes_compare(b'abc', b'abd'))


class TestKeyOperationRateLimiterV23(unittest.TestCase):
    def test_key_gen_rate_limit(self):
        limiter = KeyOperationRateLimiterV23(KeyOperationRateLimitConfigV23(
            max_key_generations_per_hour=2
        ))
        allowed, _ = limiter.check_operation('key_gen', 'client1')
        self.assertTrue(allowed)
        allowed, _ = limiter.check_operation('key_gen', 'client1')
        self.assertTrue(allowed)
        allowed, _ = limiter.check_operation('key_gen', 'client1')
        self.assertFalse(allowed)


class TestAuditLogTamperProtectorV23(unittest.TestCase):
    def test_seal_audit_entry(self):
        protector = AuditLogTamperProtectorV23()
        sealed = protector.seal_audit_entry(
            {"audit_type": "key_management", "compliance_score": 95},
            "audit-001"
        )
        self.assertIn("hash", sealed)
        self.assertIn("previous_hash", sealed)


class TestCertificateValidatorV23(unittest.TestCase):
    def test_valid_algorithm_name(self):
        result = CertificateValidatorV23.validate_algorithm_name("CRYSTALS-KYBER")
        self.assertTrue(result.valid)
        self.assertEqual(result.sanitized_value, "crystals-kyber")


class TestAlgorithmParameterValidatorV23(unittest.TestCase):
    def test_valid_key_size(self):
        result = AlgorithmParameterValidatorV23.validate_key_size("rsa", 4096)
        self.assertTrue(result.valid)
    
    def test_weak_key_size_detected(self):
        result = AlgorithmParameterValidatorV23.validate_key_size("rsa", 1024)
        self.assertFalse(result.valid)


class TestSecurePQAuditDecoratorV23(unittest.TestCase):
    def test_decorator_wraps_function(self):
        @secure_pq_audit_v23(client_id="test")
        def test_audit(audit_config=None):
            return {
                "audit_id": "audit-001",
                "audit_type": "key_management",
                "compliance_score": 90
            }
        
        result = test_audit(audit_config={"algorithm": "kyber"})
        self.assertIn("audit_id", result)
        self.assertIn("tamper_protection", result)


class TestVersionInformationV23(unittest.TestCase):
    def test_version_info(self):
        info = get_crypto_security_hardening_v23_info()
        self.assertEqual(info["version"], "v23")
        self.assertEqual(info["dimension"], "B - Security Hardening")
        self.assertEqual(info["session"], "127")
        self.assertIn("100% ADD-ONLY", info["implementation_note"])


if __name__ == '__main__':
    unittest.main(verbosity=2)
