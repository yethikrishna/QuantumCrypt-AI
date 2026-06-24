"""
Test Suite for QuantumCrypt Security Hardening v17 - PQ Audit Report Protection
================================================================================
DIMENSION B - SECURITY HARDENING
ADD-ONLY TESTS - NO EXISTING TESTS MODIFIED

All tests are isolated and do not affect existing functionality.
"""

import unittest
import time
import threading
import hashlib
import hmac
import secrets

# Import the new security hardening module
from quantum_crypt.security_hardening_pq_audit_report_protection_v17_2026_june import (
    CryptoSecurityLevel,
    KeyMaterialSensitivity,
    AuditEventType,
    CryptoValidationResult,
    KeyMaterialConfig,
    AuditSecurityContext,
    SecureKeyMaterial,
    ConstantTimeCrypto,
    AlgorithmParameterValidator,
    KeyMaterialRedactor,
    TamperEvidentAuditLog,
    ProtectedAuditGenerator,
    create_fips_140_3_audit_protector,
    create_cnsa_2024_audit_protector,
    get_version_info,
    VERSION,
    NIST_COMPLIANT,
)


# -----------------------------------------------------------------------------
# Test Security Enums
# -----------------------------------------------------------------------------

class TestCryptoSecurityLevelEnum(unittest.TestCase):
    """Test CryptoSecurityLevel enum values."""
    
    def test_security_level_values(self):
        """Test all crypto security level values exist."""
        levels = list(CryptoSecurityLevel)
        self.assertGreaterEqual(len(levels), 6)
        self.assertIn(CryptoSecurityLevel.FIPS_140_3_LEVEL2, levels)
        self.assertIn(CryptoSecurityLevel.CNSA_2024, levels)
        self.assertIn(CryptoSecurityLevel.QUANTUM_RESISTANT, levels)


class TestKeyMaterialSensitivityEnum(unittest.TestCase):
    """Test KeyMaterialSensitivity enum."""
    
    def test_sensitivity_order(self):
        """Test sensitivity ordering is correct."""
        self.assertEqual(KeyMaterialSensitivity.PUBLIC.value, "public")
        self.assertEqual(KeyMaterialSensitivity.CRITICAL.value, "critical")


# -----------------------------------------------------------------------------
# Test Data Classes
# -----------------------------------------------------------------------------

class TestCryptoValidationResult(unittest.TestCase):
    """Test CryptoValidationResult dataclass."""
    
    def test_default_values(self):
        """Test default values are correct."""
        result = CryptoValidationResult(valid=True)
        self.assertFalse(result.compliant)
        self.assertEqual(result.errors, [])
        self.assertFalse(result.nist_sp800_186_compliant)
    
    def test_nist_compliant_flag(self):
        """Test NIST compliance flag works."""
        result = CryptoValidationResult(
            valid=True,
            compliant=True,
            nist_sp800_186_compliant=True
        )
        self.assertTrue(result.nist_sp800_186_compliant)


class TestKeyMaterialConfig(unittest.TestCase):
    """Test KeyMaterialConfig dataclass."""
    
    def test_default_protections(self):
        """Test default key protections are enabled."""
        config = KeyMaterialConfig()
        self.assertTrue(config.auto_zeroize)
        self.assertTrue(config.redact_in_logs)
        self.assertEqual(config.min_key_length_bits, 256)
    
    def test_approved_algorithms(self):
        """Test approved algorithms list includes NIST PQ algorithms."""
        config = KeyMaterialConfig()
        self.assertIn('CRYSTALS-Kyber', config.allowed_algorithms)
        self.assertIn('CRYSTALS-Dilithium', config.allowed_algorithms)
        self.assertIn('SPHINCS+', config.allowed_algorithms)


# -----------------------------------------------------------------------------
# Test Secure Key Material Zeroization
# -----------------------------------------------------------------------------

class TestSecureKeyMaterial(unittest.TestCase):
    """Test PQ-specific secure key material handling."""
    
    def test_zeroize_string_key(self):
        """Test string key zeroization."""
        key = "private_key_material_here_12345"
        SecureKeyMaterial.zeroize_private_key(key)
    
    def test_zeroize_bytes_key(self):
        """Test bytes key zeroization."""
        key = b"\x01\x02\x03\x04\x05" * 100
        SecureKeyMaterial.zeroize_private_key(key)
    
    def test_zeroize_dict_keys(self):
        """Test dictionary key zeroization."""
        keys = {
            'private_key': 'secret_data',
            'shared_secret': 'sensitive_value'
        }
        SecureKeyMaterial.zeroize_private_key(keys)
        self.assertEqual(keys, {})
    
    def test_classify_key_sensitivity(self):
        """Test key sensitivity classification."""
        self.assertEqual(
            SecureKeyMaterial.classify_key_sensitivity("private_key"),
            KeyMaterialSensitivity.CRITICAL
        )
        self.assertEqual(
            SecureKeyMaterial.classify_key_sensitivity("shared_secret"),
            KeyMaterialSensitivity.CRITICAL
        )
        self.assertEqual(
            SecureKeyMaterial.classify_key_sensitivity("public_key"),
            KeyMaterialSensitivity.PUBLIC
        )


# -----------------------------------------------------------------------------
# Test Constant-Time Cryptographic Operations
# -----------------------------------------------------------------------------

class TestConstantTimeCrypto(unittest.TestCase):
    """Test constant-time crypto operations."""
    
    def test_verify_signature_ct_equal(self):
        """Test equal signatures verify correctly."""
        sig1 = secrets.token_bytes(32)
        sig2 = sig1[:]
        self.assertTrue(ConstantTimeCrypto.verify_signature_ct(sig1, sig2))
    
    def test_verify_signature_ct_not_equal(self):
        """Test unequal signatures fail correctly."""
        sig1 = secrets.token_bytes(32)
        sig2 = secrets.token_bytes(32)
        self.assertFalse(ConstantTimeCrypto.verify_signature_ct(sig1, sig2))
    
    def test_verify_digest_ct(self):
        """Test digest verification."""
        digest1 = hashlib.sha256(b"test").hexdigest()
        digest2 = hashlib.sha256(b"test").hexdigest()
        self.assertTrue(ConstantTimeCrypto.verify_digest_ct(digest1, digest2))
    
    def test_verify_digest_ct_different_length(self):
        """Test different length digests fail."""
        self.assertFalse(ConstantTimeCrypto.verify_digest_ct("abc", "abcd"))
    
    def test_check_key_length_ct(self):
        """Test key length checking without timing leakage."""
        self.assertTrue(ConstantTimeCrypto.check_key_length_ct(256, 128))
        self.assertTrue(ConstantTimeCrypto.check_key_length_ct(256, 256))
        self.assertFalse(ConstantTimeCrypto.check_key_length_ct(128, 256))


# -----------------------------------------------------------------------------
# Test Algorithm Parameter Validation
# -----------------------------------------------------------------------------

class TestAlgorithmParameterValidator(unittest.TestCase):
    """Test NIST SP 800-186 algorithm validation."""
    
    def test_validate_pq_algorithm_valid_kyber(self):
        """Test valid CRYSTALS-Kyber parameters."""
        result = AlgorithmParameterValidator.validate_pq_algorithm("CRYSTALS-Kyber", 768)
        self.assertTrue(result.valid)
        self.assertTrue(result.nist_sp800_186_compliant)
    
    def test_validate_pq_algorithm_valid_dilithium(self):
        """Test valid CRYSTALS-Dilithium parameters."""
        result = AlgorithmParameterValidator.validate_pq_algorithm("CRYSTALS-Dilithium", 3)
        self.assertTrue(result.valid)
        self.assertTrue(result.nist_sp800_186_compliant)
    
    def test_validate_pq_algorithm_invalid(self):
        """Test invalid algorithm fails."""
        result = AlgorithmParameterValidator.validate_pq_algorithm("FakeAlgorithm", 123)
        self.assertFalse(result.valid)
        self.assertFalse(result.nist_sp800_186_compliant)
    
    def test_validate_pq_algorithm_invalid_parameter(self):
        """Test invalid parameter size fails."""
        result = AlgorithmParameterValidator.validate_pq_algorithm("CRYSTALS-Kyber", 999)
        self.assertFalse(result.valid)
    
    def test_validate_classic_algorithm_rsa_3072(self):
        """Test RSA-3072 is quantum-resistant recommended."""
        result = AlgorithmParameterValidator.validate_classic_algorithm("RSA", 3072)
        self.assertTrue(result.valid)
        self.assertTrue(result.compliant)
    
    def test_validate_classic_algorithm_rsa_2048_warning(self):
        """Test RSA-2048 gives warning (not quantum-resistant)."""
        result = AlgorithmParameterValidator.validate_classic_algorithm("RSA", 2048)
        self.assertTrue(result.valid)
        self.assertGreater(len(result.warnings), 0)
    
    def test_validate_audit_check_name_valid(self):
        """Test valid audit check name."""
        result = AlgorithmParameterValidator.validate_audit_check_name("Key Management Audit")
        self.assertTrue(result.valid)
    
    def test_validate_audit_check_name_xss(self):
        """Test XSS injection detection."""
        result = AlgorithmParameterValidator.validate_audit_check_name("<script>alert(1)</script>")
        self.assertFalse(result.valid)
    
    def test_validate_audit_check_name_empty(self):
        """Test empty audit name fails."""
        result = AlgorithmParameterValidator.validate_audit_check_name("")
        self.assertFalse(result.valid)
    
    def test_validate_audit_check_name_too_long(self):
        """Test overly long audit name fails."""
        long_name = "x" * 300
        result = AlgorithmParameterValidator.validate_audit_check_name(long_name)
        self.assertFalse(result.valid)


# -----------------------------------------------------------------------------
# Test Key Material Redaction
# -----------------------------------------------------------------------------

class TestKeyMaterialRedactor(unittest.TestCase):
    """Test sensitive key material redaction."""
    
    def test_redact_long_base64_key(self):
        """Test long base64 key material redaction."""
        key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/AAAA"
        text = f"Private key: {key}"
        redacted = KeyMaterialRedactor.redact_key_material(text)
        self.assertIn("[KEY_MATERIAL_REDACTED]", redacted)
    
    def test_redact_long_hex_key(self):
        """Test long hex key material redaction."""
        key = "a" * 80
        text = f"Secret: {key}"
        redacted = KeyMaterialRedactor.redact_key_material(text)
        self.assertIn("[KEY_MATERIAL_REDACTED]", redacted)
    
    def test_redact_pem_key(self):
        """Test PEM format key redaction."""
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----"
        redacted = KeyMaterialRedactor.redact_key_material(pem)
        self.assertIn("[KEY_MATERIAL_REDACTED]", redacted)
    
    def test_redact_audit_content_recursive(self):
        """Test recursive audit content redaction."""
        content = {
            "audit_name": "Test Audit",
            "private_key": "secret_data_here",
            "nested": {
                "shared_secret": "sensitive_value",
                "public_key": "safe_to_show"
            }
        }
        redacted = KeyMaterialRedactor.redact_audit_content(content)
        self.assertEqual(redacted["private_key"], "[KEY_MATERIAL_REDACTED]")
        self.assertEqual(redacted["nested"]["shared_secret"], "[KEY_MATERIAL_REDACTED]")
        self.assertEqual(redacted["audit_name"], "Test Audit")


# -----------------------------------------------------------------------------
# Test Tamper-Evident Audit Log
# -----------------------------------------------------------------------------

class TestTamperEvidentAuditLog(unittest.TestCase):
    """Test HMAC-chained tamper-evident audit log."""
    
    def setUp(self):
        """Set up test audit log."""
        self.secret = secrets.token_bytes(32)
        self.audit_log = TamperEvidentAuditLog(self.secret)
    
    def test_add_entry(self):
        """Test adding audit entry."""
        hmac = self.audit_log.add_entry(
            AuditEventType.AUDIT_GENERATION,
            {"test": "data"}
        )
        self.assertIsNotNone(hmac)
        entries = self.audit_log.get_entries()
        self.assertEqual(len(entries), 1)
    
    def test_verify_integrity_clean(self):
        """Test integrity verification on untampered log."""
        for i in range(5):
            self.audit_log.add_entry(
                AuditEventType.AUDIT_GENERATION,
                {"entry": i}
            )
        valid, idx = self.audit_log.verify_integrity()
        self.assertTrue(valid)
        self.assertEqual(idx, -1)
    
    def test_chain_hmac_present(self):
        """Test each entry has chain HMAC."""
        self.audit_log.add_entry(AuditEventType.KEY_VALIDATION, {})
        entries = self.audit_log.get_entries()
        self.assertIn('chain_hmac', entries[0])
        self.assertEqual(len(entries[0]['chain_hmac']), 64)
    
    def test_thread_safe_additions(self):
        """Test concurrent additions maintain integrity."""
        def worker():
            for i in range(10):
                self.audit_log.add_entry(AuditEventType.INTEGRITY_CHECK, {"i": i})
        
        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        valid, idx = self.audit_log.verify_integrity()
        self.assertTrue(valid)
        self.assertEqual(len(self.audit_log.get_entries()), 30)


# -----------------------------------------------------------------------------
# Test Protected Audit Generator
# -----------------------------------------------------------------------------

class TestProtectedAuditGenerator(unittest.TestCase):
    """Test ProtectedAuditGenerator wrapper."""
    
    def test_create_default(self):
        """Test default protector creation."""
        protector = ProtectedAuditGenerator()
        self.assertIsNotNone(protector)
    
    def test_validate_audit_request_valid(self):
        """Test valid audit request passes."""
        protector = ProtectedAuditGenerator()
        result = protector.validate_audit_request(
            audit_type="Key Management Audit",
            compliance_standard="NIST_SP_800_186"
        )
        self.assertTrue(result.valid)
    
    def test_validate_audit_request_invalid(self):
        """Test invalid audit request fails."""
        protector = ProtectedAuditGenerator()
        result = protector.validate_audit_request(
            audit_type="",
            compliance_standard="TEST"
        )
        self.assertFalse(result.valid)
    
    def test_validate_pq_algorithm_selection(self):
        """Test PQ algorithm validation."""
        protector = ProtectedAuditGenerator()
        result = protector.validate_pq_algorithm_selection("CRYSTALS-Kyber", 768)
        self.assertTrue(result.valid)
        self.assertTrue(result.nist_sp800_186_compliant)
    
    def test_generate_protected_audit_basic(self):
        """Test basic protected audit generation."""
        protector = ProtectedAuditGenerator()
        result = protector.generate_protected_audit(
            audit_type="Key Management",
            compliance_standard="NIST_SP_800_186"
        )
        self.assertTrue(result['success'])
        self.assertTrue(result['security_protected'])
        self.assertIn('security_level', result)
    
    def test_generate_protected_audit_with_data(self):
        """Test audit generation with sensitive data."""
        protector = ProtectedAuditGenerator()
        sensitive_data = {
            "private_key": "very_long_hex_string_here_1234567890abcdef",
            "audit_score": 95
        }
        result = protector.generate_protected_audit(
            audit_type="Algorithm Compliance",
            compliance_standard="FIPS_140_3",
            audit_data=sensitive_data
        )
        self.assertTrue(result['success'])
    
    def test_get_security_status(self):
        """Test security status reporting."""
        protector = ProtectedAuditGenerator()
        status = protector.get_security_status()
        self.assertEqual(status['security_level'], 'cnsa_2024')
        self.assertTrue(status['nist_sp800_186_validation'])
        self.assertTrue(status['key_auto_zeroize'])
        self.assertEqual(status['version'], 'v17')
    
    def test_verify_audit_integrity_no_hmac(self):
        """Test integrity check without HMAC fails."""
        protector = ProtectedAuditGenerator()
        report = {'data': 'test'}
        self.assertFalse(protector.verify_audit_integrity(report))


# -----------------------------------------------------------------------------
# Test Factory Functions
# -----------------------------------------------------------------------------

class TestFactoryFunctions(unittest.TestCase):
    """Test convenience factory functions."""
    
    def test_create_fips_140_3_protector(self):
        """Test FIPS 140-3 protector creation."""
        protector = create_fips_140_3_audit_protector()
        status = protector.get_security_status()
        self.assertEqual(status['security_level'], 'fips_140_3_level2')
        self.assertTrue(status['audit_logging_enabled'])
    
    def test_create_cnsa_2024_protector(self):
        """Test CNSA 2024 protector creation."""
        protector = create_cnsa_2024_audit_protector()
        status = protector.get_security_status()
        self.assertEqual(status['security_level'], 'cnsa_2024')
        self.assertTrue(status['audit_trail_hmac'])


# -----------------------------------------------------------------------------
# Test Version Information
# -----------------------------------------------------------------------------

class TestVersionInformation(unittest.TestCase):
    """Test version information functions."""
    
    def test_version_constant(self):
        """Test version constant is correct."""
        self.assertEqual(VERSION, "v17")
    
    def test_nist_compliant_flag(self):
        """Test NIST compliance flag."""
        self.assertTrue(NIST_COMPLIANT)
    
    def test_get_version_info(self):
        """Test get_version_info returns correct data."""
        info = get_version_info()
        self.assertEqual(info['version'], 'v17')
        self.assertEqual(info['stability'], 'STABLE')
        self.assertEqual(info['dimension'], 'B - Security Hardening')
        self.assertTrue(info['nist_sp800_186_compliant'])
        self.assertTrue(info['backward_compatible'])
        self.assertTrue(info['add_only'])


# -----------------------------------------------------------------------------
# Test Backward Compatibility
# -----------------------------------------------------------------------------

class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility guarantees."""
    
    def test_no_dependencies(self):
        """Test module has no external dependencies."""
        from quantum_crypt.security_hardening_pq_audit_report_protection_v17_2026_june import DEPENDENCIES
        self.assertEqual(DEPENDENCIES, [])
    
    def test_pure_python(self):
        """Test module imports without external packages."""
        import quantum_crypt.security_hardening_pq_audit_report_protection_v17_2026_june as module
        self.assertIsNotNone(module)
    
    def test_wrapper_pattern(self):
        """Test wrapper pattern works without underlying generator."""
        protector = ProtectedAuditGenerator(underlying_generator=None)
        result = protector.generate_protected_audit("test", "NIST")
        self.assertTrue(result['success'])


# -----------------------------------------------------------------------------
# Run all tests
# -----------------------------------------------------------------------------

def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestCryptoSecurityLevelEnum,
        TestKeyMaterialSensitivityEnum,
        TestCryptoValidationResult,
        TestKeyMaterialConfig,
        TestSecureKeyMaterial,
        TestConstantTimeCrypto,
        TestAlgorithmParameterValidator,
        TestKeyMaterialRedactor,
        TestTamperEvidentAuditLog,
        TestProtectedAuditGenerator,
        TestFactoryFunctions,
        TestVersionInformation,
        TestBackwardCompatibility,
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == '__main__':
    result = run_tests()
    exit(0 if result.wasSuccessful() else 1)
