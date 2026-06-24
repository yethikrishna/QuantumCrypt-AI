"""
Tests for Security Hardening v22 - PQ Crypto Audit Report Protection Module
QuantumCrypt-AI

Covers all security features:
- Algorithm and key size validation
- Compliance standard validation
- Audit score and risk level validation
- Rate limiting and DoS protection
- Secure memory handling for key material
- Constant-time comparison
- HMAC audit sealing and tamper detection
- Key material masking
- Security context isolation
- Thread safety
- Backward compatibility
"""
import unittest
import threading
import time
from typing import Any

# Import security module
from quantum_crypt.crypto_security_hardening_pq_audit_report_protection_v22_2026_june import (
    AuditSecurityLevel,
    ComplianceStandard,
    ValidationSeverity,
    SecurityEventType,
    ValidationResult,
    SecurityEvent,
    AuditRateLimitConfig,
    ProtectedAuditContext,
    CryptoSecureMemoryV22,
    CryptoAuditValidator,
    AuditContentSanitizer,
    AuditRateLimiter,
    AuditSealer,
    ProtectedPQAuditGenerator,
    create_protected_audit_generator,
    __version__,
    __compatibility__,
)

# ============================================================================
# ENUMERATION TESTS
# ============================================================================

class TestAuditSecurityLevelEnum(unittest.TestCase):
    """Test security level enumeration."""
    
    def test_security_level_count(self):
        """Test correct number of security levels."""
        self.assertEqual(len(AuditSecurityLevel), 4)
    
    def test_security_level_values(self):
        """Test all security level values exist."""
        levels = {level.value for level in AuditSecurityLevel}
        self.assertIn("basic", levels)
        self.assertIn("standard", levels)
        self.assertIn("enhanced", levels)
        self.assertIn("maximum", levels)

class TestComplianceStandardEnum(unittest.TestCase):
    """Test compliance standard enumeration."""
    
    def test_compliance_standards_exist(self):
        """Test key compliance standards exist."""
        standards = {s.value for s in ComplianceStandard}
        self.assertIn("NIST SP 800-186", standards)
        self.assertIn("FIPS 140-3", standards)
        self.assertIn("CNSA 2.0", standards)
        self.assertIn("GDPR", standards)

# ============================================================================
# DATA CLASS TESTS
# ============================================================================

class TestValidationResult(unittest.TestCase):
    """Test ValidationResult data class."""
    
    def test_validation_result_creation(self):
        """Test basic validation result creation."""
        result = ValidationResult(valid=True, message="Test passed")
        self.assertTrue(result.valid)
        self.assertEqual(result.message, "Test passed")
        self.assertGreater(result.check_timestamp, 0)

class TestProtectedAuditContext(unittest.TestCase):
    """Test ProtectedAuditContext data class."""
    
    def test_context_creation(self):
        """Test context creation with defaults."""
        context = ProtectedAuditContext()
        self.assertGreater(len(context.context_id), 0)
        self.assertEqual(context.security_level, AuditSecurityLevel.STANDARD)
        self.assertEqual(context.audit_count, 0)
    
    def test_context_increment_audit(self):
        """Test thread-safe audit counter increment."""
        context = ProtectedAuditContext()
        context.increment_audit_count()
        context.increment_audit_count()
        self.assertEqual(context.audit_count, 2)

# ============================================================================
# SECURE MEMORY TESTS
# ============================================================================

class TestCryptoSecureMemoryV22(unittest.TestCase):
    """Test crypto secure memory utilities."""
    
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison for equal values."""
        a = b"crypto_key_material_123"
        b = b"crypto_key_material_123"
        self.assertTrue(CryptoSecureMemoryV22.constant_time_compare(a, b))
    
    def test_constant_time_compare_not_equal(self):
        """Test constant-time comparison for different values."""
        a = b"crypto_key_material_123"
        b = b"crypto_key_material_456"
        self.assertFalse(CryptoSecureMemoryV22.constant_time_compare(a, b))
    
    def test_mask_key_material_short(self):
        """Test key material masking for short keys."""
        masked = CryptoSecureMemoryV22.mask_key_material("abcd")
        self.assertEqual(masked, "****")
    
    def test_mask_key_material_long(self):
        """Test key material masking for long keys."""
        masked = CryptoSecureMemoryV22.mask_key_material("abcdefghijklmnopqrstuvwxyz")
        self.assertTrue(masked.startswith("abcdefgh"))
        self.assertTrue(masked.endswith("stuvwxyz"))
        self.assertIn("...", masked)
    
    def test_zeroize_bytearray(self):
        """Test bytearray zeroization."""
        data = bytearray(b"private_key_data_here_12345")
        CryptoSecureMemoryV22.zeroize_bytearray(data)
        self.assertEqual(sum(data), 0)
    
    def test_zeroize_key_material(self):
        """Test key material dictionary zeroization."""
        key_data = {
            "private_key": "secret_data_here",
            "seed": "random_entropy_value"
        }
        CryptoSecureMemoryV22.zeroize_key_material(key_data)
        # Should not raise exceptions

# ============================================================================
# CRYPTO AUDIT VALIDATOR TESTS
# ============================================================================

class TestCryptoAuditValidator(unittest.TestCase):
    """Test crypto audit input validation."""
    
    def test_validate_algorithm_valid(self):
        """Test valid algorithm validation."""
        result = CryptoAuditValidator.validate_algorithm("CRYSTALS-Kyber")
        self.assertTrue(result.valid)
    
    def test_validate_algorithm_unknown(self):
        """Test unknown algorithm validation."""
        result = CryptoAuditValidator.validate_algorithm("UnknownAlgo-123")
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.WARNING)
    
    def test_validate_algorithm_empty(self):
        """Test empty algorithm validation."""
        result = CryptoAuditValidator.validate_algorithm("")
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, ValidationSeverity.ERROR)
    
    def test_validate_key_size_valid(self):
        """Test valid key size validation."""
        result = CryptoAuditValidator.validate_key_size(2048, "rsa")
        self.assertTrue(result.valid)
    
    def test_validate_key_size_invalid(self):
        """Test invalid key size validation."""
        result = CryptoAuditValidator.validate_key_size(-1)
        self.assertFalse(result.valid)
    
    def test_validate_key_size_out_of_range(self):
        """Test out-of-range key size clamping."""
        result = CryptoAuditValidator.validate_key_size(100, "rsa")
        self.assertFalse(result.valid)
        self.assertEqual(result.sanitized_value, 2048)
    
    def test_validate_audit_score_valid(self):
        """Test valid audit score validation."""
        result = CryptoAuditValidator.validate_audit_score(75.5)
        self.assertTrue(result.valid)
    
    def test_validate_audit_score_clamped(self):
        """Test out-of-range audit score clamping."""
        result = CryptoAuditValidator.validate_audit_score(150.0)
        self.assertFalse(result.valid)
        self.assertEqual(result.sanitized_value, 100.0)
    
    def test_validate_risk_level_valid(self):
        """Test valid risk level validation."""
        result = CryptoAuditValidator.validate_risk_level("critical")
        self.assertTrue(result.valid)
    
    def test_validate_risk_level_invalid(self):
        """Test invalid risk level validation."""
        result = CryptoAuditValidator.validate_risk_level("EXTREME_DANGER")
        self.assertFalse(result.valid)
        self.assertEqual(result.sanitized_value, "unknown")
    
    def test_validate_compliance_standard_valid(self):
        """Test valid compliance standard validation."""
        result = CryptoAuditValidator.validate_compliance_standard("NIST SP 800-186")
        self.assertTrue(result.valid)

# ============================================================================
# AUDIT CONTENT SANITIZER TESTS
# ============================================================================

class TestAuditContentSanitizer(unittest.TestCase):
    """Test audit content sanitization."""
    
    def test_sanitize_xss_script(self):
        """Test XSS script tag sanitization."""
        content = '<script>steal_keys()</script>'
        sanitized = AuditContentSanitizer.sanitize_audit_content(content)
        self.assertNotIn('<script', sanitized.lower())
    
    def test_sanitize_key_material(self):
        """Test key material masking."""
        key_data = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
        sanitized = AuditContentSanitizer.sanitize_key_material(key_data)
        self.assertNotEqual(sanitized, key_data)
        self.assertIn("...", sanitized)
    
    def test_sanitize_filename(self):
        """Test filename path traversal sanitization."""
        filename = '../../etc/ssh/ssh_host_rsa_key'
        sanitized = AuditContentSanitizer.sanitize_filename(filename)
        self.assertNotIn('..', sanitized)
        self.assertNotIn('/', sanitized)
    
    def test_sanitize_recommendation(self):
        """Test recommendation text sanitization."""
        rec = 'Run <script>backdoor()</script> on server'
        sanitized = AuditContentSanitizer.sanitize_recommendation(rec)
        self.assertNotIn('<script', sanitized.lower())

# ============================================================================
# RATE LIMITER TESTS
# ============================================================================

class TestAuditRateLimiter(unittest.TestCase):
    """Test audit rate limiting functionality."""
    
    def test_rate_limit_initial_allowed(self):
        """Test initial requests are allowed."""
        limiter = AuditRateLimiter(AuditRateLimitConfig(max_audits_per_hour=5))
        allowed, meta = limiter.check_rate_limit("client1")
        self.assertTrue(allowed)
    
    def test_rate_limit_exceeded(self):
        """Test rate limit enforcement."""
        config = AuditRateLimitConfig(max_audits_per_hour=2, window_seconds=3600)
        limiter = AuditRateLimiter(config)
        
        limiter.check_rate_limit("client1")
        limiter.check_rate_limit("client1")
        allowed, _ = limiter.check_rate_limit("client1")
        
        self.assertFalse(allowed)
    
    def test_check_algorithm_count(self):
        """Test algorithm count limit check."""
        limiter = AuditRateLimiter(AuditRateLimitConfig(max_algorithms_per_audit=10))
        self.assertTrue(limiter.check_algorithm_count(5))
        self.assertFalse(limiter.check_algorithm_count(100))

# ============================================================================
# AUDIT SEALER TESTS
# ============================================================================

class TestAuditSealer(unittest.TestCase):
    """Test audit sealing and tamper detection."""
    
    def test_seal_audit(self):
        """Test audit sealing creates signature."""
        sealer = AuditSealer()
        result = sealer.seal_audit("audit content here", "audit_123")
        self.assertEqual(result["audit_id"], "audit_123")
        self.assertIn("signature", result)
        self.assertTrue(result["sealed"])
    
    def test_verify_audit_valid(self):
        """Test valid audit verification."""
        sealer = AuditSealer()
        content = "original audit content"
        seal = sealer.seal_audit(content, "audit_123")
        
        valid, msg = sealer.verify_audit(content, seal)
        self.assertTrue(valid)
    
    def test_verify_audit_tampered(self):
        """Test tampered audit detection."""
        sealer = AuditSealer()
        content = "original audit content"
        seal = sealer.seal_audit(content, "audit_123")
        
        tampered = "tampered audit content with fake scores"
        valid, msg = sealer.verify_audit(tampered, seal)
        self.assertFalse(valid)
        self.assertIn("tampering", msg.lower())

# ============================================================================
# PROTECTED AUDIT GENERATOR TESTS
# ============================================================================

class TestProtectedPQAuditGenerator(unittest.TestCase):
    """Test main protected audit generator wrapper."""
    
    def test_generator_creation(self):
        """Test generator creation with different security levels."""
        gen = ProtectedPQAuditGenerator(security_level=AuditSecurityLevel.MAXIMUM)
        self.assertEqual(gen.security_level, AuditSecurityLevel.MAXIMUM)
        self.assertTrue(gen._initialized)
    
    def test_validate_audit_inputs_valid(self):
        """Test valid audit inputs validation."""
        gen = ProtectedPQAuditGenerator()
        results = gen.validate_audit_inputs(
            audit_type="full_audit",
            output_format="json"
        )
        self.assertEqual(len(results), 0)
    
    def test_validate_audit_inputs_invalid_type(self):
        """Test invalid audit type validation."""
        gen = ProtectedPQAuditGenerator()
        results = gen.validate_audit_inputs(
            audit_type="invalid_audit_type",
            output_format="json"
        )
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].valid)
    
    def test_generate_protected_audit_mock(self):
        """Test protected audit generation with mock generator."""
        gen = ProtectedPQAuditGenerator()
        
        def mock_audit(**kwargs):
            return {"audit": "generated", "type": kwargs.get("audit_type"), "score": 85.0}
        
        result = gen.generate_protected_audit(
            mock_audit,
            audit_type="pq_compliance",
            output_format="json"
        )
        
        self.assertTrue(result["success"])
        self.assertTrue(result["security_protected"])
        self.assertIn("original_result", result)
    
    def test_get_security_audit_log(self):
        """Test security audit log retrieval."""
        gen = ProtectedPQAuditGenerator()
        
        def mock_audit(**kwargs):
            return {"test": "data"}
        
        gen.generate_protected_audit(mock_audit, "full_audit", "json")
        log = gen.get_security_audit_log()
        
        self.assertGreater(len(log), 0)
        self.assertIn("event_type", log[0])
    
    def test_secure_dispose(self):
        """Test secure context disposal."""
        gen = ProtectedPQAuditGenerator(security_level=AuditSecurityLevel.MAXIMUM)
        gen.secure_dispose()
        # Should not raise exceptions

# ============================================================================
# CONVENIENCE FUNCTION TESTS
# ============================================================================

class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience wrapper functions."""
    
    def test_create_protected_audit_generator_default(self):
        """Test default generator creation."""
        gen = create_protected_audit_generator()
        self.assertIsInstance(gen, ProtectedPQAuditGenerator)
    
    def test_create_protected_audit_generator(self):
        """Test generator creation with level parameter."""
        gen = create_protected_audit_generator("maximum")
        self.assertEqual(gen.security_level, AuditSecurityLevel.MAXIMUM)

# ============================================================================
# THREAD SAFETY TESTS
# ============================================================================

class TestThreadSafety(unittest.TestCase):
    """Test thread safety of security components."""
    
    def test_context_thread_safety(self):
        """Test ProtectedAuditContext is thread-safe."""
        context = ProtectedAuditContext()
        num_threads = 10
        increments_per_thread = 100
        
        def worker():
            for _ in range(increments_per_thread):
                context.increment_audit_count()
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(context.audit_count, num_threads * increments_per_thread)

# ============================================================================
# BACKWARD COMPATIBILITY TESTS
# ============================================================================

class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility guarantees."""
    
    def test_module_version_info(self):
        """Test version metadata exists."""
        self.assertEqual(__version__, "22.0.0")
        self.assertIn("100% backward compatible", __compatibility__)

# ============================================================================
# TEST RUNNER
# ============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
