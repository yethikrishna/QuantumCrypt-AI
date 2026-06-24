"""
Test Suite for QuantumCrypt-AI Security Hardening Module v17
DIMENSION B - Security Hardening

Tests cover:
1. CryptoSecurityLevel enum
2. AuditValidationSeverity enum
3. CryptoValidationResult dataclass
4. CryptoRateLimitConfig dataclass
5. CryptoSecureMemory utilities
6. CryptoRateLimiter functionality
7. CryptoInputValidator validation
8. CryptoSecurityAuditLogger
9. SecureAuditReportGeneratorWrapper
10. Convenience functions
11. Backward compatibility
12. Version information
13. FIPS compliance features
"""

import unittest
import threading
import time
from unittest.mock import Mock, patch

# Import the crypto security hardening module
from quantum_crypt.crypto_security_hardening_audit_report_v17_2026_june import (
    CryptoSecurityError,
    CryptoRateLimitExceededError,
    CryptoSecurityLevel,
    AuditValidationSeverity,
    CryptoValidationResult,
    CryptoRateLimitConfig,
    CryptoSecureMemory,
    CryptoRateLimiter,
    CryptoInputValidator,
    CryptoSecurityAuditLogger,
    SecureAuditReportGeneratorWrapper,
    create_crypto_secure_wrapper,
    crypto_constant_time_compare,
    crypto_zeroize_key_material,
    CRYPTO_SECURITY_HARDENING_VERSION,
    CRYPTO_SECURITY_HARDENING_BUILD_DATE,
    CRYPTO_SECURITY_HARDENING_DIMENSION,
)


class TestCryptoSecurityLevelEnum(unittest.TestCase):
    """Test CryptoSecurityLevel enum values"""
    
    def test_security_level_values(self):
        self.assertEqual(CryptoSecurityLevel.STANDARD.value, "standard")
        self.assertEqual(CryptoSecurityLevel.ENHANCED.value, "enhanced")
        self.assertEqual(CryptoSecurityLevel.HARDENED.value, "hardened")
        self.assertEqual(CryptoSecurityLevel.FIPS_COMPLIANT.value, "fips_140_3")
    
    def test_security_level_count(self):
        self.assertEqual(len(list(CryptoSecurityLevel)), 4)


class TestAuditValidationSeverityEnum(unittest.TestCase):
    """Test AuditValidationSeverity enum values"""
    
    def test_severity_values(self):
        self.assertEqual(AuditValidationSeverity.DEBUG.value, "debug")
        self.assertEqual(AuditValidationSeverity.INFO.value, "info")
        self.assertEqual(AuditValidationSeverity.NOTICE.value, "notice")
        self.assertEqual(AuditValidationSeverity.WARNING.value, "warning")
        self.assertEqual(AuditValidationSeverity.ERROR.value, "error")
        self.assertEqual(AuditValidationSeverity.CRITICAL.value, "critical")
        self.assertEqual(AuditValidationSeverity.EMERGENCY.value, "emergency")
    
    def test_severity_count(self):
        self.assertEqual(len(list(AuditValidationSeverity)), 7)


class TestCryptoValidationResult(unittest.TestCase):
    """Test CryptoValidationResult dataclass"""
    
    def test_initial_state(self):
        result = CryptoValidationResult(is_valid=True)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])
        self.assertIsNotNone(result.validation_id)
    
    def test_add_error(self):
        result = CryptoValidationResult(is_valid=True)
        result.add_error("Test crypto error")
        self.assertFalse(result.is_valid)
        self.assertIn("Test crypto error", result.errors)
    
    def test_add_warning(self):
        result = CryptoValidationResult(is_valid=True)
        result.add_warning("Test crypto warning")
        self.assertTrue(result.is_valid)
        self.assertIn("Test crypto warning", result.warnings)
    
    def test_validation_id_uniqueness(self):
        results = [CryptoValidationResult(is_valid=True) for _ in range(50)]
        ids = [r.validation_id for r in results]
        self.assertEqual(len(set(ids)), 50)  # All unique


class TestCryptoRateLimitConfig(unittest.TestCase):
    """Test CryptoRateLimitConfig dataclass"""
    
    def test_default_values(self):
        config = CryptoRateLimitConfig()
        self.assertEqual(config.max_audits_per_minute, 30)
        self.assertEqual(config.max_audits_per_hour, 500)
        self.assertEqual(config.max_key_checks_per_minute, 100)
        self.assertEqual(config.max_checks_per_audit, 200)
    
    def test_custom_values(self):
        config = CryptoRateLimitConfig(
            max_audits_per_minute=10,
            max_audits_per_hour=100
        )
        self.assertEqual(config.max_audits_per_minute, 10)
        self.assertEqual(config.max_audits_per_hour, 100)


class TestCryptoSecureMemory(unittest.TestCase):
    """Test CryptoSecureMemory security utilities"""
    
    def test_constant_time_compare_equal(self):
        self.assertTrue(CryptoSecureMemory.constant_time_compare("crypto_test", "crypto_test"))
    
    def test_constant_time_compare_not_equal(self):
        self.assertFalse(CryptoSecureMemory.constant_time_compare("crypto_test", "other_test"))
    
    def test_constant_time_compare_bytes_equal(self):
        self.assertTrue(CryptoSecureMemory.constant_time_compare_bytes(b"key", b"key"))
    
    def test_zeroize_key_material_bytearray(self):
        data = bytearray(b"sensitive_key_material_12345")
        CryptoSecureMemory.zeroize_key_material(data)
        self.assertEqual(all(b == 0 for b in data), True)
    
    def test_zeroize_key_material_list(self):
        data = [100, 200, 50, 150, 75]
        CryptoSecureMemory.zeroize_key_material(data)
        self.assertEqual(all(x == 0 for x in data), True)
    
    def test_generate_crypto_nonce(self):
        nonce = CryptoSecureMemory.generate_crypto_nonce(64)
        self.assertEqual(len(nonce), 64)
        self.assertIsInstance(nonce, bytes)
    
    def test_generate_crypto_token(self):
        token = CryptoSecureMemory.generate_crypto_token(128)
        self.assertEqual(len(token), 128)
        self.assertIsInstance(token, str)
    
    def test_mask_sensitive_data(self):
        masked = CryptoSecureMemory.mask_sensitive_data("my_secret_key_12345")
        self.assertTrue("*" in masked)
        self.assertNotEqual(masked, "my_secret_key_12345")
        # First and last 4 chars revealed
        self.assertTrue(masked.startswith("my_s"))
        self.assertTrue(masked.endswith("345"))
    
    def test_hash_sensitive_identifier(self):
        hashed = CryptoSecureMemory.hash_sensitive_identifier("operator_123_secret")
        self.assertEqual(len(hashed), 24)
        self.assertNotEqual(hashed, "operator_123_secret")


class TestCryptoRateLimiter(unittest.TestCase):
    """Test CryptoRateLimiter functionality"""
    
    def test_initialization(self):
        limiter = CryptoRateLimiter()
        self.assertIsNotNone(limiter.config)
    
    def test_check_audit_rate_limit_allowed(self):
        limiter = CryptoRateLimiter(CryptoRateLimitConfig(max_audits_per_minute=10))
        allowed, info = limiter.check_audit_rate_limit("test_operator")
        self.assertTrue(allowed)
        self.assertIn("minute_remaining", info)
    
    def test_audit_rate_limit_exceeded(self):
        limiter = CryptoRateLimiter(CryptoRateLimitConfig(max_audits_per_minute=2))
        limiter.check_audit_rate_limit("client1")
        limiter.check_audit_rate_limit("client1")
        allowed, info = limiter.check_audit_rate_limit("client1")
        self.assertFalse(allowed)
        self.assertIn("limit_exceeded", info["reason"])
    
    def test_different_operators_isolated(self):
        limiter = CryptoRateLimiter(CryptoRateLimitConfig(max_audits_per_minute=1))
        allowed1, _ = limiter.check_audit_rate_limit("operatorA")
        allowed2, _ = limiter.check_audit_rate_limit("operatorB")
        self.assertTrue(allowed1)
        self.assertTrue(allowed2)
    
    def test_get_usage_stats(self):
        limiter = CryptoRateLimiter()
        limiter.check_audit_rate_limit("test_op")
        stats = limiter.get_usage_stats("test_op")
        self.assertIn("audits_per_minute", stats)
        self.assertIn("audits_per_hour", stats)
        self.assertGreaterEqual(stats["audits_per_minute"], 1)


class TestCryptoInputValidator(unittest.TestCase):
    """Test CryptoInputValidator functionality"""
    
    def test_initialization(self):
        validator = CryptoInputValidator()
        self.assertEqual(validator.security_level, CryptoSecurityLevel.ENHANCED)
    
    def test_validate_valid_audit_request(self):
        validator = CryptoInputValidator()
        request = {
            "audit_type": "key_management",
            "compliance_standard": "fips_140_3",
            "output_format": "json",
            "title": "PQ Crypto Audit"
        }
        result = validator.validate_audit_request(request)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.errors, [])
    
    def test_validate_invalid_audit_type(self):
        validator = CryptoInputValidator()
        request = {"audit_type": "invalid_audit_type"}
        result = validator.validate_audit_request(request)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Invalid audit_type" in e for e in result.errors))
    
    def test_validate_invalid_compliance_standard(self):
        validator = CryptoInputValidator()
        request = {"compliance_standard": "invalid_standard"}
        result = validator.validate_audit_request(request)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Invalid compliance_standard" in e for e in result.errors))
    
    def test_validate_invalid_output_format(self):
        validator = CryptoInputValidator()
        request = {"output_format": "exe"}
        result = validator.validate_audit_request(request)
        self.assertFalse(result.is_valid)
    
    def test_validate_audit_checks(self):
        validator = CryptoInputValidator()
        request = {
            "audit_checks": [
                {"name": "Key Size Check", "status": "pass"},
                {"name": "Algorithm Validation", "status": "pass"}
            ]
        }
        result = validator.validate_audit_request(request)
        self.assertTrue(result.is_valid)
        self.assertIn("audit_checks", result.sanitized_input)
    
    def test_validate_algorithms_valid(self):
        validator = CryptoInputValidator()
        request = {
            "algorithms": ["CRYSTALS-Kyber", "ML-KEM", "SPHINCS+"]
        }
        result = validator.validate_audit_request(request)
        self.assertTrue(result.is_valid)
    
    def test_validate_algorithms_with_warning(self):
        validator = CryptoInputValidator()
        request = {
            "algorithms": ["UnknownAlgorithm123"]
        }
        result = validator.validate_audit_request(request)
        self.assertTrue(result.is_valid)  # Warning only, not error
        self.assertTrue(len(result.warnings) > 0)
    
    def test_fips_mode_nesting_validation(self):
        validator = CryptoInputValidator(CryptoSecurityLevel.FIPS_COMPLIANT)
        # Deeply nested structure
        nested = {}
        current = nested
        for i in range(20):  # Exceeds MAX_NESTING_DEPTH
            current["level"] = {}
            current = current["level"]
        
        request = {"deep_data": nested}
        result = validator.validate_audit_request(request)
        self.assertFalse(result.is_valid)


class TestCryptoSecurityAuditLogger(unittest.TestCase):
    """Test CryptoSecurityAuditLogger functionality"""
    
    def test_log_crypto_event(self):
        logger = CryptoSecurityAuditLogger()
        logger.log_crypto_event("key_audit", AuditValidationSeverity.INFO, {"key_type": "ML-KEM"})
        log = logger.get_audit_trail()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["event_type"], "key_audit")
    
    def test_sensitive_data_masking(self):
        logger = CryptoSecurityAuditLogger()
        logger.log_crypto_event("test", AuditValidationSeverity.INFO, 
                                {"private_key": "my_super_secret_key_12345"})
        log = logger.get_audit_trail()
        # Private key should be masked
        self.assertNotEqual(log[0]["details"]["private_key"], "my_super_secret_key_12345")
        self.assertTrue("*" in log[0]["details"]["private_key"])
    
    def test_operator_id_hashing(self):
        logger = CryptoSecurityAuditLogger()
        logger.log_crypto_event("test", AuditValidationSeverity.INFO, {}, "sensitive_operator_id")
        log = logger.get_audit_trail()
        self.assertNotEqual(log[0]["operator_hash"], "sensitive_operator_id")
        self.assertEqual(len(log[0]["operator_hash"]), 24)
    
    def test_get_compliance_summary(self):
        logger = CryptoSecurityAuditLogger()
        logger.log_crypto_event("event1", AuditValidationSeverity.INFO, {})
        logger.log_crypto_event("event2", AuditValidationSeverity.WARNING, {})
        summary = logger.get_compliance_summary()
        self.assertEqual(summary["total_events"], 2)
        self.assertIn("by_severity", summary)
        self.assertIn("by_event_type", summary)
    
    def test_log_size_limit(self):
        logger = CryptoSecurityAuditLogger()
        for i in range(6000):  # More than 5000 limit
            logger.log_crypto_event(f"event_{i}", AuditValidationSeverity.INFO, {})
        log = logger.get_audit_trail(limit=10000)
        self.assertLessEqual(len(log), 5000)


class TestSecureAuditReportGeneratorWrapper(unittest.TestCase):
    """Test SecureAuditReportGeneratorWrapper"""
    
    def test_initialization(self):
        wrapper = SecureAuditReportGeneratorWrapper()
        self.assertIsNotNone(wrapper)
        self.assertIsNotNone(wrapper.validator)
        self.assertIsNotNone(wrapper.rate_limiter)
        self.assertIsNotNone(wrapper.audit_logger)
    
    def test_fips_mode_flag(self):
        wrapper = SecureAuditReportGeneratorWrapper(security_level=CryptoSecurityLevel.FIPS_COMPLIANT)
        self.assertEqual(wrapper.security_level, CryptoSecurityLevel.FIPS_COMPLIANT)
    
    def test_generate_secure_audit_standalone(self):
        wrapper = SecureAuditReportGeneratorWrapper()
        request = {
            "audit_type": "security_audit",
            "compliance_standard": "fips_140_3"
        }
        result = wrapper.generate_secure_audit(request)
        self.assertTrue(result["security_validated"])
        self.assertIn("secure_audit_id", result)
        self.assertIn("fips_mode", result)
    
    def test_generate_secure_audit_validation_error(self):
        wrapper = SecureAuditReportGeneratorWrapper()
        request = {"audit_type": "invalid_type"}
        with self.assertRaises(CryptoSecurityError):
            wrapper.generate_secure_audit(request)
    
    def test_rate_limit_enforced(self):
        config = CryptoRateLimitConfig(max_audits_per_minute=1)
        wrapper = SecureAuditReportGeneratorWrapper(rate_limit_config=config)
        request = {"audit_type": "security_audit"}
        
        wrapper.generate_secure_audit(request, "op1")
        
        with self.assertRaises(CryptoRateLimitExceededError):
            wrapper.generate_secure_audit(request, "op1")
    
    def test_get_security_status(self):
        wrapper = SecureAuditReportGeneratorWrapper()
        status = wrapper.get_security_status()
        self.assertIn("security_level", status)
        self.assertIn("fips_compliant", status)
        self.assertIn("rate_limiter_status", status)
        self.assertIn("audit_summary", status)
        self.assertIn("security_features", status)
        self.assertEqual(status["wrapper_version"], "v17")
    
    def test_with_mock_underlying_generator(self):
        mock_generator = Mock()
        mock_generator.generate_audit_report.return_value = {"audit": "data"}
        
        wrapper = SecureAuditReportGeneratorWrapper(underlying_generator=mock_generator)
        request = {"audit_type": "security_audit"}
        result = wrapper.generate_secure_audit(request)
        
        mock_generator.generate_audit_report.assert_called_once()
        self.assertEqual(result, {"audit": "data"})


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions"""
    
    def test_create_crypto_secure_wrapper(self):
        wrapper = create_crypto_secure_wrapper()
        self.assertIsInstance(wrapper, SecureAuditReportGeneratorWrapper)
    
    def test_create_crypto_secure_wrapper_fips_mode(self):
        wrapper = create_crypto_secure_wrapper(security_level=CryptoSecurityLevel.FIPS_COMPLIANT)
        self.assertEqual(wrapper.security_level, CryptoSecurityLevel.FIPS_COMPLIANT)
    
    def test_crypto_constant_time_compare(self):
        self.assertTrue(crypto_constant_time_compare("abc", "abc"))
        self.assertFalse(crypto_constant_time_compare("abc", "def"))
    
    def test_crypto_zeroize_key_material(self):
        data = bytearray(b"test_key")
        crypto_zeroize_key_material(data)
        self.assertTrue(all(b == 0 for b in data))


class TestVersionInformation(unittest.TestCase):
    """Test version information constants"""
    
    def test_version_constants(self):
        self.assertEqual(CRYPTO_SECURITY_HARDENING_VERSION, "v17")
        self.assertEqual(CRYPTO_SECURITY_HARDENING_BUILD_DATE, "2026-06-24")
        self.assertEqual(CRYPTO_SECURITY_HARDENING_DIMENSION, "B - Security Hardening")


class TestExceptionClasses(unittest.TestCase):
    """Test custom exception classes"""
    
    def test_crypto_security_error(self):
        with self.assertRaises(CryptoSecurityError):
            raise CryptoSecurityError("Crypto security error")
    
    def test_crypto_rate_limit_error(self):
        with self.assertRaises(CryptoRateLimitExceededError):
            raise CryptoRateLimitExceededError("Rate limit exceeded")


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility"""
    
    def test_module_standalone_import(self):
        """Verify module can be imported independently"""
        import quantum_crypt.crypto_security_hardening_audit_report_v17_2026_june as sec
        self.assertIsNotNone(sec)
    
    def test_wrapper_pattern_no_changes(self):
        """Wrapper pattern means existing code needs zero changes"""
        wrapper = SecureAuditReportGeneratorWrapper(underlying_generator=None)
        self.assertIsNotNone(wrapper)
        # Works in standalone mode without any underlying generator


if __name__ == "__main__":
    unittest.main(verbosity=2)
