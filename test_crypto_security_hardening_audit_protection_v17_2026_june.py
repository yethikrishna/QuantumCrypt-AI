"""
Tests for Security Hardening v17 - PQ Crypto Audit Protection Module
QuantumCrypt-AI

Covers all security features:
- Cryptographic input validation and sanitization
- Rate limiting and DoS protection
- FIPS 140-3 compliant secure memory handling
- Constant-time comparison helpers
- Security context isolation
- Audit trail logging
"""

import unittest
import threading
import time
from typing import Any

# Import crypto security module
from quantum_crypt.crypto_security_hardening_audit_protection_v17_2026_june import (
    CryptoSecurityLevel,
    AuditValidationSeverity,
    AuditValidationResult,
    CryptoRateLimitConfig,
    AuditSecurityContext,
    CryptoSecureMemory,
    AuditInputValidator,
    CryptoRateLimiter,
    CryptoAuditSecurityProtector,
    get_default_crypto_protector,
    secure_generate_audit_report,
    crypto_constant_time_compare,
    crypto_secure_zeroize,
    VERSION,
    VERSION_INFO,
    get_version,
    get_version_info
)


class TestCryptoSecurityLevelEnum(unittest.TestCase):
    """Test CryptoSecurityLevel enumeration."""
    
    def test_security_level_values(self):
        """Test all security levels have correct values."""
        self.assertEqual(CryptoSecurityLevel.BASIC.value, "basic")
        self.assertEqual(CryptoSecurityLevel.STANDARD.value, "standard")
        self.assertEqual(CryptoSecurityLevel.ENHANCED.value, "enhanced")
        self.assertEqual(CryptoSecurityLevel.FIPS_140_3.value, "fips_140_3")
    
    def test_security_level_count(self):
        """Test correct number of security levels."""
        self.assertEqual(len(list(CryptoSecurityLevel)), 4)


class TestAuditValidationSeverityEnum(unittest.TestCase):
    """Test AuditValidationSeverity enumeration."""
    
    def test_severity_values(self):
        """Test all severity levels have correct values."""
        self.assertEqual(AuditValidationSeverity.INFO.value, "info")
        self.assertEqual(AuditValidationSeverity.WARNING.value, "warning")
        self.assertEqual(AuditValidationSeverity.ERROR.value, "error")
        self.assertEqual(AuditValidationSeverity.CRITICAL.value, "critical")
        self.assertEqual(AuditValidationSeverity.FIPS_VIOLATION.value, "fips_violation")
    
    def test_severity_count(self):
        """Test correct number of severity levels."""
        self.assertEqual(len(list(AuditValidationSeverity)), 5)


class TestAuditValidationResult(unittest.TestCase):
    """Test AuditValidationResult dataclass."""
    
    def test_validation_result_creation(self):
        """Test creating validation result with all fields."""
        result = AuditValidationResult(
            valid=True,
            severity=AuditValidationSeverity.INFO,
            message="Test message",
            field="test_field",
            sanitized_value="clean_value",
            fips_compliant=True
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.severity, AuditValidationSeverity.INFO)
        self.assertEqual(result.message, "Test message")
        self.assertEqual(result.field, "test_field")
        self.assertEqual(result.sanitized_value, "clean_value")
        self.assertTrue(result.fips_compliant)
    
    def test_validation_result_defaults(self):
        """Test default values work correctly."""
        result = AuditValidationResult(valid=False)
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, AuditValidationSeverity.INFO)
        self.assertEqual(result.message, "")
        self.assertEqual(result.field, "")
        self.assertIsNone(result.sanitized_value)
        self.assertTrue(result.fips_compliant)


class TestCryptoRateLimitConfig(unittest.TestCase):
    """Test CryptoRateLimitConfig dataclass."""
    
    def test_default_config(self):
        """Test default rate limit configuration."""
        config = CryptoRateLimitConfig()
        self.assertEqual(config.max_audits_per_window, 50)
        self.assertEqual(config.window_seconds, 60)
        self.assertEqual(config.max_audit_report_size_bytes, 50 * 1024 * 1024)
        self.assertEqual(config.max_checks_per_audit, 200)
        self.assertEqual(config.max_keys_per_audit, 100)
        self.assertEqual(config.max_concurrent_sessions, 10)
    
    def test_custom_config(self):
        """Test custom rate limit configuration."""
        config = CryptoRateLimitConfig(
            max_audits_per_window=25,
            window_seconds=30,
            max_concurrent_sessions=5
        )
        self.assertEqual(config.max_audits_per_window, 25)
        self.assertEqual(config.window_seconds, 30)
        self.assertEqual(config.max_concurrent_sessions, 5)


class TestAuditSecurityContext(unittest.TestCase):
    """Test AuditSecurityContext isolation."""
    
    def test_context_creation(self):
        """Test security context creation with defaults."""
        context = AuditSecurityContext()
        self.assertIsNotNone(context.context_id)
        self.assertEqual(context.security_level, CryptoSecurityLevel.STANDARD)
        self.assertEqual(context.audit_count, 0)
        self.assertEqual(context.validation_failures, [])
        self.assertEqual(context.audit_trail, [])
    
    def test_context_custom_level(self):
        """Test security context with custom security level."""
        context = AuditSecurityContext(security_level=CryptoSecurityLevel.FIPS_140_3)
        self.assertEqual(context.security_level, CryptoSecurityLevel.FIPS_140_3)
    
    def test_increment_audit_threadsafe(self):
        """Test audit counter is thread-safe."""
        context = AuditSecurityContext()
        
        def increment_many(n: int):
            for _ in range(n):
                context.increment_audit()
        
        threads = [threading.Thread(target=increment_many, args=(100,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(context.audit_count, 1000)
    
    def test_add_audit_entry(self):
        """Test adding entries to audit trail."""
        context = AuditSecurityContext()
        context.add_audit_entry({'operation': 'test', 'status': 'success'})
        self.assertEqual(len(context.audit_trail), 1)
        self.assertIn('timestamp', context.audit_trail[0])
        self.assertIn('context_id', context.audit_trail[0])
        self.assertEqual(context.audit_trail[0]['operation'], 'test')


class TestCryptoSecureMemory(unittest.TestCase):
    """Test CryptoSecureMemory FIPS-compliant utilities."""
    
    def test_zeroize_bytearray_multipass(self):
        """Test FIPS-compliant multi-pass bytearray zeroization."""
        data = bytearray(b'sensitive cryptographic key material')
        original = bytes(data)
        CryptoSecureMemory.zeroize_bytearray(data)
        self.assertEqual(data, bytearray(len(original)))
        self.assertEqual(all(b == 0 for b in data), True)
    
    def test_constant_time_bytes_compare_equal(self):
        """Test constant-time compare with equal bytes."""
        a = b'cryptographic hash value'
        b = b'cryptographic hash value'
        self.assertTrue(CryptoSecureMemory.constant_time_bytes_compare(a, b))
    
    def test_constant_time_bytes_compare_different(self):
        """Test constant-time compare with different bytes."""
        a = b'cryptographic hash value'
        b = b'cryptographic different value'
        self.assertFalse(CryptoSecureMemory.constant_time_bytes_compare(a, b))
    
    def test_constant_time_hex_compare_equal(self):
        """Test constant-time hex compare with equal fingerprints."""
        self.assertTrue(CryptoSecureMemory.constant_time_hex_compare(
            "A1B2C3D4", "a1b2c3d4"
        ))
        self.assertTrue(CryptoSecureMemory.constant_time_hex_compare(
            "abcdef", "ABCDEF"
        ))
    
    def test_constant_time_hex_compare_different(self):
        """Test constant-time hex compare with different fingerprints."""
        self.assertFalse(CryptoSecureMemory.constant_time_hex_compare(
            "A1B2C3D4", "A1B2C3D5"
        ))
        self.assertFalse(CryptoSecureMemory.constant_time_hex_compare(
            "abcd", "abcde"
        ))
    
    def test_secure_key_hash(self):
        """Test secure key hash generation."""
        key = b'test private key material'
        result = CryptoSecureMemory.secure_key_hash(key)
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 64)  # SHA-512 PBKDF2 output
    
    def test_fips_random_bytes(self):
        """Test FIPS-approved random byte generation."""
        result = CryptoSecureMemory.fips_approved_random_bytes(32)
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 32)
        # Verify it's not all zeros (extremely unlikely for true random)
        self.assertFalse(all(b == 0 for b in result))


class TestAuditInputValidator(unittest.TestCase):
    """Test AuditInputValidator class."""
    
    def test_validate_audit_type_valid(self):
        """Test valid audit types pass validation."""
        valid_types = [
            'key_management', 'algorithm_compliance', 'security_audit',
            'performance_benchmark', 'comprehensive_audit', 'regulatory_compliance'
        ]
        for audit_type in valid_types:
            result = AuditInputValidator.validate_audit_type(audit_type)
            self.assertTrue(result.valid, f"Failed for {audit_type}")
    
    def test_validate_audit_type_invalid(self):
        """Test invalid audit types are rejected."""
        result = AuditInputValidator.validate_audit_type('invalid_audit')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, AuditValidationSeverity.ERROR)
    
    def test_validate_compliance_standard_valid(self):
        """Test valid compliance standards pass validation."""
        standards = [
            'nist_sp_800_186', 'nist_sp_800_56c', 'fips_140_3',
            'cnsa_2.0', 'etsi_ts_103_675', 'gdpr'
        ]
        for standard in standards:
            result = AuditInputValidator.validate_compliance_standard(standard)
            self.assertTrue(result.valid, f"Failed for {standard}")
    
    def test_validate_pq_algorithm_nist_approved(self):
        """Test NIST-approved PQ algorithms pass validation."""
        approved = [
            'crystals-kyber', 'crystals-dilithium', 'falcon', 'sphincs+',
            'kyber768', 'dilithium3'
        ]
        for algo in approved:
            result = AuditInputValidator.validate_pq_algorithm(algo)
            self.assertTrue(result.valid, f"Failed for {algo}")
            self.assertTrue(result.fips_compliant)
    
    def test_validate_pq_algorithm_fips_violation(self):
        """Test non-FIPS algorithms trigger FIPS violation."""
        result = AuditInputValidator.validate_pq_algorithm('md5')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, AuditValidationSeverity.FIPS_VIOLATION)
        self.assertFalse(result.fips_compliant)
    
    def test_validate_pq_algorithm_non_standard_warning(self):
        """Test non-standard (but not forbidden) algorithms get warning."""
        result = AuditInputValidator.validate_pq_algorithm('custom_algo')
        self.assertTrue(result.valid)  # Still allowed
        self.assertEqual(result.severity, AuditValidationSeverity.WARNING)
        self.assertFalse(result.fips_compliant)
    
    def test_validate_output_format_valid(self):
        """Test valid output formats pass validation."""
        for fmt in ['json', 'markdown', 'html', 'csv', 'pdf']:
            result = AuditInputValidator.validate_output_format(fmt)
            self.assertTrue(result.valid, f"Failed for {fmt}")
    
    def test_validate_output_format_invalid(self):
        """Test invalid output formats are rejected."""
        result = AuditInputValidator.validate_output_format('exe')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, AuditValidationSeverity.ERROR)
    
    def test_validate_key_fingerprint_valid_hex(self):
        """Test valid hex fingerprints pass validation."""
        result = AuditInputValidator.validate_key_fingerprint('A1B2C3D4E5F6')
        self.assertTrue(result.valid)
    
    def test_validate_key_fingerprint_invalid_hex(self):
        """Test invalid hex fingerprints get warning."""
        result = AuditInputValidator.validate_key_fingerprint('not hex!')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, AuditValidationSeverity.WARNING)
    
    def test_validate_filename_path_traversal_blocked(self):
        """Test path traversal attempts are blocked."""
        result = AuditInputValidator.validate_filename('../../../etc/shadow')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, AuditValidationSeverity.CRITICAL)
    
    def test_validate_key_id_valid(self):
        """Test valid key IDs pass validation."""
        result = AuditInputValidator.validate_key_id('key-12345-abcde')
        self.assertTrue(result.valid)
    
    def test_validate_key_id_empty(self):
        """Test empty key IDs are rejected."""
        result = AuditInputValidator.validate_key_id('')
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, AuditValidationSeverity.ERROR)
    
    def test_validate_check_count_valid(self):
        """Test valid check counts pass validation."""
        result = AuditInputValidator.validate_check_count(50)
        self.assertTrue(result.valid)
        self.assertEqual(result.sanitized_value, 50)
    
    def test_validate_check_count_negative(self):
        """Test negative check counts are rejected."""
        result = AuditInputValidator.validate_check_count(-1)
        self.assertFalse(result.valid)
        self.assertEqual(result.severity, AuditValidationSeverity.ERROR)


class TestCryptoRateLimiter(unittest.TestCase):
    """Test CryptoRateLimiter class."""
    
    def test_audit_rate_limit_allows_initial(self):
        """Test initial audit requests are allowed."""
        limiter = CryptoRateLimiter(CryptoRateLimitConfig(max_audits_per_window=5))
        for i in range(5):
            allowed, info = limiter.check_audit_rate_limit()
            self.assertTrue(allowed, f"Audit {i+1} should be allowed")
    
    def test_audit_rate_limit_blocks_excess(self):
        """Test audits exceeding limit are blocked."""
        limiter = CryptoRateLimiter(CryptoRateLimitConfig(max_audits_per_window=3))
        for _ in range(3):
            limiter.check_audit_rate_limit()
        allowed, info = limiter.check_audit_rate_limit()
        self.assertFalse(allowed)
        self.assertEqual(info['reason'], 'global_audit_rate_limit_exceeded')
    
    def test_concurrent_session_limit(self):
        """Test concurrent session limit is enforced."""
        limiter = CryptoRateLimiter(CryptoRateLimitConfig(max_concurrent_sessions=2))
        # Open 2 sessions
        limiter.check_audit_rate_limit("session1")
        limiter.check_audit_rate_limit("session2")
        # 3rd session should be blocked
        allowed, info = limiter.check_audit_rate_limit("session3")
        self.assertFalse(allowed)
        self.assertEqual(info['reason'], 'concurrent_session_limit_exceeded')
    
    def test_release_session_frees_slot(self):
        """Test releasing session frees up slot."""
        limiter = CryptoRateLimiter(CryptoRateLimitConfig(max_concurrent_sessions=1))
        limiter.check_audit_rate_limit("session1")
        limiter.release_session("session1")
        # New session should be allowed
        allowed, _ = limiter.check_audit_rate_limit("session2")
        self.assertTrue(allowed)
    
    def test_audit_size_check_valid(self):
        """Test audits within size limit pass."""
        limiter = CryptoRateLimiter()
        allowed, info = limiter.check_audit_size(1024 * 1024)  # 1MB
        self.assertTrue(allowed)
    
    def test_audit_size_check_exceeded(self):
        """Test oversized audits are blocked."""
        limiter = CryptoRateLimiter()
        allowed, info = limiter.check_audit_size(100 * 1024 * 1024)  # 100MB
        self.assertFalse(allowed)
        self.assertEqual(info['reason'], 'audit_report_size_exceeded')
    
    def test_check_count_limit(self):
        """Test excessive check counts are blocked."""
        limiter = CryptoRateLimiter()
        allowed, info = limiter.check_check_count(1000)
        self.assertFalse(allowed)
        self.assertEqual(info['reason'], 'audit_check_count_exceeded')


class TestCryptoAuditSecurityProtector(unittest.TestCase):
    """Test main CryptoAuditSecurityProtector class."""
    
    def setUp(self):
        """Set up test protector."""
        self.protector = CryptoAuditSecurityProtector(
            security_level=CryptoSecurityLevel.STANDARD
        )
    
    def test_create_security_context(self):
        """Test creating security context."""
        context = self.protector.create_security_context()
        self.assertIsNotNone(context.context_id)
        self.assertEqual(context.security_level, CryptoSecurityLevel.STANDARD)
        self.assertIn(context.context_id, self.protector.active_contexts)
    
    def test_release_context(self):
        """Test releasing security context."""
        context = self.protector.create_security_context()
        context_id = context.context_id
        self.protector.release_context(context_id)
        self.assertNotIn(context_id, self.protector.active_contexts)
    
    def test_secure_audit_generation_success(self):
        """Test successful secure audit generation."""
        def mock_auditor(audit_type: str) -> str:
            return f"Audit report for {audit_type}"
        
        success, result, metadata = self.protector.secure_audit_generation(
            mock_auditor,
            audit_type='comprehensive_audit'
        )
        
        self.assertTrue(success)
        self.assertEqual(result, "Audit report for comprehensive_audit")
        self.assertTrue(metadata['success'])
        self.assertIn('context_id', metadata)
        self.assertIn('execution_time', metadata)
    
    def test_secure_audit_generation_validation_block(self):
        """Test validation failure blocks audit generation."""
        def mock_auditor(audit_type: str) -> str:
            return f"Audit report for {audit_type}"
        
        success, result, metadata = self.protector.secure_audit_generation(
            mock_auditor,
            audit_type='invalid_type'
        )
        
        self.assertFalse(success)
        self.assertIsNone(result)
        self.assertEqual(metadata['blocked_reason'], 'validation_failure')
    
    def test_secure_audit_generation_fips_mode(self):
        """Test FIPS 140-3 mode security level."""
        protector = CryptoAuditSecurityProtector(
            security_level=CryptoSecurityLevel.FIPS_140_3
        )
        
        def mock_auditor(audit_type: str) -> str:
            return f"FIPS audit: {audit_type}"
        
        success, result, metadata = protector.secure_audit_generation(
            mock_auditor,
            audit_type='security_audit'
        )
        
        self.assertTrue(success)
        self.assertTrue(metadata['fips_mode'])
    
    def test_secure_audit_generation_fips_violation_blocked(self):
        """Test FIPS violations block generation in FIPS mode."""
        protector = CryptoAuditSecurityProtector(
            security_level=CryptoSecurityLevel.FIPS_140_3
        )
        
        def mock_auditor(algorithm: str) -> str:
            return f"Algorithm: {algorithm}"
        
        # MD5 is a FIPS violation
        success, result, metadata = protector.secure_audit_generation(
            mock_auditor,
            algorithm='md5'
        )
        
        self.assertFalse(success)
        self.assertIsNone(result)
        self.assertEqual(metadata['blocked_reason'], 'validation_failure')
    
    def test_secure_audit_generation_path_traversal_blocked(self):
        """Test path traversal in filename is blocked."""
        def mock_auditor(filename: str) -> str:
            return f"Audit saved to {filename}"
        
        success, result, metadata = self.protector.secure_audit_generation(
            mock_auditor,
            filename='../../../etc/passwd'
        )
        
        self.assertFalse(success)
        self.assertIsNone(result)
        self.assertEqual(metadata['blocked_reason'], 'validation_failure')
    
    def test_secure_audit_generation_exception_handling(self):
        """Test exceptions in wrapped function are handled."""
        def failing_auditor() -> str:
            raise ValueError("Auditor failed")
        
        success, result, metadata = self.protector.secure_audit_generation(failing_auditor)
        
        self.assertFalse(success)
        self.assertIsNone(result)
        self.assertIn('error', metadata)
        self.assertEqual(metadata['error'], "Auditor failed")
    
    def test_get_security_stats(self):
        """Test getting security statistics."""
        for _ in range(3):
            self.protector.create_security_context()
        
        stats = self.protector.get_security_stats()
        self.assertEqual(stats['active_contexts'], 3)
        self.assertEqual(stats['security_level'], 'standard')
        self.assertFalse(stats['fips_140_3_mode'])
        self.assertIn('rate_limit_config', stats)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience wrapper functions."""
    
    def test_get_default_crypto_protector(self):
        """Test default protector singleton."""
        p1 = get_default_crypto_protector()
        p2 = get_default_crypto_protector()
        self.assertIs(p1, p2)
    
    def test_secure_generate_audit_report_wrapper(self):
        """Test convenience secure_generate_audit_report function."""
        def mock_func(audit_type: str) -> str:
            return f"Audit: {audit_type}"
        
        success, result, metadata = secure_generate_audit_report(
            mock_func,
            audit_type='comprehensive_audit',
            security_level=CryptoSecurityLevel.ENHANCED
        )
        
        self.assertTrue(success)
        self.assertEqual(result, "Audit: comprehensive_audit")
        self.assertEqual(metadata['security_level'], 'enhanced')
    
    def test_crypto_constant_time_compare(self):
        """Test crypto_constant_time_compare convenience function."""
        self.assertTrue(crypto_constant_time_compare(b"test", b"test"))
        self.assertFalse(crypto_constant_time_compare(b"test", b"different"))
    
    def test_crypto_secure_zeroize(self):
        """Test crypto_secure_zeroize convenience function."""
        data = bytearray(b'cryptographic secret')
        crypto_secure_zeroize(data)
        self.assertEqual(data, bytearray(len(b'cryptographic secret')))


class TestVersionInformation(unittest.TestCase):
    """Test module version information."""
    
    def test_version_format(self):
        """Test version string format."""
        self.assertEqual(VERSION, "1.7.0")
    
    def test_version_info_structure(self):
        """Test version info structure."""
        info = get_version_info()
        self.assertEqual(info['major'], 1)
        self.assertEqual(info['minor'], 7)
        self.assertEqual(info['patch'], 0)
        self.assertEqual(info['dimension'], 'B')
        self.assertEqual(info['dimension_version'], 17)
        self.assertEqual(info['release_date'], '2026-06-24')
        self.assertTrue(info['fips_140_3_ready'])
    
    def test_get_version_function(self):
        """Test get_version returns correct string."""
        self.assertEqual(get_version(), "1.7.0")


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - no breaking changes."""
    
    def test_module_imports_without_errors(self):
        """Test module can be imported without errors."""
        import quantum_crypt.crypto_security_hardening_audit_protection_v17_2026_june as module
        self.assertIsNotNone(module)
    
    def test_all_public_apis_exist(self):
        """Test all expected public APIs are available."""
        import quantum_crypt.crypto_security_hardening_audit_protection_v17_2026_june as module
        
        # Classes
        self.assertTrue(hasattr(module, 'CryptoSecurityLevel'))
        self.assertTrue(hasattr(module, 'CryptoSecureMemory'))
        self.assertTrue(hasattr(module, 'AuditInputValidator'))
        self.assertTrue(hasattr(module, 'CryptoRateLimiter'))
        self.assertTrue(hasattr(module, 'CryptoAuditSecurityProtector'))
        
        # Functions
        self.assertTrue(hasattr(module, 'get_default_crypto_protector'))
        self.assertTrue(hasattr(module, 'secure_generate_audit_report'))
        self.assertTrue(hasattr(module, 'get_version'))
        self.assertTrue(hasattr(module, 'get_version_info'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
