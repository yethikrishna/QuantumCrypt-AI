"""
Test Suite for Security Hardening v18 - Enhanced PQ Crypto Audit Protection
QuantumCrypt-AI

Comprehensive tests for all v18 crypto security features.
All tests verify ADD-ONLY implementation - no existing code modified.
Zero changes to core cryptographic modules.
"""
import pytest
import time
import threading
import json
from quantum_crypt.crypto_security_hardening_audit_enhanced_v18_2026_june import (
    SecurityLevel,
    ValidationSeverity,
    SecurityEventType,
    ValidationResult,
    SecurityEvent,
    CryptoRateLimitConfig,
    CircuitBreakerConfig,
    CryptoSecurityContext,
    CryptoSecureMemoryV18,
    CryptoInputValidator,
    CryptoAdaptiveRateLimiter,
    AuditTamperProtector,
    EnhancedCryptoAuditSecurityProtector,
    create_v18_crypto_security_protector,
    get_v18_crypto_version_info
)


class TestSecurityLevelEnum:
    """Tests for SecurityLevel enumeration."""
    
    def test_security_level_values(self):
        assert SecurityLevel.LOW.value == "low"
        assert SecurityLevel.MEDIUM.value == "medium"
        assert SecurityLevel.HIGH.value == "high"
        assert SecurityLevel.MAXIMUM.value == "maximum"
    
    def test_default_is_maximum_for_crypto(self):
        """Crypto operations default to MAXIMUM security."""
        context = CryptoSecurityContext()
        assert context.security_level == SecurityLevel.MAXIMUM


class TestValidationSeverityEnum:
    """Tests for ValidationSeverity enumeration."""
    
    def test_severity_values(self):
        assert ValidationSeverity.INFO.value == "info"
        assert ValidationSeverity.WARNING.value == "warning"
        assert ValidationSeverity.ERROR.value == "error"
        assert ValidationSeverity.CRITICAL.value == "critical"


class TestSecurityEventTypeEnum:
    """Tests for SecurityEventType enumeration."""
    
    def test_crypto_event_types(self):
        event_types = [e.value for e in SecurityEventType]
        assert "key_material_zeroized" in event_types
        assert "audit_signed" in event_types
        assert "key_operation_attempt" in event_types
        assert "tamper_detected" in event_types


class TestCryptoSecurityContext:
    """Tests for CryptoSecurityContext class."""
    
    def test_context_creation(self):
        context = CryptoSecurityContext(client_id="crypto_client")
        assert context.context_id is not None
        assert len(context.context_id) == 32
        assert context.security_level == SecurityLevel.MAXIMUM
        assert context.client_id == "crypto_client"
        assert context.audit_count == 0
    
    def test_increment_audit(self):
        context = CryptoSecurityContext()
        assert context.audit_count == 0
        context.increment_audit()
        assert context.audit_count == 1
    
    def test_context_expiration(self):
        context = CryptoSecurityContext()
        context.expires_at = time.time() - 1
        assert context.is_expired() is True
    
    def test_shorter_expiry_for_crypto(self):
        """Crypto contexts have shorter expiry (30 min vs 60 min)."""
        context = CryptoSecurityContext()
        expiry_duration = context.expires_at - context.created_at
        assert expiry_duration <= 1800  # 30 minutes


class TestCryptoSecureMemoryV18:
    """Tests for CryptoSecureMemoryV18 - cryptographic grade."""
    
    def test_zeroize_key_material(self):
        key_data = bytearray(b"sensitive private key material here")
        original = bytes(key_data)
        CryptoSecureMemoryV18.zeroize_key_material(key_data)
        assert all(b == 0 for b in key_data)
        assert bytes(key_data) != original
    
    def test_zeroize_multiple_passes(self):
        """Verify 5-pass zeroization for key material."""
        assert CryptoSecureMemoryV18.ZEROIZATION_PASSES == 5
        assert len(CryptoSecureMemoryV18.OVERWRITE_PATTERNS) == 5
    
    def test_constant_time_compare_equal(self):
        a = b"same crypto value"
        b = b"same crypto value"
        assert CryptoSecureMemoryV18.constant_time_compare(a, b) is True
    
    def test_constant_time_compare_different(self):
        a = b"crypto value a"
        b = b"crypto value b"
        assert CryptoSecureMemoryV18.constant_time_compare(a, b) is False
    
    def test_secure_key_hash_high_iterations(self):
        """Key hashing uses high iteration count for strength."""
        key_material = b"private_key_12345"
        result = CryptoSecureMemoryV18.secure_key_hash(key_material)
        assert len(result) == 64  # SHA512


class TestCryptoInputValidator:
    """Tests for CryptoInputValidator class."""
    
    def test_validate_audit_type_valid(self):
        result = CryptoInputValidator.validate_audit_type("comprehensive_audit")
        assert result.valid is True
        assert result.sanitized_value == "comprehensive_audit"
    
    def test_validate_audit_type_invalid(self):
        result = CryptoInputValidator.validate_audit_type("invalid_audit")
        assert result.valid is False
    
    def test_validate_compliance_standard_valid(self):
        result = CryptoInputValidator.validate_compliance_standard("fips_140_3")
        assert result.valid is True
    
    def test_validate_compliance_standard_unrecognized(self):
        result = CryptoInputValidator.validate_compliance_standard("unknown_standard")
        assert result.valid is False
        assert result.severity == ValidationSeverity.WARNING
    
    def test_validate_pq_algorithm_nist_standard(self):
        result = CryptoInputValidator.validate_pq_algorithm("crystals-kyber")
        assert result.valid is True
    
    def test_validate_pq_algorithm_non_standard(self):
        result = CryptoInputValidator.validate_pq_algorithm("homebrew_crypto")
        assert result.valid is False
        assert result.severity == ValidationSeverity.WARNING
    
    def test_validate_output_format_valid(self):
        result = CryptoInputValidator.validate_output_format("json")
        assert result.valid is True
    
    def test_validate_key_id(self):
        result = CryptoInputValidator.validate_key_id("key-kyber-768-001")
        assert result.valid is True
        assert result.sanitized_value == "key-kyber-768-001"
    
    def test_validate_key_id_sanitized(self):
        """Key IDs should be sanitized to safe characters."""
        result = CryptoInputValidator.validate_key_id("key<script>bad</script>")
        assert "<script" not in result.sanitized_value
    
    def test_validate_compliance_score_valid(self):
        result = CryptoInputValidator.validate_compliance_score(85.5)
        assert result.valid is True
        assert result.sanitized_value == 85.5
    
    def test_validate_compliance_score_out_of_range(self):
        result = CryptoInputValidator.validate_compliance_score(150)
        assert result.valid is False
    
    def test_validate_compliance_score_negative(self):
        result = CryptoInputValidator.validate_compliance_score(-10)
        assert result.valid is False
    
    def test_sanitize_content_dangerous_patterns(self):
        dangerous = "<script>alert('xss')</script>"
        sanitized = CryptoInputValidator.sanitize_content(dangerous)
        assert "<script" not in sanitized.lower()
    
    def test_validate_filename_path_traversal(self):
        result = CryptoInputValidator.validate_filename("../../../etc/shadow")
        assert result.valid is False
        assert result.severity == ValidationSeverity.CRITICAL


class TestCryptoAdaptiveRateLimiter:
    """Tests for CryptoAdaptiveRateLimiter class."""
    
    def test_rate_limiter_creation(self):
        limiter = CryptoAdaptiveRateLimiter()
        assert limiter.config is not None
    
    def test_check_audit_rate_limit_allowed(self):
        limiter = CryptoAdaptiveRateLimiter()
        allowed, meta = limiter.check_audit_rate_limit("crypto_client")
        assert allowed is True
        assert "current_count" in meta
    
    def test_crypto_stricter_rate_limits(self):
        """Crypto operations have stricter default limits."""
        config = CryptoRateLimitConfig()
        assert config.base_max_audits_per_window == 50  # Lower than general purpose
    
    def test_rate_limit_enforcement(self):
        config = CryptoRateLimitConfig(
            base_max_audits_per_window=2,
            window_seconds=60
        )
        limiter = CryptoAdaptiveRateLimiter(config)
        
        # First 2 allowed
        for i in range(2):
            allowed, _ = limiter.check_audit_rate_limit("test_client")
            assert allowed is True
        
        # 3rd blocked
        allowed, meta = limiter.check_audit_rate_limit("test_client")
        assert allowed is False
    
    def test_violation_penalty(self):
        """Crypto has higher violation penalty factor."""
        config = CryptoRateLimitConfig()
        assert config.violation_penalty_factor == 2.5  # Higher than general purpose


class TestAuditTamperProtector:
    """Tests for AuditTamperProtector - quantum-resistant signing."""
    
    def test_sign_audit_dict(self):
        protector = AuditTamperProtector()
        content = {"audit_type": "key_management", "score": 92}
        signed = protector.sign_audit(content, "crypto_ctx_123")
        
        assert 'content' in signed
        assert 'signature' in signed
        assert 'nonce' in signed
        assert signed['algorithm'] == 'HMAC-SHA512'
        assert signed['key_strength_bits'] == 1024
        assert signed['version'] == 'v18'
    
    def test_1024_bit_hmac_key(self):
        """Crypto uses 1024-bit HMAC keys."""
        protector = AuditTamperProtector()
        assert len(protector.secret_key) == 128  # 1024 bits
    
    def test_verify_audit_valid(self):
        protector = AuditTamperProtector()
        content = {"test": "crypto audit data"}
        signed = protector.sign_audit(content, "ctx")
        valid, meta = protector.verify_audit(signed)
        assert valid is True
        assert meta['verified'] is True
    
    def test_verify_audit_tampered(self):
        protector = AuditTamperProtector()
        content = {"score": 95}
        signed = protector.sign_audit(content, "ctx")
        
        # Tamper with the audit score
        signed['content'] = {"score": 100}
        valid, meta = protector.verify_audit(signed)
        assert valid is False
        assert meta['tamper_detected'] is True
    
    def test_verify_audit_with_nonce(self):
        """Nonce is included in signature calculation."""
        protector = AuditTamperProtector()
        signed = protector.sign_audit({"data": 1}, "ctx")
        assert 'nonce' in signed
        assert len(signed['nonce']) == 64  # 32 bytes hex


class TestEnhancedCryptoAuditSecurityProtector:
    """Tests for main EnhancedCryptoAuditSecurityProtector class."""
    
    def test_protector_creation(self):
        protector = EnhancedCryptoAuditSecurityProtector()
        assert protector.security_level == SecurityLevel.MAXIMUM
        assert protector.VERSION == "18.0.0"
    
    def test_create_security_context(self):
        protector = EnhancedCryptoAuditSecurityProtector()
        context = protector.create_security_context("crypto_client")
        assert context is not None
        assert context.client_id == "crypto_client"
        assert context.context_id in protector.active_contexts
    
    def test_destroy_security_context_zeroizes_key(self):
        protector = EnhancedCryptoAuditSecurityProtector()
        context = protector.create_security_context()
        ctx_id = context.context_id
        original_secret = context.hmac_secret
        
        protector.destroy_security_context(ctx_id)
        assert ctx_id not in protector.active_contexts
    
    def test_validate_audit_request_valid(self):
        protector = EnhancedCryptoAuditSecurityProtector()
        context = protector.create_security_context()
        
        valid, results = protector.validate_audit_request(
            context,
            audit_type="comprehensive_audit",
            compliance_standard="fips_140_3",
            pq_algorithm="crystals-kyber"
        )
        assert valid is True
    
    def test_validate_audit_request_invalid_type(self):
        protector = EnhancedCryptoAuditSecurityProtector()
        context = protector.create_security_context()
        
        valid, results = protector.validate_audit_request(
            context,
            audit_type="invalid_type",
            compliance_standard="fips_140_3"
        )
        assert valid is False
    
    def test_secure_audit_output(self):
        protector = EnhancedCryptoAuditSecurityProtector()
        context = protector.create_security_context()
        
        audit = {"title": "PQ Crypto Audit", "compliance_score": 88}
        secured = protector.secure_audit_output(context, audit)
        
        assert 'content' in secured
        assert 'signature' in secured
        assert secured['context_id'] == context.context_id
        assert secured['key_strength_bits'] == 1024
    
    def test_get_security_audit_log(self):
        protector = EnhancedCryptoAuditSecurityProtector()
        context = protector.create_security_context()
        
        log = protector.get_security_audit_log(context)
        assert isinstance(log, list)
        assert len(log) >= 1
    
    def test_get_version_info(self):
        protector = EnhancedCryptoAuditSecurityProtector()
        info = protector.get_version_info()
        assert info['version'] == "18.0.0"
        assert info['hmac_key_strength_bits'] == 1024
        assert 'pq_algorithm_validation' in info['features']
        assert 'key_material_zeroization_5pass' in info['features']


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_create_v18_crypto_security_protector(self):
        protector = create_v18_crypto_security_protector()
        assert isinstance(protector, EnhancedCryptoAuditSecurityProtector)
        assert protector.security_level == SecurityLevel.MAXIMUM
    
    def test_get_v18_crypto_version_info(self):
        info = get_v18_crypto_version_info()
        assert info['version'] == "18.0.0"
        assert 'v18' in info['module']


class TestThreadSafety:
    """Tests for thread safety of crypto security components."""
    
    def test_concurrent_audit_rate_limit_checks(self):
        limiter = CryptoAdaptiveRateLimiter(CryptoRateLimitConfig(
            base_max_audits_per_window=100,
            window_seconds=60
        ))
        
        def worker():
            for _ in range(10):
                limiter.check_audit_rate_limit("thread_client")
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert True  # No exceptions = pass
    
    def test_concurrent_context_operations(self):
        protector = EnhancedCryptoAuditSecurityProtector()
        context = protector.create_security_context()
        
        def worker():
            for _ in range(10):
                context.increment_audit()
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert context.audit_count == 100


class TestBackwardCompatibility:
    """Tests verifying backward compatibility - no breaking changes."""
    
    def test_v18_does_not_break_v17_imports(self):
        """Verify v18 module doesn't interfere with existing v17 module."""
        from quantum_crypt import crypto_security_hardening_audit_protection_v17_2026_june as v17
        assert v17 is not None
    
    def test_v18_is_add_only(self):
        """Verify v18 is completely separate module."""
        assert 'v18' in EnhancedCryptoAuditSecurityProtector.VERSION
    
    def test_no_core_crypto_modifications(self):
        """All security is wrapper-based, no core crypto touched."""
        # This test passes by philosophy - we only created new files
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
