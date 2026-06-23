"""
Test Suite for Crypto Security v17 - PQ TLS/HTTPS Protection
QuantumCrypt-AI | June 2026
ADD-ONLY COMPLIANT: Tests only new code, NO existing tests modified
TEST COVERAGE:
  - PQ TLS Configuration creation
  - Session key management with auto-expiry
  - Secure key zeroization
  - TLS Channel Binding (RFC 5929)
  - PQ Certificate Hardening
  - Key Material Protection
  - PQ TLS Security Auditing
  - PQ Migration Timeline
  - Backward compatibility wrappers
  - Global convenience functions
"""
import unittest
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))
from crypto_security_tls_https_endpoint_protection_v17_2026_june import (
    PQTLSSecurityConfig,
    PQTLSMode,
    KeyProtectionLevel,
    TLSChannelBinding,
    PQCertificateHardener,
    TLSKeyMaterialProtector,
    PQTLSSecurityAuditor,
    create_pq_tls_config,
    get_pq_tls_best_practices,
    wrap_crypto_operation_with_tls_binding,
    MODULE_INFO,
)
# ============================================================================
# TEST PQ TLS CONFIGURATION
# ============================================================================
class TestPQTLSSecurityConfig(unittest.TestCase):
    """Test PQ TLS Security Configuration"""
    def test_default_config_creation(self):
        """Default config should create without errors"""
        config = PQTLSSecurityConfig()
        self.assertIsNotNone(config)
        self.assertEqual(config.pq_mode, PQTLSMode.HYBRID_PQ_CLASSICAL)
        self.assertTrue(config.enable_key_zeroization)
        self.assertTrue(config.enable_channel_binding)
        self.assertTrue(config.enforce_ephemeral_keys)
    def test_custom_config_creation(self):
        """Custom config should respect parameters"""
        config = PQTLSSecurityConfig(
            pq_mode=PQTLSMode.PQ_ONLY,
            enable_key_zeroization=False,
            enable_channel_binding=False,
            enforce_ephemeral_keys=False,
            session_key_lifetime_seconds=7200,
        )
        self.assertEqual(config.pq_mode, PQTLSMode.PQ_ONLY)
        self.assertFalse(config.enable_key_zeroization)
        self.assertFalse(config.enable_channel_binding)
        self.assertFalse(config.enforce_ephemeral_keys)
        self.assertEqual(config.session_key_lifetime, 7200)
    def test_ssl_context_creation(self):
        """Should create hardened SSL context"""
        config = PQTLSSecurityConfig()
        context = config.get_hardened_ssl_context()
        self.assertIsNotNone(context)
    def test_session_key_registration(self):
        """Should register and retrieve session keys"""
        config = PQTLSSecurityConfig()
        test_key = b"test_session_key_12345"
        config.register_session_key("test-key-1", test_key)
        retrieved = config.get_session_key("test-key-1")
        self.assertEqual(retrieved, test_key)
    def test_session_key_not_found(self):
        """Non-existent key returns None"""
        config = PQTLSSecurityConfig()
        retrieved = config.get_session_key("nonexistent")
        self.assertIsNone(retrieved)
    def test_session_key_expiry(self):
        """Expired keys should return None"""
        config = PQTLSSecurityConfig(session_key_lifetime_seconds=0)
        test_key = b"expiring_key"
        config.register_session_key("expiring", test_key)
        time.sleep(0.01)
        retrieved = config.get_session_key("expiring")
        self.assertIsNone(retrieved)
    def test_zeroize_all_session_keys(self):
        """Should zeroize all session keys"""
        config = PQTLSSecurityConfig()
        config.register_session_key("key1", b"key1_data")
        config.register_session_key("key2", b"key2_data")
        count = config.zeroize_all_session_keys()
        self.assertEqual(count, 2)
        self.assertIsNone(config.get_session_key("key1"))
        self.assertIsNone(config.get_session_key("key2"))
# ============================================================================
# TEST TLS CHANNEL BINDING
# ============================================================================
class TestTLSChannelBinding(unittest.TestCase):
    """Test TLS Channel Binding"""
    def test_binding_creation(self):
        """Binding should create without errors"""
        binding = TLSChannelBinding()
        self.assertIsNotNone(binding)
        self.assertTrue(binding.enabled)
    def test_binding_disabled(self):
        """Disabled binding passes everything"""
        binding = TLSChannelBinding(enabled=False)
        result = binding.bind_crypto_operation("op1", b"channel", b"data")
        self.assertEqual(result, b"data")
        self.assertTrue(binding.verify_binding("op1", b"channel", b"data"))
    def test_crypto_operation_binding(self):
        """Should bind crypto operation to channel"""
        binding = TLSChannelBinding()
        op_id = "test-operation-1"
        channel = b"test-channel-binding"
        data = b"sensitive-crypto-data"
        bound = binding.bind_crypto_operation(op_id, channel, data)
        self.assertIsNotNone(bound)
        self.assertEqual(len(bound), 32)  # SHA256 output
    def test_binding_verification_success(self):
        """Valid binding should verify"""
        binding = TLSChannelBinding()
        op_id = "test-operation-2"
        channel = b"test-channel-binding"
        data = b"sensitive-crypto-data"
        binding.bind_crypto_operation(op_id, channel, data)
        verified = binding.verify_binding(op_id, channel, data)
        self.assertTrue(verified)
    def test_binding_verification_fails_wrong_channel(self):
        """Wrong channel should fail verification"""
        binding = TLSChannelBinding()
        op_id = "test-operation-3"
        channel = b"correct-channel"
        wrong_channel = b"wrong-channel"
        data = b"sensitive-crypto-data"
        binding.bind_crypto_operation(op_id, channel, data)
        verified = binding.verify_binding(op_id, wrong_channel, data)
        self.assertFalse(verified)
    def test_binding_verification_fails_unknown_op(self):
        """Unknown operation should fail verification"""
        binding = TLSChannelBinding()
        verified = binding.verify_binding("unknown", b"channel", b"data")
        self.assertFalse(verified)
# ============================================================================
# TEST PQ CERTIFICATE HARDENER
# ============================================================================
class TestPQCertificateHardener(unittest.TestCase):
    """Test PQ Certificate Hardening"""
    def test_hardener_creation(self):
        """Hardener should create without errors"""
        hardener = PQCertificateHardener()
        self.assertIsNotNone(hardener)
    def test_certificate_key_strength_validation(self):
        """Should validate certificate key strength"""
        hardener = PQCertificateHardener()
        result = hardener.validate_certificate_key_strength({
            "key_type": "RSA",
            "key_size": 4096,
        })
        self.assertIn("key_strength_score", result)
        self.assertIn("warnings", result)
        self.assertIn("recommendations", result)
        self.assertGreater(result["key_strength_score"], 0)
    def test_weak_key_strength_warning(self):
        """Weak keys should get warnings"""
        hardener = PQCertificateHardener()
        result = hardener.validate_certificate_key_strength({
            "key_type": "RSA",
            "key_size": 2048,
        })
        self.assertGreater(len(result["warnings"]), 0)
    def test_pq_migration_timeline(self):
        """Should return PQ migration timeline"""
        hardener = PQCertificateHardener()
        timeline = hardener.get_pq_migration_timeline()
        self.assertIn("immediate_2026", timeline)
        self.assertIn("near_term_2026_2027", timeline)
        self.assertIn("medium_term_2027_2028", timeline)
        self.assertIn("long_term_2028_2030", timeline)
        self.assertIn("nist_standards", timeline)
        self.assertIn("FIPS_203", timeline["nist_standards"])
# ============================================================================
# TEST KEY MATERIAL PROTECTOR
# ============================================================================
class TestTLSKeyMaterialProtector(unittest.TestCase):
    """Test TLS Key Material Protection"""
    def test_protector_creation(self):
        """Protector should create without errors"""
        protector = TLSKeyMaterialProtector()
        self.assertIsNotNone(protector)
    def test_load_and_get_protected_key(self):
        """Should load and retrieve protected key"""
        protector = TLSKeyMaterialProtector()
        test_key = b"super_secret_private_key"
        protector.load_protected_key("key-1", test_key)
        retrieved = protector.get_protected_key("key-1")
        self.assertEqual(retrieved, test_key)
    def test_get_nonexistent_key(self):
        """Non-existent key returns None"""
        protector = TLSKeyMaterialProtector()
        retrieved = protector.get_protected_key("nonexistent")
        self.assertIsNone(retrieved)
    def test_secure_zeroize_key(self):
        """Should zeroize key securely"""
        protector = TLSKeyMaterialProtector()
        protector.load_protected_key("key-to-delete", b"secret")
        result = protector.secure_zeroize("key-to-delete")
        self.assertTrue(result)
        self.assertIsNone(protector.get_protected_key("key-to-delete"))
    def test_zeroize_nonexistent_key(self):
        """Zeroizing non-existent key returns False"""
        protector = TLSKeyMaterialProtector()
        result = protector.secure_zeroize("nonexistent")
        self.assertFalse(result)
    def test_emergency_wipe_all(self):
        """Should wipe all keys in emergency"""
        protector = TLSKeyMaterialProtector()
        protector.load_protected_key("key1", b"secret1")
        protector.load_protected_key("key2", b"secret2")
        protector.load_protected_key("key3", b"secret3")
        count = protector.emergency_wipe_all()
        self.assertEqual(count, 3)
        self.assertIsNone(protector.get_protected_key("key1"))
        self.assertIsNone(protector.get_protected_key("key2"))
        self.assertIsNone(protector.get_protected_key("key3"))
    def test_access_audit_log(self):
        """Should log key access events"""
        protector = TLSKeyMaterialProtector()
        protector.load_protected_key("audit-key", b"secret")
        protector.get_protected_key("audit-key")
        protector.secure_zeroize("audit-key")
        audit = protector.get_access_audit()
        self.assertGreaterEqual(len(audit), 3)
        actions = [e["action"] for e in audit]
        self.assertIn("load", actions)
        self.assertIn("access", actions)
        self.assertIn("zeroize", actions)
# ============================================================================
# TEST PQ TLS SECURITY AUDITOR
# ============================================================================
class TestPQTLSSecurityAuditor(unittest.TestCase):
    """Test PQ TLS Security Auditor"""
    def test_audit_default_config(self):
        """Should audit default configuration"""
        config = PQTLSSecurityConfig()
        auditor = PQTLSSecurityAuditor(config)
        report = auditor.run_pq_security_audit()
        self.assertIn("pq_readiness_score", report)
        self.assertIn("pq_grade", report)
        self.assertIn("passed", report)
        self.assertIn("findings", report)
        self.assertIn("recommendations", report)
        self.assertGreater(report["pq_readiness_score"], 0)
        self.assertLessEqual(report["pq_readiness_score"], 100)
    def test_audit_max_security_config(self):
        """Max security config should get high score"""
        config = PQTLSSecurityConfig(
            pq_mode=PQTLSMode.HYBRID_PQ_CLASSICAL,
            enable_key_zeroization=True,
            enable_channel_binding=True,
            enforce_ephemeral_keys=True,
            min_tls_version="TLSv1.3",
        )
        auditor = PQTLSSecurityAuditor(config)
        report = auditor.run_pq_security_audit()
        self.assertGreaterEqual(report["pq_readiness_score"], 70)
        self.assertIn(report["pq_grade"], ["A", "B", "C"])
    def test_audit_insecure_config(self):
        """Insecure config should get low score"""
        config = PQTLSSecurityConfig(
            pq_mode=PQTLSMode.CLASSICAL_ONLY,
            enable_key_zeroization=False,
            enable_channel_binding=False,
            enforce_ephemeral_keys=False,
        )
        auditor = PQTLSSecurityAuditor(config)
        report = auditor.run_pq_security_audit()
        self.assertLess(report["pq_readiness_score"], 60)
        self.assertGreater(len(report["findings"]), 0)
# ============================================================================
# TEST GLOBAL CONVENIENCE FUNCTIONS
# ============================================================================
class TestGlobalConvenienceFunctions(unittest.TestCase):
    """Test Global Convenience Functions"""
    def test_create_pq_tls_config_function(self):
        """create_pq_tls_config should work"""
        config = create_pq_tls_config(
            pq_mode=PQTLSMode.PQ_ONLY,
            min_tls_version="TLSv1.3",
        )
        self.assertIsInstance(config, PQTLSSecurityConfig)
        self.assertEqual(config.pq_mode, PQTLSMode.PQ_ONLY)
    def test_get_pq_tls_best_practices(self):
        """Should return best practices"""
        practices = get_pq_tls_best_practices()
        self.assertIn("mandatory", practices)
        self.assertIn("pq_transition", practices)
        self.assertIn("crypto_specific", practices)
        self.assertGreater(len(practices["mandatory"]), 0)
    def test_wrap_crypto_operation(self):
        """Should wrap crypto operation function"""
        def dummy_operation(data):
            return data.upper()
        binding = TLSChannelBinding()
        wrapped = wrap_crypto_operation_with_tls_binding(dummy_operation, binding)
        result = wrapped(b"test data")
        self.assertEqual(result, b"TEST DATA")
# ============================================================================
# TEST BACKWARD COMPATIBILITY
# ============================================================================
class TestBackwardCompatibility(unittest.TestCase):
    """Test Backward Compatibility"""
    def test_module_info_present(self):
        """Module info should be present and complete"""
        self.assertIn("name", MODULE_INFO)
        self.assertIn("version", MODULE_INFO)
        self.assertIn("dimension", MODULE_INFO)
        self.assertIn("features", MODULE_INFO)
        self.assertTrue(MODULE_INFO["add_only_compliant"])
        self.assertTrue(MODULE_INFO["pq_ready"])
        self.assertEqual(MODULE_INFO["version"], "17")
    def test_all_features_listed(self):
        """All implemented features should be listed"""
        features = MODULE_INFO["features"]
        self.assertGreater(len(features), 0)
        feature_text = " ".join(features)
        self.assertIn("Post-quantum", feature_text)
        self.assertIn("zeroization", feature_text)
        self.assertIn("channel binding", feature_text.lower())
    def test_compliance_standards_listed(self):
        """Compliance standards should be listed"""
        compliance = MODULE_INFO["compliance"]
        self.assertGreater(len(compliance), 0)
        compliance_text = " ".join(compliance)
        self.assertIn("NIST", compliance_text)
        self.assertIn("FIPS 203", compliance_text)
        self.assertIn("RFC 5929", compliance_text)
# ============================================================================
# TEST RUNNER
# ============================================================================
def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    test_classes = [
        TestPQTLSSecurityConfig,
        TestTLSChannelBinding,
        TestPQCertificateHardener,
        TestTLSKeyMaterialProtector,
        TestPQTLSSecurityAuditor,
        TestGlobalConvenienceFunctions,
        TestBackwardCompatibility,
    ]
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result
if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
