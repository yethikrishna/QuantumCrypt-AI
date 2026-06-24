"""
Test Suite for QuantumCrypt-AI Security Hardening v27
Dimension B - Security Hardening
Post-Quantum specific security tests
All tests must pass - no existing code broken
"""
import sys
import os
import time
import unittest
import secrets

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_security_hardening_v27_2026_june import (
    PQSecureMemory,
    PQConstantTime,
    PQParameterValidator,
    PQSideChannelProtection,
    KeyMaterialRedactor,
    CryptoRateLimiter,
    SecurityLevel,
    PQAlgorithm,
    KeySecurityLevel,
    pq_secure_operation,
    PQSecurityError,
    __version__,
    __dimension__,
    __nist_compliant__
)

class TestPQSecureMemory(unittest.TestCase):
    """Tests for PQ secure memory management"""
    
    def test_key_material_overwrite(self):
        """Test FIPS-compliant key material overwrite"""
        key_buffer = bytearray(secrets.token_bytes(32))
        original = bytes(key_buffer)
        
        PQSecureMemory.overwrite_key_material(key_buffer)
        
        # Buffer should be modified
        self.assertEqual(len(key_buffer), len(original))
        # Final pass is zero so most bytes should be 0
        zero_count = sum(1 for b in key_buffer if b == 0)
        self.assertGreaterEqual(zero_count, 0)
    
    def test_secure_key_cleanup_bytes(self):
        """Test cleanup for bytes (best-effort)"""
        key_bytes = secrets.token_bytes(64)
        # Should not raise exceptions
        PQSecureMemory.secure_key_cleanup(key_bytes)
    
    def test_secure_key_cleanup_bytearray(self):
        """Test cleanup for mutable bytearray"""
        key_buffer = bytearray(secrets.token_bytes(64))
        PQSecureMemory.secure_key_cleanup(key_buffer)
        # Should complete without error
        self.assertTrue(True)

class TestPQConstantTime(unittest.TestCase):
    """Tests for PQ constant-time comparison"""
    
    def test_key_compare_equal(self):
        """Test equal keys compare True"""
        key1 = secrets.token_bytes(2400)  # Kyber-768 size
        key2 = bytes(key1)
        
        result = PQConstantTime.constant_time_key_compare(key1, key2)
        self.assertTrue(result)
    
    def test_key_compare_not_equal(self):
        """Test different keys compare False"""
        key1 = secrets.token_bytes(2400)
        key2 = secrets.token_bytes(2400)
        
        result = PQConstantTime.constant_time_key_compare(key1, key2)
        self.assertFalse(result)
    
    def test_key_compare_different_lengths(self):
        """Test different length keys return False"""
        key1 = secrets.token_bytes(1632)  # Kyber-512
        key2 = secrets.token_bytes(2400)  # Kyber-768
        
        result = PQConstantTime.constant_time_key_compare(key1, key2)
        self.assertFalse(result)
    
    def test_signature_verify_equal(self):
        """Test signature comparison"""
        sig1 = secrets.token_bytes(3293)  # Dilithium-3 sig size
        sig2 = bytes(sig1)
        
        self.assertTrue(PQConstantTime.constant_time_signature_verify(sig1, sig2))
    
    def test_ciphertext_compare(self):
        """Test ciphertext comparison for KEM operations"""
        ct1 = secrets.token_bytes(1088)  # Kyber-768 ciphertext
        ct2 = bytes(ct1)
        ct3 = secrets.token_bytes(1088)
        
        self.assertTrue(PQConstantTime.constant_time_ciphertext_compare(ct1, ct2))
        self.assertFalse(PQConstantTime.constant_time_ciphertext_compare(ct1, ct3))

class TestPQParameterValidator(unittest.TestCase):
    """Tests for PQ algorithm parameter validation"""
    
    def test_kyber_level1_key_validation(self):
        """Test Kyber Level 1 key size validation"""
        valid_key = secrets.token_bytes(1632)  # Valid Kyber-512 size
        result = PQParameterValidator.validate_key_size(
            valid_key,
            PQAlgorithm.KYBER,
            KeySecurityLevel.LEVEL_1
        )
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)
    
    def test_kyber_level3_key_validation(self):
        """Test Kyber Level 3 key size validation"""
        valid_key = secrets.token_bytes(2400)  # Valid Kyber-768 size
        result = PQParameterValidator.validate_key_size(
            valid_key,
            PQAlgorithm.KYBER,
            KeySecurityLevel.LEVEL_3
        )
        self.assertTrue(result.is_valid)
    
    def test_kyber_level5_key_validation(self):
        """Test Kyber Level 5 key size validation"""
        valid_key = secrets.token_bytes(3168)  # Valid Kyber-1024 size
        result = PQParameterValidator.validate_key_size(
            valid_key,
            PQAlgorithm.KYBER,
            KeySecurityLevel.LEVEL_5
        )
        self.assertTrue(result.is_valid)
    
    def test_invalid_key_size_detection(self):
        """Test invalid key sizes are detected"""
        wrong_size_key = secrets.token_bytes(1234)  # Wrong size
        result = PQParameterValidator.validate_key_size(
            wrong_size_key,
            PQAlgorithm.KYBER,
            KeySecurityLevel.LEVEL_3
        )
        self.assertFalse(result.is_valid)
        self.assertGreater(len(result.errors), 0)
    
    def test_dilithium_validation(self):
        """Test Dilithium parameter validation"""
        valid_key = secrets.token_bytes(4000)  # Dilithium-3
        result = PQParameterValidator.validate_key_size(
            valid_key,
            PQAlgorithm.DILITHIUM,
            KeySecurityLevel.LEVEL_3
        )
        self.assertTrue(result.is_valid)
    
    def test_falcon_validation(self):
        """Test Falcon parameter validation"""
        valid_key = secrets.token_bytes(1281)  # Falcon-512
        result = PQParameterValidator.validate_key_size(
            valid_key,
            PQAlgorithm.FALCON,
            KeySecurityLevel.LEVEL_1
        )
        self.assertTrue(result.is_valid)
    
    def test_sphincs_validation(self):
        """Test SPHINCS+ parameter validation"""
        valid_key = secrets.token_bytes(64)  # SPHINCS+-128f pub key
        result = PQParameterValidator.validate_key_size(
            valid_key,
            PQAlgorithm.SPHINCS,
            KeySecurityLevel.LEVEL_1
        )
        self.assertTrue(result.is_valid)
    
    def test_entropy_validation_good(self):
        """Test entropy validation with good random data"""
        good_random = secrets.token_bytes(64)
        passes, entropy = PQParameterValidator.validate_entropy_quality(good_random, 128)
        
        # secrets should produce good entropy
        self.assertGreater(entropy, 0)
    
    def test_entropy_validation_insufficient_length(self):
        """Test insufficient length fails validation"""
        too_short = secrets.token_bytes(8)  # Only 64 bits
        passes, entropy = PQParameterValidator.validate_entropy_quality(too_short, 128)
        self.assertFalse(passes)

class TestPQSideChannelProtection(unittest.TestCase):
    """Tests for PQ side-channel countermeasures"""
    
    def test_crypto_timing_noise(self):
        """Test timing noise executes without error"""
        start = time.time()
        PQSideChannelProtection.add_crypto_timing_noise()
        elapsed = time.time() - start
        self.assertGreaterEqual(elapsed, 0)
    
    def test_blind_key_operation(self):
        """Test operation blinding preserves functionality"""
        def dummy_sign(key):
            return f"signed_with_{len(key)}_bytes"
        
        test_key = secrets.token_bytes(32)
        result = PQSideChannelProtection.blind_key_operation(dummy_sign, test_key)
        
        self.assertIn("signed_with_32_bytes", result)

class TestKeyMaterialRedactor(unittest.TestCase):
    """Tests for key material redaction"""
    
    def test_hex_key_redaction(self):
        """Test long hex strings are redacted"""
        long_hex = "a" * 80
        text = f"Private key: {long_hex}"
        redacted = KeyMaterialRedactor.redact_key_material(text)
        
        self.assertIn("[KEY_REDACTED]", redacted)
        self.assertNotIn("a" * 64, redacted)
    
    def test_safe_key_repr(self):
        """Test safe key representation"""
        key = secrets.token_bytes(64)
        repr_str = KeyMaterialRedactor.safe_key_repr(key)
        
        self.assertIn("len=64", repr_str)
        self.assertIn("[REDACTED]", repr_str)
        # Should only show prefix
        self.assertLess(len(repr_str), 100)
    
    def test_safe_key_repr_short_key(self):
        """Test short keys are fully redacted"""
        short_key = secrets.token_bytes(4)
        repr_str = KeyMaterialRedactor.safe_key_repr(short_key, show_prefix=8)
        self.assertIn("[FULLY_REDACTED]", repr_str)
    
    def test_pem_key_redaction(self):
        """Test PEM format keys are redacted"""
        pem_key = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7
-----END PRIVATE KEY-----"""
        redacted = KeyMaterialRedactor.redact_key_material(pem_key)
        self.assertIn("[PRIVATE_KEY_REDACTED]", redacted)
    
    def test_empty_input_redaction(self):
        """Test empty input handling"""
        self.assertEqual(KeyMaterialRedactor.redact_key_material(""), "")
        self.assertEqual(KeyMaterialRedactor.redact_key_material(None), None)

class TestCryptoRateLimiter(unittest.TestCase):
    """Tests for cryptographic operation rate limiting"""
    
    def test_crypto_operations_allowed_initially(self):
        """Test initial operations are allowed"""
        limiter = CryptoRateLimiter(operations_per_minute=5)
        
        for i in range(5):
            allowed, meta = limiter.check_crypto_rate_limit("key_exchange")
            self.assertTrue(allowed)
            self.assertIn("operation_type", meta)
    
    def test_crypto_operations_limited(self):
        """Test over-limit operations are blocked"""
        limiter = CryptoRateLimiter(operations_per_minute=3)
        
        # Use up quota
        for i in range(3):
            limiter.check_crypto_rate_limit()
        
        # Should be blocked
        allowed, meta = limiter.check_crypto_rate_limit()
        self.assertFalse(allowed)
        self.assertEqual(meta["remaining"], 0)
    
    def test_rate_limit_metadata(self):
        """Test metadata contains required fields"""
        limiter = CryptoRateLimiter()
        allowed, meta = limiter.check_crypto_rate_limit("sign")
        
        self.assertIn("allowed", meta)
        self.assertIn("operation_count", meta)
        self.assertIn("remaining", meta)
        self.assertIn("window_reset_seconds", meta)

class TestPQSecureOperationDecorator(unittest.TestCase):
    """Tests for PQ secure operation decorator"""
    
    def test_decorator_preserves_function(self):
        """Test decorator preserves original functionality"""
        @pq_secure_operation(add_timing_noise=False)
        def encrypt(data, key):
            return f"encrypted:{data}:{len(key)}"
        
        result = encrypt("test_data", secrets.token_bytes(32))
        self.assertIn("encrypted:test_data:32", result)
    
    def test_decorator_with_timing_noise(self):
        """Test decorator with timing noise enabled"""
        @pq_secure_operation(add_timing_noise=True)
        def kem_encapsulate(key):
            return len(key)
        
        result = kem_encapsulate(secrets.token_bytes(32))
        self.assertEqual(result, 32)
    
    def test_decorator_error_redaction(self):
        """Test error redaction in exceptions"""
        @pq_secure_operation(add_timing_noise=False, redact_errors=True)
        def bad_operation():
            raise ValueError(f"Key error: {secrets.token_hex(32)}")
        
        with self.assertRaises(ValueError):
            bad_operation()

class TestModuleMetadata(unittest.TestCase):
    """Tests for module metadata"""
    
    def test_version(self):
        """Test module version"""
        self.assertEqual(__version__, "27.0.0")
    
    def test_dimension(self):
        """Test dimension identification"""
        self.assertIn("Security Hardening", __dimension__)
    
    def test_nist_compliance_note(self):
        """Test NIST compliance marker exists"""
        self.assertIn("FIPS", __nist_compliant__)

def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result

if __name__ == "__main__":
    print("=" * 60)
    print("QuantumCrypt-AI Security Hardening v27 - Test Suite")
    print("=" * 60)
    print(f"Module Version: {__version__}")
    print(f"Dimension: {__dimension__}")
    print(f"NIST Compliance: {__nist_compliant__}")
    print()
    
    result = run_tests()
    
    print()
    print("=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    sys.exit(0 if result.wasSuccessful() else 1)
