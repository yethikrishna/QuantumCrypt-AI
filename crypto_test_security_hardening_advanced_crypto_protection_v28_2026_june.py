"""
Test Suite for QuantumCrypt AI - Advanced Cryptographic Security Protection (Dimension B V28)
==============================================================================================
ADD-ONLY TESTS - NO MODIFICATIONS TO EXISTING TESTS
All existing tests must continue to pass.
This test suite only tests the NEW security hardening module.
"""
import sys
import os
import tempfile
import unittest

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_security_hardening_advanced_crypto_protection_v28_2026_june import (
    SecureRandom,
    SecureHashing,
    KeyMaterialProtector,
    InjectionDetector,
    SecureFileIO,
    SecretRedactor,
    CryptoAdvancedSecurityToolkit,
    SecurityLevel,
    get_crypto_security_toolkit,
)


class TestSecureRandom(unittest.TestCase):
    """Test cryptographically secure random number generation"""
    
    def test_generate_bytes(self):
        """Test secure byte generation"""
        result = SecureRandom.generate_bytes(32)
        self.assertEqual(len(result), 32)
        self.assertIsInstance(result, bytes)
    
    def test_generate_key_material(self):
        """Test key material generation"""
        key = SecureRandom.generate_key_material(32)
        self.assertEqual(len(key), 32)
        self.assertIsInstance(key, bytes)
    
    def test_generate_salt(self):
        """Test salt generation"""
        salt = SecureRandom.generate_salt(32)
        self.assertEqual(len(salt), 32)
        self.assertIsInstance(salt, bytes)
    
    def test_generate_token(self):
        """Test token generation"""
        token = SecureRandom.generate_token(32)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 30)
    
    def test_generate_hex(self):
        """Test hex generation"""
        hex_str = SecureRandom.generate_hex(32)
        self.assertEqual(len(hex_str), 64)
        self.assertIsInstance(hex_str, str)


class TestSecureHashing(unittest.TestCase):
    """Test secure password/secret hashing"""
    
    def test_hash_secret_basic(self):
        """Test basic hashing works"""
        secret = "test_api_key_12345"
        result = SecureHashing.hash_secret(secret)
        
        self.assertIsNotNone(result.hash_bytes)
        self.assertIsNotNone(result.salt)
        self.assertEqual(len(result.salt), 32)
        self.assertGreater(result.iterations, 0)
        self.assertIn('$', result.encoded_string)
    
    def test_hash_unique_salts(self):
        """Test each hash gets unique salt"""
        secret = "same_api_key"
        hash1 = SecureHashing.hash_secret(secret)
        hash2 = SecureHashing.hash_secret(secret)
        
        # Same secret should produce DIFFERENT hashes
        self.assertNotEqual(hash1.encoded_string, hash2.encoded_string)
    
    def test_verify_secret_correct(self):
        """Test verification with correct secret"""
        secret = "my_encryption_key"
        stored = SecureHashing.hash_secret(secret).encoded_string
        
        result = SecureHashing.verify_secret(secret, stored)
        self.assertTrue(result)
    
    def test_verify_secret_wrong(self):
        """Test verification with wrong secret"""
        secret = "correct_key"
        stored = SecureHashing.hash_secret(secret).encoded_string
        
        result = SecureHashing.verify_secret("wrong_key", stored)
        self.assertFalse(result)
    
    def test_verify_invalid_hash_format(self):
        """Test verification handles invalid formats gracefully"""
        result = SecureHashing.verify_secret("test", "invalid_format")
        self.assertFalse(result)


class TestKeyMaterialProtector(unittest.TestCase):
    """Test key material protection"""
    
    def test_zeroize_key(self):
        """Test key zeroization works"""
        key = bytearray(b"my_secret_key_material_12345")
        original = bytes(key)
        
        KeyMaterialProtector.zeroize_key(key)
        
        # Key should be all zeros after zeroization
        self.assertEqual(sum(key), 0)
        # Original should not equal zeroized
        self.assertNotEqual(original, bytes(key))
    
    def test_validate_key_strength_good(self):
        """Test good key passes validation"""
        good_key = SecureRandom.generate_key_material(32)
        is_valid, reason = KeyMaterialProtector.validate_key_strength(good_key)
        
        self.assertTrue(is_valid)
        self.assertIn("meets minimum", reason)
    
    def test_validate_key_strength_short(self):
        """Test short key fails validation"""
        short_key = b"short"
        is_valid, reason = KeyMaterialProtector.validate_key_strength(short_key)
        
        self.assertFalse(is_valid)
        self.assertIn("too short", reason.lower())
    
    def test_estimate_entropy(self):
        """Test entropy estimation"""
        # Random data should have high entropy
        random_data = SecureRandom.generate_bytes(32)
        entropy = KeyMaterialProtector.estimate_entropy(random_data)
        
        self.assertGreater(entropy, 0)


class TestInjectionDetector(unittest.TestCase):
    """Test injection attack detection"""
    
    def test_safe_input(self):
        """Test safe input passes"""
        detector = InjectionDetector(SecurityLevel.STANDARD)
        result = detector.scan_input("Normal crypto API input")
        
        self.assertTrue(result.is_safe)
        self.assertEqual(len(result.detected_threats), 0)
        self.assertEqual(result.risk_score, 0)
    
    def test_sql_injection_detection(self):
        """Test SQL injection patterns detected"""
        detector = InjectionDetector(SecurityLevel.STANDARD)
        
        result = detector.scan_input("' OR '1'='1")
        self.assertFalse(result.is_safe)
        self.assertGreater(result.risk_score, 0)
    
    def test_xss_detection(self):
        """Test XSS patterns detected"""
        detector = InjectionDetector(SecurityLevel.STANDARD)
        
        result = detector.scan_input('<script>alert(1)</script>')
        self.assertFalse(result.is_safe)
    
    def test_path_traversal_detection(self):
        """Test path traversal detected"""
        detector = InjectionDetector(SecurityLevel.STANDARD)
        
        result = detector.scan_input("../../../etc/passwd")
        self.assertFalse(result.is_safe)


class TestSecureFileIO(unittest.TestCase):
    """Test secure file I/O wrappers for key files"""
    
    def test_path_validation_blocks_traversal(self):
        """Test path traversal is blocked"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_io = SecureFileIO(allowed_base_dir=tmpdir)
            
            is_safe, _ = file_io._validate_path(os.path.join(tmpdir, "../../etc/passwd"))
            self.assertFalse(is_safe)
    
    def test_safe_path_allowed(self):
        """Test safe paths work"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_io = SecureFileIO(allowed_base_dir=tmpdir)
            test_file = os.path.join(tmpdir, "test.key")
            
            is_safe, _ = file_io._validate_path(test_file)
            self.assertTrue(is_safe)
    
    def test_safe_write_read_key_file(self):
        """Test writing and reading key files works"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_io = SecureFileIO(allowed_base_dir=tmpdir)
            test_file = os.path.join(tmpdir, "private.key")
            key_data = b"fake_key_material_12345"
            
            # Write
            write_ok = file_io.safe_write_key_file(test_file, key_data)
            self.assertTrue(write_ok)
            
            # Read
            content = file_io.safe_read_key_file(test_file)
            self.assertEqual(content, key_data)


class TestSecretRedactor(unittest.TestCase):
    """Test sensitive data redaction"""
    
    def test_redact_api_key(self):
        """Test API key redaction"""
        text = "api_key=abcdefghijklmnopqrstuvwxyz1234567890"
        redacted = SecretRedactor.redact(text)
        
        self.assertNotIn('abcdefghijklmnopqrstuvwxyz1234567890', redacted)
        self.assertIn('[REDACTED]', redacted)
    
    def test_redact_bearer_token(self):
        """Test Bearer token redaction"""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        redacted = SecretRedactor.redact(text)
        
        self.assertIn('[REDACTED]', redacted)
    
    def test_redact_github_token(self):
        """Test GitHub token redaction"""
        text = "ghp_fakeExampleToken123456789abcdefghijklmnop"
        redacted = SecretRedactor.redact(text)
        
        self.assertIn('[REDACTED]', redacted)
    
    def test_redact_private_key(self):
        """Test private key header redaction"""
        text = "-----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEA..."
        redacted = SecretRedactor.redact(text)
        
        self.assertIn('[REDACTED]', redacted)
    
    def test_redact_dict(self):
        """Test dictionary redaction"""
        data = {
            'key_id': 'key-123',
            'private_key': 'very_secret_key_here',
            'config': {
                'secret_key': 'another_secret'
            }
        }
        redacted = SecretRedactor.redact_dict(data)
        
        self.assertEqual(redacted['key_id'], 'key-123')
        self.assertEqual(redacted['private_key'], '[REDACTED]')
        self.assertEqual(redacted['config']['secret_key'], '[REDACTED]')
    
    def test_normal_text_unchanged(self):
        """Test normal text not affected"""
        text = "Normal operation completed successfully"
        redacted = SecretRedactor.redact(text)
        
        self.assertEqual(redacted, text)


class TestCryptoAdvancedSecurityToolkit(unittest.TestCase):
    """Test main crypto security toolkit facade"""
    
    def test_toolkit_instantiation(self):
        """Test toolkit creates successfully"""
        toolkit = CryptoAdvancedSecurityToolkit(SecurityLevel.STANDARD)
        self.assertIsNotNone(toolkit)
    
    def test_get_crypto_security_toolkit(self):
        """Test convenience function works"""
        toolkit = get_crypto_security_toolkit()
        self.assertIsNotNone(toolkit)
    
    def test_hash_and_verify_integration(self):
        """Test full hash+verify flow"""
        toolkit = get_crypto_security_toolkit()
        
        secret = "test_api_secret_key"
        stored_hash = toolkit.hash_secret(secret)
        
        self.assertIsInstance(stored_hash, str)
        self.assertTrue(toolkit.verify_secret(secret, stored_hash))
        self.assertFalse(toolkit.verify_secret("wrong_secret", stored_hash))
    
    def test_generate_secure_key_integration(self):
        """Test key generation through toolkit"""
        toolkit = get_crypto_security_toolkit()
        key = toolkit.generate_secure_key(32)
        
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)
    
    def test_key_validation_integration(self):
        """Test key strength validation"""
        toolkit = get_crypto_security_toolkit()
        key = toolkit.generate_secure_key(32)
        
        is_strong, reason = toolkit.validate_key_strength(key)
        self.assertTrue(is_strong)
    
    def test_zeroize_integration(self):
        """Test key zeroization through toolkit"""
        toolkit = get_crypto_security_toolkit()
        key = bytearray(b"test_key_to_zeroize")
        
        toolkit.zeroize_key_material(key)
        self.assertEqual(sum(key), 0)
    
    def test_scan_injection_integration(self):
        """Test injection scanning"""
        toolkit = get_crypto_security_toolkit()
        
        safe_result = toolkit.scan_for_injection("normal input")
        self.assertTrue(safe_result.is_safe)
        
        unsafe_result = toolkit.scan_for_injection("' OR 1=1--")
        self.assertFalse(unsafe_result.is_safe)
    
    def test_redact_integration(self):
        """Test redaction through toolkit"""
        toolkit = get_crypto_security_toolkit()
        
        text = "private_key=supersecretkey12345"
        redacted = toolkit.redact_secrets(text)
        
        self.assertIn('[REDACTED]', redacted)
        self.assertNotIn('supersecretkey12345', redacted)


def run_all_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestSecureRandom))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureHashing))
    suite.addTests(loader.loadTestsFromTestCase(TestKeyMaterialProtector))
    suite.addTests(loader.loadTestsFromTestCase(TestInjectionDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureFileIO))
    suite.addTests(loader.loadTestsFromTestCase(TestSecretRedactor))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoAdvancedSecurityToolkit))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"QUANTUMCRYPT TEST SUMMARY:")
    print(f"  Tests run: {result.testsRun}")
    print(f"  Failures: {len(result.failures)}")
    print(f"  Errors: {len(result.errors)}")
    print(f"  Success: {result.wasSuccessful()}")
    print(f"{'='*60}")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
