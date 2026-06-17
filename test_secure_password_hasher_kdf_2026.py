"""
Test Suite for Secure Password Hasher & KDF Engine
QuantumCrypt-AI - June 2026 Production Release
"""
import unittest
import sys
import time
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.secure_password_hasher_kdf_2026 import (
    SecurePasswordHasher,
    HashAlgorithm,
    PasswordHashAlgorithm,
    SecurityStrength,
    PasswordHashResult,
    PasswordStrengthReport
)


class TestPBKDF2Hashing(unittest.TestCase):
    """Test PBKDF2-HMAC password hashing"""

    def setUp(self):
        self.hasher = SecurePasswordHasher(
            hash_algorithm=HashAlgorithm.SHA256,
            password_algorithm=PasswordHashAlgorithm.PBKDF2_HMAC,
            security_strength=SecurityStrength.STANDARD
        )

    def test_basic_password_hashing(self):
        """Test basic password hashing works"""
        password = "MySecurePassword123!"
        result = self.hasher.hash_password(password)
        
        self.assertIsInstance(result, PasswordHashResult)
        self.assertEqual(len(result.derived_key), 32)
        self.assertEqual(len(result.salt), 32)  # Default salt length
        self.assertGreater(result.iterations, 0)
        self.assertIsNotNone(result.verification_hash)

    def test_password_verification_correct(self):
        """Test correct password verification"""
        password = "TestPassword456!"
        stored = self.hasher.hash_password(password)
        
        is_valid = self.hasher.verify_password(password, stored)
        self.assertTrue(is_valid)

    def test_password_verification_incorrect(self):
        """Test incorrect password fails verification"""
        password = "CorrectPassword789!"
        wrong_password = "WrongPassword!"
        
        stored = self.hasher.hash_password(password)
        is_valid = self.hasher.verify_password(wrong_password, stored)
        
        self.assertFalse(is_valid)

    def test_salt_generation(self):
        """Test salt generation produces unique salts"""
        salt1 = self.hasher.generate_salt()
        salt2 = self.hasher.generate_salt()
        
        self.assertEqual(len(salt1), 32)
        self.assertEqual(len(salt2), 32)
        self.assertNotEqual(salt1, salt2)  # Extremely unlikely to collide

    def test_custom_salt(self):
        """Test using custom salt works"""
        custom_salt = b"my_custom_salt_value_here_32_bytes!"
        password = "TestPassword"
        
        result = self.hasher.hash_password(password, salt=custom_salt)
        
        self.assertEqual(result.salt, custom_salt)

    def test_deterministic_hashing(self):
        """Test same password + same salt = same hash"""
        password = "DeterministicTest123!"
        salt = self.hasher.generate_salt()
        
        result1 = self.hasher.hash_password(password, salt=salt)
        result2 = self.hasher.hash_password(password, salt=salt)
        
        self.assertEqual(result1.derived_key, result2.derived_key)

    def test_custom_output_length(self):
        """Test custom output lengths"""
        password = "OutputLengthTest"
        
        result_16 = self.hasher.hash_password(password, output_length=16)
        result_64 = self.hasher.hash_password(password, output_length=64)
        
        self.assertEqual(len(result_16.derived_key), 16)
        self.assertEqual(len(result_64.derived_key), 64)


class TestPasswordStrengthAssessment(unittest.TestCase):
    """Test password strength assessment"""

    def setUp(self):
        self.hasher = SecurePasswordHasher()

    def test_weak_password_short(self):
        """Test short password is weak"""
        report = self.hasher.assess_password_strength("abc")
        
        self.assertLess(report.score, 0.5)
        self.assertFalse(report.is_strong)
        self.assertGreater(len(report.recommendations), 0)

    def test_strong_password(self):
        """Test strong password assessment"""
        strong_password = "My$trongP@ssw0rd!2026"
        report = self.hasher.assess_password_strength(strong_password)
        
        self.assertGreater(report.score, 0.5)
        self.assertGreater(report.entropy_bits, 50)

    def test_entropy_calculation(self):
        """Test entropy calculation works"""
        report1 = self.hasher.assess_password_strength("abc")
        report2 = self.hasher.assess_password_strength("My$trongP@ssw0rd!2026WithMoreChars")
        
        self.assertGreater(report2.entropy_bits, report1.entropy_bits)

    def test_recommendations_generated(self):
        """Test recommendations are generated for weak passwords"""
        weak = "abc123"
        report = self.hasher.assess_password_strength(weak)
        
        self.assertIsInstance(report.recommendations, list)
        self.assertGreater(len(report.recommendations), 0)


class TestStorageFormat(unittest.TestCase):
    """Test password storage format"""

    def setUp(self):
        self.hasher = SecurePasswordHasher(
            password_algorithm=PasswordHashAlgorithm.PBKDF2_HMAC
        )

    def test_storage_format_generation(self):
        """Test storage format generation"""
        result = self.hasher.hash_password("TestPassword123!")
        storage = result.to_storage_format()
        
        # Format: $algorithm$params$salt$hash
        parts = storage.split('$')
        self.assertEqual(len(parts), 5)
        self.assertEqual(parts[1], "pbkdf2_hmac")

    def test_verify_from_storage_format(self):
        """Test verification from storage format"""
        password = "StorageTest456!"
        result = self.hasher.hash_password(password)
        storage = result.to_storage_format()
        
        is_valid = self.hasher.verify_storage_format(password, storage)
        self.assertTrue(is_valid)

    def test_verify_wrong_password_from_storage(self):
        """Test wrong password fails storage verification"""
        result = self.hasher.hash_password("CorrectPassword")
        storage = result.to_storage_format()
        
        is_valid = self.hasher.verify_storage_format("WrongPassword", storage)
        self.assertFalse(is_valid)


class TestHashAlgorithms(unittest.TestCase):
    """Test different hash algorithms"""

    def test_sha256(self):
        """Test SHA-256"""
        hasher = SecurePasswordHasher(hash_algorithm=HashAlgorithm.SHA256)
        result = hasher.hash_password("test")
        self.assertEqual(len(result.derived_key), 32)

    def test_sha512(self):
        """Test SHA-512"""
        hasher = SecurePasswordHasher(hash_algorithm=HashAlgorithm.SHA512)
        result = hasher.hash_password("test")
        self.assertEqual(len(result.derived_key), 32)

    def test_sha3_256(self):
        """Test SHA3-256"""
        hasher = SecurePasswordHasher(hash_algorithm=HashAlgorithm.SHA3_256)
        result = hasher.hash_password("test")
        self.assertEqual(len(result.derived_key), 32)


class TestSecurityStrengthLevels(unittest.TestCase):
    """Test different security strength levels"""

    def test_standard_strength(self):
        """Test standard strength"""
        hasher = SecurePasswordHasher(security_strength=SecurityStrength.STANDARD)
        result = hasher.hash_password("test")
        
        self.assertEqual(result.security_strength, SecurityStrength.STANDARD)
        self.assertGreater(result.iterations, 0)

    def test_elevated_strength(self):
        """Test elevated strength"""
        hasher = SecurePasswordHasher(security_strength=SecurityStrength.ELEVATED)
        result = hasher.hash_password("test")
        
        self.assertEqual(result.security_strength, SecurityStrength.ELEVATED)

    def test_paranoid_strength(self):
        """Test paranoid strength (faster test with reduced iterations)"""
        hasher = SecurePasswordHasher(
            security_strength=SecurityStrength.PARANOID,
            password_algorithm=PasswordHashAlgorithm.PBKDF2_HMAC
        )
        # Override for test speed
        hasher.iterations = 1000
        
        result = hasher.hash_password("test")
        self.assertEqual(result.security_strength, SecurityStrength.PARANOID)


class TestEncryptionKeyDerivation(unittest.TestCase):
    """Test encryption key derivation"""

    def setUp(self):
        self.hasher = SecurePasswordHasher()

    def test_key_derivation(self):
        """Test basic key derivation"""
        password = "MyEncryptionPassword"
        
        key, salt = self.hasher.derive_encryption_key(password, key_length=32)
        
        self.assertEqual(len(key), 32)
        self.assertEqual(len(salt), 32)
        self.assertIsInstance(key, bytes)

    def test_key_derivation_deterministic(self):
        """Test key derivation is deterministic with same salt"""
        password = "DeterministicKey"
        salt = self.hasher.generate_salt()
        
        key1, _ = self.hasher.derive_encryption_key(password, salt=salt)
        key2, _ = self.hasher.derive_encryption_key(password, salt=salt)
        
        self.assertEqual(key1, key2)

    def test_different_key_lengths(self):
        """Test different key lengths"""
        password = "KeyLengthTest"
        
        key16, _ = self.hasher.derive_encryption_key(password, key_length=16)
        key32, _ = self.hasher.derive_encryption_key(password, key_length=32)
        
        self.assertEqual(len(key16), 16)
        self.assertEqual(len(key32), 32)


class TestConstantTimeVerification(unittest.TestCase):
    """Test constant-time verification properties"""

    def setUp(self):
        self.hasher = SecurePasswordHasher()

    def test_constant_time_compare_equal(self):
        """Test constant-time comparison of equal values"""
        a = b"test_data_12345"
        b = b"test_data_12345"
        
        result = self.hasher._constant_time_compare(a, b)
        self.assertTrue(result)

    def test_constant_time_compare_unequal(self):
        """Test constant-time comparison of unequal values"""
        a = b"test_data_12345"
        b = b"test_data_67890"
        
        result = self.hasher._constant_time_compare(a, b)
        self.assertFalse(result)

    def test_constant_time_compare_different_length(self):
        """Test constant-time comparison handles different lengths"""
        a = b"short"
        b = b"much_longer_value"
        
        result = self.hasher._constant_time_compare(a, b)
        self.assertFalse(result)


class TestSecurityReport(unittest.TestCase):
    """Test security report generation"""

    def test_security_report_contents(self):
        """Test security report has all required fields"""
        hasher = SecurePasswordHasher()
        report = hasher.get_security_report()
        
        required_fields = [
            'module', 'version', 'hash_algorithm',
            'password_algorithm', 'security_strength',
            'iterations', 'side_channel_mitigations',
            'compliance'
        ]
        
        for field in required_fields:
            self.assertIn(field, report)
        
        self.assertGreater(len(report['side_channel_mitigations']), 0)
        self.assertGreater(len(report['compliance']), 0)


class TestScryptStyleHashing(unittest.TestCase):
    """Test scrypt-style memory-hard hashing"""

    def setUp(self):
        self.hasher = SecurePasswordHasher(
            password_algorithm=PasswordHashAlgorithm.SCRYPT_STYLE,
            security_strength=SecurityStrength.STANDARD
        )
        # Reduce memory for testing
        self.hasher.memory_cost_kb = 64
        self.hasher.iterations = 128

    def test_scrypt_basic_hashing(self):
        """Test basic scrypt-style hashing"""
        result = self.hasher.hash_password("ScryptTestPassword")
        
        self.assertIsInstance(result, PasswordHashResult)
        self.assertEqual(len(result.derived_key), 32)
        self.assertEqual(result.password_algorithm, PasswordHashAlgorithm.SCRYPT_STYLE)

    def test_scrypt_verification(self):
        """Test scrypt-style verification"""
        password = "ScryptVerify123!"
        stored = self.hasher.hash_password(password)
        
        is_valid = self.hasher.verify_password(password, stored)
        self.assertTrue(is_valid)


class TestSecureWipe(unittest.TestCase):
    """Test secure wipe functionality"""

    def test_secure_wipe(self):
        """Test secure wipe works"""
        result = PasswordHashResult(
            hash_algorithm=HashAlgorithm.SHA256,
            password_algorithm=PasswordHashAlgorithm.PBKDF2_HMAC,
            derived_key=b"sensitive_data_here",
            salt=b"salt",
            iterations=1000,
            memory_cost_kb=64,
            parallelism=1,
            security_strength=SecurityStrength.STANDARD
        )
        
        original = result.derived_key
        result.secure_wipe()
        
        # After wipe, should be empty or zeros
        self.assertNotEqual(result.derived_key, original)


def run_all_tests():
    """Run all test suites"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestPBKDF2Hashing))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordStrengthAssessment))
    suite.addTests(loader.loadTestsFromTestCase(TestStorageFormat))
    suite.addTests(loader.loadTestsFromTestCase(TestHashAlgorithms))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityStrengthLevels))
    suite.addTests(loader.loadTestsFromTestCase(TestEncryptionKeyDerivation))
    suite.addTests(loader.loadTestsFromTestCase(TestConstantTimeVerification))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityReport))
    suite.addTests(loader.loadTestsFromTestCase(TestScryptStyleHashing))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureWipe))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print(f"{'='*60}")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
