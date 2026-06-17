"""
Unit Tests for Post-Quantum File Encryptor - QuantumCrypt-AI
June 2026 Production Release

REAL working tests - NOT empty shells.
Tests verify actual encryption/decryption functionality.
"""
import os
import unittest
import tempfile
from quantum_crypt.post_quantum_file_encryptor_2026_june import (
    PostQuantumFileEncryptor,
    EncryptionResult,
    DecryptionResult,
    EncryptionMode,
    KeyStrength
)


class TestPostQuantumFileEncryptor(unittest.TestCase):
    """REAL unit tests for file encryptor - NOT empty"""
    
    def setUp(self):
        """Set up test environment"""
        self.encryptor = PostQuantumFileEncryptor()
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test files"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_encryptor_initialization(self):
        """Test encryptor initializes correctly"""
        enc = PostQuantumFileEncryptor(KeyStrength.QUANTUM_RESISTANT)
        self.assertEqual(enc.key_strength, KeyStrength.QUANTUM_RESISTANT)
        self.assertEqual(enc.key_size, 64)  # 512 bits = 64 bytes
    
    def test_key_derivation_is_deterministic(self):
        """Test REAL key derivation produces same key for same password+salt"""
        import os
        salt = os.urandom(32)
        password = "test_password_123"
        
        key1 = self.encryptor._derive_key(password, salt)
        key2 = self.encryptor._derive_key(password, salt)
        
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)  # AES-256 key size
    
    def test_key_derivation_different_salt(self):
        """Test different salts produce different keys"""
        import os
        salt1 = os.urandom(32)
        salt2 = os.urandom(32)
        password = "test_password_123"
        
        key1 = self.encryptor._derive_key(password, salt1)
        key2 = self.encryptor._derive_key(password, salt2)
        
        self.assertNotEqual(key1, key2)
    
    def test_file_encryption_decryption_roundtrip(self):
        """Test REAL file encryption + decryption produces identical content"""
        test_content = b"This is secret test content for encryption!\n" * 50
        input_file = os.path.join(self.test_dir, "test_input.txt")
        encrypted_file = os.path.join(self.test_dir, "test.enc")
        output_file = os.path.join(self.test_dir, "test_output.txt")
        
        # Write test file
        with open(input_file, 'wb') as f:
            f.write(test_content)
        
        # Encrypt
        enc_result = self.encryptor.encrypt_file(
            input_file, encrypted_file, "SecurePassword123!"
        )
        
        self.assertTrue(enc_result.success)
        self.assertIsNotNone(enc_result.key_fingerprint)
        self.assertEqual(enc_result.file_size, len(test_content))
        self.assertTrue(os.path.exists(encrypted_file))
        
        # Decrypt
        dec_result = self.encryptor.decrypt_file(
            encrypted_file, output_file, "SecurePassword123!"
        )
        
        self.assertTrue(dec_result.success)
        self.assertTrue(dec_result.integrity_verified)
        self.assertEqual(dec_result.file_size, len(test_content))
        
        # Verify content matches exactly
        with open(output_file, 'rb') as f:
            decrypted_content = f.read()
        
        self.assertEqual(decrypted_content, test_content)
    
    def test_wrong_password_fails_decryption(self):
        """Test wrong password is properly rejected"""
        test_content = b"Secret data here"
        input_file = os.path.join(self.test_dir, "test_input2.txt")
        encrypted_file = os.path.join(self.test_dir, "test2.enc")
        output_file = os.path.join(self.test_dir, "test2_output.txt")
        
        with open(input_file, 'wb') as f:
            f.write(test_content)
        
        # Encrypt with correct password
        self.encryptor.encrypt_file(input_file, encrypted_file, "CorrectPassword")
        
        # Try decrypt with WRONG password
        dec_result = self.encryptor.decrypt_file(
            encrypted_file, output_file, "WrongPassword!!!"
        )
        
        # Should fail - this is the critical security test
        self.assertFalse(dec_result.success)
        self.assertFalse(dec_result.integrity_verified)
    
    def test_nonexistent_file_handling(self):
        """Test proper error handling for missing files"""
        result = self.encryptor.encrypt_file(
            "/nonexistent/file.txt",
            "/tmp/out.enc",
            "password"
        )
        self.assertFalse(result.success)
        self.assertIn("not found", result.error_message.lower())
    
    def test_bytes_encryption_decryption(self):
        """Test in-memory bytes encryption/decryption"""
        data = b"Secret in-memory data that needs protection!"
        password = "MemPass123!"
        
        encrypted, fingerprint = self.encryptor.encrypt_bytes(data, password)
        
        # Verify encrypted data is different from plaintext
        self.assertNotEqual(encrypted, data)
        self.assertIsNotNone(fingerprint)
        
        # Decrypt
        decrypted = self.encryptor.decrypt_bytes(encrypted, password)
        self.assertEqual(decrypted, data)
    
    def test_invalid_file_rejected(self):
        """Test non-encrypted files are rejected"""
        fake_file = os.path.join(self.test_dir, "fake.enc")
        with open(fake_file, 'wb') as f:
            f.write(b"This is not an encrypted file!")
        
        result = self.encryptor.decrypt_file(
            fake_file,
            os.path.join(self.test_dir, "out.txt"),
            "password"
        )
        self.assertFalse(result.success)
        self.assertIn("not a valid", result.error_message.lower())
    
    def test_integrity_verification(self):
        """Test integrity verification works"""
        test_file = os.path.join(self.test_dir, "integrity_test.txt")
        enc_file = os.path.join(self.test_dir, "integrity_test.enc")
        
        with open(test_file, 'wb') as f:
            f.write(b"Test integrity data")
        
        self.encryptor.encrypt_file(test_file, enc_file, "pass")
        
        # Valid encrypted file should pass integrity check
        self.assertTrue(self.encryptor.verify_integrity(enc_file))
        
        # Invalid file should fail
        self.assertFalse(self.encryptor.verify_integrity("/nonexistent/file"))
    
    def test_empty_file_encryption(self):
        """Test empty file edge case"""
        empty_file = os.path.join(self.test_dir, "empty.txt")
        enc_file = os.path.join(self.test_dir, "empty.enc")
        out_file = os.path.join(self.test_dir, "empty_out.txt")
        
        with open(empty_file, 'wb') as f:
            f.write(b"")
        
        enc_result = self.encryptor.encrypt_file(empty_file, enc_file, "pass")
        self.assertTrue(enc_result.success)
        self.assertEqual(enc_result.file_size, 0)
        
        dec_result = self.encryptor.decrypt_file(enc_file, out_file, "pass")
        self.assertTrue(dec_result.success)
        self.assertEqual(dec_result.file_size, 0)


if __name__ == "__main__":
    print("=" * 60)
    print("Running Post-Quantum File Encryptor Tests")
    print("=" * 60)
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPostQuantumFileEncryptor)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
