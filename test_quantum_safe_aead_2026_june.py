"""
Test Suite for Quantum-Safe AEAD Encryption 2026
June 2026 Production Release
Comprehensive tests for authenticated encryption
"""
import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quantum_crypt.quantum_safe_aead_2026_june import (
    QuantumSafeAEAD2026,
    EncryptionStrength,
    KeyType,
    AEADEncryptionResult,
    AEADDecryptionResult,
    AEADKeyPair
)


class TestQuantumSafeAEAD2026(unittest.TestCase):
    """Test cases for Quantum-Safe AEAD Encryption"""
    
    def setUp(self):
        """Initialize AEAD cipher for each test"""
        self.aead = QuantumSafeAEAD2026(strength=EncryptionStrength.HIGH)
    
    def test_aead_initialization(self):
        """Test AEAD initialization"""
        self.assertIsNotNone(self.aead)
        self.assertEqual(self.aead.strength, EncryptionStrength.HIGH)
        self.assertEqual(self.aead.NONCE_LENGTH, 12)
        self.assertEqual(self.aead.KEY_LENGTH, 32)
        self.assertEqual(self.aead.TAG_LENGTH, 16)
    
    def test_key_generation(self):
        """Test key generation"""
        # Ephemeral key generation
        key_pair = self.aead.generate_key(key_type=KeyType.EPHEMERAL)
        
        self.assertIsNotNone(key_pair)
        self.assertEqual(len(key_pair.encryption_key), 32)
        self.assertEqual(key_pair.key_type, KeyType.EPHEMERAL)
        self.assertEqual(key_pair.strength, EncryptionStrength.HIGH)
    
    def test_key_generation_from_password(self):
        """Test key derivation from password"""
        password = b"my_secure_password_123!"
        key_pair = self.aead.generate_key(password=password, key_type=KeyType.DERIVED)
        
        self.assertIsNotNone(key_pair)
        self.assertEqual(len(key_pair.encryption_key), 32)
        self.assertEqual(key_pair.key_type, KeyType.DERIVED)
        self.assertIsNotNone(key_pair.salt)
    
    def test_nonce_generation(self):
        """Test nonce generation"""
        nonce1 = self.aead.generate_nonce()
        nonce2 = self.aead.generate_nonce()
        
        self.assertEqual(len(nonce1), 12)
        self.assertEqual(len(nonce2), 12)
        self.assertNotEqual(nonce1, nonce2)  # Cryptographically random
    
    def test_basic_encryption_decryption(self):
        """Test basic encrypt/decrypt round trip"""
        plaintext = b"Hello, Quantum World! This is a test message."
        
        # Generate key
        key_pair = self.aead.generate_key()
        
        # Encrypt
        enc_result = self.aead.encrypt(
            plaintext=plaintext,
            key=key_pair.encryption_key
        )
        
        self.assertIsNotNone(enc_result)
        self.assertIsNotNone(enc_result.ciphertext)
        self.assertEqual(len(enc_result.nonce), 12)
        self.assertEqual(len(enc_result.tag), 16)
        
        # Decrypt
        dec_result = self.aead.decrypt(
            ciphertext=enc_result.ciphertext,
            key=key_pair.encryption_key,
            nonce=enc_result.nonce,
            tag=enc_result.tag
        )
        
        self.assertTrue(dec_result.verified)
        self.assertEqual(dec_result.plaintext, plaintext)
    
    def test_encryption_with_associated_data(self):
        """Test encryption with Associated Data (AD)"""
        plaintext = b"Secret message content"
        associated_data = b"context:user123,timestamp:2026-06-17,id:456"
        
        key_pair = self.aead.generate_key()
        
        # Encrypt with AD
        enc_result = self.aead.encrypt(
            plaintext=plaintext,
            key=key_pair.encryption_key,
            associated_data=associated_data
        )
        
        # Decrypt with correct AD - should work
        dec_result = self.aead.decrypt(
            ciphertext=enc_result.ciphertext,
            key=key_pair.encryption_key,
            nonce=enc_result.nonce,
            tag=enc_result.tag,
            associated_data=associated_data
        )
        
        self.assertTrue(dec_result.verified)
        self.assertEqual(dec_result.plaintext, plaintext)
        
        # Decrypt with WRONG AD - should fail
        with self.assertRaises(ValueError):
            self.aead.decrypt(
                ciphertext=enc_result.ciphertext,
                key=key_pair.encryption_key,
                nonce=enc_result.nonce,
                tag=enc_result.tag,
                associated_data=b"wrong_associated_data"
            )
    
    def test_tamper_detection(self):
        """Test that tampering is detected"""
        plaintext = b"Original message"
        key_pair = self.aead.generate_key()
        
        enc_result = self.aead.encrypt(plaintext, key_pair.encryption_key)
        
        # Tamper with ciphertext
        tampered_ciphertext = bytearray(enc_result.ciphertext)
        tampered_ciphertext[0] ^= 0xFF  # Flip first byte
        
        # Decryption should fail
        with self.assertRaises(ValueError):
            self.aead.decrypt(
                ciphertext=bytes(tampered_ciphertext),
                key=key_pair.encryption_key,
                nonce=enc_result.nonce,
                tag=enc_result.tag
            )
    
    def test_wrong_key_rejection(self):
        """Test that wrong key is rejected"""
        plaintext = b"Test message"
        
        key1 = self.aead.generate_key()
        key2 = self.aead.generate_key()
        
        enc_result = self.aead.encrypt(plaintext, key1.encryption_key)
        
        # Try decrypting with wrong key
        with self.assertRaises(ValueError):
            self.aead.decrypt(
                ciphertext=enc_result.ciphertext,
                key=key2.encryption_key,  # WRONG KEY!
                nonce=enc_result.nonce,
                tag=enc_result.tag
            )
    
    def test_password_based_encryption(self):
        """Test password-based encryption round trip"""
        plaintext = b"Password protected secret data"
        password = b"correct_horse_battery_staple"
        
        # Encrypt with password
        enc_result, key_pair = self.aead.encrypt_with_password(
            plaintext=plaintext,
            password=password
        )
        
        # Decrypt with same password
        dec_result = self.aead.decrypt_with_password(
            ciphertext=enc_result.ciphertext,
            password=password,
            nonce=enc_result.nonce,
            tag=enc_result.tag,
            salt=key_pair.salt
        )
        
        self.assertTrue(dec_result.verified)
        self.assertEqual(dec_result.plaintext, plaintext)
    
    def test_wrong_password_rejection(self):
        """Test that wrong password is rejected"""
        plaintext = b"Secret data"
        correct_password = b"correct_password"
        wrong_password = b"wrong_password"
        
        enc_result, key_pair = self.aead.encrypt_with_password(
            plaintext=plaintext,
            password=correct_password
        )
        
        with self.assertRaises(ValueError):
            self.aead.decrypt_with_password(
                ciphertext=enc_result.ciphertext,
                password=wrong_password,
                nonce=enc_result.nonce,
                tag=enc_result.tag,
                salt=key_pair.salt
            )
    
    def test_different_encryption_strengths(self):
        """Test different encryption strength levels"""
        plaintext = b"Test message for strength levels"
        
        for strength in [EncryptionStrength.STANDARD, 
                        EncryptionStrength.HIGH, 
                        EncryptionStrength.QUANTUM]:
            aead = QuantumSafeAEAD2026(strength=strength)
            key_pair = aead.generate_key()
            
            enc_result = aead.encrypt(plaintext, key_pair.encryption_key)
            dec_result = aead.decrypt(
                enc_result.ciphertext,
                key_pair.encryption_key,
                enc_result.nonce,
                enc_result.tag
            )
            
            self.assertEqual(dec_result.plaintext, plaintext)
            self.assertEqual(enc_result.encryption_strength, strength)
    
    def test_large_data_encryption(self):
        """Test encryption of larger data"""
        # 100KB of random data
        large_plaintext = os.urandom(100 * 1024)
        
        key_pair = self.aead.generate_key()
        enc_result = self.aead.encrypt(large_plaintext, key_pair.encryption_key)
        dec_result = self.aead.decrypt(
            enc_result.ciphertext,
            key_pair.encryption_key,
            enc_result.nonce,
            enc_result.tag
        )
        
        self.assertEqual(dec_result.plaintext, large_plaintext)
        self.assertEqual(len(enc_result.ciphertext), len(large_plaintext))
    
    def test_empty_data_encryption(self):
        """Test encryption of empty data (edge case)"""
        plaintext = b""
        
        key_pair = self.aead.generate_key()
        enc_result = self.aead.encrypt(plaintext, key_pair.encryption_key)
        dec_result = self.aead.decrypt(
            enc_result.ciphertext,
            key_pair.encryption_key,
            enc_result.nonce,
            enc_result.tag
        )
        
        self.assertEqual(dec_result.plaintext, b"")
    
    def test_invalid_key_length(self):
        """Test that invalid key length is rejected"""
        with self.assertRaises(ValueError):
            self.aead.encrypt(b"test", key=b"too_short")
        
        with self.assertRaises(ValueError):
            self.aead.decrypt(b"data", key=b"short", nonce=b"123456789012", tag=b"1234567890123456")
    
    def test_invalid_nonce_length(self):
        """Test that invalid nonce length is rejected"""
        key = os.urandom(32)
        
        with self.assertRaises(ValueError):
            self.aead.encrypt(b"test", key=key, nonce=b"too_short")
    
    def test_hmac_verification(self):
        """Test HMAC computation and verification"""
        data = b"Data to authenticate"
        key = os.urandom(32)
        
        mac = self.aead.compute_mac(data, key)
        
        self.assertTrue(self.aead.verify_mac(data, key, mac))
        self.assertFalse(self.aead.verify_mac(data + b"x", key, mac))
    
    def test_statistics_tracking(self):
        """Test operation statistics tracking"""
        key_pair = self.aead.generate_key()
        
        # Perform some operations
        for i in range(5):
            enc = self.aead.encrypt(f"Message {i}".encode(), key_pair.encryption_key)
            self.aead.decrypt(enc.ciphertext, key_pair.encryption_key, enc.nonce, enc.tag)
        
        stats = self.aead.get_statistics()
        
        self.assertEqual(stats['encryptions_performed'], 5)
        self.assertEqual(stats['decryptions_performed'], 5)
        self.assertEqual(stats['total_operations'], 10)
        self.assertEqual(stats['verification_failures'], 0)
    
    def test_security_report(self):
        """Test security report generation"""
        report = QuantumSafeAEAD2026.get_security_report()
        
        self.assertIn('cipher', report)
        self.assertIn('key_size', report)
        self.assertIn('security_properties', report)
        self.assertIn('resistance', report)
        self.assertIn('limitations', report)
        self.assertGreater(len(report['security_properties']), 0)
        self.assertGreater(len(report['limitations']), 0)
    
    def test_custom_nonce(self):
        """Test encryption with custom nonce"""
        plaintext = b"Test with custom nonce"
        key_pair = self.aead.generate_key()
        custom_nonce = b"123456789012"  # Exactly 12 bytes
        
        enc_result = self.aead.encrypt(
            plaintext, 
            key_pair.encryption_key,
            nonce=custom_nonce
        )
        
        self.assertEqual(enc_result.nonce, custom_nonce)
        
        dec_result = self.aead.decrypt(
            enc_result.ciphertext,
            key_pair.encryption_key,
            custom_nonce,
            enc_result.tag
        )
        
        self.assertEqual(dec_result.plaintext, plaintext)


def run_tests():
    """Run all tests and return results"""
    suite = unittest.TestLoader().loadTestsFromTestCase(TestQuantumSafeAEAD2026)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


if __name__ == '__main__':
    print("=" * 60)
    print("Quantum-Safe AEAD 2026 - Test Suite")
    print("June 2026 Production Release")
    print("=" * 60)
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
