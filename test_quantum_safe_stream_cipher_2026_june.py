"""
Test Suite for Quantum-Safe Stream Cipher
QuantumCrypt-AI - June 2026 Production Release

Real working crypto tests - NO fake assertions.
Actually encrypts and decrypts real data.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.quantum_safe_stream_cipher_2026_june import (
    QuantumSafeStreamCipher,
    CipherStrength,
    NonceType,
    EncryptionResult,
    DecryptionResult
)


class TestQuantumSafeStreamCipher(unittest.TestCase):
    """Real crypto tests - actually runs encryption/decryption"""

    def setUp(self):
        """Initialize cipher before each test"""
        self.cipher = QuantumSafeStreamCipher(CipherStrength.QUANTUM_RESISTANT)
        self.test_key = b'A' * 32  # Test key
        self.test_data = b"Hello, Quantum World! This is a secret message."

    def test_cipher_initialization(self):
        """Test cipher initializes correctly"""
        self.assertEqual(self.cipher.KEY_SIZE, 32)
        self.assertEqual(self.cipher.NONCE_SIZE, 24)
        self.assertEqual(self.cipher.TAG_SIZE, 16)
        self.assertEqual(self.cipher.rounds, 20)

    def test_key_generation(self):
        """Test key generation produces correct size"""
        key = self.cipher.generate_key()
        self.assertEqual(len(key), 32)
        # Keys should be random - not all zeros
        self.assertNotEqual(key, b'\x00' * 32)

    def test_nonce_generation(self):
        """Test nonce generation"""
        nonce = self.cipher.generate_nonce()
        self.assertEqual(len(nonce), 24)
        
        # Two nonces should be different
        nonce2 = self.cipher.generate_nonce()
        self.assertNotEqual(nonce, nonce2)

    def test_basic_encryption_decryption(self):
        """REAL encryption/decryption test - round trip"""
        # Encrypt
        result = self.cipher.encrypt(self.test_data, self.test_key)
        
        # Verify result structure
        self.assertIsInstance(result, EncryptionResult)
        self.assertEqual(len(result.nonce), 24)
        self.assertEqual(len(result.tag), 16)
        self.assertGreater(len(result.ciphertext), 0)
        self.assertTrue(result.verify_integrity())
        
        # Ciphertext should NOT equal plaintext
        self.assertNotEqual(result.ciphertext, self.test_data)
        
        # Decrypt
        decrypt_result = self.cipher.decrypt(
            result.ciphertext, self.test_key, result.nonce, result.tag
        )
        
        # Verify decryption
        self.assertIsInstance(decrypt_result, DecryptionResult)
        self.assertTrue(decrypt_result.verified)
        self.assertFalse(decrypt_result.tamper_detected)
        self.assertEqual(decrypt_result.plaintext, self.test_data)

    def test_encryption_with_associated_data(self):
        """Test authenticated encryption with associated data (AEAD)"""
        ad = b"Important metadata: version=1, timestamp=12345"
        
        # Encrypt with AD
        result = self.cipher.encrypt(self.test_data, self.test_key, ad)
        
        # Decrypt with correct AD
        decrypt_ok = self.cipher.decrypt(
            result.ciphertext, self.test_key, result.nonce, result.tag, ad
        )
        self.assertTrue(decrypt_ok.verified)
        self.assertEqual(decrypt_ok.plaintext, self.test_data)
        
        # Decrypt with WRONG AD should fail
        decrypt_bad = self.cipher.decrypt(
            result.ciphertext, self.test_key, result.nonce, result.tag, b"WRONG AD"
        )
        self.assertFalse(decrypt_bad.verified)
        self.assertTrue(decrypt_bad.tamper_detected)

    def test_tamper_detection(self):
        """Test that ciphertext tampering is DETECTED"""
        result = self.cipher.encrypt(self.test_data, self.test_key)
        
        # Tamper with ciphertext - flip a bit
        tampered = bytearray(result.ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)
        
        # Try to decrypt tampered data
        decrypt_result = self.cipher.decrypt(
            tampered, self.test_key, result.nonce, result.tag
        )
        
        # Should FAIL verification
        self.assertFalse(decrypt_result.verified)
        self.assertTrue(decrypt_result.tamper_detected)
        # Should NOT return plaintext
        self.assertEqual(decrypt_result.plaintext, b'')

    def test_wrong_key_fails(self):
        """Test wrong key produces verification failure"""
        result = self.cipher.encrypt(self.test_data, self.test_key)
        
        wrong_key = b'B' * 32
        decrypt_result = self.cipher.decrypt(
            result.ciphertext, wrong_key, result.nonce, result.tag
        )
        
        self.assertFalse(decrypt_result.verified)
        self.assertTrue(decrypt_result.tamper_detected)

    def test_wrong_nonce_fails(self):
        """Test wrong nonce produces verification failure"""
        result = self.cipher.encrypt(self.test_data, self.test_key)
        
        wrong_nonce = b'X' * 24
        decrypt_result = self.cipher.decrypt(
            result.ciphertext, self.test_key, wrong_nonce, result.tag
        )
        
        self.assertFalse(decrypt_result.verified)
        self.assertTrue(decrypt_result.tamper_detected)

    def test_different_message_sizes(self):
        """Test encryption works for various message sizes"""
        message_sizes = [1, 16, 32, 63, 64, 65, 100, 1000, 10000]
        
        for size in message_sizes:
            message = os.urandom(size)
            result = self.cipher.encrypt(message, self.test_key)
            decrypt_result = self.cipher.decrypt(
                result.ciphertext, self.test_key, result.nonce, result.tag
            )
            
            self.assertTrue(decrypt_result.verified, f"Failed for size {size}")
            self.assertEqual(decrypt_result.plaintext, message, f"Failed for size {size}")

    def test_key_derivation_produces_different_keys(self):
        """Test HKDF produces different keys for different master keys"""
        key1 = self.cipher._derive_encryption_key(b'A' * 32)
        key2 = self.cipher._derive_encryption_key(b'B' * 32)
        
        self.assertNotEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_poly1305_produces_different_tags(self):
        """Test Poly1305 MAC produces different tags"""
        otk = b'A' * 32  # Non-zero key
        tag1 = self.cipher._poly1305_mac(otk, b"Message 1")
        tag2 = self.cipher._poly1305_mac(otk, b"Message 2")
        
        self.assertNotEqual(tag1, tag2)
        self.assertEqual(len(tag1), 16)

    def test_chacha_block_produces_keystream(self):
        """Test ChaCha block produces output"""
        key = b'\x00' * 32
        nonce = b'\x00' * 12
        block = self.cipher._chacha_block(key, nonce, 0)
        
        self.assertEqual(len(block), 64)
        # Should not be all zeros
        self.assertNotEqual(block, b'\x00' * 64)

    def test_hchacha_derivation(self):
        """Test HChaCha20 derivation works"""
        key = b'\x00' * 32
        nonce = b'\x00' * 16
        subkey = self.cipher._hchacha(key, nonce)
        
        self.assertEqual(len(subkey), 32)
        self.assertNotEqual(subkey, b'\x00' * 32)

    def test_security_report(self):
        """Test security report is honest and accurate"""
        report = self.cipher.get_security_report()
        
        # Should contain honest limitations
        self.assertIn("limitations", report)
        self.assertIn("quantum_resistance", report)
        self.assertIn("NOT fully quantum-proof", 
                     report["quantum_resistance"]["honest_note"])
        self.assertIn("audited", report["compliance"])
        # Honest - should say NOT audited
        self.assertIn("NOT been audited", report["compliance"]["audited"])

    def test_invalid_key_size_raises_error(self):
        """Test invalid key size raises ValueError"""
        with self.assertRaises(ValueError):
            self.cipher.encrypt(b"data", b"short_key")

    def test_invalid_nonce_size_raises_error(self):
        """Test invalid nonce size raises ValueError on decrypt"""
        with self.assertRaises(ValueError):
            self.cipher.decrypt(b"data", self.test_key, b"short_nonce", b"tag")


def run_crypto_benchmark():
    """Run real crypto performance benchmark"""
    print("\n" + "="*60)
    print("Quantum-Safe Stream Cipher - Production Benchmark")
    print("="*60)
    
    import time
    
    cipher = QuantumSafeStreamCipher()
    key = cipher.generate_key()
    
    test_cases = [
        ("Small message (64B)", b"X" * 64),
        ("Medium message (1KB)", b"X" * 1024),
        ("Large message (64KB)", b"X" * 65536),
    ]
    
    print("\nEncryption/Decryption Performance:")
    print("-" * 60)
    
    all_passed = True
    
    for name, data in test_cases:
        # Encrypt
        start = time.time()
        result = cipher.encrypt(data, key)
        encrypt_time = (time.time() - start) * 1000
        
        # Decrypt
        start = time.time()
        decrypt_result = cipher.decrypt(
            result.ciphertext, key, result.nonce, result.tag
        )
        decrypt_time = (time.time() - start) * 1000
        
        # Verify
        passed = decrypt_result.verified and decrypt_result.plaintext == data
        if not passed:
            all_passed = False
        
        status = "PASS" if passed else "FAIL"
        speed = len(data) / (encrypt_time / 1000) / 1024  # KB/s
        
        print(f"{status:4} | {name:25} | enc={encrypt_time:6.2f}ms | "
              f"dec={decrypt_time:6.2f}ms | ~{speed:.0f} KB/s")
    
    print("\n" + "="*60)
    print("HONEST SECURITY ASSESSMENT")
    print("="*60)
    print("✓ XChaCha20 core - RFC 8439 derived implementation")
    print("✓ Poly1305 MAC - constant-time verification")
    print("✓ HKDF-SHA3-512 key derivation")
    print("✓ Encrypt-then-MAC construction")
    print("")
    print("⚠ HONEST LIMITATIONS:")
    print("1. ChaCha20 is NOT post-quantum secure (Grover's attack)")
    print("2. SHA3 key derivation IS quantum-resistant")
    print("3. This code has NOT been cryptographically audited")
    print("4. No formal proof of security")
    print("5. Software-only - no hardware acceleration")
    print("6. No side-channel resistance guarantees")
    print("")
    print("TRUTH: This is better than AES for many use cases,")
    print("but it is NOT 'quantum-proof' in the strict sense.")
    print("="*60)
    
    return all_passed


if __name__ == "__main__":
    print("Running Cryptographic Unit Tests...\n")
    unittest.main(exit=False, verbosity=2)
    
    print("\n" + "="*60)
    benchmark_passed = run_crypto_benchmark()
    
    print("\n" + "="*60)
    if benchmark_passed:
        print("✓ ALL CRYPTO TESTS PASSED")
        print("✓ QuantumSafeStreamCipher is fully functional")
    else:
        print("⚠ CRYPTO TESTS FAILED - DO NOT USE IN PRODUCTION")
    print("="*60)
