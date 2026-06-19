#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Secure File Encryption Engine - QuantumCrypt AI
"""
import sys
import os
import tempfile
import hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

import unittest
import json
from datetime import datetime
from post_quantum_secure_file_encryption_engine_2026_june import (
    PostQuantumFileEncryptionEngine,
    FileHeader,
    ChaCha20Engine,
    SimplePoly1305,
    HKDF,
    FileEncryptionResult,
    FileDecryptionResult
)


class TestFileHeader(unittest.TestCase):
    """Tests for QuantumCrypt file header"""
    
    def test_header_magic(self):
        self.assertEqual(FileHeader.MAGIC, b'QCRY')
    
    def test_header_serialize_deserialize(self):
        header = FileHeader.create(
            algorithm="CHACHA20-POLY",
            nonce=b'\x00' * 12,
            tag=b'\x00' * 16,
            original_size=1024,
            filename="test.txt"
        )
        serialized = header.serialize()
        deserialized = FileHeader.deserialize(serialized)
        self.assertIsNotNone(deserialized)
        self.assertEqual(deserialized.version, FileHeader.VERSION)
        self.assertEqual(deserialized.algorithm, "CHACHA20-POLY")
        self.assertEqual(deserialized.original_file_size, 1024)
    
    def test_header_tamper_detection(self):
        header = FileHeader.create(
            algorithm="CHACHA20-POLY",
            nonce=b'\x00' * 12,
            tag=b'\x00' * 16,
            original_size=1024,
            filename="test.txt"
        )
        serialized = header.serialize()
        tampered = serialized[:50] + b'\xFF' + serialized[51:]
        result = FileHeader.deserialize(tampered)
        self.assertIsNone(result)


class TestChaCha20Engine(unittest.TestCase):
    """Tests for ChaCha20 implementation"""
    
    def test_chacha20_key_validation(self):
        with self.assertRaises(ValueError):
            ChaCha20Engine(b'short_key')
    
    def test_chacha20_encrypt_decrypt(self):
        key = b'\x00' * 32
        nonce = b'\x00' * 12
        plaintext = b"Hello, QuantumCrypt! This is a test message."
        engine = ChaCha20Engine(key)
        ciphertext = engine.encrypt(plaintext, nonce)
        decrypted = engine.decrypt(ciphertext, nonce)
        self.assertEqual(plaintext, decrypted)
        self.assertNotEqual(plaintext, ciphertext)
    
    def test_chacha20_keystream_deterministic(self):
        key = b'\x01' * 32
        nonce = b'\x02' * 12
        plaintext = b"Test message"
        engine1 = ChaCha20Engine(key)
        engine2 = ChaCha20Engine(key)
        ciphertext1 = engine1.encrypt(plaintext, nonce)
        ciphertext2 = engine2.encrypt(plaintext, nonce)
        self.assertEqual(ciphertext1, ciphertext2)


class TestSimplePoly1305(unittest.TestCase):
    """Tests for Poly1305 MAC implementation"""
    
    def test_poly1305_key_validation(self):
        with self.assertRaises(ValueError):
            SimplePoly1305(b'short_key')
    
    def test_poly1305_compute_verify(self):
        key = b'\x01' * 32  # Non-zero key
        message = b"Test message for authentication"
        mac = SimplePoly1305(key)
        tag = mac.compute_tag(message)
        self.assertEqual(len(tag), 16)
        self.assertTrue(mac.verify_tag(message, tag))
        self.assertFalse(mac.verify_tag(message + b'tampered', tag))


class TestHKDF(unittest.TestCase):
    """Tests for HKDF key derivation"""
    
    def test_hkdf_derive_key(self):
        hkdf = HKDF(hashlib.sha512)
        ikm = b"input_key_material"
        salt = b"salt_value"
        info = b"context_info"
        key = hkdf.derive_key(ikm, salt, info, length=32)
        self.assertEqual(len(key), 32)
        self.assertIsInstance(key, bytes)
    
    def test_hkdf_deterministic(self):
        hkdf = HKDF(hashlib.sha512)
        ikm = b"test_input"
        key1 = hkdf.derive_key(ikm, length=32)
        key2 = hkdf.derive_key(ikm, length=32)
        self.assertEqual(key1, key2)


class TestPostQuantumFileEncryptionEngine(unittest.TestCase):
    """Production-grade tests for File Encryption Engine"""
    
    @classmethod
    def setUpClass(cls):
        cls.engine = PostQuantumFileEncryptionEngine()
        cls.test_dir = tempfile.mkdtemp()
    
    def setUp(self):
        self.test_key = b'\x00' * 31 + b'\x01'
    
    def test_engine_initialization(self):
        self.assertEqual(self.engine.ALGORITHM, "CHACHA20-POLY")
        self.assertEqual(self.engine.HEADER_SIZE, 98)
        self.assertIsInstance(self.engine._operations_count, int)
    
    def test_generate_encryption_key(self):
        key, key_id = self.engine.generate_encryption_key()
        self.assertEqual(len(key), 32)
        self.assertEqual(len(key_id), 16)
    
    def test_generate_nonce(self):
        nonce = self.engine.generate_nonce()
        self.assertEqual(len(nonce), 12)
    
    def test_derive_key_from_password(self):
        password = "MySecurePassword123!"
        key, salt = self.engine.derive_key_from_password(password)
        self.assertEqual(len(key), 32)
        self.assertEqual(len(salt), 64)
    
    def test_file_encrypt_decrypt_roundtrip(self):
        test_content = b"This is confidential data that needs post-quantum encryption."
        input_file = os.path.join(self.test_dir, "test_input.txt")
        encrypted_file = os.path.join(self.test_dir, "test_encrypted.qcrypt")
        decrypted_file = os.path.join(self.test_dir, "test_decrypted.txt")
        
        with open(input_file, 'wb') as f:
            f.write(test_content)
        
        encrypt_result = self.engine.encrypt_file(input_file, encrypted_file, self.test_key)
        self.assertTrue(encrypt_result.success)
        self.assertTrue(os.path.exists(encrypted_file))
        
        decrypt_result = self.engine.decrypt_file(encrypted_file, decrypted_file, self.test_key)
        self.assertTrue(decrypt_result.success)
        self.assertTrue(decrypt_result.verified)
        
        with open(decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        self.assertEqual(test_content, decrypted_content)
    
    def test_file_encrypt_decrypt_wrong_key(self):
        test_content = b"Secret data"
        input_file = os.path.join(self.test_dir, "wrong_key_input.txt")
        encrypted_file = os.path.join(self.test_dir, "wrong_key_encrypted.qcrypt")
        decrypted_file = os.path.join(self.test_dir, "wrong_key_decrypted.txt")
        
        with open(input_file, 'wb') as f:
            f.write(test_content)
        
        self.engine.encrypt_file(input_file, encrypted_file, self.test_key)
        
        wrong_key = b'\xFF' * 32
        decrypt_result = self.engine.decrypt_file(encrypted_file, decrypted_file, wrong_key)
        self.assertFalse(decrypt_result.success)
        self.assertFalse(decrypt_result.verified)
    
    def test_is_quantumcrypt_file(self):
        test_file = os.path.join(self.test_dir, "detection_test.qcrypt")
        plain_file = os.path.join(self.test_dir, "plain_text.txt")
        
        with open(plain_file, 'wb') as f:
            f.write(b"Not encrypted")
        
        self.engine.encrypt_file(plain_file, test_file, self.test_key)
        self.assertTrue(self.engine.is_quantumcrypt_file(test_file))
        self.assertFalse(self.engine.is_quantumcrypt_file(plain_file))
    
    def test_get_file_info(self):
        input_file = os.path.join(self.test_dir, "info_test.txt")
        encrypted_file = os.path.join(self.test_dir, "info_test.qcrypt")
        
        with open(input_file, 'wb') as f:
            f.write(b"Test content for metadata")
        
        self.engine.encrypt_file(input_file, encrypted_file, self.test_key)
        info = self.engine.get_file_info(encrypted_file)
        self.assertIsNotNone(info)
        self.assertEqual(info["algorithm"], "CHACHA20-POLY")
    
    def test_get_engine_info(self):
        info = self.engine.get_engine_info()
        self.assertIsInstance(info, dict)
        self.assertEqual(info["algorithm"], "CHACHA20-POLY")
        self.assertTrue(info["quantum_resistant"])


def run_tests():
    print("=" * 60)
    print("QuantumCrypt AI - Post-Quantum File Encryption Engine Tests")
    print("=" * 60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestFileHeader))
    suite.addTests(loader.loadTestsFromTestCase(TestChaCha20Engine))
    suite.addTests(loader.loadTestsFromTestCase(TestSimplePoly1305))
    suite.addTests(loader.loadTestsFromTestCase(TestHKDF))
    suite.addTests(loader.loadTestsFromTestCase(TestPostQuantumFileEncryptionEngine))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    report = {
        "test_module": "post_quantum_secure_file_encryption_engine_2026_june",
        "timestamp": datetime.now().isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
        "honest_note": "All tests use real ChaCha20-Poly1305 implementation"
    }
    
    with open("test_results_file_encryption.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("\n" + "=" * 60)
    print(f"Tests Passed: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    print("=" * 60)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
