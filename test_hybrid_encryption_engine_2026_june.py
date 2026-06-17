"""
Test Suite for Quantum-Resistant Hybrid Encryption Engine
June 2026 Production Release
"""

import unittest
import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from hybrid_encryption_engine_2026_june import (
    QuantumResistantHybridEngine,
    EncryptionMode,
    SecurityLevel,
    EncryptionResult,
    DecryptionResult,
    HybridKeyPair
)


class TestQuantumResistantHybridEngine(unittest.TestCase):
    """Test suite for hybrid encryption engine"""
    
    def setUp(self):
        self.engine = QuantumResistantHybridEngine(SecurityLevel.LEVEL_5)
        self.key_pair = self.engine.generate_key_pair()
    
    def test_key_pair_generation(self):
        """Test hybrid key pair generation"""
        key_pair = self.engine.generate_key_pair()
        
        self.assertIsInstance(key_pair, HybridKeyPair)
        self.assertEqual(len(key_pair.classical_key), 32)  # AES-256
        self.assertEqual(len(key_pair.pqc_public_key), 32)  # SHA3-256
        self.assertEqual(len(key_pair.pqc_private_key), 192)  # ML-KEM-768
        self.assertEqual(key_pair.security_level, SecurityLevel.LEVEL_5)
    
    def test_basic_encryption_decryption(self):
        """Test basic encrypt/decrypt round trip"""
        plaintext = b"Hello, Quantum World! This is a secret message."
        
        # Encrypt
        result = self.engine.encrypt(
            plaintext,
            self.key_pair.pqc_public_key
        )
        
        self.assertIsInstance(result, EncryptionResult)
        self.assertEqual(len(result.nonce), 12)  # GCM nonce
        self.assertEqual(len(result.salt), 16)
        self.assertEqual(len(result.tag), 16)
        self.assertGreater(len(result.ciphertext), 0)
        
        # Decrypt
        decrypted = self.engine.decrypt(result, self.key_pair.pqc_private_key)
        
        self.assertIsInstance(decrypted, DecryptionResult)
        self.assertTrue(decrypted.verified)
        self.assertTrue(decrypted.integrity_check_passed)
        self.assertEqual(decrypted.plaintext, plaintext)
    
    def test_encryption_with_associated_data(self):
        """Test AEAD with associated data"""
        plaintext = b"Secret data"
        associated_data = b"Public metadata: document_id=12345"
        
        result = self.engine.encrypt(
            plaintext,
            self.key_pair.pqc_public_key,
            associated_data=associated_data
        )
        
        # Correct AD should work
        decrypted = self.engine.decrypt(
            result,
            self.key_pair.pqc_private_key,
            associated_data=associated_data
        )
        self.assertTrue(decrypted.verified)
        self.assertEqual(decrypted.plaintext, plaintext)
        
        # Wrong AD should fail
        decrypted_bad = self.engine.decrypt(
            result,
            self.key_pair.pqc_private_key,
            associated_data=b"Wrong metadata"
        )
        self.assertFalse(decrypted_bad.verified)
        self.assertFalse(decrypted_bad.integrity_check_passed)
    
    def test_tamper_detection(self):
        """Test that tampering with ciphertext is detected"""
        plaintext = b"Secret message"
        
        result = self.engine.encrypt(plaintext, self.key_pair.pqc_public_key)
        
        # Tamper with ciphertext
        tampered_ciphertext = bytearray(result.ciphertext)
        tampered_ciphertext[0] ^= 0xFF  # Flip first byte
        result.ciphertext = bytes(tampered_ciphertext)
        
        decrypted = self.engine.decrypt(result, self.key_pair.pqc_private_key)
        self.assertFalse(decrypted.verified)
        self.assertFalse(decrypted.integrity_check_passed)
    
    def test_wrong_key_rejection(self):
        """Test that wrong private key fails"""
        plaintext = b"Secret message"
        
        result = self.engine.encrypt(plaintext, self.key_pair.pqc_public_key)
        
        # Generate wrong key
        wrong_key_pair = self.engine.generate_key_pair()
        
        decrypted = self.engine.decrypt(result, wrong_key_pair.pqc_private_key)
        self.assertFalse(decrypted.verified)
    
    def test_encapsulation_decapsulation(self):
        """Test key encapsulation mechanism"""
        shared_secret1, encapsulated = self.engine.encapsulate_key(
            self.key_pair.pqc_public_key
        )
        
        shared_secret2 = self.engine.decapsulate_key(
            self.key_pair.pqc_private_key,
            encapsulated
        )
        
        self.assertEqual(shared_secret1, shared_secret2)
    
    def test_invalid_encapsulated_key(self):
        """Test detection of tampered encapsulated key"""
        _, encapsulated = self.engine.encapsulate_key(
            self.key_pair.pqc_public_key
        )
        
        # Tamper with encapsulated key
        tampered = encapsulated[:-1] + bytes([encapsulated[-1] ^ 0xFF])
        
        with self.assertRaises(ValueError):
            self.engine.decapsulate_key(
                self.key_pair.pqc_private_key,
                tampered
            )
    
    def test_streaming_encryption(self):
        """Test streaming encryption for large data"""
        chunks = [
            b"First chunk of data",
            b"Second chunk with more information",
            b"Third and final chunk"
        ]
        
        encrypted = self.engine.encrypt_streaming(
            chunks,
            self.key_pair.pqc_public_key
        )
        
        self.assertEqual(len(encrypted), 3)
        
        decrypted, all_verified = self.engine.decrypt_streaming(
            encrypted,
            self.key_pair.pqc_private_key
        )
        
        self.assertTrue(all_verified)
        self.assertEqual(decrypted, b"".join(chunks))
    
    def test_different_security_levels(self):
        """Test all security levels work"""
        for level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_3, SecurityLevel.LEVEL_5]:
            engine = QuantumResistantHybridEngine(level)
            key_pair = engine.generate_key_pair()
            
            plaintext = f"Test for security level {level.value}".encode()
            result = engine.encrypt(plaintext, key_pair.pqc_public_key)
            decrypted = engine.decrypt(result, key_pair.pqc_private_key)
            
            self.assertTrue(decrypted.verified)
            self.assertEqual(decrypted.plaintext, plaintext)
            self.assertEqual(result.security_level, level)
    
    def test_empty_plaintext(self):
        """Test encryption of empty data"""
        result = self.engine.encrypt(b"", self.key_pair.pqc_public_key)
        decrypted = self.engine.decrypt(result, self.key_pair.pqc_private_key)
        
        self.assertTrue(decrypted.verified)
        self.assertEqual(decrypted.plaintext, b"")
    
    def test_large_data(self):
        """Test encryption of larger data (100KB)"""
        import os
        large_data = os.urandom(100 * 1024)  # 100KB
        
        result = self.engine.encrypt(large_data, self.key_pair.pqc_public_key)
        decrypted = self.engine.decrypt(result, self.key_pair.pqc_private_key)
        
        self.assertTrue(decrypted.verified)
        self.assertEqual(decrypted.plaintext, large_data)
    
    def test_security_report(self):
        """Test security compliance report generation"""
        report = self.engine.get_security_report()
        
        self.assertIn("engine", report)
        self.assertIn("nist_compliant", report)
        self.assertTrue(report["nist_compliant"])
        self.assertTrue(report["quantum_resistant"])
        self.assertIn("algorithms", report)
        self.assertEqual(report["algorithms"]["bulk_encryption"], "AES-256-GCM")
    
    def test_cnsa_compliance(self):
        """Test CNSA 2.0 compliance for Level 5"""
        engine_level5 = QuantumResistantHybridEngine(SecurityLevel.LEVEL_5)
        report = engine_level5.get_security_report()
        self.assertTrue(report["cnsa_2.0_compliant"])
        
        engine_level1 = QuantumResistantHybridEngine(SecurityLevel.LEVEL_1)
        report = engine_level1.get_security_report()
        self.assertFalse(report["cnsa_2.0_compliant"])
    
    def test_benchmark(self):
        """Test performance benchmark"""
        # Small benchmark for testing
        metrics = self.engine.benchmark(data_size=100 * 1024)  # 100KB
        
        self.assertIn("encrypt_time_ms", metrics)
        self.assertIn("decrypt_time_ms", metrics)
        self.assertIn("encrypt_throughput_mbps", metrics)
        self.assertIn("verified", metrics)
        self.assertTrue(metrics["verified"])
        self.assertGreater(metrics["encrypt_throughput_mbps"], 0)
    
    def test_encryption_modes(self):
        """Test all encryption modes"""
        plaintext = b"Test message"
        
        for mode in EncryptionMode:
            result = self.engine.encrypt(
                plaintext,
                self.key_pair.pqc_public_key,
                mode=mode
            )
            self.assertEqual(result.mode, mode)
            
            decrypted = self.engine.decrypt(result, self.key_pair.pqc_private_key)
            self.assertTrue(decrypted.verified)
            self.assertEqual(decrypted.plaintext, plaintext)
    
    def test_metadata_tracking(self):
        """Test metadata is properly tracked"""
        plaintext = b"Test message of known length"
        result = self.engine.encrypt(plaintext, self.key_pair.pqc_public_key)
        
        self.assertIn("plaintext_size", result.metadata)
        self.assertIn("ciphertext_size", result.metadata)
        self.assertIn("overhead_ratio", result.metadata)
        self.assertEqual(result.metadata["plaintext_size"], len(plaintext))
    
    def test_timing_information(self):
        """Test timing information is captured"""
        result = self.engine.encrypt(b"Test", self.key_pair.pqc_public_key)
        self.assertGreater(result.timestamp, 0)
        
        decrypted = self.engine.decrypt(result, self.key_pair.pqc_private_key)
        self.assertGreater(decrypted.timestamp, 0)
    
    def test_file_encryption(self):
        """Test file encryption functionality"""
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b"Test file content for encryption")
            input_path = f.name
        
        output_path = input_path + ".encrypted"
        
        try:
            stats = self.engine.encrypt_file(
                input_path,
                output_path,
                self.key_pair.pqc_public_key
            )
            
            self.assertTrue(stats["success"])
            self.assertGreater(stats["file_size"], 0)
            self.assertTrue(os.path.exists(output_path))
            
        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def test_kdf_derivation(self):
        """Test KDF produces consistent keys"""
        secret = b"test_secret"
        salt = b"test_salt"
        
        key1 = self.engine._kdf_derive(secret, salt)
        key2 = self.engine._kdf_derive(secret, salt)
        
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)  # AES-256 key size
    
    def test_public_key_derivation(self):
        """Test public key derivation is deterministic"""
        private = b"test_private_key"
        
        pub1 = self.engine._derive_public_key(private)
        pub2 = self.engine._derive_public_key(private)
        
        self.assertEqual(pub1, pub2)
        self.assertEqual(len(pub1), 32)  # SHA3-256


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestQuantumResistantHybridEngine)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print(f"{'='*60}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
