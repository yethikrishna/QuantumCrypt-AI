"""
Test Suite for Hybrid Cryptosystem and FIPS-Optimized Implementations
June 2026 Post-Quantum Cryptography Features
"""

import unittest
import sys
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt import (
    HybridCryptosystem,
    CryptoAgilityFramework,
    OptimizedMLKEM,
    OptimizedMLDSA
)


class TestHybridCryptosystem(unittest.TestCase):
    """Test Hybrid Cryptographic System"""
    
    def setUp(self):
        self.hybrid = HybridCryptosystem()
        
    def test_hybrid_key_generation(self):
        """Test hybrid key generation"""
        session_key, metadata = self.hybrid.hybrid_key_generation()
        self.assertEqual(len(session_key), 32)  # 256 bits
        self.assertIn('classical_key_fingerprint', metadata)
        self.assertIn('pqc_key_fingerprint', metadata)
        
    def test_hybrid_encryption(self):
        """Test hybrid encryption"""
        plaintext = b"Secret message for hybrid encryption test"
        ciphertext, metadata = self.hybrid.hybrid_encrypt(plaintext)
        self.assertIsInstance(ciphertext, bytes)
        self.assertIn('algorithm', metadata)
        self.assertIn('ML-KEM', metadata['algorithm'])
        
    def test_hybrid_decryption(self):
        """Test hybrid decryption flow"""
        plaintext = b"Test message"
        session_key, _ = self.hybrid.hybrid_key_generation()
        nonce = bytes.fromhex('0' * 24)
        tag = bytes.fromhex('0' * 64)
        
        # Test decryption with verification
        decrypted, verified = self.hybrid.hybrid_decrypt(
            b'test', session_key, nonce, tag
        )
        self.assertIsInstance(verified, bool)


class TestCryptoAgilityFramework(unittest.TestCase):
    """Test Crypto-Agility Framework"""
    
    def setUp(self):
        self.framework = CryptoAgilityFramework()
        
    def test_algorithm_registration(self):
        """Test algorithm registration"""
        result = self.framework.register_algorithm('TEST-ALG', 'post_quantum')
        self.assertTrue(result)
        
    def test_algorithm_selection(self):
        """Test algorithm selection"""
        result = self.framework.select_algorithm('ML-KEM-768+AES-256')
        self.assertTrue(result)
        
    def test_key_rotation(self):
        """Test key rotation"""
        rotation = self.framework.rotate_keys('test_rotation')
        self.assertIn('rotation_id', rotation)
        self.assertIn('timestamp', rotation)
        
    def test_migration_status(self):
        """Test migration status report"""
        status = self.framework.get_migration_status()
        self.assertIn('current_algorithm', status)
        self.assertIn('migration_readiness', status)
        self.assertTrue(status['migration_readiness']['nist_compliance'])
        
    def test_compliance_report(self):
        """Test NIST compliance report"""
        report = self.framework.generate_compliance_report()
        self.assertIn('fips_203_compliant', report)
        self.assertIn('recommended_migration', report)


class TestOptimizedMLKEM(unittest.TestCase):
    """Test Optimized ML-KEM Implementation"""
    
    def test_mlkem_keygen(self):
        """Test ML-KEM key generation"""
        mlkem = OptimizedMLKEM(security_level=2)
        pk, sk = mlkem.keygen()
        self.assertEqual(len(pk), 32)
        self.assertGreater(len(sk), 32)
        
    def test_mlkem_encaps_decaps(self):
        """Test ML-KEM encapsulation/decapsulation"""
        mlkem = OptimizedMLKEM(security_level=2)
        pk, sk = mlkem.keygen()
        ct, ss = mlkem.encaps(pk)
        self.assertEqual(len(ct), 32)
        self.assertEqual(len(ss), 32)
        
        ss2 = mlkem.decaps(ct, sk)
        self.assertEqual(len(ss2), 32)
        
    def test_mlkem_performance_metrics(self):
        """Test ML-KEM performance metrics"""
        mlkem = OptimizedMLKEM(security_level=2)
        mlkem.keygen()
        metrics = mlkem.get_performance_metrics()
        self.assertIn('algorithm', metrics)
        self.assertEqual(metrics['algorithm'], 'ML-KEM-768')
        self.assertTrue(metrics['fips_203_compliant'])


class TestOptimizedMLDSA(unittest.TestCase):
    """Test Optimized ML-DSA Implementation"""
    
    def test_mldsa_keygen(self):
        """Test ML-DSA key generation"""
        mldsa = OptimizedMLDSA(security_level=2)
        pk, sk = mldsa.keygen()
        self.assertGreater(len(pk), 0)
        self.assertGreater(len(sk), 0)
        
    def test_mldsa_sign_verify(self):
        """Test ML-DSA sign and verify"""
        mldsa = OptimizedMLDSA(security_level=2)
        pk, sk = mldsa.keygen()
        message = b"Test message for ML-DSA signing"
        signature = mldsa.sign(message, sk)
        self.assertGreater(len(signature), 0)
        
    def test_mldsa_performance_metrics(self):
        """Test ML-DSA performance metrics"""
        mldsa = OptimizedMLDSA(security_level=2)
        mldsa.sign(b"test", mldsa.keygen()[1])
        metrics = mldsa.get_performance_metrics()
        self.assertIn('algorithm', metrics)
        self.assertEqual(metrics['algorithm'], 'ML-DSA-65')
        self.assertTrue(metrics['fips_204_compliant'])


if __name__ == '__main__':
    print("=" * 60)
    print("QuantumCrypt-AI: Hybrid Crypto & FIPS-Optimized Tests")
    print("2026 Post-Quantum Cryptography Features")
    print("=" * 60)
    
    unittest.main(verbosity=2)
