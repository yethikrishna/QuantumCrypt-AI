"""
Test Coverage for Post-Quantum KEM Engine v85
DIMENSION C - TEST COVERAGE EXPANSION
Session 146 - June 2026

Comprehensive tests for the new KEM feature:
- Basic key generation, encapsulation, decapsulation
- All security levels (L1, L3, L5)
- Hybrid mode testing
- Invalid ciphertext handling
- Edge cases and boundary conditions
- Backward compatibility verification
"""

import unittest
import hmac
import os
import sys

# Add quantum_crypto to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypto'))

from feature_expansion_pq_kem_key_encapsulation_v85_2026_june import (
    create_kem_engine,
    kem_keygen,
    kem_encapsulate,
    kem_decapsulate,
    get_module_metadata,
    KEMSecurityLevel,
    KyberStyleKEM,
    HybridPQCryptoKEM
)

class TestKEMBasicFunctionality(unittest.TestCase):
    """Test basic KEM functionality"""
    
    def test_module_metadata(self):
        """Verify module metadata is correct"""
        metadata = get_module_metadata()
        self.assertEqual(metadata['version'], '85.0.0')
        self.assertEqual(metadata['dimension'], 'A - Feature Expansion')
        self.assertEqual(metadata['stability'], 'STABLE')
        self.assertTrue(metadata['backward_compatible'])
        self.assertTrue(metadata['add_only'])
        self.assertIn('KYBER-STYLE-KEM', metadata['algorithms'])
        self.assertIn('HYBRID-CLASSICAL-PQ-KEM', metadata['algorithms'])
    
    def test_create_engine_default(self):
        """Test creating engine with default parameters"""
        engine = create_kem_engine()
        self.assertIsInstance(engine, KyberStyleKEM)
        self.assertEqual(engine.security_level, KEMSecurityLevel.L3)
    
    def test_create_engine_l1(self):
        """Test creating engine with L1 security level"""
        engine = create_kem_engine(KEMSecurityLevel.L1)
        self.assertEqual(engine.security_level, KEMSecurityLevel.L1)
    
    def test_create_engine_l5(self):
        """Test creating engine with L5 security level"""
        engine = create_kem_engine(KEMSecurityLevel.L5)
        self.assertEqual(engine.security_level, KEMSecurityLevel.L5)
    
    def test_create_hybrid_engine(self):
        """Test creating hybrid engine"""
        engine = create_kem_engine(hybrid=True)
        self.assertIsInstance(engine, HybridPQCryptoKEM)

class TestKEMKeyGeneration(unittest.TestCase):
    """Test KEM key generation"""
    
    def test_keygen_l3(self):
        """Test key generation for L3 security level"""
        engine = create_kem_engine(KEMSecurityLevel.L3)
        pk, sk = kem_keygen(engine)
        
        self.assertIsNotNone(pk)
        self.assertIsNotNone(sk)
        self.assertEqual(pk.security_level, KEMSecurityLevel.L3)
        self.assertEqual(sk.security_level, KEMSecurityLevel.L3)
        self.assertGreater(len(pk.key_data), 0)
        self.assertGreater(len(sk.key_data), 0)
        self.assertEqual(len(sk.z), 32)  # z should be 32 bytes
    
    def test_keygen_l1(self):
        """Test key generation for L1 security level"""
        engine = create_kem_engine(KEMSecurityLevel.L1)
        pk, sk = kem_keygen(engine)
        
        self.assertEqual(pk.security_level, KEMSecurityLevel.L1)
        self.assertEqual(sk.security_level, KEMSecurityLevel.L1)
    
    def test_keygen_l5(self):
        """Test key generation for L5 security level"""
        engine = create_kem_engine(KEMSecurityLevel.L5)
        pk, sk = kem_keygen(engine)
        
        self.assertEqual(pk.security_level, KEMSecurityLevel.L5)
        self.assertEqual(sk.security_level, KEMSecurityLevel.L5)
    
    def test_keygen_deterministic_with_seed(self):
        """Test deterministic key generation with seed"""
        engine = create_kem_engine(KEMSecurityLevel.L3)
        seed = os.urandom(48)
        
        pk1, sk1 = engine.keygen(seed)
        pk2, sk2 = engine.keygen(seed)
        
        # Same seed should produce same keys
        self.assertEqual(pk1.key_data, pk2.key_data)
        # Note: z is random even with same seed for FO security

class TestKEMEncapsulationDecapsulation(unittest.TestCase):
    """Test core encapsulation/decapsulation functionality"""
    
    def test_encapsulate_decapuslate_match_l3(self):
        """Test that shared secrets match for L3"""
        engine = create_kem_engine(KEMSecurityLevel.L3)
        pk, sk = kem_keygen(engine)
        ct, ss_encap = kem_encapsulate(engine, pk)
        ss_decap = kem_decapsulate(engine, sk, pk, ct)
        
        self.assertTrue(hmac.compare_digest(ss_encap.secret, ss_decap.secret))
        self.assertTrue(ss_decap.authenticated)
        self.assertEqual(len(ss_encap.secret), 48)  # L3 = 48 bytes
    
    def test_encapsulate_decapuslate_match_l1(self):
        """Test that shared secrets match for L1"""
        engine = create_kem_engine(KEMSecurityLevel.L1)
        pk, sk = kem_keygen(engine)
        ct, ss_encap = kem_encapsulate(engine, pk)
        ss_decap = kem_decapsulate(engine, sk, pk, ct)
        
        self.assertTrue(hmac.compare_digest(ss_encap.secret, ss_decap.secret))
        self.assertEqual(len(ss_encap.secret), 32)  # L1 = 32 bytes
    
    def test_encapsulate_decapuslate_match_l5(self):
        """Test that shared secrets match for L5"""
        engine = create_kem_engine(KEMSecurityLevel.L5)
        pk, sk = kem_keygen(engine)
        ct, ss_encap = kem_encapsulate(engine, pk)
        ss_decap = kem_decapsulate(engine, sk, pk, ct)
        
        self.assertTrue(hmac.compare_digest(ss_encap.secret, ss_decap.secret))
        self.assertEqual(len(ss_encap.secret), 64)  # L5 = 64 bytes
    
    def test_multiple_encapsulations_different(self):
        """Test that multiple encapsulations produce different ciphertexts"""
        engine = create_kem_engine(KEMSecurityLevel.L3)
        pk, sk = kem_keygen(engine)
        
        ct1, ss1 = kem_encapsulate(engine, pk)
        ct2, ss2 = kem_encapsulate(engine, pk)
        
        # Different ciphertexts
        self.assertNotEqual(ct1.ciphertext_data, ct2.ciphertext_data)
        # Different shared secrets
        self.assertFalse(hmac.compare_digest(ss1.secret, ss2.secret))
    
    def test_wrong_private_key(self):
        """Test decapsulation with wrong private key"""
        engine = create_kem_engine(KEMSecurityLevel.L3)
        pk1, sk1 = kem_keygen(engine)
        pk2, sk2 = kem_keygen(engine)
        
        ct, ss_encap = kem_encapsulate(engine, pk1)
        ss_decap = kem_decapsulate(engine, sk2, pk1, ct)
        
        # Wrong key should fail authentication but still produce a secret (implicit rejection)
        self.assertFalse(ss_decap.authenticated)
        # Shared secret should NOT match
        self.assertFalse(hmac.compare_digest(ss_encap.secret, ss_decap.secret))

class TestKEMTamperResistance(unittest.TestCase):
    """Test KEM tamper resistance and CCA2 security"""
    
    def test_ciphertext_tampering_detected(self):
        """Test that tampered ciphertext is detected"""
        engine = create_kem_engine(KEMSecurityLevel.L3)
        pk, sk = kem_keygen(engine)
        ct, ss_encap = kem_encapsulate(engine, pk)
        
        # Tamper with ciphertext
        tampered_data = bytearray(ct.ciphertext_data)
        tampered_data[0] ^= 0xFF  # Flip first byte
        tampered_ct = type(ct)(
            ciphertext_data=bytes(tampered_data),
            security_level=ct.security_level,
            algorithm=ct.algorithm
        )
        
        ss_decap = kem_decapsulate(engine, sk, pk, tampered_ct)
        
        # Tampering should be detected
        self.assertFalse(ss_decap.authenticated)
        self.assertFalse(hmac.compare_digest(ss_encap.secret, ss_decap.secret))
    
    def test_truncated_ciphertext(self):
        """Test handling of truncated ciphertext"""
        engine = create_kem_engine(KEMSecurityLevel.L3)
        pk, sk = kem_keygen(engine)
        ct, ss_encap = kem_encapsulate(engine, pk)
        
        # Truncate ciphertext
        truncated_data = ct.ciphertext_data[:len(ct.ciphertext_data)//2]
        truncated_ct = type(ct)(
            ciphertext_data=truncated_data,
            security_level=ct.security_level,
            algorithm=ct.algorithm
        )
        
        # Should handle gracefully (may raise or produce non-authenticated)
        try:
            ss_decap = kem_decapsulate(engine, sk, pk, truncated_ct)
            self.assertFalse(ss_decap.authenticated)
        except Exception:
            # Exception is also acceptable behavior
            pass

class TestHybridKEM(unittest.TestCase):
    """Test Hybrid Classical + Post-Quantum KEM"""
    
    def test_hybrid_keygen(self):
        """Test hybrid key generation"""
        engine = create_kem_engine(hybrid=True)
        pk, sk = kem_keygen(engine)
        
        self.assertIsNotNone(pk)
        self.assertIsNotNone(sk)
        self.assertEqual(pk.algorithm, "HYBRID-CLASSICAL-PQ-KEM")
    
    def test_hybrid_encapsulate_decapuslate(self):
        """Test hybrid encapsulation/decapsulation"""
        engine = create_kem_engine(hybrid=True)
        pk, sk = kem_keygen(engine)
        ct, ss_encap = kem_encapsulate(engine, pk)
        ss_decap = kem_decapsulate(engine, sk, pk, ct)
        
        self.assertTrue(hmac.compare_digest(ss_encap.secret, ss_decap.secret))
        self.assertTrue(ss_decap.authenticated)
        self.assertEqual(len(ss_encap.secret), 64)  # SHA3-512 output

class TestKEMEdgeCases(unittest.TestCase):
    """Test KEM edge cases"""
    
    def test_external_randomness_provided(self):
        """Test encapsulation with explicit external randomness"""
        engine = create_kem_engine(KEMSecurityLevel.L3)
        pk, sk = kem_keygen(engine)
        
        external_rand = os.urandom(32)
        ct1, ss1 = engine.encapsulate(pk, external_rand)
        ct2, ss2 = engine.encapsulate(pk, external_rand)
        
        # Same external randomness should produce same ciphertext
        self.assertEqual(ct1.ciphertext_data, ct2.ciphertext_data)
        self.assertTrue(hmac.compare_digest(ss1.secret, ss2.secret))
    
    def test_empty_external_randomness(self):
        """Test that None external randomness works"""
        engine = create_kem_engine(KEMSecurityLevel.L3)
        pk, sk = kem_keygen(engine)
        
        ct, ss = engine.encapsulate(pk, None)
        ss_decap = kem_decapsulate(engine, sk, pk, ct)
        
        self.assertTrue(hmac.compare_digest(ss.secret, ss_decap.secret))

class TestKEMBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - no existing code broken"""
    
    def test_no_import_conflicts(self):
        """Verify module imports without conflicts"""
        # This test passes if we got here without import errors
        pass
    
    def test_public_api_stable(self):
        """Test that public API functions exist and work"""
        # All these should be callable
        self.assertTrue(callable(create_kem_engine))
        self.assertTrue(callable(kem_keygen))
        self.assertTrue(callable(kem_encapsulate))
        self.assertTrue(callable(kem_decapsulate))
        self.assertTrue(callable(get_module_metadata))

def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestKEMBasicFunctionality))
    suite.addTests(loader.loadTestsFromTestCase(TestKEMKeyGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestKEMEncapsulationDecapsulation))
    suite.addTests(loader.loadTestsFromTestCase(TestKEMTamperResistance))
    suite.addTests(loader.loadTestsFromTestCase(TestHybridKEM))
    suite.addTests(loader.loadTestsFromTestCase(TestKEMEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestKEMBackwardCompatibility))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print(f"{'='*60}")
    
    return result

if __name__ == '__main__':
    print("=" * 60)
    print("Post-Quantum KEM Engine v85 - Comprehensive Test Suite")
    print("DIMENSION C - Test Coverage Expansion")
    print("Session 146 - June 2026")
    print("=" * 60)
    print()
    
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
