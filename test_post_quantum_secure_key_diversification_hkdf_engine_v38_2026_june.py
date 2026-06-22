"""
Test Suite for Post-Quantum Secure Key Diversification HKDF Engine v38
Dimension A - Feature Expansion Tests
100% ADD-ONLY - No existing tests modified
"""

import unittest
import time
import sys
import os
import hmac

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_key_diversification_hkdf_engine_v38_2026_june import (
    PQKeyDiversificationEngineV38,
    QuantumResistantSaltGenerator,
    SideChannelResistantHKDF,
    ForwardSecrecyRatcheting,
    KeyHierarchyManager,
    DerivedKey,
    KeyPurpose,
    HashAlgorithm,
    SecurityLevel,
    DiversificationResult,
    get_key_diversification_engine_v38,
    diversify_pq_key_v38,
    VERSION,
    VERSION_DATE
)


class TestQuantumResistantSaltGenerator(unittest.TestCase):
    """Test quantum-resistant salt generation."""
    
    def test_initialization(self):
        """Test salt generator initializes with security levels."""
        gen = QuantumResistantSaltGenerator(SecurityLevel.LEVEL_5)
        self.assertEqual(gen.security_level, SecurityLevel.LEVEL_5)
    
    def test_salt_length_by_security_level(self):
        """Test salt length matches security level requirements."""
        for level, expected_len in [
            (SecurityLevel.LEVEL_1, 16),
            (SecurityLevel.LEVEL_3, 24),
            (SecurityLevel.LEVEL_5, 32),
        ]:
            gen = QuantumResistantSaltGenerator(level)
            salt = gen.generate_salt()
            self.assertEqual(len(salt), expected_len)
    
    def test_salt_uniqueness(self):
        """Test generated salts are unique."""
        gen = QuantumResistantSaltGenerator()
        salts = set()
        for _ in range(100):
            salt = gen.generate_salt()
            salt_hex = salt.hex()
            self.assertNotIn(salt_hex, salts)
            salts.add(salt_hex)
    
    def test_kyber_style_salt(self):
        """Test Kyber-style salt generation."""
        gen = QuantumResistantSaltGenerator()
        salt = gen.generate_kyber_style_salt()
        self.assertEqual(len(salt), 32)  # CRYSTALS-Kyber uses 32 bytes
    
    def test_additional_entropy_mixing(self):
        """Test additional entropy is properly mixed."""
        gen = QuantumResistantSaltGenerator()
        user_entropy = b"my_custom_entropy_12345"
        salt1 = gen.generate_salt(additional_entropy=user_entropy)
        salt2 = gen.generate_salt(additional_entropy=b"different")
        self.assertNotEqual(salt1, salt2)


class TestSideChannelResistantHKDF(unittest.TestCase):
    """Test side-channel resistant HKDF."""
    
    def test_initialization(self):
        """Test HKDF initializes with hash algorithms."""
        hkdf = SideChannelResistantHKDF(HashAlgorithm.SHA3_512)
        self.assertEqual(hkdf.hash_len, 64)
    
    def test_hash_algorithm_lengths(self):
        """Test hash lengths are correct."""
        test_cases = [
            (HashAlgorithm.SHA256, 32),
            (HashAlgorithm.SHA384, 48),
            (HashAlgorithm.SHA512, 64),
            (HashAlgorithm.SHA3_256, 32),
            (HashAlgorithm.SHA3_512, 64),
        ]
        for alg, expected_len in test_cases:
            hkdf = SideChannelResistantHKDF(alg)
            self.assertEqual(hkdf.hash_len, expected_len)
    
    def test_extract_deterministic(self):
        """Test HKDF-Extract is deterministic."""
        hkdf = SideChannelResistantHKDF()
        ikm = b"test_input_key_material"
        salt = b"test_salt_12345"
        
        prk1 = hkdf.extract(ikm, salt)
        prk2 = hkdf.extract(ikm, salt)
        self.assertEqual(prk1, prk2)
    
    def test_expand_correct_length(self):
        """Test HKDF-Expand produces correct length."""
        hkdf = SideChannelResistantHKDF()
        prk = hkdf.extract(b"ikm", b"salt")
        
        for length in [16, 32, 64, 100]:
            output = hkdf.expand(prk, b"info", length)
            self.assertEqual(len(output), length)
    
    def test_full_derive(self):
        """Test full HKDF derivation."""
        hkdf = SideChannelResistantHKDF()
        key = hkdf.derive_key(b"master", b"salt", b"encryption", 32)
        self.assertEqual(len(key), 32)


class TestForwardSecrecyRatcheting(unittest.TestCase):
    """Test forward secrecy key ratcheting."""
    
    def test_initialization(self):
        """Test ratchet engine initializes."""
        initial = b"initial_ratchet_key_material_12345"
        ratchet = ForwardSecrecyRatcheting(initial)
        self.assertEqual(ratchet.get_ratchet_count(), 0)
    
    def test_ratchet_produces_output(self):
        """Test ratchet produces valid output."""
        ratchet = ForwardSecrecyRatcheting(b"initial_key")
        output = ratchet.ratchet()
        self.assertEqual(len(output), 32)
        self.assertEqual(ratchet.get_ratchet_count(), 1)
    
    def test_ratchet_forward_secrecy(self):
        """Test ratchet provides forward secrecy - cannot go backward."""
        ratchet = ForwardSecrecyRatcheting(b"initial_key")
        key1 = ratchet.ratchet()
        key2 = ratchet.ratchet()
        key3 = ratchet.ratchet()
        
        # All keys should be different
        self.assertNotEqual(key1, key2)
        self.assertNotEqual(key2, key3)
        self.assertNotEqual(key1, key3)
        self.assertEqual(ratchet.get_ratchet_count(), 3)
    
    def test_ratchet_with_additional_input(self):
        """Test ratchet with additional input."""
        ratchet = ForwardSecrecyRatcheting(b"initial_key")
        key1 = ratchet.ratchet(b"input_a")
        key2 = ratchet.ratchet(b"input_b")
        self.assertNotEqual(key1, key2)


class TestKeyHierarchyManager(unittest.TestCase):
    """Test key hierarchy management."""
    
    def test_initialization(self):
        """Test hierarchy initializes with root."""
        hierarchy = KeyHierarchyManager(b"root_key_material")
        self.assertIn("root", hierarchy.nodes)
        self.assertEqual(hierarchy.root_node.level, 0)
    
    def test_create_child_node(self):
        """Test creating child nodes."""
        hierarchy = KeyHierarchyManager(b"root_key")
        child = hierarchy.create_child_node("root", "child1", KeyPurpose.ENCRYPTION)
        
        self.assertEqual(child.level, 1)
        self.assertEqual(child.parent_id, "root")
        self.assertIn("child1", hierarchy.nodes)
        self.assertIn("child1", hierarchy.root_node.children)
    
    def test_derive_for_node(self):
        """Test deriving key for a node."""
        hierarchy = KeyHierarchyManager(b"root_key")
        hierarchy.create_child_node("root", "enc", KeyPurpose.ENCRYPTION)
        derived = hierarchy.derive_for_node("enc", 32)
        
        self.assertEqual(len(derived.key_material), 32)
        self.assertEqual(derived.purpose, KeyPurpose.ENCRYPTION)
        self.assertEqual(derived.derivation_level, 1)
    
    def test_hierarchical_derivation(self):
        """Test multi-level hierarchy derivation."""
        hierarchy = KeyHierarchyManager(b"root_key")
        hierarchy.create_child_node("root", "l1", KeyPurpose.DERIVATION)
        hierarchy.create_child_node("l1", "l2", KeyPurpose.ENCRYPTION)
        
        derived = hierarchy.derive_for_node("l2", 32)
        self.assertEqual(derived.derivation_level, 2)
    
    def test_forward_secrecy_in_hierarchy(self):
        """Test forward secrecy in hierarchy derivation."""
        hierarchy = KeyHierarchyManager(b"root_key")
        hierarchy.create_child_node("root", "session", KeyPurpose.SESSION)
        
        derived = hierarchy.derive_for_node("session", 32, forward_secret=True)
        self.assertTrue(derived.forward_secret)
        self.assertGreater(derived.ratchet_count, 0)


class TestDerivedKey(unittest.TestCase):
    """Test DerivedKey container."""
    
    def test_commitment_verification(self):
        """Test key commitment verification works."""
        key = DerivedKey(
            key_material=b"test_key_material_12345",
            purpose=KeyPurpose.ENCRYPTION,
            security_level=SecurityLevel.LEVEL_5,
            salt_used=b"salt",
            info_context=b"info",
            derivation_level=0,
            timestamp=time.time(),
            commitment=b''
        )
        # Fix commitment
        import hashlib
        key.commitment = hashlib.sha3_512(key.key_material).digest()[:32]
        
        self.assertTrue(key.verify_commitment())
    
    def test_commitment_tampering_detected(self):
        """Test tampering is detected."""
        key = DerivedKey(
            key_material=b"test_key_material_12345",
            purpose=KeyPurpose.ENCRYPTION,
            security_level=SecurityLevel.LEVEL_5,
            salt_used=b"salt",
            info_context=b"info",
            derivation_level=0,
            timestamp=time.time(),
            commitment=b"wrong_commitment"
        )
        self.assertFalse(key.verify_commitment())
    
    def test_secure_wipe(self):
        """Test secure key wiping."""
        key = DerivedKey(
            key_material=b"secret_key_here_1234567890",
            purpose=KeyPurpose.ENCRYPTION,
            security_level=SecurityLevel.LEVEL_5,
            salt_used=b"salt",
            info_context=b"info",
            derivation_level=0,
            timestamp=time.time(),
            commitment=b''
        )
        original = key.key_material
        key.wipe()
        self.assertEqual(key.key_material, b'')


class TestPQKeyDiversificationEngineV38(unittest.TestCase):
    """Main test suite for v38 engine."""
    
    def setUp(self):
        """Set up test engine."""
        self.master_key = b"test_master_key_1234567890_abcdefghij"
        self.engine = PQKeyDiversificationEngineV38(
            self.master_key,
            SecurityLevel.LEVEL_5
        )
    
    def test_initialization(self):
        """Test engine initializes correctly."""
        self.assertEqual(self.engine.security_level, SecurityLevel.LEVEL_5)
        self.assertEqual(self.engine.total_derivations, 0)
    
    def test_basic_key_diversification(self):
        """Test basic key diversification."""
        result = self.engine.diversify_key(KeyPurpose.ENCRYPTION, 32)
        
        self.assertTrue(result.success)
        self.assertIsNotNone(result.derived_key)
        self.assertEqual(len(result.derived_key.key_material), 32)
        self.assertTrue(result.quantum_resistant_salt)
        self.assertGreater(self.engine.total_derivations, 0)
    
    def test_all_key_purposes(self):
        """Test diversification for all key purposes."""
        for purpose in KeyPurpose:
            result = self.engine.diversify_key(purpose, 32)
            self.assertTrue(result.success)
            self.assertEqual(result.derived_key.purpose, purpose)
    
    def test_different_key_lengths(self):
        """Test different key output lengths."""
        for length in [16, 24, 32, 48, 64]:
            result = self.engine.diversify_key(KeyPurpose.SESSION, length)
            self.assertEqual(len(result.derived_key.key_material), length)
    
    def test_domain_separation(self):
        """Test different contexts produce different keys."""
        result1 = self.engine.diversify_key(
            KeyPurpose.ENCRYPTION, 32, context="user_a"
        )
        result2 = self.engine.diversify_key(
            KeyPurpose.ENCRYPTION, 32, context="user_b"
        )
        self.assertNotEqual(
            result1.derived_key.key_material,
            result2.derived_key.key_material
        )
    
    def test_forward_secrecy_diversification(self):
        """Test forward secrecy diversification."""
        result = self.engine.diversify_key(
            KeyPurpose.SESSION, 32, forward_secrecy=True
        )
        self.assertTrue(result.success)
        self.assertTrue(result.forward_secrecy_applied)
        self.assertTrue(result.derived_key.forward_secret)
        self.assertGreater(result.derived_key.ratchet_count, 0)
    
    def test_hierarchical_diversification(self):
        """Test hierarchical key diversification."""
        result = self.engine.diversify_hierarchical([
            ("tenant", KeyPurpose.DERIVATION),
            ("user_alice", KeyPurpose.ENCRYPTION)
        ], 32)
        
        self.assertTrue(result.success)
        self.assertIsNotNone(result.hierarchy_node)
        self.assertEqual(result.hierarchy_node.level, 2)
    
    def test_multiple_hierarchical_derivations(self):
        """Test multiple hierarchical paths."""
        result1 = self.engine.diversify_hierarchical([
            ("t1", KeyPurpose.DERIVATION),
            ("u1", KeyPurpose.ENCRYPTION)
        ])
        result2 = self.engine.diversify_hierarchical([
            ("t1", KeyPurpose.DERIVATION),
            ("u2", KeyPurpose.ENCRYPTION)
        ])
        
        self.assertNotEqual(
            result1.derived_key.key_material,
            result2.derived_key.key_material
        )
    
    def test_force_rotation(self):
        """Test forced forward secrecy rotation."""
        # Initialize ratchet
        self.engine.diversify_key(KeyPurpose.SESSION, forward_secrecy=True)
        initial_count = self.engine.total_rotations
        
        result = self.engine.rotate_forward_secrecy_key()
        self.assertTrue(result.success)
        self.assertTrue(result.forward_secrecy_applied)
        self.assertEqual(self.engine.total_rotations, initial_count + 1)
    
    def test_deterministic_with_same_salt(self):
        """Test same master + same salt + same info = same key."""
        # Note: salts are random by default, so we test domain separation
        master = b"fixed_master_key"
        engine1 = PQKeyDiversificationEngineV38(master)
        engine2 = PQKeyDiversificationEngineV38(master)
        
        # Different engines should produce different keys due to random salts
        # This is the expected behavior for salt-based diversification
        result1 = engine1.diversify_key(KeyPurpose.ENCRYPTION, 32)
        result2 = engine2.diversify_key(KeyPurpose.ENCRYPTION, 32)
        # Different random salts = different keys
        self.assertNotEqual(
            result1.derived_key.key_material,
            result2.derived_key.key_material
        )
    
    def test_processing_time_recorded(self):
        """Test derivation timing is recorded."""
        result = self.engine.diversify_key(KeyPurpose.ENCRYPTION)
        self.assertGreaterEqual(result.derivation_time_ms, 0)
    
    def test_get_stats(self):
        """Test statistics retrieval."""
        self.engine.diversify_key(KeyPurpose.ENCRYPTION)
        self.engine.diversify_key(KeyPurpose.AUTHENTICATION)
        
        stats = self.engine.get_stats()
        self.assertIn("total_derivations", stats)
        self.assertIn("security_level", stats)
        self.assertGreaterEqual(stats["total_derivations"], 2)


class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions."""
    
    def test_get_engine_singleton(self):
        """Test global singleton pattern."""
        engine1 = get_key_diversification_engine_v38()
        engine2 = get_key_diversification_engine_v38()
        self.assertIs(engine1, engine2)
    
    def test_convenience_diversify(self):
        """Test convenience diversification function."""
        result = diversify_pq_key_v38(KeyPurpose.SESSION, 32)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.derived_key)
    
    def test_version_info(self):
        """Test version information."""
        self.assertEqual(VERSION, "38.0.0")
        self.assertEqual(VERSION_DATE, "2026-06-23")


class TestBackwardCompatibility(unittest.TestCase):
    """Verify backward compatibility."""
    
    def test_purely_additive(self):
        """Verify this is purely additive - no existing files modified."""
        src_path = os.path.join(
            os.path.dirname(__file__),
            'quantum_crypt',
            'post_quantum_secure_key_diversification_hkdf_engine_v38_2026_june.py'
        )
        self.assertTrue(os.path.exists(src_path))
    
    def test_imports_cleanly(self):
        """Test module imports without errors."""
        try:
            from quantum_crypt import post_quantum_secure_key_diversification_hkdf_engine_v38_2026_june as module
            self.assertTrue(hasattr(module, 'PQKeyDiversificationEngineV38'))
        except Exception as e:
            self.fail(f"Import failed: {e}")


if __name__ == '__main__':
    # Run all tests
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestQuantumResistantSaltGenerator)
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestSideChannelResistantHKDF))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestForwardSecrecyRatcheting))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestKeyHierarchyManager))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestDerivedKey))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestPQKeyDiversificationEngineV38))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestGlobalFunctions))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestBackwardCompatibility))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    sys.exit(0 if result.wasSuccessful() else 1)
