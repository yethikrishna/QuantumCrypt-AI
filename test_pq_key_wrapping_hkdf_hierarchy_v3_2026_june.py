"""
Test suite for Post-Quantum Key Wrapping with HKDF Hierarchy v3
QuantumCrypt-AI Feature Expansion - June 2026
ADD-ONLY - NO EXISTING CODE MODIFIED
"""

import unittest
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_key_wrapping_hkdf_hierarchy_v3_2026_june import (
    KeyHierarchyManager,
    HKDF,
    AESKeyWrap,
    AESGCMWrap,
    WrappedKey,
    DerivedKey,
    KeyType,
    WrapAlgorithm,
    HKDFHash,
    constant_time_compare,
    secure_zeroize,
    generate_wrapping_key,
    hkdf_derive_key,
)


class TestConstantTimeCompare(unittest.TestCase):
    """Test constant-time comparison security"""

    def test_constant_time_equal(self):
        """Test equal byte strings compare equal"""
        self.assertTrue(constant_time_compare(b"test", b"test"))
        self.assertTrue(constant_time_compare(b"", b""))
        self.assertTrue(constant_time_compare(b"\x00" * 100, b"\x00" * 100))

    def test_constant_time_not_equal(self):
        """Test unequal byte strings compare not equal"""
        self.assertFalse(constant_time_compare(b"test", b"TEST"))
        self.assertFalse(constant_time_compare(b"a", b"b"))
        self.assertFalse(constant_time_compare(b"longstring", b"short"))

    def test_constant_time_different_lengths(self):
        """Test different length strings always return False"""
        self.assertFalse(constant_time_compare(b"a", b"aa"))
        self.assertFalse(constant_time_compare(b"abc", b"ab"))


class TestSecureZeroize(unittest.TestCase):
    """Test secure memory zeroization"""

    def test_zeroize_bytearray(self):
        """Test bytearray zeroization"""
        data = bytearray(b"sensitive data here")
        original = bytes(data)
        
        secure_zeroize(data)
        
        # All bytes should be zero
        self.assertEqual(len(data), len(original))
        self.assertTrue(all(b == 0 for b in data))


class TestHKDF(unittest.TestCase):
    """Test HKDF key derivation"""

    def test_hkdf_basic_derivation(self):
        """Test basic HKDF derivation"""
        hkdf = HKDF(HKDFHash.SHA256)
        ikm = os.urandom(32)
        
        derived = hkdf.derive_key(ikm, info=b"test_context")
        
        self.assertEqual(len(derived.key_material), 32)
        self.assertEqual(len(derived.salt), 32)
        self.assertEqual(derived.info, b"test_context")

    def test_hkdf_deterministic(self):
        """Test same inputs produce same output"""
        hkdf = HKDF(HKDFHash.SHA256)
        ikm = b"fixed_input_key_material"
        salt = b"fixed_salt_value"
        
        d1 = hkdf.derive_key(ikm, salt=salt, info=b"info")
        d2 = hkdf.derive_key(ikm, salt=salt, info=b"info")
        
        self.assertEqual(d1.key_material, d2.key_material)

    def test_hkdf_different_info(self):
        """Test different info produces different keys"""
        hkdf = HKDF(HKDFHash.SHA256)
        ikm = b"fixed_ikm"
        salt = b"fixed_salt"
        
        d1 = hkdf.derive_key(ikm, salt=salt, info=b"context1")
        d2 = hkdf.derive_key(ikm, salt=salt, info=b"context2")
        
        self.assertNotEqual(d1.key_material, d2.key_material)

    def test_hkdf_hash_algorithms(self):
        """Test all supported hash algorithms"""
        ikm = os.urandom(32)
        
        for hash_algo in HKDFHash:
            hkdf = HKDF(hash_algo)
            derived = hkdf.derive_key(ikm)
            self.assertGreater(len(derived.key_material), 0)

    def test_hkdf_extract_expand_separate(self):
        """Test separate extract and expand steps"""
        hkdf = HKDF(HKDFHash.SHA256)
        ikm = os.urandom(32)
        
        prk = hkdf.extract(ikm)
        expanded = hkdf.expand(prk, info=b"test", length=64)
        
        self.assertEqual(len(expanded), 64)

    def test_derived_key_zeroize(self):
        """Test derived key zeroization"""
        hkdf = HKDF(HKDFHash.SHA256)
        derived = hkdf.derive_key(os.urandom(32))
        
        key_copy = bytes(derived.key_material)
        derived.zeroize()
        
        # Key material should be all zeros
        self.assertTrue(all(b == 0 for b in derived.key_material))


class TestAESGCMWrap(unittest.TestCase):
    """Test AES-GCM key wrapping"""

    def test_wrap_unwrap_cycle(self):
        """Test wrap then unwrap returns original"""
        kek = os.urandom(32)
        wrapper = AESGCMWrap(kek)
        
        plaintext_key = os.urandom(32)
        ciphertext, iv, tag = wrapper.wrap(plaintext_key)
        
        unwrapped = wrapper.unwrap(ciphertext, iv, tag)
        
        self.assertEqual(unwrapped, plaintext_key)

    def test_wrap_with_associated_data(self):
        """Test wrap with authenticated associated data"""
        kek = os.urandom(32)
        wrapper = AESGCMWrap(kek)
        
        plaintext = os.urandom(32)
        ad = b"contextual_metadata"
        
        ciphertext, iv, tag = wrapper.wrap(plaintext, associated_data=ad)
        unwrapped = wrapper.unwrap(ciphertext, iv, tag, associated_data=ad)
        
        self.assertEqual(unwrapped, plaintext)

    def test_wrong_ad_fails(self):
        """Test wrong associated data causes authentication failure"""
        kek = os.urandom(32)
        wrapper = AESGCMWrap(kek)
        
        plaintext = os.urandom(32)
        ciphertext, iv, tag = wrapper.wrap(plaintext, associated_data=b"correct_ad")
        
        with self.assertRaises(Exception):
            wrapper.unwrap(ciphertext, iv, tag, associated_data=b"wrong_ad")

    def test_wrong_kek_fails(self):
        """Test wrong KEK causes authentication failure"""
        kek1 = os.urandom(32)
        kek2 = os.urandom(32)
        
        wrapper1 = AESGCMWrap(kek1)
        wrapper2 = AESGCMWrap(kek2)
        
        plaintext = os.urandom(32)
        ciphertext, iv, tag = wrapper1.wrap(plaintext)
        
        with self.assertRaises(Exception):
            wrapper2.unwrap(ciphertext, iv, tag)


class TestKeyHierarchyManager(unittest.TestCase):
    """Test hierarchical key management"""

    def test_manager_initialization(self):
        """Test manager initialization with and without seed"""
        mgr1 = KeyHierarchyManager()
        mgr2 = KeyHierarchyManager(root_seed=os.urandom(64))
        
        self.assertIsNotNone(mgr1)
        self.assertIsNotNone(mgr2)

    def test_kek_derivation_caching(self):
        """Test KEK derivation caching works"""
        mgr = KeyHierarchyManager()
        
        kek1 = mgr.derive_kek("kek_1")
        kek2 = mgr.derive_kek("kek_1")
        
        # Should return cached instance
        self.assertIs(kek1, kek2)

    def test_kek_different_ids(self):
        """Test different KEK IDs produce different keys"""
        mgr = KeyHierarchyManager()
        
        kek1 = mgr.derive_kek("kek_a")
        kek2 = mgr.derive_kek("kek_b")
        
        self.assertNotEqual(kek1.key_material, kek2.key_material)

    def test_dek_derivation(self):
        """Test DEK derivation under KEK"""
        mgr = KeyHierarchyManager()
        
        dek1 = mgr.derive_dek("kek_1", "dek_1")
        dek2 = mgr.derive_dek("kek_1", "dek_2")
        
        self.assertEqual(len(dek1.key_material), 32)
        self.assertEqual(len(dek2.key_material), 32)
        self.assertNotEqual(dek1.key_material, dek2.key_material)

    def test_dek_wrap_unwrap(self):
        """Test DEK wrap and unwrap cycle"""
        mgr = KeyHierarchyManager()
        
        plaintext_dek = os.urandom(32)
        wrapped = mgr.wrap_dek("production_kek", plaintext_dek)
        
        self.assertEqual(wrapped.algorithm, WrapAlgorithm.AES_GCM_WRAP)
        self.assertEqual(wrapped.key_type, KeyType.DEK)
        self.assertIsNotNone(wrapped.iv)
        self.assertIsNotNone(wrapped.tag)
        
        unwrapped = mgr.unwrap_dek("production_kek", wrapped)
        
        self.assertEqual(unwrapped, plaintext_dek)

    def test_root_kek_rotation(self):
        """Test root KEK rotation with forward secrecy"""
        mgr = KeyHierarchyManager()
        
        initial_kek = mgr.derive_kek("test_kek")
        initial_key_material = bytes(initial_kek.key_material)
        
        mgr.rotate_root_kek()
        
        # Cache should be cleared
        status = mgr.get_hierarchy_status()
        self.assertEqual(status["cached_keys"], 0)
        self.assertEqual(status["root_kek_rotations"], 1)
        
        # New derivation should produce different key
        new_kek = mgr.derive_kek("test_kek")
        self.assertNotEqual(new_kek.key_material, initial_key_material)

    def test_session_key_derivation(self):
        """Test ephemeral session key derivation"""
        mgr = KeyHierarchyManager()
        
        s1 = mgr.derive_session_key("tls_connection_1")
        s2 = mgr.derive_session_key("tls_connection_1")  # Same context, different nonce
        
        self.assertEqual(len(s1.key_material), 32)
        self.assertEqual(len(s2.key_material), 32)
        # Should be different due to random nonce
        self.assertNotEqual(s1.key_material, s2.key_material)

    def test_hierarchy_status(self):
        """Test status reporting"""
        mgr = KeyHierarchyManager()
        
        # Derive some keys
        mgr.derive_kek("kek1")
        mgr.derive_kek("kek2")
        
        status = mgr.get_hierarchy_status()
        
        self.assertIn("hash_algorithm", status)
        self.assertIn("root_kek_rotations", status)
        self.assertIn("cached_keys", status)
        self.assertIn("created_age", status)
        self.assertEqual(status["cached_keys"], 2)

    def test_zeroize_all(self):
        """Test full zeroization of all key material"""
        mgr = KeyHierarchyManager()
        
        mgr.derive_kek("kek1")
        mgr.derive_kek("kek2")
        
        mgr.zeroize_all()
        
        status = mgr.get_hierarchy_status()
        self.assertEqual(status["cached_keys"], 0)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience wrapper functions"""

    def test_generate_wrapping_key(self):
        """Test secure key generation"""
        key16 = generate_wrapping_key(16)
        key32 = generate_wrapping_key(32)
        
        self.assertEqual(len(key16), 16)
        self.assertEqual(len(key32), 32)
        self.assertNotEqual(key16, key32)

    def test_hkdf_one_shot(self):
        """Test one-shot HKDF convenience function"""
        ikm = os.urandom(32)
        
        key1 = hkdf_derive_key(ikm, info=b"context1")
        key2 = hkdf_derive_key(ikm, info=b"context2")
        
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(key2), 32)
        self.assertNotEqual(key1, key2)


class TestIntegrationWorkflows(unittest.TestCase):
    """Integration tests for complete key management workflows"""

    def test_complete_key_hierarchy_workflow(self):
        """Test complete key hierarchy workflow"""
        # 1. Initialize hierarchy
        mgr = KeyHierarchyManager(hash_algorithm=HKDFHash.SHA256)
        
        # 2. Derive KEKs for different environments
        prod_kek = mgr.derive_kek("production")
        staging_kek = mgr.derive_kek("staging")
        
        self.assertNotEqual(prod_kek.key_material, staging_kek.key_material)
        
        # 3. Derive and wrap DEKs
        user_data_dek = os.urandom(32)
        wrapped = mgr.wrap_dek("production", user_data_dek)
        
        # 4. Store wrapped key (simulate database storage)
        stored_wrapped = wrapped
        
        # 5. Later retrieval and unwrap
        unwrapped = mgr.unwrap_dek("production", stored_wrapped)
        
        self.assertEqual(unwrapped, user_data_dek)
        
        # 6. Generate session keys for transactions
        session1 = mgr.derive_session_key("user_123_transaction")
        session2 = mgr.derive_session_key("user_456_transaction")
        
        self.assertNotEqual(session1.key_material, session2.key_material)
        
        # 7. Get status
        status = mgr.get_hierarchy_status()
        self.assertGreater(status["cached_keys"], 0)

    def test_multi_tenant_key_isolation(self):
        """Test key isolation between tenants"""
        mgr = KeyHierarchyManager()
        
        # Derive DEKs for different tenants
        dek_tenant_a = mgr.derive_dek("tenant_kek", "tenant_a_data")
        dek_tenant_b = mgr.derive_dek("tenant_kek", "tenant_b_data")
        
        # Keys must be different
        self.assertNotEqual(dek_tenant_a.key_material, dek_tenant_b.key_material)
        
        # Wrap each tenant's key
        wrapped_a = mgr.wrap_dek("tenant_kek", dek_tenant_a.key_material)
        wrapped_b = mgr.wrap_dek("tenant_kek", dek_tenant_b.key_material)
        
        # Unwrap and verify
        unwrapped_a = mgr.unwrap_dek("tenant_kek", wrapped_a)
        unwrapped_b = mgr.unwrap_dek("tenant_kek", wrapped_b)
        
        self.assertEqual(unwrapped_a, dek_tenant_a.key_material)
        self.assertEqual(unwrapped_b, dek_tenant_b.key_material)
        self.assertNotEqual(unwrapped_a, unwrapped_b)


if __name__ == '__main__':
    unittest.main(verbosity=2)
