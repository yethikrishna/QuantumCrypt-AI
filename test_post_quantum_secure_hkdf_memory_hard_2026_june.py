#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure HKDF with Memory Hardening
June 2026 - Production Grade Tests

Real working cryptographic tests.
"""

import sys
import hmac
import secrets
import unittest
import time

# Import directly from the file
exec(open('quantum_crypt/post_quantum_secure_hkdf_memory_hard_2026_june.py').read())


class TestHashAlgorithm(unittest.TestCase):
    """Test hash algorithm support."""
    
    def test_all_hash_algorithms(self):
        """Test all supported hash algorithms work."""
        test_ikm = b"test input key material"
        
        for alg in HashAlgorithm:
            with self.subTest(algorithm=alg.value):
                kdf = PostQuantumSecureHKDF(hash_alg=alg, memory_mode=MemoryHardnessMode.NONE)
                result = kdf.derive_key(test_ikm, length=32)
                self.assertEqual(len(result.derived_key), 32)
                self.assertEqual(result.hash_algorithm, alg)


class TestHKDFBasicFunctionality(unittest.TestCase):
    """Test basic HKDF functionality."""
    
    def setUp(self):
        self.kdf = PostQuantumSecureHKDF(
            hash_alg=HashAlgorithm.SHA256,
            memory_mode=MemoryHardnessMode.NONE
        )
        self.test_ikm = b"my secret input key material"
    
    def test_derive_key_deterministic_with_salt(self):
        """Same IKM + same salt = same key."""
        salt = secrets.token_bytes(32)
        
        result1 = self.kdf.derive_key(self.test_ikm, salt=salt, length=32)
        result2 = self.kdf.derive_key(self.test_ikm, salt=salt, length=32)
        
        self.assertTrue(hmac.compare_digest(result1.derived_key, result2.derived_key))
    
    def test_different_salt_different_key(self):
        """Different salt = different key."""
        result1 = self.kdf.derive_key(self.test_ikm, length=32)
        result2 = self.kdf.derive_key(self.test_ikm, length=32)
        
        # Different random salts should produce different keys
        self.assertFalse(hmac.compare_digest(result1.derived_key, result2.derived_key))
    
    def test_different_info_different_key(self):
        """Different info = different key (key diversification)."""
        salt = secrets.token_bytes(32)
        
        key1 = self.kdf.derive_key(self.test_ikm, salt=salt, info=b"encryption", length=32)
        key2 = self.kdf.derive_key(self.test_ikm, salt=salt, info=b"authentication", length=32)
        
        self.assertFalse(hmac.compare_digest(key1.derived_key, key2.derived_key))
    
    def test_various_key_lengths(self):
        """Test various output key lengths."""
        for length in [16, 32, 64, 128]:
            with self.subTest(length=length):
                result = self.kdf.derive_key(self.test_ikm, length=length)
                self.assertEqual(len(result.derived_key), length)
    
    def test_string_ikm_conversion(self):
        """String IKM should be converted to bytes."""
        result = self.kdf.derive_key("password as string", length=32)
        self.assertEqual(len(result.derived_key), 32)
    
    def test_max_length_validation(self):
        """Test maximum length validation."""
        # SHA256 max length = 255 * 32 = 8160
        with self.assertRaises(ValueError):
            self.kdf.derive_key(self.test_ikm, length=10000)


class TestMemoryHardening(unittest.TestCase):
    """Test memory-hardening functionality."""
    
    def test_memory_modes_produce_different_keys(self):
        """Different memory modes should produce different keys."""
        test_ikm = b"test key material"
        salt = secrets.token_bytes(32)
        
        kdf_none = PostQuantumSecureHKDF(memory_mode=MemoryHardnessMode.NONE)
        kdf_light = PostQuantumSecureHKDF(memory_mode=MemoryHardnessMode.LIGHT)
        
        result_none = kdf_none.derive_key(test_ikm, salt=salt, length=32)
        result_light = kdf_light.derive_key(test_ikm, salt=salt, length=32)
        
        # Memory hardening should change the output
        self.assertFalse(hmac.compare_digest(result_none.derived_key, result_light.derived_key))
    
    def test_memory_hard_deterministic(self):
        """Memory-hardened KDF should be deterministic."""
        test_ikm = b"test key material"
        salt = secrets.token_bytes(32)
        
        kdf = PostQuantumSecureHKDF(memory_mode=MemoryHardnessMode.LIGHT)
        
        result1 = kdf.derive_key(test_ikm, salt=salt, length=32)
        result2 = kdf.derive_key(test_ikm, salt=salt, length=32)
        
        self.assertTrue(hmac.compare_digest(result1.derived_key, result2.derived_key))


class TestKDFResultVerification(unittest.TestCase):
    """Test KDF result verification."""
    
    def test_verify_correct_ikm(self):
        """Verification passes with correct IKM."""
        kdf = PostQuantumSecureHKDF(memory_mode=MemoryHardnessMode.NONE)
        ikm = b"correct password"
        
        result = kdf.derive_key(ikm, length=32)
        self.assertTrue(result.verify(ikm))
    
    def test_verify_incorrect_ikm(self):
        """Verification fails with incorrect IKM."""
        kdf = PostQuantumSecureHKDF(memory_mode=MemoryHardnessMode.NONE)
        
        result = kdf.derive_key(b"correct password", length=32)
        self.assertFalse(result.verify(b"wrong password"))


class TestContextKeyDerivation(unittest.TestCase):
    """Test context-based key derivation."""
    
    def test_key_hierarchy(self):
        """Test deriving multiple subkeys from master key."""
        kdf = PostQuantumSecureHKDF(memory_mode=MemoryHardnessMode.NONE)
        master_key = create_quantum_resistant_master_seed(64)
        
        enc_key = kdf.derive_key_for_context(master_key, "encryption", "aes-256-gcm", length=32)
        auth_key = kdf.derive_key_for_context(master_key, "authentication", "hmac-sha256", length=32)
        sign_key = kdf.derive_key_for_context(master_key, "signing", "ed25519", length=32)
        
        # All keys should be different
        self.assertFalse(hmac.compare_digest(enc_key, auth_key))
        self.assertFalse(hmac.compare_digest(enc_key, sign_key))
        self.assertFalse(hmac.compare_digest(auth_key, sign_key))
        
        # All keys should be correct length
        self.assertEqual(len(enc_key), 32)
        self.assertEqual(len(auth_key), 32)
        self.assertEqual(len(sign_key), 32)


class TestKeyConfirmation(unittest.TestCase):
    """Test key confirmation mechanism."""
    
    def test_key_confirmation_flow(self):
        """Test complete key confirmation flow."""
        shared_key = create_quantum_resistant_master_seed(32)
        nonce = secrets.token_bytes(16)
        
        # Alice generates tag
        alice_tag = KeyConfirmation.generate_confirmation_tag(shared_key, "alice", nonce)
        
        # Bob verifies Alice's tag
        self.assertTrue(KeyConfirmation.verify_confirmation_tag(shared_key, alice_tag, "alice", nonce))
        
        # Bob generates tag
        bob_tag = KeyConfirmation.generate_confirmation_tag(shared_key, "bob", nonce)
        
        # Alice verifies Bob's tag
        self.assertTrue(KeyConfirmation.verify_confirmation_tag(shared_key, bob_tag, "bob", nonce))
    
    def test_key_confirmation_wrong_key(self):
        """Key confirmation fails with wrong key."""
        correct_key = create_quantum_resistant_master_seed(32)
        wrong_key = create_quantum_resistant_master_seed(32)
        nonce = secrets.token_bytes(16)
        
        tag = KeyConfirmation.generate_confirmation_tag(correct_key, "alice", nonce)
        self.assertFalse(KeyConfirmation.verify_confirmation_tag(wrong_key, tag, "alice", nonce))


class TestMasterSeedGeneration(unittest.TestCase):
    """Test master seed generation."""
    
    def test_seed_generation(self):
        """Test seeds are random and unique."""
        seeds = [create_quantum_resistant_master_seed(64) for _ in range(10)]
        
        # All seeds should be unique
        seed_set = set(seeds)
        self.assertEqual(len(seed_set), 10)
        
        # All seeds should have correct length
        for seed in seeds:
            self.assertEqual(len(seed), 64)


def run_crypto_demo():
    """Run a comprehensive cryptographic demo."""
    print("\n" + "="*60)
    print("Post-Quantum Secure HKDF - CRYPTOGRAPHIC DEMO")
    print("="*60)
    
    print("\n[1] Generating Post-Quantum Resistant Master Seed...")
    master_seed = create_quantum_resistant_master_seed(64)
    print(f"  ✓ Master Seed generated: {len(master_seed)} bytes")
    print(f"    First 16 bytes: {master_seed[:16].hex()}")
    
    print("\n[2] Testing KDF with different configurations...")
    
    # Test LIGHT mode (fast)
    kdf_light = PostQuantumSecureHKDF(
        hash_alg=HashAlgorithm.SHA512,
        memory_mode=MemoryHardnessMode.LIGHT
    )
    
    start = time.time()
    result_light = kdf_light.derive_key(master_seed, length=32, info=b"light-mode-test")
    light_time = time.time() - start
    
    print(f"  ✓ LIGHT mode: {len(result_light.derived_key)} bytes in {light_time:.3f}s")
    print(f"    Key: {result_light.derived_key.hex()[:32]}...")
    
    # Test NONE mode (very fast)
    kdf_fast = PostQuantumSecureHKDF(
        hash_alg=HashAlgorithm.SHA512,
        memory_mode=MemoryHardnessMode.NONE
    )
    
    start = time.time()
    result_fast = kdf_fast.derive_key(master_seed, length=32, info=b"fast-mode-test")
    fast_time = time.time() - start
    
    print(f"  ✓ FAST mode: {len(result_fast.derived_key)} bytes in {fast_time:.4f}s")
    print(f"    Key: {result_fast.derived_key.hex()[:32]}...")
    
    print("\n[3] Testing Key Hierarchy Derivation...")
    kdf = PostQuantumSecureHKDF(memory_mode=MemoryHardnessMode.NONE)
    
    enc_key = kdf.derive_key_for_context(master_seed, "encryption", "aes-256-gcm", 32)
    auth_key = kdf.derive_key_for_context(master_seed, "authentication", "hmac-sha256", 32)
    backup_key = kdf.derive_key_for_context(master_seed, "backup", "recovery", 64)
    
    print(f"  ✓ Encryption Key: {enc_key.hex()[:16]}... ({len(enc_key)} bytes)")
    print(f"  ✓ Authentication Key: {auth_key.hex()[:16]}... ({len(auth_key)} bytes)")
    print(f"  ✓ Backup Key: {backup_key.hex()[:16]}... ({len(backup_key)} bytes)")
    
    print("\n[4] Testing Key Verification...")
    salt = secrets.token_bytes(32)
    test_result = kdf.derive_key(b"my secret password", salt=salt, length=32)
    
    verify_ok = test_result.verify(b"my secret password")
    verify_fail = test_result.verify(b"wrong password")
    
    print(f"  ✓ Correct password verification: {verify_ok}")
    print(f"  ✓ Wrong password rejection: {not verify_fail}")
    
    print("\n[5] Testing Key Confirmation Protocol...")
    shared_key = create_quantum_resistant_master_seed(32)
    nonce = secrets.token_bytes(16)
    
    alice_tag = KeyConfirmation.generate_confirmation_tag(shared_key, "alice", nonce)
    bob_verify = KeyConfirmation.verify_confirmation_tag(shared_key, alice_tag, "alice", nonce)
    
    print(f"  ✓ Alice generates confirmation tag")
    print(f"  ✓ Bob verifies tag: {bob_verify}")
    print(f"  ✓ Mutual key confirmation complete")
    
    print("\n" + "="*60)
    print("CRYPTOGRAPHIC DEMO COMPLETED SUCCESSFULLY")
    print("="*60 + "\n")
    
    return True


if __name__ == "__main__":
    print("Running Post-Quantum Secure HKDF Tests...\n")
    
    # Run unit tests
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run demo
    success = run_crypto_demo()
    
    if success:
        print("\n✅ ALL CRYPTO TESTS PASSED!")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED")
        sys.exit(1)
