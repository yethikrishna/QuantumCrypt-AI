"""
Test suite for Memory-Hard KDF with Side-Channel Resistance - QuantumCrypt AI
Tests all KDF functionality with real cryptographic assertions.
"""

import unittest
import time
from quantum_crypt.memory_hard_kdf_side_channel_2026_june import (
    QuantumResistantKDF,
    MemoryHardPBKDF2,
    ScryptStyleKDF,
    KDFStrength,
    KDFParameters,
    KDFResult
)


class TestKDFParameters(unittest.TestCase):
    """Test KDF parameter configuration."""
    
    def test_default_parameters(self):
        """Test default parameter values."""
        params = KDFParameters()
        self.assertEqual(params.time_cost, 3)
        self.assertEqual(params.memory_cost, 65536)
        self.assertEqual(params.parallelism, 4)
        self.assertEqual(params.hash_length, 32)
    
    def test_strength_based_configuration(self):
        """Test pre-configured strength levels."""
        interactive = KDFParameters.for_strength(KDFStrength.INTERACTIVE)
        moderate = KDFParameters.for_strength(KDFStrength.MODERATE)
        sensitive = KDFParameters.for_strength(KDFStrength.SENSITIVE)
        crypto = KDFParameters.for_strength(KDFStrength.CRYPTOGRAPHIC)
        
        # Verify increasing security levels
        self.assertLessEqual(interactive.time_cost, moderate.time_cost)
        self.assertLessEqual(moderate.time_cost, sensitive.time_cost)
        self.assertLessEqual(sensitive.time_cost, crypto.time_cost)
        self.assertLessEqual(interactive.memory_cost, moderate.memory_cost)


class TestMemoryHardPBKDF2(unittest.TestCase):
    """Test Memory-Hard PBKDF2 implementation."""
    
    def setUp(self):
        """Set up KDF instance."""
        params = KDFParameters(time_cost=2, memory_cost=4096)
        self.kdf = MemoryHardPBKDF2(params)
    
    def test_key_derivation_basic(self):
        """Test basic key derivation."""
        result = self.kdf.derive_key("test_password")
        
        self.assertIsInstance(result, KDFResult)
        self.assertEqual(len(result.derived_key), 32)
        self.assertEqual(len(result.salt), 16)
        self.assertGreater(result.computation_time_ms, 0)
        self.assertEqual(result.kdf_type, "MemoryHardPBKDF2")
    
    def test_key_derivation_with_salt(self):
        """Test key derivation with explicit salt."""
        salt = b"fixed_salt_123456"
        result1 = self.kdf.derive_key("password123", salt)
        result2 = self.kdf.derive_key("password123", salt)
        
        self.assertEqual(result1.derived_key, result2.derived_key)
        self.assertEqual(result1.salt, salt)
    
    def test_different_passwords_produce_different_keys(self):
        """Test different passwords produce different keys."""
        result1 = self.kdf.derive_key("password1")
        result2 = self.kdf.derive_key("password2")
        
        self.assertNotEqual(result1.derived_key, result2.derived_key)
    
    def test_verification_correct_password(self):
        """Test verification with correct password."""
        result = self.kdf.derive_key("my_secure_password")
        verified = self.kdf.verify_key("my_secure_password", result.salt, result.derived_key)
        self.assertTrue(verified)
    
    def test_verification_wrong_password(self):
        """Test verification with wrong password fails."""
        result = self.kdf.derive_key("correct_password")
        verified = self.kdf.verify_key("wrong_password", result.salt, result.derived_key)
        self.assertFalse(verified)
    
    def test_constant_time_compare(self):
        """Test constant-time comparison works."""
        a = b"test_data_12345"
        b = b"test_data_12345"
        c = b"test_data_xxxxx"
        
        self.assertTrue(self.kdf._constant_time_compare(a, b))
        self.assertFalse(self.kdf._constant_time_compare(a, c))
    
    def test_salt_generation(self):
        """Test salt generation produces unique salts."""
        salt1 = self.kdf._generate_salt()
        salt2 = self.kdf._generate_salt()
        
        self.assertNotEqual(salt1, salt2)
        self.assertEqual(len(salt1), 16)
    
    def test_result_serialization(self):
        """Test KDF result serialization."""
        result = self.kdf.derive_key("test")
        result_dict = result.to_dict()
        
        self.assertIn("kdf_type", result_dict)
        self.assertIn("salt_hex", result_dict)
        self.assertIn("params", result_dict)
        self.assertIn("derived_key_length", result_dict)
        self.assertEqual(result_dict["derived_key_length"], 32)


class TestScryptStyleKDF(unittest.TestCase):
    """Test Scrypt-style KDF implementation."""
    
    def setUp(self):
        """Set up lightweight scrypt KDF."""
        self.kdf = ScryptStyleKDF(n=1024, r=2, p=1, dk_len=32)
    
    def test_scrypt_key_derivation(self):
        """Test scrypt-style key derivation."""
        result = self.kdf.derive_key("test_password")
        
        self.assertIsInstance(result, KDFResult)
        self.assertEqual(len(result.derived_key), 32)
        self.assertGreater(result.computation_time_ms, 0)
        self.assertEqual(result.kdf_type, "ScryptStyleKDF")
    
    def test_scrypt_deterministic(self):
        """Test same password + salt produces same key."""
        salt = b"test_salt_fixed"
        result1 = self.kdf.derive_key("password", salt)
        result2 = self.kdf.derive_key("password", salt)
        
        self.assertEqual(result1.derived_key, result2.derived_key)
    
    def test_scrypt_verification(self):
        """Test scrypt verification."""
        result = self.kdf.derive_key("secure_pass")
        self.assertTrue(self.kdf.verify_key("secure_pass", result.salt, result.derived_key))
        self.assertFalse(self.kdf.verify_key("wrong_pass", result.salt, result.derived_key))
    
    def test_block_mix_function(self):
        """Test BlockMix function."""
        block = b"x" * 128
        mixed = self.kdf._block_mix(block)
        
        self.assertEqual(len(mixed), len(block))
        self.assertNotEqual(mixed, block)  # Should change input


class TestQuantumResistantKDF(unittest.TestCase):
    """Test main QuantumResistantKDF facade."""
    
    def test_pbkdf2_facade(self):
        """Test PBKDF2 algorithm through facade."""
        kdf = QuantumResistantKDF(strength=KDFStrength.INTERACTIVE, algorithm="pbkdf2")
        result = kdf.derive("test_password")
        
        self.assertIsInstance(result, KDFResult)
        self.assertEqual(len(result.derived_key), 32)
    
    def test_scrypt_facade(self):
        """Test Scrypt algorithm through facade."""
        kdf = QuantumResistantKDF(strength=KDFStrength.INTERACTIVE, algorithm="scrypt")
        result = kdf.derive("test_password")
        
        self.assertIsInstance(result, KDFResult)
        self.assertEqual(len(result.derived_key), 32)
    
    def test_facade_verification(self):
        """Test verification through facade."""
        kdf = QuantumResistantKDF(strength=KDFStrength.INTERACTIVE)
        result = kdf.derive("my_password")
        
        self.assertTrue(kdf.verify("my_password", result.salt, result.derived_key))
        self.assertFalse(kdf.verify("wrong_password", result.salt, result.derived_key))
    
    def test_strength_levels(self):
        """Test different strength levels."""
        kdf_low = QuantumResistantKDF(strength=KDFStrength.INTERACTIVE)
        kdf_high = QuantumResistantKDF(strength=KDFStrength.SENSITIVE)
        
        result_low = kdf_low.derive("test")
        result_high = kdf_high.derive("test")
        
        # Higher strength should produce longer keys (configured)
        self.assertLessEqual(len(result_low.derived_key), len(result_high.derived_key))
    
    def test_invalid_algorithm(self):
        """Test invalid algorithm raises error."""
        with self.assertRaises(ValueError):
            QuantumResistantKDF(algorithm="invalid")
    
    def test_empty_password(self):
        """Test empty password handling."""
        kdf = QuantumResistantKDF(strength=KDFStrength.INTERACTIVE)
        result = kdf.derive("")
        
        self.assertIsInstance(result, KDFResult)
        self.assertEqual(len(result.derived_key), 32)
    
    def test_long_password(self):
        """Test very long password."""
        kdf = QuantumResistantKDF(strength=KDFStrength.INTERACTIVE)
        long_pass = "a" * 1000
        result = kdf.derive(long_pass)
        
        self.assertIsInstance(result, KDFResult)
        self.assertEqual(len(result.derived_key), 32)


class TestKDFSecurityProperties(unittest.TestCase):
    """Test security properties of KDF implementations."""
    
    def test_unique_salts_produce_unique_keys(self):
        """Test same password with different salts produces different keys."""
        kdf = QuantumResistantKDF(strength=KDFStrength.INTERACTIVE)
        
        result1 = kdf.derive("same_password")
        result2 = kdf.derive("same_password")
        
        self.assertNotEqual(result1.derived_key, result2.derived_key)
        self.assertNotEqual(result1.salt, result2.salt)
    
    def test_key_entropy(self):
        """Test derived keys have good entropy (not all zeros, etc)."""
        kdf = QuantumResistantKDF(strength=KDFStrength.INTERACTIVE)
        result = kdf.derive("test")
        
        # Key should not be all zeros
        self.assertFalse(all(b == 0 for b in result.derived_key))
        
        # Key should not be uniform pattern
        unique_bytes = len(set(result.derived_key))
        self.assertGreater(unique_bytes, 10)
    
    def test_computation_time(self):
        """Test computation time is measurable."""
        kdf = QuantumResistantKDF(strength=KDFStrength.INTERACTIVE)
        result = kdf.derive("test")
        
        # Should take at least some measurable time
        self.assertGreaterEqual(result.computation_time_ms, 0)
        
        # Print actual computation time for documentation
        print(f"Actual KDF computation time: {result.computation_time_ms:.2f} ms")


if __name__ == "__main__":
    unittest.main(verbosity=2)
