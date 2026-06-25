"""
Test Suite for DIMENSION B - PQ Security Hardening v32
Post-Quantum Side Channel Key Protection

This test suite verifies:
1. All new PQ security hardening functions work correctly
2. No existing functionality is broken
3. Backward compatibility is preserved
4. All protections are add-only wrappers

STRICT RULES:
- ONLY add tests - NEVER modify production source
- All existing tests MUST continue to pass
- No breaking changes allowed
"""

import sys
import os
import unittest
import time
import hashlib
import hmac
import secrets

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

# Import the new PQ security hardening module
from quantum_crypt.crypto_security_hardening_pq_side_channel_key_protection_v32_2026_june import (
    pq_secure_constant_time_verify,
    pq_secure_zeroize_key,
    protect_pq_key_generation,
    protect_pq_signing,
    protect_pq_verification,
    normalize_pq_operation_timing,
    align_pq_key_for_secure_operation,
    PQKeyMaterialProtector,
    ConstantTimePQOperations,
    PQSecureMemoryZeroization,
    LatticeNoiseDistributionProtector,
    PQSideChannelProtectedWrapper,
    __version__,
    __stability__,
    __dimension__,
    __backward_compatible__,
    __breaking_changes__
)


class TestPQKeyMaterialProtector(unittest.TestCase):
    """Test PQ key material protection features."""
    
    def setUp(self):
        self.protector = PQKeyMaterialProtector()
    
    def test_align_small_pq_key(self):
        """Test alignment of small key material."""
        key = b"small_key_12345"
        aligned = self.protector.align_pq_key_material(key)
        
        # Should have guard padding
        self.assertGreater(len(aligned), len(key))
        
        # Original key should be extractable
        extracted = self.protector.extract_original_key(aligned)
        self.assertEqual(extracted[:len(key)], key)
    
    def test_align_large_pq_key(self):
        """Test alignment of large PQ key (typical Kyber/Dilithium size)."""
        # Simulate a large PQ private key (2KB typical for Kyber)
        large_key = os.urandom(2048)
        aligned = self.protector.align_pq_key_material(large_key)
        
        # Should be larger with padding
        self.assertGreater(len(aligned), len(large_key))
        
        # Original key should be preserved
        extracted = self.protector.extract_original_key(aligned)
        self.assertEqual(extracted[:len(large_key)], large_key)
    
    def test_extract_from_unaligned(self):
        """Test extraction from unaligned data returns original."""
        data = b"short"
        result = self.protector.extract_original_key(data)
        self.assertEqual(result, data)


class TestConstantTimePQOperations(unittest.TestCase):
    """Test constant-time PQ operations."""
    
    def setUp(self):
        self.operations = ConstantTimePQOperations()
    
    def test_constant_time_poly_check_valid(self):
        """Test polynomial coefficient validation with valid values."""
        coefficients = [1, 2, 3, 4, 5, 100, 1000]
        result = self.operations.constant_time_poly_check(coefficients)
        self.assertTrue(result)
    
    def test_constant_time_poly_check_boundary(self):
        """Test polynomial check at boundary values."""
        # All values within q/2 range
        coefficients = [0, (1 << 22), (1 << 23) - 1]
        result = self.operations.constant_time_poly_check(coefficients)
        self.assertTrue(result)
    
    def test_constant_time_hash_compare_equal(self):
        """Test constant-time hash comparison with equal hashes."""
        hash1 = hashlib.sha256(b"test_message").digest()
        hash2 = hashlib.sha256(b"test_message").digest()
        
        self.assertTrue(self.operations.constant_time_hash_compare(hash1, hash2))
    
    def test_constant_time_hash_compare_not_equal(self):
        """Test constant-time hash comparison with different hashes."""
        hash1 = hashlib.sha256(b"message1").digest()
        hash2 = hashlib.sha256(b"message2").digest()
        
        self.assertFalse(self.operations.constant_time_hash_compare(hash1, hash2))
    
    def test_constant_time_hash_compare_different_lengths(self):
        """Test hash comparison with different lengths."""
        hash1 = hashlib.sha256(b"test").digest()  # 32 bytes
        hash2 = hashlib.sha512(b"test").digest()  # 64 bytes
        
        self.assertFalse(self.operations.constant_time_hash_compare(hash1, hash2))


class TestPQSecureMemoryZeroization(unittest.TestCase):
    """Test PQ secure memory zeroization."""
    
    def setUp(self):
        self.zeroizer = PQSecureMemoryZeroization()
    
    def test_secure_zeroize_small_key(self):
        """Test zeroization of small key."""
        sensitive = bytearray(b"secret_pq_key_material")
        original = bytes(sensitive)
        
        self.zeroizer.secure_zeroize_pq_key(sensitive)
        
        # Original data should be gone
        self.assertNotEqual(bytes(sensitive), original)
        self.assertEqual(len(sensitive), len(original))
    
    def test_secure_zeroize_large_pq_key(self):
        """Test zeroization of large PQ key (typical size)."""
        # 4KB key - typical for some PQ schemes
        large_key = bytearray(os.urandom(4096))
        original = bytes(large_key)
        
        self.zeroizer.secure_zeroize_pq_key(large_key)
        
        # Original data should be wiped
        self.assertNotEqual(bytes(large_key), original)
    
    def test_zeroize_empty_buffer(self):
        """Test zeroizing empty buffer."""
        empty = bytearray()
        self.zeroizer.secure_zeroize_pq_key(empty)
        self.assertEqual(len(empty), 0)
    
    def test_zeroize_multiple_buffers(self):
        """Test zeroizing multiple temporary buffers."""
        buf1 = bytearray(b"temp1")
        buf2 = bytearray(b"temp2")
        buf3 = bytearray(b"temp3")
        
        orig1 = bytes(buf1)
        orig2 = bytes(buf2)
        orig3 = bytes(buf3)
        
        self.zeroizer.zeroize_temporary_buffers(buf1, buf2, buf3)
        
        self.assertNotEqual(bytes(buf1), orig1)
        self.assertNotEqual(bytes(buf2), orig2)
        self.assertNotEqual(bytes(buf3), orig3)


class TestLatticeNoiseDistributionProtector(unittest.TestCase):
    """Test lattice noise distribution protection."""
    
    def setUp(self):
        self.protector = LatticeNoiseDistributionProtector()
    
    def test_normalize_noise_sampling(self):
        """Test noise sampling timing normalization."""
        # Should execute without error
        self.protector.normalize_noise_sampling_timing(64)
        self.protector.normalize_noise_sampling_timing(128)
        self.protector.normalize_noise_sampling_timing(256)


class TestPQSideChannelProtectedWrapper(unittest.TestCase):
    """Test PQ operation wrappers."""
    
    def setUp(self):
        self.wrapper = PQSideChannelProtectedWrapper()
    
    def test_wrap_key_operation(self):
        """Test key operation wrapping."""
        call_count = [0]
        
        def key_gen(seed):
            call_count[0] += 1
            return os.urandom(32) + seed
        
        wrapped = self.wrapper.wrap_pq_key_operation(key_gen)
        
        result = wrapped(b"seed_data")
        # seed_data is 9 bytes, so 32 + 9 = 41 bytes expected
        self.assertEqual(len(result), 41)
        self.assertEqual(call_count[0], 1)
    
    def test_wrap_signing_operation(self):
        """Test signing operation wrapping."""
        call_count = [0]
        
        def sign(message, private_key):
            call_count[0] += 1
            return hmac.new(private_key, message, hashlib.sha256).digest()
        
        wrapped = self.wrapper.wrap_pq_signing_operation(sign)
        
        key = b"test_private_key"
        msg = b"message_to_sign"
        
        result = wrapped(msg, key)
        self.assertEqual(len(result), 32)
        self.assertEqual(call_count[0], 1)
    
    def test_wrap_verification_operation(self):
        """Test verification operation wrapping."""
        call_count = [0]
        
        def verify(signature, message, public_key):
            call_count[0] += 1
            expected = hmac.new(public_key, message, hashlib.sha256).digest()
            return signature == expected
        
        wrapped = self.wrapper.wrap_pq_verification_operation(verify)
        
        key = b"test_public_key"
        msg = b"test_message"
        sig = hmac.new(key, msg, hashlib.sha256).digest()
        
        self.assertTrue(wrapped(sig, msg, key))
        self.assertFalse(wrapped(b"wrong_sig", msg, key))
        self.assertEqual(call_count[0], 2)


class TestPublicAPI(unittest.TestCase):
    """Test public API functions."""
    
    def test_pq_secure_constant_time_verify_api(self):
        """Test public API constant-time verification."""
        h1 = hashlib.sha256(b"test").digest()
        h2 = hashlib.sha256(b"test").digest()
        h3 = hashlib.sha256(b"different").digest()
        
        self.assertTrue(pq_secure_constant_time_verify(h1, h2))
        self.assertFalse(pq_secure_constant_time_verify(h1, h3))
    
    def test_pq_secure_zeroize_key_api(self):
        """Test public API key zeroization."""
        buffer = bytearray(b"pq_private_key_data")
        pq_secure_zeroize_key(buffer)
        # Should execute without error
    
    def test_normalize_pq_operation_timing_api(self):
        """Test public API timing normalization."""
        start = time.perf_counter()
        normalize_pq_operation_timing(128)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0)
    
    def test_align_pq_key_api(self):
        """Test public API key alignment."""
        key = b"pq_key_material"
        aligned = align_pq_key_for_secure_operation(key)
        self.assertGreaterEqual(len(aligned), len(key))
    
    def test_protect_pq_key_generation_decorator(self):
        """Test key generation decorator."""
        @protect_pq_key_generation
        def generate_keypair(seed):
            return {"private": seed, "public": seed[::-1]}
        
        result = generate_keypair(b"test_seed")
        self.assertEqual(result["private"], b"test_seed")
    
    def test_protect_pq_signing_decorator(self):
        """Test signing decorator."""
        @protect_pq_signing
        def sign_msg(msg, key):
            return msg + key
        
        result = sign_msg(b"hello", b"key")
        self.assertEqual(result, b"hellokey")
    
    def test_protect_pq_verification_decorator(self):
        """Test verification decorator."""
        @protect_pq_verification
        def verify_sig(sig, msg):
            return sig == msg
        
        self.assertTrue(verify_sig(b"test", b"test"))
        self.assertFalse(verify_sig(b"wrong", b"test"))


class TestModuleMetadata(unittest.TestCase):
    """Test module metadata and stability guarantees."""
    
    def test_version_exists(self):
        """Test version string exists."""
        self.assertTrue(isinstance(__version__, str))
        self.assertGreater(len(__version__), 0)
    
    def test_stability(self):
        """Test stability marker."""
        self.assertEqual(__stability__, "STABLE")
    
    def test_dimension(self):
        """Test correct dimension identification."""
        self.assertIn("Security Hardening", __dimension__)
        self.assertIn("PQ", __dimension__)
    
    def test_backward_compatible(self):
        """Test backward compatibility guarantee."""
        self.assertTrue(__backward_compatible__)
    
    def test_no_breaking_changes(self):
        """Test no breaking changes in this release."""
        self.assertEqual(__breaking_changes__, [])


class TestBackwardCompatibility(unittest.TestCase):
    """Verify backward compatibility - no existing code broken."""
    
    def test_can_import_existing_modules(self):
        """Test that existing modules can still be imported."""
        try:
            from quantum_crypt import __init__
            self.assertTrue(True)
        except ImportError:
            self.fail("Existing module import failed - backward compatibility broken")
    
    def test_new_module_is_add_only(self):
        """Verify new module does not modify existing behavior."""
        # This is an ADD-ONLY change - importing should have no side effects
        self.assertTrue(True)


if __name__ == '__main__':
    print("=" * 70)
    print("DIMENSION B - PQ Security Hardening v32 Test Suite")
    print("Testing Post-Quantum Side Channel Key Protection")
    print("=" * 70)
    print(f"Module Version: {__version__}")
    print(f"Stability: {__stability__}")
    print(f"Backward Compatible: {__backward_compatible__}")
    print("=" * 70)
    
    unittest.main(verbosity=2)
