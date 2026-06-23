"""
Tests for Security Hardening: Cryptographic Key Material Protection v18
QuantumCrypt-AI - June 2026

DIMENSION B - Security Hardening
Comprehensive test coverage for the new security module.
"""

import pytest
import secrets
import time
import gc
import hashlib

from quantum_crypt.crypto_security_hardening_key_material_protection_v18_2026_june import (
    KeyType,
    KeyProtectionLevel,
    KeyProtectionResult,
    SecureKeyMaterial,
    KeyDiversifier,
    ConstantTimeOperations,
    protect_key,
    constant_time_compare,
)


class TestKeyType:
    """Tests for KeyType enum."""
    
    def test_all_key_types_exist(self):
        """Test all key types are defined."""
        assert KeyType.SYMMETRIC.value == "symmetric"
        assert KeyType.ASYMMETRIC_PRIVATE.value == "asymmetric_private"
        assert KeyType.ASYMMETRIC_PUBLIC.value == "asymmetric_public"
        assert KeyType.KEM_SECRET.value == "kem_secret"
        assert KeyType.SIGNING.value == "signing"
        assert KeyType.VERIFICATION.value == "verification"
        assert KeyType.DERIVATION.value == "derivation"
        assert KeyType.EPHEMERAL.value == "ephemeral"


class TestKeyProtectionLevel:
    """Tests for KeyProtectionLevel enum."""
    
    def test_all_protection_levels_exist(self):
        """Test all protection levels are defined."""
        assert KeyProtectionLevel.SOFTWARE.value == "software"
        assert KeyProtectionLevel.HARDENED.value == "hardened"
        assert KeyProtectionLevel.MAXIMUM.value == "maximum"


class TestSecureKeyMaterial:
    """Tests for SecureKeyMaterial class."""
    
    def test_initialization_basic(self):
        """Test basic initialization."""
        key_data = secrets.token_bytes(32)
        key = SecureKeyMaterial(key_data)
        
        assert key.key_type == KeyType.SYMMETRIC
        assert key.key_size == 32
        assert key.is_destroyed == False
        assert key.usage_count == 0
    
    def test_initialization_with_type(self):
        """Test initialization with specific key type."""
        key_data = secrets.token_bytes(64)
        key = SecureKeyMaterial(key_data, key_type=KeyType.SIGNING)
        
        assert key.key_type == KeyType.SIGNING
        assert key.key_size == 64
    
    def test_initialization_with_size_validation(self):
        """Test initialization with expected size validation."""
        key_data = secrets.token_bytes(32)
        
        # Should succeed
        key = SecureKeyMaterial(key_data, expected_size=32)
        assert key.key_size == 32
        
        # Should fail
        with pytest.raises(ValueError, match="size mismatch"):
            SecureKeyMaterial(key_data, expected_size=64)
    
    def test_get_key_bytes(self):
        """Test key material retrieval."""
        original = secrets.token_bytes(32)
        key = SecureKeyMaterial(original)
        
        retrieved = key.get_key_bytes()
        
        assert retrieved == original
        assert key.usage_count == 1
    
    def test_get_key_bytes_multiple(self):
        """Test multiple key retrievals increment usage count."""
        key = SecureKeyMaterial(secrets.token_bytes(32))
        
        key.get_key_bytes()
        key.get_key_bytes()
        key.get_key_bytes()
        
        assert key.usage_count == 3
    
    def test_with_key_callback(self):
        """Test safe key access via callback."""
        original = secrets.token_bytes(32)
        key = SecureKeyMaterial(original)
        
        def process_key(k: bytes) -> bytes:
            return hashlib.sha256(k).digest()
        
        result = key.with_key(process_key)
        expected = hashlib.sha256(original).digest()
        
        assert result == expected
        assert key.usage_count == 1
    
    def test_constant_time_compare_equal(self):
        """Test constant time key comparison with equal keys."""
        key_data = secrets.token_bytes(32)
        key1 = SecureKeyMaterial(key_data)
        key2 = SecureKeyMaterial(key_data)
        
        assert key1.constant_time_compare(key2) == True
    
    def test_constant_time_compare_different(self):
        """Test constant time key comparison with different keys."""
        key1 = SecureKeyMaterial(secrets.token_bytes(32))
        key2 = SecureKeyMaterial(secrets.token_bytes(32))
        
        assert key1.constant_time_compare(key2) == False
    
    def test_constant_time_compare_with_bytes(self):
        """Test comparison with raw bytes."""
        key_data = secrets.token_bytes(32)
        key = SecureKeyMaterial(key_data)
        
        assert key.constant_time_compare(key_data) == True
        assert key.constant_time_compare(b"different_data") == False
    
    def test_context_manager(self):
        """Test context manager automatic cleanup."""
        key_data = secrets.token_bytes(32)
        
        with SecureKeyMaterial(key_data) as key:
            assert key.is_destroyed == False
            assert key.get_key_bytes() == key_data
        
        assert key.is_destroyed == True
    
    def test_destroy_explicit(self):
        """Test explicit key destruction."""
        key = SecureKeyMaterial(secrets.token_bytes(32))
        assert key.is_destroyed == False
        
        result = key.destroy()
        
        assert result.success == True
        assert result.operation == "destroy"
        assert key.is_destroyed == True
    
    def test_destroy_twice(self):
        """Test destroying already destroyed key."""
        key = SecureKeyMaterial(secrets.token_bytes(32))
        key.destroy()
        
        result = key.destroy()
        
        assert result.success == True
        assert len(result.warnings) > 0
        assert "already destroyed" in result.warnings[0]
    
    def test_access_after_destroy_raises(self):
        """Test that accessing destroyed key raises error."""
        key = SecureKeyMaterial(secrets.token_bytes(32))
        key.destroy()
        
        with pytest.raises(ValueError, match="destroyed"):
            key.get_key_bytes()
        
        with pytest.raises(ValueError, match="destroyed"):
            key.with_key(lambda x: x)
    
    def test_derive_subkey(self):
        """Test subkey derivation."""
        master = SecureKeyMaterial(secrets.token_bytes(32))
        salt = secrets.token_bytes(16)
        
        subkey = master.derive_subkey(salt)
        
        assert subkey.key_type == KeyType.DERIVATION
        assert subkey.key_size == master.key_size
        assert subkey.is_destroyed == False
        assert master.usage_count == 1
        
        # Derived key should be deterministic
        subkey2 = master.derive_subkey(salt)
        assert subkey.constant_time_compare(subkey2) == True
    
    def test_derive_subkey_different_salt(self):
        """Test different salts produce different subkeys."""
        master = SecureKeyMaterial(secrets.token_bytes(32))
        
        subkey1 = master.derive_subkey(b"salt1")
        subkey2 = master.derive_subkey(b"salt2")
        
        assert subkey1.constant_time_compare(subkey2) == False


class TestKeyDiversifier:
    """Tests for KeyDiversifier class."""
    
    def test_derive_domain_key(self):
        """Test domain key derivation."""
        master = SecureKeyMaterial(secrets.token_bytes(32))
        diversifier = KeyDiversifier(master)
        
        domain_key = diversifier.derive_domain_key(b"domain1", key_size=32)
        
        assert domain_key.key_type == KeyType.DERIVATION
        assert domain_key.key_size == 32
        assert domain_key.is_destroyed == False
    
    def test_domain_separation(self):
        """Test different domains produce different keys."""
        master = SecureKeyMaterial(secrets.token_bytes(32))
        diversifier = KeyDiversifier(master)
        
        key1 = diversifier.derive_domain_key(b"domain1")
        key2 = diversifier.derive_domain_key(b"domain2")
        
        assert key1.constant_time_compare(key2) == False
    
    def test_domain_deterministic(self):
        """Test same domain produces same key."""
        master = SecureKeyMaterial(secrets.token_bytes(32))
        diversifier = KeyDiversifier(master)
        
        key1 = diversifier.derive_domain_key(b"mydomain")
        key2 = diversifier.derive_domain_key(b"mydomain")
        
        assert key1.constant_time_compare(key2) == True


class TestConstantTimeOperations:
    """Tests for ConstantTimeOperations class."""
    
    def test_bytes_equal(self):
        """Test constant time bytes equality."""
        assert ConstantTimeOperations.bytes_equal(b"abc", b"abc") == True
        assert ConstantTimeOperations.bytes_equal(b"abc", b"def") == False
    
    def test_bytes_equal_different_lengths(self):
        """Test bytes equality with different lengths."""
        assert ConstantTimeOperations.bytes_equal(b"short", b"longer_string") == False
    
    def test_select_true(self):
        """Test constant time selection when condition is True."""
        a = b"option_a"
        b = b"option_b"
        
        result = ConstantTimeOperations.select(True, a, b)
        
        assert result == a
    
    def test_select_false(self):
        """Test constant time selection when condition is False."""
        a = b"option_a"
        b = b"option_b"
        
        result = ConstantTimeOperations.select(False, a, b)
        
        assert result == b
    
    def test_secure_wipe(self):
        """Test secure buffer wiping."""
        buffer = bytearray(b"sensitive_key_material_here")
        
        ConstantTimeOperations.secure_wipe(buffer)
        
        assert all(b == 0 for b in buffer)


class TestModuleLevelFunctions:
    """Tests for module-level convenience functions."""
    
    def test_protect_key(self):
        """Test protect_key convenience function."""
        key_data = secrets.token_bytes(32)
        
        with protect_key(key_data) as key:
            assert key.get_key_bytes() == key_data
            assert key.key_type == KeyType.SYMMETRIC
    
    def test_constant_time_compare_function(self):
        """Test module-level constant time compare."""
        assert constant_time_compare(b"test", b"test") == True
        assert constant_time_compare(b"test", b"best") == False


class TestTimingAttackResistance:
    """Tests for timing attack resistance."""
    
    def test_comparison_timing_consistency(self):
        """Test that key comparison timing is consistent."""
        key1 = SecureKeyMaterial(b"a" * 1000)
        key2_first_diff = SecureKeyMaterial(b"b" + b"a" * 999)
        key2_last_diff = SecureKeyMaterial(b"a" * 999 + b"b")
        
        times_first = []
        times_last = []
        
        for _ in range(50):
            start = time.perf_counter_ns()
            key1.constant_time_compare(key2_first_diff)
            times_first.append(time.perf_counter_ns() - start)
            
            start = time.perf_counter_ns()
            key1.constant_time_compare(key2_last_diff)
            times_last.append(time.perf_counter_ns() - start)
        
        avg_first = sum(times_first) / len(times_first)
        avg_last = sum(times_last) / len(times_last)
        ratio = max(avg_first, avg_last) / min(avg_first, avg_last)
        
        # Timing should be reasonably consistent
        assert ratio < 2.0, f"Timing variance too high: {ratio:.2f}x"


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""
    
    def test_empty_key(self):
        """Test handling of empty key material."""
        with SecureKeyMaterial(b"") as key:
            assert key.key_size == 0
            assert key.get_key_bytes() == b""
    
    def test_large_key(self):
        """Test handling of large key material."""
        key_data = secrets.token_bytes(4096)
        
        with SecureKeyMaterial(key_data) as key:
            assert key.key_size == 4096
            assert key.get_key_bytes() == key_data
    
    def test_garbage_collection_cleanup(self):
        """Test keys are zeroized on garbage collection."""
        key = SecureKeyMaterial(b"sensitive_data_to_cleanup")
        buffer_ref = key._key_buffer
        
        del key
        gc.collect()
        
        # Buffer should be zeroized
        assert all(b == 0 for b in buffer_ref)
    
    def test_protection_levels(self):
        """Test all protection levels work."""
        key_data = secrets.token_bytes(32)
        
        for level in KeyProtectionLevel:
            key = SecureKeyMaterial(key_data, protection_level=level)
            assert key.is_destroyed == False
            key.destroy()
            assert key.is_destroyed == True
    
    def test_all_key_types(self):
        """Test all key types work."""
        key_data = secrets.token_bytes(32)
        
        for key_type in KeyType:
            key = SecureKeyMaterial(key_data, key_type=key_type)
            assert key.key_type == key_type
            key.destroy()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
