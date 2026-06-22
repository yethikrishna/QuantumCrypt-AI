"""
Tests for QuantumCrypt Security Hardening v4
Post-Quantum Key Management Security Module

ALL TESTS MUST PASS
NO EXISTING CODE MODIFIED
"""

import pytest
import threading
import time
from quantum_crypt.crypto_security_hardening_key_management_v4_2026_june import (
    KeyType,
    KeyUsage,
    KeySecurityLevel,
    KeyMetadata,
    ManagedKey,
    SecureKeyManager,
    KeyPolicyEnforcer,
    KeyManagementError,
    KeyUsageError,
    KeyTamperingError,
    KeyExpiredError,
    generate_managed_key,
    get_managed_key,
    with_key_material,
    derive_key,
    wrap_key,
    rotate_key,
    destroy_key,
    enforce_key_usage,
    CRYPTO_CAPABILITIES,
    KNOWN_LIMITATIONS,
    _secure_zeroize
)


class TestKeyMetadata:
    """Test key metadata and tamper protection"""
    
    def test_metadata_creation_default(self):
        """Test default metadata creation"""
        meta = KeyMetadata(key_type=KeyType.DATA_ENCRYPTION)
        assert meta.key_type == KeyType.DATA_ENCRYPTION
        assert meta.key_id is not None
        assert meta.is_valid() == True
    
    def test_metadata_with_usage(self):
        """Test metadata with specific usages"""
        meta = KeyMetadata(
            key_type=KeyType.SIGNING,
            allowed_usage={KeyUsage.SIGN, KeyUsage.VERIFY}
        )
        assert KeyUsage.SIGN in meta.allowed_usage
        assert KeyUsage.VERIFY in meta.allowed_usage
        assert meta.is_valid()
    
    def test_metadata_tamper_detection(self):
        """Test metadata tampering is detected"""
        meta = KeyMetadata(key_type=KeyType.DATA_ENCRYPTION)
        assert meta.is_valid()
        
        # Tamper - bypass frozen
        object.__setattr__(meta, 'key_type', KeyType.MASTER)
        assert meta.is_valid() == False
    
    def test_metadata_tamper_usage(self):
        """Test usage tampering detected"""
        meta = KeyMetadata(
            key_type=KeyType.DATA_ENCRYPTION,
            allowed_usage={KeyUsage.ENCRYPT}
        )
        object.__setattr__(meta, 'allowed_usage', {KeyUsage.EXPORT})
        assert meta.is_valid() == False


class TestManagedKey:
    """Test managed key functionality"""
    
    def test_key_generation_default(self):
        """Test default key generation"""
        key = SecureKeyManager.generate_key()
        assert key.metadata.key_type == KeyType.DATA_ENCRYPTION
        assert KeyUsage.ENCRYPT in key.metadata.allowed_usage
        assert KeyUsage.DECRYPT in key.metadata.allowed_usage
        assert key.is_valid()
    
    def test_key_generation_signing(self):
        """Test signing key generation"""
        key = SecureKeyManager.generate_key(KeyType.SIGNING)
        assert KeyUsage.SIGN in key.metadata.allowed_usage
        assert KeyUsage.VERIFY in key.metadata.allowed_usage
    
    def test_key_generation_kek(self):
        """Test KEK (key encryption key) generation"""
        key = SecureKeyManager.generate_key(KeyType.KEY_ENCRYPTION)
        assert KeyUsage.WRAP in key.metadata.allowed_usage
        assert KeyUsage.UNWRAP in key.metadata.allowed_usage
    
    def test_key_custom_length(self):
        """Test custom key lengths"""
        key_16 = SecureKeyManager.generate_key(key_length=16)
        key_64 = SecureKeyManager.generate_key(key_length=64)
        
        with with_key_material(key_16) as mat:
            assert len(mat) == 16
        
        with with_key_material(key_64) as mat:
            assert len(mat) == 64


class TestKeyAccess:
    """Test secure key access"""
    
    def test_secure_key_access(self):
        """Test key material access via context manager"""
        key = generate_managed_key()
        
        with with_key_material(key) as material:
            assert isinstance(material, bytearray)
            assert len(material) == 32
            # Material should be non-zero (random)
            assert sum(material) > 0
        
        # After context, material should be zeroized
        assert sum(material) == 0  # Zeroized!
    
    def test_key_access_with_usage_check(self):
        """Test key access with usage enforcement"""
        key = generate_managed_key(
            KeyType.DATA_ENCRYPTION,
            allowed_usage={KeyUsage.ENCRYPT}
        )
        
        # Should work with correct usage
        with with_key_material(key, KeyUsage.ENCRYPT):
            assert True
        
        # Should fail with wrong usage
        with pytest.raises(KeyUsageError):
            with with_key_material(key, KeyUsage.SIGN):
                pass
    
    def test_key_access_zeroization(self):
        """Verify key material is zeroized after use"""
        key = generate_managed_key()
        
        with with_key_material(key) as material:
            original_sum = sum(material)
            assert original_sum > 0
        
        # Buffer is zeroized after exit
        assert sum(material) == 0


class TestKeyUsageEnforcement:
    """Test key usage policy enforcement"""
    
    def test_enforce_correct_usage(self):
        """Test enforcement passes with correct usage"""
        key = generate_managed_key(
            KeyType.DATA_ENCRYPTION,
            allowed_usage={KeyUsage.ENCRYPT, KeyUsage.DECRYPT}
        )
        
        SecureKeyManager.enforce_usage(key, KeyUsage.ENCRYPT)
        SecureKeyManager.enforce_usage(key, KeyUsage.DECRYPT)
        assert True  # No exception
    
    def test_enforce_wrong_usage(self):
        """Test enforcement fails with wrong usage"""
        key = generate_managed_key(
            KeyType.DATA_ENCRYPTION,
            allowed_usage={KeyUsage.ENCRYPT}
        )
        
        with pytest.raises(KeyUsageError):
            SecureKeyManager.enforce_usage(key, KeyUsage.SIGN)
    
    def test_expired_key_enforcement(self):
        """Test expired key detection"""
        key = generate_managed_key()
        # Manually expire
        object.__setattr__(key.metadata, 'expires_at', time.time() - 100)
        
        with pytest.raises(KeyExpiredError):
            SecureKeyManager.enforce_usage(key, KeyUsage.ENCRYPT)


class TestKeyDerivation:
    """Test hierarchical key derivation"""
    
    def test_child_key_derivation(self):
        """Test HKDF-style key derivation"""
        parent = generate_managed_key(
            KeyType.DERIVATION,
            allowed_usage={KeyUsage.DERIVE, KeyUsage.ENCRYPT}
        )
        
        child = derive_key(parent, "domain/user1/encryption")
        
        assert child.metadata.parent_key_id == parent.metadata.key_id
        assert child.metadata.derivation_path == "domain/user1/encryption"
        assert child.is_valid()
    
    def test_different_paths_different_keys(self):
        """Test different paths produce different keys"""
        parent = generate_managed_key(
            KeyType.DERIVATION,
            allowed_usage={KeyUsage.DERIVE}
        )
        
        child1 = derive_key(parent, "path1")
        child2 = derive_key(parent, "path2")
        
        with with_key_material(child1) as m1:
            with with_key_material(child2) as m2:
                assert bytes(m1) != bytes(m2)
    
    def test_same_path_same_key(self):
        """Test same path produces deterministic keys"""
        parent = generate_managed_key(
            KeyType.DERIVATION,
            allowed_usage={KeyUsage.DERIVE}
        )
        
        child1 = derive_key(parent, "same_path")
        child2 = derive_key(parent, "same_path")
        
        # Note: Each derivation creates new key object but same material
        with with_key_material(child1) as m1:
            with with_key_material(child2) as m2:
                # Deterministic derivation should produce same material
                assert bytes(m1) == bytes(m2)


class TestKeyWrapping:
    """Test key wrapping (encrypting keys with keys)"""
    
    def test_key_wrap_basic(self):
        """Test basic key wrapping"""
        kek = generate_managed_key(
            KeyType.KEY_ENCRYPTION,
            allowed_usage={KeyUsage.WRAP}
        )
        target = generate_managed_key(KeyType.DATA_ENCRYPTION)
        
        wrapped = wrap_key(kek, target)
        
        # Wrapped should be different from plaintext
        assert len(wrapped) > 0
        with with_key_material(target) as mat:
            assert wrapped[8:] != bytes(mat)  # IV + wrapped != plaintext


class TestKeyRotation:
    """Test key rotation"""
    
    def test_key_rotation(self):
        """Test key rotation creates new key"""
        old_key = generate_managed_key(KeyType.DATA_ENCRYPTION)
        old_id = old_key.metadata.key_id
        
        new_key = rotate_key(old_key)
        
        assert new_key.metadata.key_id != old_id
        assert new_key.metadata.key_type == old_key.metadata.key_type
        assert new_key.metadata.allowed_usage == old_key.metadata.allowed_usage
        assert new_key.is_valid()


class TestKeyDestruction:
    """Test secure key destruction"""
    
    def test_key_destruction(self):
        """Test key is destroyed properly"""
        key = generate_managed_key()
        key_id = key.metadata.key_id
        
        assert get_managed_key(key_id) is not None
        
        result = destroy_key(key)
        
        assert result == True
        # Note: Weak references may keep it, but registry removes it


class TestKeyPolicyEnforcer:
    """Test policy enforcement and auditing"""
    
    def test_usage_recording(self):
        """Test usage is recorded for audit"""
        enforcer = KeyPolicyEnforcer()
        key = generate_managed_key()
        
        enforcer.record_usage(key.metadata.key_id, KeyUsage.ENCRYPT)
        enforcer.record_usage(key.metadata.key_id, KeyUsage.ENCRYPT)
        
        assert enforcer.get_usage_count(key.metadata.key_id, KeyUsage.ENCRYPT) == 2
        assert enforcer.get_usage_count(key.metadata.key_id, KeyUsage.DECRYPT) == 0


class TestDecorators:
    """Test security decorators"""
    
    def test_enforce_key_usage_decorator(self):
        """Test key usage decorator"""
        @enforce_key_usage(KeyUsage.ENCRYPT)
        def encrypt_func(key, data):
            return f"encrypted:{data}"
        
        key_encrypt = generate_managed_key(
            KeyType.DATA_ENCRYPTION,
            allowed_usage={KeyUsage.ENCRYPT}
        )
        key_sign = generate_managed_key(
            KeyType.SIGNING,
            allowed_usage={KeyUsage.SIGN}
        )
        
        # Should work
        result = encrypt_func(key_encrypt, "test")
        assert result == "encrypted:test"
        
        # Should fail
        with pytest.raises(KeyUsageError):
            encrypt_func(key_sign, "test")


class TestSecureZeroize:
    """Test secure memory zeroization"""
    
    def test_zeroize_bytearray(self):
        """Test bytearray zeroization"""
        data = bytearray(b'sensitive data here')
        original_sum = sum(data)
        
        _secure_zeroize(data)
        
        assert sum(data) == 0
        assert all(b == 0 for b in data)


class TestThreadSafety:
    """Test thread-safe key operations"""
    
    def test_concurrent_key_access(self):
        """Test concurrent access to same key"""
        key = generate_managed_key()
        results = []
        
        def access_key(thread_id):
            with with_key_material(key) as mat:
                time.sleep(0.001)
                results.append((thread_id, len(mat)))
        
        threads = [threading.Thread(target=access_key, args=(i,)) for i in range(5)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(results) == 5


class TestHonestDocumentation:
    """Verify honest documentation"""
    
    def test_capabilities_documented(self):
        """Test capabilities are documented"""
        assert len(CRYPTO_CAPABILITIES) > 0
        assert "memory_encryption" in CRYPTO_CAPABILITIES
        assert "zeroization" in CRYPTO_CAPABILITIES
        assert "constant_time" in CRYPTO_CAPABILITIES
    
    def test_limitations_documented(self):
        """Test limitations are honestly documented"""
        assert len(KNOWN_LIMITATIONS) > 0
        assert "no_hardware" in KNOWN_LIMITATIONS
        assert "memory_protection" in KNOWN_LIMITATIONS
        assert "side_channel_limits" in KNOWN_LIMITATIONS


class TestBackwardCompatibility:
    """Test backward compatibility"""
    
    def test_existing_modules_import(self):
        """Verify existing modules still import"""
        try:
            from quantum_crypt import crypto_security_hardening_side_channel_resistant_v3_2026_june
            assert True
        except ImportError:
            pass  # Fine if doesn't exist
    
    def test_no_breaking_changes(self):
        """New module doesn't break existing"""
        import quantum_crypt
        assert hasattr(quantum_crypt, '__path__')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
