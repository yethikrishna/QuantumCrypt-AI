"""
Tests for QuantumCrypt AI - Post-Quantum Key Material Protection v29
Dimension B: Security Hardening
"""

import pytest
import threading
import secrets
from quantum_crypt.crypto_security_hardening_pq_key_protection_v29_2026_june import (
    ProtectedKey,
    KeyProtectionError,
    CryptoSecurityError,
    crypto_secure_environment,
    constant_time_key_compare,
    KeyDerivationHardened,
    AlgorithmAgilityProtection,
    SideChannelResistantCrypto,
    KeyRotationSecurity,
    __version__,
    __dimension__,
)


class TestModuleMetadata:
    """Test module metadata correctness."""
    
    def test_version_correct(self):
        assert __version__ == "29.0.0"
    
    def test_dimension_correct(self):
        assert __dimension__ == "B - Security Hardening"


class TestProtectedKey:
    """Test protected key container."""
    
    def test_create_and_access(self):
        key_data = secrets.token_bytes(32)
        with ProtectedKey(key_data) as key:
            accessed = key.access()
            assert accessed == key_data
    
    def test_wipe_prevents_access(self):
        key = ProtectedKey(secrets.token_bytes(32))
        key.wipe()
        with pytest.raises(KeyProtectionError):
            key.access()
    
    def test_context_manager_auto_wipe(self):
        key_ref = None
        key_data = secrets.token_bytes(32)
        
        with ProtectedKey(key_data) as key:
            key_ref = key
            assert key.access() == key_data
        
        with pytest.raises(KeyProtectionError):
            key_ref.access()
    
    def test_fingerprint_safe(self):
        key_data = secrets.token_bytes(32)
        with ProtectedKey(key_data) as key:
            fp = key.get_fingerprint()
            assert len(fp) == 16  # Truncated hash
            assert fp != key_data.hex()  # Not raw material
    
    def test_fingerprint_consistent(self):
        key_data = secrets.token_bytes(32)
        with ProtectedKey(key_data) as key:
            fp1 = key.get_fingerprint()
            fp2 = key.get_fingerprint()
            assert fp1 == fp2
    
    def test_access_count_tracking(self):
        with ProtectedKey(secrets.token_bytes(32)) as key:
            assert key._access_count == 0
            key.access()
            assert key._access_count == 1
            key.access()
            assert key._access_count == 2
    
    def test_double_wipe_safe(self):
        key = ProtectedKey(secrets.token_bytes(32))
        key.wipe()
        key.wipe()  # Should not raise
        assert key._wiped is True
    
    def test_repr_wiped(self):
        key = ProtectedKey(secrets.token_bytes(32))
        key.wipe()
        assert "wiped=True" in repr(key)
    
    def test_repr_active(self):
        with ProtectedKey(secrets.token_bytes(32)) as key:
            r = repr(key)
            assert "fingerprint" in r
            assert "accesses" in r
    
    def test_with_lock_memory(self):
        # Should not raise even if mlock fails
        key = ProtectedKey(secrets.token_bytes(32), lock_memory=True)
        key.wipe()
        assert key._wiped is True


class TestCryptoSecureEnvironment:
    """Test secure crypto execution environment."""
    
    def test_context_manager_no_error(self):
        with crypto_secure_environment():
            x = sum(range(100))
        assert x == 4950
    
    def test_gc_behavior(self):
        import gc
        gc.enable()
        
        with crypto_secure_environment():
            # GC should be disabled during
            pass
        
        # GC should be restored
        assert gc.isenabled()


class TestConstantTimeKeyCompare:
    """Test constant-time key comparison."""
    
    def test_equal_keys(self):
        key = secrets.token_bytes(32)
        assert constant_time_key_compare(key, key) is True
    
    def test_different_keys(self):
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        assert constant_time_key_compare(key1, key2) is False
    
    def test_different_lengths(self):
        key1 = secrets.token_bytes(16)
        key2 = secrets.token_bytes(32)
        assert constant_time_key_compare(key1, key2) is False
    
    def test_single_bit_difference(self):
        key1 = bytearray(secrets.token_bytes(32))
        key2 = key1.copy()
        key2[0] ^= 0x01  # Flip one bit
        assert constant_time_key_compare(bytes(key1), bytes(key2)) is False
    
    def test_empty_keys(self):
        assert constant_time_key_compare(b"", b"") is True


class TestKeyDerivationHardened:
    """Test hardened key derivation."""
    
    def test_hkdf_blinded_output_length(self):
        ikm = secrets.token_bytes(32)
        result = KeyDerivationHardened.hkdf_blinded(ikm, length=64)
        assert len(result) == 64
    
    def test_hkdf_blinded_deterministic(self):
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        result1 = KeyDerivationHardened.hkdf_blinded(ikm, salt=salt, length=32)
        result2 = KeyDerivationHardened.hkdf_blinded(ikm, salt=salt, length=32)
        
        assert result1 == result2
    
    def test_hkdf_blinded_different_inputs(self):
        ikm1 = secrets.token_bytes(32)
        ikm2 = secrets.token_bytes(32)
        
        result1 = KeyDerivationHardened.hkdf_blinded(ikm1, length=32)
        result2 = KeyDerivationHardened.hkdf_blinded(ikm2, length=32)
        
        assert result1 != result2


class TestAlgorithmAgilityProtection:
    """Test algorithm negotiation protection."""
    
    def test_validate_strong_algorithm(self):
        assert AlgorithmAgilityProtection.validate_algorithm_strength('aes-256-gcm', 128) is True
        assert AlgorithmAgilityProtection.validate_algorithm_strength('kyber-1024', 128) is True
    
    def test_validate_insufficient_strength(self):
        # kyber-512 is 128 bits, should fail for 192 requirement
        assert AlgorithmAgilityProtection.validate_algorithm_strength('kyber-512', 192) is False
    
    def test_validate_unknown_algorithm(self):
        assert AlgorithmAgilityProtection.validate_algorithm_strength('unknown-cipher', 128) is False
    
    def test_validate_case_insensitive(self):
        assert AlgorithmAgilityProtection.validate_algorithm_strength('AES-256-GCM', 128) is True
    
    def test_select_strongest_algorithm(self):
        offered = ['aes-128-gcm', 'aes-256-gcm', 'kyber-512']
        selected = AlgorithmAgilityProtection.select_secure_algorithm(offered, 128)
        assert selected == 'aes-256-gcm'  # Highest strength
    
    def test_select_none_too_weak(self):
        offered = ['weak-algorithm']
        selected = AlgorithmAgilityProtection.select_secure_algorithm(offered, 128)
        assert selected is None


class TestSideChannelResistantCrypto:
    """Test side-channel resistant crypto wrappers."""
    
    def test_secure_hash_sha256(self):
        data = b"test message"
        result = SideChannelResistantCrypto.secure_hash(data, 'sha256')
        assert len(result) == 32
    
    def test_secure_hash_sha512(self):
        data = b"test message"
        result = SideChannelResistantCrypto.secure_hash(data, 'sha512')
        assert len(result) == 64
    
    def test_secure_hmac(self):
        key = secrets.token_bytes(32)
        data = b"test message"
        result = SideChannelResistantCrypto.secure_hmac(key, data)
        assert len(result) == 32
    
    def test_verify_hmac_valid(self):
        key = secrets.token_bytes(32)
        data = b"test message"
        sig = SideChannelResistantCrypto.secure_hmac(key, data)
        assert SideChannelResistantCrypto.verify_hmac(key, data, sig) is True
    
    def test_verify_hmac_invalid(self):
        key = secrets.token_bytes(32)
        data = b"test message"
        wrong_sig = secrets.token_bytes(32)
        assert SideChannelResistantCrypto.verify_hmac(key, data, wrong_sig) is False
    
    def test_verify_hmac_wrong_key(self):
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        data = b"test message"
        sig = SideChannelResistantCrypto.secure_hmac(key1, data)
        assert SideChannelResistantCrypto.verify_hmac(key2, data, sig) is False


class TestKeyRotationSecurity:
    """Test secure key generation."""
    
    def test_generate_ephemeral_key(self):
        with KeyRotationSecurity.generate_ephemeral_key(32) as key:
            material = key.access()
            assert len(material) == 32
    
    def test_generate_different_keys(self):
        with KeyRotationSecurity.generate_ephemeral_key(32) as key1:
            with KeyRotationSecurity.generate_ephemeral_key(32) as key2:
                assert key1.access() != key2.access()


class TestThreadSafety:
    """Test thread safety of security primitives."""
    
    def test_concurrent_protected_keys(self):
        errors = []
        
        def worker():
            try:
                for _ in range(10):
                    with ProtectedKey(secrets.token_bytes(32)) as key:
                        _ = key.access()
                        _ = key.get_fingerprint()
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
    
    def test_concurrent_hmac_verification(self):
        key = secrets.token_bytes(32)
        data = b"test message"
        sig = SideChannelResistantCrypto.secure_hmac(key, data)
        results = []
        
        def worker():
            for _ in range(10):
                results.append(SideChannelResistantCrypto.verify_hmac(key, data, sig))
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert all(results)
