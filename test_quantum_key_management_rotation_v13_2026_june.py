"""
Tests for Quantum-Resistant Key Management & Rotation Engine (Dimension A - Feature Expansion)
ADD-ONLY tests - no modifications to existing tests
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from quantum_key_management_rotation_v13_2026_june import (
    QuantumKeyManagementManager,
    SecureKeyStore,
    KeyRotationManager,
    KeyDerivationFunction,
    QuantumResistantKeyWrapper,
    CryptographicKey,
    KeyStatus,
    KeyAlgorithm,
    KeyPurpose,
)
from datetime import datetime, timedelta


class TestKeyDerivationFunction:
    """Tests for HKDF key derivation"""
    
    def test_basic_key_derivation(self):
        """Test basic key derivation works"""
        master = b"test_master_key_material_32_bytes!!"
        derived = KeyDerivationFunction.derive_key(master, length=32)
        assert len(derived) == 32
        assert derived != master  # Should be different
    
    def test_deterministic_derivation(self):
        """Test derivation is deterministic with same inputs"""
        master = b"test_master_key_material_32_bytes!!"
        salt = b"test_salt"
        info = b"test_context"
        
        d1 = KeyDerivationFunction.derive_key(master, salt=salt, info=info)
        d2 = KeyDerivationFunction.derive_key(master, salt=salt, info=info)
        assert d1 == d2
    
    def test_different_info_produces_different_keys(self):
        """Test different context produces different keys"""
        master = b"test_master_key_material_32_bytes!!"
        d1 = KeyDerivationFunction.derive_key(master, info=b"context1")
        d2 = KeyDerivationFunction.derive_key(master, info=b"context2")
        assert d1 != d2
    
    def test_hierarchical_derivation(self):
        """Test hierarchical key chain derivation"""
        master = b"test_master_key_material_32_bytes!!"
        levels = ["root", "intermediate", "leaf"]
        keys = KeyDerivationFunction.derive_key_hierarchy(master, levels)
        
        assert len(keys) == 3
        assert "root" in keys
        assert "intermediate" in keys
        assert "leaf" in keys
        assert keys["root"] != keys["intermediate"]
        assert keys["intermediate"] != keys["leaf"]
    
    def test_variable_key_length(self):
        """Test key derivation with different lengths"""
        master = b"test_master_key_material_32_bytes!!"
        
        for length in [16, 24, 32, 64]:
            derived = KeyDerivationFunction.derive_key(master, length=length)
            assert len(derived) == length


class TestQuantumResistantKeyWrapper:
    """Tests for key wrapping"""
    
    def test_wrap_unwrap_cycle(self):
        """Test wrap and unwrap produces original key"""
        wrapper = QuantumResistantKeyWrapper()
        original = b"test_key_material_32_bytes_123456"
        
        wrapped, nonce, tag = wrapper.wrap_key(original)
        assert wrapped != original
        
        unwrapped = wrapper.unwrap_key(wrapped, nonce, tag)
        assert unwrapped == original
    
    def test_wrapping_produces_different_outputs(self):
        """Test same key wrapped twice produces different output (nonce)"""
        wrapper = QuantumResistantKeyWrapper()
        key = b"test_key_material_32_bytes_123456"
        
        w1, n1, t1 = wrapper.wrap_key(key)
        w2, n2, t2 = wrapper.wrap_key(key)
        
        assert w1 != w2
        assert n1 != n2
    
    def test_tamper_detection(self):
        """Test tampered wrapped key is detected"""
        wrapper = QuantumResistantKeyWrapper()
        key = b"test_key_material_32_bytes_123456"
        
        wrapped, nonce, tag = wrapper.wrap_key(key)
        
        # Tamper with the wrapped key
        tampered = bytes([wrapped[0] ^ 0xFF]) + wrapped[1:]
        
        result = wrapper.unwrap_key(tampered, nonce, tag)
        assert result is None
    
    def test_wrong_nonce_fails(self):
        """Test wrong nonce fails authentication"""
        wrapper = QuantumResistantKeyWrapper()
        key = b"test_key_material_32_bytes_123456"
        
        wrapped, nonce, tag = wrapper.wrap_key(key)
        wrong_nonce = bytes([b ^ 0xFF for b in nonce])
        
        result = wrapper.unwrap_key(wrapped, wrong_nonce, tag)
        assert result is None


class TestCryptographicKey:
    """Tests for key metadata class"""
    
    def test_key_is_active(self):
        """Test active status detection"""
        key = CryptographicKey(
            key_id="test",
            version=1,
            algorithm=KeyAlgorithm.AES_256_GCM,
            purpose=KeyPurpose.ENCRYPTION,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(),
            activated_at=datetime.now()
        )
        assert key.is_active() is True
    
    def test_revoked_key_not_active(self):
        """Test revoked keys are not active"""
        key = CryptographicKey(
            key_id="test",
            version=1,
            algorithm=KeyAlgorithm.AES_256_GCM,
            purpose=KeyPurpose.ENCRYPTION,
            status=KeyStatus.REVOKED,
            created_at=datetime.now()
        )
        assert key.is_active() is False
    
    def test_needs_rotation_detection(self):
        """Test rotation needed detection"""
        key = CryptographicKey(
            key_id="test",
            version=1,
            algorithm=KeyAlgorithm.AES_256_GCM,
            purpose=KeyPurpose.ENCRYPTION,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(),
            activated_at=datetime.now() - timedelta(hours=100),
            rotation_period_hours=24  # 1 day
        )
        assert key.needs_rotation() is True
    
    def test_fresh_key_no_rotation_needed(self):
        """Test fresh key doesn't need rotation"""
        key = CryptographicKey(
            key_id="test",
            version=1,
            algorithm=KeyAlgorithm.AES_256_GCM,
            purpose=KeyPurpose.ENCRYPTION,
            status=KeyStatus.ACTIVE,
            created_at=datetime.now(),
            activated_at=datetime.now(),
            rotation_period_hours=24 * 30
        )
        assert key.needs_rotation() is False


class TestSecureKeyStore:
    """Tests for secure key store"""
    
    def test_key_generation(self):
        """Test key generation creates valid key"""
        store = SecureKeyStore()
        key_id = store.generate_key()
        
        assert key_id is not None
        assert key_id.startswith("key_")
        
        key = store.get_key(key_id)
        assert key is not None
        assert key.status == KeyStatus.ACTIVE
        assert key.version == 1
    
    def test_different_key_purposes(self):
        """Test creating keys for different purposes"""
        store = SecureKeyStore()
        
        enc_id = store.generate_key(purpose=KeyPurpose.ENCRYPTION)
        sign_id = store.generate_key(purpose=KeyPurpose.SIGNING)
        
        enc_key = store.get_key(enc_id)
        sign_key = store.get_key(sign_id)
        
        assert enc_key.purpose == KeyPurpose.ENCRYPTION
        assert sign_key.purpose == KeyPurpose.SIGNING
    
    def test_key_material_retrieval(self):
        """Test key material can be retrieved"""
        store = SecureKeyStore()
        key_id = store.generate_key()
        
        material = store.get_key_material(key_id)
        assert material is not None
        assert len(material) == 32
    
    def test_key_revocation(self):
        """Test key revocation works"""
        store = SecureKeyStore()
        key_id = store.generate_key()
        
        success = store.revoke_key(key_id, reason="compromised")
        assert success is True
        
        key = store.get_key(key_id)
        assert key.status == KeyStatus.REVOKED
        assert key.revoked_at is not None
    
    def test_list_keys(self):
        """Test key listing"""
        store = SecureKeyStore()
        
        for i in range(5):
            store.generate_key()
        
        keys = store.list_keys()
        assert len(keys) == 5
    
    def test_audit_logging(self):
        """Test operations are audited"""
        store = SecureKeyStore()
        key_id = store.generate_key()
        
        # Access key to generate log entry
        store.get_key_material(key_id)
        
        logs = store.get_audit_log(key_id)
        assert len(logs) >= 2  # generation + access
    
    def test_nonexistent_key_returns_none(self):
        """Test non-existent key returns None"""
        store = SecureKeyStore()
        key = store.get_key("nonexistent_key")
        assert key is None
        
        material = store.get_key_material("nonexistent_key")
        assert material is None


class TestKeyRotationManager:
    """Tests for key rotation"""
    
    def test_key_rotation_creates_new_version(self):
        """Test rotation creates new key version"""
        store = SecureKeyStore()
        key_id = store.generate_key()
        rotation_manager = store.get_rotation_manager()
        
        old, new = rotation_manager.rotate_key(key_id)
        
        assert old is not None
        assert new is not None
        assert old.version == 1
        assert new.version == 2
        assert old.status == KeyStatus.ROTATED
        assert new.status == KeyStatus.ACTIVE
    
    def test_rotation_callbacks(self):
        """Test rotation callbacks are triggered"""
        store = SecureKeyStore()
        key_id = store.generate_key()
        rotation_manager = store.get_rotation_manager()
        
        callback_results = []
        def callback(kid, version):
            callback_results.append((kid, version))
        
        rotation_manager.register_rotation_callback(callback)
        rotation_manager.rotate_key(key_id)
        
        assert len(callback_results) == 1
        assert callback_results[0][0] == key_id
    
    def test_auto_rotation_detection(self):
        """Test automatic rotation detection"""
        store = SecureKeyStore()
        rotation_manager = store.get_rotation_manager()
        
        # Create key that needs rotation
        key_id = store.generate_key(rotation_period_hours=1)
        key = store.get_key(key_id)
        key.activated_at = datetime.now() - timedelta(hours=2)
        store._update_key(key)
        
        rotations = rotation_manager.check_and_rotate_all()
        assert len(rotations) >= 1


class TestQuantumKeyManagementManager:
    """Tests for main public API"""
    
    def test_manager_initialization(self):
        """Test manager initializes properly"""
        manager = QuantumKeyManagementManager()
        assert manager.key_store is not None
        assert manager.initialized_at is not None
    
    def test_create_different_key_types(self):
        """Test creating different key types"""
        manager = QuantumKeyManagementManager()
        
        enc_id = manager.create_encryption_key()
        sign_id = manager.create_signing_key()
        qr_id = manager.create_quantum_resistant_key()
        
        assert enc_id is not None
        assert sign_id is not None
        assert qr_id is not None
        
        enc_info = manager.get_key_info(enc_id)
        assert enc_info["purpose"] == "encryption"
        
        sign_info = manager.get_key_info(sign_id)
        assert sign_info["purpose"] == "signing"
    
    def test_get_key_info(self):
        """Test key info retrieval"""
        manager = QuantumKeyManagementManager()
        key_id = manager.create_encryption_key()
        
        info = manager.get_key_info(key_id)
        assert info is not None
        assert info["key_id"] == key_id
        assert info["version"] == 1
        assert info["is_active"] is True
        assert "status" in info
        assert "usage_count" in info
    
    def test_manual_key_rotation(self):
        """Test manual key rotation"""
        manager = QuantumKeyManagementManager()
        key_id = manager.create_encryption_key()
        
        result = manager.rotate_key(key_id)
        assert result["success"] is True
        assert result["old_version"] == 1
        assert result["new_version"] == 2
        
        info = manager.get_key_info(key_id)
        assert info["version"] == 2
    
    def test_child_key_derivation(self):
        """Test child key derivation"""
        manager = QuantumKeyManagementManager()
        key_id = manager.create_encryption_key()
        
        child1 = manager.derive_child_key(key_id, "context1")
        child2 = manager.derive_child_key(key_id, "context2")
        
        assert child1 is not None
        assert child2 is not None
        assert child1 != child2
        assert len(child1) == 32
    
    def test_dashboard_summary(self):
        """Test dashboard summary generation"""
        manager = QuantumKeyManagementManager()
        
        # Create some keys
        for i in range(3):
            manager.create_encryption_key()
        
        dashboard = manager.get_key_dashboard()
        
        assert dashboard["feature"] == "quantum_key_management_v13"
        assert dashboard["dimension"] == "A - Feature Expansion"
        assert dashboard["total_keys"] == 3
        assert dashboard["active_keys"] == 3
        assert "status_distribution" in dashboard
        assert "engine_uptime_seconds" in dashboard
    
    def test_automatic_rotation_run(self):
        """Test automatic rotation execution"""
        manager = QuantumKeyManagementManager()
        
        # Create some keys
        for i in range(2):
            manager.create_encryption_key()
        
        result = manager.run_automatic_rotation()
        assert "rotations_performed" in result
        assert "rotated_keys" in result
        assert "timestamp" in result


class TestBackwardCompatibility:
    """Tests ensuring backward compatibility - no existing code breakage"""
    
    def test_purely_additive_feature(self):
        """Verify this is purely additive - no dependencies on modified code"""
        import importlib
        spec = importlib.util.spec_from_file_location(
            "kms_module",
            os.path.join(os.path.dirname(__file__), 'quantum_crypt', 'quantum_key_management_rotation_v13_2026_june.py')
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Verify all exports exist
        assert hasattr(module, "QuantumKeyManagementManager")
        assert hasattr(module, "SecureKeyStore")
        assert hasattr(module, "KeyRotationManager")
        assert hasattr(module, "KeyDerivationFunction")
        
        # Can instantiate without errors
        manager = module.QuantumKeyManagementManager()
        assert manager is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
