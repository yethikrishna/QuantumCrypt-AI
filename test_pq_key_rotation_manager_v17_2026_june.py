"""
Test Suite for Post-Quantum Key Rotation Manager v17
QuantumCrypt AI - Feature Expansion (Dimension A)

Comprehensive tests for key rotation management functionality.
All tests are ADD-ONLY - no modifications to existing production code.
"""

import pytest
import time
from quantum_crypt.pq_key_rotation_manager_v17_2026_june import (
    KeyRotationManager,
    ManagedKey,
    RotationEvent,
    RotationPolicy,
    KeyStatus,
    KeyType,
    RotationStrategy,
)


class TestKeyRotationManager:
    """Test suite for Post-Quantum Key Rotation Manager."""
    
    def test_manager_initialization(self):
        """Test manager initialization."""
        manager = KeyRotationManager()
        
        stats = manager.get_stats()
        assert stats["total_keys_created"] == 0
        assert stats["total_rotations"] == 0
        assert stats["total_active_keys"] == 0
    
    def test_create_key_basic(self):
        """Test basic key creation."""
        manager = KeyRotationManager()
        
        key_id = manager.create_key(KeyType.KYBER_KEM, activate=True)
        
        assert key_id.startswith("key_")
        assert len(key_id) > 10
        
        key = manager.get_key(key_id, increment_usage=False)
        assert key is not None
        assert key.key_type == KeyType.KYBER_KEM
        assert key.status == KeyStatus.ACTIVE
        assert key.version == 1
    
    def test_create_key_inactive(self):
        """Test creating key in pending state."""
        manager = KeyRotationManager()
        
        key_id = manager.create_key(KeyType.DILITHIUM_SIG, activate=False)
        key = manager.get_key(key_id, increment_usage=False)
        
        assert key.status == KeyStatus.PENDING_ACTIVATION
        assert key.activated_at is None
    
    def test_create_key_with_ttl(self):
        """Test creating key with TTL."""
        manager = KeyRotationManager()
        
        key_id = manager.create_key(KeyType.SYMMETRIC_AES, ttl_seconds=3600)
        key = manager.get_key(key_id, increment_usage=False)
        
        assert key.expires_at is not None
        assert key.expires_at > time.time()
    
    def test_get_key_increments_usage(self):
        """Test that key retrieval increments usage counter."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM)
        
        key1 = manager.get_key(key_id, increment_usage=True)
        key2 = manager.get_key(key_id, increment_usage=True)
        
        assert key2.usage_count == 2
    
    def test_get_key_no_increment(self):
        """Test key retrieval without usage increment."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM)
        
        key1 = manager.get_key(key_id, increment_usage=False)
        key2 = manager.get_key(key_id, increment_usage=False)
        
        assert key1.usage_count == 0
        assert key2.usage_count == 0
    
    def test_get_nonexistent_key(self):
        """Test retrieving non-existent key."""
        manager = KeyRotationManager()
        key = manager.get_key("nonexistent_key")
        
        assert key is None
    
    def test_get_active_keys(self):
        """Test retrieving active keys."""
        manager = KeyRotationManager()
        
        key1 = manager.create_key(KeyType.KYBER_KEM, activate=True)
        key2 = manager.create_key(KeyType.DILITHIUM_SIG, activate=True)
        key3 = manager.create_key(KeyType.FALCON_SIG, activate=False)
        
        active = manager.get_active_keys()
        assert len(active) == 2
    
    def test_get_active_keys_filtered(self):
        """Test retrieving active keys filtered by type."""
        manager = KeyRotationManager()
        
        manager.create_key(KeyType.KYBER_KEM, activate=True)
        manager.create_key(KeyType.KYBER_KEM, activate=True)
        manager.create_key(KeyType.DILITHIUM_SIG, activate=True)
        
        kyber_keys = manager.get_active_keys(KeyType.KYBER_KEM)
        assert len(kyber_keys) == 2
    
    def test_create_policy(self):
        """Test creating rotation policy."""
        manager = KeyRotationManager()
        
        policy_id = manager.create_policy(
            key_type=KeyType.KYBER_KEM,
            strategy=RotationStrategy.TIME_BASED,
            rotation_interval_seconds=3600,
        )
        
        assert policy_id.startswith("policy_")
    
    def test_rotate_key_on_demand(self):
        """Test on-demand key rotation."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM)
        
        success, new_key_id, error = manager.rotate_key(
            key_id,
            strategy=RotationStrategy.ON_DEMAND,
        )
        
        assert success is True
        assert error is None
        assert new_key_id is not None
        assert new_key_id.startswith("key_")
        
        old_key = manager.get_key(key_id, increment_usage=False)
        new_key = manager.get_key(new_key_id, increment_usage=False)
        
        assert old_key.status in [KeyStatus.PENDING_DEACTIVATION, KeyStatus.DEACTIVATED]
        assert old_key.next_key_id == new_key_id
        assert new_key.previous_key_id == key_id
        assert new_key.version == 2
    
    def test_rotate_nonexistent_key(self):
        """Test rotating non-existent key."""
        manager = KeyRotationManager()
        
        success, new_key_id, error = manager.rotate_key("nonexistent")
        
        assert success is False
        assert new_key_id is None
        assert error == "key_not_found"
    
    def test_needs_rotation_expired(self):
        """Test rotation check for expired key."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM, ttl_seconds=0)
        
        needs_rot, reason = manager.needs_rotation(key_id)
        
        assert needs_rot is True
        assert reason == "key_expired"
    
    def test_needs_rotation_usage_limit(self):
        """Test rotation check based on usage limit."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM)
        
        # Manually set usage count
        key = manager._keys[key_id]
        key.max_usage_count = 5
        key.usage_count = 10
        
        needs_rot, reason = manager.needs_rotation(key_id)
        
        assert needs_rot is True
        assert reason == "usage_limit_exceeded"
    
    def test_mark_compromised(self):
        """Test marking key as compromised."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM)
        
        result = manager.mark_compromised(key_id)
        
        assert result is True
        
        # Key should be rotated and deactivated
        key = manager.get_key(key_id, increment_usage=False)
        # After emergency rotation, key moves to deactivation
        assert key.status in [KeyStatus.COMPROMISED, KeyStatus.PENDING_DEACTIVATION, KeyStatus.DEACTIVATED]
        
        stats = manager.get_stats()
        assert stats["emergency_rotations"] >= 1
    
    def test_revoke_key(self):
        """Test key revocation."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM)
        
        result = manager.revoke_key(key_id)
        
        assert result is True
        
        key = manager.get_key(key_id, increment_usage=False)
        assert key.status == KeyStatus.DEACTIVATED
    
    def test_revoke_nonexistent_key(self):
        """Test revoking non-existent key."""
        manager = KeyRotationManager()
        result = manager.revoke_key("nonexistent")
        
        assert result is False
    
    def test_rotation_history(self):
        """Test rotation history tracking."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM)
        
        manager.rotate_key(key_id)
        history = manager.get_rotation_history()
        
        assert len(history) >= 1
        assert history[0].old_key_id == key_id
        assert history[0].success is True
    
    def test_rotation_history_filtered(self):
        """Test filtered rotation history."""
        manager = KeyRotationManager()
        
        key1 = manager.create_key(KeyType.KYBER_KEM)
        key2 = manager.create_key(KeyType.DILITHIUM_SIG)
        
        manager.rotate_key(key1)
        manager.rotate_key(key2)
        
        kyber_history = manager.get_rotation_history(KeyType.KYBER_KEM)
        assert len(kyber_history) == 1
        assert kyber_history[0].key_type == KeyType.KYBER_KEM
    
    def test_perform_scheduled_rotations(self):
        """Test scheduled rotation execution."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM, ttl_seconds=0)
        
        rotations = manager.perform_scheduled_rotations()
        
        assert rotations >= 1
    
    def test_key_age_property(self):
        """Test key age property."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM)
        key = manager.get_key(key_id, increment_usage=False)
        
        assert key.age_seconds >= 0
    
    def test_key_expired_property(self):
        """Test key expired property."""
        manager = KeyRotationManager()
        
        # Not expired
        key1_id = manager.create_key(KeyType.KYBER_KEM, ttl_seconds=3600)
        key1 = manager.get_key(key1_id, increment_usage=False)
        assert key1.is_expired is False
        
        # Expired
        key2_id = manager.create_key(KeyType.KYBER_KEM, ttl_seconds=0)
        key2 = manager.get_key(key2_id, increment_usage=False)
        assert key2.is_expired is True
    
    def test_key_usage_exceeded_property(self):
        """Test usage exceeded property."""
        manager = KeyRotationManager()
        key_id = manager.create_key(KeyType.KYBER_KEM)
        
        key = manager._keys[key_id]
        key.max_usage_count = 5
        key.usage_count = 3
        
        managed_key = manager.get_key(key_id, increment_usage=False)
        assert managed_key.usage_exceeded is False
        
        key.usage_count = 10
        managed_key = manager.get_key(key_id, increment_usage=False)
        assert managed_key.usage_exceeded is True
    
    def test_register_rotation_callback(self):
        """Test rotation callback registration."""
        manager = KeyRotationManager()
        callback_called = []
        
        def callback(event):
            callback_called.append(event)
        
        manager.register_rotation_callback(callback)
        
        key_id = manager.create_key(KeyType.KYBER_KEM)
        manager.rotate_key(key_id)
        
        assert len(callback_called) == 1
        assert callback_called[0].old_key_id == key_id
    
    def test_manager_stats(self):
        """Test manager statistics."""
        manager = KeyRotationManager()
        
        manager.create_key(KeyType.KYBER_KEM)
        manager.create_key(KeyType.DILITHIUM_SIG)
        
        stats = manager.get_stats()
        
        assert stats["total_keys_created"] == 2
        assert stats["total_active_keys"] == 2
        assert stats["total_managed_keys"] == 2
    
    def test_multiple_key_types(self):
        """Test creating keys of different types."""
        manager = KeyRotationManager()
        
        for key_type in KeyType:
            key_id = manager.create_key(key_type)
            key = manager.get_key(key_id, increment_usage=False)
            assert key.key_type == key_type
            assert len(key.key_material) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
