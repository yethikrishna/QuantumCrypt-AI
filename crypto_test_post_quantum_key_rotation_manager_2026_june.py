"""
Tests for Post-Quantum Key Rotation Manager
Dimension A: Feature Expansion - Test Coverage
"""

import pytest
import time
from quantum_crypt.post_quantum_key_rotation_manager_2026_june import (
    PostQuantumKeyRotationManager,
    CryptographicKey,
    KeyStatus,
    AlgorithmType,
    RotationStrategy,
    RotationEvent,
)


class TestCryptographicKey:
    """Test CryptographicKey dataclass"""
    
    def test_key_creation(self):
        """Test basic key creation"""
        key = CryptographicKey(
            key_id="test_key_123",
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            status=KeyStatus.ACTIVE,
            created_at=time.time(),
            activated_at=time.time(),
        )
        assert key.key_id == "test_key_123"
        assert key.algorithm == AlgorithmType.CRYSTALS_KYBER
        assert key.is_active() is True
    
    def test_key_is_valid_active(self):
        """Test valid active key"""
        key = CryptographicKey(
            key_id="test",
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            status=KeyStatus.ACTIVE,
            created_at=time.time(),
            activated_at=time.time(),
            expires_at=time.time() + 86400,
        )
        assert key.is_valid() is True
    
    def test_key_is_valid_expired(self):
        """Test expired key"""
        key = CryptographicKey(
            key_id="test",
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            status=KeyStatus.ACTIVE,
            created_at=time.time(),
            activated_at=time.time(),
            expires_at=time.time() - 100,
        )
        assert key.is_valid() is False
    
    def test_key_is_valid_retired(self):
        """Test retired key"""
        key = CryptographicKey(
            key_id="test",
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            status=KeyStatus.RETIRED,
            created_at=time.time(),
        )
        assert key.is_valid() is False
    
    def test_key_usage_increment(self):
        """Test usage counter increment"""
        key = CryptographicKey(
            key_id="test",
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            status=KeyStatus.ACTIVE,
            created_at=time.time(),
            usage_count=0,
        )
        key.increment_usage()
        assert key.usage_count == 1
        key.increment_usage()
        assert key.usage_count == 2
    
    def test_key_max_usage_exceeded(self):
        """Test key validity when max usage exceeded"""
        key = CryptographicKey(
            key_id="test",
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            status=KeyStatus.ACTIVE,
            created_at=time.time(),
            usage_count=100,
            max_usage=100,
        )
        assert key.is_valid() is False


class TestPostQuantumKeyRotationManager:
    """Test main rotation manager functionality"""
    
    def test_manager_initialization(self):
        """Test manager initialization"""
        manager = PostQuantumKeyRotationManager(
            default_rotation_days=30,
            grace_period_hours=12,
            max_keys_per_algorithm=3,
        )
        assert manager.default_rotation_days == 30
        assert manager.grace_period_seconds == 12 * 3600
        assert manager.max_keys_per_algorithm == 3
        assert len(manager.keys) == 0
    
    def test_create_key_basic(self):
        """Test basic key creation"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        assert key is not None
        assert key.key_id != ""
        assert key.algorithm == AlgorithmType.CRYSTALS_KYBER
        assert key.status == KeyStatus.ACTIVE
        assert key.key_material_hash != ""
        assert key.key_id in manager.keys
    
    def test_create_key_pending(self):
        """Test creating key without immediate activation"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(
            AlgorithmType.CRYSTALS_DILITHIUM,
            activate_immediately=False,
        )
        assert key.status == KeyStatus.PENDING
        assert key.activated_at is None
    
    def test_create_key_with_metadata(self):
        """Test creating key with custom metadata"""
        manager = PostQuantumKeyRotationManager()
        custom_meta = {"environment": "production", "owner": "security_team"}
        key = manager.create_key(
            AlgorithmType.FALCON,
            metadata=custom_meta,
        )
        assert key.metadata["environment"] == "production"
        assert key.metadata["owner"] == "security_team"
    
    def test_get_active_key(self):
        """Test retrieving active key"""
        manager = PostQuantumKeyRotationManager()
        created = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        active = manager.get_active_key(AlgorithmType.CRYSTALS_KYBER)
        
        assert active is not None
        assert active.key_id == created.key_id
    
    def test_get_active_key_none(self):
        """Test get active key when none exist"""
        manager = PostQuantumKeyRotationManager()
        active = manager.get_active_key(AlgorithmType.SPHINCS)
        assert active is None
    
    def test_get_key_by_id(self):
        """Test retrieving key by ID"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(AlgorithmType.NTRU)
        retrieved = manager.get_key(key.key_id)
        
        assert retrieved is not None
        assert retrieved.key_id == key.key_id
    
    def test_should_rotate_time_expired(self):
        """Test rotation check for expired key"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(
            AlgorithmType.CRYSTALS_KYBER,
            rotation_days=0,  # Expire immediately
        )
        # Force expiration
        key.expires_at = time.time() - 100
        
        should_rotate, reason = manager.should_rotate(key)
        assert should_rotate is True
        assert reason == "time_expired"
    
    def test_should_rotate_usage_exceeded(self):
        """Test rotation check for usage limit"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(
            AlgorithmType.CRYSTALS_KYBER,
            max_usage=5,
        )
        # Exceed usage limit
        for _ in range(6):
            key.increment_usage()
        
        should_rotate, reason = manager.should_rotate(key)
        assert should_rotate is True
        assert reason == "usage_limit_exceeded"
    
    def test_should_rotate_compromised(self):
        """Test rotation check for compromised key"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        key.status = KeyStatus.COMPROMISED
        
        should_rotate, reason = manager.should_rotate(key)
        assert should_rotate is True
        assert reason == "key_compromised"
    
    def test_should_not_rotate_valid_key(self):
        """Test valid key should not rotate"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(
            AlgorithmType.CRYSTALS_KYBER,
            rotation_days=90,
        )
        
        should_rotate, reason = manager.should_rotate(key)
        assert should_rotate is False
        assert reason == "key_valid"
    
    def test_rotate_key_success(self):
        """Test successful key rotation"""
        manager = PostQuantumKeyRotationManager()
        old_key = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        event = manager.rotate_key(old_key.key_id)
        
        assert event.success is True
        assert event.old_key_id == old_key.key_id
        assert event.new_key_id != ""
        assert event.zero_downtime is True
        assert old_key.status == KeyStatus.GRACE_PERIOD
        
        # New key should be active
        new_key = manager.get_key(event.new_key_id)
        assert new_key is not None
        assert new_key.status == KeyStatus.ACTIVE
    
    def test_rotate_key_not_found(self):
        """Test rotation with non-existent key"""
        manager = PostQuantumKeyRotationManager()
        event = manager.rotate_key("non_existent_key")
        
        assert event.success is False
        assert event.new_key_id == ""
    
    def test_rotate_if_needed_no_key(self):
        """Test auto-rotation when no active key exists"""
        manager = PostQuantumKeyRotationManager()
        event = manager.rotate_if_needed(AlgorithmType.CRYSTALS_KYBER)
        
        assert event is not None
        assert event.success is True
        assert event.reason == "no_active_key"
    
    def test_rotate_if_needed_valid_key(self):
        """Test auto-rotation when key is still valid"""
        manager = PostQuantumKeyRotationManager()
        manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        event = manager.rotate_if_needed(AlgorithmType.CRYSTALS_KYBER)
        
        assert event is None  # No rotation needed
    
    def test_retire_key(self):
        """Test key retirement"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        result = manager.retire_key(key.key_id, reason="test_retirement")
        
        assert result is True
        assert key.status == KeyStatus.RETIRED
        assert key.retired_at is not None
    
    def test_retire_key_not_found(self):
        """Test retiring non-existent key"""
        manager = PostQuantumKeyRotationManager()
        result = manager.retire_key("non_existent")
        assert result is False
    
    def test_mark_compromised(self):
        """Test emergency compromise marking"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        result = manager.mark_compromised(key.key_id)
        
        assert result is True
        assert key.status == KeyStatus.COMPROMISED
        # Should have triggered rotation
        assert len(manager.rotation_history) >= 1
    
    def test_get_rotation_status_empty(self):
        """Test status with no keys"""
        manager = PostQuantumKeyRotationManager()
        status = manager.get_rotation_status()
        
        assert status["total_keys"] == 0
        assert status["total_rotations"] == 0
        assert status["zero_downtime_success_rate"] == 1.0
    
    def test_get_rotation_status_with_data(self):
        """Test status with keys and rotations"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        manager.rotate_key(key.key_id)
        
        status = manager.get_rotation_status()
        
        assert status["total_keys"] >= 1
        assert status["total_rotations"] == 1
        assert status["keys_by_status"]["active"] >= 1
    
    def test_max_keys_enforcement(self):
        """Test max keys per algorithm enforcement"""
        manager = PostQuantumKeyRotationManager(max_keys_per_algorithm=2)
        
        # Create 3 keys for same algorithm
        key1 = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        key2 = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        key3 = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        # Oldest should be retired
        algo_keys = manager.keys_by_algorithm[AlgorithmType.CRYSTALS_KYBER.value]
        assert len(algo_keys) <= 2  # Should not exceed max
    
    def test_record_key_usage(self):
        """Test recording key usage"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        initial = key.usage_count
        
        result = manager.record_key_usage(key.key_id)
        
        assert result is True
        assert key.usage_count == initial + 1
    
    def test_register_custom_generator(self):
        """Test registering custom key generator"""
        manager = PostQuantumKeyRotationManager()
        calls = []
        
        def custom_generator(algo):
            calls.append(algo)
            return "custom_hash", {"custom": True}
        
        manager.register_key_generator(AlgorithmType.FALCON, custom_generator)
        key = manager.create_key(AlgorithmType.FALCON)
        
        assert len(calls) == 1
        assert key.metadata.get("custom") is True
    
    def test_rotation_callback(self):
        """Test rotation callback execution"""
        manager = PostQuantumKeyRotationManager()
        callback_events = []
        
        def callback(event):
            callback_events.append(event)
        
        manager.register_rotation_callback(callback)
        key = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        manager.rotate_key(key.key_id)
        
        assert len(callback_events) == 1
        assert callback_events[0].success is True
    
    def test_cleanup_expired_keys(self):
        """Test cleanup of old retired keys"""
        manager = PostQuantumKeyRotationManager()
        key = manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        manager.retire_key(key.key_id)
        key.retired_at = time.time() - (10 * 86400)  # Retired 10 days ago
        
        removed = manager.cleanup_expired_keys(older_than_days=7)
        
        assert removed >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
