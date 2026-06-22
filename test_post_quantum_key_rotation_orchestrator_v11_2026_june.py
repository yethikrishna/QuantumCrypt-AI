"""
Test suite for Post-Quantum Key Rotation Orchestrator v11
QuantumCrypt-AI Feature Expansion (Dimension A)
Add-only tests - no modifications to existing tests
"""

import pytest
import time
from quantum_crypt.post_quantum_key_rotation_orchestrator_v11_2026_june import (
    KeyAlgorithm,
    KeyStatus,
    RotationStrategy,
    SecurityLevel,
    CryptographicKey,
    RotationEvent,
    RotationPolicy,
    PostQuantumKeyRotationOrchestrator
)


class TestCryptographicKey:
    """Tests for CryptographicKey dataclass"""

    def test_key_creation(self):
        """Test basic key creation"""
        key = CryptographicKey(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5,
            key_material=b"test_key_material_1234567890123456"
        )
        assert key.algorithm == KeyAlgorithm.AES_256_GCM
        assert key.status == KeyStatus.ACTIVE
        assert key.key_id is not None

    def test_key_expiration_check(self):
        """Test key expiration detection"""
        key = CryptographicKey(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5,
            key_material=b"test",
            ttl_seconds=0
        )
        assert key.is_expired() == True

    def test_key_rotation_needed_usage(self):
        """Test rotation needed based on usage"""
        key = CryptographicKey(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5,
            key_material=b"test",
            max_usage=5
        )
        key.usage_count = 10
        assert key.needs_rotation() == True

    def test_key_age_calculation(self):
        """Test key age calculation"""
        key = CryptographicKey(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5,
            key_material=b"test"
        )
        age = key.get_age_seconds()
        assert age >= 0.0


class TestRotationPolicy:
    """Tests for RotationPolicy dataclass"""

    def test_policy_defaults(self):
        """Test default policy values"""
        policy = RotationPolicy(strategy=RotationStrategy.TIME_BASED)
        assert policy.rotation_interval_seconds == 86400
        assert policy.max_key_usage == 10000
        assert policy.overlap_period_seconds == 300


class TestPostQuantumKeyRotationOrchestrator:
    """Tests for PostQuantumKeyRotationOrchestrator"""

    def test_orchestrator_initialization(self):
        """Test orchestrator initialization"""
        orchestrator = PostQuantumKeyRotationOrchestrator()
        assert orchestrator.enable_post_quantum == True
        assert orchestrator.require_hybrid_keys == False

    def test_create_classical_key(self):
        """Test creating a classical key"""
        orchestrator = PostQuantumKeyRotationOrchestrator()
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        assert key is not None
        assert key.algorithm == KeyAlgorithm.AES_256_GCM
        assert len(key.key_material) == 64  # Level 5 = 512 bits

    def test_create_post_quantum_key(self):
        """Test creating a post-quantum key"""
        orchestrator = PostQuantumKeyRotationOrchestrator(enable_post_quantum=True)
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            security_level=SecurityLevel.LEVEL_5
        )
        assert key is not None
        assert key.algorithm == KeyAlgorithm.CRYSTALS_KYBER
        assert len(key.key_material) == 128  # PQ keys are double size

    def test_create_hybrid_key(self):
        """Test creating a hybrid classical+PQ key"""
        orchestrator = PostQuantumKeyRotationOrchestrator()
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.HYBRID_AES_KYBER,
            security_level=SecurityLevel.LEVEL_5
        )
        assert key is not None
        assert key.algorithm == KeyAlgorithm.HYBRID_AES_KYBER

    def test_disabled_post_quantum_rejection(self):
        """Test that PQ algorithms are rejected when disabled"""
        orchestrator = PostQuantumKeyRotationOrchestrator(enable_post_quantum=False)
        with pytest.raises(ValueError):
            orchestrator.create_key(
                algorithm=KeyAlgorithm.CRYSTALS_KYBER,
                security_level=SecurityLevel.LEVEL_5
            )

    def test_hybrid_key_enforcement(self):
        """Test hybrid key requirement enforcement"""
        orchestrator = PostQuantumKeyRotationOrchestrator(
            enable_post_quantum=True,
            require_hybrid_keys=True
        )
        with pytest.raises(ValueError):
            orchestrator.create_key(
                algorithm=KeyAlgorithm.AES_256_GCM,
                security_level=SecurityLevel.LEVEL_5
            )
        
        # Hybrid key should work
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.HYBRID_AES_KYBER,
            security_level=SecurityLevel.LEVEL_5
        )
        assert key is not None

    def test_get_key(self):
        """Test retrieving a key"""
        orchestrator = PostQuantumKeyRotationOrchestrator()
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        
        retrieved = orchestrator.get_key(key.key_id)
        assert retrieved is not None
        assert retrieved.key_id == key.key_id
        assert retrieved.usage_count == 1  # Incremented on access

    def test_key_rotation_on_demand(self):
        """Test on-demand key rotation"""
        policy = RotationPolicy(
            strategy=RotationStrategy.TIME_BASED,
            minimum_rotation_interval=0
        )
        orchestrator = PostQuantumKeyRotationOrchestrator(default_policy=policy)
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        
        event = orchestrator.rotate_key(key.key_id)
        assert event is not None
        assert event.success == True
        assert event.strategy == RotationStrategy.ON_DEMAND
        assert event.new_key_id != ""
        
        # Old key should be deprecated
        old_key = orchestrator._active_keys.get(key.key_id)
        assert old_key.status == KeyStatus.DEPRECATED

    def test_rotation_too_frequent_prevention(self):
        """Test that too-frequent rotation is prevented"""
        policy = RotationPolicy(
            strategy=RotationStrategy.TIME_BASED,
            minimum_rotation_interval=0  # Allow first rotation
        )
        orchestrator = PostQuantumKeyRotationOrchestrator(default_policy=policy)
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        
        # First rotation should succeed
        event1 = orchestrator.rotate_key(key.key_id)
        assert event1.success == True
        
        # Now enforce minimum interval for second rotation
        policy.minimum_rotation_interval = 3600
        
        # Immediate second rotation should fail
        event2 = orchestrator.rotate_key(key.key_id)
        assert event2.success == False
        assert "rotation_too_frequent" in event2.reason

    def test_check_rotation_needed_time_based(self):
        """Test time-based rotation detection"""
        policy = RotationPolicy(
            strategy=RotationStrategy.TIME_BASED,
            rotation_interval_seconds=0  # Immediate expiration
        )
        orchestrator = PostQuantumKeyRotationOrchestrator(default_policy=policy)
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        
        needs_rotation, reason = orchestrator.check_rotation_needed(key.key_id)
        assert needs_rotation == True
        assert "ttl_exceeded" in reason

    def test_check_rotation_needed_usage_based(self):
        """Test usage-based rotation detection"""
        policy = RotationPolicy(
            strategy=RotationStrategy.USAGE_BASED,
            max_key_usage=2
        )
        orchestrator = PostQuantumKeyRotationOrchestrator(default_policy=policy)
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        
        # Access key multiple times
        orchestrator.get_key(key.key_id)
        orchestrator.get_key(key.key_id)
        orchestrator.get_key(key.key_id)
        
        needs_rotation, reason = orchestrator.check_rotation_needed(key.key_id)
        assert needs_rotation == True
        assert "usage_exceeded" in reason

    def test_auto_rotate_all(self):
        """Test automatic rotation of all expired keys"""
        policy = RotationPolicy(
            strategy=RotationStrategy.TIME_BASED,
            rotation_interval_seconds=0,
            minimum_rotation_interval=0
        )
        orchestrator = PostQuantumKeyRotationOrchestrator(default_policy=policy)
        
        # Create multiple keys
        key1 = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        key2 = orchestrator.create_key(
            algorithm=KeyAlgorithm.CHACHA20_POLY1305,
            security_level=SecurityLevel.LEVEL_5
        )
        
        events = orchestrator.auto_rotate_all()
        assert len(events) >= 2

    def test_emergency_rotation(self):
        """Test emergency compromise rotation"""
        policy = RotationPolicy(
            strategy=RotationStrategy.TIME_BASED,
            minimum_rotation_interval=0
        )
        orchestrator = PostQuantumKeyRotationOrchestrator(default_policy=policy)
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.HYBRID_AES_KYBER,
            security_level=SecurityLevel.LEVEL_5
        )
        
        event = orchestrator.emergency_rotation(key.key_id)
        assert event is not None
        assert event.strategy == RotationStrategy.COMPROMISE_TRIGGERED
        assert "compromise" in event.reason
        
        # Old key should be revoked
        revoked_key = orchestrator._active_keys.get(key.key_id)
        assert revoked_key.status == KeyStatus.REVOKED

    def test_subkey_derivation(self):
        """Test HKDF-style subkey derivation"""
        orchestrator = PostQuantumKeyRotationOrchestrator()
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        
        subkey1 = orchestrator.derive_subkey(key.key_id, "encryption", 32)
        subkey2 = orchestrator.derive_subkey(key.key_id, "authentication", 32)
        
        assert subkey1 is not None
        assert subkey2 is not None
        assert len(subkey1) == 32
        assert len(subkey2) == 32
        assert subkey1 != subkey2  # Different contexts = different subkeys

    def test_subkey_derivation_deterministic(self):
        """Test that subkey derivation is deterministic"""
        orchestrator = PostQuantumKeyRotationOrchestrator()
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        
        subkey1 = orchestrator.derive_subkey(key.key_id, "test_context", 32)
        subkey2 = orchestrator.derive_subkey(key.key_id, "test_context", 32)
        
        assert subkey1 == subkey2  # Same context = same subkey

    def test_rotation_callback(self):
        """Test rotation callback execution"""
        callback_events = []
        
        def callback(event):
            callback_events.append(event)
        
        policy = RotationPolicy(
            strategy=RotationStrategy.TIME_BASED,
            minimum_rotation_interval=0
        )
        orchestrator = PostQuantumKeyRotationOrchestrator(default_policy=policy)
        orchestrator.add_rotation_callback(callback)
        
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        orchestrator.rotate_key(key.key_id)
        
        assert len(callback_events) == 1

    def test_rotation_statistics(self):
        """Test rotation statistics collection"""
        policy = RotationPolicy(
            strategy=RotationStrategy.TIME_BASED,
            minimum_rotation_interval=0
        )
        orchestrator = PostQuantumKeyRotationOrchestrator(default_policy=policy)
        
        # Create some keys
        key1 = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        key2 = orchestrator.create_key(
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            security_level=SecurityLevel.LEVEL_5
        )
        
        # Perform rotations
        orchestrator.rotate_key(key1.key_id)
        orchestrator.rotate_key(key2.key_id)
        
        stats = orchestrator.get_rotation_statistics()
        assert stats["active_keys"] == 4  # 2 original + 2 rotated
        assert stats["total_rotations"] == 2
        assert stats["orchestrator_version"] == "v11"

    def test_key_integrity_verification(self):
        """Test key integrity verification"""
        orchestrator = PostQuantumKeyRotationOrchestrator()
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        
        result = orchestrator.verify_key_integrity(key.key_id)
        assert result == True
        
        # Non-existent key should fail
        result = orchestrator.verify_key_integrity("non_existent_key")
        assert result == False

    def test_cleanup_archived_keys(self):
        """Test cleanup of archived keys"""
        policy = RotationPolicy(
            strategy=RotationStrategy.TIME_BASED,
            overlap_period_seconds=0
        )
        orchestrator = PostQuantumKeyRotationOrchestrator(default_policy=policy)
        
        key = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        orchestrator.rotate_key(key.key_id)
        
        archived = orchestrator.cleanup_archived_keys()
        assert archived >= 0

    def test_security_level_key_sizes(self):
        """Test key sizes for different security levels"""
        orchestrator = PostQuantumKeyRotationOrchestrator()
        
        key_l1 = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_1
        )
        key_l3 = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_3
        )
        key_l5 = orchestrator.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            security_level=SecurityLevel.LEVEL_5
        )
        
        assert len(key_l1.key_material) == 32  # 256 bits
        assert len(key_l3.key_material) == 48  # 384 bits
        assert len(key_l5.key_material) == 64  # 512 bits


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
