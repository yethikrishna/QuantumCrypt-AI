"""
Tests for Post-Quantum Key Rotation Manager - QuantumCrypt AI
Comprehensive test coverage for all features.

All tests must pass - no breaking changes.
"""

import pytest
import time
from datetime import datetime, timedelta
from quantum_crypt.pq_key_rotation_manager_v27_2026_june import (
    PostQuantumKeyRotationManager,
    PostQuantumKeyGenerator,
    InMemoryKeyStorage,
    KeyAlgorithm,
    KeyState,
    RotationTrigger,
    RotationPolicy,
    KeyVersion,
    get_key_rotation_manager
)


class TestKeyGeneration:
    """Tests for post-quantum key generation."""

    def test_generate_kyber_key(self):
        """Test CRYSTALS-KYBER key generation."""
        key = PostQuantumKeyGenerator.generate_key_material(KeyAlgorithm.CRYSTALS_KYBER)
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_generate_ntru_key(self):
        """Test NTRU key generation."""
        key = PostQuantumKeyGenerator.generate_key_material(KeyAlgorithm.NTRU_HPS)
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_generate_rsa_key(self):
        """Test RSA 4096 key generation."""
        key = PostQuantumKeyGenerator.generate_key_material(KeyAlgorithm.RSA_4096)
        assert len(key) == 64

    def test_generate_ecc_key(self):
        """Test ECC P384 key generation."""
        key = PostQuantumKeyGenerator.generate_key_material(KeyAlgorithm.ECC_P384)
        assert len(key) == 48

    def test_key_derivation(self):
        """Test key derivation function."""
        base_key = b"test_base_key_12345"
        derived1 = PostQuantumKeyGenerator.derive_key(base_key, "context1")
        derived2 = PostQuantumKeyGenerator.derive_key(base_key, "context2")
        assert derived1 != derived2
        assert len(derived1) == 32


class TestInMemoryStorage:
    """Tests for in-memory key storage backend."""

    def test_store_and_load_key(self):
        """Test storing and loading a key."""
        storage = InMemoryKeyStorage()
        key = KeyVersion(
            key_id="test-key",
            version=1,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            state=KeyState.ACTIVE,
            key_material=b"test_key_material",
            created_at=datetime.utcnow()
        )

        assert storage.store_key(key) is True
        loaded = storage.load_key("test-key", 1)
        assert loaded is not None
        assert loaded.key_id == "test-key"
        assert loaded.version == 1

    def test_load_all_versions(self):
        """Test loading all versions of a key."""
        storage = InMemoryKeyStorage()
        for v in range(1, 4):
            key = KeyVersion(
                key_id="test-key",
                version=v,
                algorithm=KeyAlgorithm.CRYSTALS_KYBER,
                state=KeyState.ACTIVE,
                key_material=f"key_v{v}".encode(),
                created_at=datetime.utcnow()
            )
            storage.store_key(key)

        versions = storage.load_all_versions("test-key")
        assert len(versions) == 3
        assert versions[0].version == 1
        assert versions[-1].version == 3

    def test_update_key_state(self):
        """Test updating key state."""
        storage = InMemoryKeyStorage()
        key = KeyVersion(
            key_id="test-key",
            version=1,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            state=KeyState.ACTIVE,
            key_material=b"test",
            created_at=datetime.utcnow()
        )
        storage.store_key(key)

        assert storage.update_key_state("test-key", 1, KeyState.RETIRED) is True
        loaded = storage.load_key("test-key", 1)
        assert loaded.state == KeyState.RETIRED


class TestKeyCreation:
    """Tests for key creation functionality."""

    def test_create_key_defaults(self):
        """Test creating a key with default settings."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        assert key_id.startswith("pq-")
        assert len(key_id) > 10

        active_key = manager.get_active_key(key_id)
        assert active_key is not None
        assert active_key.version == 1
        assert active_key.state == KeyState.ACTIVE
        assert active_key.algorithm == KeyAlgorithm.CRYSTALS_KYBER

    def test_create_key_custom_algorithm(self):
        """Test creating a key with specific algorithm."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key(algorithm=KeyAlgorithm.SABER)

        active_key = manager.get_active_key(key_id)
        assert active_key.algorithm == KeyAlgorithm.SABER

    def test_create_key_with_metadata(self):
        """Test creating a key with metadata."""
        manager = PostQuantumKeyRotationManager()
        metadata = {"environment": "production", "owner": "security-team"}
        key_id = manager.create_key(metadata=metadata)

        active_key = manager.get_active_key(key_id)
        assert active_key.metadata["environment"] == "production"
        assert active_key.metadata["owner"] == "security-team"

    def test_create_key_pending_state(self):
        """Test creating a key in pending state."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key(activate_immediately=False)

        versions = manager.list_key_versions(key_id)
        assert versions[0]["state"] == "pending"


class TestRotationPolicy:
    """Tests for rotation policy management."""

    def test_get_default_policy(self):
        """Test getting default policy."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()
        policy = manager.get_key_policy(key_id)

        assert policy.max_age_hours == 168  # 7 days
        assert policy.max_usage_count == 10000
        assert policy.auto_rotate is True

    def test_set_custom_policy(self):
        """Test setting custom policy."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        custom_policy = RotationPolicy(
            max_age_hours=24,
            max_usage_count=1000,
            auto_rotate=True
        )

        assert manager.set_key_policy(key_id, custom_policy) is True
        retrieved = manager.get_key_policy(key_id)
        assert retrieved.max_age_hours == 24
        assert retrieved.max_usage_count == 1000


class TestKeyRotation:
    """Tests for key rotation functionality."""

    def test_manual_key_rotation(self):
        """Test manual key rotation."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        event = manager.rotate_key(key_id, trigger=RotationTrigger.MANUAL)

        assert event.success is True
        assert event.old_version == 1
        assert event.new_version == 2
        assert event.trigger == RotationTrigger.MANUAL

        active_key = manager.get_active_key(key_id)
        assert active_key.version == 2

    def test_rotation_updates_old_key_state(self):
        """Test that old key state is updated on rotation."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        manager.rotate_key(key_id)

        old_version = manager.get_key_version(key_id, 1)
        assert old_version.state == KeyState.RETIRING
        assert old_version.retired_at is not None

    def test_rotation_with_nonexistent_key(self):
        """Test rotation with non-existent key."""
        manager = PostQuantumKeyRotationManager()
        event = manager.rotate_key("nonexistent-key")

        assert event.success is False
        assert "No active key" in event.reason

    def test_multiple_rotations(self):
        """Test multiple sequential rotations."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        for i in range(3):
            manager.rotate_key(key_id)

        active_key = manager.get_active_key(key_id)
        assert active_key.version == 4

        versions = manager.list_key_versions(key_id)
        assert len(versions) == 4


class TestRotationChecks:
    """Tests for rotation need detection."""

    def test_no_rotation_needed_fresh_key(self):
        """Test fresh key doesn't need rotation."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        needs_rotation, reason = manager.check_rotation_needed(key_id)
        assert needs_rotation is False
        assert reason is None

    def test_rotation_needed_usage_based(self):
        """Test usage-based rotation trigger."""
        manager = PostQuantumKeyRotationManager()
        policy = RotationPolicy(max_usage_count=5)
        key_id = manager.create_key(policy=policy)

        # Simulate usage
        for _ in range(6):
            manager.record_key_usage(key_id)

        needs_rotation, reason = manager.check_rotation_needed(key_id)
        assert needs_rotation is True
        assert "Usage count exceeded" in reason


class TestEmergencyRollback:
    """Tests for emergency key rollback."""

    def test_rollback_to_previous_version(self):
        """Test rolling back to previous version."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()
        manager.rotate_key(key_id)  # Now at v2

        # Rollback to v1
        assert manager.emergency_rollback(key_id, 1) is True

        active_key = manager.get_active_key(key_id)
        assert active_key.version == 1

    def test_rollback_nonexistent_version(self):
        """Test rollback to non-existent version."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        assert manager.emergency_rollback(key_id, 999) is False

    def test_rollback_destroyed_version(self):
        """Test rollback to destroyed version fails."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        # Mark v1 as destroyed
        manager._storage.update_key_state(key_id, 1, KeyState.DESTROYED)

        assert manager.emergency_rollback(key_id, 1) is False


class TestCompromiseHandling:
    """Tests for key compromise handling."""

    def test_mark_compromised_triggers_rotation(self):
        """Test marking key as compromised triggers rotation."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        assert manager.mark_key_compromised(key_id) is True

        old_version = manager.get_key_version(key_id, 1)
        assert old_version.state == KeyState.COMPROMISED

        # Should have rotated to v2
        active_key = manager.get_active_key(key_id)
        assert active_key.version == 2


class TestKeyUsageTracking:
    """Tests for key usage tracking."""

    def test_record_usage(self):
        """Test recording key usage."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        initial_key = manager.get_active_key(key_id)
        initial_count = initial_key.usage_count

        assert manager.record_key_usage(key_id, data_bytes=1024) is True

        updated_key = manager.get_active_key(key_id)
        assert updated_key.usage_count == initial_count + 1
        assert updated_key.data_processed_bytes == 1024

    def test_record_usage_nonexistent_key(self):
        """Test recording usage for non-existent key."""
        manager = PostQuantumKeyRotationManager()
        assert manager.record_key_usage("nonexistent") is False


class TestVersionListing:
    """Tests for key version listing."""

    def test_list_key_versions(self):
        """Test listing all key versions."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()
        manager.rotate_key(key_id)
        manager.rotate_key(key_id)

        versions = manager.list_key_versions(key_id)
        assert len(versions) == 3

        for v in versions:
            assert "version" in v
            assert "state" in v
            assert "algorithm" in v
            assert "fingerprint" in v
            assert len(v["fingerprint"]) == 16

    def test_key_fingerprint_unique(self):
        """Test different keys have different fingerprints."""
        manager = PostQuantumKeyRotationManager()
        key_id1 = manager.create_key()
        key_id2 = manager.create_key()

        v1 = manager.list_key_versions(key_id1)[0]
        v2 = manager.list_key_versions(key_id2)[0]

        assert v1["fingerprint"] != v2["fingerprint"]


class TestRotationHistory:
    """Tests for rotation history and audit."""

    def test_rotation_history_records(self):
        """Test rotation events are recorded."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        manager.rotate_key(key_id, reason="Test rotation 1")
        manager.rotate_key(key_id, reason="Test rotation 2")

        history = manager.get_rotation_history(key_id)
        assert len(history) == 2
        assert history[0]["reason"] == "Test rotation 2"  # Most recent first

    def test_rotation_statistics(self):
        """Test rotation statistics."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()

        manager.rotate_key(key_id, trigger=RotationTrigger.MANUAL)
        manager.rotate_key(key_id, trigger=RotationTrigger.TIME_BASED)

        stats = manager.get_rotation_statistics()
        assert stats["total_rotations"] == 2
        assert stats["successful_rotations"] == 2
        assert "manual" in stats["rotations_by_trigger"]
        assert "time_based" in stats["rotations_by_trigger"]
        assert stats["average_rotation_duration_ms"] >= 0


class TestSecureKeyExport:
    """Tests for secure key material export."""

    def test_secure_export_active_key(self):
        """Test secure export of active key."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()
        wrapping_key = b"my_secure_wrapping_key_12345"

        exported = manager.export_key_material_secure(key_id, wrapping_key)
        assert exported is not None
        assert len(exported) > 32  # nonce + hmac + key

    def test_secure_export_specific_version(self):
        """Test secure export of specific version."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()
        wrapping_key = b"my_secure_wrapping_key_12345"

        exported = manager.export_key_material_secure(key_id, wrapping_key, version=1)
        assert exported is not None

    def test_export_compromised_key_rejected(self):
        """Test export of compromised key is rejected."""
        manager = PostQuantumKeyRotationManager()
        key_id = manager.create_key()
        wrapping_key = b"test"

        manager.mark_key_compromised(key_id)
        exported = manager.export_key_material_secure(key_id, wrapping_key, version=1)
        assert exported is None


class TestVersionCleanup:
    """Tests for old version cleanup."""

    def test_old_versions_cleaned_up(self):
        """Test old versions beyond retention are cleaned up."""
        manager = PostQuantumKeyRotationManager()
        policy = RotationPolicy(retain_versions=2)
        key_id = manager.create_key(policy=policy)

        # Rotate multiple times
        for _ in range(5):
            manager.rotate_key(key_id)

        versions = manager._storage.load_all_versions(key_id)
        # Should have at most 2 non-destroyed versions
        active_or_retired = [
            v for v in versions
            if v.state not in (KeyState.DESTROYED, KeyState.COMPROMISED)
        ]
        assert len(active_or_retired) <= 3  # Allow for current active


class TestSingletonPattern:
    """Tests for singleton get_key_rotation_manager function."""

    def test_singleton_returns_same_instance(self):
        """Test that singleton returns same instance."""
        manager1 = get_key_rotation_manager()
        manager2 = get_key_rotation_manager()
        assert manager1 is manager2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
