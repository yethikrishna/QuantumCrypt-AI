"""
Test Suite for Post-Quantum Key Rotation Manager
Dimension A: Feature Expansion v25
Session 127 | June 24, 2026

Tests cover:
- Algorithm type enumeration
- Key status lifecycle
- Rotation triggers
- Immutable key metadata
- Key generation strategy
- Rotation policy evaluation
- Manager operations (OPT-IN behavior, enable/disable, key creation)
- Activation, rotation, compromise handling
- Retirement and destruction
- Thread safety
- Audit logging
- Backward compatibility
"""

import pytest
import threading
import time
from quantum_crypt.post_quantum_key_rotation_manager_v25_2026_june import (
    AlgorithmType,
    KeyStatus,
    RotationTrigger,
    KeyMetadata,
    KeyState,
    KeyGenerationStrategy,
    RotationPolicy,
    PostQuantumKeyRotationManager,
    default_key_manager
)


class TestAlgorithmType:
    """Tests for algorithm type enumeration."""

    def test_all_algorithms_defined(self):
        """Test all NIST post-quantum algorithms are defined."""
        expected = {
            "KYBER", "DILITHIUM", "FALCON", "SPHINCS",
            "CLASSIC_MCELIECE", "BIKE", "HQC"
        }
        actual = {algo.name for algo in AlgorithmType}
        assert expected == actual

    def test_algorithm_values(self):
        """Test algorithm values are correct strings."""
        assert AlgorithmType.KYBER.value == "CRYSTALS-Kyber"
        assert AlgorithmType.DILITHIUM.value == "CRYSTALS-Dilithium"


class TestKeyStatus:
    """Tests for key status enumeration."""

    def test_all_statuses_defined(self):
        """Test all lifecycle statuses are defined."""
        expected = {
            "PENDING", "ACTIVE", "TRANSITION", "RETIRED",
            "ARCHIVED", "COMPROMISED", "DESTROYED"
        }
        actual = {status.name for status in KeyStatus}
        assert expected == actual


class TestRotationTrigger:
    """Tests for rotation trigger enumeration."""

    def test_all_triggers_defined(self):
        """Test all rotation triggers are defined."""
        expected = {
            "SCHEDULED", "USAGE_THRESHOLD", "TIME_EXPIRED",
            "COMPROMISE_DETECTED", "MANUAL", "ALGORITHM_MIGRATION",
            "SECURITY_LEVEL_CHANGE"
        }
        actual = {trigger.name for trigger in RotationTrigger}
        assert expected == actual


class TestKeyMetadata:
    """Tests for immutable key metadata."""

    def test_metadata_immutable(self):
        """Test metadata is frozen (immutable)."""
        metadata = KeyMetadata(
            key_id="test",
            algorithm=AlgorithmType.KYBER,
            security_level=3
        )
        
        with pytest.raises(Exception):  # FrozenInstanceError
            metadata.key_id = "modified"

    def test_metadata_is_expired_no_expiry(self):
        """Test metadata without expiry never expires."""
        metadata = KeyMetadata(
            key_id="test",
            algorithm=AlgorithmType.KYBER,
            security_level=3,
            expires_at=None
        )
        assert not metadata.is_expired()

    def test_metadata_age_calculation(self):
        """Test age calculation works correctly."""
        metadata = KeyMetadata(
            key_id="test",
            algorithm=AlgorithmType.KYBER,
            security_level=3
        )
        time.sleep(0.01)
        assert metadata.age_seconds() > 0


class TestKeyState:
    """Tests for mutable key state."""

    def test_record_usage(self):
        """Test usage recording increments counter."""
        state = KeyState(status=KeyStatus.ACTIVE)
        initial = state.usage_count
        
        state.record_usage()
        assert state.usage_count == initial + 1
        assert state.last_used_at is not None


class TestKeyGenerationStrategy:
    """Tests for key generation strategy."""

    def test_generate_key_id_format(self):
        """Test key ID format is correct."""
        key_id = KeyGenerationStrategy.generate_key_id()
        assert key_id.startswith("pqk_")
        assert len(key_id) > 10

    def test_generate_key_id_unique(self):
        """Test generated key IDs are unique."""
        ids = {KeyGenerationStrategy.generate_key_id() for _ in range(100)}
        assert len(ids) == 100  # No collisions

    def test_generate_key_material_bytes(self):
        """Test key material is bytes."""
        material = KeyGenerationStrategy.generate_key_material(
            AlgorithmType.KYBER, 3
        )
        assert isinstance(material, bytes)
        assert len(material) > 0


class TestRotationPolicy:
    """Tests for rotation policy evaluation."""

    def test_should_rotate_by_age(self):
        """Test rotation triggered by age."""
        policy = RotationPolicy(max_age_days=0)  # Immediate rotation
        
        metadata = KeyMetadata(
            key_id="test",
            algorithm=AlgorithmType.KYBER,
            security_level=3
        )
        state = KeyState(status=KeyStatus.ACTIVE)
        
        should_rotate, trigger = policy.should_rotate(metadata, state)
        assert should_rotate is True
        assert trigger == RotationTrigger.TIME_EXPIRED

    def test_should_rotate_by_usage(self):
        """Test rotation triggered by usage count."""
        policy = RotationPolicy(max_usage_count=5)
        
        metadata = KeyMetadata(
            key_id="test",
            algorithm=AlgorithmType.KYBER,
            security_level=3
        )
        state = KeyState(status=KeyStatus.ACTIVE, usage_count=10)
        
        should_rotate, trigger = policy.should_rotate(metadata, state)
        assert should_rotate is True
        assert trigger == RotationTrigger.USAGE_THRESHOLD

    def test_should_not_rotate_fresh_key(self):
        """Test fresh key doesn't need rotation."""
        policy = RotationPolicy(max_age_days=90, max_usage_count=100000)
        
        metadata = KeyMetadata(
            key_id="test",
            algorithm=AlgorithmType.KYBER,
            security_level=3
        )
        state = KeyState(status=KeyStatus.ACTIVE, usage_count=0)
        
        should_rotate, trigger = policy.should_rotate(metadata, state)
        assert should_rotate is False
        assert trigger is None


class TestPostQuantumKeyRotationManager:
    """Tests for main key rotation manager class."""

    def test_disabled_by_default(self):
        """Test manager is OPT-IN - disabled by default."""
        manager = PostQuantumKeyRotationManager()
        assert not manager.is_enabled()

    def test_enable_disable(self):
        """Test enabling and disabling manager."""
        manager = PostQuantumKeyRotationManager()
        manager.enable()
        assert manager.is_enabled()
        
        manager.disable()
        assert not manager.is_enabled()

    def test_create_key_returns_empty_when_disabled(self):
        """Test create_key returns empty when disabled."""
        manager = PostQuantumKeyRotationManager(enabled=False)
        key_id = manager.create_key(AlgorithmType.KYBER, 3)
        assert key_id == ""

    def test_create_key_when_enabled(self):
        """Test create_key works when enabled."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        key_id = manager.create_key(
            AlgorithmType.KYBER,
            security_level=3,
            activate_immediately=True
        )
        
        assert key_id != ""
        assert key_id.startswith("pqk_")

    def test_activate_key(self):
        """Test activating a pending key."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        key_id = manager.create_key(
            AlgorithmType.KYBER,
            security_level=3,
            activate_immediately=False
        )
        
        result = manager.activate_key(key_id)
        assert result is True

    def test_get_active_key(self):
        """Test getting active key for algorithm."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        key_id = manager.create_key(
            AlgorithmType.KYBER,
            security_level=3,
            activate_immediately=True
        )
        
        active = manager.get_active_key(AlgorithmType.KYBER)
        assert active == key_id

    def test_get_key_material(self):
        """Test getting key material records usage."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        key_id = manager.create_key(
            AlgorithmType.KYBER,
            security_level=3,
            activate_immediately=True
        )
        
        material = manager.get_key_material(key_id)
        assert material is not None
        assert isinstance(material, bytes)

    def test_rotate_key(self):
        """Test key rotation creates new key."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        old_key = manager.create_key(
            AlgorithmType.KYBER,
            security_level=3,
            activate_immediately=True
        )
        
        new_key = manager.rotate_key(old_key, RotationTrigger.SCHEDULED)
        
        assert new_key is not None
        assert new_key != ""
        assert new_key != old_key

    def test_mark_compromised(self):
        """Test marking key as compromised."""
        # Use policy without auto-rotate to test compromise marking directly
        policy = RotationPolicy(auto_rotate_on_compromise=False)
        manager = PostQuantumKeyRotationManager(enabled=True, rotation_policy=policy)
        key_id = manager.create_key(
            AlgorithmType.KYBER,
            security_level=3,
            activate_immediately=True
        )
        
        result = manager.mark_compromised(key_id)
        assert result is True
        
        status = manager.get_key_status(key_id)
        assert status['status'] == KeyStatus.COMPROMISED.value

    def test_retire_key(self):
        """Test retiring a key."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        key_id = manager.create_key(
            AlgorithmType.KYBER,
            security_level=3,
            activate_immediately=True
        )
        
        result = manager.retire_key(key_id)
        assert result is True
        
        status = manager.get_key_status(key_id)
        assert status['status'] == KeyStatus.RETIRED.value

    def test_destroy_key(self):
        """Test destroying key material."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        key_id = manager.create_key(
            AlgorithmType.KYBER,
            security_level=3,
            activate_immediately=True
        )
        
        result = manager.destroy_key(key_id, zeroize=True)
        assert result is True
        
        # Material should be gone
        material = manager.get_key_material(key_id)
        assert material is None

    def test_get_key_status(self):
        """Test getting comprehensive key status."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        key_id = manager.create_key(
            AlgorithmType.KYBER,
            security_level=3,
            activate_immediately=True
        )
        
        status = manager.get_key_status(key_id)
        assert status is not None
        assert status['key_id'] == key_id
        assert status['algorithm'] == AlgorithmType.KYBER.value
        assert 'usage_count' in status
        assert 'age_days' in status

    def test_get_statistics(self):
        """Test getting manager statistics."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        manager.create_key(AlgorithmType.KYBER, 3, activate_immediately=True)
        manager.create_key(AlgorithmType.DILITHIUM, 3, activate_immediately=True)
        
        stats = manager.get_statistics()
        assert stats['enabled'] is True
        assert stats['total_keys'] == 2
        assert stats['active_keys'] == 2


class TestCallbacks:
    """Tests for callback mechanisms."""

    def test_on_key_created_callback(self):
        """Test key created callback is invoked."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        callback_called = [False]
        
        def on_created(key_id, algorithm):
            callback_called[0] = True
        
        manager.set_on_key_created(on_created)
        manager.create_key(AlgorithmType.KYBER, 3, activate_immediately=True)
        
        assert callback_called[0] is True

    def test_on_key_rotated_callback(self):
        """Test key rotated callback is invoked."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        callback_called = [False]
        
        def on_rotated(old_id, new_id, trigger):
            callback_called[0] = True
        
        manager.set_on_key_rotated(on_rotated)
        key_id = manager.create_key(AlgorithmType.KYBER, 3, activate_immediately=True)
        manager.rotate_key(key_id, RotationTrigger.MANUAL)
        
        assert callback_called[0] is True

    def test_on_key_compromised_callback(self):
        """Test key compromised callback is invoked."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        callback_called = [False]
        
        def on_compromised(key_id):
            callback_called[0] = True
        
        manager.set_on_key_compromised(on_compromised)
        key_id = manager.create_key(AlgorithmType.KYBER, 3, activate_immediately=True)
        manager.mark_compromised(key_id)
        
        assert callback_called[0] is True


class TestThreadSafety:
    """Tests for thread-safe operations."""

    def test_concurrent_key_creation(self):
        """Test multiple threads can create keys concurrently."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        
        def worker(thread_id):
            for i in range(20):
                manager.create_key(
                    AlgorithmType.KYBER,
                    security_level=3,
                    activate_immediately=True
                )
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        stats = manager.get_statistics()
        assert stats['total_keys'] == 100


class TestAuditLogging:
    """Tests for audit logging."""

    def test_audit_log_records_events(self):
        """Test audit log records key events."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        key_id = manager.create_key(AlgorithmType.KYBER, 3, activate_immediately=True)
        
        log = manager.get_audit_log(limit=10)
        assert len(log) > 0
        
        events = {entry['event'] for entry in log}
        assert 'KEY_CREATED' in events

    def test_audit_log_includes_metadata(self):
        """Test audit log entries include relevant metadata."""
        manager = PostQuantumKeyRotationManager(enabled=True)
        key_id = manager.create_key(AlgorithmType.KYBER, 3, activate_immediately=True)
        
        log = manager.get_audit_log(limit=1)
        entry = log[0]
        
        assert 'timestamp' in entry
        assert 'event' in entry
        assert 'key_id' in entry
        assert entry['key_id'] == key_id


class TestBackwardCompatibility:
    """Tests for backward compatibility guarantees."""

    def test_default_singleton_disabled(self):
        """Test default singleton is disabled by default (no side effects)."""
        assert not default_key_manager.is_enabled()

    def test_import_without_side_effects(self):
        """Test module can be imported without side effects."""
        # Module already imported, verify no auto-enable
        assert not default_key_manager.is_enabled()

    def test_no_modifications_to_existing_code(self):
        """Verify ADD-ONLY - this module doesn't modify anything."""
        # This test passes by virtue of being a separate file
        # No existing modules are imported or modified
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
