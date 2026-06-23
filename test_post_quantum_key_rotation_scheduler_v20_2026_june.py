"""
Test Suite for Post-Quantum Key Rotation Scheduler v20
QuantumCrypt AI - Dimension A Feature Expansion

Comprehensive tests for key rotation scheduling functionality.
All tests are ADD-ONLY - no existing code modified.
"""

import pytest
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_key_rotation_scheduler_v20_2026_june import (
    PostQuantumKeyRotationManager,
    KeyRotationScheduler,
    KeyRotationPolicy,
    KeyStore,
    KeyMetadata,
    RotationEvent,
    KeyStatus,
    RotationPolicy,
    AlgorithmType
)
from datetime import datetime, timedelta


class TestEnums:
    """Test enum classes."""

    def test_key_status_enum(self):
        """Test KeyStatus enum values."""
        assert KeyStatus.ACTIVE.value == "active"
        assert KeyStatus.ROTATING.value == "rotating"
        assert KeyStatus.DEPRECATED.value == "deprecated"
        assert KeyStatus.REVOKED.value == "revoked"
        assert KeyStatus.EXPIRED.value == "expired"

    def test_rotation_policy_enum(self):
        """Test RotationPolicy enum values."""
        assert RotationPolicy.TIME_BASED.value == "time_based"
        assert RotationPolicy.USAGE_BASED.value == "usage_based"
        assert RotationPolicy.HYBRID.value == "hybrid"
        assert RotationPolicy.ON_DEMAND.value == "on_demand"

    def test_algorithm_type_enum(self):
        """Test AlgorithmType enum values."""
        assert AlgorithmType.KYBER.value == "CRYSTALS-Kyber"
        assert AlgorithmType.NTRU.value == "NTRU-HRSS"
        assert AlgorithmType.SABER.value == "SABER"


class TestKeyMetadata:
    """Test KeyMetadata dataclass."""

    def test_key_metadata_creation(self):
        """Test basic key metadata creation."""
        now = datetime.utcnow()
        metadata = KeyMetadata(
            key_id="test-key-001",
            algorithm=AlgorithmType.KYBER,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=90),
            rotation_policy=RotationPolicy.HYBRID
        )
        assert metadata.key_id == "test-key-001"
        assert metadata.algorithm == AlgorithmType.KYBER
        assert metadata.version == 1
        assert metadata.usage_count == 0

    def test_key_metadata_with_labels(self):
        """Test key metadata with custom labels."""
        now = datetime.utcnow()
        labels = {'environment': 'production', 'team': 'security'}
        metadata = KeyMetadata(
            key_id="test-key-002",
            algorithm=AlgorithmType.NTRU,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=90),
            rotation_policy=RotationPolicy.TIME_BASED,
            labels=labels
        )
        assert metadata.labels == labels


class TestKeyRotationPolicy:
    """Test KeyRotationPolicy class."""

    def test_policy_initialization(self):
        """Test policy initialization with defaults."""
        policy = KeyRotationPolicy()
        assert policy.policy_type == RotationPolicy.TIME_BASED
        assert policy.rotation_interval == timedelta(days=90)
        assert policy.max_usage == 100000

    def test_policy_custom_config(self):
        """Test policy with custom configuration."""
        policy = KeyRotationPolicy(
            policy_type=RotationPolicy.HYBRID,
            rotation_interval=timedelta(days=30),
            max_usage=50000
        )
        assert policy.policy_type == RotationPolicy.HYBRID
        assert policy.rotation_interval == timedelta(days=30)
        assert policy.max_usage == 50000

    def test_should_rotate_time_based(self):
        """Test time-based rotation decision."""
        policy = KeyRotationPolicy(
            policy_type=RotationPolicy.TIME_BASED,
            rotation_interval=timedelta(days=1)
        )
        
        # Create old key (should rotate)
        old_key = KeyMetadata(
            key_id="old",
            algorithm=AlgorithmType.KYBER,
            status=KeyStatus.ACTIVE,
            created_at=datetime.utcnow() - timedelta(days=2),
            expires_at=datetime.utcnow() + timedelta(days=365),
            rotation_policy=RotationPolicy.TIME_BASED
        )
        assert policy.should_rotate(old_key) is True

    def test_should_rotate_usage_based(self):
        """Test usage-based rotation decision."""
        policy = KeyRotationPolicy(
            policy_type=RotationPolicy.USAGE_BASED,
            max_usage=100
        )
        
        high_usage_key = KeyMetadata(
            key_id="high-usage",
            algorithm=AlgorithmType.KYBER,
            status=KeyStatus.ACTIVE,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=365),
            rotation_policy=RotationPolicy.USAGE_BASED,
            usage_count=150
        )
        assert policy.should_rotate(high_usage_key) is True

    def test_should_not_rotate_fresh_key(self):
        """Test fresh key should not rotate."""
        policy = KeyRotationPolicy(
            policy_type=RotationPolicy.HYBRID,
            rotation_interval=timedelta(days=90),
            max_usage=100000
        )
        
        fresh_key = KeyMetadata(
            key_id="fresh",
            algorithm=AlgorithmType.KYBER,
            status=KeyStatus.ACTIVE,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=365),
            rotation_policy=RotationPolicy.HYBRID,
            usage_count=10
        )
        assert policy.should_rotate(fresh_key) is False

    def test_calculate_next_rotation(self):
        """Test next rotation time calculation."""
        policy = KeyRotationPolicy(rotation_interval=timedelta(days=90))
        key = KeyMetadata(
            key_id="test",
            algorithm=AlgorithmType.KYBER,
            status=KeyStatus.ACTIVE,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=365),
            rotation_policy=RotationPolicy.TIME_BASED
        )
        next_rotation = policy.calculate_next_rotation(key)
        # Should be approximately 90 days out (with jitter)
        expected_min = datetime.utcnow() + timedelta(days=81)
        expected_max = datetime.utcnow() + timedelta(days=99)
        assert expected_min < next_rotation < expected_max


class TestKeyStore:
    """Test KeyStore class."""

    def test_keystore_initialization(self):
        """Test keystore initialization."""
        store = KeyStore()
        assert store.get_all_keys() == []

    def test_add_key(self):
        """Test adding key to store."""
        store = KeyStore()
        now = datetime.utcnow()
        metadata = KeyMetadata(
            key_id="key-001",
            algorithm=AlgorithmType.KYBER,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=90),
            rotation_policy=RotationPolicy.HYBRID
        )
        assert store.add_key(metadata) is True
        assert len(store.get_all_keys()) == 1

    def test_add_duplicate_key(self):
        """Test adding duplicate key returns False."""
        store = KeyStore()
        now = datetime.utcnow()
        metadata = KeyMetadata(
            key_id="key-001",
            algorithm=AlgorithmType.KYBER,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=90),
            rotation_policy=RotationPolicy.HYBRID
        )
        store.add_key(metadata)
        assert store.add_key(metadata) is False

    def test_get_key(self):
        """Test retrieving key from store."""
        store = KeyStore()
        now = datetime.utcnow()
        metadata = KeyMetadata(
            key_id="key-001",
            algorithm=AlgorithmType.KYBER,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=90),
            rotation_policy=RotationPolicy.HYBRID
        )
        store.add_key(metadata)
        
        retrieved = store.get_key("key-001")
        assert retrieved is not None
        assert retrieved.key_id == "key-001"

    def test_get_nonexistent_key(self):
        """Test retrieving non-existent key returns None."""
        store = KeyStore()
        assert store.get_key("nonexistent") is None

    def test_update_key(self):
        """Test updating key metadata."""
        store = KeyStore()
        now = datetime.utcnow()
        metadata = KeyMetadata(
            key_id="key-001",
            algorithm=AlgorithmType.KYBER,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=90),
            rotation_policy=RotationPolicy.HYBRID
        )
        store.add_key(metadata)
        
        metadata.usage_count = 100
        assert store.update_key(metadata) is True
        
        updated = store.get_key("key-001")
        assert updated.usage_count == 100

    def test_increment_usage(self):
        """Test incrementing key usage count."""
        store = KeyStore()
        now = datetime.utcnow()
        metadata = KeyMetadata(
            key_id="key-001",
            algorithm=AlgorithmType.KYBER,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=90),
            rotation_policy=RotationPolicy.HYBRID
        )
        store.add_key(metadata)
        
        assert store.increment_usage("key-001") is True
        assert store.increment_usage("key-001") is True
        
        key = store.get_key("key-001")
        assert key.usage_count == 2

    def test_record_and_get_rotation_history(self):
        """Test recording and retrieving rotation history."""
        store = KeyStore()
        event = RotationEvent(
            event_id="evt-001",
            key_id="key-001",
            timestamp=datetime.utcnow(),
            status="success",
            old_key_version=1,
            new_key_version=2,
            duration_ms=15.5
        )
        store.record_rotation(event)
        
        history = store.get_rotation_history("key-001")
        assert len(history) == 1
        assert history[0].event_id == "evt-001"


class TestKeyRotationScheduler:
    """Test KeyRotationScheduler class."""

    def test_scheduler_initialization(self):
        """Test scheduler initialization."""
        scheduler = KeyRotationScheduler(check_interval=30)
        assert scheduler.check_interval == 30
        status = scheduler.get_scheduler_status()
        assert status['running'] is False
        assert status['managed_keys'] == 0

    def test_register_key(self):
        """Test registering a key for rotation."""
        scheduler = KeyRotationScheduler()
        result = scheduler.register_key(
            key_id="test-key-001",
            algorithm=AlgorithmType.KYBER,
            labels={'env': 'test'}
        )
        assert result is True
        
        status = scheduler.get_scheduler_status()
        assert status['managed_keys'] == 1

    def test_register_duplicate_key(self):
        """Test registering duplicate key returns False."""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key-001", AlgorithmType.KYBER)
        result = scheduler.register_key("key-001", AlgorithmType.NTRU)
        assert result is False

    def test_rotate_now(self):
        """Test immediate key rotation."""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key-001", AlgorithmType.KYBER)
        
        event = scheduler.rotate_now("key-001")
        assert event.status == "success"
        assert event.old_key_version == 1
        assert event.new_key_version == 2
        assert event.duration_ms >= 0

    def test_rotate_nonexistent_key(self):
        """Test rotating non-existent key."""
        scheduler = KeyRotationScheduler()
        event = scheduler.rotate_now("nonexistent")
        assert event.status == "failed"
        assert event.error is not None

    def test_get_key_rotation_status(self):
        """Test getting key rotation status."""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key-001", AlgorithmType.KYBER)
        
        status = scheduler.get_key_rotation_status("key-001")
        assert status['found'] is True
        assert status['key_id'] == "key-001"
        assert status['algorithm'] == "CRYSTALS-Kyber"
        assert status['version'] == 1

    def test_get_nonexistent_key_status(self):
        """Test getting status for non-existent key."""
        scheduler = KeyRotationScheduler()
        status = scheduler.get_key_rotation_status("nonexistent")
        assert status['found'] is False

    def test_scheduler_start_stop(self):
        """Test scheduler start and stop functionality."""
        scheduler = KeyRotationScheduler(check_interval=1)
        scheduler.start()
        time.sleep(0.1)
        assert scheduler.get_scheduler_status()['running'] is True
        scheduler.stop()
        assert scheduler.get_scheduler_status()['running'] is False


class TestPostQuantumKeyRotationManager:
    """Test main PostQuantumKeyRotationManager class."""

    def test_manager_initialization(self):
        """Test manager initialization."""
        manager = PostQuantumKeyRotationManager(check_interval=30)
        assert manager.scheduler is not None

    def test_add_key_for_rotation(self):
        """Test adding key for rotation management."""
        manager = PostQuantumKeyRotationManager()
        result = manager.add_key_for_rotation(
            key_id="pq-key-001",
            algorithm=AlgorithmType.KYBER,
            rotation_days=30,
            max_usage=50000,
            labels={'env': 'production'}
        )
        assert result is True

    def test_rotate_key_immediately(self):
        """Test immediate key rotation via manager."""
        manager = PostQuantumKeyRotationManager()
        manager.add_key_for_rotation("key-001", AlgorithmType.KYBER)
        
        result = manager.rotate_key_immediately("key-001")
        assert result['status'] == "success"
        assert result['old_version'] == 1
        assert result['new_version'] == 2

    def test_get_rotation_report(self):
        """Test getting rotation report."""
        manager = PostQuantumKeyRotationManager()
        manager.add_key_for_rotation("key-001", AlgorithmType.KYBER)
        manager.add_key_for_rotation("key-002", AlgorithmType.NTRU)
        
        report = manager.get_rotation_report()
        assert report['total_keys'] == 2
        assert 'scheduler_status' in report
        assert 'keys_by_algorithm' in report
        assert 'keys_by_status' in report


class TestCallbacks:
    """Test callback functionality."""

    def test_callback_registration(self):
        """Test callback registration."""
        scheduler = KeyRotationScheduler()
        callback_called = []
        
        def test_callback(**kwargs):
            callback_called.append(kwargs)
        
        scheduler.callbacks.register('post_rotation', test_callback)
        scheduler.register_key("key-001", AlgorithmType.KYBER)
        scheduler.rotate_now("key-001")
        
        assert len(callback_called) > 0


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_key_id(self):
        """Test empty key ID handling."""
        scheduler = KeyRotationScheduler()
        # Should not crash
        event = scheduler.rotate_now("")
        assert event.status == "failed"

    def test_multiple_algorithms(self):
        """Test all supported algorithm types."""
        scheduler = KeyRotationScheduler()
        algorithms = [
            AlgorithmType.KYBER,
            AlgorithmType.NTRU,
            AlgorithmType.SABER,
            AlgorithmType.CLASSIC_MCELIECE,
            AlgorithmType.FRODO,
            AlgorithmType.BIKE,
            AlgorithmType.HQC
        ]
        
        for i, alg in enumerate(algorithms):
            result = scheduler.register_key(f"key-{i}", alg)
            assert result is True
        
        status = scheduler.get_scheduler_status()
        assert status['managed_keys'] == len(algorithms)

    def test_concurrent_rotations_limit(self):
        """Test max concurrent rotations limit."""
        scheduler = KeyRotationScheduler(max_concurrent_rotations=2)
        for i in range(5):
            scheduler.register_key(f"key-{i}", AlgorithmType.KYBER)
        
        # Should not exceed max concurrent rotations
        status = scheduler.get_scheduler_status()
        assert status['active_rotations'] <= 2


class TestThreadSafety:
    """Test thread safety of scheduler operations."""

    def test_concurrent_key_registration(self):
        """Test concurrent key registration."""
        import threading
        
        scheduler = KeyRotationScheduler()
        num_threads = 5
        keys_per_thread = 10
        
        def register_keys(thread_id):
            for i in range(keys_per_thread):
                scheduler.register_key(
                    f"thread-{thread_id}-key-{i}",
                    AlgorithmType.KYBER
                )
        
        threads = []
        for t_id in range(num_threads):
            t = threading.Thread(target=register_keys, args=(t_id,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        status = scheduler.get_scheduler_status()
        assert status['managed_keys'] == num_threads * keys_per_thread


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
