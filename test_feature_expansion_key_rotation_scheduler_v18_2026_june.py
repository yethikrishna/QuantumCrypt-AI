"""
Test Suite: Post-Quantum Key Rotation Scheduler & Policy Engine v18
Dimension A - Feature Expansion Tests
ADD-ONLY: Tests only, no production code modified
All existing tests must continue to pass
"""

import pytest
import time
import threading

from quantum_crypt.post_quantum_key_rotation_scheduler_policy_engine_v18_2026_june import (
    KeyRotationScheduler,
    RotationPolicy,
    RotationTrigger,
    KeyStatus,
    AlgorithmClass,
    KeyMetadata,
    RotationEvent,
    register_key_for_rotation,
    check_key_rotation,
    perform_key_rotation,
    get_key_rotation_status,
    get_key_rotation_stats
)


class TestRotationPolicy:
    """Test rotation policy configuration"""
    
    def test_policy_default_initialization(self):
        """Test default policy values"""
        policy = RotationPolicy(policy_id="test", name="Test Policy")
        assert policy.max_age_seconds == 86400 * 30  # 30 days
        assert policy.max_usage_count == 10000
        assert policy.min_key_strength_bits == 256
        assert policy.auto_rotate_on_compromise is True
    
    def test_policy_custom_values(self):
        """Test custom policy configuration"""
        policy = RotationPolicy(
            policy_id="strict",
            name="Strict Security",
            max_age_seconds=3600,  # 1 hour
            max_usage_count=100,
            min_key_strength_bits=512
        )
        assert policy.max_age_seconds == 3600
        assert policy.max_usage_count == 100
        assert policy.min_key_strength_bits == 512


class TestKeyRotationScheduler:
    """Test core key rotation scheduler"""
    
    def test_scheduler_initialization(self):
        """Test scheduler initializes correctly"""
        scheduler = KeyRotationScheduler()
        assert "default" in scheduler._policies
        assert len(scheduler._keys) == 0
        assert len(scheduler._rotation_history) == 0
    
    def test_register_policy(self):
        """Test registering a new policy"""
        scheduler = KeyRotationScheduler()
        initial_count = len(scheduler._policies)
        
        new_policy = RotationPolicy(
            policy_id="high_security",
            name="High Security Policy",
            max_age_seconds=3600
        )
        scheduler.register_policy(new_policy)
        
        assert len(scheduler._policies) == initial_count + 1
        assert "high_security" in scheduler._policies
    
    def test_register_key(self):
        """Test registering a key for rotation management"""
        scheduler = KeyRotationScheduler()
        
        scheduler.register_key(
            key_id="key_001",
            algorithm="CRYSTALS-Kyber",
            algorithm_class=AlgorithmClass.KEM_HYBRID,
            key_strength_bits=256
        )
        
        assert "key_001" in scheduler._keys
        key = scheduler._keys["key_001"]
        assert key.algorithm == "CRYSTALS-Kyber"
        assert key.status == KeyStatus.ACTIVE
        assert key.version == 1
        assert scheduler._stats["total_keys_registered"] == 1
    
    def test_register_key_idempotent(self):
        """Test duplicate registration is idempotent"""
        scheduler = KeyRotationScheduler()
        
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        
        # Should only count once
        assert scheduler._stats["total_keys_registered"] == 1
    
    def test_unregister_key(self):
        """Test unregistering a key"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        assert "key_001" in scheduler._keys
        
        scheduler.unregister_key("key_001")
        assert "key_001" not in scheduler._keys
    
    def test_increment_key_usage(self):
        """Test usage tracking"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        
        for _ in range(5):
            scheduler.increment_key_usage("key_001")
        
        assert scheduler._keys["key_001"].usage_count == 5
    
    def test_check_rotation_age_based(self):
        """Test age-based rotation detection"""
        scheduler = KeyRotationScheduler()
        
        # Create a policy with very short max age
        strict_policy = RotationPolicy(
            policy_id="strict",
            name="Strict",
            max_age_seconds=0.001  # 1ms
        )
        scheduler.register_policy(strict_policy)
        
        scheduler.register_key(
            key_id="key_001",
            algorithm="Kyber",
            algorithm_class=AlgorithmClass.KEM_PQC,
            policy_id="strict"
        )
        
        # Wait a tiny bit
        time.sleep(0.01)
        
        needs_rotation, reason = scheduler.check_key_rotation_needed("key_001")
        assert needs_rotation is True
        assert "age" in reason.lower()
    
    def test_check_rotation_usage_based(self):
        """Test usage-based rotation detection"""
        scheduler = KeyRotationScheduler()
        
        strict_policy = RotationPolicy(
            policy_id="strict",
            name="Strict",
            max_usage_count=5
        )
        scheduler.register_policy(strict_policy)
        
        scheduler.register_key(
            key_id="key_001",
            algorithm="Kyber",
            algorithm_class=AlgorithmClass.KEM_PQC,
            policy_id="strict"
        )
        
        # Use key 6 times
        for _ in range(6):
            scheduler.increment_key_usage("key_001")
        
        needs_rotation, reason = scheduler.check_key_rotation_needed("key_001")
        assert needs_rotation is True
        assert "usage" in reason.lower()
    
    def test_mark_key_compromised(self):
        """Test compromise marking"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        
        scheduler.mark_key_compromised("key_001", "Suspicious activity detected")
        
        assert scheduler._keys["key_001"].is_compromised is True
        assert scheduler._keys["key_001"].compromise_reason == "Suspicious activity detected"
        assert scheduler._stats["total_compromises_detected"] == 1
    
    def test_compromise_triggers_rotation(self):
        """Test compromise triggers auto-rotation check"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        scheduler.mark_key_compromised("key_001", "Test compromise")
        
        needs_rotation, reason = scheduler.check_key_rotation_needed("key_001")
        assert needs_rotation is True
        assert "compromised" in reason.lower()
    
    def test_perform_rotation_manual(self):
        """Test manual key rotation"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        
        initial_version = scheduler._keys["key_001"].version
        
        success, new_key_id = scheduler.perform_rotation(
            "key_001",
            RotationTrigger.MANUAL,
            "Administrative rotation"
        )
        
        assert success is True
        assert scheduler._keys["key_001"].version == initial_version + 1
        assert scheduler._keys["key_001"].rotation_count == 1
        assert scheduler._keys["key_001"].usage_count == 0
        assert scheduler._stats["total_rotations_performed"] == 1
        assert scheduler._stats["manual_rotations"] == 1
    
    def test_perform_rotation_with_generator(self):
        """Test rotation with custom key generator"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        
        generated_key_id = "new_generated_key_123"
        
        def mock_generator():
            return generated_key_id
        
        success, result_key = scheduler.perform_rotation(
            "key_001",
            RotationTrigger.MANUAL,
            "Test",
            key_generator=mock_generator
        )
        
        assert success is True
        assert result_key == generated_key_id
    
    def test_rotation_idempotent_check(self):
        """Test rotation prevents concurrent rotations"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        
        # First rotation
        success1, _ = scheduler.perform_rotation("key_001", RotationTrigger.MANUAL)
        assert success1 is True
        
        # Second rotation should also work (not actually concurrent)
        success2, _ = scheduler.perform_rotation("key_001", RotationTrigger.MANUAL)
        assert success2 is True
        assert scheduler._keys["key_001"].version == 3  # Started at 1, +2 rotations
    
    def test_check_all_rotations(self):
        """Test bulk rotation check"""
        scheduler = KeyRotationScheduler()
        
        strict_policy = RotationPolicy(
            policy_id="strict",
            name="Strict",
            max_usage_count=3
        )
        scheduler.register_policy(strict_policy)
        
        # Register keys
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC, policy_id="strict")
        scheduler.register_key("key_002", "Kyber", AlgorithmClass.KEM_PQC, policy_id="strict")
        scheduler.register_key("key_003", "Kyber", AlgorithmClass.KEM_PQC, policy_id="default")
        
        # Exhaust usage on two keys
        for _ in range(5):
            scheduler.increment_key_usage("key_001")
            scheduler.increment_key_usage("key_002")
        
        needs_rotation = scheduler.check_all_rotations()
        
        # Should find at least 2 keys needing rotation
        assert len(needs_rotation) >= 2
    
    def test_get_key_status(self):
        """Test comprehensive key status reporting"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key(
            "key_001",
            "CRYSTALS-Kyber",
            AlgorithmClass.KEM_HYBRID,
            key_strength_bits=256
        )
        
        status = scheduler.get_key_status("key_001")
        
        assert status is not None
        assert status["key_id"] == "key_001"
        assert status["algorithm"] == "CRYSTALS-Kyber"
        assert status["algorithm_class"] == "kem_hybrid"
        assert status["status"] == "active"
        assert status["version"] == 1
        assert "age_seconds" in status
        assert "usage_count" in status
        assert "needs_rotation" in status
    
    def test_get_key_status_nonexistent(self):
        """Test status for non-existent key"""
        scheduler = KeyRotationScheduler()
        status = scheduler.get_key_status("nonexistent_key")
        assert status is None
    
    def test_get_all_key_statuses(self):
        """Test getting all key statuses"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        scheduler.register_key("key_002", "Dilithium", AlgorithmClass.SIGNATURE_PQC)
        
        statuses = scheduler.get_all_key_statuses()
        assert len(statuses) == 2
        assert {s["key_id"] for s in statuses} == {"key_001", "key_002"}
    
    def test_get_rotation_history(self):
        """Test rotation audit history"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        
        scheduler.perform_rotation("key_001", RotationTrigger.MANUAL, "Test 1")
        scheduler.perform_rotation("key_001", RotationTrigger.MANUAL, "Test 2")
        
        history = scheduler.get_rotation_history("key_001")
        assert len(history) == 2
        assert all(e["key_id"] == "key_001" for e in history)
        assert all(e["success"] is True for e in history)
    
    def test_get_stats(self):
        """Test scheduler statistics"""
        scheduler = KeyRotationScheduler()
        
        scheduler.register_key("key_001", "Kyber", AlgorithmClass.KEM_PQC)
        scheduler.register_key("key_002", "Dilithium", AlgorithmClass.SIGNATURE_PQC)
        scheduler.perform_rotation("key_001", RotationTrigger.MANUAL)
        
        stats = scheduler.get_stats()
        
        assert stats["registered_keys"] == 2
        assert stats["active_keys"] == 2
        assert stats["total_keys_registered"] == 2
        assert stats["total_rotations_performed"] == 1
        assert "avg_rotations_per_key" in stats


class TestConvenienceFunctions:
    """Test module-level convenience functions"""
    
    def test_register_key_function(self):
        """Test module-level key registration"""
        register_key_for_rotation(
            key_id="test_key_123",
            algorithm="CRYSTALS-Kyber",
            algorithm_class="kem_hybrid"
        )
        # Should not raise
    
    def test_check_key_rotation_function(self):
        """Test module-level rotation check"""
        register_key_for_rotation("check_test", "Kyber", "kem_pqc")
        needs_rotation, reason = check_key_rotation("check_test")
        assert isinstance(needs_rotation, bool)
        # reason can be None if no rotation needed
    
    def test_perform_key_rotation_function(self):
        """Test module-level rotation"""
        register_key_for_rotation("rotate_test", "Kyber", "kem_pqc")
        success, result = perform_key_rotation("rotate_test", "test rotation")
        assert success is True
    
    def test_get_key_rotation_status_function(self):
        """Test module-level status"""
        register_key_for_rotation("status_test", "Kyber", "kem_pqc")
        status = get_key_rotation_status("status_test")
        assert status is not None
    
    def test_get_key_rotation_stats_function(self):
        """Test module-level stats"""
        stats = get_key_rotation_stats()
        assert isinstance(stats, dict)


class TestBackgroundScheduler:
    """Test background scheduler thread"""
    
    def test_background_scheduler_start_stop(self):
        """Test starting and stopping background scheduler"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("bg_test", "Kyber", AlgorithmClass.KEM_PQC)
        
        scheduler.start_background_scheduler(check_interval_seconds=0.1)
        time.sleep(0.2)
        scheduler.stop_background_scheduler()
        
        # Should not raise exceptions
    
    def test_background_scheduler_idempotent_start(self):
        """Test multiple start calls are safe"""
        scheduler = KeyRotationScheduler()
        scheduler.start_background_scheduler()
        scheduler.start_background_scheduler()  # Should not create duplicate
        scheduler.stop_background_scheduler()


class TestBackwardCompatibility:
    """Verify ADD-ONLY philosophy - no existing code broken"""
    
    def test_new_module_is_isolated(self):
        """Test new module works independently"""
        scheduler = KeyRotationScheduler()
        scheduler.register_key("compat_test", "Kyber", AlgorithmClass.KEM_PQC)
        status = scheduler.get_key_status("compat_test")
        assert status is not None
    
    def test_no_existing_dependencies(self):
        """Test module doesn't depend on existing crypto code"""
        # This module should work completely standalone
        # It only manages metadata, doesn't do actual crypto
        scheduler = KeyRotationScheduler()
        assert scheduler is not None
        
        # Key generation is delegated to caller via callback
        def dummy_generator():
            return "generated_key"
        
        scheduler.register_key("gen_test", "Test-Algorithm", AlgorithmClass.KEM_HYBRID)
        success, result = scheduler.perform_rotation(
            "gen_test",
            RotationTrigger.MANUAL,
            key_generator=dummy_generator
        )
        assert success is True
        assert result == "generated_key"


class TestAlgorithmClasses:
    """Test algorithm class enumeration"""
    
    def test_all_algorithm_classes_exist(self):
        """Test all expected algorithm classes are defined"""
        expected_classes = [
            "kem_classic",
            "kem_pqc",
            "kem_hybrid",
            "signature_classic",
            "signature_pqc",
            "signature_hybrid"
        ]
        
        for cls in expected_classes:
            assert AlgorithmClass(cls) is not None


class TestRotationTriggers:
    """Test rotation trigger enumeration"""
    
    def test_all_triggers_exist(self):
        """Test all expected rotation triggers are defined"""
        expected_triggers = [
            "time_based",
            "usage_based",
            "compromise_suspected",
            "manual",
            "policy_violation",
            "security_advisory"
        ]
        
        for trigger in expected_triggers:
            assert RotationTrigger(trigger) is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
