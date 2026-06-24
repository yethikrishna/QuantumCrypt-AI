"""
Tests for Post-Quantum Key Rotation Scheduler v25
Dimension A - Feature Expansion Tests
"""
import pytest
import time
from datetime import datetime, timedelta, timezone
from quantum_crypt.feature_expansion_pq_key_rotation_scheduler_v25_2026_june import (
    PQKeyRotationScheduler,
    PQAlgorithm,
    KeyStatus,
    RotationStrategy,
    ComplianceStandard,
    KeyMetadata,
    RotationPolicy
)


class TestPQKeyRotationScheduler:
    """Test suite for Post-Quantum Key Rotation Scheduler."""
    
    def test_initialization(self):
        """Test scheduler initialization."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        assert len(scheduler._keys) == 0
        assert len(scheduler._policies) >= 4  # Default policies
        assert "standard" in scheduler._policies
        assert "high_security" in scheduler._policies
    
    def test_default_policies_exist(self):
        """Test default policies are created."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        assert "standard" in scheduler._policies
        assert "high_security" in scheduler._policies
        assert "pci_dss" in scheduler._policies
        assert "quantum_resistant" in scheduler._policies
    
    def test_register_key(self):
        """Test key registration."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        
        key_id = scheduler.register_key(
            algorithm=PQAlgorithm.CRYSTALS_KYBER_768,
            policy_id="standard"
        )
        
        assert key_id.startswith("pq_key_")
        assert key_id in scheduler._keys
        key = scheduler._keys[key_id]
        assert key.algorithm == PQAlgorithm.CRYSTALS_KYBER_768
        assert key.status == KeyStatus.ACTIVE
    
    def test_register_key_with_compliance_tags(self):
        """Test key registration with compliance tags."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        
        key_id = scheduler.register_key(
            algorithm=PQAlgorithm.CRYSTALS_KYBER_1024,
            policy_id="high_security",
            compliance_tags=["pci", "hipaa", "production"]
        )
        
        key = scheduler._keys[key_id]
        assert "pci" in key.compliance_tags
        assert "hipaa" in key.compliance_tags
    
    def test_get_key_metadata(self):
        """Test getting key metadata."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        key_id = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_512)
        
        metadata = scheduler.get_key_metadata(key_id)
        assert metadata is not None
        assert metadata.key_id == key_id
        assert metadata.algorithm == PQAlgorithm.CRYSTALS_KYBER_512
    
    def test_get_nonexistent_key_metadata(self):
        """Test getting metadata for non-existent key."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        metadata = scheduler.get_key_metadata("nonexistent")
        assert metadata is None
    
    def test_record_key_usage(self):
        """Test recording key usage."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        key_id = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        
        result = scheduler.record_key_usage(key_id)
        assert result is True
        
        key = scheduler._keys[key_id]
        assert key.usage_count == 1
        assert key.last_used is not None
    
    def test_record_usage_nonexistent_key(self):
        """Test recording usage for non-existent key."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        result = scheduler.record_key_usage("nonexistent")
        assert result is False
    
    def test_key_expiration_check(self):
        """Test key expiration logic."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        key_id = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        
        key = scheduler._keys[key_id]
        assert key.is_expired() is False
        
        # Manually expire key
        key.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        assert key.is_expired() is True
    
    def test_key_needs_rotation_by_time(self):
        """Test rotation needed based on time."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        key_id = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        
        key = scheduler._keys[key_id]
        assert key.needs_rotation() is False
        
        # Force rotation deadline to past
        key.rotation_deadline = datetime.now(timezone.utc) - timedelta(days=1)
        assert key.needs_rotation() is True
    
    def test_key_needs_rotation_by_usage(self):
        """Test rotation needed based on usage."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        key_id = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        
        key = scheduler._keys[key_id]
        key.max_usage = 5
        
        for _ in range(6):
            scheduler.record_key_usage(key_id)
        
        assert key.needs_rotation() is True
    
    def test_manual_key_rotation(self):
        """Test manual key rotation."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        old_key_id = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        
        new_key_id = scheduler.rotate_key_now(old_key_id, "manual_test")
        
        assert new_key_id is not None
        assert new_key_id != old_key_id
        assert new_key_id in scheduler._keys
        
        old_key = scheduler._keys[old_key_id]
        assert old_key.status in [KeyStatus.ROTATING, KeyStatus.DEPRECATED]
    
    def test_revoke_key(self):
        """Test key revocation."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        key_id = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        
        result = scheduler.revoke_key(key_id, "test_compromise")
        assert result is True
        
        key = scheduler._keys[key_id]
        assert key.status == KeyStatus.REVOKED
    
    def test_revoke_nonexistent_key(self):
        """Test revoking non-existent key."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        result = scheduler.revoke_key("nonexistent")
        assert result is False
    
    def test_get_keys_needing_rotation(self):
        """Test getting keys that need rotation."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        
        # Normal key
        key1 = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_512)
        
        # Key needing rotation
        key2 = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        scheduler._keys[key2].rotation_deadline = datetime.now(timezone.utc) - timedelta(days=1)
        
        needing_rotation = scheduler.get_keys_needing_rotation()
        assert key2 in needing_rotation
        assert key1 not in needing_rotation
    
    def test_emergency_rotation_all(self):
        """Test emergency rotation of all keys."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        
        key1 = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_512)
        key2 = scheduler.register_key(PQAlgorithm.NTRU_HPS_2048)
        
        results = scheduler.emergency_rotation_all("test_incident")
        
        assert len(results) >= 2
        assert key1 in results
        assert key2 in results
    
    def test_compliance_check(self):
        """Test compliance checking."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        
        # Register keys with PCI policy
        key1 = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768, policy_id="pci_dss")
        
        result = scheduler.check_compliance(ComplianceStandard.PCI_DSS)
        
        assert result["standard"] == "pci_dss"
        assert "compliance_percentage" in result
        assert 0 <= result["compliance_percentage"] <= 100
    
    def test_rotation_statistics(self):
        """Test rotation statistics."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        
        scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_512)
        scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        scheduler.register_key(PQAlgorithm.NTRU_HPS_2048)
        
        stats = scheduler.get_rotation_statistics()
        
        assert stats["total_keys"] == 3
        assert "keys_by_status" in stats
        assert "keys_by_algorithm" in stats
        assert "total_rotations" in stats
        assert stats["total_rotations"] == 0
    
    def test_rotation_statistics_with_rotations(self):
        """Test statistics after rotations."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        
        key_id = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        scheduler.rotate_key_now(key_id, "test")
        
        stats = scheduler.get_rotation_statistics()
        
        assert stats["total_rotations"] == 1
        assert stats["successful_rotations"] == 1
    
    def test_create_custom_policy(self):
        """Test creating custom rotation policy."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        
        policy_id = scheduler.create_custom_policy(
            name="Custom Policy",
            rotation_days=14,
            max_usage=5000,
            overlap_hours=2
        )
        
        assert policy_id in scheduler._policies
        policy = scheduler._policies[policy_id]
        assert policy.name == "Custom Policy"
        assert policy.rotation_interval == timedelta(days=14)
    
    def test_rotation_callback(self):
        """Test rotation callback mechanism."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        callback_called = []
        
        def callback(old_id, new_id):
            callback_called.append((old_id, new_id))
        
        scheduler.add_rotation_callback(callback)
        
        old_key = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        scheduler.rotate_key_now(old_key)
        
        assert len(callback_called) == 1
        assert callback_called[0][0] == old_key
    
    def test_key_time_until_rotation(self):
        """Test time until rotation calculation."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        key_id = scheduler.register_key(PQAlgorithm.CRYSTALS_KYBER_768)
        
        key = scheduler._keys[key_id]
        time_left = key.get_time_until_rotation()
        
        assert isinstance(time_left, timedelta)
        assert time_left.total_seconds() > 0
    
    def test_scheduler_stop(self):
        """Test scheduler stop functionality."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=True)
        time.sleep(0.1)  # Let thread start
        scheduler.stop_scheduler()
        assert scheduler._running is False
    
    def test_hybrid_algorithm_support(self):
        """Test hybrid PQ-classical algorithm support."""
        scheduler = PQKeyRotationScheduler(enable_background_thread=False)
        
        key_id = scheduler.register_key(PQAlgorithm.HYBRID_KYBER_RSA)
        key = scheduler._keys[key_id]
        
        assert key.algorithm == PQAlgorithm.HYBRID_KYBER_RSA
        assert key.algorithm.value == "hybrid_kyber_rsa"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
