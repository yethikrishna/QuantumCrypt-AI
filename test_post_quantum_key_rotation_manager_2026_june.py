"""
Test Suite for Post-Quantum Key Rotation Manager
QuantumCrypt-AI - June 2026

Production-grade tests with real working test cases.
"""

import unittest
import sys
import os
import tempfile
import shutil
from datetime import datetime, timedelta

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_key_rotation_manager_2026_june import (
    PostQuantumKeyRotationManager,
    KeyMaterialGenerator,
    RotationScheduler,
    KeyStatus,
    AlgorithmType,
    KeyVersion,
    RotationPolicy,
    RotationEvent
)


class TestKeyMaterialGenerator(unittest.TestCase):
    """Tests for secure key material generation."""
    
    def test_generate_key_material(self):
        """Test key material generation produces valid output."""
        material = KeyMaterialGenerator.generate_key_material(AlgorithmType.CRYSTALS_KYBER)
        self.assertTrue(material.startswith("CRYSTALS-Kyber:"))
        # Should be hex string after prefix
        hex_part = material.split(":", 1)[1]
        int(hex_part, 16)  # Should not throw ValueError
    
    def test_generate_key_material_different_algorithms(self):
        """Test different algorithms produce different prefixes."""
        kyber = KeyMaterialGenerator.generate_key_material(AlgorithmType.CRYSTALS_KYBER)
        dilithium = KeyMaterialGenerator.generate_key_material(AlgorithmType.CRYSTALS_DILITHIUM)
        
        self.assertTrue(kyber.startswith("CRYSTALS-Kyber:"))
        self.assertTrue(dilithium.startswith("CRYSTALS-Dilithium:"))
    
    def test_generate_key_id_format(self):
        """Test key IDs follow expected format."""
        key_id = KeyMaterialGenerator.generate_key_id()
        self.assertTrue(key_id.startswith("pqk-"))
        self.assertEqual(len(key_id), 20)  # pqk- + 16 hex chars
    
    def test_key_material_uniqueness(self):
        """Test generated keys are unique."""
        keys = set()
        for _ in range(100):
            material = KeyMaterialGenerator.generate_key_material(AlgorithmType.SPHINCS)
            self.assertNotIn(material, keys)
            keys.add(material)
    
    def test_derive_child_key(self):
        """Test child key derivation."""
        parent = "test_parent_key_12345"
        child1 = KeyMaterialGenerator.derive_child_key(parent, "context1")
        child2 = KeyMaterialGenerator.derive_child_key(parent, "context2")
        child1_again = KeyMaterialGenerator.derive_child_key(parent, "context1")
        
        self.assertNotEqual(child1, child2)  # Different contexts = different keys
        self.assertEqual(child1, child1_again)  # Same context = same key


class TestRotationScheduler(unittest.TestCase):
    """Tests for rotation scheduling logic."""
    
    def test_calculate_next_rotation(self):
        """Test next rotation calculation."""
        created = datetime.utcnow().isoformat()
        policy = RotationPolicy(max_age_days=90)
        next_rot = RotationScheduler.calculate_next_rotation(created, policy)
        
        expected = datetime.fromisoformat(created) + timedelta(days=90)
        self.assertAlmostEqual(
            (next_rot - expected).total_seconds(),
            0,
            delta=1
        )
    
    def test_needs_rotation_fresh_key(self):
        """Test fresh keys don't need rotation."""
        key = KeyVersion(
            key_id="test",
            version=1,
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            key_material="test",
            created_at=datetime.utcnow().isoformat(),
            status=KeyStatus.ACTIVE
        )
        policy = RotationPolicy(max_age_days=90)
        
        needs, reason = RotationScheduler.needs_rotation(key, policy)
        self.assertFalse(needs)
        self.assertIn("valid", reason.lower())
    
    def test_needs_rotation_expired_key(self):
        """Test expired keys need rotation."""
        old_date = (datetime.utcnow() - timedelta(days=100)).isoformat()
        key = KeyVersion(
            key_id="test",
            version=1,
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            key_material="test",
            created_at=old_date,
            status=KeyStatus.ACTIVE
        )
        policy = RotationPolicy(max_age_days=90)
        
        needs, reason = RotationScheduler.needs_rotation(key, policy)
        self.assertTrue(needs)
        self.assertIn("exceeded", reason.lower())
    
    def test_needs_rotation_warning_period(self):
        """Test keys in warning period flag for rotation."""
        almost_expired = (datetime.utcnow() - timedelta(days=85)).isoformat()
        key = KeyVersion(
            key_id="test",
            version=1,
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            key_material="test",
            created_at=almost_expired,
            status=KeyStatus.ACTIVE
        )
        policy = RotationPolicy(max_age_days=90, warning_days_before=7)
        
        needs, reason = RotationScheduler.needs_rotation(key, policy)
        self.assertTrue(needs)
        self.assertIn("expiring", reason.lower())


class TestPostQuantumKeyRotationManagerBasics(unittest.TestCase):
    """Basic tests for the key rotation manager."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = PostQuantumKeyRotationManager(self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_create_key_basic(self):
        """Test basic key creation."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        self.assertIsNotNone(key)
        self.assertEqual(key.version, 1)
        self.assertEqual(key.status, KeyStatus.ACTIVE)
        self.assertEqual(key.algorithm, AlgorithmType.CRYSTALS_KYBER)
        self.assertTrue(key.fingerprint)
    
    def test_create_key_with_policy(self):
        """Test key creation with custom rotation policy."""
        custom_policy = RotationPolicy(
            max_age_days=30,
            auto_rotate=True,
            min_versions_kept=5
        )
        
        key = self.manager.create_key(
            AlgorithmType.FALCON,
            policy=custom_policy
        )
        
        self.assertIsNotNone(key)
        policy = self.manager.policies[key.key_id]
        self.assertEqual(policy.max_age_days, 30)
        self.assertEqual(policy.min_versions_kept, 5)
    
    def test_create_key_with_metadata(self):
        """Test key creation with metadata."""
        metadata = {"environment": "production", "owner": "security-team"}
        key = self.manager.create_key(
            AlgorithmType.SPHINCS,
            metadata=metadata
        )
        
        self.assertEqual(key.metadata["environment"], "production")
        self.assertEqual(key.metadata["owner"], "security-team")
    
    def test_get_active_key(self):
        """Test retrieving active key version."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        retrieved = self.manager.get_active_key(key.key_id)
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.key_id, key.key_id)
        self.assertEqual(retrieved.version, 1)
    
    def test_get_active_key_nonexistent(self):
        """Test retrieving non-existent key returns None."""
        retrieved = self.manager.get_active_key("nonexistent_key")
        self.assertIsNone(retrieved)
    
    def test_get_all_versions(self):
        """Test retrieving all key versions."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        versions = self.manager.get_all_versions(key.key_id)
        
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0].version, 1)


class TestKeyRotationFunctionality(unittest.TestCase):
    """Tests for key rotation operations."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = PostQuantumKeyRotationManager(self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_rotate_key_success(self):
        """Test successful key rotation."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        success, new_key, message = self.manager.rotate_key(
            key_id=key.key_id,
            reason="test_rotation"
        )
        
        self.assertTrue(success)
        self.assertIsNotNone(new_key)
        self.assertEqual(new_key.version, 2)
        self.assertIn("Successfully rotated", message)
        
        # Old version should be deprecated
        old_version = self.manager.get_all_versions(key.key_id)[0]
        self.assertEqual(old_version.status, KeyStatus.DEPRECATED)
        
        # New version should be active
        active = self.manager.get_active_key(key.key_id)
        self.assertEqual(active.version, 2)
    
    def test_rotate_key_nonexistent(self):
        """Test rotating non-existent key fails gracefully."""
        success, new_key, message = self.manager.rotate_key(
            key_id="nonexistent",
            reason="test"
        )
        
        self.assertFalse(success)
        self.assertIsNone(new_key)
        self.assertIn("not found", message)
    
    def test_rotate_key_with_algorithm_change(self):
        """Test algorithm agility - change algorithm on rotation."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        success, new_key, _ = self.manager.rotate_key(
            key_id=key.key_id,
            new_algorithm=AlgorithmType.CRYSTALS_DILITHIUM
        )
        
        self.assertTrue(success)
        self.assertEqual(new_key.algorithm, AlgorithmType.CRYSTALS_DILITHIUM)
    
    def test_multiple_rotations(self):
        """Test multiple consecutive rotations."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        for i in range(5):
            success, _, _ = self.manager.rotate_key(key.key_id)
            self.assertTrue(success)
        
        versions = self.manager.get_all_versions(key.key_id)
        self.assertEqual(len(versions), 6)  # v1 + 5 rotations
        
        active = self.manager.get_active_key(key.key_id)
        self.assertEqual(active.version, 6)
    
    def test_rotation_audit_logging(self):
        """Test rotations are properly logged."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        initial_log_count = len(self.manager.audit_log)
        
        self.manager.rotate_key(key.key_id, reason="audit_test")
        
        self.assertGreater(len(self.manager.audit_log), initial_log_count)
        
        latest_event = self.manager.audit_log[-1]
        self.assertEqual(latest_event.key_id, key.key_id)
        self.assertEqual(latest_event.reason, "audit_test")
        self.assertTrue(latest_event.success)


class TestEmergencyOperations(unittest.TestCase):
    """Tests for emergency key management operations."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = PostQuantumKeyRotationManager(self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_rollback_key(self):
        """Test emergency rollback to previous version."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        self.manager.rotate_key(key.key_id)  # v2
        
        # Now at v2, rollback to v1
        success, message = self.manager.rollback_key(key.key_id, 1)
        
        self.assertTrue(success)
        self.assertIn("Rolled back", message)
        
        active = self.manager.get_active_key(key.key_id)
        self.assertEqual(active.version, 1)
    
    def test_rollback_nonexistent_version(self):
        """Test rollback to non-existent version fails."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        success, message = self.manager.rollback_key(key.key_id, 999)
        self.assertFalse(success)
        self.assertIn("not found", message)
    
    def test_mark_compromised(self):
        """Test marking key as compromised."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        success, message = self.manager.mark_compromised(key.key_id)
        
        self.assertTrue(success)
        
        # All versions should be marked compromised
        versions = self.manager.get_all_versions(key.key_id)
        for v in versions:
            if v.version != len(versions):  # Except the new replacement
                self.assertEqual(v.status, KeyStatus.COMPROMISED)


class TestStatusAndReporting(unittest.TestCase):
    """Tests for status reporting and health checks."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = PostQuantumKeyRotationManager(self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_get_rotation_status(self):
        """Test getting key rotation status."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        status = self.manager.get_rotation_status(key.key_id)
        
        self.assertTrue(status["exists"])
        self.assertEqual(status["active_version"], 1)
        self.assertFalse(status["needs_rotation"])
        self.assertIn("next_scheduled_rotation", status)
        self.assertIn("policy", status)
    
    def test_get_rotation_status_nonexistent(self):
        """Test status for non-existent key."""
        status = self.manager.get_rotation_status("nonexistent")
        self.assertFalse(status["exists"])
    
    def test_get_health_report_empty(self):
        """Test health report with no keys."""
        report = self.manager.get_health_report()
        self.assertEqual(report["total_managed_keys"], 0)
        self.assertEqual(report["healthy_keys"], 0)
    
    def test_get_health_report_with_keys(self):
        """Test health report with keys."""
        for _ in range(3):
            self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        report = self.manager.get_health_report()
        self.assertEqual(report["total_managed_keys"], 3)
        self.assertEqual(report["healthy_keys"], 3)
        self.assertEqual(report["keys_needing_attention"], 0)
    
    def test_get_audit_log(self):
        """Test retrieving audit log."""
        key = self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        self.manager.rotate_key(key.key_id)
        
        log = self.manager.get_audit_log()
        self.assertGreater(len(log), 0)
        
        key_log = self.manager.get_audit_log(key_id=key.key_id)
        self.assertGreater(len(key_log), 0)


class TestAutoRotationProcessing(unittest.TestCase):
    """Tests for automated scheduled rotation processing."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = PostQuantumKeyRotationManager(self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_process_scheduled_rotations_no_ops(self):
        """Test scheduled rotation with nothing to do."""
        self.manager.create_key(AlgorithmType.CRYSTALS_KYBER)
        
        result = self.manager.process_scheduled_rotations()
        
        self.assertEqual(result["rotated_count"], 0)
        self.assertEqual(result["failed_count"], 0)
    
    def test_process_scheduled_rotations_with_manual_policy(self):
        """Test keys requiring manual approval are skipped."""
        policy = RotationPolicy(
            max_age_days=90,
            auto_rotate=True,
            require_manual_approval=True
        )
        self.manager.create_key(AlgorithmType.CRYSTALS_KYBER, policy=policy)
        
        result = self.manager.process_scheduled_rotations()
        
        # Should be skipped, not rotated
        self.assertEqual(result["rotated_count"], 0)


class TestKeyVersionProperties(unittest.TestCase):
    """Tests for KeyVersion dataclass properties."""
    
    def test_fingerprint_generation(self):
        """Test fingerprint is automatically generated."""
        key = KeyVersion(
            key_id="test123",
            version=1,
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            key_material="test_material",
            created_at=datetime.utcnow().isoformat(),
            status=KeyStatus.ACTIVE
        )
        
        self.assertTrue(key.fingerprint)
        self.assertEqual(len(key.fingerprint), 32)  # 16 bytes hex
    
    def test_fingerprint_uniqueness(self):
        """Test different keys have different fingerprints."""
        key1 = KeyVersion(
            key_id="test1",
            version=1,
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            key_material="material1",
            created_at=datetime.utcnow().isoformat(),
            status=KeyStatus.ACTIVE
        )
        
        key2 = KeyVersion(
            key_id="test2",
            version=1,
            algorithm=AlgorithmType.CRYSTALS_KYBER,
            key_material="material2",
            created_at=datetime.utcnow().isoformat(),
            status=KeyStatus.ACTIVE
        )
        
        self.assertNotEqual(key1.fingerprint, key2.fingerprint)


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("Post-Quantum Key Rotation Manager - Test Suite")
    print("=" * 60)
    print()
    
    result = run_tests()
    
    print()
    print("=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    sys.exit(0 if result.wasSuccessful() else 1)
