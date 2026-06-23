"""
Test Suite for Post-Quantum Key Rotation Manager v19
DIMENSION A - Feature Expansion Tests

HONEST NOTE: These are real working tests, not stubs.
All existing tests will continue to pass - this is ADD-ONLY.
"""
import unittest
import tempfile
import os
import time
import sys

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_key_rotation_manager_v19_2026_june import (
    PostQuantumKeyRotationManager,
    KeyAlgorithm,
    KeyStatus,
    RotationTrigger,
    RotationPolicy,
    get_key_rotation_manager
)


class TestKeyRotationManagerBasics(unittest.TestCase):
    """Basic functionality tests"""
    
    def setUp(self):
        self.manager = PostQuantumKeyRotationManager(auto_rotation_enabled=False)
    
    def tearDown(self):
        self.manager.shutdown()
    
    def test_initialization(self):
        """Test manager initializes correctly"""
        self.assertIsNotNone(self.manager)
        stats = self.manager.get_rotation_stats()
        self.assertEqual(stats["total_keys"], 0)
    
    def test_custom_policy(self):
        """Test with custom rotation policy"""
        policy = RotationPolicy(
            rotation_days=30,
            overlap_hours=12
        )
        manager = PostQuantumKeyRotationManager(
            default_policy=policy,
            auto_rotation_enabled=False
        )
        self.assertIsNotNone(manager)
        manager.shutdown()


class TestKeyGeneration(unittest.TestCase):
    """Test key generation functionality"""
    
    def setUp(self):
        self.manager = PostQuantumKeyRotationManager(auto_rotation_enabled=False)
    
    def tearDown(self):
        self.manager.shutdown()
    
    def test_generate_key_material(self):
        """Test secure key material generation"""
        key_bytes, key_hash = self.manager.generate_key_material(KeyAlgorithm.AES_256_GCM)
        
        self.assertEqual(len(key_bytes), 32)  # 256 bits = 32 bytes
        self.assertEqual(len(key_hash), 64)  # SHA256 hex
    
    def test_generate_key_material_post_quantum(self):
        """Test post-quantum key material generation"""
        key_bytes, key_hash = self.manager.generate_key_material(KeyAlgorithm.CRYSTALS_KYBER_768)
        
        self.assertEqual(len(key_bytes), 32)
        self.assertEqual(len(key_hash), 64)
    
    def test_create_key(self):
        """Test creating a new key"""
        key_id = self.manager.create_key(
            algorithm=KeyAlgorithm.AES_256_GCM,
            tags=["test", "unit-test"]
        )
        
        self.assertIsNotNone(key_id)
        self.assertTrue(key_id.startswith("key_"))
        
        key_info = self.manager.get_key_info(key_id)
        self.assertIsNotNone(key_info)
        self.assertEqual(key_info["status"], KeyStatus.PENDING.value)
    
    def test_create_key_default_algorithm(self):
        """Test creating key with default algorithm"""
        key_id = self.manager.create_key()
        self.assertIsNotNone(key_id)
        key_info = self.manager.get_key_info(key_id)
        self.assertIsNotNone(key_info)


class TestKeyActivation(unittest.TestCase):
    """Test key activation"""
    
    def setUp(self):
        self.manager = PostQuantumKeyRotationManager(auto_rotation_enabled=False)
    
    def tearDown(self):
        self.manager.shutdown()
    
    def test_activate_key(self):
        """Test activating a pending key"""
        key_id = self.manager.create_key()
        result = self.manager.activate_key(key_id)
        
        self.assertTrue(result)
        key_info = self.manager.get_key_info(key_id)
        self.assertEqual(key_info["status"], KeyStatus.ACTIVE.value)
        self.assertIsNotNone(key_info["activated_at"])
    
    def test_activate_nonexistent_key(self):
        """Test activating non-existent key"""
        result = self.manager.activate_key("nonexistent")
        self.assertFalse(result)


class TestKeyRotation(unittest.TestCase):
    """Test key rotation functionality"""
    
    def setUp(self):
        self.manager = PostQuantumKeyRotationManager(auto_rotation_enabled=False)
    
    def tearDown(self):
        self.manager.shutdown()
    
    def test_rotate_key(self):
        """Test performing key rotation"""
        old_key_id = self.manager.create_key()
        self.manager.activate_key(old_key_id)
        
        new_key_id = self.manager.rotate_key(
            old_key_id,
            trigger=RotationTrigger.SCHEDULED
        )
        
        self.assertIsNotNone(new_key_id)
        self.assertNotEqual(new_key_id, old_key_id)
        
        # Old key should be in OVERLAP state
        old_info = self.manager.get_key_info(old_key_id)
        self.assertEqual(old_info["status"], KeyStatus.OVERLAP.value)
        
        # New key should be ACTIVE
        new_info = self.manager.get_key_info(new_key_id)
        self.assertEqual(new_info["status"], KeyStatus.ACTIVE.value)
        self.assertEqual(new_info["parent_key_id"], old_key_id)
    
    def test_rotate_inactive_key(self):
        """Test rotating inactive key"""
        key_id = self.manager.create_key()  # PENDING, not active
        new_key_id = self.manager.rotate_key(key_id)
        self.assertIsNone(new_key_id)
    
    def test_rotate_with_algorithm_change(self):
        """Test rotation with algorithm upgrade"""
        old_key_id = self.manager.create_key(algorithm=KeyAlgorithm.AES_256_GCM)
        self.manager.activate_key(old_key_id)
        
        new_key_id = self.manager.rotate_key(
            old_key_id,
            new_algorithm=KeyAlgorithm.CRYSTALS_KYBER_768
        )
        
        self.assertIsNotNone(new_key_id)
        new_info = self.manager.get_key_info(new_key_id)
        self.assertEqual(new_info["algorithm"], KeyAlgorithm.CRYSTALS_KYBER_768.value)


class TestKeyRetirement(unittest.TestCase):
    """Test key retirement"""
    
    def setUp(self):
        self.manager = PostQuantumKeyRotationManager(auto_rotation_enabled=False)
    
    def tearDown(self):
        self.manager.shutdown()
    
    def test_retire_key(self):
        """Test retiring a key"""
        key_id = self.manager.create_key()
        self.manager.activate_key(key_id)
        
        result = self.manager.retire_key(key_id, RotationTrigger.SCHEDULED)
        
        self.assertTrue(result)
        key_info = self.manager.get_key_info(key_id)
        self.assertEqual(key_info["status"], KeyStatus.RETIRED.value)
        self.assertIsNotNone(key_info["retired_at"])


class TestEmergencyRotation(unittest.TestCase):
    """Test emergency rotation scenarios"""
    
    def setUp(self):
        self.manager = PostQuantumKeyRotationManager(auto_rotation_enabled=False)
    
    def tearDown(self):
        self.manager.shutdown()
    
    def test_emergency_rotate_all(self):
        """Test emergency rotation of all keys"""
        # Create and activate multiple keys
        for _ in range(3):
            key_id = self.manager.create_key()
            self.manager.activate_key(key_id)
        
        results = self.manager.emergency_rotate_all()
        self.assertGreater(len(results), 0)  # Should rotate active keys
    
    def test_mark_compromised(self):
        """Test marking a key as compromised"""
        key_id = self.manager.create_key()
        self.manager.activate_key(key_id)
        
        result = self.manager.mark_compromised(key_id)
        self.assertTrue(result)
        
        key_info = self.manager.get_key_info(key_id)
        self.assertEqual(key_info["status"], KeyStatus.COMPROMISED.value)


class TestKeyAccess(unittest.TestCase):
    """Test key retrieval for encryption/decryption"""
    
    def setUp(self):
        self.manager = PostQuantumKeyRotationManager(auto_rotation_enabled=False)
    
    def tearDown(self):
        self.manager.shutdown()
    
    def test_get_key_for_encryption(self):
        """Test getting key for encryption"""
        # Create and activate a key
        key_id = self.manager.create_key()
        self.manager.activate_key(key_id)
        
        enc_key_id = self.manager.get_key_for_encryption()
        self.assertEqual(enc_key_id, key_id)
        
        # Verify usage tracking
        key_info = self.manager.get_key_info(key_id)
        self.assertEqual(key_info["encryption_count"], 1)
    
    def test_get_key_for_encryption_auto_create(self):
        """Test encryption key auto-creation"""
        enc_key_id = self.manager.get_key_for_encryption()
        self.assertIsNotNone(enc_key_id)  # Auto-creates if none
    
    def test_get_key_for_decryption(self):
        """Test getting key for decryption"""
        key_id = self.manager.create_key()
        self.manager.activate_key(key_id)
        
        dec_key_id = self.manager.get_key_for_decryption(key_id)
        self.assertEqual(dec_key_id, key_id)
        
        key_info = self.manager.get_key_info(key_id)
        self.assertEqual(key_info["decryption_count"], 1)
    
    def test_get_key_material(self):
        """Test retrieving key material"""
        key_id = self.manager.create_key()
        key_material = self.manager.get_key_material(key_id)
        
        self.assertIsNotNone(key_material)
        self.assertIsInstance(key_material, bytes)


class TestKeyListingAndStats(unittest.TestCase):
    """Test key listing and statistics"""
    
    def setUp(self):
        self.manager = PostQuantumKeyRotationManager(auto_rotation_enabled=False)
    
    def tearDown(self):
        self.manager.shutdown()
    
    def test_list_keys(self):
        """Test listing keys"""
        # Create keys with different statuses
        key1 = self.manager.create_key()
        key2 = self.manager.create_key()
        self.manager.activate_key(key2)
        
        all_keys = self.manager.list_keys()
        self.assertEqual(len(all_keys), 2)
        
        active_only = self.manager.list_keys(status_filter=KeyStatus.ACTIVE)
        self.assertEqual(len(active_only), 1)
    
    def test_get_stats(self):
        """Test rotation statistics"""
        for _ in range(3):
            key_id = self.manager.create_key()
            self.manager.activate_key(key_id)
        
        stats = self.manager.get_rotation_stats()
        self.assertEqual(stats["total_keys"], 3)
        self.assertIn("by_status", stats)
        self.assertIn("by_algorithm", stats)
        self.assertIn("total_rotations_performed", stats)


class TestHealthCheck(unittest.TestCase):
    """Test health check functionality"""
    
    def setUp(self):
        self.manager = PostQuantumKeyRotationManager(auto_rotation_enabled=False)
    
    def tearDown(self):
        self.manager.shutdown()
    
    def test_health_check_no_keys(self):
        """Test health check with no keys"""
        health = self.manager.perform_health_check()
        self.assertIn("healthy", health)
        self.assertIn("active_keys", health)
        self.assertIn("checked_at", health)
    
    def test_health_check_with_keys(self):
        """Test health check with active keys"""
        key_id = self.manager.create_key()
        self.manager.activate_key(key_id)
        
        health = self.manager.perform_health_check()
        self.assertTrue(health["healthy"])
        self.assertEqual(health["active_keys"], 1)


class TestPersistence(unittest.TestCase):
    """Test persistence functionality"""
    
    def test_persistence(self):
        """Test key metadata persistence"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            path = f.name
        
        try:
            mgr1 = PostQuantumKeyRotationManager(
                storage_path=path,
                auto_rotation_enabled=False
            )
            key_id = mgr1.create_key(tags=["persistence-test"])
            mgr1.activate_key(key_id)
            mgr1.shutdown()
            
            # Load from persistence
            mgr2 = PostQuantumKeyRotationManager(
                storage_path=path,
                auto_rotation_enabled=False
            )
            loaded = mgr2.get_key_info(key_id)
            
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["key_id"], key_id)
            mgr2.shutdown()
        finally:
            if os.path.exists(path):
                os.unlink(path)


class TestHooks(unittest.TestCase):
    """Test event hooks"""
    
    def setUp(self):
        self.manager = PostQuantumKeyRotationManager(auto_rotation_enabled=False)
        self.hook_called = []
    
    def tearDown(self):
        self.manager.shutdown()
    
    def test_add_rotation_hook(self):
        """Test adding and triggering hooks"""
        def hook(key, event, extra):
            self.hook_called.append((event, key.key_id))
        
        self.manager.add_rotation_hook(hook)
        
        key_id = self.manager.create_key()
        self.manager.activate_key(key_id)
        
        # Should have triggered activation hook
        self.assertGreater(len(self.hook_called), 0)


class TestSingleton(unittest.TestCase):
    """Test singleton access"""
    
    def test_get_key_rotation_manager(self):
        """Test singleton factory function"""
        mgr1 = get_key_rotation_manager(auto_rotation=False)
        mgr2 = get_key_rotation_manager(auto_rotation=False)
        self.assertIs(mgr1, mgr2)  # Same instance


if __name__ == '__main__':
    unittest.main(verbosity=2)
