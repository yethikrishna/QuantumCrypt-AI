"""
Test Suite for Post-Quantum Key Management System - June 2026
Production-grade tests with real assertions
"""
import unittest
import tempfile
import os
import time
from quantum_crypt.key_management_system_2026 import (
    PostQuantumKMS,
    KeyWrapping,
    KeyState,
    KeyType,
    KeyAlgorithm,
    RotationPolicy,
)


class TestKeyWrapping(unittest.TestCase):
    """Test suite for NIST-compliant key wrapping"""

    def test_wrap_unwrap_cycle(self):
        """Test wrap and unwrap returns original key"""
        wrapper = KeyWrapping()
        original_key = b"test_post_quantum_key_material_12345"

        ciphertext, nonce, tag = wrapper.wrap_key(original_key)
        unwrapped = wrapper.unwrap_key(ciphertext, nonce, tag)

        self.assertEqual(unwrapped, original_key)
        print(f"✓ Wrap/unwrap cycle successful")

    def test_wrap_with_aad(self):
        """Test wrapping with additional authenticated data"""
        wrapper = KeyWrapping()
        original_key = b"test_key_with_aad"
        aad = b"key_id:test-001,version:v1"

        ciphertext, nonce, tag = wrapper.wrap_key(original_key, aad=aad)
        unwrapped = wrapper.unwrap_key(ciphertext, nonce, tag, aad=aad)

        self.assertEqual(unwrapped, original_key)
        print(f"✓ Wrap with AAD successful")

    def test_tamper_detection(self):
        """Test tampered ciphertext is rejected"""
        wrapper = KeyWrapping()
        original_key = b"sensitive_key_material"

        ciphertext, nonce, tag = wrapper.wrap_key(original_key)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF

        unwrapped = wrapper.unwrap_key(bytes(tampered), nonce, tag)
        self.assertIsNone(unwrapped)
        print(f"✓ Tamper detection working correctly")

    def test_wrong_aad_rejected(self):
        """Test wrong AAD causes authentication failure"""
        wrapper = KeyWrapping()
        original_key = b"test_key"

        ciphertext, nonce, tag = wrapper.wrap_key(original_key, aad=b"correct_aad")
        unwrapped = wrapper.unwrap_key(ciphertext, nonce, tag, aad=b"wrong_aad")

        self.assertIsNone(unwrapped)
        print(f"✓ Wrong AAD correctly rejected")


class TestPostQuantumKMS(unittest.TestCase):
    """Test suite for Post-Quantum KMS"""

    def setUp(self):
        """Fresh KMS for each test"""
        self.kms = PostQuantumKMS()

    def test_create_ml_kem_key(self):
        """Test creating ML-KEM post-quantum key"""
        key = self.kms.create_key(
            key_id="test-ml-kem-768",
            key_type=KeyType.ML_KEM_KEY,
            algorithm=KeyAlgorithm.ML_KEM_768,
            description="Test ML-KEM-768 key encapsulation key"
        )

        self.assertEqual(key.key_id, "test-ml-kem-768")
        self.assertEqual(key.algorithm, KeyAlgorithm.ML_KEM_768)
        self.assertEqual(key.key_type, KeyType.ML_KEM_KEY)

        info = self.kms.get_key_info("test-ml-kem-768")
        self.assertEqual(info['state'], KeyState.ACTIVE.value)
        print(f"✓ ML-KEM key created successfully")

    def test_create_ml_dsa_key(self):
        """Test creating ML-DSA signature key"""
        key = self.kms.create_key(
            key_id="test-ml-dsa-65",
            key_type=KeyType.ML_DSA_KEY,
            algorithm=KeyAlgorithm.ML_DSA_65,
            rotation_policy=RotationPolicy.HIGH_SECURITY
        )

        self.assertEqual(key.rotation_policy, RotationPolicy.HIGH_SECURITY)

        info = self.kms.get_key_info("test-ml-dsa-65")
        self.assertEqual(info['rotation_policy_days'], 30)
        print(f"✓ ML-DSA key created with HIGH_SECURITY rotation policy")

    def test_get_key_material(self):
        """Test retrieving key material"""
        self.kms.create_key(
            key_id="test-get-key",
            key_type=KeyType.ML_KEM_KEY,
            algorithm=KeyAlgorithm.ML_KEM_512
        )

        key_material = self.kms.get_key("test-get-key")
        self.assertIsNotNone(key_material)
        self.assertIsInstance(key_material, bytes)
        self.assertGreater(len(key_material), 0)

        # Verify usage tracking
        info = self.kms.get_key_info("test-get-key")
        self.assertEqual(info['usage_count'], 1)
        print(f"✓ Key material retrieved, usage tracked")

    def test_get_nonexistent_key(self):
        """Test getting non-existent key returns None"""
        key_material = self.kms.get_key("nonexistent-key")
        self.assertIsNone(key_material)
        print(f"✓ Non-existent key correctly returns None")

    def test_key_rotation(self):
        """Test manual key rotation"""
        self.kms.create_key(
            key_id="test-rotate",
            key_type=KeyType.ML_KEM_KEY,
            algorithm=KeyAlgorithm.ML_KEM_768
        )

        info_before = self.kms.get_key_info("test-rotate")
        old_version = info_before['current_version']

        success = self.kms.rotate_key("test-rotate")
        self.assertTrue(success)

        info_after = self.kms.get_key_info("test-rotate")
        new_version = info_after['current_version']

        self.assertNotEqual(old_version, new_version)
        self.assertEqual(info_after['version_count'], 2)
        print(f"✓ Key rotation successful: {old_version} -> {new_version}")

    def test_rotation_preserves_old_versions(self):
        """Test old versions are preserved after rotation"""
        self.kms.create_key(
            key_id="test-versions",
            key_type=KeyType.ML_KEM_KEY,
            algorithm=KeyAlgorithm.ML_KEM_512
        )

        # Rotate multiple times
        self.kms.rotate_key("test-versions")
        self.kms.rotate_key("test-versions")

        info = self.kms.get_key_info("test-versions")
        self.assertEqual(info['version_count'], 3)
        print(f"✓ Version history preserved: {info['version_count']} versions")

    def test_auto_rotation_detection(self):
        """Test detection of keys needing rotation"""
        # Create key with very short rotation policy
        key = self.kms.create_key(
            key_id="test-auto",
            key_type=KeyType.ML_KEM_KEY,
            algorithm=KeyAlgorithm.ML_KEM_512,
            rotation_policy=RotationPolicy.NIST_RECOMMENDED
        )

        # Manually set last_rotated to simulate being overdue
        key.last_rotated = time.time() - (100 * 86400)  # 100 days ago

        overdue = self.kms.check_rotation_required()
        self.assertIn("test-auto", overdue)
        print(f"✓ Overdue rotation detected")

    def test_key_revocation(self):
        """Test key revocation for compromised keys"""
        self.kms.create_key(
            key_id="test-revoke",
            key_type=KeyType.ML_DSA_KEY,
            algorithm=KeyAlgorithm.ML_DSA_65
        )

        success = self.kms.revoke_key("test-revoke", reason="suspected compromise")
        self.assertTrue(success)

        info = self.kms.get_key_info("test-revoke")
        self.assertTrue(info['compromised'])
        self.assertEqual(info['state'], KeyState.COMPROMISED.value)

        # Revoked key should not be retrievable
        key_material = self.kms.get_key("test-revoke")
        self.assertIsNone(key_material)
        print(f"✓ Key revocation working, revoked key inaccessible")

    def test_compliance_report(self):
        """Test NIST compliance report generation"""
        # Create some keys
        self.kms.create_key("key1", KeyType.ML_KEM_KEY, KeyAlgorithm.ML_KEM_768)
        self.kms.create_key("key2", KeyType.ML_DSA_KEY, KeyAlgorithm.ML_DSA_65)

        report = self.kms.get_compliance_report()

        self.assertIn('summary', report)
        self.assertIn('rotation_compliance', report)
        self.assertEqual(report['summary']['total_keys'], 2)
        self.assertEqual(report['summary']['compromised_keys'], 0)
        self.assertIn('nist_compliant', report)

        print(f"✓ Compliance report generated: {report['summary']['total_keys']} keys")
        print(f"  NIST compliant: {report['nist_compliant']}")

    def test_audit_logging(self):
        """Test audit logging of key operations"""
        self.kms.create_key("audit-test", KeyType.ML_KEM_KEY, KeyAlgorithm.ML_KEM_512)
        self.kms.get_key("audit-test")
        self.kms.rotate_key("audit-test")

        report = self.kms.get_compliance_report()
        self.assertGreater(report['summary']['audit_entries'], 0)
        print(f"✓ Audit logging working: {report['summary']['audit_entries']} entries")

    def test_audit_export(self):
        """Test audit log export"""
        self.kms.create_key("export-test", KeyType.ML_KEM_KEY, KeyAlgorithm.ML_KEM_512)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name

        try:
            success = self.kms.export_audit_log(filepath)
            self.assertTrue(success)
            self.assertTrue(os.path.exists(filepath))
            self.assertGreater(os.path.getsize(filepath), 0)
            print(f"✓ Audit log exported successfully")
        finally:
            if os.path.exists(filepath):
                os.unlink(filepath)

    def test_list_keys(self):
        """Test listing all managed keys"""
        self.kms.create_key("key-a", KeyType.ML_KEM_KEY, KeyAlgorithm.ML_KEM_512)
        self.kms.create_key("key-b", KeyType.ML_DSA_KEY, KeyAlgorithm.ML_DSA_65)

        keys = self.kms.list_keys()
        self.assertIn("key-a", keys)
        self.assertIn("key-b", keys)
        self.assertEqual(len(keys), 2)
        print(f"✓ Key listing working: {len(keys)} keys")

    def test_key_destruction(self):
        """Test secure key destruction"""
        self.kms.create_key("destroy-me", KeyType.ML_KEM_KEY, KeyAlgorithm.ML_KEM_512)
        self.assertIn("destroy-me", self.kms.list_keys())

        success = self.kms.destroy_key("destroy-me")
        self.assertTrue(success)
        self.assertNotIn("destroy-me", self.kms.list_keys())

        info = self.kms.get_key_info("destroy-me")
        self.assertIsNone(info)
        print(f"✓ Key destruction working correctly")

    def test_duplicate_key_rejected(self):
        """Test duplicate key IDs are rejected"""
        self.kms.create_key("duplicate-test", KeyType.ML_KEM_KEY, KeyAlgorithm.ML_KEM_512)

        with self.assertRaises(ValueError):
            self.kms.create_key("duplicate-test", KeyType.ML_KEM_KEY, KeyAlgorithm.ML_KEM_512)

        print(f"✓ Duplicate key IDs correctly rejected")

    def test_all_algorithm_support(self):
        """Test all NIST PQC algorithms are supported"""
        algorithms = [
            (KeyAlgorithm.ML_KEM_512, KeyType.ML_KEM_KEY),
            (KeyAlgorithm.ML_KEM_768, KeyType.ML_KEM_KEY),
            (KeyAlgorithm.ML_KEM_1024, KeyType.ML_KEM_KEY),
            (KeyAlgorithm.ML_DSA_44, KeyType.ML_DSA_KEY),
            (KeyAlgorithm.ML_DSA_65, KeyType.ML_DSA_KEY),
            (KeyAlgorithm.ML_DSA_87, KeyType.ML_DSA_KEY),
            (KeyAlgorithm.SLH_DSA_128F, KeyType.SLH_DSA_KEY),
        ]

        for i, (alg, key_type) in enumerate(algorithms):
            key_id = f"alg-test-{i}"
            self.kms.create_key(key_id, key_type, alg)
            key_material = self.kms.get_key(key_id)
            self.assertIsNotNone(key_material)

        print(f"✓ All {len(algorithms)} NIST PQC algorithms supported")


def run_all_tests():
    """Run complete test suite"""
    print("\n" + "="*60)
    print("QuantumCrypt-AI: Post-Quantum KMS - Test Suite")
    print("="*60 + "\n")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestKeyWrapping))
    suite.addTests(loader.loadTestsFromTestCase(TestPostQuantumKMS))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "="*60)
    print(f"Tests Passed: {result.testsRun - len(result.failures) - len(result.errors)} / {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*60)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
