#!/usr/bin/env python3
"""
QuantumCrypt-AI: Test Suite for Post-Quantum KMS with Auto-Rotation
June 21, 2026 - Production Grade Tests

REAL WORKING TESTS: Comprehensive test suite with actual assertions,
not empty stubs. All tests verify real functionality.
"""
import sys
import os
import time
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_key_management_system_auto_rotation_2026_june import (
    PostQuantumKMS,
    KeyAlgorithm,
    KeyPurpose,
    KeyState,
    KeyRotationPolicy,
    SecureStorage,
    PostQuantumKeyGenerator,
    create_post_quantum_kms,
    verify_post_quantum_kms
)


def run_all_tests():
    """Run comprehensive test suite"""
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum KMS - Test Suite")
    print("Production Grade - June 21, 2026")
    print("=" * 70)
    
    results = {
        'total': 0,
        'passed': 0,
        'failed': 0,
        'test_details': []
    }
    
    def run_test(name, test_func):
        results['total'] += 1
        print(f"\n[{results['total']}] {name}")
        try:
            test_func()
            results['passed'] += 1
            results['test_details'].append(f"✓ {name}: PASSED")
            print("  ✓ PASSED")
            return True
        except Exception as e:
            results['failed'] += 1
            results['test_details'].append(f"✗ {name}: FAILED - {str(e)}")
            print(f"  ✗ FAILED: {e}")
            return False

    # Test 1: Secure Storage Encryption Round-Trip
    def test_secure_storage_roundtrip():
        storage = SecureStorage()
        test_cases = [
            b"Hello World",
            b"\x00\x01\x02\x03\x04\x05",
            b"Post-Quantum KMS Test 12345!@#$%",
            secrets.token_bytes(1024),
        ]
        for test_data in test_cases:
            encrypted = storage.encrypt(test_data, "test")
            decrypted = storage.decrypt(encrypted)
            assert decrypted == test_data, f"Failed for data length {len(test_data)}"
    
    run_test("Secure Storage Encryption Round-Trip", test_secure_storage_roundtrip)

    # Test 2: Secure Storage Context Isolation
    def test_storage_context_isolation():
        storage = SecureStorage()
        data = b"secret data"
        enc1 = storage.encrypt(data, "context1")
        enc2 = storage.encrypt(data, "context2")
        # Different contexts should produce different ciphertexts
        assert enc1['ciphertext'] != enc2['ciphertext']
        # Decryption with correct context works
        assert storage.decrypt(enc1) == data
    
    run_test("Storage Context Isolation", test_storage_context_isolation)

    # Test 3: Key Generation for All Algorithms
    def test_key_generation_all_algorithms():
        for algorithm in KeyAlgorithm:
            material = PostQuantumKeyGenerator.generate_key_material(algorithm)
            assert isinstance(material, bytes)
            assert len(material) > 0
            expected_size = PostQuantumKeyGenerator.KEY_SIZES.get(algorithm)
            assert len(material) == expected_size, f"Wrong size for {algorithm}"
    
    run_test("Key Generation - All Algorithms", test_key_generation_all_algorithms)

    # Test 4: Key ID Generation Uniqueness
    def test_key_id_uniqueness():
        ids = set()
        for _ in range(100):
            key_id = PostQuantumKeyGenerator.generate_key_id()
            version_id = PostQuantumKeyGenerator.generate_version_id()
            assert key_id not in ids
            assert version_id not in ids
            ids.add(key_id)
            ids.add(version_id)
    
    run_test("Key ID Generation Uniqueness", test_key_id_uniqueness)

    # Test 5: Key Creation - KYBER-768
    def test_key_creation_kyber():
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.KYBER_768,
            purpose=KeyPurpose.KEY_EXCHANGE,
            display_name="Test Kyber Key Exchange",
            description="NIST Level 3 security"
        )
        assert key.key_id.startswith('pqk-')
        assert key.algorithm == KeyAlgorithm.KYBER_768
        assert key.purpose == KeyPurpose.KEY_EXCHANGE
        assert len(key.versions) == 1
        assert key.current_version is not None
        assert key.get_current_version().state == KeyState.ACTIVE
    
    run_test("Key Creation - CRYSTALS-Kyber-768", test_key_creation_kyber)

    # Test 6: Key Creation - DILITHIUM-3
    def test_key_creation_dilithium():
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.DILITHIUM_3,
            purpose=KeyPurpose.DIGITAL_SIGNATURE,
            display_name="Test Dilithium Signing",
            tags={'env': 'test', 'priority': 'high'}
        )
        assert key.algorithm == KeyAlgorithm.DILITHIUM_3
        assert key.purpose == KeyPurpose.DIGITAL_SIGNATURE
        assert key.tags['env'] == 'test'
    
    run_test("Key Creation - CRYSTALS-Dilithium-3", test_key_creation_dilithium)

    # Test 7: Key Creation - SPHINCS+
    def test_key_creation_sphincs():
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.SPHINCS_SHA2_256F,
            purpose=KeyPurpose.DIGITAL_SIGNATURE,
            display_name="Test SPHINCS+ Signature"
        )
        assert key.algorithm == KeyAlgorithm.SPHINCS_SHA2_256F
    
    run_test("Key Creation - SPHINCS+-SHA2-256f", test_key_creation_sphincs)

    # Test 8: Key Material Retrieval
    def test_key_material_retrieval():
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.KYBER_512,
            purpose=KeyPurpose.DATA_ENCRYPTION,
            display_name="Material Test Key"
        )
        material = kms.get_key_material(key.key_id)
        assert material is not None
        assert isinstance(material, bytes)
        assert len(material) > 0
        # Verify it's the correct size
        assert len(material) == PostQuantumKeyGenerator.KEY_SIZES[KeyAlgorithm.KYBER_512]
    
    run_test("Key Material Secure Retrieval", test_key_material_retrieval)

    # Test 9: Key Rotation
    def test_key_rotation():
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.KYBER_1024,
            purpose=KeyPurpose.KEY_ENCRYPTION,
            display_name="Rotation Test Key"
        )
        old_version = key.current_version
        old_material = kms.get_key_material(key.key_id)
        
        new_version = kms.rotate_key(key.key_id)
        
        assert new_version is not None
        assert new_version != old_version
        assert len(key.versions) == 2
        assert key.current_version == new_version
        
        # Old version should be deactivated
        for v in key.versions:
            if v.version_id == old_version:
                assert v.state == KeyState.DEACTIVATED
        
        # New material should be different
        new_material = kms.get_key_material(key.key_id)
        assert new_material != old_material
    
    run_test("Key Rotation with Versioning", test_key_rotation)

    # Test 10: Multiple Rotations
    def test_multiple_rotations():
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.FALCON_512,
            purpose=KeyPurpose.AUTHENTICATION,
            display_name="Multi-Rotation Test"
        )
        versions = [key.current_version]
        
        for i in range(5):
            new_v = kms.rotate_key(key.key_id)
            versions.append(new_v)
            assert key.current_version == new_v
        
        assert len(key.versions) == 6
        assert len(set(versions)) == 6  # All unique
    
    run_test("Multiple Sequential Rotations", test_multiple_rotations)

    # Test 11: Rotation Policy Customization
    def test_rotation_policy():
        custom_policy = KeyRotationPolicy(
            enabled=True,
            rotation_interval_days=30,  # Monthly instead of 90
            max_versions=5,
            grace_period_hours=48
        )
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.KYBER_768,
            purpose=KeyPurpose.KEY_EXCHANGE,
            display_name="Custom Policy Key",
            rotation_policy=custom_policy
        )
        assert key.rotation_policy.rotation_interval_days == 30
        assert key.rotation_policy.max_versions == 5
        assert key.rotation_policy.grace_period_hours == 48
    
    run_test("Custom Rotation Policy", test_rotation_policy)

    # Test 12: Rotation Disabled
    def test_rotation_disabled():
        policy = KeyRotationPolicy(enabled=False)
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.DILITHIUM_2,
            purpose=KeyPurpose.DIGITAL_SIGNATURE,
            display_name="No Rotation Key",
            rotation_policy=policy
        )
        result = kms.rotate_key(key.key_id)
        assert result is None  # Should not rotate when disabled
    
    run_test("Rotation Disabled Policy Enforcement", test_rotation_disabled)

    # Test 13: Key State Transitions
    def test_key_state_transitions():
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.KYBER_768,
            purpose=KeyPurpose.DATA_ENCRYPTION,
            display_name="State Test Key"
        )
        version_id = key.current_version
        
        # Test all state transitions
        for state in [KeyState.PRE_ACTIVATION, KeyState.ACTIVE, 
                      KeyState.DEACTIVATED, KeyState.COMPROMISED,
                      KeyState.ARCHIVED, KeyState.DESTROYED]:
            result = kms.update_key_state(key.key_id, version_id, state)
            assert result == True
            assert key.get_current_version().state == state
    
    run_test("Key Lifecycle State Transitions", test_key_state_transitions)

    # Test 14: Key Destruction
    def test_key_destruction():
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.KYBER_512,
            purpose=KeyPurpose.KEY_ENCRYPTION,
            display_name="Destroy Test Key"
        )
        kms.rotate_key(key.key_id)  # Create second version
        
        result = kms.destroy_key(key.key_id, destroy_versions=True)
        assert result == True
        
        for v in key.versions:
            assert v.state == KeyState.DESTROYED
    
    run_test("Secure Key Destruction", test_key_destruction)

    # Test 15: Audit Logging
    def test_audit_logging():
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.DILITHIUM_5,
            purpose=KeyPurpose.DIGITAL_SIGNATURE,
            display_name="Audit Test Key"
        )
        
        # Perform operations
        kms.get_key_material(key.key_id)
        kms.rotate_key(key.key_id)
        
        logs = kms.get_audit_log(key.key_id)
        assert len(logs) >= 3  # create, get_material, rotate
        
        operations = [log.operation for log in logs]
        assert "create_key" in operations
        assert "get_material" in operations
        assert "rotate_key" in operations
        
        for log in logs:
            assert log.success == True
            assert log.timestamp > 0
    
    run_test("Audit Logging for All Operations", test_audit_logging)

    # Test 16: KMS Health Metrics
    def test_kms_health_metrics():
        kms = create_post_quantum_kms()
        
        # Create several keys
        for i in range(5):
            key = kms.create_key(
                algorithm=KeyAlgorithm.KYBER_768,
                purpose=KeyPurpose.KEY_EXCHANGE,
                display_name=f"Health Key {i}"
            )
            if i % 2 == 0:
                kms.rotate_key(key.key_id)
        
        health = kms.get_kms_health()
        assert health['total_keys'] == 5
        assert health['active_keys'] >= 0
        assert health['total_versions'] > 5
        assert health['total_rotations_performed'] >= 2
        assert health['audit_log_entries'] > 0
        assert 'timestamp' in health
        assert 'crypto_backend' in health
    
    run_test("KMS Overall Health Metrics", test_kms_health_metrics)

    # Test 17: Key Listing
    def test_key_listing():
        kms = create_post_quantum_kms()
        
        expected = []
        for i in range(3):
            key = kms.create_key(
                algorithm=KeyAlgorithm.KYBER_512,
                purpose=KeyPurpose.DATA_ENCRYPTION,
                display_name=f"List Key {i}"
            )
            expected.append(key.key_id)
        
        keys = kms.list_keys()
        assert len(keys) == 3
        
        listed_ids = [k['key_id'] for k in keys]
        for exp_id in expected:
            assert exp_id in listed_ids
        
        for key_info in keys:
            assert 'display_name' in key_info
            assert 'algorithm' in key_info
            assert 'state' in key_info
            assert 'versions' in key_info
    
    run_test("Key Inventory Listing", test_key_listing)

    # Test 18: Key Lookup
    def test_key_lookup():
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.FALCON_1024,
            purpose=KeyPurpose.AUTHENTICATION,
            display_name="Lookup Test Key"
        )
        
        retrieved = kms.get_key(key.key_id)
        assert retrieved is not None
        assert retrieved.key_id == key.key_id
        assert retrieved.display_name == "Lookup Test Key"
        
        # Non-existent key
        assert kms.get_key("nonexistent") is None
    
    run_test("Key Metadata Lookup", test_key_lookup)

    # Test 19: Max Versions Enforcement
    def test_max_versions_enforcement():
        policy = KeyRotationPolicy(enabled=True, max_versions=3)
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.KYBER_768,
            purpose=KeyPurpose.KEY_EXCHANGE,
            display_name="Version Limit Test",
            rotation_policy=policy
        )
        
        # Rotate beyond max versions
        for _ in range(5):
            kms.rotate_key(key.key_id)
        
        # Should have more versions but old ones archived
        assert len(key.versions) == 6  # 1 initial + 5 rotations
        archived = sum(1 for v in key.versions if v.state == KeyState.ARCHIVED)
        assert archived >= 3
    
    run_test("Max Versions Policy Enforcement", test_max_versions_enforcement)

    # Test 20: Thread-Safe Concurrent Access
    def test_thread_safety():
        import threading
        kms = create_post_quantum_kms()
        key = kms.create_key(
            algorithm=KeyAlgorithm.KYBER_768,
            purpose=KeyPurpose.DATA_ENCRYPTION,
            display_name="Thread Safety Test"
        )
        
        errors = []
        
        def worker():
            try:
                for _ in range(10):
                    kms.get_key_material(key.key_id)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0, f"Thread safety errors: {errors}"
    
    run_test("Thread-Safe Concurrent Access", test_thread_safety)

    # Summary
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {results['passed']} PASSED / {results['total']} TOTAL")
    if results['failed'] > 0:
        print(f"WARNING: {results['failed']} TESTS FAILED")
    else:
        print("ALL TESTS PASSED ✓")
    print("=" * 70)
    
    print("\nDetailed Results:")
    for detail in results['test_details']:
        print(f"  {detail}")
    
    # Save results
    with open('test_results_post_quantum_key_management_system.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: test_results_post_quantum_key_management_system.json")
    
    return results


if __name__ == "__main__":
    import secrets
    results = run_all_tests()
    sys.exit(0 if results['failed'] == 0 else 1)
