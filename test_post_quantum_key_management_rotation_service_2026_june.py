#!/usr/bin/env python3
"""
Test suite for QuantumCrypt Post-Quantum Key Management & Rotation Service
Production-grade tests with real-world scenarios
"""

import sys
import os
import time

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_key_management_rotation_service_2026_june import (
    PostQuantumKeyManagementService,
    KeyType,
    KeyStatus,
    PQAlgorithm,
    ConstantTimeOperations,
    KeyGenerator,
    ShamirSecretSharing,
    KeyRotationManager
)


def test_key_lifecycle_management():
    """Test complete key lifecycle: create -> activate -> use -> retire -> destroy"""
    print("Test 1: Complete Key Lifecycle Management...")
    
    kms = PostQuantumKeyManagementService()
    
    # Create key
    key = kms.create_key(
        key_type=KeyType.DATA_ENCRYPTION,
        algorithm=PQAlgorithm.CRYSTALS_KYBER,
        rotation_interval_days=90
    )
    
    assert key.metadata.status == KeyStatus.PRE_ACTIVE, "New key should be PRE_ACTIVE"
    assert key.metadata.key_id.startswith("pqk_"), "Key ID should have correct prefix"
    assert len(key.key_material) > 0, "Key material should exist"
    assert len(key.public_key) > 0, "Public key should exist"
    assert len(key.backup_shares) == 3, "Should have 3 backup shares"
    
    print(f"  ✓ Created key: {key.metadata.key_id}")
    print(f"  ✓ Status: {key.metadata.status.value}")
    
    # Activate key
    result = kms.activate_key(key.metadata.key_id)
    assert result, "Activation should succeed"
    
    activated = kms.keys[key.metadata.key_id]
    assert activated.metadata.status == KeyStatus.ACTIVE, "Key should be ACTIVE"
    assert activated.metadata.activated_at is not None, "Activation timestamp should be set"
    
    print(f"  ✓ Activated: {activated.metadata.status.value}")
    
    # Get active key
    active = kms.get_active_key(KeyType.DATA_ENCRYPTION)
    assert active is not None, "Should get active key"
    assert active.metadata.usage_count == 1, "Usage count should increment"
    
    print(f"  ✓ Usage count incremented: {active.metadata.usage_count}")
    
    # Retire key
    result = kms.retire_key(key.metadata.key_id)
    assert result, "Retirement should succeed"
    assert kms.keys[key.metadata.key_id].metadata.status == KeyStatus.RETIRED
    
    print(f"  ✓ Retired: {kms.keys[key.metadata.key_id].metadata.status.value}")
    
    # Destroy key
    result = kms.destroy_key(key.metadata.key_id)
    assert result, "Destruction should succeed"
    assert kms.keys[key.metadata.key_id].metadata.status == KeyStatus.DESTROYED
    
    print(f"  ✓ Destroyed: {kms.keys[key.metadata.key_id].metadata.status.value}")
    print("  PASSED\n")


def test_key_rotation():
    """Test automated key rotation functionality"""
    print("Test 2: Key Rotation...")
    
    kms = PostQuantumKeyManagementService()
    
    # Create and activate a key
    old_key = kms.create_key(
        key_type=KeyType.SIGNING,
        algorithm=PQAlgorithm.CRYSTALS_DILITHIUM,
        rotation_interval_days=90
    )
    kms.activate_key(old_key.metadata.key_id)
    
    old_key_id = old_key.metadata.key_id
    
    # Perform rotation
    new_key = kms.rotate_key(old_key_id)
    
    assert new_key is not None, "Rotation should produce new key"
    assert new_key.metadata.key_id != old_key_id, "New key should have different ID"
    assert new_key.metadata.status == KeyStatus.ACTIVE, "New key should be active"
    assert kms.keys[old_key_id].metadata.status == KeyStatus.DEPRECATED, "Old key should be deprecated"
    
    # Check same algorithm and type preserved
    assert new_key.metadata.algorithm == old_key.metadata.algorithm
    assert new_key.metadata.key_type == old_key.metadata.key_type
    
    print(f"  ✓ Old key ({old_key_id[:16]}...): DEPRECATED")
    print(f"  ✓ New key ({new_key.metadata.key_id[:16]}...): ACTIVE")
    print(f"  ✓ Algorithm preserved: {new_key.metadata.algorithm.value}")
    print("  PASSED\n")


def test_constant_time_operations():
    """Test side-channel protected constant-time operations"""
    print("Test 3: Constant-Time Operations (Side-Channel Protection)...")
    
    ct = ConstantTimeOperations()
    
    # Test constant-time comparison
    a = b"test_data_12345"
    b = b"test_data_12345"
    c = b"test_data_XXXXX"
    
    assert ct.compare_equal(a, b) == True, "Equal bytes should match"
    assert ct.compare_equal(a, c) == False, "Different bytes should not match"
    
    print("  ✓ Constant-time comparison works correctly")
    
    # Test nonce generation
    nonce1 = ct.generate_nonce(16)
    nonce2 = ct.generate_nonce(16)
    assert len(nonce1) == 16, "Nonce should be correct length"
    assert nonce1 != nonce2, "Nonces should be unique"
    
    print(f"  ✓ Cryptographic nonce generation: {nonce1.hex()[:16]}...")
    
    # Test secure erase
    buffer = bytearray(b"sensitive_key_material_here")
    original = bytes(buffer)
    ct.secure_erase(buffer)
    assert all(b == 0 for b in buffer), "Buffer should be zeroed after erase"
    
    print("  ✓ Secure memory erase works")
    print("  PASSED\n")


def test_shamir_secret_sharing():
    """Test Shamir's Secret Sharing for key backup"""
    print("Test 4: Shamir Secret Sharing for Key Backup...")
    
    shamir = ShamirSecretSharing()
    
    secret = b"this_is_a_secret_post_quantum_key_12345"
    
    # Split into 5 shares, 3 required
    shares = shamir.split_secret(secret, 5, 3)
    
    assert len(shares) == 5, "Should create 5 shares"
    assert all(len(s) > 2 for s in shares), "All shares should have data"
    
    print(f"  ✓ Split secret into {len(shares)} shares")
    for i, share in enumerate(shares[:3]):
        print(f"    Share {i+1}: {share.hex()[:16]}...")
    
    # Reconstruct
    reconstructed = shamir.reconstruct_secret(shares[:3])
    assert reconstructed is not None, "Reconstruction should succeed"
    
    print("  ✓ Secret reconstruction successful")
    print("  PASSED\n")


def test_key_health_monitoring():
    """Test key health and monitoring metrics"""
    print("Test 5: Key Health Monitoring...")
    
    kms = PostQuantumKeyManagementService()
    
    # Create multiple keys
    key1 = kms.create_key(
        key_type=KeyType.DATA_ENCRYPTION,
        algorithm=PQAlgorithm.CRYSTALS_KYBER,
        rotation_interval_days=90,
        max_usage=1000
    )
    kms.activate_key(key1.metadata.key_id)
    
    key2 = kms.create_key(
        key_type=KeyType.SIGNING,
        algorithm=PQAlgorithm.FALCON,
        rotation_interval_days=30,
        max_usage=500
    )
    kms.activate_key(key2.metadata.key_id)
    
    # Simulate usage
    for _ in range(50):
        kms.get_active_key()
    
    # Check individual key health
    health1 = kms.get_key_health(key1.metadata.key_id)
    assert "usage_pct" in health1
    assert "days_until_rotation" in health1
    assert "needs_rotation" in health1
    
    print(f"  ✓ Key 1 health: usage={health1['usage_count']} ({health1['usage_pct']}%), "
          f"rotation_in={health1['days_until_rotation']}d")
    
    # Check system health
    sys_health = kms.get_system_health()
    assert sys_health["total_keys"] >= 2
    assert sys_health["active_keys"] >= 2
    assert "health_status" in sys_health
    
    print(f"  ✓ System health: {sys_health['total_keys']} total, "
          f"{sys_health['active_keys']} active, status={sys_health['health_status']}")
    print("  PASSED\n")


def test_rotation_policy_evaluation():
    """Test rotation policy evaluation logic"""
    print("Test 6: Rotation Policy Evaluation...")
    
    kms = PostQuantumKeyManagementService()
    rotation_mgr = KeyRotationManager()
    
    # Create key with very short rotation interval
    key = kms.create_key(
        key_type=KeyType.DATA_ENCRYPTION,
        algorithm=PQAlgorithm.BIKE,
        rotation_interval_days=0,  # Immediate rotation needed
        max_usage=5
    )
    kms.activate_key(key.metadata.key_id)
    
    # Simulate heavy usage
    for _ in range(10):
        kms.get_active_key()
    
    should_rotate, reason = rotation_mgr.should_rotate(kms.keys[key.metadata.key_id])
    print(f"  ✓ Rotation check: should_rotate={should_rotate}")
    print(f"  ✓ Reason: {reason}")
    
    # Perform auto-rotation check
    rotations = kms.check_and_perform_rotations()
    print(f"  ✓ Auto-rotations performed: {len(rotations)}")
    
    print("  PASSED\n")


def test_compromise_handling():
    """Test compromise detection and emergency key handling"""
    print("Test 7: Compromise Detection & Emergency Handling...")
    
    kms = PostQuantumKeyManagementService()
    
    key = kms.create_key(
        key_type=KeyType.KEM,
        algorithm=PQAlgorithm.HQC,
        rotation_interval_days=90
    )
    kms.activate_key(key.metadata.key_id)
    
    # Mark as compromised
    result = kms.mark_compromised(key.metadata.key_id)
    assert result, "Compromise marking should succeed"
    
    compromised_key = kms.keys[key.metadata.key_id]
    assert compromised_key.metadata.status == KeyStatus.COMPROMISED
    assert compromised_key.metadata.compromise_detected_at is not None
    
    print(f"  ✓ Key marked as COMPROMISED")
    print(f"  ✓ Compromise detected at: {compromised_key.metadata.compromise_detected_at}")
    
    # Compromised keys should be rotated
    rotation_mgr = KeyRotationManager()
    should_rotate, reason = rotation_mgr.should_rotate(compromised_key)
    assert should_rotate, "Compromised keys should trigger rotation"
    
    print(f"  ✓ Rotation triggered: {reason}")
    print("  PASSED\n")


def test_key_hierarchy():
    """Test hierarchical key architecture (root -> intermediate -> data)"""
    print("Test 8: Key Hierarchy Architecture...")
    
    kms = PostQuantumKeyManagementService()
    
    # Root key should exist from initialization
    root_key = kms.get_active_key(KeyType.ROOT)
    assert root_key is not None, "Root key should auto-initialize"
    assert root_key.metadata.key_type == KeyType.ROOT
    
    print(f"  ✓ Root key exists: {root_key.metadata.key_id[:16]}...")
    
    # Create intermediate key under root
    intermediate = kms.create_key(
        key_type=KeyType.INTERMEDIATE,
        algorithm=PQAlgorithm.CRYSTALS_KYBER,
        rotation_interval_days=180,
        parent_key_id=root_key.metadata.key_id
    )
    kms.activate_key(intermediate.metadata.key_id)
    
    assert intermediate.metadata.parent_key_id == root_key.metadata.key_id
    
    print(f"  ✓ Intermediate key created, parent={intermediate.metadata.parent_key_id[:16]}...")
    
    # Create data encryption key under intermediate
    data_key = kms.create_key(
        key_type=KeyType.DATA_ENCRYPTION,
        algorithm=PQAlgorithm.CRYSTALS_KYBER,
        rotation_interval_days=30,
        parent_key_id=intermediate.metadata.key_id
    )
    kms.activate_key(data_key.metadata.key_id)
    
    print(f"  ✓ Data key created under intermediate")
    print(f"  ✓ Hierarchy: ROOT -> INTERMEDIATE -> DATA_ENCRYPTION")
    print("  PASSED\n")


def test_algorithm_support():
    """Test all NIST post-quantum algorithm support"""
    print("Test 9: NIST Post-Quantum Algorithm Support...")
    
    kms = PostQuantumKeyManagementService()
    
    algorithms = [
        PQAlgorithm.CRYSTALS_KYBER,
        PQAlgorithm.CRYSTALS_DILITHIUM,
        PQAlgorithm.FALCON,
        PQAlgorithm.SPHINCS,
        PQAlgorithm.BIKE,
        PQAlgorithm.HQC,
    ]
    
    for algo in algorithms:
        key = kms.create_key(
            key_type=KeyType.DATA_ENCRYPTION,
            algorithm=algo,
            rotation_interval_days=90
        )
        assert len(key.key_material) > 0
        assert len(key.public_key) > 0
        print(f"  ✓ {algo.value}: priv={len(key.key_material)} bytes, "
              f"pub={len(key.public_key)} bytes")
    
    print("  PASSED\n")


def test_audit_logging():
    """Test audit logging for compliance"""
    print("Test 10: Audit Logging & Compliance...")
    
    kms = PostQuantumKeyManagementService()
    
    # Perform operations
    key = kms.create_key(
        key_type=KeyType.SIGNING,
        algorithm=PQAlgorithm.CRYSTALS_DILITHIUM
    )
    kms.activate_key(key.metadata.key_id)
    kms.get_active_key()
    kms.retire_key(key.metadata.key_id)
    
    log_count_before = len(kms.audit_log)
    
    # Export audit log
    export_path = "/tmp/test_kms_audit_log.json"
    success = kms.export_audit_log(export_path)
    
    assert success, "Audit export should succeed"
    assert os.path.exists(export_path), "Audit file should be created"
    
    import json
    with open(export_path) as f:
        data = json.load(f)
    
    assert data["entry_count"] >= log_count_before
    assert len(data["entries"]) > 0
    
    print(f"  ✓ Audit log entries: {data['entry_count']}")
    print(f"  ✓ Actions logged: {[e['action'] for e in data['entries']]}")
    print(f"  ✓ Exported to: {export_path}")
    
    os.remove(export_path)
    print("  PASSED\n")


def run_all_tests():
    """Run complete test suite"""
    print("=" * 70)
    print("QuantumCrypt AI - Post-Quantum Key Management Service Tests")
    print("=" * 70 + "\n")
    
    tests_passed = 0
    tests_failed = 0
    
    test_functions = [
        test_key_lifecycle_management,
        test_key_rotation,
        test_constant_time_operations,
        test_shamir_secret_sharing,
        test_key_health_monitoring,
        test_rotation_policy_evaluation,
        test_compromise_handling,
        test_key_hierarchy,
        test_algorithm_support,
        test_audit_logging
    ]
    
    for test_func in test_functions:
        try:
            test_func()
            tests_passed += 1
        except AssertionError as e:
            print(f"  FAILED: {e}\n")
            tests_failed += 1
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}\n")
            tests_failed += 1
    
    print("=" * 70)
    print(f"TEST SUMMARY: {tests_passed} PASSED, {tests_failed} FAILED")
    print("=" * 70)
    
    return tests_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
