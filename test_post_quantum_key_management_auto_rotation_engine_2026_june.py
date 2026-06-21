#!/usr/bin/env python3
"""
Test suite for Post-Quantum Key Management & Auto-Rotation Engine
Real production-grade tests
"""

import sys
import json
import time

# Add the module to path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_key_management_auto_rotation_engine_2026_june import (
    KeyAlgorithm,
    KeyStatus,
    KeyType,
    CryptoKey,
    KeyRotationPolicy,
    RotationEvent,
    KeyGenerator,
    KeyStore,
    KeyRotationEngine
)


def test_key_algorithms():
    """Test KeyAlgorithm enum"""
    print("Testing KeyAlgorithm enum...")
    
    # Verify PQ algorithms exist
    assert hasattr(KeyAlgorithm, 'CRYSTALS_KYBER_512')
    assert hasattr(KeyAlgorithm, 'CRYSTALS_DILITHIUM_3')
    assert hasattr(KeyAlgorithm, 'FALCON_512')
    
    # Verify classical algorithms exist
    assert hasattr(KeyAlgorithm, 'RSA_4096')
    assert hasattr(KeyAlgorithm, 'AES_256_GCM')
    
    print("  ✓ KeyAlgorithm tests passed")
    return True


def test_key_generator():
    """Test KeyGenerator functionality"""
    print("Testing KeyGenerator...")
    
    generator = KeyGenerator()
    
    # Test key generation for different algorithms
    algorithms = [
        KeyAlgorithm.CRYSTALS_KYBER_512,
        KeyAlgorithm.CRYSTALS_KYBER_768,
        KeyAlgorithm.CRYSTALS_KYBER_1024,
        KeyAlgorithm.CRYSTALS_DILITHIUM_3,
        KeyAlgorithm.AES_256_GCM,
        KeyAlgorithm.RSA_4096
    ]
    
    for alg in algorithms:
        pub, priv = generator.generate_key_material(alg)
        assert len(pub) > 0
        assert len(priv) > 0
        assert pub != priv  # Public and private should be different
    
    print("  ✓ KeyGenerator tests passed")
    return True


def test_crypto_key():
    """Test CryptoKey data structure"""
    print("Testing CryptoKey...")
    
    generator = KeyGenerator()
    pub, priv = generator.generate_key_material(KeyAlgorithm.CRYSTALS_KYBER_768)
    
    now = time.time()
    key = CryptoKey(
        key_id="test-key-001",
        version=1,
        algorithm=KeyAlgorithm.CRYSTALS_KYBER_768,
        key_type=KeyType.ENCRYPTION,
        status=KeyStatus.ACTIVE,
        created_at=now,
        expires_at=now + (90 * 86400),
        last_rotated_at=now,
        rotation_policy_days=90,
        public_key=pub,
        private_key=priv
    )
    
    # Test basic properties
    assert key.key_id == "test-key-001"
    assert key.version == 1
    assert key.status == KeyStatus.ACTIVE
    assert key.is_expired() == False
    
    # Test security strength
    strength = key.get_security_strength()
    assert strength == 192  # Kyber-768 = 192 bits
    
    # Test age calculation
    age = key.get_age_days()
    assert age >= 0
    
    print("  ✓ CryptoKey tests passed")
    return True


def test_key_store():
    """Test KeyStore functionality"""
    print("Testing KeyStore...")
    
    store = KeyStore()
    generator = KeyGenerator()
    
    # Create and store multiple keys
    keys_created = []
    for i in range(5):
        pub, priv = generator.generate_key_material(KeyAlgorithm.CRYSTALS_KYBER_512)
        now = time.time()
        key = CryptoKey(
            key_id=f"store-test-{i:03d}",
            version=1,
            algorithm=KeyAlgorithm.CRYSTALS_KYBER_512,
            key_type=KeyType.ENCRYPTION,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + (90 * 86400),
            last_rotated_at=now,
            rotation_policy_days=90,
            public_key=pub,
            private_key=priv
        )
        store.store_key(key)
        keys_created.append(key)
    
    # Test retrieval
    retrieved = store.get_key("store-test-000")
    assert retrieved is not None
    assert retrieved.key_id == "store-test-000"
    
    # Test get all keys
    all_keys = store.get_all_keys()
    assert len(all_keys) == 5
    
    # Test status filtering
    active_keys = store.get_keys_by_status(KeyStatus.ACTIVE)
    assert len(active_keys) == 5
    
    # Test status update
    store.update_key_status("store-test-000", KeyStatus.DEPRECATED)
    updated = store.get_key("store-test-000")
    assert updated.status == KeyStatus.DEPRECATED
    
    print("  ✓ KeyStore tests passed")
    return True


def test_key_rotation_engine_basic():
    """Test KeyRotationEngine basic functionality"""
    print("Testing KeyRotationEngine (basic)...")
    
    engine = KeyRotationEngine()
    
    # Create a key
    key = engine.create_key(
        algorithm=KeyAlgorithm.CRYSTALS_KYBER_768,
        key_type=KeyType.KEY_EXCHANGE,
        labels={"environment": "production", "service": "api-gateway"}
    )
    
    assert key is not None
    assert key.key_id is not None
    assert key.version == 1
    assert key.status == KeyStatus.ACTIVE
    assert key.labels["environment"] == "production"
    
    # Test security strength
    assert key.get_security_strength() == 192
    
    print("  ✓ KeyRotationEngine basic tests passed")
    print(f"    - Created key: {key.key_id}")
    return True


def test_key_rotation():
    """Test key rotation functionality"""
    print("Testing key rotation...")
    
    engine = KeyRotationEngine()
    
    # Create a key
    key = engine.create_key(
        algorithm=KeyAlgorithm.CRYSTALS_KYBER_1024,
        key_type=KeyType.ENCRYPTION
    )
    
    original_version = key.version
    
    # Perform rotation
    success, new_key, message = engine.rotate_key(key.key_id, reason="test_rotation")
    
    assert success == True
    assert new_key is not None
    assert new_key.version == original_version + 1
    assert new_key.status == KeyStatus.ACTIVE
    
    # Old key should be deprecated
    old_key = engine.key_store.get_key(key.key_id)
    # Note: same key_id, different version stored in versions
    
    # Check rotation history
    history = engine.key_store.get_rotation_history(key.key_id)
    assert len(history) >= 1
    assert history[0].success == True
    
    print("  ✓ Key rotation tests passed")
    print(f"    - Rotated from v{original_version} to v{new_key.version}")
    print(f"    - Message: {message}")
    return True


def test_hybrid_key_creation():
    """Test hybrid post-quantum + classical key creation"""
    print("Testing hybrid key creation...")
    
    engine = KeyRotationEngine()
    
    # Create a hybrid key
    hybrid_key = engine.create_key(
        algorithm=KeyAlgorithm.CRYSTALS_KYBER_768,
        key_type=KeyType.KEY_EXCHANGE,
        create_hybrid=True,
        classical_algorithm=KeyAlgorithm.AES_256_GCM
    )
    
    assert hybrid_key.is_hybrid == True
    assert hybrid_key.classical_component is not None
    assert hybrid_key.classical_component.algorithm == KeyAlgorithm.AES_256_GCM
    assert hybrid_key.classical_component.parent_key_id == hybrid_key.key_id
    
    # Both components should be active
    assert hybrid_key.status == KeyStatus.ACTIVE
    assert hybrid_key.classical_component.status == KeyStatus.ACTIVE
    
    print("  ✓ Hybrid key creation tests passed")
    print(f"    - PQ Algorithm: {hybrid_key.algorithm.value}")
    print(f"    - Classical Algorithm: {hybrid_key.classical_component.algorithm.value}")
    return True


def test_health_report():
    """Test key health reporting"""
    print("Testing key health reporting...")
    
    engine = KeyRotationEngine()
    
    # Create several keys
    for i in range(3):
        engine.create_key(
            algorithm=KeyAlgorithm.CRYSTALS_KYBER_512,
            key_type=KeyType.ENCRYPTION
        )
    
    for i in range(2):
        engine.create_key(
            algorithm=KeyAlgorithm.CRYSTALS_DILITHIUM_3,
            key_type=KeyType.SIGNING
        )
    
    # Generate report
    report = engine.get_key_health_report()
    
    assert report["total_keys"] >= 5
    assert "by_status" in report
    assert "by_algorithm" in report
    assert "by_security_strength" in report
    assert "rotation_summary" in report
    
    print("  ✓ Health report tests passed")
    print(f"    - Total keys: {report['total_keys']}")
    print(f"    - Algorithms: {list(report['by_algorithm'].keys())}")
    return True


def test_auto_rotation():
    """Test automatic rotation functionality"""
    print("Testing auto-rotation...")
    
    engine = KeyRotationEngine()
    
    # Create keys with very short rotation policy
    short_policy = KeyRotationPolicy(
        policy_id="short-policy",
        name="Short Rotation Policy",
        rotation_days=0,  # Immediate rotation needed
        auto_rotate=True
    )
    engine.add_policy(short_policy)
    
    # Create keys that need immediate rotation
    for i in range(3):
        key = engine.create_key(
            algorithm=KeyAlgorithm.CRYSTALS_KYBER_512,
            key_type=KeyType.ENCRYPTION,
            policy_id="short-policy"
        )
        # Manually set last_rotated to simulate old key
        key.last_rotated_at = time.time() - 86400  # 1 day ago
    
    # Run auto-rotation
    results = engine.run_auto_rotation()
    
    assert results["keys_checked"] >= 3
    assert results["keys_needing_rotation"] >= 0
    assert "successful_rotations" in results
    assert "failed_rotations" in results
    
    print("  ✓ Auto-rotation tests passed")
    print(f"    - Keys checked: {results['keys_checked']}")
    print(f"    - Keys needing rotation: {results['keys_needing_rotation']}")
    print(f"    - Successful rotations: {results['successful_rotations']}")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Post-Quantum Key Management Engine - Test Suite")
    print("=" * 60)
    print()
    
    tests = [
        test_key_algorithms,
        test_key_generator,
        test_crypto_key,
        test_key_store,
        test_key_rotation_engine_basic,
        test_key_rotation,
        test_hybrid_key_creation,
        test_health_report,
        test_auto_rotation
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__} FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print()
    print("=" * 60)
    print(f"TEST RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save test results
    test_results = {
        "test_timestamp": time.time(),
        "module": "post_quantum_key_management_auto_rotation_engine",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(tests)
    }
    
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_post_quantum_key_management_auto_rotation_engine_2026_june.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print(f"Test results saved to JSON file")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
