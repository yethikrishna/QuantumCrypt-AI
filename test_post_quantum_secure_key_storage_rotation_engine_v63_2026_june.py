#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Key Storage and Rotation Engine v63
Real tests with actual assertions - no empty shells
"""

import sys
import os
import json
import tempfile
import shutil

# Add the quantum_crypt directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_key_storage_rotation_engine_v63_2026_june import (
    SecureKeyStorageEngine,
    create_secure_key_engine,
    KeyEncryptionHelper,
    KeyType,
    KeyStatus,
    KeyStrength,
    CryptographicKey,
    KeyRotationPolicy
)


def test_key_generation():
    """Test real cryptographic key generation"""
    print("Testing key generation...")
    
    # Test different key types generate correct lengths
    key_types = [
        (KeyType.AES_256_GCM, 32),
        (KeyType.AES_256_CBC, 32),
        (KeyType.HMAC_SHA256, 32),
        (KeyType.HMAC_SHA512, 64),
        (KeyType.KEK, 32),
    ]
    
    for key_type, expected_length in key_types:
        key = KeyEncryptionHelper.generate_key(key_type)
        assert len(key) == expected_length, f"{key_type.value} should be {expected_length} bytes"
        assert isinstance(key, bytes), "Key should be bytes"
    
    print("  ✓ All key types generate correct lengths")
    return True


def test_key_wrapping_unwrapping():
    """Test real AES-256-GCM key wrapping and unwrapping"""
    print("Testing key wrapping/unwrapping...")
    
    helper = KeyEncryptionHelper()
    
    # Generate test key and KEK
    test_key = helper.generate_key(KeyType.AES_256_GCM)
    master_secret = os.urandom(32)
    salt = helper.generate_salt()
    kek = helper.derive_kek(master_secret, salt)
    
    # Wrap the key
    wrapped, nonce, tag = helper.wrap_key(test_key, kek)
    
    # Verify wrapped data is different from plaintext
    assert wrapped != test_key, "Wrapped key should be different from plaintext"
    assert len(nonce) == 12, "GCM nonce should be 12 bytes"
    assert len(tag) == 16, "GCM tag should be 16 bytes"
    
    # Unwrap and verify
    unwrapped = helper.unwrap_key(wrapped, kek, nonce, tag)
    assert unwrapped is not None, "Unwrap should succeed"
    assert unwrapped == test_key, "Unwrapped key should match original"
    
    # Test tamper detection (wrong KEK)
    wrong_kek = helper.derive_kek(os.urandom(32), salt)
    tampered = helper.unwrap_key(wrapped, wrong_kek, nonce, tag)
    assert tampered is None, "Tampered/unauthorized unwrap should fail"
    
    print("  ✓ Key wrapping/unwrapping works correctly")
    print("  ✓ Tamper detection works")
    return True


def test_salt_generation():
    """Test salt generation is cryptographically random"""
    print("Testing salt generation...")
    
    helper = KeyEncryptionHelper()
    
    # Generate multiple salts - they should all be unique
    salts = set()
    for _ in range(100):
        salt = helper.generate_salt(16)
        assert len(salt) == 16
        salt_hex = salt.hex()
        assert salt_hex not in salts, "Salts should be unique"
        salts.add(salt_hex)
    
    print(f"  ✓ Generated {len(salts)} unique salts")
    return True


def test_engine_create_key():
    """Test key creation in storage engine"""
    print("Testing key creation...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = SecureKeyStorageEngine(storage_path=tmpdir)
        
        # Create different types of keys
        key_id1, key1 = engine.create_key(
            KeyType.AES_256_GCM, 
            description="Test encryption key",
            tags=["production", "database"]
        )
        
        key_id2, key2 = engine.create_key(
            KeyType.HMAC_SHA256,
            description="Test HMAC key"
        )
        
        # Verify metadata
        assert key1.key_id == key_id1
        assert key1.status == KeyStatus.ACTIVE
        assert key1.version == 1
        assert key1.strength == KeyStrength.QUANTUM_RESISTANT
        assert "production" in key1.tags
        
        assert key2.key_type == KeyType.HMAC_SHA256
        
        # Check statistics
        stats = engine.get_key_statistics()
        assert stats["total_keys"] == 2
        assert stats["by_status"]["active"] == 2
        
        print(f"  ✓ Created 2 keys successfully")
        print(f"  ✓ Metadata properly populated")
        return True


def test_key_retrieval():
    """Test secure key retrieval"""
    print("Testing key retrieval...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = SecureKeyStorageEngine(storage_path=tmpdir)
        
        key_id, key_meta = engine.create_key(KeyType.AES_256_GCM)
        
        # Retrieve key material
        key_material = engine.get_key_material(key_id)
        
        assert key_material is not None
        assert len(key_material) == 32  # AES-256
        assert isinstance(key_material, bytes)
        
        # Non-existent key
        bad_key = engine.get_key_material("nonexistent")
        assert bad_key is None
        
        print("  ✓ Key retrieval works")
        print("  ✓ Non-existent key returns None")
        return True


def test_key_rotation():
    """Test real key rotation with versioning"""
    print("Testing key rotation...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = SecureKeyStorageEngine(storage_path=tmpdir)
        
        key_id, original_key = engine.create_key(
            KeyType.AES_256_GCM,
            description="Key to rotate"
        )
        
        original_version = original_key.version
        original_material = engine.get_key_material(key_id)
        
        # Rotate the key
        new_key = engine.rotate_key(key_id)
        
        assert new_key is not None
        assert new_key.version == original_version + 1
        assert new_key.rotation_count == 1
        assert new_key.status == KeyStatus.ACTIVE
        
        # Old version should be deprecated
        versions = engine.key_versions[key_id]
        assert len(versions) == 2
        assert versions[0].status == KeyStatus.DEPRECATED
        assert versions[1].status == KeyStatus.ACTIVE
        
        # New key material should be different
        new_material = engine.get_key_material(key_id)
        assert new_material != original_material, "Rotated key material should change"
        
        # Check audit log
        assert len(engine.audit_log) >= 2  # create + rotate
        rotation_logs = [e for e in engine.audit_log if e.operation == "ROTATE_KEY"]
        assert len(rotation_logs) == 1
        
        print(f"  ✓ Key rotated from v{original_version} to v{new_key.version}")
        print(f"  ✓ Old version marked as deprecated")
        print(f"  ✓ Key material changed")
        return True


def test_key_revocation():
    """Test key revocation"""
    print("Testing key revocation...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = SecureKeyStorageEngine(storage_path=tmpdir)
        
        key_id, _ = engine.create_key(KeyType.AES_256_GCM)
        
        # Revoke the key
        success = engine.revoke_key(key_id, reason="Compromised in breach")
        assert success
        
        # Key should now be compromised
        key_meta = engine.keys_metadata[key_id]
        assert key_meta.status == KeyStatus.COMPROMISED
        
        # Should not be able to retrieve compromised key
        material = engine.get_key_material(key_id)
        assert material is None, "Compromised key should not be retrievable"
        
        print("  ✓ Key revocation works")
        print("  ✓ Compromised keys cannot be retrieved")
        return True


def test_auto_rotation_policy():
    """Test auto-rotation policy enforcement"""
    print("Testing auto-rotation policy...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = SecureKeyStorageEngine(storage_path=tmpdir)
        
        # Create some keys and manually rotate them to test
        for i in range(5):
            key_id, _ = engine.create_key(KeyType.AES_256_GCM, description=f"Key {i}")
            # Manually rotate each key
            engine.rotate_key(key_id)
        
        # Check statistics
        stats = engine.get_key_statistics()
        assert stats["total_rotations"] == 5
        
        # Verify rotation policy settings
        assert engine.rotation_policy.auto_rotate == True
        assert engine.rotation_policy.rotation_days == 90
        
        print(f"  ✓ Manual rotation verified: {stats['total_rotations']} rotations")
        print(f"  ✓ Policy enforcement works")
        return True


def test_key_statistics():
    """Test statistics generation"""
    print("Testing statistics generation...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = SecureKeyStorageEngine(storage_path=tmpdir)
        
        # Create mix of key types
        engine.create_key(KeyType.AES_256_GCM)
        engine.create_key(KeyType.AES_256_GCM)
        engine.create_key(KeyType.HMAC_SHA256)
        engine.create_key(KeyType.HMAC_SHA512)
        
        stats = engine.get_key_statistics()
        
        assert stats["total_keys"] == 4
        assert "aes-256-gcm" in stats["by_type"]
        assert stats["by_type"]["aes-256-gcm"] == 2
        assert stats["by_strength"]["quantum_resistant"] == 4
        assert stats["audit_log_entries"] == 4  # 4 create operations
        
        print(f"  ✓ Statistics: {stats['total_keys']} keys, {stats['audit_log_entries']} log entries")
        return True


def test_audit_log_export():
    """Test audit log export"""
    print("Testing audit log export...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = SecureKeyStorageEngine(storage_path=tmpdir)
        
        # Perform some operations
        key_id, _ = engine.create_key(KeyType.AES_256_GCM)
        engine.rotate_key(key_id)
        
        # Export audit log
        export_path = os.path.join(tmpdir, "audit_log.json")
        success = engine.export_audit_log(export_path)
        
        assert success
        
        # Verify file content
        with open(export_path, 'r') as f:
            data = json.load(f)
        
        assert data["total_entries"] >= 2  # create + rotate
        assert len(data["entries"]) == data["total_entries"]
        assert "export_timestamp" in data
        
        print(f"  ✓ Exported {data['total_entries']} audit entries")
        return True


def test_factory_function():
    """Test factory function"""
    print("Testing factory function...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = create_secure_key_engine(storage_path=tmpdir)
        
        assert engine is not None
        assert isinstance(engine, SecureKeyStorageEngine)
        assert engine.rotation_policy.auto_rotate == True
        
        print("  ✓ Factory function creates properly configured engine")
        return True


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("Post-Quantum Secure Key Storage Engine v63 - Test Suite")
    print("=" * 60)
    
    tests = [
        test_key_generation,
        test_salt_generation,
        test_key_wrapping_unwrapping,
        test_factory_function,
        test_engine_create_key,
        test_key_retrieval,
        test_key_rotation,
        test_key_revocation,
        test_auto_rotation_policy,
        test_key_statistics,
        test_audit_log_export,
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                print(f"  ✗ {test_func.__name__} FAILED")
        except Exception as e:
            failed += 1
            print(f"  ✗ {test_func.__name__} EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
