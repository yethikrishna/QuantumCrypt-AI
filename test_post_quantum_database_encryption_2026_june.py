"""
Test Suite for Post-Quantum Database Encryption 2026
Production-Grade Testing - June 2026
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.post_quantum_database_encryption_2026_june import (
    PostQuantumDatabaseEncryptor,
    EncryptionMode,
    FieldSensitivity,
    KeyRotationStatus,
    EncryptedField,
    EncryptionResult,
    DecryptionResult
)
import json


def test_initialization():
    """Test encryptor initialization"""
    print("Test 1: Initialization...")
    encryptor = PostQuantumDatabaseEncryptor()
    assert encryptor is not None
    assert encryptor.enable_audit_logging == True
    print("  ✓ Encryptor initialized successfully")


def test_basic_encryption_decryption():
    """Test basic encrypt/decrypt roundtrip"""
    print("\nTest 2: Basic Encryption/Decryption Roundtrip...")
    encryptor = PostQuantumDatabaseEncryptor()
    
    plaintext = "user@example.com"
    field_name = "user_email"
    
    # Encrypt
    enc_result = encryptor.encrypt_field(
        plaintext, field_name, FieldSensitivity.CONFIDENTIAL
    )
    assert enc_result.success == True
    assert enc_result.encrypted_field is not None
    print("  ✓ Encryption successful")
    
    # Decrypt
    dec_result = encryptor.decrypt_field(
        enc_result.encrypted_field, field_name
    )
    assert dec_result.success == True
    assert dec_result.plaintext == plaintext
    assert dec_result.integrity_verified == True
    print(f"  ✓ Decryption successful: '{plaintext}' -> '{dec_result.plaintext}'")


def test_different_sensitivity_levels():
    """Test encryption with different sensitivity levels"""
    print("\nTest 3: Sensitivity Level Encryption...")
    encryptor = PostQuantumDatabaseEncryptor()
    
    test_cases = [
        ("public_data", FieldSensitivity.PUBLIC),
        ("internal_data", FieldSensitivity.INTERNAL),
        ("confidential_data", FieldSensitivity.CONFIDENTIAL),
        ("restricted_pii", FieldSensitivity.RESTRICTED),
    ]
    
    for value, sensitivity in test_cases:
        result = encryptor.encrypt_field(value, f"field_{value}", sensitivity)
        assert result.success == True
        assert result.encrypted_field.sensitivity == sensitivity
        print(f"  ✓ {sensitivity.value}: {value} encrypted with {result.encrypted_field.encryption_mode.value}")


def test_deterministic_field_equality():
    """Test deterministic encryption field equality checks"""
    print("\nTest 4: Deterministic Field Equality Check...")
    encryptor = PostQuantumDatabaseEncryptor()
    
    field_name = "username"
    value1 = "john_doe"
    value2 = "john_doe"
    value3 = "jane_doe"
    
    # Encrypt with deterministic mode
    enc1 = encryptor.encrypt_field(
        value1, field_name, FieldSensitivity.INTERNAL, 
        force_mode=EncryptionMode.DETERMINISTIC
    )
    enc2 = encryptor.encrypt_field(
        value2, field_name, FieldSensitivity.INTERNAL,
        force_mode=EncryptionMode.DETERMINISTIC
    )
    
    # Same values should produce same ciphertext (deterministic)
    assert enc1.encrypted_field.ciphertext == enc2.encrypted_field.ciphertext
    print("  ✓ Same plaintext produces same ciphertext (deterministic)")
    
    # Test equality check without decryption
    is_equal = encryptor.field_equals(enc1.encrypted_field, value1, field_name)
    assert is_equal == True
    print("  ✓ Equality check PASS for matching value")
    
    is_not_equal = encryptor.field_equals(enc1.encrypted_field, value3, field_name)
    assert is_not_equal == False
    print("  ✓ Equality check FAIL for different value")


def test_hash_only_equality():
    """Test hash-only mode equality"""
    print("\nTest 5: Hash-Only Mode Equality...")
    encryptor = PostQuantumDatabaseEncryptor()
    
    field_name = "ssn_last4"
    value = "1234"
    
    enc_result = encryptor.encrypt_field(
        value, field_name, FieldSensitivity.PUBLIC,
        force_mode=EncryptionMode.HASH_ONLY
    )
    assert enc_result.success == True
    
    # Hash-only can do equality checks
    is_equal = encryptor.field_equals(enc_result.encrypted_field, value, field_name)
    assert is_equal == True
    print("  ✓ Hash-only equality check works")
    
    # Hash-only cannot be decrypted
    dec_result = encryptor.decrypt_field(enc_result.encrypted_field, field_name)
    assert dec_result.success == False
    print("  ✓ Hash-only correctly cannot be decrypted")


def test_tamper_detection():
    """Test tamper detection via checksums and auth tags"""
    print("\nTest 6: Tamper Detection...")
    encryptor = PostQuantumDatabaseEncryptor()
    
    enc_result = encryptor.encrypt_field(
        "secret_data", "sensitive_field", FieldSensitivity.RESTRICTED
    )
    assert enc_result.success == True
    
    # Tamper with ciphertext
    original_ciphertext = enc_result.encrypted_field.ciphertext
    enc_result.encrypted_field.ciphertext = b"tampered_data!" + original_ciphertext[12:]
    
    # Decryption should fail due to checksum mismatch
    dec_result = encryptor.decrypt_field(enc_result.encrypted_field, "sensitive_field")
    assert dec_result.success == False
    assert "tampered" in dec_result.error_message.lower()
    print("  ✓ Checksum tampering detected")
    
    # Test auth tag tampering
    enc_result2 = encryptor.encrypt_field(
        "another_secret", "field2", FieldSensitivity.RESTRICTED
    )
    enc_result2.encrypted_field.auth_tag = b"fake_tag_12345678901234567890123456789012"
    
    dec_result2 = encryptor.decrypt_field(enc_result2.encrypted_field, "field2")
    assert dec_result2.success == False
    print("  ✓ Auth tag tampering detected")


def test_key_rotation():
    """Test key rotation functionality"""
    print("\nTest 7: Key Rotation...")
    encryptor = PostQuantumDatabaseEncryptor()
    
    initial_version = encryptor._current_key_version
    
    # Encrypt with old key
    enc_old = encryptor.encrypt_field("old_key_data", "test_field")
    assert enc_old.encrypted_field.key_version == initial_version
    
    # Rotate keys
    rotation_report = encryptor.rotate_keys()
    assert rotation_report["rotation_success"] == True
    assert rotation_report["new_version"] == initial_version + 1
    print(f"  ✓ Key rotated: v{initial_version} -> v{rotation_report['new_version']}")
    
    # New encryption uses new key
    enc_new = encryptor.encrypt_field("new_key_data", "test_field")
    assert enc_new.encrypted_field.key_version == initial_version + 1
    print("  ✓ New encryptions use new key version")
    
    # Old data can still be decrypted (key versioning)
    dec_old = encryptor.decrypt_field(enc_old.encrypted_field, "test_field")
    assert dec_old.success == True
    assert dec_old.plaintext == "old_key_data"
    print("  ✓ Old data still decryptable after rotation (backward compatible)")


def test_audit_logging():
    """Test audit logging functionality"""
    print("\nTest 8: Audit Logging...")
    encryptor = PostQuantumDatabaseEncryptor(enable_audit_logging=True)
    
    # Perform some operations
    encryptor.encrypt_field("test1", "field1")
    encryptor.encrypt_field("test2", "field2")
    
    audit_log = encryptor.get_audit_log()
    assert len(audit_log) >= 2
    
    for event in audit_log:
        assert "timestamp" in event
        assert "operation" in event
        assert "success" in event
    
    print(f"  ✓ Audit log contains {len(audit_log)} events")
    print("  ✓ All events have required fields")


def test_key_inventory():
    """Test key inventory reporting"""
    print("\nTest 9: Key Inventory Reporting...")
    encryptor = PostQuantumDatabaseEncryptor()
    
    encryptor.rotate_keys()
    encryptor.rotate_keys()
    
    inventory = encryptor.get_key_inventory()
    assert len(inventory) == 3  # v1, v2, v3
    
    versions = [k["version"] for k in inventory]
    assert 1 in versions
    assert 2 in versions
    assert 3 in versions
    
    print(f"  ✓ Key inventory shows {len(inventory)} key versions")
    print("  ✓ All versions tracked correctly")


def test_serialization_deserialization():
    """Test field serialization for database storage"""
    print("\nTest 10: Serialization/Deserialization...")
    encryptor = PostQuantumDatabaseEncryptor()
    
    original = encryptor.encrypt_field("serialize_test", "my_field")
    
    # Serialize to JSON string (for database storage)
    serialized = encryptor.serialize_encrypted_field(original.encrypted_field)
    assert isinstance(serialized, str)
    json.loads(serialized)  # Valid JSON
    print("  ✓ Serialization produces valid JSON")
    
    # Deserialize back
    deserialized = encryptor.deserialize_encrypted_field(serialized)
    
    # Verify deserialized field decrypts correctly
    result = encryptor.decrypt_field(deserialized, "my_field")
    assert result.success == True
    assert result.plaintext == "serialize_test"
    print("  ✓ Deserialized field decrypts correctly")


def test_record_id_binding():
    """Test record ID binding for cryptographic isolation"""
    print("\nTest 11: Record ID Cryptographic Isolation...")
    encryptor = PostQuantumDatabaseEncryptor()
    
    field_name = "email"
    value = "user@example.com"
    
    # Same value, different record IDs produce DIFFERENT ciphertexts
    enc1 = encryptor.encrypt_field(value, field_name, record_id="record_001")
    enc2 = encryptor.encrypt_field(value, field_name, record_id="record_002")
    
    assert enc1.encrypted_field.ciphertext != enc2.encrypted_field.ciphertext
    print("  ✓ Same value with different record IDs produces different ciphertexts")
    print("  ✓ Cryptographic isolation between records works")


def run_all_tests():
    """Run complete test suite"""
    print("=" * 60)
    print("Post-Quantum Database Encryption - Production Test Suite")
    print("=" * 60)
    
    tests = [
        test_initialization,
        test_basic_encryption_decryption,
        test_different_sensitivity_levels,
        test_deterministic_field_equality,
        test_hash_only_equality,
        test_tamper_detection,
        test_key_rotation,
        test_audit_logging,
        test_key_inventory,
        test_serialization_deserialization,
        test_record_id_binding,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"\n  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"\n  ✗ ERROR: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed}/{len(tests)} PASSED")
    if failed > 0:
        print(f"WARNING: {failed} TESTS FAILED!")
    else:
        print("ALL TESTS PASSED ✓")
    print("=" * 60)
    
    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
