#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Configuration Encryptor
Production-grade cryptographic tests
"""

import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_configuration_encryptor_2026_june import PostQuantumConfigEncryptor, EncryptedConfig


def test_initialization():
    """Test encryptor initialization"""
    print("Test 1: Initialization")
    encryptor = PostQuantumConfigEncryptor()
    assert encryptor is not None
    assert encryptor.KEY_SIZE == 32
    assert encryptor.NONCE_SIZE == 12
    info = encryptor.get_security_info()
    assert info['quantum_resistant'] == True
    assert info['nist_security_category'] == 5
    print("  ✓ Initialization successful")
    return True


def test_custom_master_key():
    """Test initialization with custom master key"""
    print("\nTest 2: Custom master key")
    import os
    custom_key = os.urandom(32)
    encryptor = PostQuantumConfigEncryptor(master_key=custom_key)
    assert encryptor.master_key == custom_key
    print("  ✓ Custom master key accepted")
    return True


def test_invalid_key_length():
    """Test that invalid key length raises error"""
    print("\nTest 3: Invalid key length validation")
    try:
        bad_key = b"too_short"
        PostQuantumConfigEncryptor(master_key=bad_key)
        print("  ✗ Should have raised ValueError")
        return False
    except ValueError as e:
        print(f"  ✓ Correctly raised ValueError: {e}")
        return True


def test_encrypt_decrypt_basic():
    """Test basic encryption and decryption roundtrip"""
    print("\nTest 4: Basic encrypt/decrypt roundtrip")
    encryptor = PostQuantumConfigEncryptor()

    plaintext = "my-secret-api-key-12345"
    encrypted = encryptor.encrypt(plaintext)

    print(f"  Plaintext: {plaintext}")
    print(f"  Ciphertext (truncated): {encrypted.ciphertext[:32]}...")
    print(f"  Key version: {encrypted.key_version}")
    print(f"  Algorithm: {encrypted.algorithm}")

    decrypted = encryptor.decrypt(encrypted)
    assert decrypted == plaintext
    print(f"  Decrypted: {decrypted}")
    print("  ✓ Roundtrip successful")
    return True


def test_encrypt_decrypt_special_chars():
    """Test encryption with special characters and unicode"""
    print("\nTest 5: Special characters and unicode")
    encryptor = PostQuantumConfigEncryptor()

    test_values = [
        "postgres://user:pass@host:5432/db?ssl=true",
        "xk_abc123!@#$%^&*()_+-=[]{}|;:,.<>?",
        "密码123_Ключ🔑",
        '{"nested": "json", "value": true}',
        ""
    ]

    for test_val in test_values:
        encrypted = encryptor.encrypt(test_val)
        decrypted = encryptor.decrypt(encrypted)
        assert decrypted == test_val, f"Failed for: {test_val[:20]}"

    print(f"  ✓ All {len(test_values)} special character tests passed")
    return True


def test_json_serialization():
    """Test JSON serialization and deserialization"""
    print("\nTest 6: JSON serialization")
    encryptor = PostQuantumConfigEncryptor()

    plaintext = "secret-token-abc-xyz"

    # Test dict format
    encrypted_dict = encryptor.encrypt_to_dict(plaintext)
    assert 'ciphertext' in encrypted_dict
    assert 'nonce' in encrypted_dict
    decrypted = encryptor.decrypt_from_dict(encrypted_dict)
    assert decrypted == plaintext

    # Test JSON string format
    encrypted_json = encryptor.encrypt_to_json(plaintext)
    parsed = json.loads(encrypted_json)
    assert 'checksum' in parsed
    decrypted2 = encryptor.decrypt_from_json(encrypted_json)
    assert decrypted2 == plaintext

    print("  ✓ JSON serialization working")
    return True


def test_integrity_verification():
    """Test that tampering is detected"""
    print("\nTest 7: Tamper detection (integrity verification)")
    encryptor = PostQuantumConfigEncryptor()

    encrypted = encryptor.encrypt("secret-value")

    # Tamper with ciphertext
    original_ciphertext = encrypted.ciphertext
    encrypted.ciphertext = "AAAA" + original_ciphertext[4:]

    try:
        encryptor.decrypt(encrypted)
        print("  ✗ Tampering not detected!")
        return False
    except ValueError as e:
        print(f"  ✓ Tampering correctly detected: {e}")

    # Restore and tamper with checksum
    encrypted.ciphertext = original_ciphertext
    encrypted.checksum = "0" * 64

    try:
        encryptor.decrypt(encrypted)
        print("  ✗ Checksum tampering not detected!")
        return False
    except ValueError as e:
        print(f"  ✓ Checksum tampering correctly detected")

    return True


def test_wrong_key_rejection():
    """Test that wrong key cannot decrypt"""
    print("\nTest 8: Wrong key rejection")
    encryptor1 = PostQuantumConfigEncryptor()
    encryptor2 = PostQuantumConfigEncryptor()  # Different random key

    encrypted = encryptor1.encrypt("secret-data")

    try:
        encryptor2.decrypt(encrypted)
        print("  ✗ Wrong key should not decrypt!")
        return False
    except ValueError as e:
        print(f"  ✓ Wrong key correctly rejected")

    return True


def test_key_rotation():
    """Test key rotation functionality"""
    print("\nTest 9: Key rotation")
    encryptor = PostQuantumConfigEncryptor()

    old_version = encryptor.key_version
    old_fingerprint = encryptor.get_security_info()['key_fingerprint']

    new_key, rotation_info = encryptor.rotate_key()

    assert encryptor.key_version == old_version + 1
    assert rotation_info['old_key_version'] == old_version
    assert rotation_info['new_key_version'] == old_version + 1

    new_fingerprint = encryptor.get_security_info()['key_fingerprint']
    assert new_fingerprint != old_fingerprint

    print(f"  Rotated from v{old_version} to v{encryptor.key_version}")
    print("  ✓ Key rotation successful")
    return True


def test_batch_encryption():
    """Test batch configuration encryption"""
    print("\nTest 10: Batch encryption")
    encryptor = PostQuantumConfigEncryptor()

    config = {
        'DB_HOST': 'localhost',
        'DB_USER': 'admin',
        'DB_PASS': 'super-secret-password',
        'API_KEY': 'sk_live_12345abcde',
        'DEBUG': 'false'
    }

    sensitive_keys = ['DB_PASS', 'API_KEY']

    encrypted_batch = encryptor.encrypt_config_batch(config, sensitive_keys)
    assert encrypted_batch['_encrypted'] == True

    # Verify sensitive keys are encrypted
    assert isinstance(encrypted_batch['values']['DB_PASS'], dict)
    assert isinstance(encrypted_batch['values']['API_KEY'], dict)

    # Verify non-sensitive are in plaintext
    assert encrypted_batch['values']['DB_HOST'] == 'localhost'

    # Decrypt and verify
    decrypted_config = encryptor.decrypt_config_batch(encrypted_batch)
    for key, value in config.items():
        assert decrypted_config[key] == value, f"Mismatch for {key}"

    print(f"  ✓ Batch processed {len(config)} config values")
    print(f"  ✓ Encrypted {len(sensitive_keys)} sensitive fields")
    return True


def test_metadata_storage():
    """Test metadata storage with encrypted values"""
    print("\nTest 11: Metadata storage")
    encryptor = PostQuantumConfigEncryptor()

    metadata = {
        'environment': 'production',
        'expires': '2026-12-31',
        'owner': 'security-team'
    }

    encrypted = encryptor.encrypt("secret-value", metadata)

    assert encrypted.metadata['environment'] == 'production'
    assert encrypted.metadata['owner'] == 'security-team'

    decrypted = encryptor.decrypt(encrypted)
    assert decrypted == "secret-value"

    print("  ✓ Metadata correctly stored and retrieved")
    return True


def test_security_info():
    """Test security info reporting"""
    print("\nTest 12: Security information reporting")
    encryptor = PostQuantumConfigEncryptor()

    # Perform some operations
    encryptor.encrypt("test1")
    encryptor.encrypt("test2")
    encryptor.encrypt("test3")

    info = encryptor.get_security_info()

    assert info['key_size_bits'] == 256
    assert info['encryption_mode'] == 'AES-GCM'
    assert info['operations']['encryptions'] == 3
    assert 'key_fingerprint' in info

    print(f"  Key size: {info['key_size_bits']} bits")
    print(f"  NIST Category: {info['nist_security_category']}")
    print(f"  Operations: {info['operations']}")
    print("  ✓ Security info correctly reported")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Post-Quantum Configuration Encryptor - Test Suite")
    print("=" * 60)

    tests = [
        test_initialization,
        test_custom_master_key,
        test_invalid_key_length,
        test_encrypt_decrypt_basic,
        test_encrypt_decrypt_special_chars,
        test_json_serialization,
        test_integrity_verification,
        test_wrong_key_rejection,
        test_key_rotation,
        test_batch_encryption,
        test_metadata_storage,
        test_security_info
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
            print(f"  ✗ FAILED with exception: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 60)

    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
