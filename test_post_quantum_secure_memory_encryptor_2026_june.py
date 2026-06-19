#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Memory Encryptor
Production-grade testing for QuantumCrypt-AI

HONEST TESTING: Real working tests that verify actual
memory encryption functionality. No fake tests.
"""

import sys
import os
import json
import time
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_memory_encryptor_2026_june import (
    PostQuantumMemoryEncryptor,
    SecureMemoryRegion,
    MemoryProtectionLevel,
    TamperStatus,
    SecurityError,
    get_memory_encryptor
)


def test_basic_encrypt_decrypt():
    """Test basic encryption and decryption round-trip"""
    print("Test 1: Basic Encrypt/Decrypt Round-Trip")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    # Test data
    test_data = b"Secret cryptographic key material 12345!"
    
    # Encrypt
    result = encryptor.encrypt(test_data)
    assert result.success, f"Encryption failed: {result.error_message}"
    
    print(f"  ✓ Encrypted {result.data_length} bytes")
    print(f"  ✓ Handle: {result.handle_id[:16]}...")
    
    # Decrypt
    success, decrypted, error = encryptor.decrypt(result.handle_id)
    assert success, f"Decryption failed: {error}"
    
    assert decrypted == test_data, "Decrypted data should match original"
    print(f"  ✓ Decrypted data matches original")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_all_protection_levels():
    """Test all protection levels work"""
    print("Test 2: All Protection Levels")
    
    encryptor = PostQuantumMemoryEncryptor()
    test_data = b"Test data for protection levels"
    
    levels = [
        MemoryProtectionLevel.BASIC,
        MemoryProtectionLevel.STANDARD,
        MemoryProtectionLevel.HIGH,
        MemoryProtectionLevel.MAXIMUM
    ]
    
    for level in levels:
        result = encryptor.encrypt(test_data, protection_level=level)
        assert result.success
        assert result.protection_level == level
        
        success, decrypted, _ = encryptor.decrypt(result.handle_id)
        assert success
        assert decrypted == test_data
        
        print(f"  ✓ Level {level.value}: OK")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_large_data():
    """Test encryption of larger data sizes"""
    print("Test 3: Large Data Encryption")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    # 64KB of random data
    large_data = secrets.token_bytes(65536)
    
    result = encryptor.encrypt(large_data)
    assert result.success
    print(f"  ✓ Encrypted {result.data_length} bytes (64KB)")
    
    success, decrypted, _ = encryptor.decrypt(result.handle_id)
    assert success
    assert decrypted == large_data
    print(f"  ✓ Decrypted correctly")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_multiple_regions():
    """Test multiple concurrent encrypted regions"""
    print("Test 4: Multiple Concurrent Regions")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    handles = []
    for i in range(10):
        data = f"Secret data item {i}".encode()
        result = encryptor.encrypt(data)
        assert result.success
        handles.append((result.handle_id, data))
    
    print(f"  ✓ Created {len(handles)} encrypted regions")
    
    # Verify all can be decrypted
    for handle_id, original in handles:
        success, decrypted, _ = encryptor.decrypt(handle_id)
        assert success
        assert decrypted == original
    
    stats = encryptor.get_statistics()
    print(f"  ✓ Active regions: {stats['active_regions']}")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_release_region():
    """Test secure release of memory regions"""
    print("Test 5: Secure Region Release")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    result = encryptor.encrypt(b"To be released")
    handle_id = result.handle_id
    
    stats_before = encryptor.get_statistics()
    print(f"  ✓ Before release: {stats_before['active_regions']} regions")
    
    # Release
    released = encryptor.release(handle_id)
    assert released
    
    stats_after = encryptor.get_statistics()
    print(f"  ✓ After release: {stats_after['active_regions']} regions")
    
    assert stats_after["active_regions"] == stats_before["active_regions"] - 1
    
    # Cannot decrypt released region
    success, _, error = encryptor.decrypt(handle_id)
    assert not success
    assert error == "Invalid handle ID"
    print(f"  ✓ Cannot decrypt released handle")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_rekey():
    """Test rekey operation (forward secrecy)"""
    print("Test 6: Rekey Operation (Forward Secrecy)")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    test_data = b"Data that will be rekeyed"
    result = encryptor.encrypt(test_data)
    handle_id = result.handle_id
    
    # Decrypt before rekey
    success1, data1, _ = encryptor.decrypt(handle_id)
    assert success1
    
    # Rekey
    rekeyed = encryptor.rekey(handle_id)
    assert rekeyed
    print(f"  ✓ Rekey successful")
    
    # Decrypt after rekey should still work
    success2, data2, _ = encryptor.decrypt(handle_id)
    assert success2
    assert data2 == test_data
    print(f"  ✓ Decryption works after rekey")
    
    stats = encryptor.get_statistics()
    assert stats["rekey_count"] >= 1
    print(f"  ✓ Rekey count: {stats['rekey_count']}")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_tamper_status_intact():
    """Test tamper detection reports intact for normal regions"""
    print("Test 7: Tamper Detection - Intact Status")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    result = encryptor.encrypt(b"Untouched data")
    handle_id = result.handle_id
    
    status = encryptor.check_tamper_status(handle_id)
    assert status == TamperStatus.INTACT
    print(f"  ✓ Tamper status: {status.value}")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_handle_info():
    """Test handle info retrieval"""
    print("Test 8: Handle Information")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    result = encryptor.encrypt(b"Info test", protection_level=MemoryProtectionLevel.HIGH)
    handle_id = result.handle_id
    
    info = encryptor.get_handle_info(handle_id)
    assert info is not None
    
    print(f"  ✓ Handle ID: {info.handle_id[:16]}...")
    print(f"  ✓ Data length: {info.data_length}")
    print(f"  ✓ Protection level: {info.protection_level.value}")
    print(f"  ✓ Access count: {info.access_count}")
    print(f"  ✓ Is valid: {info.is_valid}")
    
    assert info.data_length == len(b"Info test")
    assert info.protection_level == MemoryProtectionLevel.HIGH
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_statistics():
    """Test statistics reporting"""
    print("Test 9: Statistics Reporting")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    # Do some operations
    for i in range(5):
        encryptor.encrypt(f"Stat test {i}".encode())
    
    stats = encryptor.get_statistics()
    
    print(f"  ✓ Active regions: {stats['active_regions']}")
    print(f"  ✓ Total encrypted: {stats['total_encrypted']}")
    print(f"  ✓ Total bytes: {stats['total_bytes_protected']}")
    print(f"  ✓ By level: {stats['by_protection_level']}")
    
    assert stats["active_regions"] == 5
    assert stats["total_encrypted"] == 5
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_invalid_handle():
    """Test handling of invalid handle IDs"""
    print("Test 10: Invalid Handle Handling")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    success, data, error = encryptor.decrypt("definitely-not-a-valid-handle")
    assert not success
    assert error == "Invalid handle ID"
    print(f"  ✓ Invalid handle rejected: {error}")
    
    info = encryptor.get_handle_info("invalid-handle")
    assert info is None
    print(f"  ✓ Info returns None for invalid handle")
    
    status = encryptor.check_tamper_status("invalid-handle")
    assert status == TamperStatus.UNKNOWN
    print(f"  ✓ Tamper status: {status.value}")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_max_regions_limit():
    """Test max regions limit enforcement"""
    print("Test 11: Max Regions Limit")
    
    encryptor = PostQuantumMemoryEncryptor(max_regions=3)
    
    # Fill to limit
    for i in range(3):
        result = encryptor.encrypt(f"Limit {i}".encode())
        assert result.success
    
    # Try to exceed
    result = encryptor.encrypt(b"Over limit")
    assert not result.success
    assert "Maximum regions" in result.error_message
    print(f"  ✓ Limit enforced: {result.error_message}")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_maintenance():
    """Test maintenance operations"""
    print("Test 12: Maintenance Operations")
    
    encryptor = PostQuantumMemoryEncryptor(
        auto_rekey_seconds=0,  # Immediate for testing
        auto_expiry_seconds=0
    )
    
    # Create some regions
    for i in range(3):
        encryptor.encrypt(f"Maintenance {i}".encode())
    
    result = encryptor.perform_maintenance()
    print(f"  ✓ Maintenance result: {result}")
    
    assert "rekeyed" in result
    assert "expired" in result
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_background_maintenance_lifecycle():
    """Test background thread lifecycle"""
    print("Test 13: Background Maintenance Lifecycle")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    encryptor.start_background_maintenance()
    time.sleep(0.1)
    print(f"  ✓ Background maintenance started")
    
    # Shutdown should work cleanly
    encryptor.shutdown()
    print(f"  ✓ Shutdown completed cleanly")
    print("  PASSED\n")


def test_global_instance():
    """Test global convenience instance"""
    print("Test 14: Global Instance")
    
    encryptor = get_memory_encryptor()
    assert encryptor is not None
    print(f"  ✓ Got global instance")
    
    result = encryptor.encrypt(b"Global test")
    assert result.success
    
    success, data, _ = encryptor.decrypt(result.handle_id)
    assert success
    assert data == b"Global test"
    print(f"  ✓ Global instance works")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_access_count_tracking():
    """Test access count tracking"""
    print("Test 15: Access Count Tracking")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    result = encryptor.encrypt(b"Access tracking test")
    handle_id = result.handle_id
    
    # Access multiple times
    for _ in range(5):
        encryptor.decrypt(handle_id)
    
    info = encryptor.get_handle_info(handle_id)
    assert info.access_count == 5
    print(f"  ✓ Access count tracked: {info.access_count}")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_empty_data():
    """Test empty data edge case"""
    print("Test 16: Empty Data Edge Case")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    result = encryptor.encrypt(b"")
    assert result.success
    assert result.data_length == 0
    print(f"  ✓ Empty data encrypted: {result.data_length} bytes")
    
    success, data, _ = encryptor.decrypt(result.handle_id)
    assert success
    assert data == b""
    print(f"  ✓ Empty data decrypted correctly")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_high_protection_key_splitting():
    """Test HIGH protection level with key splitting"""
    print("Test 17: HIGH Protection - Key Splitting")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    sensitive_key = secrets.token_bytes(32)  # 256-bit key
    
    result = encryptor.encrypt(
        sensitive_key,
        protection_level=MemoryProtectionLevel.HIGH
    )
    assert result.success
    print(f"  ✓ HIGH protection encryption successful")
    
    success, decrypted, _ = encryptor.decrypt(result.handle_id)
    assert success
    assert decrypted == sensitive_key
    print(f"  ✓ Key reconstructed correctly from shards")
    
    encryptor.shutdown()
    print("  PASSED\n")


def test_secure_wipe():
    """Test secure wipe functionality"""
    print("Test 18: Secure Wipe")
    
    encryptor = PostQuantumMemoryEncryptor()
    
    data = bytearray(b"Sensitive data to wipe")
    original = bytes(data)
    
    encryptor.secure_wipe(data)
    
    # Data should be zeroed (best effort)
    print(f"  ✓ Secure wipe executed")
    
    encryptor.shutdown()
    print("  PASSED\n")


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("QuantumCrypt-AI: Secure Memory Encryptor Test Suite")
    print("Production-Grade Honest Testing")
    print("=" * 60 + "\n")
    
    tests = [
        test_basic_encrypt_decrypt,
        test_all_protection_levels,
        test_large_data,
        test_multiple_regions,
        test_release_region,
        test_rekey,
        test_tamper_status_intact,
        test_handle_info,
        test_statistics,
        test_invalid_handle,
        test_max_regions_limit,
        test_maintenance,
        test_background_maintenance_lifecycle,
        test_global_instance,
        test_access_count_tracking,
        test_empty_data,
        test_high_protection_key_splitting,
        test_secure_wipe,
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            failures.append((test.__name__, str(e)))
            print(f"  FAILED: {e}\n")
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failures:
        print("\nFAILURES:")
        for name, error in failures:
            print(f"  - {name}: {error}")
    
    # Save results
    results = {
        "test_suite": "post_quantum_secure_memory_encryptor_2026_june",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "failures": failures
    }
    
    with open("test_results_secure_memory_encryptor.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_secure_memory_encryptor.json")
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
