"""
Test Suite for Quantum-Secure Checksum 2026
Real, working tests - actual file I/O and hash computation
"""

import sys
import os
import tempfile
import secrets

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.quantum_secure_checksum_2026_june import (
    QuantumSecureChecksum,
    QuantumHashVerifier,
    create_secure_checksum,
    HashFunction,
    VerificationStatus,
    IntegrityLevel,
    FileChecksum,
    VerificationResult
)
import json


def create_test_file(content: bytes) -> str:
    """Helper to create temporary test file."""
    fd, path = tempfile.mkstemp(suffix=".bin", prefix="qc_test_")
    with os.fdopen(fd, 'wb') as f:
        f.write(content)
    return path


def test_checksum_initialization():
    """Test verifier initialization."""
    print("Test 1: Checksum Initialization")
    verifier = create_secure_checksum("high")
    assert verifier.integrity_level == IntegrityLevel.HIGH
    assert len(verifier.hash_functions) >= 3
    print("  ✓ PASSED")


def test_different_integrity_levels():
    """Test different integrity levels."""
    print("Test 2: Integrity Levels")
    
    levels = ["basic", "standard", "high", "maximum"]
    for level in levels:
        verifier = create_secure_checksum(level)
        assert len(verifier.hash_functions) > 0
        print(f"  ✓ Level '{level}': {len(verifier.hash_functions)} hash functions")
    print("  ✓ All integrity levels work")


def test_checksum_generation_from_data():
    """Test checksum generation from memory data."""
    print("Test 3: In-Memory Checksum Generation")
    
    verifier = create_secure_checksum("high")
    test_data = b"Test data for quantum checksum verification!" * 10
    
    cs = verifier.generate_checksum_from_data(test_data, "test.bin")
    
    assert isinstance(cs, FileChecksum)
    assert cs.file_size == len(test_data)
    assert len(cs.hashes) >= 3
    assert cs.checksum_id is not None
    
    print(f"  ✓ Generated checksum with {len(cs.hashes)} hashes")
    print(f"  ✓ File size recorded: {cs.file_size} bytes")


def test_checksum_generation_from_file():
    """Test actual file checksum generation."""
    print("Test 4: File Checksum Generation")
    
    test_content = b"QuantumCrypt test file content " * 50
    test_file = create_test_file(test_content)
    
    try:
        verifier = create_secure_checksum("standard")
        cs = verifier.generate_checksum(test_file)
        
        assert cs.file_size == len(test_content)
        assert "sha256" in cs.hashes
        assert "sha3_256" in cs.hashes
        
        print(f"  ✓ Checksum generated for real file")
        print(f"  ✓ SHA256: {cs.hashes['sha256'][:16]}...")
        print(f"  ✓ SHA3-256: {cs.hashes['sha3_256'][:16]}...")
    finally:
        os.unlink(test_file)


def test_valid_file_verification():
    """Test verification of unmodified file."""
    print("Test 5: Valid File Verification")
    
    test_content = b"Original, untampered file content"
    test_file = create_test_file(test_content)
    
    try:
        verifier = create_secure_checksum("high")
        cs = verifier.generate_checksum(test_file)
        result = verifier.verify_checksum(test_file, cs)
        
        assert result.is_valid == True
        assert result.status == VerificationStatus.VERIFIED
        assert all(result.verified_hashes.values())
        
        print(f"  ✓ Valid file correctly verified")
        print(f"  ✓ Verification time: {result.verification_time_ms}ms")
    finally:
        os.unlink(test_file)


def test_tampered_file_detection():
    """Test that tampered files are detected."""
    print("Test 6: Tampered File Detection")
    
    test_content = b"Original secure content"
    test_file = create_test_file(test_content)
    
    try:
        verifier = create_secure_checksum("high")
        cs = verifier.generate_checksum(test_file)
        
        # Tamper with the file
        with open(test_file, 'r+b') as f:
            f.write(b"HACKED CONTENT")
        
        result = verifier.verify_checksum(test_file, cs)
        
        assert result.is_valid == False
        assert len(result.mismatched_hashes) > 0
        assert result.status in [VerificationStatus.MISMATCH, VerificationStatus.CORRUPTED]
        
        print(f"  ✓ Tampering correctly detected!")
        print(f"  ✓ Mismatched hashes: {result.mismatched_hashes}")
        print(f"  ✓ Status: {result.status.value}")
    finally:
        os.unlink(test_file)


def test_hmac_authentication():
    """Test HMAC authentication feature."""
    print("Test 7: HMAC Authentication")
    
    test_content = b"Authenticated content"
    test_file = create_test_file(test_content)
    auth_key = secrets.token_bytes(32)
    
    try:
        verifier = create_secure_checksum("high")
        cs = verifier.generate_checksum(test_file, auth_key)
        
        assert cs.hmac_auth is not None
        assert cs.salt is not None
        
        # Verify with correct key
        result = verifier.verify_checksum(test_file, cs, auth_key)
        assert result.hmac_authenticated == True
        print("  ✓ Correct key - HMAC authenticated")
        
        # Verify with wrong key
        wrong_key = secrets.token_bytes(32)
        result2 = verifier.verify_checksum(test_file, cs, wrong_key)
        assert result2.hmac_authenticated == False
        print("  ✓ Wrong key - HMAC correctly rejected")
        
    finally:
        os.unlink(test_file)


def test_json_export():
    """Test JSON export functionality."""
    print("Test 8: JSON Export")
    
    verifier = create_secure_checksum("standard")
    cs = verifier.generate_checksum_from_data(b"Test data")
    
    json_str = verifier.export_checksum_json(cs)
    parsed = json.loads(json_str)
    
    assert "checksum_id" in parsed
    assert "hashes" in parsed
    assert "file_size" in parsed
    
    print("  ✓ JSON export valid")
    print(f"  ✓ Exported checksum ID: {parsed['checksum_id']}")


def test_quick_verify():
    """Test quick SHA256 verification."""
    print("Test 9: Quick SHA256 Verify")
    
    test_content = b"Quick verify test"
    test_file = create_test_file(test_content)
    
    try:
        import hashlib
        expected = hashlib.sha256(test_content).hexdigest()
        
        result = QuantumHashVerifier.quick_verify(test_file, expected)
        assert result == True
        
        result2 = QuantumHashVerifier.quick_verify(test_file, "wrong_hash")
        assert result2 == False
        
        print("  ✓ Quick verify works correctly")
    finally:
        os.unlink(test_file)


def test_multi_hash():
    """Test multi-hash computation."""
    print("Test 10: Multi-Hash Computation")
    
    data = b"Multi hash test data"
    hashes = QuantumHashVerifier.multi_hash(data)
    
    assert "sha256" in hashes
    assert "sha3_256" in hashes
    assert "blake2b" in hashes
    
    # Verify hashes are different (different algorithms)
    hash_values = list(hashes.values())
    assert len(set(hash_values)) == len(hash_values)
    
    print(f"  ✓ Computed {len(hashes)} different hashes")
    print(f"  ✓ All hash values are distinct")


def test_large_file():
    """Test with larger file."""
    print("Test 11: Larger File Handling")
    
    # 100KB test file
    large_data = secrets.token_bytes(100 * 1024)
    test_file = create_test_file(large_data)
    
    try:
        verifier = create_secure_checksum("standard")
        cs = verifier.generate_checksum(test_file)
        result = verifier.verify_checksum(test_file, cs)
        
        assert cs.file_size == 100 * 1024
        assert result.is_valid == True
        
        print(f"  ✓ 100KB file processed successfully")
        print(f"  ✓ Verification time: {result.verification_time_ms}ms")
    finally:
        os.unlink(test_file)


def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("QUANTUM-SECURE CHECKSUM - TEST SUITE")
    print("=" * 60)
    print()
    
    tests = [
        test_checksum_initialization,
        test_different_integrity_levels,
        test_checksum_generation_from_data,
        test_checksum_generation_from_file,
        test_valid_file_verification,
        test_tampered_file_detection,
        test_hmac_authentication,
        test_json_export,
        test_quick_verify,
        test_multi_hash,
        test_large_file,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
        print()
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failed > 0:
        print("\n❌ Some tests failed!")
        return False
    else:
        print("\n✅ All tests passed! Cryptography is working correctly.")
        return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
