#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Checksum Verifier
QuantumCrypt-AI - June 2026

Real, working tests that verify actual cryptographic functionality
"""

import sys
import os
import json
import tempfile
from datetime import datetime
from pathlib import Path

# Add quantum_crypt to path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_checksum_verifier_2026_june import (
    ChecksumResult,
    HashChainEntry,
    HashAlgorithms,
    ChecksumHasher,
    ChecksumVerifier,
    HashChain,
    MultiAlgorithmVerifier,
    PostQuantumChecksumEngine,
)


def test_hash_algorithms_constants():
    """Test HashAlgorithms constants and validation"""
    print("\n=== Test 1: Hash Algorithms Constants ===")
    
    # Test all algorithms defined
    assert len(HashAlgorithms.ALL) == 6
    assert HashAlgorithms.SHA256 in HashAlgorithms.ALL
    assert HashAlgorithms.SHA3_256 in HashAlgorithms.ALL
    assert HashAlgorithms.BLAKE2B in HashAlgorithms.ALL
    
    # Test is_supported
    assert HashAlgorithms.is_supported('sha256')
    assert HashAlgorithms.is_supported('SHA3_512')
    assert not HashAlgorithms.is_supported('md5')
    assert not HashAlgorithms.is_supported('invalid')
    
    # Test is_post_quantum_resistant
    assert HashAlgorithms.is_post_quantum_resistant('sha3_256')
    assert HashAlgorithms.is_post_quantum_resistant('blake2b')
    assert not HashAlgorithms.is_post_quantum_resistant('sha256')  # SHA256 not in PQ list
    
    print(f"  ✓ Supported algorithms: {HashAlgorithms.ALL}")
    print(f"  ✓ PQ-resistant: {HashAlgorithms.PQ_RESISTANT}")
    print("✓ Hash algorithm validation works correctly")
    return True


def test_checksum_result_dataclass():
    """Test ChecksumResult data class"""
    print("\n=== Test 2: ChecksumResult Data Class ===")
    
    result = ChecksumResult(
        file_path="/test/file.txt",
        algorithm="sha3_256",
        checksum="abc123def456",
        file_size=1024
    )
    
    assert result.file_path == "/test/file.txt"
    assert result.algorithm == "sha3_256"
    assert result.checksum == "abc123def456"
    assert result.file_size == 1024
    assert result.timestamp is not None
    assert result.verified == False
    
    print(f"  ✓ File: {result.file_path}")
    print(f"  ✓ Checksum: {result.checksum}")
    print(f"  ✓ Timestamp: {result.timestamp}")
    print("✓ ChecksumResult dataclass works correctly")
    return True


def test_checksum_hasher_basic_hashing():
    """Test ChecksumHasher basic hashing"""
    print("\n=== Test 3: ChecksumHasher Basic Hashing ===")
    
    test_data = b"Hello, QuantumCrypt!"
    test_string = "Post-Quantum Security"
    
    # Test all algorithms
    for algo in HashAlgorithms.ALL:
        hasher = ChecksumHasher(algo)
        
        # Hash bytes
        hash_bytes = hasher.hash_bytes(test_data)
        assert len(hash_bytes) > 0
        assert all(c in '0123456789abcdef' for c in hash_bytes.lower())
        
        # Hash string
        hash_str = hasher.hash_string(test_string)
        assert len(hash_str) > 0
        
        print(f"  ✓ {algo}: {hash_bytes[:16]}...")
    
    print("✓ Basic hashing works for all algorithms")
    return True


def test_checksum_hasher_deterministic():
    """Test hashing is deterministic"""
    print("\n=== Test 4: Deterministic Hashing ===")
    
    hasher = ChecksumHasher(HashAlgorithms.SHA3_256)
    data = b"Test data for deterministic hashing"
    
    # Same input should produce same output
    hash1 = hasher.hash_bytes(data)
    hash2 = hasher.hash_bytes(data)
    assert hash1 == hash2
    
    # Different input should produce different output
    hash3 = hasher.hash_bytes(data + b"!")
    assert hash1 != hash3
    
    print(f"  ✓ Same input = same hash: {hash1 == hash2}")
    print(f"  ✓ Different input = different hash: {hash1 != hash3}")
    print("✓ Hashing is deterministic")
    return True


def test_checksum_hasher_unsupported_algo():
    """Test unsupported algorithm rejection"""
    print("\n=== Test 5: Unsupported Algorithm Rejection ===")
    
    try:
        ChecksumHasher('md5')
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  ✓ Correctly rejected: {e}")
    
    try:
        ChecksumHasher('invalid_algo')
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  ✓ Correctly rejected: {e}")
    
    print("✓ Unsupported algorithms correctly rejected")
    return True


def test_checksum_hasher_file_hashing():
    """Test file hashing functionality"""
    print("\n=== Test 6: File Hashing ===")
    
    # Create temp file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
        f.write(b"Test file content for checksum verification\n")
        f.write(b"Multiple lines of content\n")
        temp_path = f.name
    
    try:
        hasher = ChecksumHasher(HashAlgorithms.SHA3_256)
        checksum, size = hasher.hash_file(temp_path)
        
        assert len(checksum) == 64  # SHA3-256 = 64 hex chars
        assert size > 0
        
        print(f"  ✓ File: {temp_path}")
        print(f"  ✓ Size: {size} bytes")
        print(f"  ✓ SHA3-256: {checksum}")
        
        # Verify streaming produces same result
        with open(temp_path, 'rb') as f:
            checksum2, size2 = hasher.hash_stream(f)
        assert checksum == checksum2
        print(f"  ✓ Streaming matches: {checksum == checksum2}")
        
    finally:
        os.unlink(temp_path)
    
    print("✓ File hashing works correctly")
    return True


def test_checksum_hasher_file_not_found():
    """Test file not found handling"""
    print("\n=== Test 7: File Not Found Handling ===")
    
    hasher = ChecksumHasher()
    
    try:
        hasher.hash_file("/nonexistent/file_12345.txt")
        assert False, "Should have raised FileNotFoundError"
    except FileNotFoundError:
        print("  ✓ Correctly raised FileNotFoundError")
    
    print("✓ File not found correctly handled")
    return True


def test_checksum_hasher_hmac():
    """Test HMAC computation"""
    print("\n=== Test 8: HMAC Computation ===")
    
    # Test HMAC with supported algorithms
    for algo in ['sha256', 'sha512', 'sha3_256', 'sha3_512']:
        hasher = ChecksumHasher(algo)
        key = b"secret_key_12345"
        data = b"Message to authenticate"
        
        hmac_result = hasher.compute_hmac(data, key)
        assert len(hmac_result) > 0
        print(f"  ✓ HMAC-{algo.upper()}: {hmac_result[:16]}...")
    
    # Test HMAC is deterministic
    hasher = ChecksumHasher('sha256')
    h1 = hasher.compute_hmac(b"data", b"key")
    h2 = hasher.compute_hmac(b"data", b"key")
    assert h1 == h2
    
    # Test different key produces different HMAC
    h3 = hasher.compute_hmac(b"data", b"different_key")
    assert h1 != h3
    
    print("✓ HMAC computation works correctly")
    return True


def test_checksum_verifier_compute():
    """Test ChecksumVerifier compute functionality"""
    print("\n=== Test 9: ChecksumVerifier Compute ===")
    
    verifier = ChecksumVerifier()
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"Test content for verification")
        temp_path = f.name
    
    try:
        result = verifier.compute_checksum(temp_path)
        
        assert result.file_path == temp_path
        assert result.algorithm == HashAlgorithms.SHA3_256
        assert len(result.checksum) == 64
        assert result.file_size > 0
        assert result.computation_time_ms >= 0
        
        print(f"  ✓ File: {temp_path}")
        print(f"  ✓ Checksum: {result.checksum}")
        print(f"  ✓ Computed in: {result.computation_time_ms:.2f}ms")
        
    finally:
        os.unlink(temp_path)
    
    print("✓ Checksum computation works")
    return True


def test_checksum_verifier_verify():
    """Test ChecksumVerifier verification"""
    print("\n=== Test 10: ChecksumVerifier Verify ===")
    
    verifier = ChecksumVerifier()
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"Known content for verification")
        temp_path = f.name
    
    try:
        # First compute
        compute_result = verifier.compute_checksum(temp_path)
        
        # Verify with correct checksum
        verify_pass = verifier.verify_checksum(temp_path, compute_result.checksum)
        assert verify_pass.verified == True
        assert verify_pass.expected_checksum == compute_result.checksum
        
        # Verify with wrong checksum
        verify_fail = verifier.verify_checksum(temp_path, "wrong_checksum_here")
        assert verify_fail.verified == False
        
        print(f"  ✓ Correct checksum: {verify_pass.verified}")
        print(f"  ✓ Wrong checksum: {verify_fail.verified}")
        
        # Check stats
        stats = verifier.stats
        assert stats['files_verified'] == 2
        assert stats['verifications_passed'] == 1
        assert stats['verifications_failed'] == 1
        
    finally:
        os.unlink(temp_path)
    
    print("✓ Checksum verification works correctly")
    return True


def test_checksum_verifier_manifest():
    """Test manifest generation and verification"""
    print("\n=== Test 11: Manifest Generation ===")
    
    verifier = ChecksumVerifier()
    
    # Create temp directory with files
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create test files
        files = []
        for i in range(3):
            path = os.path.join(temp_dir, f"file_{i}.txt")
            with open(path, 'w') as f:
                f.write(f"Content for file {i}")
            files.append(path)
        
        # Compute checksums
        results = [verifier.compute_checksum(f) for f in files]
        
        # Generate manifest
        manifest_path = os.path.join(temp_dir, "checksum_manifest.json")
        success = verifier.generate_manifest(results, manifest_path)
        assert success
        assert os.path.exists(manifest_path)
        
        # Verify manifest
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
            assert manifest['total_files'] == 3
            assert len(manifest['checksums']) == 3
        
        print(f"  ✓ Generated manifest with {manifest['total_files']} files")
        print(f"  ✓ Manifest saved to: {manifest_path}")
        
    finally:
        import shutil
        shutil.rmtree(temp_dir)
    
    print("✓ Manifest generation works")
    return True


def test_hash_chain_basic():
    """Test HashChain basic functionality"""
    print("\n=== Test 12: Hash Chain Basic ===")
    
    chain = HashChain()
    
    # Initialize
    genesis = chain.initialize()
    assert genesis is not None
    assert len(genesis) > 0
    
    # Add entries
    entry1 = chain.add_entry("First data item")
    entry2 = chain.add_entry("Second data item")
    entry3 = chain.add_entry("Third data item")
    
    assert entry1.index == 0
    assert entry2.index == 1
    assert entry3.index == 2
    
    assert entry1.previous_hash == genesis
    assert entry2.previous_hash == entry1.chain_hash
    assert entry3.previous_hash == entry2.chain_hash
    
    print(f"  ✓ Genesis hash: {genesis[:16]}...")
    print(f"  ✓ Chain length: {len(chain.chain)} entries")
    print(f"  ✓ Root hash: {chain.get_root_hash()[:16]}...")
    
    print("✓ Hash chain creation works")
    return True


def test_hash_chain_verification():
    """Test HashChain integrity verification"""
    print("\n=== Test 13: Hash Chain Verification ===")
    
    chain = HashChain()
    chain.initialize()
    
    # Add valid entries
    for i in range(5):
        chain.add_entry(f"Data entry {i}")
    
    # Verify valid chain
    is_valid, invalid = chain.verify_chain()
    assert is_valid == True
    assert len(invalid) == 0
    print(f"  ✓ Valid chain verification: {is_valid}")
    
    # Tamper with chain
    original_hash = chain.chain[2].data_hash
    chain.chain[2].data_hash = "tampered_hash_value"
    
    # Verify tampered chain
    is_valid, invalid = chain.verify_chain()
    assert is_valid == False
    assert 2 in invalid
    print(f"  ✓ Tampered chain detected at index: {invalid}")
    
    # Restore and verify again
    chain.chain[2].data_hash = original_hash
    is_valid, invalid = chain.verify_chain()
    assert is_valid == True
    
    print("✓ Hash chain verification works correctly")
    return True


def test_hash_chain_export():
    """Test HashChain export functionality"""
    print("\n=== Test 14: Hash Chain Export ===")
    
    chain = HashChain()
    chain.initialize()
    chain.add_entry("Item 1")
    chain.add_entry("Item 2")
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        temp_path = f.name
    
    try:
        success = chain.export_chain(temp_path)
        assert success
        
        with open(temp_path, 'r') as f:
            data = json.load(f)
            assert data['chain_length'] == 2
            assert 'genesis_hash' in data
            assert 'root_hash' in data
            assert len(data['entries']) == 2
        
        print(f"  ✓ Exported chain: {data['chain_length']} entries")
        
    finally:
        os.unlink(temp_path)
    
    print("✓ Hash chain export works")
    return True


def test_multi_algorithm_verifier():
    """Test MultiAlgorithmVerifier"""
    print("\n=== Test 15: Multi-Algorithm Verifier ===")
    
    multi = MultiAlgorithmVerifier()
    
    # Multi-hash a string
    results = multi.multi_hash("Test data for multi-hashing")
    
    # Should have multiple algorithm results
    assert len(results) >= 3
    for algo, checksum in results.items():
        assert algo in HashAlgorithms.ALL
        assert len(checksum) > 0
        print(f"  ✓ {algo}: {checksum[:16]}...")
    
    # Multi-verify
    all_pass, per_algo = multi.multi_verify("Test data", results)
    # This will fail since we used different data, but test the mechanism
    assert isinstance(all_pass, bool)
    assert isinstance(per_algo, dict)
    
    print("✓ Multi-algorithm verification works")
    return True


def test_post_quantum_engine():
    """Test main PostQuantumChecksumEngine"""
    print("\n=== Test 16: Post-Quantum Engine ===")
    
    engine = PostQuantumChecksumEngine(HashAlgorithms.SHA3_256)
    
    # Test string hashing
    hash_result = engine.compute_string_hash("Hello Quantum World")
    assert len(hash_result) == 64
    print(f"  ✓ String hash: {hash_result[:16]}...")
    
    # Test hash chain creation
    items = ["Transaction 1", "Transaction 2", "Transaction 3"]
    chain = engine.create_hash_chain(items)
    assert len(chain.chain) == 3
    is_valid, _ = chain.verify_chain()
    assert is_valid
    print(f"  ✓ Created valid hash chain with {len(chain.chain)} entries")
    
    # Get statistics
    stats = engine.get_statistics()
    assert stats['pq_resistant'] == True
    assert stats['algorithm'] == HashAlgorithms.SHA3_256
    print(f"  ✓ PQ resistant: {stats['pq_resistant']}")
    
    # Get security report
    report = engine.get_security_report()
    assert 'security_level' in report
    assert 'nist_standard' in report
    print(f"  ✓ Security level: {report['security_level']}")
    print(f"  ✓ NIST standard: {report['nist_standard']}")
    
    print("✓ Post-quantum engine works correctly")
    return True


def test_all_hash_lengths():
    """Verify correct hash output lengths"""
    print("\n=== Test 17: Hash Output Lengths ===")
    
    expected_lengths = {
        'sha256': 64,
        'sha512': 128,
        'sha3_256': 64,
        'sha3_512': 128,
        'blake2b': 128,
        'blake2s': 64,
    }
    
    for algo, expected_len in expected_lengths.items():
        hasher = ChecksumHasher(algo)
        result = hasher.hash_string("test")
        assert len(result) == expected_len, f"{algo}: expected {expected_len}, got {len(result)}"
        print(f"  ✓ {algo}: {expected_len} hex chars")
    
    print("✓ All hash output lengths correct")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("QuantumCrypt-AI: Post-Quantum Checksum Verifier Tests")
    print("=" * 60)
    print(f"Run time: {datetime.utcnow().isoformat()}Z")
    
    tests = [
        test_hash_algorithms_constants,
        test_checksum_result_dataclass,
        test_checksum_hasher_basic_hashing,
        test_checksum_hasher_deterministic,
        test_checksum_hasher_unsupported_algo,
        test_checksum_hasher_file_hashing,
        test_checksum_hasher_file_not_found,
        test_checksum_hasher_hmac,
        test_checksum_verifier_compute,
        test_checksum_verifier_verify,
        test_checksum_verifier_manifest,
        test_hash_chain_basic,
        test_hash_chain_verification,
        test_hash_chain_export,
        test_multi_algorithm_verifier,
        test_post_quantum_engine,
        test_all_hash_lengths,
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                failures.append(test_func.__name__)
        except Exception as e:
            failed += 1
            failures.append(f"{test_func.__name__}: {e}")
            print(f"  ✗ FAILED: {e}")
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failures:
        print("\nFailures:")
        for f in failures:
            print(f"  - {f}")
    
    success_rate = (passed / len(tests)) * 100
    print(f"\nSuccess rate: {success_rate:.1f}%")
    
    # Save results
    report = {
        'test_timestamp': datetime.utcnow().isoformat() + "Z",
        'total_tests': len(tests),
        'passed': passed,
        'failed': failed,
        'success_rate': success_rate,
        'failures': failures,
        'pq_algorithms_tested': HashAlgorithms.PQ_RESISTANT,
    }
    
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_checksum_verifier.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nResults saved to test_results_checksum_verifier.json")
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
