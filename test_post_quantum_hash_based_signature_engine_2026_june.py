#!/usr/bin/env python3
"""
Test Suite for QuantumCrypt-AI Post-Quantum Hash-Based Signature Engine
June 2026 - Production-grade testing
"""

import sys
import os
import json
import time

# Add the quantum_crypt directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_hash_based_signature_engine_2026_june import (
    PostQuantumHashBasedSigner,
    HashAlgorithm,
    SecurityLevel,
    LamportKeyPair,
    run_hash_signature_demo
)


def test_signer_initialization():
    """Test signer initialization with various parameters."""
    print("[TEST 1] Testing Signer Initialization...")
    
    signer = PostQuantumHashBasedSigner(
        hash_algorithm=HashAlgorithm.SHA256,
        security_level=SecurityLevel.LEVEL_5
    )
    
    assert signer.hash_alg == HashAlgorithm.SHA256
    assert signer.security_level == SecurityLevel.LEVEL_5
    assert signer.hash_size == 32  # 256 bits = 32 bytes
    
    print("  ✓ Initialization successful")
    print(f"  ✓ Hash size: {signer.hash_size} bytes")
    return True


def test_hash_algorithms():
    """Test all hash algorithm options."""
    print("[TEST 2] Testing Hash Algorithms...")
    
    for alg in [HashAlgorithm.SHA256, HashAlgorithm.SHA3_256, HashAlgorithm.BLAKE2b]:
        signer = PostQuantumHashBasedSigner(hash_algorithm=alg)
        test_data = b"test data"
        result = signer._hash(test_data)
        assert len(result) > 0
        print(f"  ✓ {alg.value}: {len(result)} bytes")
    
    return True


def test_security_levels():
    """Test all security levels."""
    print("[TEST 3] Testing Security Levels...")
    
    for level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_3, SecurityLevel.LEVEL_5]:
        signer = PostQuantumHashBasedSigner(security_level=level)
        assert signer.security_level == level
        assert signer.hash_size == level.value // 8
        print(f"  ✓ {level.name}: {level.value} bits, {signer.hash_size} bytes")
    
    return True


def test_lamport_key_generation():
    """Test Lamport key pair generation."""
    print("[TEST 4] Testing Lamport Key Generation...")
    
    signer = PostQuantumHashBasedSigner(security_level=SecurityLevel.LEVEL_1)
    keypair = signer.generate_lamport_keypair()
    
    assert isinstance(keypair, LamportKeyPair)
    assert len(keypair.private_key) == 128  # 128 bits for Level 1
    assert len(keypair.public_key) == 128
    assert keypair.used == False
    
    # Check each key has 2 secrets
    assert len(keypair.private_key[0]) == 2
    assert len(keypair.public_key[0]) == 2
    
    print(f"  ✓ Generated {len(keypair.private_key)} bit key pair")
    print(f"  ✓ Key pair marked as unused")
    return True


def test_lamport_sign_and_verify():
    """Test Lamport signature and verification."""
    print("[TEST 5] Testing Lamport Sign and Verify...")
    
    signer = PostQuantumHashBasedSigner(security_level=SecurityLevel.LEVEL_1)
    keypair = signer.generate_lamport_keypair()
    
    message = b"Test message for Lamport signature"
    signature = signer.lamport_sign(message, keypair)
    
    assert keypair.used == True  # Should be marked as used
    assert len(signature.signature) == 128
    
    # Valid verification
    valid = signer.lamport_verify(message, signature, keypair.public_key)
    assert valid == True
    print("  ✓ Valid signature verified correctly")
    
    # Invalid message should fail
    bad_message = b"Tampered message!"
    invalid = signer.lamport_verify(bad_message, signature, keypair.public_key)
    assert invalid == False
    print("  ✓ Tampered message rejected correctly")
    
    return True


def test_lamport_key_reuse_prevention():
    """Test that Lamport keys cannot be reused."""
    print("[TEST 6] Testing Lamport Key Reuse Prevention...")
    
    signer = PostQuantumHashBasedSigner(security_level=SecurityLevel.LEVEL_1)
    keypair = signer.generate_lamport_keypair()
    
    # First signature should work
    message1 = b"First message"
    signer.lamport_sign(message1, keypair)
    assert keypair.used == True
    
    # Second signature should raise ValueError
    try:
        message2 = b"Second message - should fail!"
        signer.lamport_sign(message2, keypair)
        print("  ✗ ERROR: Key reuse was not prevented!")
        return False
    except ValueError as e:
        print(f"  ✓ Key reuse correctly prevented: {e}")
        return True


def test_merkle_tree_generation():
    """Test Merkle tree generation."""
    print("[TEST 7] Testing Merkle Tree Generation...")
    
    signer = PostQuantumHashBasedSigner(security_level=SecurityLevel.LEVEL_1)
    root, keypairs, tree = signer.generate_merkle_tree(num_leaves=8)
    
    assert len(keypairs) == 8
    assert len(root) == 32  # SHA256 hash
    assert len(tree) > 8  # Tree has leaves + internal nodes
    
    print(f"  ✓ Generated tree with 8 leaves")
    print(f"  ✓ Root hash: {root[:8].hex()}...")
    print(f"  ✓ Total tree nodes: {len(tree)}")
    return True


def test_merkle_sign_and_verify():
    """Test Merkle signature and verification."""
    print("[TEST 8] Testing Merkle Sign and Verify...")
    
    signer = PostQuantumHashBasedSigner(security_level=SecurityLevel.LEVEL_1)
    root, keypairs, tree = signer.generate_merkle_tree(num_leaves=8)
    
    message = b"Test message for Merkle signature"
    signature = signer.merkle_sign(message, keypairs, tree, 3)
    
    assert signature.leaf_index == 3
    assert len(signature.authentication_path) == 3  # log2(8) = 3
    
    valid = signer.merkle_verify(message, signature, keypairs[3].public_key)
    assert valid == True
    print("  ✓ Valid Merkle signature verified correctly")
    
    # Wrong public key should fail
    invalid = signer.merkle_verify(message, signature, keypairs[0].public_key)
    assert invalid == False
    print("  ✓ Wrong public key rejected correctly")
    
    return True


def test_constant_time_compare():
    """Test constant-time comparison function."""
    print("[TEST 9] Testing Constant-Time Comparison...")
    
    signer = PostQuantumHashBasedSigner()
    
    # Equal bytes should return True
    assert signer._constant_time_compare(b"test", b"test") == True
    
    # Different bytes should return False
    assert signer._constant_time_compare(b"test", b"tesx") == False
    
    # Different lengths should return False
    assert signer._constant_time_compare(b"test", b"test1") == False
    
    print("  ✓ Constant-time comparison working correctly")
    return True


def test_security_properties():
    """Test security properties report."""
    print("[TEST 10] Testing Security Properties...")
    
    signer = PostQuantumHashBasedSigner()
    props = signer.get_security_properties()
    
    assert "post_quantum_secure" in props
    assert props["post_quantum_secure"] == True
    assert "quantum_resistance" in props
    assert "limitations" in props
    assert len(props["limitations"]) > 0
    
    print(f"  ✓ Post-quantum secure: {props['post_quantum_secure']}")
    print(f"  ✓ Quantum resistance: {props['quantum_resistance']}")
    print(f"  ✓ Limitations documented: {len(props['limitations'])} items")
    return True


def run_all_tests():
    """Run all test cases and generate report."""
    print("=" * 70)
    print("QuantumCrypt-AI Post-Quantum Hash-Based Signature - Test Suite")
    print("=" * 70)
    print(f"Test Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    tests = [
        test_signer_initialization,
        test_hash_algorithms,
        test_security_levels,
        test_lamport_key_generation,
        test_lamport_sign_and_verify,
        test_lamport_key_reuse_prevention,
        test_merkle_tree_generation,
        test_merkle_sign_and_verify,
        test_constant_time_compare,
        test_security_properties,
    ]
    
    passed = 0
    failed = 0
    failures = []
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                failures.append(test.__name__)
        except Exception as e:
            failed += 1
            failures.append(f"{test.__name__}: {str(e)}")
            print(f"  ✗ FAILED: {e}")
    
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total Tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/len(tests)*100):.1f}%")
    
    if failures:
        print("\nFailed Tests:")
        for f in failures:
            print(f"  - {f}")
    
    print()
    
    # Run demo
    print("=" * 70)
    print("RUNNING DEMO")
    print("=" * 70)
    try:
        run_hash_signature_demo()
    except Exception as e:
        print(f"Demo completed with: {e}")
    
    # Save test results
    results = {
        "test_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": f"{(passed/len(tests)*100):.1f}%",
        "failures": failures,
        "module": "post_quantum_hash_based_signature_engine_2026_june",
        "post_quantum_secure": True,
        "algorithms_implemented": ["Lamport-Diffie OTS", "Merkle Tree Signatures"],
        "hash_algorithms_supported": ["SHA256", "SHA3-256", "BLAKE2b"],
        "security_levels_supported": ["128-bit", "192-bit", "256-bit"]
    }
    
    with open("test_results_hash_signature.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print()
    print(f"Results saved to test_results_hash_signature.json")
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
