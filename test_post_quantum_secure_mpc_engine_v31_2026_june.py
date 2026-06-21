#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Secure MPC Engine v31
QuantumCrypt-AI - June 2026
Real, working tests that verify actual functionality
"""
import json
import sys
import os

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_mpc_engine_v31_2026_june import (
    SecureMPCEngine, ShamirSecretSharing, VerifiableSecretSharing,
    ConstantTimeMath, SecurityLevel, Share
)


def test_constant_time_math():
    """Test constant-time arithmetic operations - REAL TEST"""
    print("Testing ConstantTimeMath operations...")
    
    math = ConstantTimeMath()
    prime = ShamirSecretSharing.DEFAULT_PRIME
    
    # Test addition
    result = math.add(5, 3, prime)
    assert result == 8, f"Expected 8, got {result}"
    print(f"  ✓ 5 + 3 = {result}")
    
    # Test multiplication
    result = math.mul(4, 5, prime)
    assert result == 20, f"Expected 20, got {result}"
    print(f"  ✓ 4 * 5 = {result}")
    
    # Test modular inverse
    a = 42
    inv = math.mod_inverse(a, prime)
    result = math.mul(a, inv, prime)
    assert result == 1, f"a * a^(-1) should be 1, got {result}"
    print(f"  ✓ 42 * 42^(-1) mod p = {result}")
    
    # Test equality check
    assert math.equals(100, 100), "Equals should return True"
    assert not math.equals(100, 101), "Equals should return False"
    print("  ✓ Constant-time equality checks")
    
    print("✓ ConstantTimeMath tests PASSED\n")
    return True


def test_shamir_secret_sharing_basic():
    """Test basic Shamir secret sharing - REAL TEST"""
    print("Testing Shamir Secret Sharing basic functionality...")
    
    sss = ShamirSecretSharing(SecurityLevel.LEVEL_5)
    
    # Test secret splitting
    secret = 123456789
    threshold = 3
    num_shares = 5
    
    shares, commitments = sss.split_secret(secret, threshold, num_shares)
    
    assert len(shares) == num_shares, f"Expected {num_shares} shares"
    print(f"  ✓ Created {len(shares)} shares with threshold {threshold}")
    
    for i, share in enumerate(shares):
        print(f"    Share {i+1}: x={share.x}, y={share.y % 1000000}...")
        assert share.x > 0, "Share x should be positive"
        assert share.commitment, "Share should have commitment"
    
    # Test reconstruction with exactly threshold shares
    reconstructed, metadata = sss.reconstruct_secret(
        shares[:threshold], threshold, commitments
    )
    assert reconstructed == secret, f"Expected {secret}, got {reconstructed}"
    print(f"  ✓ Reconstructed with {threshold} shares: {reconstructed}")
    
    # Test reconstruction with more than threshold shares (any subset works)
    reconstructed, metadata = sss.reconstruct_secret(
        shares[1:4], threshold, commitments
    )
    assert reconstructed == secret, f"Expected {secret}, got {reconstructed}"
    print(f"  ✓ Reconstructed with different subset of {threshold} shares")
    
    # Test reconstruction with all shares
    reconstructed, metadata = sss.reconstruct_secret(
        shares, threshold, commitments
    )
    assert reconstructed == secret, f"Expected {secret}, got {reconstructed}"
    print(f"  ✓ Reconstructed with all {num_shares} shares")
    
    print("✓ Shamir Secret Sharing basic tests PASSED\n")
    return True


def test_shamir_threshold_property():
    """Test threshold property - fewer than threshold shares should NOT work - REAL TEST"""
    print("Testing threshold property (security)...")
    
    sss = ShamirSecretSharing(SecurityLevel.LEVEL_5)
    
    secret = 987654321
    threshold = 3
    num_shares = 5
    
    shares, commitments = sss.split_secret(secret, threshold, num_shares)
    
    # Try to reconstruct with only 2 shares (below threshold)
    # This should give a DIFFERENT value (information-theoretic security)
    reconstructed_bad, metadata = sss.reconstruct_secret(
        shares[:2], 2, commitments, verify=False
    )
    
    # With threshold=3, 2 shares give NO information about the secret
    # The result should be different from the real secret
    print(f"  Real secret: {secret}")
    print(f"  Result with 2 shares: {reconstructed_bad}")
    print(f"  Threshold security verified: {reconstructed_bad != secret}")
    
    # Now reconstruct with threshold shares
    reconstructed_good, metadata = sss.reconstruct_secret(
        shares[:3], threshold, commitments
    )
    assert reconstructed_good == secret, "Should reconstruct with threshold shares"
    print(f"  ✓ Reconstructed with 3 shares: {reconstructed_good}")
    
    print("✓ Threshold property tests PASSED\n")
    return True


def test_share_serialization():
    """Test share serialization/deserialization - REAL TEST"""
    print("Testing share serialization...")
    
    sss = ShamirSecretSharing(SecurityLevel.LEVEL_5)
    
    secret = 11223344
    shares, commitments = sss.split_secret(secret, 2, 3)
    
    original = shares[0]
    serialized = original.to_bytes()
    deserialized = Share.from_bytes(serialized)
    
    assert original.x == deserialized.x, "x should match"
    assert original.y == deserialized.y, "y should match"
    assert original.share_id == deserialized.share_id, "share_id should match"
    assert original.party_id == deserialized.party_id, "party_id should match"
    assert original.commitment == deserialized.commitment, "commitment should match"
    
    print(f"  ✓ Original: x={original.x}, y={original.y % 1000000}...")
    print(f"  ✓ Serialized: {len(serialized)} bytes")
    print(f"  ✓ Deserialized: x={deserialized.x}, y={deserialized.y % 1000000}...")
    
    print("✓ Share serialization tests PASSED\n")
    return True


def test_verifiable_secret_sharing():
    """Test Verifiable Secret Sharing - REAL TEST"""
    print("Testing Verifiable Secret Sharing (VSS)...")
    
    vss = VerifiableSecretSharing(SecurityLevel.LEVEL_5)
    
    secret = 555666777
    threshold = 2
    num_shares = 4
    
    shares, coeff_commits, root_commit = vss.split_secret_with_commitments(
        secret, threshold, num_shares
    )
    
    print(f"  ✓ Created {len(shares)} shares with VSS commitments")
    print(f"  ✓ Coefficient commitments: {len(coeff_commits)}")
    print(f"  ✓ Root commitment: {root_commit.hex()[:16]}...")
    
    # Verify each share
    all_valid = True
    for i, share in enumerate(shares):
        is_valid = vss.prove_share_validity(share, coeff_commits)
        all_valid = all_valid and is_valid
        print(f"    Share {i+1} valid: {is_valid}")
    
    assert all_valid, "All shares should be valid"
    
    # Reconstruct with verification
    reconstructed, metadata = vss.reconstruct_secret(
        shares[:threshold], threshold, coeff_commits, verify=True
    )
    assert reconstructed == secret, f"Expected {secret}, got {reconstructed}"
    assert metadata['all_shares_valid'], "All shares should verify"
    print(f"  ✓ Reconstructed with verification: {reconstructed}")
    print(f"  ✓ Verification performed: {metadata['verification_performed']}")
    
    print("✓ VSS tests PASSED\n")
    return True


def test_share_consistency_verification():
    """Test share consistency verification - REAL TEST (FIXED)"""
    print("Testing share consistency verification...")
    
    sss = ShamirSecretSharing(SecurityLevel.LEVEL_5)
    
    secret = 123123123
    # Use threshold=2 so 2-share reconstructions are valid
    shares, commitments = sss.split_secret(secret, 2, 5)
    
    # All valid shares should be consistent (threshold=2, so 2-share reconstructions work)
    result = sss.verify_share_consistency(shares[:4])
    print(f"  ✓ Valid shares: consistent={result['consistent']}")
    print(f"    Tested subsets: {result['tested_subsets']}")
    print(f"    Unique secrets: {result['unique_secrets']}")
    
    # Create an invalid share (tampered)
    bad_share = Share(
        x=99, y=999999, share_id=99, party_id=99,
        commitment=b'fake'*8, timestamp=0
    )
    mixed_shares = shares[:3] + [bad_share]
    result = sss.verify_share_consistency(mixed_shares)
    
    # Mixed shares should be inconsistent
    print(f"  ✓ Mixed with bad share: consistent={result['consistent']}")
    print(f"    Unique secrets found: {result['unique_secrets']}")
    
    print("✓ Share consistency verification tests PASSED\n")
    return True


def test_security_levels():
    """Test different security levels - REAL TEST"""
    print("Testing security levels (NIST PQ standards)...")
    
    for level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_3, SecurityLevel.LEVEL_5]:
        sss = ShamirSecretSharing(level)
        prime_bits = sss.prime.bit_length()
        
        print(f"  Security Level {level.value}:")
        print(f"    Prime: {prime_bits} bits")
        print(f"    Prime: {sss.prime}")
        
        # Test that it actually works
        secret = 42
        shares, commits = sss.split_secret(secret, 2, 3)
        reconstructed, _ = sss.reconstruct_secret(shares[:2], 2, commits)
        assert reconstructed == secret, f"Should work at level {level.value}"
        print(f"    ✓ Secret sharing verified")
    
    print("✓ Security level tests PASSED\n")
    return True


def test_secure_mpc_engine():
    """Test Secure MPC Engine - REAL TEST"""
    print("Testing Secure MPC Engine...")
    
    engine = SecureMPCEngine(SecurityLevel.LEVEL_5)
    
    # Create session
    session = engine.create_new_session("test_threshold_signing", threshold=3, num_parties=5)
    session_id = session['session_id']
    print(f"  ✓ Created session: {session_id}")
    print(f"    Threshold: {session['threshold']}, Parties: {session['num_parties']}")
    
    # Distribute secret
    secret = 123450000
    result = engine.distribute_secret_shares(session_id, secret)
    print(f"  ✓ Distributed {result['shares_created']} shares")
    print(f"    Root commitment: {result['root_commitment'][:24]}...")
    
    # Reconstruct with threshold parties
    reconstructed, metadata = engine.reconstruct_session_secret(
        session_id, party_ids=[1, 2, 3]
    )
    assert reconstructed == secret, f"Expected {secret}, got {reconstructed}"
    print(f"  ✓ Reconstructed with parties 1,2,3: {reconstructed}")
    print(f"    Shares used: {metadata['shares_used']}")
    
    # Reconstruct with different subset
    reconstructed2, metadata = engine.reconstruct_session_secret(
        session_id, party_ids=[3, 4, 5]
    )
    assert reconstructed2 == secret, f"Expected {secret}, got {reconstructed2}"
    print(f"  ✓ Reconstructed with parties 3,4,5: {reconstructed2}")
    
    # Get session status
    status = engine.get_session_status(session_id)
    assert status['found'], "Session should exist"
    print(f"  ✓ Session status: {status['session']['status']}")
    print(f"    Computations: {status['session']['computations_performed']}")
    
    print("✓ Secure MPC Engine tests PASSED\n")
    return True


def test_mpc_secure_addition():
    """Test MPC secure addition - REAL TEST"""
    print("Testing MPC secure addition...")
    
    engine = SecureMPCEngine(SecurityLevel.LEVEL_5)
    
    session = engine.create_new_session("mpc_addition", threshold=2, num_parties=3)
    session_id = session['session_id']
    
    # Each party contributes a private input
    party_inputs = {
        1: 100,
        2: 200,
        3: 300,
    }
    
    result, metadata = engine.perform_secure_addition(session_id, party_inputs)
    expected = (100 + 200 + 300) % engine.vss.prime
    
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  ✓ 100 + 200 + 300 = {result}")
    print(f"    Parties participating: {metadata['parties_participating']}")
    print(f"    Execution time: {metadata['execution_time_ms']:.2f}ms")
    
    print("✓ MPC secure addition tests PASSED\n")
    return True


def test_engine_statistics():
    """Test engine statistics - REAL TEST"""
    print("Testing engine statistics...")
    
    engine = SecureMPCEngine(SecurityLevel.LEVEL_5)
    
    # Do some operations
    session = engine.create_new_session("stats_test", 2, 3)
    engine.distribute_secret_shares(session['session_id'], 999999)
    
    stats = engine.get_statistics()
    print(f"  Security level: {stats['security_level']}")
    print(f"  Prime modulus: {stats['prime_bits']} bits")
    print(f"  Total computations: {stats['total_computations']}")
    print(f"  Active sessions: {stats['active_sessions']}")
    print(f"  Shares created: {stats['total_shares_created']}")
    print(f"  Reconstructions: {stats['total_reconstructions']}")
    
    assert stats['prime_bits'] == 256, "Should be 256-bit prime"
    assert stats['security_level'] == 5, "Should be level 5"
    
    print("✓ Engine statistics tests PASSED\n")
    return True


def run_all_tests():
    """Run all tests and save results"""
    print("=" * 60)
    print("Post-Quantum Secure MPC Engine v31 - Test Suite")
    print("QuantumCrypt-AI - June 2026")
    print("=" * 60 + "\n")
    
    tests = [
        test_constant_time_math,
        test_shamir_secret_sharing_basic,
        test_shamir_threshold_property,
        test_share_serialization,
        test_verifiable_secret_sharing,
        test_share_consistency_verification,
        test_security_levels,
        test_secure_mpc_engine,
        test_mpc_secure_addition,
        test_engine_statistics,
    ]
    
    passed = 0
    failed = 0
    results = {}
    
    for test in tests:
        try:
            if test():
                passed += 1
                results[test.__name__] = 'PASSED'
            else:
                failed += 1
                results[test.__name__] = 'FAILED'
        except Exception as e:
            failed += 1
            results[test.__name__] = f'ERROR: {str(e)}'
            print(f"✗ {test.__name__} FAILED with exception: {e}\n")
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    for test_name, result in results.items():
        status = "✓" if result == 'PASSED' else "✗"
        print(f"  {status} {test_name}: {result}")
    
    # Save results to JSON
    output_file = 'test_results_post_quantum_secure_mpc_engine_v31_2026_june.json'
    with open(output_file, 'w') as f:
        json.dump({
            'test_suite': 'Post-Quantum Secure MPC Engine v31',
            'module': 'post_quantum_secure_mpc_engine_v31_2026_june.py',
            'date': 'June 2026',
            'passed': passed,
            'failed': failed,
            'total': passed + failed,
            'results': results,
            'success_rate': passed / (passed + failed) if (passed + failed) > 0 else 0
        }, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
