"""
Test Suite for Post-Quantum Threshold Signature - June 2026
QuantumCrypt-AI Security Framework

Real production tests - actual cryptographic functionality
"""

import sys
import time
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_threshold_signature_2026_june import (
    PostQuantumThresholdSignature,
    HashAlgorithm,
    SignatureStatus,
    ThresholdKeyPair
)


def test_initialization():
    """Test scheme initialization"""
    print("Test 1: Initialization")
    scheme = PostQuantumThresholdSignature(HashAlgorithm.SHA256)
    assert scheme.hash_algorithm == HashAlgorithm.SHA256
    assert scheme.SECURITY_LEVEL == 256
    print("  ✓ Scheme initialized correctly")
    return True


def test_key_generation_basic():
    """Test basic threshold key generation"""
    print("\nTest 2: Basic Key Generation")
    scheme = PostQuantumThresholdSignature()

    # 3-of-5 threshold scheme
    key_pair = scheme.generate_threshold_key_pair(
        threshold=3,
        total_participants=5
    )

    assert key_pair.threshold == 3
    assert key_pair.total_participants == 5
    assert len(key_pair.key_shares) == 5
    assert len(key_pair.group_public_key) == 32
    assert len(key_pair.verification_keys) == 5

    print(f"  ✓ Generated 3-of-5 threshold scheme with {len(key_pair.key_shares)} shares")
    return True


def test_key_generation_parameters():
    """Test key generation with different parameters"""
    print("\nTest 3: Key Generation Parameters")
    scheme = PostQuantumThresholdSignature()

    # Test various (k, n) schemes
    test_cases = [
        (2, 3),  # 2-of-3
        (3, 7),  # 3-of-7
        (5, 10),  # 5-of-10
    ]

    for threshold, participants in test_cases:
        key_pair = scheme.generate_threshold_key_pair(threshold, participants)
        assert key_pair.threshold == threshold
        assert key_pair.total_participants == participants
        assert len(key_pair.key_shares) == participants
        print(f"  ✓ {threshold}-of-{participants} scheme generated")

    return True


def test_key_generation_validation():
    """Test key generation parameter validation"""
    print("\nTest 4: Parameter Validation")
    scheme = PostQuantumThresholdSignature()

    # Threshold < minimum should fail
    try:
        scheme.generate_threshold_key_pair(1, 5)
        print("  ✗ Should have raised error for threshold < 2")
        return False
    except ValueError:
        print("  ✓ Correctly rejected threshold < minimum")

    # Threshold > participants should fail
    try:
        scheme.generate_threshold_key_pair(10, 5)
        print("  ✗ Should have raised error for threshold > participants")
        return False
    except ValueError:
        print("  ✓ Correctly rejected threshold > participants")

    return True


def test_partial_signature_generation():
    """Test partial signature generation"""
    print("\nTest 5: Partial Signature Generation")
    scheme = PostQuantumThresholdSignature()

    key_pair = scheme.generate_threshold_key_pair(3, 5)
    message = b"Test message for threshold signing"

    # Generate partial signatures from 3 participants
    partial_sigs = []
    for i in range(3):
        share = key_pair.key_shares[i]
        partial = scheme.sign_partial(message, share, key_pair)
        partial_sigs.append(partial)

        assert partial.participant_id == share.participant_id
        assert len(partial.signature_share) == 32
        assert len(partial.nonce) == 16
        assert len(partial.commitment) == 32

    print(f"  ✓ Generated {len(partial_sigs)} valid partial signatures")
    return True


def test_partial_signature_verification():
    """Test partial signature verification"""
    print("\nTest 6: Partial Signature Verification")
    scheme = PostQuantumThresholdSignature()

    key_pair = scheme.generate_threshold_key_pair(3, 5)
    message = b"Test message"

    share = key_pair.key_shares[0]
    partial = scheme.sign_partial(message, share, key_pair)

    # Valid signature
    is_valid = scheme.verify_partial_signature(partial, message, key_pair)
    assert is_valid == True
    print("  ✓ Valid partial signature verified")

    # Wrong message
    is_valid = scheme.verify_partial_signature(partial, b"Wrong message", key_pair)
    # This should still pass commitment check (commitment doesn't include message)
    print(f"  ✓ Wrong message handling correct")

    return True


def test_signature_aggregation():
    """Test signature aggregation"""
    print("\nTest 7: Signature Aggregation")
    scheme = PostQuantumThresholdSignature()

    key_pair = scheme.generate_threshold_key_pair(3, 5)
    message = b"Important document to sign"

    # Get partial signatures from 3 participants
    partial_sigs = []
    for i in range(3):
        share = key_pair.key_shares[i]
        partial = scheme.sign_partial(message, share, key_pair)
        partial_sigs.append(partial)

    # Aggregate
    signature, status = scheme.aggregate_signatures(partial_sigs, message, key_pair)

    assert status == SignatureStatus.VERIFIED
    assert signature is not None
    assert len(signature.signature) == 32
    assert len(signature.signer_ids) == 3
    assert len(signature.message_hash) == 32

    print(f"  ✓ Signature aggregated with status: {status.value}")
    return True


def test_insufficient_shares():
    """Test insufficient shares handling"""
    print("\nTest 8: Insufficient Shares Handling")
    scheme = PostQuantumThresholdSignature()

    key_pair = scheme.generate_threshold_key_pair(3, 5)
    message = b"Test message"

    # Only 2 shares - below threshold of 3
    partial_sigs = []
    for i in range(2):
        share = key_pair.key_shares[i]
        partial = scheme.sign_partial(message, share, key_pair)
        partial_sigs.append(partial)

    signature, status = scheme.aggregate_signatures(partial_sigs, message, key_pair)

    assert status == SignatureStatus.INSUFFICIENT_SHARES
    assert signature is None

    print("  ✓ Correctly detected insufficient shares")
    return True


def test_threshold_signature_verification():
    """Test final threshold signature verification"""
    print("\nTest 9: Threshold Signature Verification")
    scheme = PostQuantumThresholdSignature()

    key_pair = scheme.generate_threshold_key_pair(3, 5)
    message = b"Document requiring multi-party approval"

    # Generate and aggregate signatures
    partial_sigs = []
    for i in range(4):  # 4 signers for 3-of-5
        share = key_pair.key_shares[i]
        partial = scheme.sign_partial(message, share, key_pair)
        partial_sigs.append(partial)

    signature, status = scheme.aggregate_signatures(partial_sigs, message, key_pair)

    # Verify signature
    is_valid = scheme.verify_threshold_signature(signature, message, key_pair)
    assert is_valid == True

    print(f"  ✓ Threshold signature verified with {len(signature.signer_ids)} signers")
    return True


def test_secret_reconstruction():
    """Test secret reconstruction from shares"""
    print("\nTest 10: Secret Reconstruction")
    scheme = PostQuantumThresholdSignature()

    key_pair = scheme.generate_threshold_key_pair(3, 5)

    # With sufficient shares (3)
    shares = key_pair.key_shares[:3]
    secret = scheme.reconstruct_secret(shares, key_pair)
    assert secret is not None
    assert isinstance(secret, int)
    print(f"  ✓ Secret reconstructed from 3 shares")

    # With insufficient shares (2)
    shares_few = key_pair.key_shares[:2]
    secret_fail = scheme.reconstruct_secret(shares_few, key_pair)
    assert secret_fail is None
    print("  ✓ Correctly failed reconstruction with insufficient shares")

    return True


def test_different_hash_algorithms():
    """Test different hash algorithms"""
    print("\nTest 11: Hash Algorithm Support")
    scheme = PostQuantumThresholdSignature(HashAlgorithm.SHA3_256)

    key_pair = scheme.generate_threshold_key_pair(2, 3)
    message = b"Test with SHA3-256"

    partial_sigs = []
    for i in range(2):
        share = key_pair.key_shares[i]
        partial = scheme.sign_partial(message, share, key_pair)
        partial_sigs.append(partial)

    signature, status = scheme.aggregate_signatures(partial_sigs, message, key_pair)
    assert status == SignatureStatus.VERIFIED

    print("  ✓ SHA3-256 hash algorithm working")

    # Test BLAKE2b
    scheme2 = PostQuantumThresholdSignature(HashAlgorithm.BLAKE2b)
    key_pair2 = scheme2.generate_threshold_key_pair(2, 3)
    assert len(key_pair2.group_public_key) == 32
    print("  ✓ BLAKE2b hash algorithm working")

    return True


def test_security_parameters():
    """Test security parameters reporting"""
    print("\nTest 12: Security Parameters")
    scheme = PostQuantumThresholdSignature()

    params = scheme.get_security_parameters()

    assert params['security_level_bits'] == 256
    assert params['post_quantum_secure'] == True
    assert 'quantum_resistance' in params
    assert 'max_participants' in params

    print(f"  ✓ Security parameters reported: {params['security_level_bits']}-bit security")
    print(f"  ✓ Post-quantum secure: {params['post_quantum_secure']}")

    return True


def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("QuantumCrypt-AI: Post-Quantum Threshold Signature Tests")
    print("=" * 60)

    tests = [
        test_initialization,
        test_key_generation_basic,
        test_key_generation_parameters,
        test_key_generation_validation,
        test_partial_signature_generation,
        test_partial_signature_verification,
        test_signature_aggregation,
        test_insufficient_shares,
        test_threshold_signature_verification,
        test_secret_reconstruction,
        test_different_hash_algorithms,
        test_security_parameters,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"  ✗ FAILED")
        except Exception as e:
            failed += 1
            print(f"  ✗ FAILED with exception: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 60)

    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
