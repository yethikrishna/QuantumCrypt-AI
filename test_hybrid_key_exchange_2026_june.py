#!/usr/bin/env python3
"""
Test Suite for Hybrid Post-Quantum Key Exchange
QuantumCrypt-AI - June 2026 Production Release

Comprehensive tests for hybrid key exchange with forward secrecy.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.hybrid_key_exchange_2026_june import (
    HybridKeyExchange,
    KeyExchangeProtocol,
    SecurityLevel,
    CurveType,
    SharedSecret,
    KeyExchangeResult
)


def test_basic_initialization():
    """Test basic key exchange initialization"""
    print("Test 1: Basic Initialization")
    
    kex = HybridKeyExchange()
    assert kex.protocol == KeyExchangeProtocol.HYBRID_ECDH_KYBER
    assert kex.security_level == SecurityLevel.LEVEL_3
    assert kex.enable_forward_secrecy == True
    print("  ✓ HybridKeyExchange initialized successfully")


def test_security_levels():
    """Test different NIST security levels"""
    print("\nTest 2: Security Levels")
    
    for level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_3, SecurityLevel.LEVEL_5]:
        kex = HybridKeyExchange(security_level=level)
        assert kex.security_level == level
        stats = kex.get_exchange_stats()
        assert stats["key_strength_bits"] > 0
        print(f"  ✓ Level {level.value}: {stats['key_strength_bits']} bits security")


def test_ecdh_key_pair_generation():
    """Test ECDH key pair generation"""
    print("\nTest 3: ECDH Key Pair Generation")
    
    kex = HybridKeyExchange(curve=CurveType.SECP256R1)
    key_pair = kex.generate_ecdh_key_pair()
    
    assert key_pair.private_key is not None
    assert key_pair.public_key is not None
    assert key_pair.curve == CurveType.SECP256R1
    assert b"PRIVATE KEY" in key_pair.private_key
    assert b"PUBLIC KEY" in key_pair.public_key
    
    print(f"  ✓ Private key length: {len(key_pair.private_key)} bytes")
    print(f"  ✓ Public key length: {len(key_pair.public_key)} bytes")


def test_session_initiation():
    """Test session initiation"""
    print("\nTest 4: Session Initiation")
    
    alice = HybridKeyExchange()
    ecdh_key, pq_public, ciphertext, session_id = alice.initiate_session()
    
    assert ecdh_key is not None
    assert pq_public is not None
    assert ciphertext is not None
    assert len(session_id) == 32  # 16 bytes hex
    
    stats = alice.get_exchange_stats()
    assert stats["pending_exchanges"] == 1
    
    print(f"  ✓ Session ID: {session_id[:16]}...")
    print(f"  ✓ PQ public key: {len(pq_public)} bytes")
    print(f"  ✓ Ciphertext: {len(ciphertext)} bytes")


def test_full_key_exchange():
    """Test complete key exchange between two parties"""
    print("\nTest 5: Full Key Exchange Flow")
    
    # Alice initiates
    alice = HybridKeyExchange(security_level=SecurityLevel.LEVEL_3)
    alice_key, alice_pq_public, alice_ciphertext, session_id = alice.initiate_session()
    
    # Bob accepts
    bob = HybridKeyExchange(security_level=SecurityLevel.LEVEL_3)
    bob_result = bob.accept_session(
        alice_key.public_key,
        alice_pq_public,
        alice_ciphertext
    )
    
    assert bob_result.success == True
    assert bob_result.shared_secret is not None
    assert bob_result.shared_secret.forward_secret == True
    
    # Alice completes
    alice_result = alice.complete_session(session_id, bob_result.peer_public_key)
    
    assert alice_result.success == True
    assert alice_result.shared_secret is not None
    assert len(alice_result.shared_secret.derived_key) > 0
    
    print(f"  ✓ Bob's key ID: {bob_result.shared_secret.key_id}")
    print(f"  ✓ Alice's key ID: {alice_result.shared_secret.key_id}")
    print(f"  ✓ Derived key length: {len(alice_result.shared_secret.derived_key) * 8} bits")


def test_forward_secrecy():
    """Test forward secrecy - ephemeral keys are destroyed"""
    print("\nTest 6: Forward Secrecy")
    
    alice = HybridKeyExchange(enable_forward_secrecy=True)
    _, _, _, session_id = alice.initiate_session()
    
    # Verify ephemeral key exists before completion
    assert session_id in alice._ephemeral_keys
    
    # Create dummy peer key and complete
    dummy_key = alice.generate_ecdh_key_pair()
    result = alice.complete_session(session_id, dummy_key.public_key)
    
    assert result.success == True
    # Ephemeral key should be destroyed after completion
    assert session_id not in alice._ephemeral_keys
    
    print("  ✓ Ephemeral keys destroyed after session completion")
    print("  ✓ Forward secrecy enforced")


def test_session_key_retrieval():
    """Test session key retrieval"""
    print("\nTest 7: Session Key Retrieval")
    
    kex = HybridKeyExchange()
    key_pair, _, _, session_id = kex.initiate_session()
    
    # Complete session
    result = kex.complete_session(session_id, key_pair.public_key)
    
    retrieved_key = kex.get_session_key(session_id)
    assert retrieved_key is not None
    assert len(retrieved_key) > 0
    assert retrieved_key == result.shared_secret.derived_key
    
    print(f"  ✓ Session key retrieved: {retrieved_key.hex()[:32]}...")


def test_session_destruction():
    """Test session destruction"""
    print("\nTest 8: Session Destruction")
    
    kex = HybridKeyExchange()
    key_pair, _, _, session_id = kex.initiate_session()
    kex.complete_session(session_id, key_pair.public_key)
    
    # Destroy session
    destroyed = kex.destroy_session(session_id)
    assert destroyed == True
    
    # Key should no longer be available
    assert kex.get_session_key(session_id) is None
    
    print("  ✓ Session key material destroyed")
    print("  ✓ Forward secrecy maintained")


def test_exchange_statistics():
    """Test exchange statistics"""
    print("\nTest 9: Exchange Statistics")
    
    kex = HybridKeyExchange(
        protocol=KeyExchangeProtocol.HYBRID_ECDH_KYBER,
        security_level=SecurityLevel.LEVEL_5
    )
    
    # Perform some operations
    kex.initiate_session()
    kex.initiate_session()
    
    stats = kex.get_exchange_stats()
    
    assert stats["protocol"] == "hybrid_ecdh_kyber"
    assert stats["security_level"] == "NIST Level 5"
    assert stats["forward_secrecy_enabled"] == True
    assert stats["pending_exchanges"] == 2
    assert stats["total_keys_generated"] == 2
    
    print(f"  ✓ Protocol: {stats['protocol']}")
    print(f"  ✓ Security: {stats['security_level']}")
    print(f"  ✓ Pending sessions: {stats['pending_exchanges']}")


def test_curve_variants():
    """Test different curve types"""
    print("\nTest 10: Curve Variants")
    
    curves = [CurveType.SECP256R1, CurveType.SECP384R1]
    
    for curve in curves:
        kex = HybridKeyExchange(curve=curve)
        key_pair = kex.generate_ecdh_key_pair()
        assert key_pair.curve == curve
        stats = kex.get_exchange_stats()
        print(f"  ✓ {curve.value}: {len(key_pair.public_key)} bytes public key")


def test_invalid_session_completion():
    """Test error handling for invalid sessions"""
    print("\nTest 11: Invalid Session Handling")
    
    kex = HybridKeyExchange()
    
    # Try to complete non-existent session
    result = kex.complete_session("non_existent_session", b"dummy_key")
    
    assert result.success == False
    assert result.error_message is not None
    assert "Session not found" in result.error_message
    
    print("  ✓ Invalid session properly rejected")
    print(f"  ✓ Error message: {result.error_message}")


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("QuantumCrypt-AI: Hybrid Key Exchange Tests")
    print("June 2026 Production Release")
    print("=" * 60)
    
    tests = [
        test_basic_initialization,
        test_security_levels,
        test_ecdh_key_pair_generation,
        test_session_initiation,
        test_full_key_exchange,
        test_forward_secrecy,
        test_session_key_retrieval,
        test_session_destruction,
        test_exchange_statistics,
        test_curve_variants,
        test_invalid_session_completion,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {type(e).__name__}: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
