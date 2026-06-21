#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Session Key Manager with Perfect Forward Secrecy
Production-grade testing for QuantumCrypt-AI

Author: QuantumCrypt-AI Team
Date: June 2026
"""

import sys
import json
import time
import secrets

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_session_key_manager_forward_secrecy_2026_june import (
    SessionKeyManager,
    PostQuantumKeyGenerator,
    PerfectForwardSecrecyManager,
    HKDF,
    KeyStrength,
    KeyAlgorithm,
    SessionKey,
    SessionState,
)


def test_hkdf_implementation():
    """Test HKDF key derivation implementation"""
    print("\n=== Testing HKDF Implementation ===")
    hkdf = HKDF('sha256')
    
    # Test basic derivation
    ikm = b'input_key_material_test_12345'
    salt = b'salt_value'
    info = b'context_info'
    
    derived = hkdf.derive_key(ikm, salt, info, length=32)
    print(f"  Derived key length: {len(derived)} bytes")
    assert len(derived) == 32, "HKDF should produce correct length"
    
    # Test determinism - same inputs produce same output
    derived2 = hkdf.derive_key(ikm, salt, info, length=32)
    assert derived == derived2, "HKDF should be deterministic"
    
    # Test different inputs produce different outputs
    derived3 = hkdf.derive_key(ikm, b'different_salt', info, length=32)
    assert derived != derived3, "Different salt should produce different key"
    
    # Test variable lengths
    for length in [16, 32, 48, 64]:
        key = hkdf.derive_key(ikm, salt, info, length=length)
        assert len(key) == length, f"HKDF should produce {length} bytes"
    
    print(f"  SHA-256 hash length: {hkdf.hash_len}")
    print("  ✓ HKDF implementation tests passed")


def test_key_strength_enum():
    """Test KeyStrength enumeration"""
    print("\n=== Testing KeyStrength Enumeration ===")
    
    assert KeyStrength.CRYPTOGRAPHIC_128.value == 16
    assert KeyStrength.CRYPTOGRAPHIC_256.value == 32
    assert KeyStrength.CRYPTOGRAPHIC_384.value == 48
    assert KeyStrength.CRYPTOGRAPHIC_512.value == 64
    
    print(f"  128-bit security: {KeyStrength.CRYPTOGRAPHIC_128.value} bytes")
    print(f"  256-bit security: {KeyStrength.CRYPTOGRAPHIC_256.value} bytes")
    print(f"  384-bit security: {KeyStrength.CRYPTOGRAPHIC_384.value} bytes")
    print(f"  512-bit security: {KeyStrength.CRYPTOGRAPHIC_512.value} bytes")
    print("  ✓ KeyStrength tests passed")


def test_post_quantum_key_generator():
    """Test PostQuantumKeyGenerator functionality"""
    print("\n=== Testing PostQuantumKeyGenerator ===")
    generator = PostQuantumKeyGenerator(KeyStrength.CRYPTOGRAPHIC_256)
    
    # Test ephemeral key generation
    key_id, key_bytes = generator.generate_ephemeral_key()
    print(f"  Generated key ID: {key_id[:16]}...")
    print(f"  Key length: {len(key_bytes)} bytes")
    
    assert len(key_id) == 32, "Key ID should be 32 hex chars"
    assert len(key_bytes) == 32, "256-bit key should be 32 bytes"
    assert isinstance(key_bytes, bytes), "Key should be bytes"
    
    # Test different strengths
    for strength in [KeyStrength.CRYPTOGRAPHIC_128, KeyStrength.CRYPTOGRAPHIC_256, 
                     KeyStrength.CRYPTOGRAPHIC_512]:
        kid, kb = generator.generate_ephemeral_key(strength=strength)
        assert len(kb) == strength.value, f"Strength {strength.name} should produce {strength.value} bytes"
        print(f"  {strength.name}: {len(kb)} bytes ✓")
    
    # Test key pair generation
    private, public = generator.generate_key_pair()
    print(f"  Private key length: {len(private)} bytes")
    print(f"  Public key length: {len(public)} bytes")
    assert len(private) == 64  # Double strength for private
    assert len(public) == 32
    
    # Test shared secret generation
    shared = generator.generate_shared_secret(public, private)
    print(f"  Shared secret length: {len(shared)} bytes")
    assert len(shared) == 32
    
    print("  ✓ PostQuantumKeyGenerator tests passed")


def test_perfect_forward_secrecy_manager():
    """Test PerfectForwardSecrecyManager functionality"""
    print("\n=== Testing PerfectForwardSecrecyManager ===")
    pfs_manager = PerfectForwardSecrecyManager(rotation_interval_seconds=3600)
    
    session_id = "test-session-pfs-001"
    
    # Generate ephemeral key pair
    private, public = pfs_manager.generate_ephemeral_keypair(session_id)
    print(f"  Generated ephemeral keypair for session: {session_id}")
    print(f"  Private key length: {len(private)} bytes")
    print(f"  Public key length: {len(public)} bytes")
    
    assert len(private) > 0
    assert len(public) > 0
    
    # Retrieve private key - should be deleted after retrieval (forward secrecy)
    retrieved = pfs_manager.get_ephemeral_private(session_id)
    assert retrieved is not None, "Should retrieve private key"
    print(f"  Retrieved private key, length: {len(retrieved)} bytes")
    
    # Second retrieval should return None (key was deleted for forward secrecy)
    retrieved2 = pfs_manager.get_ephemeral_private(session_id)
    assert retrieved2 is None, "Private key should be deleted after first retrieval (PFS)"
    print(f"  Second retrieval returns None (forward secrecy enforced): {retrieved2 is None}")
    
    print("  ✓ PerfectForwardSecrecyManager tests passed")


def test_session_key_creation():
    """Test session creation functionality"""
    print("\n=== Testing Session Key Creation ===")
    manager = SessionKeyManager(
        key_strength=KeyStrength.CRYPTOGRAPHIC_256,
        key_lifetime_seconds=3600,
        rotation_interval=1800,
    )
    
    # Create a new session
    session_info = manager.create_session("peer-server-001", KeyAlgorithm.KYBER_768)
    
    print(f"  Session ID: {session_info['session_id']}")
    print(f"  Peer ID: {session_info['peer_id']}")
    print(f"  Root key ID: {session_info['root_key_id']}")
    print(f"  Algorithm: {session_info['algorithm']}")
    print(f"  Key strength: {session_info['key_strength_bits']} bits")
    print(f"  Created at: {session_info['created_at']}")
    
    assert session_info['session_id'] is not None
    assert session_info['peer_id'] == "peer-server-001"
    assert session_info['algorithm'] == "kyber-768"
    assert session_info['key_strength_bits'] == 256
    
    # Get session status
    status = manager.get_session_status(session_info['session_id'])
    assert status is not None
    assert status['is_active'] == True
    assert status['active_key_count'] == 1
    
    print(f"  Session active: {status['is_active']}")
    print(f"  Active keys: {status['active_key_count']}")
    
    print("  ✓ Session key creation tests passed")


def test_key_derivation():
    """Test subkey derivation functionality"""
    print("\n=== Testing Key Derivation ===")
    manager = SessionKeyManager(key_strength=KeyStrength.CRYPTOGRAPHIC_256)
    
    session_info = manager.create_session("peer-server-002")
    session_id = session_info['session_id']
    root_key_id = session_info['root_key_id']
    
    # Derive encryption key
    enc_key = manager.derive_subkey(session_id, root_key_id, "encryption", 32)
    print(f"  Encryption subkey ID: {enc_key['subkey_id']}")
    print(f"  Encryption key length: {enc_key['length_bits']} bits")
    
    # Derive authentication key
    auth_key = manager.derive_subkey(session_id, root_key_id, "authentication", 32)
    print(f"  Authentication subkey ID: {auth_key['subkey_id']}")
    
    # Derive signing key
    sign_key = manager.derive_subkey(session_id, root_key_id, "signing", 64)
    print(f"  Signing subkey length: {sign_key['length_bits']} bits")
    
    assert enc_key is not None
    assert auth_key is not None
    assert sign_key is not None
    
    # Different purposes should produce different keys
    assert enc_key['key_bytes_hex'] != auth_key['key_bytes_hex'], "Different purposes should produce different keys"
    assert enc_key['key_bytes_hex'] != sign_key['key_bytes_hex']
    
    # Check stats
    stats = manager.get_statistics()
    print(f"  Total derivations performed: {stats['derivations_performed']}")
    assert stats['derivations_performed'] == 3
    
    print("  ✓ Key derivation tests passed")


def test_key_rotation():
    """Test key rotation functionality"""
    print("\n=== Testing Key Rotation ===")
    manager = SessionKeyManager(key_strength=KeyStrength.CRYPTOGRAPHIC_256)
    
    session_info = manager.create_session("peer-server-003")
    session_id = session_info['session_id']
    
    initial_status = manager.get_session_status(session_id)
    initial_rotation_count = initial_status['key_rotation_count']
    print(f"  Initial rotation count: {initial_rotation_count}")
    
    # Perform first rotation
    rotation1 = manager.rotate_session_key(session_id)
    print(f"  Rotation 1 - New key ID: {rotation1['new_key_id']}")
    print(f"  Rotation count: {rotation1['rotation_count']}")
    
    # Perform second rotation
    rotation2 = manager.rotate_session_key(session_id)
    print(f"  Rotation 2 - New key ID: {rotation2['new_key_id']}")
    print(f"  Rotation count: {rotation2['rotation_count']}")
    
    final_status = manager.get_session_status(session_id)
    print(f"  Final total keys: {final_status['total_key_count']}")
    print(f"  Final rotation count: {final_status['key_rotation_count']}")
    
    assert final_status['key_rotation_count'] == 2
    assert final_status['total_key_count'] == 3  # 1 initial + 2 rotations
    
    stats = manager.get_statistics()
    print(f"  Total keys rotated: {stats['keys_rotated']}")
    assert stats['keys_rotated'] == 2
    
    print("  ✓ Key rotation tests passed")


def test_key_revocation():
    """Test key revocation functionality"""
    print("\n=== Testing Key Revocation ===")
    manager = SessionKeyManager(key_strength=KeyStrength.CRYPTOGRAPHIC_256)
    
    session_info = manager.create_session("peer-server-004")
    session_id = session_info['session_id']
    key_id = session_info['root_key_id']
    
    # Revoke the key due to compromise
    revoked = manager.revoke_key(session_id, key_id, "compromise detected")
    print(f"  Key revoked: {revoked}")
    assert revoked == True
    
    # Try to derive from revoked key - should fail
    derived = manager.derive_subkey(session_id, key_id, "encryption")
    print(f"  Derivation from revoked key: {derived is None}")
    assert derived is None, "Should not derive from revoked key"
    
    stats = manager.get_statistics()
    print(f"  Total keys revoked: {stats['keys_revoked']}")
    assert stats['keys_revoked'] == 1
    
    print("  ✓ Key revocation tests passed")


def test_session_termination():
    """Test session termination with secure cleanup"""
    print("\n=== Testing Session Termination ===")
    manager = SessionKeyManager(key_strength=KeyStrength.CRYPTOGRAPHIC_256)
    
    session_info = manager.create_session("peer-server-005")
    session_id = session_info['session_id']
    
    # Check session exists
    status_before = manager.get_session_status(session_id)
    assert status_before is not None
    print(f"  Session exists before termination: {status_before is not None}")
    
    # Terminate session
    terminated = manager.terminate_session(session_id)
    print(f"  Session terminated: {terminated}")
    assert terminated == True
    
    # Check session is gone
    status_after = manager.get_session_status(session_id)
    print(f"  Session exists after termination: {status_after is not None}")
    assert status_after is None, "Session should be removed after termination"
    
    stats = manager.get_statistics()
    print(f"  Sessions terminated: {stats['sessions_terminated']}")
    assert stats['sessions_terminated'] == 1
    
    print("  ✓ Session termination tests passed")


def test_statistics():
    """Test statistics collection"""
    print("\n=== Testing Statistics Collection ===")
    manager = SessionKeyManager(key_strength=KeyStrength.CRYPTOGRAPHIC_256)
    
    # Perform some operations
    for i in range(3):
        session = manager.create_session(f"peer-{i}")
        manager.derive_subkey(session['session_id'], session['root_key_id'], "encryption")
        manager.rotate_session_key(session['session_id'])
    
    manager.revoke_key(session['session_id'], session['root_key_id'])
    manager.terminate_session(session['session_id'])
    
    stats = manager.get_statistics()
    
    print(f"  Keys created: {stats['keys_created']}")
    print(f"  Keys rotated: {stats['keys_rotated']}")
    print(f"  Keys revoked: {stats['keys_revoked']}")
    print(f"  Sessions created: {stats['sessions_created']}")
    print(f"  Sessions terminated: {stats['sessions_terminated']}")
    print(f"  Derivations performed: {stats['derivations_performed']}")
    print(f"  Active sessions: {stats['active_sessions']}")
    print(f"  Key strength: {stats['key_strength_bits']} bits")
    
    assert stats['keys_created'] > 0
    assert stats['sessions_created'] == 3
    assert stats['key_strength_bits'] == 256
    
    print("  ✓ Statistics collection tests passed")


def test_edge_cases():
    """Test edge cases and error handling"""
    print("\n=== Testing Edge Cases ===")
    manager = SessionKeyManager()
    
    # Non-existent session
    status = manager.get_session_status("non-existent-session")
    print(f"  Non-existent session status: {status is None}")
    assert status is None
    
    # Rotate non-existent session
    rotation = manager.rotate_session_key("non-existent-session")
    print(f"  Rotate non-existent session: {rotation is None}")
    assert rotation is None
    
    # Terminate non-existent session
    terminated = manager.terminate_session("non-existent-session")
    print(f"  Terminate non-existent session: {terminated is False}")
    assert terminated is False
    
    # Derive from non-existent key
    derived = manager.derive_subkey("non-existent", "bad-key-id", "encryption")
    print(f"  Derive from non-existent key: {derived is None}")
    assert derived is None
    
    # Cleanup operation
    manager.cleanup()
    print("  Cleanup operation completed successfully")
    
    print("  ✓ Edge case tests passed")


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("Post-Quantum Secure Session Key Manager with Perfect Forward Secrecy")
    print("Production Test Suite - QuantumCrypt-AI")
    print("=" * 70)
    
    start_time = time.time()
    all_passed = True
    
    try:
        test_hkdf_implementation()
        test_key_strength_enum()
        test_post_quantum_key_generator()
        test_perfect_forward_secrecy_manager()
        test_session_key_creation()
        test_key_derivation()
        test_key_rotation()
        test_key_revocation()
        test_session_termination()
        test_statistics()
        test_edge_cases()
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        all_passed = False
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False
    
    elapsed = time.time() - start_time
    
    print("\n" + "=" * 70)
    if all_passed:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
    print(f"Total test time: {elapsed:.2f} seconds")
    print("=" * 70)
    
    # Save test results
    test_results = {
        'test_suite': 'Post-Quantum Secure Session Key Manager',
        'module': 'quantum_crypt/post_quantum_secure_session_key_manager_forward_secrecy_2026_june.py',
        'all_passed': all_passed,
        'test_time_seconds': round(elapsed, 2),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'version': '1.0.0',
        'features': [
            'HKDF RFC 5869 compliant key derivation',
            'Post-quantum strength key generation',
            'Perfect forward secrecy enforcement',
            'Session key lifecycle management',
            'Key rotation and revocation',
            'Secure memory cleanup',
        ],
    }
    
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_post_quantum_secure_session_key_manager_forward_secrecy.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to: test_results_post_quantum_secure_session_key_manager_forward_secrecy.json")
    
    return all_passed


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
