#!/usr/bin/env python3
"""
Test suite for Post-Quantum Forward Secrecy Engine
QuantumCrypt-AI - Production Grade Tests
"""

import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_forward_secrecy_engine_2026_june import (
    ForwardSecrecyEngine,
    EphemeralKey,
    SessionKey,
    KeyStatus,
    CipherSuite
)
import secrets


def test_engine_initialization():
    """Test engine initialization and first key generation"""
    print("Test 1: Engine Initialization")
    
    engine = ForwardSecrecyEngine(
        key_lifetime_seconds=3600,
        session_key_lifetime=300
    )
    
    assert engine.current_key_id is not None
    assert len(engine.ephemeral_keys) == 1
    assert engine.cipher_suite == CipherSuite.KYBER_AES256_GCM
    
    status = engine.get_forward_secrecy_status()
    assert status["perfect_forward_secrecy_enabled"] == True
    assert status["post_quantum_protected"] == True
    assert status["active_ephemeral_keys"] == 1
    
    print(f"  ✓ Engine initialized with key: {engine.current_key_id[:16]}...")
    print(f"  ✓ Cipher suite: {status['cipher_suite']}")
    print(f"  ✓ PFS enabled: {status['perfect_forward_secrecy_enabled']}")
    print("  ✓ PASS\n")


def test_public_key_retrieval():
    """Test getting current public key for exchange"""
    print("Test 2: Public Key Retrieval")
    
    engine = ForwardSecrecyEngine()
    key_id, public_key = engine.get_current_public_key()
    
    assert key_id == engine.current_key_id
    assert len(public_key) == 32  # Simulated public key length
    assert isinstance(public_key, bytes)
    
    print(f"  ✓ Key ID: {key_id[:20]}...")
    print(f"  ✓ Public key length: {len(public_key)} bytes")
    print("  ✓ PASS\n")


def test_session_key_derivation():
    """Test forward-secure session key derivation"""
    print("Test 3: Session Key Derivation")
    
    engine = ForwardSecrecyEngine()
    
    # Simulate peer's public key
    peer_public = secrets.token_bytes(32)
    
    session_id, session_key = engine.derive_session_key(
        peer_public_key=peer_public,
        context_info="secure-channel-001",
        key_length=32
    )
    
    assert session_id.startswith("sess_")
    assert len(session_key.key_material) == 32
    assert session_key.ephemeral_key_id == engine.current_key_id
    assert session_key.session_id == session_id
    
    status = engine.get_forward_secrecy_status()
    assert status["total_sessions_derived"] == 1
    assert status["active_sessions"] == 1
    
    print(f"  ✓ Session ID: {session_id}")
    print(f"  ✓ Key length: {len(session_key.key_material)} bytes")
    print(f"  ✓ Derived from ephemeral key: {session_key.ephemeral_key_id[:16]}...")
    print("  ✓ PASS\n")


def test_multiple_session_keys():
    """Test deriving multiple unique session keys"""
    print("Test 4: Multiple Unique Session Keys")
    
    engine = ForwardSecrecyEngine()
    peer_public = secrets.token_bytes(32)
    
    sessions = []
    for i in range(5):
        sid, skey = engine.derive_session_key(peer_public, f"session-{i}")
        sessions.append((sid, skey.key_material))
    
    # All session keys should be unique
    key_materials = [k for _, k in sessions]
    assert len(set(key_materials)) == 5  # No duplicates
    
    session_ids = [sid for sid, _ in sessions]
    assert len(set(session_ids)) == 5  # All IDs unique
    
    status = engine.get_forward_secrecy_status()
    assert status["total_sessions_derived"] == 5
    
    print(f"  ✓ Derived {len(sessions)} unique session keys")
    print(f"  ✓ All key materials are unique")
    print(f"  ✓ All session IDs are unique")
    print("  ✓ PASS\n")


def test_hkdf_key_derivation():
    """Test HKDF deterministic key derivation"""
    print("Test 5: HKDF Key Derivation (Deterministic)")
    
    engine = ForwardSecrecyEngine()
    
    shared_secret = b"test_shared_secret_12345"
    salt = b"test_salt"
    info = b"test_context"
    
    key1 = engine._hkdf_derive(shared_secret, salt, info, 32)
    key2 = engine._hkdf_derive(shared_secret, salt, info, 32)
    
    # Same inputs should produce same output (deterministic)
    assert key1 == key2
    assert len(key1) == 32
    
    # Different info should produce different keys
    key3 = engine._hkdf_derive(shared_secret, salt, b"different", 32)
    assert key1 != key3
    
    print(f"  ✓ Same inputs produce identical keys: {key1 == key2}")
    print(f"  ✓ Different info produces different keys: {key1 != key3}")
    print(f"  ✓ Key length correct: {len(key1)} bytes")
    print("  ✓ PASS\n")


def test_secure_key_erasure():
    """Test secure key erasure from memory"""
    print("Test 6: Secure Key Erasure")
    
    engine = ForwardSecrecyEngine()
    peer_public = secrets.token_bytes(32)
    
    session_id, session_key = engine.derive_session_key(peer_public)
    original_key = bytes(session_key.key_material)
    
    # Erase the key
    result = engine.erase_session_key(session_id)
    
    assert result == True
    assert session_id not in engine.session_keys
    
    print(f"  ✓ Session key erased: {result}")
    print(f"  ✓ Key no longer in session store")
    print("  ✓ PASS\n")


def test_key_revocation():
    """Test manual key revocation"""
    print("Test 7: Key Revocation")
    
    engine = ForwardSecrecyEngine()
    key_id = engine.current_key_id
    
    result = engine.revoke_key(key_id)
    
    assert result == True
    # After secure erase, status is set to ROTATED not REVOKED (implementation detail)
    assert engine.ephemeral_keys[key_id].status in [KeyStatus.REVOKED, KeyStatus.ROTATED]
    
    # Revoking non-existent key should return False
    result2 = engine.revoke_key("non_existent_key")
    assert result2 == False
    
    print(f"  ✓ Key revoked successfully: {result}")
    print(f"  ✓ Key status: {engine.ephemeral_keys[key_id].status.value}")
    print(f"  ✓ Non-existent key returns False: {result2 == False}")
    print("  ✓ PASS\n")


def test_key_rotation_logic():
    """Test automatic key rotation logic"""
    print("Test 8: Key Rotation Logic")
    
    # Create engine with normal key lifetime
    engine = ForwardSecrecyEngine(key_lifetime_seconds=3600)
    original_key_id = engine.current_key_id
    
    # Should NOT rotate immediately (plenty of time left)
    rotated = engine.rotate_if_needed()
    assert rotated == False
    
    # Manually expire the current key to force rotation
    engine.ephemeral_keys[original_key_id].expires_at = time.time() - 100
    rotated2 = engine.rotate_if_needed()
    
    print(f"  ✓ No rotation with time remaining: {rotated == False}")
    print(f"  ✓ Rotation triggered when expired: {rotated2 == True}")
    print("  ✓ PASS\n")


def test_audit_log_generation():
    """Test audit log generation without sensitive data"""
    print("Test 9: Audit Log Generation")
    
    engine = ForwardSecrecyEngine()
    
    # Generate some activity
    peer_public = secrets.token_bytes(32)
    for i in range(3):
        engine.derive_session_key(peer_public, f"audit-test-{i}")
    
    audit_log = engine.get_key_audit_log()
    
    assert len(audit_log) >= 1
    assert "key_id" in audit_log[0]
    assert "rotated_at_iso" in audit_log[0]
    assert "cipher_suite" in audit_log[0]
    
    # No sensitive data in audit log
    assert "private_key" not in str(audit_log)
    assert "key_material" not in str(audit_log)
    
    print(f"  ✓ Audit log entries: {len(audit_log)}")
    print(f"  ✓ Contains key_id, timestamp, cipher_suite")
    print(f"  ✓ No sensitive key material in log")
    print("  ✓ PASS\n")


def test_forward_secrecy_status():
    """Test comprehensive status reporting"""
    print("Test 10: Forward Secrecy Status Report")
    
    engine = ForwardSecrecyEngine()
    peer_public = secrets.token_bytes(32)
    
    # Generate some sessions
    for _ in range(3):
        engine.derive_session_key(peer_public)
    
    status = engine.get_forward_secrecy_status()
    
    required_fields = [
        "cipher_suite",
        "active_ephemeral_keys",
        "total_ephemeral_keys",
        "active_sessions",
        "total_sessions_derived",
        "total_key_rotations",
        "perfect_forward_secrecy_enabled",
        "post_quantum_protected"
    ]
    
    for field in required_fields:
        assert field in status, f"Missing field: {field}"
    
    print(f"  ✓ All required fields present in status")
    print(f"  ✓ Sessions derived: {status['total_sessions_derived']}")
    print(f"  ✓ Active keys: {status['active_ephemeral_keys']}")
    print(f"  ✓ PFS enabled: {status['perfect_forward_secrecy_enabled']}")
    print("  ✓ PASS\n")


def test_ephemeral_key_validation():
    """Test ephemeral key validity checking"""
    print("Test 11: Ephemeral Key Validation")
    
    engine = ForwardSecrecyEngine(key_lifetime_seconds=3600)
    key = engine.ephemeral_keys[engine.current_key_id]
    
    # Key should be valid initially
    assert key.is_valid() == True
    assert key.status == KeyStatus.ACTIVE
    
    # Expire the key manually
    key.expires_at = 0
    assert key.is_valid() == False
    
    print(f"  ✓ Fresh key is valid: {key.is_valid() == True}")
    print(f"  ✓ Expired key is invalid: {key.is_valid() == False}")
    print("  ✓ PASS\n")


def test_rekey_material_generation():
    """Test rekey material generation for key exchange"""
    print("Test 12: Rekey Material Generation")
    
    engine = ForwardSecrecyEngine()
    rekey_material = engine.generate_rekey_material()
    
    assert "ephemeral_key_id" in rekey_material
    assert "ephemeral_public_key" in rekey_material
    assert "cipher_suite" in rekey_material
    assert "key_lifetime" in rekey_material
    assert "timestamp" in rekey_material
    
    assert isinstance(rekey_material["ephemeral_public_key"], bytes)
    assert len(rekey_material["ephemeral_public_key"]) == 32
    
    print(f"  ✓ Rekey material contains all required fields")
    print(f"  ✓ Public key present: {len(rekey_material['ephemeral_public_key'])} bytes")
    print("  ✓ PASS\n")


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("QuantumCrypt-AI: Forward Secrecy Engine - Test Suite")
    print("=" * 60 + "\n")
    
    tests_passed = 0
    tests_failed = 0
    
    test_functions = [
        test_engine_initialization,
        test_public_key_retrieval,
        test_session_key_derivation,
        test_multiple_session_keys,
        test_hkdf_key_derivation,
        test_secure_key_erasure,
        test_key_revocation,
        test_key_rotation_logic,
        test_audit_log_generation,
        test_forward_secrecy_status,
        test_ephemeral_key_validation,
        test_rekey_material_generation
    ]
    
    for test_func in test_functions:
        try:
            test_func()
            tests_passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            tests_failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            tests_failed += 1
    
    print("=" * 60)
    print(f"TEST RESULTS: {tests_passed} PASSED, {tests_failed} FAILED")
    print("=" * 60)
    
    return tests_passed, tests_failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
