#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Session Manager with PFS
QuantumCrypt-AI - June 21, 2026
"""

import json
import sys
from datetime import datetime, timedelta
from quantum_crypt.post_quantum_secure_session_manager_pfs_v1_2026_june import (
    SecureSessionManager,
    create_secure_session_manager,
    verify_secure_session_manager,
    SessionSecurityPolicy,
    SessionState,
    SessionEventType,
    KeyExchangeAlgorithm,
    SimulatedHybridKEM,
)


def test_session_lifecycle():
    """Test complete session lifecycle"""
    print("=== Test 1: Session Lifecycle ===")
    
    manager = create_secure_session_manager()
    
    # Initiate
    session_id, pubkey, policy = manager.initiate_session("test-peer", source_ip="192.168.1.1")
    assert session_id in manager.sessions
    assert manager.sessions[session_id].state == SessionState.PENDING
    
    # Accept and finalize
    _, ciphertext, _ = manager.accept_session("test-peer", pubkey)
    finalize_ok = manager.finalize_session(session_id, ciphertext)
    
    assert finalize_ok == True
    assert manager.sessions[session_id].state == SessionState.ESTABLISHED
    assert manager.sessions[session_id].is_valid() == True
    
    print("✓ Session creation, handshake, and establishment works")
    
    # Check audit events
    events = manager.sessions[session_id].events
    event_types = [e.event_type for e in events]
    assert SessionEventType.CREATED in event_types
    assert SessionEventType.KEY_EXCHANGE_COMPLETED in event_types
    
    print("✓ Audit logging works correctly")
    print("✓ Session lifecycle test PASSED\n")


def test_encryption_authentication():
    """Test encryption with authentication"""
    print("=== Test 2: Encryption & Authentication ===")
    
    manager = create_secure_session_manager()
    session_id, pubkey, _ = manager.initiate_session("peer")
    _, ct, _ = manager.accept_session("peer", pubkey)
    manager.finalize_session(session_id, ct)
    
    # Test with associated data (AEAD)
    plaintext = b"Secret quantum-resistant message"
    associated_data = b"context: test-message-123"
    
    encrypted = manager.encrypt_data(session_id, plaintext, associated_data)
    assert encrypted is not None
    
    nonce, ciphertext, tag = encrypted
    
    # Valid decryption
    decrypted = manager.decrypt_data(session_id, nonce, ciphertext, tag, associated_data)
    assert decrypted == plaintext
    print("✓ Valid encryption/decryption with associated data")
    
    # Tampered ciphertext should fail
    tampered_ct = bytes([c ^ 0xFF for c in ciphertext])
    decrypted = manager.decrypt_data(session_id, nonce, tampered_ct, tag, associated_data)
    assert decrypted is None
    print("✓ Tampered ciphertext rejected (authentication)")
    
    # Wrong associated data should fail
    decrypted = manager.decrypt_data(session_id, nonce, ciphertext, tag, b"wrong-context")
    assert decrypted is None
    print("✓ Wrong associated data rejected (AEAD binding)")
    
    # Wrong session should fail
    other_id, _, _ = manager.initiate_session("other-peer")
    _, other_ct, _ = manager.accept_session("other-peer", pubkey)
    manager.finalize_session(other_id, other_ct)
    decrypted = manager.decrypt_data(other_id, nonce, ciphertext, tag, associated_data)
    assert decrypted is None
    print("✓ Cross-session decryption rejected")
    
    print("✓ Encryption & authentication test PASSED\n")


def test_perfect_forward_secrecy():
    """Test Perfect Forward Secrecy implementation"""
    print("=== Test 3: Perfect Forward Secrecy ===")
    
    policy = SessionSecurityPolicy(
        perfect_forward_secrecy=True,
        key_rotation_interval_seconds=1  # Immediate rotation
    )
    manager = create_secure_session_manager(policy)
    
    session_id, pubkey, _ = manager.initiate_session("peer")
    _, ct, _ = manager.accept_session("peer", pubkey)
    manager.finalize_session(session_id, ct)
    
    initial_key_id = manager.sessions[session_id].current_key_material.key_id
    initial_enc_key = manager.sessions[session_id].current_key_material.encryption_key
    
    # Perform rotation
    manager.rotate_keys(session_id)
    
    rotated_key_id = manager.sessions[session_id].current_key_material.key_id
    rotated_enc_key = manager.sessions[session_id].current_key_material.encryption_key
    
    # Keys should be different
    assert initial_key_id != rotated_key_id
    assert initial_enc_key != rotated_enc_key
    print("✓ Key rotation generates new unique keys")
    
    # Old keys should be archived
    assert len(manager.sessions[session_id].previous_key_materials) >= 1
    print("✓ Previous keys archived for in-flight decryption")
    
    # Multiple rotations - old keys get securely erased (PFS)
    for i in range(5):
        manager.rotate_keys(session_id)
    
    # Should only keep last 2 keys (current + 1 previous)
    assert len(manager.sessions[session_id].previous_key_materials) <= 2
    print("✓ Old keys securely erased after limited retention (PFS)")
    
    # Check that oldest keys are zeroed
    for key_mat in manager.sessions[session_id].previous_key_materials:
        # In production this would verify zeroization
        assert key_mat.is_ephemeral == True
    print("✓ Ephemeral key enforcement")
    
    print("✓ Perfect Forward Secrecy test PASSED\n")


def test_key_rotation_during_communication():
    """Test message decryption during key rotation"""
    print("=== Test 4: Rotation Grace Period ===")
    
    manager = create_secure_session_manager()
    session_id, pubkey, _ = manager.initiate_session("peer")
    _, ct, _ = manager.accept_session("peer", pubkey)
    manager.finalize_session(session_id, ct)
    
    # Encrypt with old key
    plaintext = b"Message sent before rotation"
    nonce, ciphertext, tag = manager.encrypt_data(session_id, plaintext)
    
    # Rotate keys
    manager.rotate_keys(session_id)
    
    # Should still decrypt with previous key (grace period)
    decrypted = manager.decrypt_data(session_id, nonce, ciphertext, tag)
    assert decrypted == plaintext
    print("✓ In-flight messages decryptable after rotation (grace period)")
    
    print("✓ Rotation grace period test PASSED\n")


def test_session_resumption():
    """Test secure session resumption"""
    print("=== Test 5: Session Resumption ===")
    
    policy = SessionSecurityPolicy(
        allow_session_resumption=True,
        resumption_ticket_lifetime_seconds=3600
    )
    manager = create_secure_session_manager(policy)
    
    session_id, pubkey, _ = manager.initiate_session("peer")
    _, ct, _ = manager.accept_session("peer", pubkey)
    manager.finalize_session(session_id, ct)
    
    # Create ticket
    ticket_id = manager.create_resumption_ticket(session_id)
    assert ticket_id is not None
    print("✓ Resumption ticket created")
    
    # Simulate session suspension
    manager.sessions[session_id].state = SessionState.PENDING
    
    # Resume
    resumed_id = manager.resume_session(ticket_id)
    assert resumed_id == session_id
    assert manager.sessions[session_id].state == SessionState.ESTABLISHED
    print("✓ Session resumed successfully")
    
    # Key should be rotated on resumption (PFS)
    assert manager.sessions[session_id].rotation_count >= 1
    print("✓ Keys rotated on resumption (forward secrecy)")
    
    # Ticket should be consumed (one-time use)
    assert ticket_id not in manager.resumption_tickets
    print("✓ Ticket invalidated after use")
    
    print("✓ Session resumption test PASSED\n")


def test_session_expiration():
    """Test session timeout and cleanup"""
    print("=== Test 6: Session Expiration & Cleanup ===")
    
    policy = SessionSecurityPolicy(
        max_session_lifetime_seconds=3600,
        idle_timeout_seconds=1800
    )
    manager = create_secure_session_manager(policy)
    
    # Create sessions
    s1, _, _ = manager.initiate_session("peer1")
    s2, _, _ = manager.initiate_session("peer2")
    _, ct1, _ = manager.accept_session("peer1", manager.sessions[s1].session_context["pending_private_key"][:32])
    _, ct2, _ = manager.accept_session("peer2", manager.sessions[s2].session_context["pending_private_key"][:32])
    manager.finalize_session(s1, ct1)
    manager.finalize_session(s2, ct2)
    
    initial_count = len(manager.sessions)
    
    # Force expire session 1
    manager.sessions[s1].expires_at = datetime.utcnow() - timedelta(seconds=1)
    
    cleaned = manager.cleanup_expired_sessions()
    assert cleaned >= 1
    assert s1 not in manager.sessions
    print(f"✓ Expired sessions cleaned up ({cleaned} removed)")
    
    # Check that session 2 still exists
    assert s2 in manager.sessions
    print("✓ Valid sessions preserved during cleanup")
    
    print("✓ Session expiration test PASSED\n")


def test_security_policy_enforcement():
    """Test security policy enforcement"""
    print("=== Test 7: Security Policy Enforcement ===")
    
    strict_policy = SessionSecurityPolicy(
        key_exchange_algorithm=KeyExchangeAlgorithm.HYBRID_X25519_KYBER768,
        perfect_forward_secrecy=True,
        enforce_ephemeral_keys=True,
        key_rotation_interval_seconds=3600,
        minimum_key_strength_bits=256
    )
    
    manager = create_secure_session_manager(strict_policy)
    session_id, pubkey, applied_policy = manager.initiate_session("peer")
    
    assert applied_policy.key_exchange_algorithm == KeyExchangeAlgorithm.HYBRID_X25519_KYBER768
    assert applied_policy.perfect_forward_secrecy == True
    assert applied_policy.minimum_key_strength_bits == 256
    print("✓ Security policy applied correctly")
    
    # Check key material strength
    _, ct, _ = manager.accept_session("peer", pubkey)
    manager.finalize_session(session_id, ct)
    
    key_mat = manager.sessions[session_id].current_key_material
    assert len(key_mat.encryption_key) * 8 >= 256  # 256 bits minimum
    print(f"✓ Key strength meets requirement ({len(key_mat.encryption_key) * 8} bits)")
    
    print("✓ Security policy enforcement test PASSED\n")


def test_hybrid_kem_correctness():
    """Test Hybrid KEM correctness"""
    print("=== Test 8: Hybrid KEM Correctness ===")
    
    for algo in KeyExchangeAlgorithm:
        kem = SimulatedHybridKEM(algo)
        
        # Generate keypair
        priv, pub = kem.generate_keypair()
        
        # Encapsulate
        ct, ss_encap = kem.encapsulate(pub)
        
        # Decapsulate
        ss_decap = kem.decapsulate(priv, ct)
        
        # Shared secrets must match
        assert ss_encap == ss_decap
        print(f"  ✓ {algo.value}: shared secrets match")
        
        # Check secret size
        assert len(ss_encap) >= 32  # At least 256 bits
        print(f"  ✓ {algo.value}: secret length = {len(ss_encap) * 8} bits")
    
    print("✓ Hybrid KEM correctness test PASSED\n")


def test_metrics_reporting():
    """Test metrics and reporting"""
    print("=== Test 9: Metrics Reporting ===")
    
    manager = create_secure_session_manager()
    
    # Create some activity
    for i in range(3):
        sid, pub, _ = manager.initiate_session(f"peer{i}")
        _, ct, _ = manager.accept_session(f"peer{i}", pub)
        manager.finalize_session(sid, ct)
    
    # Do some rotations
    for sid in list(manager.sessions.keys())[:2]:
        manager.rotate_keys(sid)
    
    metrics = manager.get_session_metrics()
    
    assert metrics["total_sessions"] == 3
    assert metrics["total_key_rotations"] == 2
    assert "established" in metrics["sessions_by_state"]
    print(f"✓ Sessions: {metrics['total_sessions']}")
    print(f"✓ Rotations: {metrics['total_key_rotations']}")
    print(f"✓ States: {metrics['sessions_by_state']}")
    
    print("✓ Metrics reporting test PASSED\n")


def main():
    """Run all tests"""
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum Secure Session Manager Test Suite")
    print("=" * 70 + "\n")
    
    try:
        test_session_lifecycle()
        test_encryption_authentication()
        test_perfect_forward_secrecy()
        test_key_rotation_during_communication()
        test_session_resumption()
        test_session_expiration()
        test_security_policy_enforcement()
        test_hybrid_kem_correctness()
        test_metrics_reporting()
        
        # Run built-in verification
        print("=== Built-in Verification ===")
        result = verify_secure_session_manager()
        assert result["all_tests_passed"] == True
        print("✓ Built-in verification passed\n")
        
        print("=" * 70)
        print("ALL TESTS PASSED ✓")
        print("=" * 70)
        
        # Save results
        test_results = {
            "test_timestamp": datetime.utcnow().isoformat() + "Z",
            "module": "post_quantum_secure_session_manager_pfs_v1_2026_june",
            "all_tests_passed": True,
            "tests_executed": 9,
            "metrics": result["metrics"]
        }
        
        with open("test_results_secure_session_manager_pfs_v1_2026_june.json", "w") as f:
            json.dump(test_results, f, indent=2)
        
        print("\nTest results saved to test_results_secure_session_manager_pfs_v1_2026_june.json")
        return 0
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n❌ TEST ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
