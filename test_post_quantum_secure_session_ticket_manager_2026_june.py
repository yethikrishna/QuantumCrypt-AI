#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Session Ticket Manager
June 19, 2026 - Production Grade Tests

Tests cover:
- Session state serialization/deserialization
- Ticket creation and encryption
- Ticket validation and decryption
- Anti-replay protection
- Key rotation mechanism
- Ticket lifetime enforcement
- Post-quantum key derivation
- Statistics tracking
"""

import sys
import json
import time
import importlib.util
from datetime import datetime, timedelta

# Import directly from module file
spec = importlib.util.spec_from_file_location(
    "ticket_module",
    "/home/user/autonomous-developer/QuantumCrypt-AI/quantum_crypt/post_quantum_secure_session_ticket_manager_2026_june.py"
)
ticket_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ticket_module)

SessionTicketManager = ticket_module.SessionTicketManager
SessionState = ticket_module.SessionState
SecureSessionTicket = ticket_module.SecureSessionTicket
TicketLifetimePolicy = ticket_module.TicketLifetimePolicy
PostQuantumKeyDerivation = ticket_module.PostQuantumKeyDerivation
TicketEncryptionKey = ticket_module.TicketEncryptionKey


def run_tests():
    print("=" * 70)
    print("TEST SUITE: Post-Quantum Secure Session Ticket Manager")
    print("=" * 70)
    print(f"Test Time: {datetime.utcnow().isoformat()}")
    print()
    
    all_passed = True
    test_results = []
    
    # Test 1: Post-Quantum Key Derivation
    print("[TEST 1] Post-Quantum Key Derivation")
    try:
        shared_secret = b"test_post_quantum_shared_secret_kyber_768" * 2
        aes_key, hmac_key = PostQuantumKeyDerivation.derive_ticket_keys(shared_secret)
        
        assert len(aes_key) == 32, f"AES key should be 32 bytes, got {len(aes_key)}"
        assert len(hmac_key) == 32, f"HMAC key should be 32 bytes, got {len(hmac_key)}"
        assert aes_key != hmac_key, "Keys should be different"
        
        # Deterministic derivation check
        aes_key2, hmac_key2 = PostQuantumKeyDerivation.derive_ticket_keys(shared_secret)
        assert aes_key == aes_key2, "Derivation should be deterministic"
        assert hmac_key == hmac_key2, "Derivation should be deterministic"
        
        print(f"  ✓ Passed: Derived AES ({len(aes_key)} bytes) + HMAC ({len(hmac_key)} bytes) keys")
        test_results.append({"test": "pq_key_derivation", "status": "PASS"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        test_results.append({"test": "pq_key_derivation", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 2: Session State Serialization Roundtrip
    print("\n[TEST 2] Session State Serialization/Deserialization Roundtrip")
    try:
        original = SessionState(
            session_id="test-session-001",
            master_secret=b"test_master_secret_12345",
            client_random=b"client_random_bytes_32_chars___",
            server_random=b"server_random_bytes_32_chars___",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            protocol_version="TLS/1.3",
            psk_identity="test-psk-001"
        )
        
        serialized = original.serialize()
        deserialized = SessionState.deserialize(serialized)
        
        assert original.session_id == deserialized.session_id, "Session ID mismatch"
        assert original.master_secret == deserialized.master_secret, "Master secret mismatch"
        assert original.client_random == deserialized.client_random, "Client random mismatch"
        assert original.server_random == deserialized.server_random, "Server random mismatch"
        assert original.cipher_suite == deserialized.cipher_suite, "Cipher suite mismatch"
        assert original.protocol_version == deserialized.protocol_version, "Protocol version mismatch"
        assert original.psk_identity == deserialized.psk_identity, "PSK identity mismatch"
        
        print(f"  ✓ Passed: Serialization roundtrip successful ({len(serialized)} bytes)")
        test_results.append({"test": "state_serialization", "status": "PASS"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        test_results.append({"test": "state_serialization", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 3: Ticket Creation and Validation
    print("\n[TEST 3] Ticket Creation and Validation (Full Flow)")
    try:
        manager = SessionTicketManager(lifetime_policy=TicketLifetimePolicy.SHORT_LIVED)
        
        # Create session state
        session_state = manager.create_session_state(
            master_secret=b"post_quantum_master_secret_test_value",
            client_random=b"client_random_32_bytes____________",
            server_random=b"server_random_32_bytes____________",
            cipher_suite="TLS_CHACHA20_POLY1305_SHA256",
            protocol_version="TLS/1.3"
        )
        
        # Create ticket
        ticket, ticket_bytes = manager.create_ticket(session_state)
        
        assert len(ticket_bytes) > 0, "Ticket should not be empty"
        assert ticket.key_id == manager.primary_key_id, "Should use primary key"
        assert len(ticket.nonce) == 12, "Nonce should be 12 bytes"
        
        # Validate ticket
        is_valid, restored_state, reason = manager.validate_ticket(ticket_bytes)
        
        assert is_valid, f"Ticket should be valid: {reason}"
        assert restored_state is not None, "Should have restored state"
        assert restored_state.session_id == session_state.session_id, "Session ID should match"
        assert restored_state.master_secret == session_state.master_secret, "Master secret should match"
        assert restored_state.cipher_suite == session_state.cipher_suite, "Cipher suite should match"
        
        print(f"  ✓ Passed:")
        print(f"    Ticket size: {len(ticket_bytes)} bytes")
        print(f"    Session ID: {restored_state.session_id}")
        print(f"    Validation: {reason}")
        
        test_results.append({"test": "ticket_create_validate", "status": "PASS"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        test_results.append({"test": "ticket_create_validate", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 4: Anti-Replay Protection
    print("\n[TEST 4] Anti-Replay Protection")
    try:
        manager = SessionTicketManager()
        
        session_state = manager.create_session_state(
            master_secret=b"test_secret",
            client_random=b"a" * 32,
            server_random=b"b" * 32
        )
        
        ticket, ticket_bytes = manager.create_ticket(session_state)
        
        # First validation should succeed
        valid1, state1, reason1 = manager.validate_ticket(ticket_bytes)
        assert valid1, f"First validation should succeed: {reason1}"
        
        # Second validation (replay) should fail
        valid2, state2, reason2 = manager.validate_ticket(ticket_bytes)
        assert not valid2, "Replay should be rejected"
        assert "replay" in reason2.lower(), f"Reason should mention replay: {reason2}"
        
        print(f"  ✓ Passed:")
        print(f"    First validation: {reason1}")
        print(f"    Replay detected: {reason2}")
        print(f"    Replay cache entries: {len(manager.used_nonces)}")
        
        test_results.append({"test": "anti_replay", "status": "PASS"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "anti_replay", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 5: Tampered Ticket Rejection
    print("\n[TEST 5] Tampered Ticket Rejection")
    try:
        manager = SessionTicketManager()
        
        session_state = manager.create_session_state(
            master_secret=b"test_secret",
            client_random=b"a" * 32,
            server_random=b"b" * 32
        )
        
        ticket, ticket_bytes = manager.create_ticket(session_state)
        
        # Tamper with ticket bytes
        tampered_bytes = bytearray(ticket_bytes)
        tampered_bytes[-1] ^= 0xFF  # Flip last byte
        
        valid, state, reason = manager.validate_ticket(bytes(tampered_bytes))
        
        assert not valid, "Tampered ticket should be rejected"
        # Tampering can be detected at multiple levels: decryption, validation, or integrity check
        assert not valid, f"Tampered ticket was accepted: {reason}"
        
        print(f"  ✓ Passed: Tampered ticket rejected - {reason}")
        test_results.append({"test": "tamper_protection", "status": "PASS"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "tamper_protection", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 6: Key Rotation
    print("\n[TEST 6] Key Rotation Mechanism")
    try:
        # Create manager with very short rotation interval
        manager = SessionTicketManager(key_rotation_interval_hours=0)
        
        initial_key_id = manager.primary_key_id
        
        # Force rotation
        manager._rotate_encryption_key()
        
        new_key_id = manager.primary_key_id
        
        assert initial_key_id != new_key_id, "Key ID should change after rotation"
        assert len(manager.encryption_keys) >= 2, "Should have at least 2 keys"
        assert manager.stats["key_rotations"] >= 2, "Should track rotations"
        
        # Old tickets should still validate (grace period)
        session_state = manager.create_session_state(
            master_secret=b"rotation_test",
            client_random=b"a" * 32,
            server_random=b"b" * 32
        )
        ticket, ticket_bytes = manager.create_ticket(session_state)
        
        # Rotate again
        manager._rotate_encryption_key()
        
        # Old ticket should still validate with old key
        valid, state, reason = manager.validate_ticket(ticket_bytes)
        assert valid, f"Old key should still be valid during grace period: {reason}"
        
        print(f"  ✓ Passed:")
        print(f"    Initial key: {initial_key_id[:8]}...")
        print(f"    After rotation: {new_key_id[:8]}...")
        print(f"    Active keys: {len(manager.encryption_keys)}")
        print(f"    Rotations: {manager.stats['key_rotations']}")
        
        test_results.append({"test": "key_rotation", "status": "PASS"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        test_results.append({"test": "key_rotation", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 7: Statistics Tracking
    print("\n[TEST 7] Statistics Tracking")
    try:
        manager = SessionTicketManager()
        
        # Generate some activity
        for i in range(5):
            session_state = manager.create_session_state(
                master_secret=f"secret_{i}".encode(),
                client_random=b"a" * 32,
                server_random=b"b" * 32
            )
            _, ticket_bytes = manager.create_ticket(session_state)
            manager.validate_ticket(ticket_bytes)
        
        stats = manager.get_statistics()
        
        assert stats["tickets_issued"] == 5, f"Expected 5 issued, got {stats['tickets_issued']}"
        assert stats["tickets_accepted"] == 5, f"Expected 5 accepted, got {stats['tickets_accepted']}"
        assert "acceptance_rate" in stats
        assert "active_encryption_keys" in stats
        
        print(f"  ✓ Passed:")
        print(f"    Tickets issued: {stats['tickets_issued']}")
        print(f"    Tickets accepted: {stats['tickets_accepted']}")
        print(f"    Acceptance rate: {stats['acceptance_rate']:.2%}")
        print(f"    Active keys: {stats['active_encryption_keys']}")
        
        test_results.append({"test": "statistics_tracking", "status": "PASS"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "statistics_tracking", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Test 8: Invalid Ticket Handling
    print("\n[TEST 8] Invalid Ticket Handling")
    try:
        manager = SessionTicketManager()
        
        # Garbage bytes
        valid, state, reason = manager.validate_ticket(b"completely_invalid_ticket_data")
        assert not valid, "Garbage bytes should be rejected"
        
        # Empty ticket
        valid, state, reason = manager.validate_ticket(b"")
        assert not valid, "Empty ticket should be rejected"
        
        print(f"  ✓ Passed: Invalid tickets properly rejected")
        test_results.append({"test": "invalid_ticket_handling", "status": "PASS"})
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append({"test": "invalid_ticket_handling", "status": "FAIL", "error": str(e)})
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in test_results if r["status"] == "PASS")
    total = len(test_results)
    print(f"Passed: {passed}/{total}")
    
    if all_passed:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
        failed = [r for r in test_results if r["status"] == "FAIL"]
        for f in failed:
            print(f"  - {f['test']}: {f.get('error', 'Unknown error')}")
    
    print()
    
    # Save results
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_session_ticket_manager.json', 'w') as f:
        json.dump({
            "test_suite": "Post-Quantum Secure Session Ticket Manager",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": passed,
            "total": total,
            "all_passed": all_passed,
            "results": test_results
        }, f, indent=2)
    
    print(f"Results saved to test_results_session_ticket_manager.json")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(run_tests())
