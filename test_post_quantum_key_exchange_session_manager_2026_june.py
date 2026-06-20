#!/usr/bin/env python3
"""
Test suite for Post-Quantum Key Exchange Session Manager
Comprehensive tests covering all functionality
"""

import sys
import os
import json
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_key_exchange_session_manager_2026_june import (
    PQKeyExchangeSessionManager,
    KeyExchangeAlgorithm,
    SessionState,
    HashFunction,
    SessionTicketManager,
    PQSession
)


def test_hash_function():
    """Test cryptographic hash utilities"""
    print("Testing HashFunction...")
    
    # Test SHA-256
    data = b"test data"
    hash_result = HashFunction.sha256(data)
    assert len(hash_result) == 32, "SHA-256 should return 32 bytes"
    
    # Test HKDF
    salt = b"salt"
    ikm = b"input key material"
    prk = HashFunction.hkdf_extract(salt, ikm)
    assert len(prk) == 32, "HKDF extract should return 32 bytes"
    
    expanded = HashFunction.hkdf_expand(prk, b"info", 64)
    assert len(expanded) == 64, "HKDF expand should return requested length"
    
    print("  ✓ Hash functions working correctly")
    return True


def test_session_lifecycle():
    """Test basic session lifecycle"""
    print("Testing session lifecycle...")
    
    manager = PQKeyExchangeSessionManager(max_sessions=100)
    
    # Create session
    session_id, session = manager.create_session(
        algorithm=KeyExchangeAlgorithm.KYBER_768,
        peer_identity="client_123"
    )
    
    assert session_id is not None, "Should have session ID"
    assert session.state == SessionState.PENDING, "Initial state should be PENDING"
    assert session.session_id == session_id, "Session ID should match"
    
    # Establish session
    shared_secret = b"test_shared_secret_32_bytes_long_enough"
    success = manager.establish_session(session_id, shared_secret)
    assert success, "Session establishment should succeed"
    
    retrieved = manager.get_session(session_id)
    assert retrieved is not None, "Should retrieve session"
    assert retrieved.state == SessionState.ESTABLISHED, "State should be ESTABLISHED"
    assert len(retrieved.derived_keys) == 4, "Should have 4 derived keys"
    
    print(f"  ✓ Session lifecycle working: {session_id[:16]}...")
    print(f"    - Derived keys: {list(retrieved.derived_keys.keys())}")
    return True


def test_session_tickets():
    """Test session ticket issuance and validation"""
    print("Testing session tickets...")
    
    manager = PQKeyExchangeSessionManager()
    
    # Create and establish session
    session_id, session = manager.create_session(KeyExchangeAlgorithm.KYBER_768)
    manager.establish_session(session_id, b"test_secret_123456789012345678901234")
    
    # Issue ticket
    ticket = manager.issue_ticket(session_id)
    assert ticket is not None, "Should issue ticket"
    assert ticket.is_valid(), "Ticket should be valid"
    
    # Resume session from ticket
    resumed = manager.resume_session(ticket, "client_identity")
    assert resumed is not None, "Should resume session"
    assert resumed.state == SessionState.RESUMED, "Resumed state should be RESUMED"
    assert len(resumed.derived_keys) == 4, "Resumed session should have keys"
    
    metrics = manager.metrics
    assert metrics['tickets_issued'] >= 1, "Should track tickets issued"
    assert metrics['tickets_validated'] >= 1, "Should track tickets validated"
    assert metrics['sessions_resumed'] >= 1, "Should track resumed sessions"
    
    print(f"  ✓ Session tickets working")
    print(f"    - Ticket ID: {ticket.ticket_id[:16]}...")
    print(f"    - Resumed session: {resumed.session_id[:16]}...")
    return True


def test_key_refresh_forward_secrecy():
    """Test key refresh for forward secrecy"""
    print("Testing key refresh (forward secrecy)...")
    
    manager = PQKeyExchangeSessionManager()
    
    session_id, session = manager.create_session(KeyExchangeAlgorithm.KYBER_1024)
    manager.establish_session(session_id, b"initial_secret_12345678901234567890")
    
    # Get original keys
    original_keys = dict(session.derived_keys)
    original_secret = session.shared_secret
    
    # Perform key refresh
    success = manager.refresh_session_keys(session_id)
    assert success, "Key refresh should succeed"
    
    refreshed = manager.get_session(session_id)
    
    # Keys should change after refresh (forward secrecy)
    keys_changed = False
    for key_name, original_value in original_keys.items():
        if refreshed.derived_keys[key_name] != original_value:
            keys_changed = True
            break
    
    assert keys_changed, "Keys should change after refresh"
    assert refreshed.key_refresh_count == 1, "Should track refresh count"
    assert refreshed.shared_secret != original_secret, "Shared secret should change"
    
    metrics = manager.metrics
    assert metrics['key_refreshes'] == 1, "Should track key refreshes"
    
    print(f"  ✓ Key refresh working (forward secrecy)")
    print(f"    - Refresh count: {refreshed.key_refresh_count}")
    print(f"    - Keys properly rotated")
    return True


def test_anti_replay_nonces():
    """Test anti-replay nonce mechanism"""
    print("Testing anti-replay nonces...")
    
    manager = PQKeyExchangeSessionManager()
    
    session_id, session = manager.create_session(KeyExchangeAlgorithm.KYBER_768)
    manager.establish_session(session_id, b"test_secret")
    
    # Get unique nonces
    nonce1 = session.get_next_nonce()
    nonce2 = session.get_next_nonce()
    
    assert nonce1 != nonce2, "Nonces should be unique"
    
    # Validate fresh nonce
    assert manager.validate_session_nonce(session_id, b"\x00" * 12) == True, "Fresh nonce should be valid"
    
    # Replay detection - same nonce twice
    assert manager.validate_session_nonce(session_id, b"\x00" * 12) == False, "Replayed nonce should be rejected"
    
    metrics = manager.metrics
    assert metrics['nonce_replays_detected'] == 1, "Should track replay attempts"
    
    print(f"  ✓ Anti-replay protection working")
    print(f"    - Replays detected: {metrics['nonce_replays_detected']}")
    return True


def test_session_expiration():
    """Test session expiration and cleanup"""
    print("Testing session expiration...")
    
    # Create manager with very short timeout
    manager = PQKeyExchangeSessionManager(session_timeout=1, cleanup_interval=1)
    
    session_id, session = manager.create_session(KeyExchangeAlgorithm.KYBER_512)
    manager.establish_session(session_id, b"test_secret")
    
    # Session should exist initially
    assert manager.get_session(session_id) is not None, "Session should exist"
    
    # Wait for expiration
    time.sleep(1.5)
    
    # Session should be expired
    expired_session = manager.get_session(session_id)
    assert expired_session is None, "Session should be expired and removed"
    
    metrics = manager.metrics
    assert metrics['sessions_expired'] >= 1, "Should track expired sessions"
    
    print(f"  ✓ Session expiration working")
    print(f"    - Expired sessions: {metrics['sessions_expired']}")
    return True


def test_session_revocation():
    """Test explicit session revocation"""
    print("Testing session revocation...")
    
    manager = PQKeyExchangeSessionManager()
    
    session_id, session = manager.create_session(KeyExchangeAlgorithm.KYBER_768)
    manager.establish_session(session_id, b"test_secret")
    
    # Revoke session
    success = manager.revoke_session(session_id)
    assert success, "Revocation should succeed"
    
    # Session should be gone
    assert manager.get_session(session_id) is None, "Revoked session should not be retrievable"
    
    metrics = manager.metrics
    assert metrics['sessions_revoked'] == 1, "Should track revoked sessions"
    
    print(f"  ✓ Session revocation working")
    print(f"    - Revoked sessions: {metrics['sessions_revoked']}")
    return True


def test_max_sessions_lru():
    """Test LRU eviction when max sessions reached"""
    print("Testing LRU session eviction...")
    
    manager = PQKeyExchangeSessionManager(max_sessions=5)
    
    # Create 10 sessions (should evict oldest)
    session_ids = []
    for i in range(10):
        sid, _ = manager.create_session(KeyExchangeAlgorithm.KYBER_512, peer_identity=f"client_{i}")
        session_ids.append(sid)
    
    # First 5 should be evicted, last 5 should remain
    remaining = 0
    for sid in session_ids:
        if manager.get_session(sid) is not None:
            remaining += 1
    
    assert remaining <= 5, f"Should have max 5 sessions, got {remaining}"
    
    print(f"  ✓ LRU eviction working")
    print(f"    - Active sessions after eviction: {remaining}")
    return True


def test_concurrent_access():
    """Test thread-safe concurrent access"""
    print("Testing concurrent thread-safe access...")
    
    manager = PQKeyExchangeSessionManager(max_sessions=1000)
    errors = []
    
    def worker(worker_id: int):
        try:
            for i in range(50):
                sid, _ = manager.create_session(
                    KeyExchangeAlgorithm.KYBER_768,
                    peer_identity=f"worker_{worker_id}_session_{i}"
                )
                manager.establish_session(sid, f"secret_{worker_id}_{i}".encode())
                manager.get_session(sid)
        except Exception as e:
            errors.append(str(e))
    
    threads = []
    for i in range(10):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    assert len(errors) == 0, f"Concurrent access errors: {errors}"
    
    metrics = manager.metrics
    assert metrics['sessions_created'] == 500, f"Should have 500 sessions, got {metrics['sessions_created']}"
    
    print(f"  ✓ Thread-safe concurrent access working")
    print(f"    - Total sessions created: {metrics['sessions_created']}")
    print(f"    - No concurrency errors")
    return True


def test_ticket_manager_standalone():
    """Test standalone ticket manager"""
    print("Testing ticket manager...")
    
    ticket_manager = SessionTicketManager()
    
    # Create test session
    session = PQSession(
        session_id="test_session",
        algorithm=KeyExchangeAlgorithm.KYBER_768,
        state=SessionState.ESTABLISHED,
        shared_secret=b"test_shared_secret_1234567890123456"
    )
    
    ticket = ticket_manager.create_ticket(session)
    assert ticket.is_valid(), "Created ticket should be valid"
    assert ticket_manager.validate_ticket(ticket), "Ticket should validate"
    
    extracted = ticket_manager.extract_shared_secret(ticket)
    assert extracted is not None, "Should extract shared secret"
    
    # Tamper with ticket - should fail validation
    bad_ticket = ticket_manager.create_ticket(session)
    bad_ticket.mac = b"\x00" * 32  # Corrupt MAC
    assert not ticket_manager.validate_ticket(bad_ticket), "Tampered ticket should fail validation"
    
    print(f"  ✓ Ticket manager working")
    print(f"    - Integrity protection verified")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum Key Exchange Session Manager - Test Suite")
    print("=" * 70)
    print()
    
    tests = [
        test_hash_function,
        test_session_lifecycle,
        test_session_tickets,
        test_key_refresh_forward_secrecy,
        test_anti_replay_nonces,
        test_session_expiration,
        test_session_revocation,
        test_max_sessions_lru,
        test_concurrent_access,
        test_ticket_manager_standalone
    ]
    
    results = []
    start_time = time.time()
    
    for test_func in tests:
        try:
            result = test_func()
            results.append((test_func.__name__, "PASS", None))
            print()
        except Exception as e:
            results.append((test_func.__name__, "FAIL", str(e)))
            print(f"  ✗ FAILED: {e}")
            print()
    
    elapsed = time.time() - start_time
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in results if r[1] == "PASS")
    failed = sum(1 for r in results if r[1] == "FAIL")
    
    for name, status, error in results:
        status_icon = "✓" if status == "PASS" else "✗"
        print(f"{status_icon} {name}: {status}")
        if error:
            print(f"   Error: {error}")
    
    print()
    print(f"Results: {passed}/{len(tests)} tests passed")
    print(f"Total time: {elapsed:.2f}s")
    print()
    
    # Write test results to JSON
    test_report = {
        "test_suite": "Post-Quantum Key Exchange Session Manager",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(tests),
        "elapsed_seconds": elapsed,
        "results": [{"name": r[0], "status": r[1], "error": r[2]} for r in results]
    }
    
    with open("test_results_post_quantum_key_exchange_session_manager_2026_june.json", "w") as f:
        json.dump(test_report, f, indent=2)
    
    print(f"Test report written to test_results_post_quantum_key_exchange_session_manager_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
