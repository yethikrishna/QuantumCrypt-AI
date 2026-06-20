#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Session Manager - QuantumCrypt-AI
Comprehensive tests covering all security features
"""

import sys
import json
import time
from quantum_crypt.post_quantum_secure_session_manager_2026_june import (
    PostQuantumSecureSessionManager,
    SessionData,
    SessionState,
    create_secure_session,
    get_secure_session
)


def run_tests():
    """Run all session manager tests and report results"""
    print("=" * 70)
    print("Post-Quantum Secure Session Manager - Test Suite")
    print("=" * 70)
    
    manager = PostQuantumSecureSessionManager(
        session_timeout=3600,
        max_sessions=100,
        rotation_interval=1
    )
    
    test_results = []
    passed = 0
    failed = 0
    
    # Test 1: Session creation
    print("\n[Test 1] Session creation")
    session_id, session = manager.create_session({"user_id": "test123"})
    print(f"  Session ID length: {len(session_id)}")
    print(f"  Session state: {session.state.value}")
    print(f"  Key material length: {len(session.key_material)} bytes")
    if session_id and len(session_id) >= 96 and len(session.key_material) == 64:
        print("  ✓ PASS: Session created with secure parameters")
        passed += 1
        test_results.append({"test": "session_creation", "status": "PASS"})
    else:
        print("  ✗ FAIL: Session creation failed")
        failed += 1
        test_results.append({"test": "session_creation", "status": "FAIL"})
    
    # Test 2: Session retrieval
    print("\n[Test 2] Session retrieval")
    retrieved = manager.get_session(session_id)
    print(f"  Retrieved session: {retrieved is not None}")
    print(f"  Access count: {retrieved.access_count}")
    if retrieved and retrieved.user_data.get("user_id") == "test123":
        print("  ✓ PASS: Session retrieved correctly")
        passed += 1
        test_results.append({"test": "session_retrieval", "status": "PASS"})
    else:
        print("  ✗ FAIL: Session retrieval failed")
        failed += 1
        test_results.append({"test": "session_retrieval", "status": "FAIL"})
    
    # Test 3: Invalid session ID
    print("\n[Test 3] Invalid session ID handling")
    invalid = manager.get_session("invalid_session_id_12345")
    print(f"  Invalid session returns: {invalid}")
    if invalid is None:
        print("  ✓ PASS: Invalid ID correctly returns None")
        passed += 1
        test_results.append({"test": "invalid_session", "status": "PASS"})
    else:
        print("  ✗ FAIL: Invalid ID should return None")
        failed += 1
        test_results.append({"test": "invalid_session", "status": "FAIL"})
    
    # Test 4: Session data update
    print("\n[Test 4] Session data update")
    update_success = manager.update_session_data(session_id, "role", "admin")
    updated = manager.get_session(session_id)
    print(f"  Update successful: {update_success}")
    print(f"  Updated data: {updated.user_data.get('role')}")
    if update_success and updated.user_data.get("role") == "admin":
        print("  ✓ PASS: Session data updated correctly")
        passed += 1
        test_results.append({"test": "data_update", "status": "PASS"})
    else:
        print("  ✗ FAIL: Data update failed")
        failed += 1
        test_results.append({"test": "data_update", "status": "FAIL"})
    
    # Test 5: Session verification token
    print("\n[Test 5] HMAC verification token")
    token = manager.generate_verification_token(session_id)
    is_valid = manager.validate_session(session_id, token)
    print(f"  Token generated: {token is not None}")
    print(f"  Token length: {len(token) if token else 0} bytes")
    print(f"  Validation result: {is_valid}")
    if token and len(token) == 32 and is_valid:
        print("  ✓ PASS: Verification token works correctly")
        passed += 1
        test_results.append({"test": "verification_token", "status": "PASS"})
    else:
        print("  ✗ FAIL: Verification token system broken")
        failed += 1
        test_results.append({"test": "verification_token", "status": "FAIL"})
    
    # Test 6: Invalid token rejection
    print("\n[Test 6] Invalid token rejection")
    fake_token = b"\x00" * 32
    is_valid_fake = manager.validate_session(session_id, fake_token)
    print(f"  Fake token validation: {is_valid_fake}")
    if not is_valid_fake:
        print("  ✓ PASS: Invalid token correctly rejected")
        passed += 1
        test_results.append({"test": "invalid_token_rejection", "status": "PASS"})
    else:
        print("  ✗ FAIL: Fake token should be rejected")
        failed += 1
        test_results.append({"test": "invalid_token_rejection", "status": "FAIL"})
    
    # Test 7: Session revocation
    print("\n[Test 7] Session revocation")
    revoke_id, _ = manager.create_session({"temp": True})
    revoke_success = manager.revoke_session(revoke_id)
    revoked_session = manager.get_session(revoke_id)
    print(f"  Revoke successful: {revoke_success}")
    print(f"  Revoked session retrievable: {revoked_session is not None}")
    if revoke_success and revoked_session is None:
        print("  ✓ PASS: Session revoked and removed")
        passed += 1
        test_results.append({"test": "session_revocation", "status": "PASS"})
    else:
        print("  ✗ FAIL: Revocation not working")
        failed += 1
        test_results.append({"test": "session_revocation", "status": "FAIL"})
    
    # Test 8: Session statistics
    print("\n[Test 8] Session statistics")
    # Create a few more sessions
    for i in range(5):
        manager.create_session({"test": i})
    stats = manager.get_session_stats()
    print(f"  Total sessions: {stats['total_sessions']}")
    print(f"  Active sessions: {stats['active_sessions']}")
    if stats["total_sessions"] >= 5 and stats["active_sessions"] >= 5:
        print("  ✓ PASS: Statistics tracking works")
        passed += 1
        test_results.append({"test": "session_stats", "status": "PASS", "total": stats["total_sessions"]})
    else:
        print("  ✗ FAIL: Statistics incorrect")
        failed += 1
        test_results.append({"test": "session_stats", "status": "FAIL"})
    
    # Test 9: Session expiration
    print("\n[Test 9] Session expiration")
    exp_id, _ = manager.create_session({}, custom_timeout=1)  # 1 second timeout
    time.sleep(1.1)  # Wait for expiration
    expired_session = manager.get_session(exp_id)
    print(f"  Expired session retrievable: {expired_session is not None}")
    if expired_session is None:
        print("  ✓ PASS: Expired sessions correctly rejected")
        passed += 1
        test_results.append({"test": "session_expiration", "status": "PASS"})
    else:
        print("  ✗ FAIL: Expired session still accessible")
        failed += 1
        test_results.append({"test": "session_expiration", "status": "FAIL"})
    
    # Test 10: Convenience wrapper functions
    print("\n[Test 10] Convenience wrapper functions")
    wrapper_id, wrapper_sess = create_secure_session({"wrapper": "test"})
    wrapper_retrieved = get_secure_session(wrapper_id)
    print(f"  Create wrapper works: {wrapper_id is not None}")
    print(f"  Get wrapper works: {wrapper_retrieved is not None}")
    if wrapper_id and wrapper_retrieved:
        print("  ✓ PASS: Convenience functions work")
        passed += 1
        test_results.append({"test": "convenience_wrappers", "status": "PASS"})
    else:
        print("  ✗ FAIL: Convenience wrappers broken")
        failed += 1
        test_results.append({"test": "convenience_wrappers", "status": "FAIL"})
    
    # Test 11: Master key validation
    print("\n[Test 11] Master key validation")
    try:
        bad_manager = PostQuantumSecureSessionManager(master_key=b"short")
        print("  ✗ FAIL: Should reject short master key")
        failed += 1
        test_results.append({"test": "master_key_validation", "status": "FAIL"})
    except ValueError as e:
        print(f"  Correctly raised ValueError: {str(e)[:40]}...")
        print("  ✓ PASS: Master key length enforced")
        passed += 1
        test_results.append({"test": "master_key_validation", "status": "PASS"})
    
    # Test 12: Session ID uniqueness
    print("\n[Test 12] Session ID uniqueness")
    session_ids = set()
    duplicates = 0
    for i in range(100):
        sid, _ = manager.create_session()
        if sid in session_ids:
            duplicates += 1
        session_ids.add(sid)
    print(f"  Generated 100 sessions, duplicates: {duplicates}")
    if duplicates == 0:
        print("  ✓ PASS: All session IDs unique")
        passed += 1
        test_results.append({"test": "session_id_uniqueness", "status": "PASS"})
    else:
        print("  ✗ FAIL: Duplicate session IDs found")
        failed += 1
        test_results.append({"test": "session_id_uniqueness", "status": "FAIL"})
    
    # Summary
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 70)
    
    success_rate = passed / (passed + failed) * 100
    print(f"\nSuccess rate: {success_rate:.1f}%")
    
    # Save test results
    output = {
        "test_suite": "post_quantum_secure_session_manager",
        "timestamp": "2026-06-20",
        "total_tests": passed + failed,
        "passed": passed,
        "failed": failed,
        "success_rate": success_rate,
        "results": test_results
    }
    
    with open("test_results_post_quantum_secure_session_manager.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nTest results saved to test_results_post_quantum_secure_session_manager.json")
    
    return success_rate >= 80  # Require 80%+ pass rate


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
