"""
Test suite for Hybrid KEM Signature Session Manager V2
Tests all new V2 features: forward secrecy, heartbeat, audit logging,
context binding, emergency revocation, and session migration.
"""
import sys
import json
import time
from pathlib import Path

# Add module path
sys.path.insert(0, str(Path(__file__).parent))

from quantum_crypt.post_quantum_hybrid_kem_signature_session_manager_v2_2026_june import (
    HybridKEMSignatureSessionManagerV2,
    KEMAlgorithm,
    SignatureAlgorithm,
    SessionStatus,
    SecurityLevel,
    AuditEventType,
    SessionRotationPolicy
)


def run_tests():
    """Run all session manager tests"""
    print("=" * 70)
    print("QuantumCrypt AI - Hybrid KEM Session Manager V2 Tests")
    print("=" * 70)
    
    manager = HybridKEMSignatureSessionManagerV2(
        max_concurrent_sessions=100,
        enable_audit_logging=True
    )
    
    test_results = []
    all_passed = True
    
    # Test 1: Session creation with security context - NEW V2 FEATURE
    print("\n[TEST 1] Session Creation with Security Context Binding")
    security_ctx = {"user_id": "user123", "ip": "192.168.1.1", "device": "mobile"}
    session = manager.create_session(
        peer_identity="test-peer",
        kem_algorithm=KEMAlgorithm.HYBRID_KYBER768_ECDH384,
        sig_algorithm=SignatureAlgorithm.HYBRID_DILITHIUM3_ECDSA384,
        security_context=security_ctx
    )
    passed = (session is not None and 
              session.status == SessionStatus.ACTIVE and
              session.security_context == security_ctx)
    print(f"  Session created: {session is not None}")
    print(f"  Security context bound: {session.security_context == security_ctx}")
    print(f"  Security level: {session.security_level.name}")
    test_results.append({"test": "session_creation", "passed": passed, "session_id": session.session_id})
    if not passed:
        all_passed = False
    session_id_1 = session.session_id
    
    # Test 2: Forward Secrecy Rekey - NEW V2 FEATURE
    print("\n[TEST 2] Forward Secrecy Rekey Operation")
    original_key_hash = session.shared_secret.hex()[:16]
    rekey_result = manager.rekey_session(session_id_1)
    updated_session = manager.get_session(session_id_1)
    new_key_hash = updated_session.shared_secret.hex()[:16]
    passed = (rekey_result.success and 
              rekey_result.forward_secrecy_verified and
              original_key_hash != new_key_hash)
    print(f"  Rekey successful: {rekey_result.success}")
    print(f"  Forward secrecy verified: {rekey_result.forward_secrecy_verified}")
    print(f"  Key changed: {original_key_hash} -> {new_key_hash}")
    print(f"  Rekey count: {updated_session.rekey_count}")
    test_results.append({"test": "forward_secrecy_rekey", "passed": passed, 
                        "rekey_time_ms": rekey_result.rekey_time_ms})
    if not passed:
        all_passed = False
    
    # Test 3: Context Verification (Anti-Hijacking) - NEW V2 FEATURE
    print("\n[TEST 3] Security Context Verification (Anti-Hijacking)")
    correct_ctx = {"user_id": "user123", "ip": "192.168.1.1"}
    wrong_ctx = {"user_id": "hacker", "ip": "malicious"}
    
    session_valid = manager.get_session(session_id_1, verify_context=correct_ctx)
    session_blocked = manager.get_session(session_id_1, verify_context=wrong_ctx)
    
    passed = (session_valid is not None and session_blocked is None)
    print(f"  Correct context allowed: {session_valid is not None}")
    print(f"  Wrong context blocked: {session_blocked is None}")
    test_results.append({"test": "context_verification", "passed": passed})
    if not passed:
        all_passed = False
    
    # Test 4: Heartbeat Monitoring - NEW V2 FEATURE
    print("\n[TEST 4] Session Heartbeat Monitoring")
    heartbeat_result = manager.heartbeat(session_id_1)
    session_after = manager.get_session(session_id_1)
    passed = (heartbeat_result and session_after.last_heartbeat > session.created_at)
    print(f"  Heartbeat accepted: {heartbeat_result}")
    print(f"  Last heartbeat updated: {session_after.last_heartbeat > session.created_at}")
    test_results.append({"test": "heartbeat_monitoring", "passed": passed})
    if not passed:
        all_passed = False
    
    # Test 5: Audit Logging - NEW V2 FEATURE
    print("\n[TEST 5] Session Audit Logging")
    audit_log = manager.get_audit_log(limit=20)
    has_create = any(e['event_type'] == 'session_created' for e in audit_log)
    has_rekey = any(e['event_type'] == 'rekey_performed' for e in audit_log)
    has_heartbeat = any(e['event_type'] == 'heartbeat' for e in audit_log)
    passed = has_create and has_rekey and has_heartbeat
    print(f"  Audit log entries: {len(audit_log)}")
    print(f"  Contains session_created: {has_create}")
    print(f"  Contains rekey_performed: {has_rekey}")
    print(f"  Contains heartbeat: {has_heartbeat}")
    test_results.append({"test": "audit_logging", "passed": passed, "log_count": len(audit_log)})
    if not passed:
        all_passed = False
    
    # Test 6: Session Migration - NEW V2 FEATURE
    print("\n[TEST 6] Session Migration to New Context")
    new_ctx = {"user_id": "user123", "privilege": "elevated", "mfa_verified": "true"}
    new_session_id = manager.migrate_session(session_id_1, new_ctx)
    old_session = manager.get_session(session_id_1)
    new_session = manager.get_session(new_session_id) if new_session_id else None
    
    passed = (new_session_id is not None and
              old_session.status == SessionStatus.MIGRATED and
              new_session is not None and
              new_session.security_context == new_ctx)
    print(f"  Migration successful: {new_session_id is not None}")
    print(f"  Old session marked as migrated: {old_session.status == SessionStatus.MIGRATED}")
    print(f"  New session has updated context: {new_session.security_context == new_ctx if new_session else False}")
    test_results.append({"test": "session_migration", "passed": passed})
    if not passed:
        all_passed = False
    
    # Test 7: Session Revocation
    print("\n[TEST 7] Individual Session Revocation")
    revoke_session = manager.create_session(peer_identity="to-revoke")
    revoke_id = revoke_session.session_id
    revoke_result = manager.revoke_session(revoke_id, reason="compromise_detected")
    revoked_session = manager.get_session(revoke_id)
    
    passed = (revoke_result and 
              revoked_session is not None and 
              revoked_session.status == SessionStatus.REVOKED)
    print(f"  Revocation successful: {revoke_result}")
    print(f"  Session status: {revoked_session.status.value if revoked_session else 'None'}")
    test_results.append({"test": "session_revocation", "passed": passed})
    if not passed:
        all_passed = False
    
    # Test 8: Emergency Bulk Revocation - NEW V2 FEATURE
    print("\n[TEST 8] Emergency Bulk Session Revocation")
    # Create a few more sessions
    for i in range(3):
        manager.create_session(peer_identity=f"emergency-test-{i}")
    
    metrics_before = manager.get_metrics()
    active_before = metrics_before['active_sessions']
    revoked_count = manager.emergency_revoke_all(reason="breach_response")
    metrics_after = manager.get_metrics()
    
    passed = revoked_count > 0
    print(f"  Sessions revoked: {revoked_count}")
    print(f"  Active before: {active_before}, Active after: {metrics_after['active_sessions']}")
    test_results.append({"test": "emergency_revocation", "passed": passed, "revoked_count": revoked_count})
    if not passed:
        all_passed = False
    
    # Test 9: Concurrent Session Limit Enforcement - NEW V2 FEATURE
    print("\n[TEST 9] Concurrent Session Limit Enforcement")
    limit_manager = HybridKEMSignatureSessionManagerV2(max_concurrent_sessions=5)
    
    # Fill to limit
    sessions_created = 0
    for i in range(5):
        try:
            limit_manager.create_session(peer_identity=f"limit-test-{i}")
            sessions_created += 1
        except:
            pass
    
    # Try to exceed limit
    try:
        limit_manager.create_session(peer_identity="should-fail")
        limit_exceeded = False
    except RuntimeError:
        limit_exceeded = True
    
    passed = sessions_created == 5 and limit_exceeded
    print(f"  Sessions at limit: {sessions_created}")
    print(f"  Exceeding limit blocked: {limit_exceeded}")
    test_results.append({"test": "concurrent_limit", "passed": passed})
    if not passed:
        all_passed = False
    
    # Test 10: Enhanced Metrics Reporting - NEW V2
    print("\n[TEST 10] Enhanced Metrics Reporting")
    metrics = manager.get_metrics()
    required_metrics = [
        'sessions_created', 'rekeys_performed', 'heartbeats_processed',
        'emergency_revocations', 'audit_log_entries', 'manager_version'
    ]
    has_all_metrics = all(m in metrics for m in required_metrics)
    version_correct = metrics.get('manager_version') == 'v2'
    
    passed = has_all_metrics and version_correct
    print(f"  All metrics present: {has_all_metrics}")
    print(f"  Manager version v2: {version_correct}")
    print(f"  Forward secrecy supported: {metrics.get('forward_secrecy_supported')}")
    print(f"  Audit logging enabled: {metrics.get('audit_logging_enabled')}")
    test_results.append({"test": "metrics_reporting", "passed": passed})
    if not passed:
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed_count = sum(1 for r in test_results if r["passed"])
    total_count = len(test_results)
    
    for r in test_results:
        status = "✓ PASS" if r["passed"] else "✗ FAIL"
        print(f"  {status}: {r['test']}")
    
    print(f"\nTotal: {passed_count}/{total_count} tests passed")
    
    # Save results
    output = {
        "test_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "manager_version": "v2",
        "total_tests": total_count,
        "passed_tests": passed_count,
        "all_passed": all_passed,
        "test_results": test_results,
        "new_v2_features": [
            "forward_secrecy_rekeying",
            "heartbeat_monitoring",
            "security_context_binding",
            "audit_logging_compliance",
            "session_migration",
            "emergency_bulk_revocation",
            "concurrent_session_limits",
            "enhanced_metrics_reporting"
        ],
        "limitations": [
            "Actual post-quantum algorithms require liboqs library",
            "This implementation uses classical crypto primitives as framework",
            "Production deployment requires HSM integration"
        ]
    }
    
    with open("test_results_hybrid_kem_session_manager_v2_2026_june.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to: test_results_hybrid_kem_session_manager_v2_2026_june.json")
    
    return all_passed, output


if __name__ == "__main__":
    success, results = run_tests()
    sys.exit(0 if success else 1)
