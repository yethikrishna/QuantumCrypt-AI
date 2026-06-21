#!/usr/bin/env python3
"""
Test Suite for QuantumCrypt-AI v6: Post-Quantum Secure MPC Session Manager
Production-grade testing - all tests must pass
"""
import sys
import time
import json

# Add module path
sys.path.insert(0, '/home/user/.super_doubao/super-doubao-runtime/workspace/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_mpc_session_manager_v6_2026_june import (
    MPCSessionManager,
    SessionState,
    ParticipantRole,
    ComputationType,
    SecurityLevel,
    MPCResult,
    KyberSimulatedKEM,
    DilithiumSimulatedSignature,
    ShamirSecretSharing,
    SessionAuditLog,
    ZeroKnowledgeProofVerifier,
    SecureMPCComputationEngine,
    ConstantTimeOperations
)

def run_test(test_name, test_func):
    """Run a single test and report result"""
    print(f"\n[TEST {test_name}]")
    try:
        result = test_func()
        if result:
            print(f"  ✓ PASSED")
            return True
        else:
            print(f"  ✗ FAILED")
            return False
    except Exception as e:
        print(f"  ✗ FAILED with exception: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_dilithium_kyber_hybrid_signatures():
    """TEST 1: Dilithium-Kyber hybrid signature verification"""
    signer = DilithiumSimulatedSignature()
    
    priv_key, pub_key = signer.generate_keypair()
    message = b"Test message for post-quantum signature"
    
    signature = signer.sign(priv_key, message)
    verified = signer.verify(pub_key, message, signature)
    
    assert len(priv_key) == 64, "Private key should be 64 bytes"
    assert len(pub_key) == 64, "Public key should be 64 bytes"
    assert verified == True, "Signature should verify correctly"
    
    print(f"  ✓ Key pair generated: priv={len(priv_key)} bytes, pub={len(pub_key)} bytes")
    print(f"  ✓ Signature verified: {verified}")
    
    return True

def test_constant_time_operations():
    """TEST 2: Constant-time operations for side-channel resistance"""
    ct_ops = ConstantTimeOperations()
    
    # Test equality
    assert ct_ops.ct_equal(42, 42) == True, "Equal values should return True"
    assert ct_ops.ct_equal(42, 43) == False, "Different values should return False"
    
    # Test zero check
    assert ct_ops.ct_is_zero(0) == True, "Zero should return True"
    assert ct_ops.ct_is_zero(1) == False, "Non-zero should return False"
    
    # Test conditional select
    assert ct_ops.ct_select(True, 100, 200) == 100, "Should select first value"
    assert ct_ops.ct_select(False, 100, 200) == 200, "Should select second value"
    
    print(f"  ✓ ct_equal: constant-time comparison working")
    print(f"  ✓ ct_is_zero: constant-time zero check working")
    print(f"  ✓ ct_select: constant-time conditional selection working")
    
    return True

def test_zero_knowledge_proofs():
    """TEST 3: Zero-Knowledge Proof computation integrity"""
    verifier = ZeroKnowledgeProofVerifier()
    
    session_id = "test-session-001"
    inputs = [10, 20, 30, 40]
    result = 100
    
    proof = verifier.generate_proof(session_id, inputs, result)
    verified = verifier.verify_proof(proof, inputs, result)
    
    assert proof.proof_id is not None, "Should have proof ID"
    assert proof.statement_hash is not None, "Should have statement hash"
    assert verified == True, "Proof should verify correctly"
    
    print(f"  ✓ Proof generated: {proof.proof_id}")
    print(f"  ✓ Proof verified: {verified}")
    print(f"  ✓ Statement hash: {proof.statement_hash[:16]}...")
    
    return True

def test_session_resumption_tickets():
    """TEST 4: Secure session resumption with tickets"""
    manager = MPCSessionManager()
    
    session_id = manager.create_session("alice", ComputationType.SUM, threshold=2)
    manager.add_participant(session_id, "bob")
    
    # Create resumption ticket
    ticket_id = manager.create_resumption_ticket(session_id, "alice")
    
    # Resume session
    resumed_id = manager.resume_session(ticket_id, "alice")
    
    assert ticket_id is not None, "Should create ticket"
    assert resumed_id == session_id, "Should resume same session"
    
    status = manager.get_session_status(session_id)
    assert status["state"] == "resumed", "Session should be in resumed state"
    
    print(f"  ✓ Ticket created: {ticket_id[:16]}...")
    print(f"  ✓ Session resumed: {resumed_id is not None}")
    print(f"  ✓ Session state: {status['state']}")
    
    return True

def test_participant_heartbeat_adaptive_threshold():
    """TEST 5: Participant heartbeat with adaptive threshold adjustment"""
    manager = MPCSessionManager()
    
    session_id = manager.create_session("alice", ComputationType.SUM, threshold=3)
    manager.add_participant(session_id, "bob")
    manager.add_participant(session_id, "charlie")
    manager.add_participant(session_id, "dave")
    
    initial_status = manager.get_session_status(session_id)
    
    # Send heartbeats
    manager.participant_heartbeat(session_id, "alice")
    manager.participant_heartbeat(session_id, "bob")
    manager.participant_heartbeat(session_id, "charlie")
    
    after_status = manager.get_session_status(session_id)
    
    assert initial_status["threshold"] == 3, "Initial threshold should be 3"
    assert after_status["adaptive_threshold"] == 3, "Adaptive threshold should be maintained"
    
    print(f"  ✓ Initial threshold: {initial_status['threshold']}")
    print(f"  ✓ Adaptive threshold: {after_status['adaptive_threshold']}")
    print(f"  ✓ Heartbeats processed successfully")
    
    return True

def test_merkle_audit_log_integrity():
    """TEST 6: Merkle tree audit log integrity proofs"""
    audit_log = SessionAuditLog()
    
    audit_log.add_entry("session_created", "alice", {"session": "test-001"})
    audit_log.add_entry("participant_added", "bob", {})
    audit_log.add_entry("computation_executed", None, {"result": 100})
    
    merkle_root = audit_log.get_merkle_root()
    integrity_valid = audit_log.verify_integrity()
    
    assert len(audit_log.entries) == 3, "Should have 3 audit entries"
    assert merkle_root != "0" * 64, "Should have valid Merkle root"
    assert integrity_valid == True, "Audit log integrity should verify"
    
    print(f"  ✓ Audit entries: {len(audit_log.entries)}")
    print(f"  ✓ Merkle root: {merkle_root[:32]}...")
    print(f"  ✓ Integrity verified: {integrity_valid}")
    
    return True

def test_batch_computation_high_throughput():
    """TEST 7: Batch computation for high-throughput scenarios"""
    engine = SecureMPCComputationEngine()
    
    # Batch of input batches
    input_batches = [
        [1, 2, 3],
        [10, 20, 30],
        [100, 200, 300]
    ]
    
    results = engine.secure_batch_sum(input_batches)
    
    assert len(results) == 3, "Should have 3 batch results"
    assert results[0] == 6, "First batch sum should be 6"
    assert results[1] == 60, "Second batch sum should be 60"
    assert results[2] == 600, "Third batch sum should be 600"
    
    print(f"  ✓ Input batches: {len(input_batches)} batches")
    print(f"  ✓ Batch results: {results}")
    print(f"  ✓ Batch processing working correctly")
    
    return True

def test_complete_mpc_workflow_all_v6_features():
    """TEST 8: Complete MPC workflow with all v6 security features"""
    manager = MPCSessionManager()
    
    # Create session
    session_id = manager.create_session("alice", ComputationType.SUM, threshold=2)
    manager.add_participant(session_id, "bob")
    
    # Key exchange (post-quantum)
    manager.perform_key_exchange(session_id)
    
    # Distribute secret shares
    manager.distribute_secret_shares(session_id)
    
    # Submit inputs
    manager.submit_private_input(session_id, "alice", 100)
    manager.submit_private_input(session_id, "bob", 300)
    
    # Execute computation
    result = manager.execute_computation(session_id)
    
    # Verify result
    verified = manager.verify_result(session_id)
    
    status = manager.get_session_status(session_id)
    
    assert result is not None, "Should have computation result"
    assert result.result_value == 400, "Sum should be 400"
    assert result.zkp_verified == True, "ZKP should be verified"
    assert result.signature is not None, "Result should be signed"
    assert verified == True, "Result should verify"
    
    print(f"  ✓ Session created: {session_id[:24]}...")
    print(f"  ✓ Computation result: {result.result_value}")
    print(f"  ✓ ZKP verified: {result.zkp_verified}")
    print(f"  ✓ Result signed: {result.signature is not None}")
    print(f"  ✓ Latency: {result.computation_latency_ms:.2f}ms")
    print(f"  ✓ Final state: {status['state']}")
    print(f"  ✓ Merkle root: {status['merkle_root'][:16]}...")
    
    return True

def test_forward_secrecy_ephemeral_key_rotation():
    """TEST 9: Forward secrecy with ephemeral key rotation"""
    manager = MPCSessionManager()
    
    session_id = manager.create_session("alice", ComputationType.SUM, threshold=2)
    manager.add_participant(session_id, "bob")
    manager.perform_key_exchange(session_id)
    manager.distribute_secret_shares(session_id)
    
    # Perform multiple computations to trigger key rotation
    operations = 0
    for i in range(15):  # More than rotation interval (3)
        manager.submit_private_input(session_id, "alice", i * 10)
        manager.submit_private_input(session_id, "bob", i * 20)
        result = manager.execute_computation(session_id)
        if result:
            operations += 1
    
    status = manager.get_session_status(session_id)
    key_count = len(manager.ephemeral_keys.get(session_id, []))
    
    assert operations == 15, "Should execute 15 operations"
    assert key_count >= 5, "Should have rotated keys multiple times (15/3 = 5)"
    
    print(f"  ✓ Operations executed: {operations}")
    print(f"  ✓ Key rotations performed: {key_count}")
    print(f"  ✓ Forward secrecy keys maintained: {key_count > 1}")
    
    return True

def test_manager_statistics_feature_reporting():
    """TEST 10: Manager statistics and feature reporting"""
    manager = MPCSessionManager()
    
    # Create multiple sessions
    s1 = manager.create_session("alice", ComputationType.SUM)
    s2 = manager.create_session("bob", ComputationType.AVERAGE)
    s3 = manager.create_session("charlie", ComputationType.MAX)
    
    stats = manager.get_stats()
    
    assert stats["version"] == "6.0.0", "Should be version 6.0.0"
    assert stats["active_sessions"] == 3, "Should have 3 active sessions"
    assert stats["security_level"] == 3, "Should be NIST Level 3 security"
    assert len(stats["features"]) == 10, "Should report all 10 v6 features"
    
    print(f"  ✓ Version: {stats['version']}")
    print(f"  ✓ Active sessions: {stats['active_sessions']}")
    print(f"  ✓ Security level: NIST Level {stats['security_level']}")
    print(f"  ✓ Features implemented: {len(stats['features'])}")
    for feature in stats["features"]:
        print(f"    - {feature}")
    
    return True

def main():
    """Run all tests"""
    print("=" * 70)
    print("QuantumCrypt-AI: Testing Post-Quantum MPC Session Manager v6")
    print("=" * 70)
    
    tests = [
        ("1: Dilithium-Kyber hybrid signature verification", test_dilithium_kyber_hybrid_signatures),
        ("2: Constant-time operations for side-channel resistance", test_constant_time_operations),
        ("3: Zero-Knowledge Proof computation integrity", test_zero_knowledge_proofs),
        ("4: Secure session resumption with tickets", test_session_resumption_tickets),
        ("5: Participant heartbeat with adaptive threshold", test_participant_heartbeat_adaptive_threshold),
        ("6: Merkle tree audit log integrity proofs", test_merkle_audit_log_integrity),
        ("7: Batch computation for high-throughput", test_batch_computation_high_throughput),
        ("8: Complete MPC workflow with all v6 features", test_complete_mpc_workflow_all_v6_features),
        ("9: Forward secrecy with ephemeral key rotation", test_forward_secrecy_ephemeral_key_rotation),
        ("10: Manager statistics and feature reporting", test_manager_statistics_feature_reporting),
    ]
    
    results = []
    for name, func in tests:
        results.append(run_test(name, func))
    
    passed = sum(results)
    total = len(results)
    
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY:")
    print(f"  Passed: {passed}")
    print(f"  Failed: {total - passed}")
    print(f"  Success rate: {passed/total*100:.1f}%")
    print("=" * 70)
    
    # Save results
    result_data = {
        "test_version": "v6",
        "timestamp": time.time(),
        "passed": passed,
        "failed": total - passed,
        "success_rate": passed / total,
        "tests": [t[0] for t in tests]
    }
    
    with open('/home/user/.super_doubao/super-doubao-runtime/workspace/QuantumCrypt-AI/test_results_mpc_session_manager_v6_2026_june.json', 'w') as f:
        json.dump(result_data, f, indent=2)
    
    print(f"\nResults saved to test_results_mpc_session_manager_v6_2026_june.json")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
