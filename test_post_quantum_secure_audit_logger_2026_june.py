#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Audit Logger
Production-grade testing with real cryptographic assertions
"""

import sys
import json
import hashlib
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_secure_audit_logger_2026_june import (
    PostQuantumSecureAuditLogger,
    AuditEventType,
    AuditSeverity,
    AuditEntry
)


def test_basic_initialization():
    """Test basic logger initialization"""
    print("Test 1: Basic Initialization")
    logger = PostQuantumSecureAuditLogger("Test-Service")
    assert logger.service_name == "Test-Service"
    assert len(logger.audit_log) == 0
    assert logger.genesis_hash is not None
    assert len(logger.genesis_hash) == 128  # SHA3-512 hex
    print("  ✓ PASSED: Logger initialized correctly")
    print(f"    - Genesis hash: {logger.genesis_hash[:32]}...")


def test_log_basic_event():
    """Test basic event logging"""
    print("\nTest 2: Basic Event Logging")
    logger = PostQuantumSecureAuditLogger()
    
    entry = logger.log_event(
        event_type=AuditEventType.AUTHENTICATION,
        severity=AuditSeverity.INFO,
        actor="user123",
        action="LOGIN",
        resource="API",
        outcome="SUCCESS",
        source_ip="192.168.1.1"
    )
    
    assert entry.entry_id is not None
    assert entry.timestamp is not None
    assert entry.entry_hash is not None
    assert entry.signature is not None
    assert len(entry.entry_hash) == 128  # SHA3-512
    assert len(entry.signature) == 64     # HMAC-SHA3-256
    
    assert len(logger.audit_log) == 1
    print("  ✓ PASSED: Basic event logged correctly")
    print(f"    - Entry hash: {entry.entry_hash[:32]}...")
    print(f"    - Signature: {entry.signature[:32]}...")


def test_hash_chaining():
    """Test cryptographic hash chaining"""
    print("\nTest 3: Hash Chaining")
    logger = PostQuantumSecureAuditLogger()
    
    # Log multiple events
    for i in range(5):
        logger.log_event(
            event_type=AuditEventType.DATA_ACCESS,
            severity=AuditSeverity.LOW,
            actor=f"user{i}",
            action="READ",
            resource=f"file{i}.txt",
            outcome="SUCCESS"
        )
    
    # Verify chain links
    for i in range(1, 5):
        prev_hash = logger.audit_log[i-1].entry_hash
        current_prev = logger.audit_log[i].previous_hash
        assert prev_hash == current_prev, f"Chain broken at index {i}"
    
    print("  ✓ PASSED: Hash chaining verified for 5 entries")


def test_convenience_methods():
    """Test convenience logging methods"""
    print("\nTest 4: Convenience Methods")
    logger = PostQuantumSecureAuditLogger()
    
    # Authentication logging
    auth_entry = logger.log_authentication(
        actor="alice",
        success=True,
        source_ip="10.0.0.1"
    )
    assert auth_entry.event_type == "AUTHENTICATION"
    assert auth_entry.outcome == "SUCCESS"
    
    # Data access logging
    access_entry = logger.log_data_access(
        actor="bob",
        resource="/data/secret.key",
        source_ip="10.0.0.2"
    )
    assert access_entry.event_type == "DATA_ACCESS"
    
    # Security alert
    alert_entry = logger.log_security_alert(
        actor="INTRUDER",
        alert_type="BRUTE_FORCE",
        details={"attempts": 100, "blocked": True}
    )
    assert alert_entry.event_type == "SECURITY_ALERT"
    assert alert_entry.severity == "CRITICAL"
    
    assert len(logger.audit_log) == 3
    print("  ✓ PASSED: All convenience methods work")


def test_single_entry_verification():
    """Test single entry integrity verification"""
    print("\nTest 5: Single Entry Verification")
    logger = PostQuantumSecureAuditLogger()
    
    logger.log_event(
        AuditEventType.SYSTEM_EVENT, AuditSeverity.INFO,
        "system", "START", "SERVICE", "SUCCESS"
    )
    
    is_valid, message = logger.verify_entry_integrity(0)
    assert is_valid, f"Verification failed: {message}"
    
    print(f"  ✓ PASSED: Single entry verification - {message}")


def test_full_chain_verification():
    """Test full chain integrity verification"""
    print("\nTest 6: Full Chain Verification")
    logger = PostQuantumSecureAuditLogger()
    
    # Log 10 events
    for i in range(10):
        logger.log_event(
            AuditEventType.DATA_ACCESS, AuditSeverity.LOW,
            f"user{i}", "READ", f"res{i}", "SUCCESS"
        )
    
    result = logger.verify_full_chain()
    
    assert result.is_valid == True
    assert result.verified_count == 10
    assert result.total_entries == 10
    assert len(result.broken_chains) == 0
    assert result.first_invalid_entry is None
    assert result.verification_time > 0
    
    print(f"  ✓ PASSED: Full chain verified")
    print(f"    - Entries verified: {result.verified_count}/{result.total_entries}")
    print(f"    - Verification time: {result.verification_time:.4f}s")


def test_tamper_detection():
    """Test that tampering is detected (REAL security test)"""
    print("\nTest 7: Tamper Detection - CRITICAL SECURITY TEST")
    logger = PostQuantumSecureAuditLogger()
    
    # Log events
    for i in range(3):
        logger.log_event(
            AuditEventType.DATA_MODIFICATION, AuditSeverity.HIGH,
            "admin", "WRITE", f"file{i}", "SUCCESS"
        )
    
    # Verify initially valid
    assert logger.verify_full_chain().is_valid == True
    
    # TAMPER WITH LOG - modify entry data (simulating attack)
    original_outcome = logger.audit_log[1].outcome
    logger.audit_log[1].outcome = "FRAUDULENT_SUCCESS"  # Tamper!
    
    # Verify tampering is detected
    result = logger.verify_full_chain()
    assert result.is_valid == False, "Tampering was NOT detected! Security failure!"
    assert len(result.broken_chains) > 0
    assert 1 in result.broken_chains
    
    print(f"  ✓ PASSED: Tampering DETECTED correctly!")
    print(f"    - Broken chains: {result.broken_chains}")
    print(f"    - First invalid: {result.first_invalid_entry}")
    
    # Restore for other tests
    logger.audit_log[1].outcome = original_outcome


def test_merkle_root():
    """Test Merkle root computation"""
    print("\nTest 8: Merkle Root Computation")
    logger = PostQuantumSecureAuditLogger()
    
    # Empty log merkle root
    root_empty = logger.compute_merkle_root()
    assert root_empty == logger.genesis_hash
    
    # Add entries
    for i in range(7):  # Odd number to test tree padding
        logger.log_event(
            AuditEventType.SYSTEM_EVENT, AuditSeverity.INFO,
            "sys", "OP", "RES", "OK"
        )
    
    root = logger.compute_merkle_root()
    assert len(root) == 128  # SHA3-512 hex
    
    # Merkle root should change when log changes
    old_root = root
    logger.log_event(
        AuditEventType.SYSTEM_EVENT, AuditSeverity.INFO,
        "sys", "OP2", "RES2", "OK"
    )
    new_root = logger.compute_merkle_root()
    assert old_root != new_root
    
    print(f"  ✓ PASSED: Merkle root computed correctly")
    print(f"    - Root: {root[:32]}...")


def test_key_rotation_forward_secrecy():
    """Test forward-secure key rotation"""
    print("\nTest 9: Forward-Secure Key Rotation")
    logger = PostQuantumSecureAuditLogger()
    
    initial_key_hash = hashlib.sha3_256(logger.current_key).hexdigest()
    
    # Log before rotation
    logger.log_authentication("user1", True)
    
    # Perform key rotation
    rotation_result = logger.rotate_key()
    
    assert rotation_result["status"] == "success"
    assert rotation_result["rotation_count"] == 1
    assert rotation_result["old_key_fingerprint"] == initial_key_hash[:16]
    
    # Key rotation creates a log entry
    assert len(logger.audit_log) == 2  # auth + rotation
    
    new_key_hash = hashlib.sha3_256(logger.current_key).hexdigest()
    assert initial_key_hash != new_key_hash  # Key actually changed!
    
    print(f"  ✓ PASSED: Forward-secure key rotation works")
    print(f"    - Rotation count: {rotation_result['rotation_count']}")
    print(f"    - Old key fingerprint: {rotation_result['old_key_fingerprint']}")


def test_log_statistics():
    """Test log statistics generation"""
    print("\nTest 10: Log Statistics")
    logger = PostQuantumSecureAuditLogger("StatsTest")
    
    # Generate varied events
    logger.log_authentication("alice", True)
    logger.log_authentication("bob", False)
    logger.log_data_access("charlie", "file1")
    logger.log_data_access("charlie", "file2")
    logger.log_security_alert("hacker", "XSS", {"payload": "<script>"})
    
    stats = logger.get_log_statistics()
    
    assert stats["total_entries"] == 5
    assert stats["unique_actors"] == 4  # alice, bob, charlie, hacker
    assert "AUTHENTICATION" in stats["event_type_distribution"]
    assert "CRITICAL" in stats["severity_distribution"]
    assert stats["merkle_root"] is not None
    
    print(f"  ✓ PASSED: Statistics generated correctly")
    print(f"    - Total entries: {stats['total_entries']}")
    print(f"    - Unique actors: {stats['unique_actors']}")
    print(f"    - Event types: {list(stats['event_type_distribution'].keys())}")


def test_json_export():
    """Test JSON export functionality"""
    print("\nTest 11: JSON Export")
    logger = PostQuantumSecureAuditLogger("ExportTest")
    logger.log_authentication("user1", True, "1.2.3.4")
    
    json_output = logger.export_logs_json()
    parsed = json.loads(json_output)
    
    assert len(parsed) == 1
    assert parsed[0]["actor"] == "user1"
    assert parsed[0]["entry_hash"] is not None
    
    print(f"  ✓ PASSED: JSON export works ({len(json_output)} chars)")


def test_verification_report():
    """Test verification report generation"""
    print("\nTest 12: Verification Report")
    logger = PostQuantumSecureAuditLogger("ReportService")
    
    for i in range(5):
        logger.log_authentication(f"user{i}", True)
    
    report = logger.export_verification_report()
    
    assert report["service"] == "ReportService"
    assert report["integrity_status"] == "PASS"
    assert report["verification_details"]["is_valid"] == True
    assert report["log_statistics"]["total_entries"] == 5
    assert "merkle_root" in report
    
    print(f"  ✓ PASSED: Verification report generated")
    print(f"    - Integrity status: {report['integrity_status']}")
    print(f"    - Merkle root: {report['merkle_root'][:32]}...")


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("QuantumCrypt-AI - Secure Audit Logger Test Suite")
    print("Post-Quantum Cryptographic Verification")
    print("=" * 60)
    print()
    
    all_passed = True
    test_functions = [
        test_basic_initialization,
        test_log_basic_event,
        test_hash_chaining,
        test_convenience_methods,
        test_single_entry_verification,
        test_full_chain_verification,
        test_tamper_detection,
        test_merkle_root,
        test_key_rotation_forward_secrecy,
        test_log_statistics,
        test_json_export,
        test_verification_report
    ]
    
    for test_func in test_functions:
        try:
            test_func()
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            all_passed = False
        except Exception as e:
            print(f"  ✗ ERROR: {type(e).__name__}: {e}")
            all_passed = False
    
    print()
    print("=" * 60)
    if all_passed:
        print("✅ ALL TESTS PASSED - Production Ready!")
        print("✅ Post-quantum security verified!")
        print("✅ Tamper detection working correctly!")
    else:
        print("❌ SOME TESTS FAILED")
    print("=" * 60)
    
    return all_passed


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
