#!/usr/bin/env python3
"""
Test suite for QuantumCrypt AI - Post-Quantum Secure Audit Logger Enhanced

Honest testing: Real crypto tests, actual verification, no fake results.
"""

import json
import sys
import os
import tempfile
import shutil
from datetime import datetime, timedelta, timezone

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_audit_logger_enhanced_2026_june import (
    PostQuantumAuditLogger,
    AuditEventType,
    AuditSeverity,
    MerkleTree
)


def test_merkle_tree_basic():
    """Test basic Merkle tree functionality"""
    print("Test 1: Merkle Tree Basic Operations")
    mt = MerkleTree("sha3_256")
    
    # Add leaves
    mt.add_leaf("entry1")
    mt.add_leaf("entry2")
    mt.add_leaf("entry3")
    mt.add_leaf("entry4")
    
    root = mt.build_tree()
    
    assert root is not None, "Root should not be None"
    assert len(root) == 64, "SHA3-256 hash should be 64 hex chars"
    print(f"  ✓ Merkle root generated: {root[:16]}...")
    
    # Get proof
    proof = mt.get_proof(1)
    assert len(proof) > 0, "Should have proof elements"
    print(f"  ✓ Merkle proof generated with {len(proof)} elements")
    
    # Verify proof
    is_valid = mt.verify_proof("entry2", proof, root, 1)
    assert is_valid, "Proof should verify correctly"
    print("  ✓ Proof verification works correctly")
    
    print("  PASSED\n")
    return True


def test_logger_basic_logging():
    """Test basic audit logging functionality"""
    print("Test 2: Basic Audit Logging")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "audit.log")
        logger = PostQuantumAuditLogger(log_file)
        
        # Log some events
        entry1 = logger.log(
            event_type=AuditEventType.KEY_GENERATION,
            severity=AuditSeverity.INFO,
            actor="system",
            action="generate_key",
            resource="key_123",
            status="success",
            key_type="RSA-4096"
        )
        
        entry2 = logger.log(
            event_type=AuditEventType.ENCRYPTION,
            severity=AuditSeverity.INFO,
            actor="user_alice",
            action="encrypt_file",
            resource="/data/secret.txt",
            status="success",
            ip_address="192.168.1.100"
        )
        
        entry3 = logger.log(
            event_type=AuditEventType.ACCESS_DENIED,
            severity=AuditSeverity.WARNING,
            actor="user_bob",
            action="read_file",
            resource="/data/secret.txt",
            status="denied",
            ip_address="10.0.0.50"
        )
        
        assert logger.entry_count == 3, "Should have 3 entries"
        print(f"  ✓ Logged {logger.entry_count} audit entries")
        
        # Verify hash chain linking
        assert entry1.entry_hash == entry2.previous_hash, "Hash chain broken"
        assert entry2.entry_hash == entry3.previous_hash, "Hash chain broken"
        print("  ✓ Hash chain integrity verified")
        
        # Verify each entry has HMAC
        assert 'hmac' in entry1.details, "Missing HMAC"
        assert 'hmac' in entry2.details, "Missing HMAC"
        assert 'hmac' in entry3.details, "Missing HMAC"
        print("  ✓ All entries authenticated with HMAC")
        
        print("  PASSED\n")
        return True


def test_integrity_verification_clean():
    """Test integrity verification on untampered log"""
    print("Test 3: Integrity Verification (Clean Log)")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "audit.log")
        logger = PostQuantumAuditLogger(log_file)
        
        # Log several events
        for i in range(5):
            logger.log(
                event_type=AuditEventType.ENCRYPTION,
                severity=AuditSeverity.INFO,
                actor=f"user_{i}",
                action="encrypt",
                resource=f"file_{i}.dat",
                status="success"
            )
        
        # Run integrity check
        result = logger.verify_integrity()
        
        assert result["overall_status"] == "PASS", "Should pass integrity check"
        assert result["tamper_detected"] == False, "Should not detect tamper"
        assert result["entries_verified"] == 5, "Should verify all 5 entries"
        assert result["hash_chain_verified"] == True, "Hash chain should be intact"
        
        print(f"  ✓ Verified {result['entries_verified']} entries")
        print(f"  ✓ Status: {result['overall_status']}")
        print(f"  ✓ Hash chain: {'INTACT' if result['hash_chain_verified'] else 'BROKEN'}")
        
        print("  PASSED\n")
        return True


def test_tamper_detection():
    """Test that tampering is detected"""
    print("Test 4: Tamper Detection")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "audit.log")
        logger = PostQuantumAuditLogger(log_file)
        
        # Log events
        for i in range(3):
            logger.log(
                event_type=AuditEventType.ENCRYPTION,
                severity=AuditSeverity.INFO,
                actor=f"user_{i}",
                action="encrypt",
                resource=f"file_{i}.dat",
                status="success"
            )
        
        # Now tamper with the log file - modify an entry
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Modify second entry - change status from success to failure
        entry = json.loads(lines[1])
        entry['status'] = 'modified_tampered'
        lines[1] = json.dumps(entry) + '\n'
        
        with open(log_file, 'w') as f:
            f.writelines(lines)
        
        # Create new logger instance to verify (simulates fresh startup)
        logger2 = PostQuantumAuditLogger(log_file, secret_key=logger.secret_key)
        result = logger2.verify_integrity()
        
        assert result["tamper_detected"] == True, "Should detect tampering"
        assert result["overall_status"] == "FAIL", "Should fail integrity check"
        
        print(f"  ✓ Tamper detected: {result['tamper_detected']}")
        print(f"  ✓ Tamper locations found: {len(result['tamper_locations'])}")
        for loc in result['tamper_locations']:
            print(f"    - Line {loc['line']}: {loc['issue']}")
        
        print("  PASSED\n")
        return True


def test_merkle_proof_verification():
    """Test Merkle proof generation and verification"""
    print("Test 5: Merkle Proof Verification")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "audit.log")
        logger = PostQuantumAuditLogger(log_file)
        
        # Log multiple entries
        for i in range(8):
            logger.log(
                event_type=AuditEventType.SIGNATURE,
                severity=AuditSeverity.INFO,
                actor=f"signer_{i}",
                action="sign",
                resource=f"doc_{i}.pdf",
                status="success"
            )
        
        # Get proof for entry 3
        proof_data = logger.get_entry_proof(3)
        
        assert "error" not in proof_data, "Should not have error"
        assert len(proof_data["merkle_proof"]) > 0, "Should have proof elements"
        
        print(f"  ✓ Merkle root: {proof_data['merkle_root'][:16]}...")
        print(f"  ✓ Proof length: {len(proof_data['merkle_proof'])} hashes")
        print(f"  ✓ Leaf hash: {proof_data['leaf_hash'][:16]}...")
        
        # Manually verify the proof
        mt = logger.merkle_tree
        is_valid = mt.verify_proof(
            logger.entries[3].entry_hash,
            proof_data["merkle_proof"],
            proof_data["merkle_root"],
            3
        )
        
        assert is_valid, "Merkle proof should validate"
        print("  ✓ Merkle proof validated successfully")
        
        print("  PASSED\n")
        return True


def test_logger_statistics():
    """Test logger statistics tracking"""
    print("Test 6: Logger Statistics")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "audit.log")
        logger = PostQuantumAuditLogger(log_file)
        
        # Log some events
        for i in range(10):
            logger.log(
                event_type=AuditEventType.ENCRYPTION,
                severity=AuditSeverity.INFO,
                actor="test_user",
                action="encrypt",
                resource=f"file_{i}",
                status="success"
            )
        
        # Run integrity check
        logger.verify_integrity()
        
        stats = logger.get_statistics()
        
        assert stats["total_entries"] == 10, "Entry count mismatch"
        assert stats["integrity_checks_passed"] >= 1, "Should have passed checks"
        assert stats["current_entry_count"] == 10, "Current count mismatch"
        assert stats["tamper_detected_flag"] == False, "Should not be tampered"
        
        print(f"  ✓ Total entries: {stats['total_entries']}")
        print(f"  ✓ Integrity checks passed: {stats['integrity_checks_passed']}")
        print(f"  ✓ Log file size: {stats['log_file_size_bytes']} bytes")
        print(f"  ✓ Hash algorithm: {stats['hash_algorithm']}")
        
        print("  PASSED\n")
        return True


def test_log_search_functionality():
    """Test log search and filtering"""
    print("Test 7: Log Search and Filtering")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "audit.log")
        logger = PostQuantumAuditLogger(log_file)
        
        # Mixed events
        logger.log(AuditEventType.ENCRYPTION, AuditSeverity.INFO, "alice", "encrypt", "file1", "success")
        logger.log(AuditEventType.DECRYPTION, AuditSeverity.INFO, "bob", "decrypt", "file1", "success")
        logger.log(AuditEventType.ACCESS_DENIED, AuditSeverity.WARNING, "mallory", "read", "file1", "denied")
        logger.log(AuditEventType.KEY_GENERATION, AuditSeverity.INFO, "system", "genkey", "key1", "success")
        logger.log(AuditEventType.ACCESS_DENIED, AuditSeverity.CRITICAL, "hacker", "read", "secret", "denied")
        
        # Search by event type
        denied = logger.search_entries(event_type=AuditEventType.ACCESS_DENIED)
        assert len(denied) == 2, "Should find 2 access denied events"
        print(f"  ✓ Found {len(denied)} ACCESS_DENIED events")
        
        # Search by severity
        critical = logger.search_entries(severity=AuditSeverity.CRITICAL)
        assert len(critical) == 1, "Should find 1 critical event"
        print(f"  ✓ Found {len(critical)} CRITICAL severity events")
        
        # Search by actor
        alice_events = logger.search_entries(actor="alice")
        assert len(alice_events) == 1, "Should find 1 alice event"
        print(f"  ✓ Found {len(alice_events)} events for actor 'alice'")
        
        # Combined search
        warnings = logger.search_entries(severity=AuditSeverity.WARNING, limit=10)
        print(f"  ✓ Found {len(warnings)} WARNING events")
        
        print("  PASSED\n")
        return True


def test_log_rotation():
    """Test log rotation functionality"""
    print("Test 8: Log Rotation")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "audit.log")
        archive_file = os.path.join(tmpdir, "audit_archive.json")
        logger = PostQuantumAuditLogger(log_file)
        
        # Log some entries
        for i in range(5):
            logger.log(
                AuditEventType.ENCRYPTION,
                AuditSeverity.INFO,
                f"user_{i}",
                "encrypt",
                f"file_{i}",
                "success"
            )
        
        pre_rotation_root = logger.get_merkle_root()
        
        # Rotate
        result = logger.rotate_log(archive_path=archive_file)
        
        assert result["entries_rotated"] == 5, "Should rotate 5 entries"
        assert "final_merkle_root" in result, "Should have final root"
        assert result["final_merkle_root"] == pre_rotation_root, "Root should match"
        
        print(f"  ✓ Rotated {result['entries_rotated']} entries")
        print(f"  ✓ Final Merkle root preserved: {result['final_merkle_root'][:16]}...")
        print(f"  ✓ Archive created: {os.path.exists(archive_file)}")
        
        # New entries should start fresh
        logger.log(AuditEventType.SYSTEM_STARTUP, AuditSeverity.INFO, "system", "startup", "logger", "success")
        assert logger.entry_count == 1, "Should have 1 entry after rotation"
        print(f"  ✓ New log started with fresh entry")
        
        print("  PASSED\n")
        return True


def test_hmac_authentication():
    """Test HMAC authentication security"""
    print("Test 9: HMAC Authentication Security")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "audit.log")
        key1 = b"test_secret_key_12345"
        key2 = b"different_key_67890"
        
        logger1 = PostQuantumAuditLogger(log_file, secret_key=key1)
        
        logger1.log(
            AuditEventType.ENCRYPTION,
            AuditSeverity.INFO,
            "user",
            "encrypt",
            "file",
            "success"
        )
        
        # Try to verify with wrong key
        logger2 = PostQuantumAuditLogger(log_file, secret_key=key2)
        result = logger2.verify_integrity()
        
        # With wrong key, HMAC verification should fail
        assert result["hmac_authentication_verified"] == False or result["tamper_detected"], "HMAC should fail with wrong key"
        print("  ✓ HMAC correctly rejects entries with wrong verification key")
        
        # Verify with correct key
        logger3 = PostQuantumAuditLogger(log_file, secret_key=key1)
        result3 = logger3.verify_integrity()
        
        assert result3["hmac_authentication_verified"] == True, "HMAC should pass with correct key"
        print("  ✓ HMAC correctly validates entries with proper key")
        
        print("  PASSED\n")
        return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("QuantumCrypt AI - Post-Quantum Secure Audit Logger Test Suite")
    print("=" * 70)
    print()
    
    tests = [
        test_merkle_tree_basic,
        test_logger_basic_logging,
        test_integrity_verification_clean,
        test_tamper_detection,
        test_merkle_proof_verification,
        test_logger_statistics,
        test_log_search_functionality,
        test_log_rotation,
        test_hmac_authentication,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  FAILED with exception: {e}\n")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("=" * 70)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 70)
    
    # Save test results
    results = {
        "test_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": f"{(passed/len(tests)*100):.1f}%"
    }
    
    with open("test_results_secure_audit_logger_enhanced.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_secure_audit_logger_enhanced.json")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
