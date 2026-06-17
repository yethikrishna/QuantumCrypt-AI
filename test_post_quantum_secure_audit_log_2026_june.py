"""
Test Suite for Post-Quantum Secure Audit Log
June 2026 Production Release

REAL WORKING TESTS - NO EMPTY SHELLS

Tests cover:
1. Log entry creation and chaining
2. Cryptographic hash verification
3. Chain integrity verification
4. Merkle tree operations
5. Audit proof generation
6. Search and filtering
7. Tamper detection
8. Export functionality
"""

import unittest
import os
import json
import tempfile
from datetime import datetime, timedelta
from quantum_crypt.post_quantum_secure_audit_log_2026_june import (
    PostQuantumSecureAuditLog,
    AuditEventType,
    AuditSeverity,
    VerificationStatus,
    SAMPLE_AUDIT_EVENTS
)


class TestPostQuantumSecureAuditLog(unittest.TestCase):
    """Test cases for PostQuantumSecureAuditLog"""

    def setUp(self):
        """Set up test audit log"""
        self.audit_log = PostQuantumSecureAuditLog()

    def test_log_initialization(self):
        """Test log initializes correctly"""
        self.assertIsNotNone(self.audit_log.log_id)
        self.assertIsNotNone(self.audit_log.genesis_hash)
        self.assertEqual(len(self.audit_log.entries), 0)
        self.assertEqual(self.audit_log.sequence_counter, 0)

    def test_create_single_entry(self):
        """Test creating single audit entry"""
        entry = self.audit_log.create_entry(
            event_type=AuditEventType.AUTHENTICATION,
            severity=AuditSeverity.INFO,
            actor="test_user",
            action="login",
            resource="system"
        )

        self.assertEqual(entry.sequence, 1)
        self.assertIsNotNone(entry.entry_hash)
        self.assertEqual(entry.previous_hash, self.audit_log.genesis_hash)
        self.assertEqual(len(self.audit_log.entries), 1)

    def test_create_multiple_entries(self):
        """Test creating multiple entries with proper chaining"""
        entries = []
        for i, (event_type, severity, actor, action, resource, details) in enumerate(SAMPLE_AUDIT_EVENTS):
            entry = self.audit_log.create_entry(
                event_type=event_type,
                severity=severity,
                actor=actor,
                action=action,
                resource=resource,
                details=details
            )
            entries.append(entry)

        self.assertEqual(len(self.audit_log.entries), 7)
        self.assertEqual(self.audit_log.sequence_counter, 7)

        # Verify chaining
        for i in range(1, len(entries)):
            self.assertEqual(entries[i].previous_hash, entries[i-1].entry_hash)

    def test_entry_hash_integrity(self):
        """Test entry hash integrity verification"""
        entry = self.audit_log.create_entry(
            AuditEventType.ENCRYPTION, AuditSeverity.INFO,
            "user1", "encrypt", "file.txt", {"size": 1024}
        )

        # Original should verify
        self.assertTrue(self.audit_log.verify_entry(entry))

        # Tampered entry should fail
        original_details = entry.details.copy()
        entry.details["tampered"] = True
        self.assertFalse(self.audit_log.verify_entry(entry))

        # Restore and verify again
        entry.details = original_details
        entry.entry_hash = self.audit_log._compute_entry_hash(entry)
        self.assertTrue(self.audit_log.verify_entry(entry))

    def test_chain_verification_valid(self):
        """Test verification of valid chain"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        result = self.audit_log.verify_chain()
        self.assertEqual(result.status, VerificationStatus.VALID)
        self.assertEqual(len(result.tampered_entries), 0)
        self.assertEqual(len(result.corrupted_entries), 0)

    def test_chain_verification_tampered(self):
        """Test tamper detection in chain"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        # Tamper with entry 3
        self.audit_log.entries[2].details["tampered"] = True

        result = self.audit_log.verify_chain()
        self.assertIn(result.status, [VerificationStatus.TAMPERED, VerificationStatus.CORRUPTED])
        self.assertGreater(len(result.tampered_entries) + len(result.corrupted_entries), 0)

    def test_chain_verification_broken_link(self):
        """Test detection of broken hash chain"""
        for event in SAMPLE_AUDIT_EVENTS[:5]:
            self.audit_log.create_entry(*event)

        # Break the chain by modifying previous_hash
        original_hash = self.audit_log.entries[2].previous_hash
        self.audit_log.entries[2].previous_hash = "broken_hash_12345"

        result = self.audit_log.verify_chain()
        self.assertIn(result.status, [VerificationStatus.TAMPERED, VerificationStatus.CORRUPTED])
        self.assertIn(3, result.tampered_entries)

        # Restore
        self.audit_log.entries[2].previous_hash = original_hash

    def test_get_entry_by_sequence(self):
        """Test retrieving entry by sequence"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        entry = self.audit_log.get_entry(3)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.sequence, 3)

        # Out of bounds
        self.assertIsNone(self.audit_log.get_entry(100))
        self.assertIsNone(self.audit_log.get_entry(0))

    def test_filter_by_event_type(self):
        """Test filtering entries by event type"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        auth_entries = self.audit_log.get_entries_by_type(AuditEventType.AUTHENTICATION)
        self.assertEqual(len(auth_entries), 1)
        self.assertEqual(auth_entries[0].event_type, "authentication")

    def test_filter_by_severity(self):
        """Test filtering entries by minimum severity"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        # Get WARNING and above
        high_severity = self.audit_log.get_entries_by_severity(AuditSeverity.WARNING)
        self.assertGreaterEqual(len(high_severity), 2)  # WARNING + CRITICAL

        # Critical only
        critical = self.audit_log.get_entries_by_severity(AuditSeverity.CRITICAL)
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].severity, "critical")

    def test_filter_by_time(self):
        """Test time-based filtering"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        # Use wide time range to avoid timezone issues
        start_time = datetime(2020, 1, 1)
        end_time = datetime(2030, 12, 31)

        entries = self.audit_log.get_entries_by_time(start_time, end_time)
        self.assertEqual(len(entries), 7)

    def test_merkle_root_computation(self):
        """Test Merkle root computation"""
        # Empty log
        empty_root = self.audit_log.compute_merkle_root()
        self.assertIsNotNone(empty_root)

        # With entries
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        root1 = self.audit_log.compute_merkle_root()
        self.assertIsNotNone(root1)
        self.assertNotEqual(root1, empty_root)

        # Same log should produce same root
        root2 = self.audit_log.compute_merkle_root()
        self.assertEqual(root1, root2)

    def test_audit_proof_generation(self):
        """Test audit proof generation"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        proof = self.audit_log.generate_audit_proof()
        self.assertIsNotNone(proof.root_hash)
        self.assertIsNotNone(proof.merkle_root)
        self.assertIsNotNone(proof.signature)
        self.assertEqual(proof.entry_count, 7)

    def test_audit_proof_verification(self):
        """Test audit proof signature verification"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        proof = self.audit_log.generate_audit_proof()
        self.assertTrue(self.audit_log.verify_audit_proof(proof))

        # Tampered proof should fail
        proof.entry_count = 999
        self.assertFalse(self.audit_log.verify_audit_proof(proof))

    def test_search_functionality(self):
        """Test log search functionality"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        # Search for admin actions
        admin_results = self.audit_log.search("admin")
        self.assertGreater(len(admin_results), 0)

        # Search for encryption
        encrypt_results = self.audit_log.search("encrypt")
        self.assertGreater(len(encrypt_results), 0)

        # Search for non-existent term
        no_results = self.audit_log.search("xyz_nonexistent_123")
        self.assertEqual(len(no_results), 0)

    def test_log_statistics(self):
        """Test log statistics generation"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        stats = self.audit_log.get_statistics()
        self.assertEqual(stats["total_entries"], 7)
        self.assertIn("by_type", stats)
        self.assertIn("by_severity", stats)
        self.assertGreater(stats["unique_actors"], 0)

    def test_export_log(self):
        """Test log export functionality"""
        for event in SAMPLE_AUDIT_EVENTS:
            self.audit_log.create_entry(*event)

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = f.name

        try:
            result = self.audit_log.export_log(temp_path)
            self.assertTrue(result)

            # Verify file exists and has content
            with open(temp_path, 'r') as f:
                data = json.load(f)

            self.assertEqual(data["entry_count"], 7)
            self.assertIn("export_signature", data)
            self.assertIn("merkle_root", data)

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_custom_secret_key(self):
        """Test using custom secret key"""
        custom_key = b"my_custom_secret_key_1234567890" * 3
        custom_log = PostQuantumSecureAuditLog(secret_key=custom_key)

        entry = custom_log.create_entry(
            AuditEventType.SYSTEM_EVENT, AuditSeverity.INFO,
            "system", "start", "service"
        )

        self.assertTrue(custom_log.verify_entry(entry))

    def test_custom_log_id(self):
        """Test using custom log ID"""
        custom_log = PostQuantumSecureAuditLog(log_id="MY_AUDIT_LOG_001")
        self.assertEqual(custom_log.log_id, "MY_AUDIT_LOG_001")

    def test_memory_hard_kdf(self):
        """Test memory-hard KDF function"""
        salt = b"test_salt_123"
        key1 = self.audit_log._memory_hard_kdf("password123", salt)
        key2 = self.audit_log._memory_hard_kdf("password123", salt)
        key3 = self.audit_log._memory_hard_kdf("different", salt)

        # Same password produces same key
        self.assertEqual(key1, key2)
        # Different password produces different key
        self.assertNotEqual(key1, key3)
        # Key is 64 bytes
        self.assertEqual(len(key1), 64)

    def test_entry_with_all_fields(self):
        """Test entry with all optional fields"""
        entry = self.audit_log.create_entry(
            event_type=AuditEventType.DATA_ACCESS,
            severity=AuditSeverity.INFO,
            actor="user_john",
            action="read",
            resource="confidential_doc.pdf",
            details={"size": 1048576, "format": "pdf"},
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0"
        )

        self.assertEqual(entry.ip_address, "192.168.1.100")
        self.assertEqual(entry.user_agent, "Mozilla/5.0")
        self.assertIn("size", entry.details)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPostQuantumSecureAuditLog)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print(f"\n{'='*60}")
    print(f"TEST SUMMARY:")
    print(f"  Tests Run: {result.testsRun}")
    print(f"  Failures: {len(result.failures)}")
    print(f"  Errors: {len(result.errors)}")
    print(f"  Success: {result.wasSuccessful()}")
    print(f"{'='*60}")

    return result


if __name__ == "__main__":
    run_tests()
