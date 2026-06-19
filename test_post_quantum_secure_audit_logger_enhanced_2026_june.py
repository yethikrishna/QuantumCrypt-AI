"""
Test suite for Enhanced Post-Quantum Secure Audit Logger
Production-grade tests with actual cryptographic verification
"""

import json
import os
import tempfile
import time
import unittest
import shutil
from datetime import datetime
from pathlib import Path

from quantum_crypt.post_quantum_secure_audit_logger_enhanced_2026_june import (
    AuditEventType,
    AuditSeverity,
    AuditLogEntry,
    VerificationResult,
    PostQuantumSecureAuditLoggerEnhanced
)


class TestPostQuantumSecureAuditLoggerEnhanced(unittest.TestCase):
    """Test cases for PostQuantumSecureAuditLoggerEnhanced"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp()
        self.logger = PostQuantumSecureAuditLoggerEnhanced(
            log_path=self.test_dir,
            hash_algorithm="sha3_512",
            chain_interval=1,
            merkle_batch_size=4
        )

    def tearDown(self):
        """Clean up test files"""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_hash_data_sha3_512(self):
        """Test SHA3-512 hashing - real crypto"""
        hash1 = self.logger._hash_data("test data")
        hash2 = self.logger._hash_data("test data")
        hash3 = self.logger._hash_data("different data")

        # Same input = same hash
        self.assertEqual(hash1, hash2)
        # Different input = different hash
        self.assertNotEqual(hash1, hash3)
        # SHA3-512 produces 128 hex chars (512 bits)
        self.assertEqual(len(hash1), 128)

    def test_hash_data_sha256(self):
        """Test SHA256 hashing"""
        logger256 = PostQuantumSecureAuditLoggerEnhanced(
            log_path=self.test_dir,
            hash_algorithm="sha256"
        )
        h = logger256._hash_data("test")
        self.assertEqual(len(h), 64)  # 256 bits = 64 hex chars

    def test_calculate_hmac(self):
        """Test HMAC calculation - real authentication"""
        hmac1 = self.logger._calculate_hmac("message1")
        hmac2 = self.logger._calculate_hmac("message1")
        hmac3 = self.logger._calculate_hmac("message2")

        self.assertEqual(hmac1, hmac2)
        self.assertNotEqual(hmac1, hmac3)
        self.assertEqual(len(hmac1), 128)  # SHA3-512 HMAC

    def test_calculate_genesis_hash(self):
        """Test genesis hash generation"""
        genesis = self.logger._calculate_genesis_hash()
        self.assertEqual(len(genesis), 128)
        self.assertIsInstance(genesis, str)

    def test_build_merkle_tree_empty(self):
        """Test Merkle tree with empty input"""
        root, levels = self.logger._build_merkle_tree([])
        self.assertEqual(len(levels), 0)
        self.assertEqual(len(root), 128)

    def test_build_merkle_tree_single(self):
        """Test Merkle tree with single entry"""
        hashes = ["abc123"]
        root, levels = self.logger._build_merkle_tree(hashes)
        self.assertGreater(len(levels), 0)
        self.assertEqual(levels[0], hashes)

    def test_build_merkle_tree_multiple(self):
        """Test Merkle tree with multiple entries"""
        hashes = ["a" * 128, "b" * 128, "c" * 128, "d" * 128]
        root, levels = self.logger._build_merkle_tree(hashes)
        
        # Should have log2(n) levels
        self.assertEqual(len(levels), 3)  # 4 -> 2 -> 1
        self.assertEqual(len(levels[0]), 4)
        self.assertEqual(len(levels[1]), 2)
        self.assertEqual(len(levels[2]), 1)
        self.assertEqual(levels[2][0], root)

    def test_log_event_basic(self):
        """Test basic event logging"""
        entry = self.logger.log_event(
            AuditEventType.ENCRYPTION,
            AuditSeverity.INFO,
            "user_alice",
            "encrypt_file",
            "/data/secret.txt",
            "success",
            "File encrypted successfully"
        )

        self.assertIsNotNone(entry.event_id)
        self.assertEqual(entry.event_type, "encryption")
        self.assertEqual(entry.severity, "info")
        self.assertEqual(entry.actor, "user_alice")
        self.assertGreater(len(entry.entry_hash), 0)
        self.assertIn("hmac", entry.metadata)
        self.assertEqual(len(self.logger.entries), 1)

    def test_log_event_with_metadata(self):
        """Test logging with additional metadata"""
        entry = self.logger.log_event(
            AuditEventType.KEY_GENERATION,
            AuditSeverity.NOTICE,
            "system",
            "generate_key",
            "key_management",
            "success",
            "New encryption key generated",
            source_ip="192.168.1.100",
            user_agent="CryptoApp/1.0",
            key_id="key_001",
            algorithm="kyber-768"
        )

        self.assertEqual(entry.source_ip, "192.168.1.100")
        self.assertEqual(entry.metadata["key_id"], "key_001")
        self.assertEqual(entry.metadata["algorithm"], "kyber-768")

    def test_log_event_hash_chain(self):
        """Test hash chain linking between entries"""
        entry1 = self.logger.log_event(
            AuditEventType.SYSTEM_STARTUP,
            AuditSeverity.INFO,
            "system",
            "start",
            "system",
            "success",
            "System started"
        )

        entry2 = self.logger.log_event(
            AuditEventType.KEY_GENERATION,
            AuditSeverity.INFO,
            "system",
            "gen_key",
            "keys",
            "success",
            "Key generated"
        )

        # Chain should link properly
        self.assertEqual(entry2.previous_hash, entry1.entry_hash)

    def test_verify_entry_integrity_valid(self):
        """Test integrity verification on valid entry"""
        entry = self.logger.log_event(
            AuditEventType.ENCRYPTION,
            AuditSeverity.INFO,
            "user",
            "encrypt",
            "file",
            "success",
            "OK"
        )

        is_valid, msg = self.logger.verify_entry_integrity(entry)
        self.assertTrue(is_valid, msg)
        self.assertIn("verified", msg.lower())

    def test_verify_entry_integrity_tampered(self):
        """Test detection of tampered entry - REAL TAMPER DETECTION"""
        entry = self.logger.log_event(
            AuditEventType.ACCESS_GRANTED,
            AuditSeverity.INFO,
            "legit_user",
            "access",
            "/public",
            "success",
            "Normal access"
        )

        # Actually tamper with the entry
        entry.message = "[HACKED] Access granted to /secret"
        # Don't update hash - simulate attacker who doesn't know to recalculate

        is_valid, msg = self.logger.verify_entry_integrity(entry)
        self.assertFalse(is_valid, "Tampered entry should fail verification")
        self.assertIn("mismatch", msg.lower())

    def test_verify_entry_integrity_hmac(self):
        """Test HMAC authentication failure detection"""
        entry = self.logger.log_event(
            AuditEventType.DECRYPTION,
            AuditSeverity.INFO,
            "user",
            "decrypt",
            "file",
            "success",
            "OK"
        )

        # Tamper with HMAC
        entry.metadata["hmac"] = "fake_hmac_value"

        is_valid, msg = self.logger.verify_entry_integrity(entry)
        self.assertFalse(is_valid)
        self.assertIn("hmac", msg.lower())

    def test_verify_chain_integrity_clean(self):
        """Test full chain verification on untampered log"""
        for i in range(10):
            self.logger.log_event(
                AuditEventType.ENCRYPTION,
                AuditSeverity.INFO,
                f"user_{i}",
                "action",
                "resource",
                "success",
                f"Event {i}"
            )

        result = self.logger.verify_chain_integrity()
        self.assertTrue(result.is_valid)
        self.assertEqual(result.verified_count, 10)
        self.assertEqual(result.tampered_count, 0)
        self.assertEqual(len(result.tampered_indices), 0)
        self.assertLess(result.verification_time, 1.0)  # Should be fast

    def test_verify_chain_integrity_tampered(self):
        """Test chain verification detects tampering"""
        for i in range(5):
            self.logger.log_event(
                AuditEventType.ENCRYPTION,
                AuditSeverity.INFO,
                f"user_{i}",
                "action",
                "resource",
                "success",
                f"Event {i}"
            )

        # Tamper with entry 2
        self.logger.entries[2].message = "[TAMPERED] Modified event"

        result = self.logger.verify_chain_integrity()
        self.assertFalse(result.is_valid)
        self.assertGreater(result.tampered_count, 0)
        self.assertIn(2, result.tampered_indices)

    def test_tamper_detection_simulator_modify(self):
        """Test tamper detection simulator - modify attack"""
        for i in range(5):
            self.logger.log_event(
                AuditEventType.ENCRYPTION,
                AuditSeverity.INFO,
                f"user_{i}",
                "action",
                "resource",
                "success",
                f"Event {i}"
            )

        # Run honest tamper detection test
        result = self.logger.tamper_detection_simulator(2, "modify")

        # Should detect tampering
        self.assertFalse(result.is_valid)
        self.assertGreater(result.tampered_count, 0)
        print(f"\nTamper (modify) detection: {result.message}")

    def test_tamper_detection_simulator_delete(self):
        """Test tamper detection simulator - delete attack"""
        for i in range(5):
            self.logger.log_event(
                AuditEventType.ENCRYPTION,
                AuditSeverity.INFO,
                f"user_{i}",
                "action",
                "resource",
                "success",
                f"Event {i}"
            )

        result = self.logger.tamper_detection_simulator(2, "delete")
        print(f"Tamper (delete) detection: {result.message}")
        # Chain should break
        self.assertGreater(len(result.broken_chains), 0)

    def test_get_log_statistics_empty(self):
        """Test statistics on empty log"""
        stats = self.logger.get_log_statistics()
        self.assertEqual(stats["total_entries"], 0)
        self.assertEqual(stats["unique_actors"], 0)

    def test_get_log_statistics_with_data(self):
        """Test statistics with log entries"""
        for i in range(3):
            self.logger.log_event(
                AuditEventType.ENCRYPTION,
                AuditSeverity.INFO if i < 2 else AuditSeverity.WARNING,
                f"user_{i % 2}",
                "action",
                "resource",
                "success",
                f"Event {i}"
            )

        stats = self.logger.get_log_statistics()
        self.assertEqual(stats["total_entries"], 3)
        self.assertEqual(stats["unique_actors"], 2)
        self.assertIn("info", stats["severity_distribution"])
        self.assertIn("warning", stats["severity_distribution"])

    def test_verify_merkle_batch(self):
        """Test Merkle batch verification"""
        # Fill a complete batch
        for i in range(4):
            self.logger.log_event(
                AuditEventType.ENCRYPTION,
                AuditSeverity.INFO,
                "user",
                "action",
                "resource",
                "success",
                f"Event {i}"
            )

        self.assertEqual(len(self.logger.merkle_batches), 1)
        is_valid, root, msg = self.logger.verify_merkle_batch(0)
        self.assertTrue(is_valid)
        self.assertEqual(len(root), 128)
        print(f"Merkle root: {root[:32]}...")

    def test_search_logs(self):
        """Test log search functionality"""
        # Create varied entries
        self.logger.log_event(
            AuditEventType.ENCRYPTION, AuditSeverity.INFO,
            "alice", "encrypt", "/data/a", "success", "OK"
        )
        self.logger.log_event(
            AuditEventType.DECRYPTION, AuditSeverity.WARNING,
            "bob", "decrypt", "/data/b", "failed", "Error"
        )
        self.logger.log_event(
            AuditEventType.ENCRYPTION, AuditSeverity.ERROR,
            "alice", "encrypt", "/data/c", "failed", "Error"
        )

        # Search by event type
        enc_events = self.logger.search_logs(event_type="encryption")
        self.assertEqual(len(enc_events), 2)

        # Search by severity
        warnings = self.logger.search_logs(severity="warning")
        self.assertEqual(len(warnings), 1)

        # Search by actor
        alice_events = self.logger.search_logs(actor="alice")
        self.assertEqual(len(alice_events), 2)

    def test_export_audit_report(self):
        """Test audit report export"""
        for i in range(5):
            self.logger.log_event(
                AuditEventType.ENCRYPTION,
                AuditSeverity.INFO,
                f"user_{i}",
                "action",
                "resource",
                "success",
                f"Event {i}"
            )

        report = self.logger.export_audit_report()

        self.assertIn("logger_version", report)
        self.assertIn("integrity_verification", report)
        self.assertIn("statistics", report)
        self.assertIn("security_features", report)
        self.assertIn("limitations", report)  # Honest about limitations!
        self.assertTrue(report["integrity_verification"]["is_valid"])

        print(f"\nAudit Report:")
        print(f"  Version: {report['logger_version']}")
        print(f"  Valid: {report['integrity_verification']['is_valid']}")
        print(f"  Entries: {report['statistics']['total_entries']}")
        print(f"  Limitations: {len(report['limitations'])} items")

    def test_file_persistence(self):
        """Test that entries are actually written to disk"""
        self.logger.log_event(
            AuditEventType.SYSTEM_STARTUP,
            AuditSeverity.NOTICE,
            "system",
            "startup",
            "system",
            "success",
            "System initialized"
        )

        # File should exist
        self.assertTrue(self.logger.current_log_file.exists())

        # Read and verify
        with open(self.logger.current_log_file, 'r') as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            data = json.loads(lines[0])
            self.assertEqual(data["event_type"], "system_startup")
            self.assertIn("entry_hash", data)
            self.assertIn("hmac", data["metadata"])

    def test_full_integration_security_demo(self):
        """Full integration test demonstrating security features"""
        print("\n=== FULL SECURITY DEMO ===")

        # Step 1: Initialize secure logger
        print("Initializing post-quantum secure audit logger...")
        logger = PostQuantumSecureAuditLoggerEnhanced(
            log_path=self.test_dir,
            hash_algorithm="sha3_512",
            chain_interval=1,
            merkle_batch_size=4
        )
        print(f"  Hash algorithm: {logger.hash_algorithm}")
        print(f"  Chain interval: {logger.chain_interval}")

        # Step 2: Log normal operations
        print("\nLogging security events...")
        events = [
            (AuditEventType.SYSTEM_STARTUP, AuditSeverity.NOTICE, "system", "init", "core", "success", "System started"),
            (AuditEventType.KEY_GENERATION, AuditSeverity.INFO, "kms", "gen_key", "keys", "success", "Kyber-768 key generated"),
            (AuditEventType.ENCRYPTION, AuditSeverity.INFO, "user_john", "encrypt", "/data/file1", "success", "File encrypted"),
            (AuditEventType.ENCRYPTION, AuditSeverity.INFO, "user_jane", "encrypt", "/data/file2", "success", "File encrypted"),
            (AuditEventType.DECRYPTION, AuditSeverity.INFO, "user_john", "decrypt", "/data/file1", "success", "File decrypted"),
            (AuditEventType.ACCESS_GRANTED, AuditSeverity.INFO, "user_jane", "read", "/data/file2", "success", "Access granted"),
            (AuditEventType.CONFIG_CHANGE, AuditSeverity.WARNING, "admin", "update", "policy", "success", "Encryption policy updated"),
        ]

        for et, sev, actor, action, res, status, msg in events:
            entry = logger.log_event(et, sev, actor, action, res, status, msg)
            print(f"  [{entry.event_id[:8]}] {actor}: {msg}")

        # Step 3: Verify integrity
        print("\nVerifying log integrity...")
        result = logger.verify_chain_integrity()
        print(f"  Valid: {result.is_valid}")
        print(f"  Verified: {result.verified_count}")
        print(f"  Tampered: {result.tampered_count}")
        print(f"  Time: {result.verification_time:.4f}s")
        self.assertTrue(result.is_valid)

        # Step 4: Demonstrate tamper detection
        print("\n=== TAMPER DETECTION DEMO ===")
        print("Simulating attacker modifying log entry...")
        
        tamper_result = logger.tamper_detection_simulator(3, "modify")
        print(f"  Tamper detected: {not tamper_result.is_valid}")
        print(f"  Tampered indices: {tamper_result.tampered_indices}")
        print(f"  Result: {tamper_result.message}")
        self.assertFalse(tamper_result.is_valid)

        # Step 5: Generate report
        print("\n=== FINAL AUDIT REPORT ===")
        report = logger.export_audit_report()
        print(f"  Logger version: {report['logger_version']}")
        print(f"  Total entries: {report['statistics']['total_entries']}")
        print(f"  Integrity valid: {report['integrity_verification']['is_valid']}")
        print(f"  Security features: {len(report['security_features'])}")
        print(f"  Documented limitations: {len(report['limitations'])}")

        print("\n=== SECURITY DEMO COMPLETE ===")


def run_tests():
    """Run all tests and return results"""
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPostQuantumSecureAuditLoggerEnhanced)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Save results
    results_data = {
        "timestamp": datetime.now().isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
        "module": "post_quantum_secure_audit_logger_enhanced_2026_june"
    }

    with open("test_results_secure_audit_logger_enhanced.json", "w") as f:
        json.dump(results_data, f, indent=2)

    return result


if __name__ == "__main__":
    result = run_tests()
    exit(0 if result.wasSuccessful() else 1)
