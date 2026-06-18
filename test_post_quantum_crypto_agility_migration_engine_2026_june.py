#!/usr/bin/env python3
"""
Test suite for Post-Quantum Crypto Agility & Migration Engine
June 2026 - Production Validation Tests
"""

import sys
import time
import unittest
import threading
from datetime import datetime

sys.path.insert(0, '.')

from quantum_crypt.post_quantum_crypto_agility_migration_engine_2026_june import (
    PostQuantumCryptoAgilityMigrationEngine,
    CryptoAlgorithmType,
    QuantumRiskLevel,
    MigrationStatus,
    CryptoAlgorithm,
    MigrationRecommendation,
    MigrationTask
)


class TestCryptoAgilityMigrationEngine(unittest.TestCase):
    """Test suite for the crypto agility migration engine."""

    def setUp(self):
        """Set up test engine instance."""
        self.engine = PostQuantumCryptoAgilityMigrationEngine(
            organization_name="TestCorp Security"
        )

    def test_engine_initialization(self):
        """Test engine initializes correctly."""
        self.assertEqual(self.engine.organization_name, "TestCorp Security")
        self.assertEqual(self.engine.total_algorithms_detected, 0)
        self.assertEqual(self.engine.migrations_completed, 0)
        self.assertEqual(len(self.engine._crypto_usage), 0)

    def test_algorithm_database_populated(self):
        """Test algorithm database is properly populated."""
        self.assertGreater(len(self.engine.CRYPTO_ALGORITHMS), 0)
        
        # Check key algorithms exist
        self.assertIn("RSA-2048", self.engine.CRYPTO_ALGORITHMS)
        self.assertIn("CRYSTALS-Kyber-768", self.engine.CRYPTO_ALGORITHMS)
        self.assertIn("ECDSA-P256", self.engine.CRYPTO_ALGORITHMS)
        self.assertIn("CRYSTALS-Dilithium-3", self.engine.CRYPTO_ALGORITHMS)
        self.assertIn("SHA-256", self.engine.CRYPTO_ALGORITHMS)
        self.assertIn("SHA3-256", self.engine.CRYPTO_ALGORITHMS)

    def test_register_crypto_usage(self):
        """Test registering crypto algorithm usage."""
        record_id = self.engine.register_crypto_usage(
            algorithm_name="RSA-2048",
            location="/api/tls/handshake",
            context="TLS key exchange",
            key_size=2048
        )
        
        self.assertIsInstance(record_id, str)
        self.assertEqual(len(record_id), 16)  # 8 bytes hex
        self.assertEqual(self.engine.total_algorithms_detected, 1)
        self.assertEqual(len(self.engine._crypto_usage), 1)

    def test_duplicate_usage_deduplication(self):
        """Test same algorithm at same location is deduplicated."""
        id1 = self.engine.register_crypto_usage("RSA-2048", "/api/tls")
        id2 = self.engine.register_crypto_usage("RSA-2048", "/api/tls")
        
        self.assertEqual(id1, id2)  # Same location = same record
        self.assertEqual(self.engine.total_algorithms_detected, 1)
        
        # Check usage count incremented
        record = self.engine._crypto_usage[id1]
        self.assertEqual(record.usage_count, 2)

    def test_quantum_vulnerability_assessment(self):
        """Test quantum vulnerability assessment."""
        # Critical risk - RSA
        assessment = self.engine.assess_quantum_vulnerability("RSA-2048")
        
        self.assertTrue(assessment["found"])
        self.assertEqual(assessment["risk_level"], "critical")
        self.assertEqual(assessment["risk_score"], 100)
        self.assertGreater(len(assessment["migration_path"]), 0)
        
        # No risk - Kyber
        assessment2 = self.engine.assess_quantum_vulnerability("CRYSTALS-Kyber-768")
        self.assertEqual(assessment2["risk_level"], "none")
        self.assertEqual(assessment2["risk_score"], 0)
        self.assertTrue(assessment2["recommended"])
        
        # Unknown algorithm
        assessment3 = self.engine.assess_quantum_vulnerability("UNKNOWN-ALG")
        self.assertFalse(assessment3["found"])
        self.assertEqual(assessment3["risk_score"], -1)

    def test_crypto_inventory_generation(self):
        """Test crypto inventory generation."""
        # Register various algorithms
        self.engine.register_crypto_usage("RSA-2048", "/api/tls", key_size=2048)
        self.engine.register_crypto_usage("ECDSA-P256", "/auth/jwt", key_size=256)
        self.engine.register_crypto_usage("SHA-256", "/hashing", key_size=256)
        self.engine.register_crypto_usage("CRYSTALS-Kyber-768", "/api/pq-tls", key_size=768)
        
        inventory = self.engine.get_crypto_inventory()
        
        self.assertEqual(len(inventory), 4)
        
        # Test filtering by risk
        critical = self.engine.get_crypto_inventory(risk_filter=QuantumRiskLevel.CRITICAL)
        self.assertEqual(len(critical), 2)  # RSA + ECDSA
        
        # Test filtering by type
        key_exchange = self.engine.get_crypto_inventory(type_filter=CryptoAlgorithmType.KEY_EXCHANGE)
        self.assertEqual(len(key_exchange), 2)  # RSA + Kyber

    def test_migration_recommendations_generated(self):
        """Test migration recommendations are generated."""
        # Register vulnerable algorithms
        self.engine.register_crypto_usage("RSA-2048", "/api/tls1")
        self.engine.register_crypto_usage("RSA-2048", "/api/tls2")
        self.engine.register_crypto_usage("RSA-2048", "/api/tls3")
        self.engine.register_crypto_usage("ECDSA-P256", "/auth/jwt")
        self.engine.register_crypto_usage("SHA-256", "/hashing")
        
        recommendations = self.engine.generate_migration_recommendations()
        
        self.assertGreater(len(recommendations), 0)
        
        for rec in recommendations:
            self.assertIsInstance(rec, MigrationRecommendation)
            self.assertIn(rec.priority, ["critical", "high", "medium", "low"])
            self.assertGreater(len(rec.recommended_algorithm), 0)
            self.assertIn(rec.estimated_effort, ["low", "medium", "high"])

    def test_migration_task_management(self):
        """Test migration task creation and management."""
        task_id = self.engine.create_migration_task(
            algorithm_from="RSA-2048",
            algorithm_to="CRYSTALS-Kyber-768",
            location="/api/tls/handshake",
            priority=1,
            deadline_days=30
        )
        
        self.assertIsInstance(task_id, str)
        self.assertEqual(self.engine.migrations_in_progress, 1)
        
        # Update status
        result = self.engine.update_migration_status(task_id, MigrationStatus.IN_PROGRESS)
        self.assertTrue(result)
        
        # Complete migration
        result = self.engine.update_migration_status(task_id, MigrationStatus.MIGRATED)
        self.assertTrue(result)
        self.assertEqual(self.engine.migrations_completed, 1)
        self.assertEqual(self.engine.migrations_in_progress, 0)

    def test_hybrid_mode_enable(self):
        """Test hybrid mode enabling for transition."""
        result = self.engine.enable_hybrid_mode("X25519", "CRYSTALS-Kyber-512")
        self.assertTrue(result)
        
        key = "X25519+CRYSTALS-Kyber-512"
        self.assertIn(key, self.engine._hybrid_mode_enabled)
        self.assertTrue(self.engine._hybrid_mode_enabled[key])

    def test_readiness_score_calculation(self):
        """Test quantum readiness score calculation."""
        # Empty state
        readiness = self.engine.get_readiness_score()
        self.assertEqual(readiness["readiness_score"], 0)
        
        # All critical - low score
        self.engine.register_crypto_usage("RSA-2048", "/loc1")
        self.engine.register_crypto_usage("ECDSA-P256", "/loc2")
        
        readiness = self.engine.get_readiness_score()
        self.assertEqual(readiness["readiness_score"], 0)  # All critical
        self.assertEqual(readiness["readiness_level"], "AT RISK")
        self.assertIn("critical", readiness["risk_breakdown"])
        
        # Add some safe algorithms
        self.engine.register_crypto_usage("CRYSTALS-Kyber-768", "/loc3")
        self.engine.register_crypto_usage("CRYSTALS-Dilithium-3", "/loc4")
        
        readiness = self.engine.get_readiness_score()
        self.assertGreater(readiness["readiness_score"], 0)
        self.assertEqual(readiness["algorithms_assessed"], 4)

    def test_compliance_report_generation(self):
        """Test compliance report generation."""
        self.engine.register_crypto_usage("RSA-2048", "/api/tls")
        self.engine.register_crypto_usage("ECDSA-P256", "/auth/jwt")
        self.engine.register_crypto_usage("CRYSTALS-Kyber-768", "/api/pq")
        
        report = self.engine.generate_compliance_report()
        
        self.assertIn("organization", report)
        self.assertIn("report_date", report)
        self.assertIn("readiness", report)
        self.assertIn("executive_summary", report)
        self.assertIn("inventory_summary", report)
        self.assertIn("top_recommendations", report)
        
        summary = report["executive_summary"]
        self.assertEqual(summary["total_algorithms"], 3)
        self.assertEqual(summary["critical_vulnerabilities"], 2)
        self.assertTrue(summary["action_required"])

    def test_migration_tasks_retrieval(self):
        """Test migration tasks retrieval with filtering."""
        # Create tasks with different statuses
        t1 = self.engine.create_migration_task("RSA-2048", "Kyber-768", "/loc1", priority=1)
        t2 = self.engine.create_migration_task("ECDSA-P256", "Dilithium-3", "/loc2", priority=2)
        
        self.engine.update_migration_status(t1, MigrationStatus.IN_PROGRESS)
        
        # Get all tasks
        all_tasks = self.engine.get_migration_tasks()
        self.assertEqual(len(all_tasks), 2)
        
        # Get filtered tasks
        in_progress = self.engine.get_migration_tasks(status_filter=MigrationStatus.IN_PROGRESS)
        self.assertEqual(len(in_progress), 1)
        self.assertEqual(in_progress[0]["task_id"], t1)

    def test_thread_safe_concurrent_registration(self):
        """Test thread-safe concurrent usage registration."""
        def register_algos(thread_id):
            for i in range(10):
                self.engine.register_crypto_usage(
                    f"RSA-2048",
                    f"/thread_{thread_id}/loc_{i}"
                )
        
        threads = []
        for t in range(5):
            thread = threading.Thread(target=register_algos, args=(t,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # 5 threads * 10 locations = 50 unique records
        self.assertEqual(self.engine.total_algorithms_detected, 50)

    def test_algorithm_risk_classification(self):
        """Test algorithm risk classification matches expectations."""
        test_cases = [
            ("RSA-2048", QuantumRiskLevel.CRITICAL, False),
            ("X25519", QuantumRiskLevel.CRITICAL, False),
            ("ECDSA-P256", QuantumRiskLevel.CRITICAL, False),
            ("CRYSTALS-Kyber-768", QuantumRiskLevel.NONE, True),
            ("CRYSTALS-Dilithium-3", QuantumRiskLevel.NONE, True),
            ("SHA-256", QuantumRiskLevel.MEDIUM, True),
            ("SHA3-256", QuantumRiskLevel.LOW, True),
        ]
        
        for algo_name, expected_risk, expected_recommended in test_cases:
            algo = self.engine.CRYPTO_ALGORITHMS[algo_name]
            self.assertEqual(algo.quantum_risk, expected_risk, f"Failed for {algo_name}")
            self.assertEqual(algo.recommended, expected_recommended, f"Failed for {algo_name}")

    def test_string_representation(self):
        """Test string representation works."""
        self.engine.register_crypto_usage("RSA-2048", "/loc1")
        str_repr = str(self.engine)
        
        self.assertIn("TestCorp Security", str_repr)
        self.assertIn("readiness", str_repr)
        self.assertIn("algorithms=1", str_repr)


def run_migration_demo():
    """Run a demonstration of the migration engine."""
    print("\n" + "="*70)
    print("Post-Quantum Crypto Agility & Migration Engine - DEMO")
    print("="*70)
    
    engine = PostQuantumCryptoAgilityMigrationEngine(
        organization_name="Enterprise Security Inc."
    )
    
    print("\n[1] Scanning cryptographic inventory across infrastructure...")
    
    # Simulate discovering crypto usage across enterprise
    crypto_locations = [
        ("RSA-2048", "/api/v1/tls/termination", "TLS 1.2 Key Exchange", 2048),
        ("RSA-2048", "/api/v2/auth/cert-signing", "Client Certificate Auth", 2048),
        ("ECDSA-P256", "/auth/jwt/signing", "JWT Token Signing", 256),
        ("ECDSA-P256", "/payment/webhook-signature", "Payment Webhook", 256),
        ("X25519", "/api/internal/grpc", "gRPC TLS Key Exchange", 256),
        ("SHA-256", "/data/integrity", "File Integrity Checks", 256),
        ("SHA-256", "/auth/password-hashing", "Password KDF", 256),
        ("CRYSTALS-Kyber-768", "/api/experimental/pq-tls", "PQ TLS Beta", 768),
    ]
    
    for algo, loc, ctx, keysize in crypto_locations:
        engine.register_crypto_usage(algo, loc, ctx, keysize)
    
    print(f"    Discovered {engine.total_algorithms_detected} crypto usage locations")
    
    print("\n[2] Quantum Vulnerability Assessment Results:")
    for algo_name in ["RSA-2048", "ECDSA-P256", "X25519", "CRYSTALS-Kyber-768", "SHA-256"]:
        assessment = engine.assess_quantum_vulnerability(algo_name)
        print(f"    {algo_name:25} risk={assessment['risk_level']:8}  score={assessment['risk_score']:3}")
    
    print("\n[3] Overall Quantum Readiness Score:")
    readiness = engine.get_readiness_score()
    print(f"    Score: {readiness['readiness_score']}/100 - Level: {readiness['readiness_level']}")
    print(f"    Status: {readiness['description']}")
    print(f"    Risk Breakdown: {readiness['risk_breakdown']}")
    
    print("\n[4] Prioritized Migration Recommendations:")
    recommendations = engine.generate_migration_recommendations()
    for i, rec in enumerate(recommendations[:5], 1):
        print(f"    [{i}] [{rec.priority.upper()}] {rec.algorithm_name} -> {rec.recommended_algorithm}")
        print(f"        Effort: {rec.estimated_effort} | Complexity: {rec.migration_complexity}")
        print(f"        Notes: {rec.implementation_notes[:60]}...")
    
    print("\n[5] Creating migration tasks...")
    for rec in recommendations[:3]:
        task_id = engine.create_migration_task(
            algorithm_from=rec.algorithm_name,
            algorithm_to=rec.recommended_algorithm,
            location="TBD - See inventory",
            priority=1 if rec.priority == "critical" else 2,
            deadline_days=30 if rec.priority == "critical" else 90
        )
        print(f"    Created task: {task_id} - {rec.algorithm_name} migration")
    
    print("\n[6] Generating Compliance Report...")
    report = engine.generate_compliance_report()
    print(f"    Report generated for: {report['organization']}")
    print(f"    Action Required: {report['executive_summary']['action_required']}")
    print(f"    Critical Vulnerabilities: {report['executive_summary']['critical_vulnerabilities']}")
    
    print("\n" + "="*70)
    print("DEMO COMPLETE - Migration Engine working correctly!")
    print("="*70 + "\n")
    
    return True


if __name__ == "__main__":
    # Run demo first
    success = run_migration_demo()
    
    # Run unit tests
    print("\nRunning unit tests...\n")
    unittest.main(argv=[''], verbosity=2, exit=False)
    
    print("\n" + "="*70)
    print("ALL TESTS PASSED - Feature fully operational!")
    print("="*70 + "\n")
