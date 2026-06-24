#!/usr/bin/env python3
"""
Test suite for Post-Quantum Key Rotation Scheduler v28
Dimension A - Feature Expansion
ADD-ONLY TESTS - no production code modified
All existing tests continue to pass
"""
import sys
import os
import json
import unittest
import time
from typing import Dict, List

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from feature_expansion_pq_key_rotation_scheduler_v28_2026_june import (
    PQKeyRotationScheduler,
    KeyAlgorithm,
    KeyType,
    RotationStatus,
    RotationPolicy,
    ManagedKey,
    RotationResult,
    create_pq_key_rotation_scheduler,
    quick_key_rotation
)


class TestPQKeyRotationScheduler(unittest.TestCase):
    """Test cases for PQKeyRotationScheduler"""

    def setUp(self):
        """Set up test fixtures"""
        self.scheduler = PQKeyRotationScheduler()

    def test_scheduler_initialization(self):
        """Test scheduler initializes with correct defaults"""
        self.assertIsNotNone(self.scheduler)
        self.assertEqual(self.scheduler.default_rotation_interval, 720)
        self.assertEqual(self.scheduler.rotation_overlap_hours, 24)
        self.assertIsInstance(self.scheduler._managed_keys, dict)
        self.assertEqual(len(self.scheduler._managed_keys), 0)

    def test_register_kyber_key(self):
        """Test registering a CRYSTALS-Kyber post-quantum key"""
        key = self.scheduler.register_key(
            key_id="TEST-KEY-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION,
            rotation_interval_hours=168  # 7 days
        )
        
        self.assertIsNotNone(key)
        self.assertIsInstance(key, ManagedKey)
        self.assertEqual(key.key_id, "TEST-KEY-001")
        self.assertEqual(key.algorithm, KeyAlgorithm.CRYSTALS_KYBER)
        self.assertTrue(key.quantum_safe)
        self.assertEqual(key.rotation_interval_hours, 168)

    def test_register_dilithium_signing_key(self):
        """Test registering a CRYSTALS-Dilithium signing key"""
        key = self.scheduler.register_key(
            key_id="TEST-KEY-002",
            algorithm=KeyAlgorithm.CRYSTALS_DILITHIUM,
            key_type=KeyType.SIGNING
        )
        
        self.assertIsNotNone(key)
        self.assertEqual(key.key_type, KeyType.SIGNING)
        self.assertTrue(key.quantum_safe)

    def test_register_hybrid_key(self):
        """Test registering a hybrid Kyber-ECC key"""
        key = self.scheduler.register_key(
            key_id="TEST-KEY-003",
            algorithm=KeyAlgorithm.HYBRID_KYBER_ECC,
            key_type=KeyType.KEY_EXCHANGE
        )
        
        self.assertIsNotNone(key)
        self.assertTrue(key.quantum_safe)

    def test_register_classical_key(self):
        """Test registering a classical (non-quantum-safe) key"""
        key = self.scheduler.register_key(
            key_id="TEST-RSA-001",
            algorithm=KeyAlgorithm.RSA_4096,
            key_type=KeyType.ENCRYPTION,
            quantum_safe=False
        )
        
        self.assertIsNotNone(key)
        self.assertFalse(key.quantum_safe)

    def test_key_needs_rotation_time_based(self):
        """Test time-based rotation detection"""
        # Register key that has already expired (negative interval)
        key = self.scheduler.register_key(
            key_id="TEST-EXP-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION,
            rotation_interval_hours=-1  # Already expired
        )
        
        self.assertTrue(key.needs_rotation())

    def test_key_not_needing_rotation(self):
        """Test key that should not need rotation"""
        key = self.scheduler.register_key(
            key_id="TEST-OK-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION,
            rotation_interval_hours=720
        )
        
        self.assertFalse(key.needs_rotation())

    def test_key_needs_rotation_usage_based(self):
        """Test usage-based rotation detection"""
        key = self.scheduler.register_key(
            key_id="TEST-USAGE-001",
            algorithm=KeyAlgorithm.SPHINCS,
            key_type=KeyType.SIGNING,
            max_usage=5
        )
        
        # Increment usage beyond limit
        for _ in range(6):
            self.scheduler.increment_key_usage("TEST-USAGE-001")
        
        self.assertTrue(key.needs_rotation())

    def test_get_key_status(self):
        """Test getting key status information"""
        self.scheduler.register_key(
            key_id="TEST-STATUS-001",
            algorithm=KeyAlgorithm.FALCON,
            key_type=KeyType.SIGNING
        )
        
        status = self.scheduler.get_key_status("TEST-STATUS-001")
        
        self.assertIsNotNone(status)
        self.assertIsInstance(status, dict)
        self.assertEqual(status["key_id"], "TEST-STATUS-001")
        self.assertIn("quantum_safe", status)
        self.assertIn("needs_rotation", status)
        self.assertIn("hours_until_rotation", status)
        self.assertIn("usage_percentage", status)

    def test_get_key_status_not_found(self):
        """Test key status for non-existent key"""
        status = self.scheduler.get_key_status("NONEXISTENT")
        self.assertIsNone(status)

    def test_perform_rotation_success(self):
        """Test successful key rotation"""
        self.scheduler.register_key(
            key_id="TEST-ROT-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION
        )
        
        result = self.scheduler.perform_rotation("TEST-ROT-001")
        
        self.assertIsInstance(result, RotationResult)
        self.assertTrue(result.success)
        self.assertEqual(result.old_key_id, "TEST-ROT-001")
        self.assertIsNotNone(result.new_key_id)
        self.assertGreater(result.rotation_time_ms, 0)

    def test_perform_rotation_key_not_found(self):
        """Test rotation for non-existent key"""
        result = self.scheduler.perform_rotation("NONEXISTENT")
        
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error_message)

    def test_schedule_rotation(self):
        """Test scheduling a rotation job"""
        self.scheduler.register_key(
            key_id="TEST-SCHED-001",
            algorithm=KeyAlgorithm.NTRU,
            key_type=KeyType.KEY_EXCHANGE
        )
        
        job_id = self.scheduler.schedule_rotation(
            key_id="TEST-SCHED-001",
            policy=RotationPolicy.TIME_BASED,
            delay_hours=1
        )
        
        self.assertIsNotNone(job_id)
        self.assertTrue(job_id.startswith("PQ-ROT-"))

    def test_schedule_rotation_key_not_found(self):
        """Test scheduling rotation for non-existent key"""
        job_id = self.scheduler.schedule_rotation("NONEXISTENT")
        self.assertIsNone(job_id)

    def test_get_pending_jobs(self):
        """Test getting pending rotation jobs"""
        self.scheduler.register_key(
            key_id="TEST-JOB-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION
        )
        
        self.scheduler.schedule_rotation("TEST-JOB-001")
        jobs = self.scheduler.get_pending_jobs()
        
        self.assertIsInstance(jobs, list)
        self.assertGreater(len(jobs), 0)

    def test_check_and_rotate_due_keys(self):
        """Test automatic rotation check for due keys"""
        # Register keys that have already expired
        self.scheduler.register_key(
            key_id="TEST-DUE-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION,
            rotation_interval_hours=-1  # Already expired
        )
        self.scheduler.register_key(
            key_id="TEST-DUE-002",
            algorithm=KeyAlgorithm.CRYSTALS_DILITHIUM,
            key_type=KeyType.SIGNING,
            rotation_interval_hours=-1  # Already expired
        )
        
        results = self.scheduler.check_and_rotate_due_keys()
        
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        for result in results:
            self.assertTrue(result.success)

    def test_get_rotation_history(self):
        """Test getting rotation history"""
        self.scheduler.register_key(
            key_id="TEST-HIST-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION
        )
        
        self.scheduler.perform_rotation("TEST-HIST-001")
        history = self.scheduler.get_rotation_history()
        
        self.assertIsInstance(history, list)
        self.assertGreater(len(history), 0)

    def test_get_rotation_statistics(self):
        """Test getting rotation statistics"""
        self.scheduler.register_key(
            key_id="TEST-STAT-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION
        )
        self.scheduler.register_key(
            key_id="TEST-STAT-002",
            algorithm=KeyAlgorithm.RSA_4096,
            key_type=KeyType.ENCRYPTION,
            quantum_safe=False
        )
        
        self.scheduler.perform_rotation("TEST-STAT-001")
        stats = self.scheduler.get_rotation_statistics()
        
        self.assertIsInstance(stats, dict)
        # After rotation, 2 original + 1 new rotated key = 3 total
        self.assertGreaterEqual(stats["total_managed_keys"], 2)
        self.assertEqual(stats["classical_keys"], 1)
        self.assertGreater(stats["successful_rotations"], 0)
        self.assertIn("success_rate", stats)
        self.assertIn("keys_by_algorithm", stats)

    def test_register_rotation_callback(self):
        """Test registering rotation callback"""
        callback_called = []
        
        def mock_callback(key: ManagedKey) -> RotationResult:
            callback_called.append(True)
            return RotationResult(
                success=True,
                old_key_id=key.key_id,
                new_key_id=f"{key.key_id}-CALLBACK"
            )
        
        self.scheduler.register_rotation_callback(
            KeyAlgorithm.CRYSTALS_KYBER,
            mock_callback
        )
        
        self.scheduler.register_key(
            key_id="TEST-CB-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION
        )
        
        self.scheduler.perform_rotation("TEST-CB-001")
        self.assertTrue(len(callback_called) > 0)

    def test_export_rotation_policy(self):
        """Test exporting rotation policy"""
        policy_json = self.scheduler.export_rotation_policy("json")
        policy = json.loads(policy_json)
        
        self.assertIsInstance(policy, dict)
        self.assertIn("default_rotation_interval_hours", policy)
        self.assertIn("supported_algorithms", policy)
        self.assertIn("quantum_risk_factors", policy)

    def test_assess_quantum_risk_safe_key(self):
        """Test quantum risk assessment for safe key"""
        self.scheduler.register_key(
            key_id="TEST-RISK-SAFE",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION
        )
        
        risk = self.scheduler.assess_quantum_risk("TEST-RISK-SAFE")
        
        self.assertTrue(risk["quantum_safe"])
        self.assertFalse(risk["shor_algorithm_vulnerable"])
        self.assertEqual(risk["risk_level"], "LOW")

    def test_assess_quantum_risk_vulnerable_key(self):
        """Test quantum risk assessment for vulnerable key"""
        self.scheduler.register_key(
            key_id="TEST-RISK-VULN",
            algorithm=KeyAlgorithm.RSA_4096,
            key_type=KeyType.ENCRYPTION,
            quantum_safe=False
        )
        
        risk = self.scheduler.assess_quantum_risk("TEST-RISK-VULN")
        
        self.assertFalse(risk["quantum_safe"])
        self.assertTrue(risk["shor_algorithm_vulnerable"])
        self.assertEqual(risk["risk_level"], "CRITICAL")
        self.assertTrue(risk["recommended_migration"])

    def test_assess_quantum_risk_key_not_found(self):
        """Test risk assessment for non-existent key"""
        risk = self.scheduler.assess_quantum_risk("NONEXISTENT")
        self.assertIn("error", risk)

    def test_factory_function(self):
        """Test factory function creates valid instance"""
        instance = create_pq_key_rotation_scheduler()
        self.assertIsInstance(instance, PQKeyRotationScheduler)

    def test_quick_key_rotation_function(self):
        """Test convenience quick key rotation function"""
        result = quick_key_rotation(
            key_id="QUICK-TEST-001",
            algorithm="CRYSTALS-Kyber",
            key_type="encryption"
        )
        
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["new_key_id"])

    def test_quick_key_rotation_invalid_input(self):
        """Test quick rotation handles invalid inputs gracefully"""
        result = quick_key_rotation("TEST", "INVALID_ALG")
        self.assertFalse(result["success"])

    def test_background_scheduler_start_stop(self):
        """Test background scheduler thread lifecycle"""
        self.scheduler.start_background_scheduler()
        self.assertTrue(self.scheduler._scheduler_running)
        
        self.scheduler.stop_background_scheduler()
        self.assertFalse(self.scheduler._scheduler_running)

    def test_time_until_rotation_calculation(self):
        """Test time until rotation calculation"""
        key = self.scheduler.register_key(
            key_id="TEST-TIME-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION,
            rotation_interval_hours=24
        )
        
        hours = key.time_until_rotation()
        self.assertGreater(hours, 23)
        self.assertLess(hours, 25)


class TestEdgeCases(unittest.TestCase):
    """Edge case tests for Key Rotation Scheduler"""

    def setUp(self):
        self.scheduler = PQKeyRotationScheduler()

    def test_multiple_algorithms_all_pq(self):
        """Test managing all post-quantum algorithm types"""
        algorithms = [
            KeyAlgorithm.CRYSTALS_KYBER,
            KeyAlgorithm.CRYSTALS_DILITHIUM,
            KeyAlgorithm.FALCON,
            KeyAlgorithm.SPHINCS,
            KeyAlgorithm.NTRU,
            KeyAlgorithm.HYBRID_KYBER_ECC
        ]
        
        for i, alg in enumerate(algorithms):
            key_id = f"TEST-ALG-{i}"
            self.scheduler.register_key(key_id, alg, KeyType.ENCRYPTION)
        
        stats = self.scheduler.get_rotation_statistics()
        self.assertEqual(stats["quantum_safe_keys"], len(algorithms))

    def test_all_key_types(self):
        """Test managing all key types"""
        key_types = list(KeyType)
        
        for i, kt in enumerate(key_types):
            key_id = f"TEST-TYPE-{i}"
            self.scheduler.register_key(key_id, KeyAlgorithm.CRYSTALS_KYBER, kt)
        
        stats = self.scheduler.get_rotation_statistics()
        self.assertEqual(stats["total_managed_keys"], len(key_types))

    def test_rotation_result_metadata(self):
        """Test rotation result includes metadata"""
        self.scheduler.register_key(
            key_id="TEST-META-001",
            algorithm=KeyAlgorithm.CRYSTALS_KYBER,
            key_type=KeyType.ENCRYPTION
        )
        
        result = self.scheduler.perform_rotation("TEST-META-001")
        self.assertIn("algorithm", result.metadata)
        self.assertIn("simulated", result.metadata)

    def test_custom_config_values(self):
        """Test scheduler with custom configuration"""
        custom_scheduler = PQKeyRotationScheduler({
            "default_rotation_hours": 168,
            "overlap_hours": 48,
            "check_interval_seconds": 60
        })
        
        self.assertEqual(custom_scheduler.default_rotation_interval, 168)
        self.assertEqual(custom_scheduler.rotation_overlap_hours, 48)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestPQKeyRotationScheduler))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("Post-Quantum Key Rotation Scheduler v28 - Test Suite")
    print("Dimension A: Feature Expansion")
    print("=" * 60)
    
    result = run_tests()
    
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    sys.exit(0 if result.wasSuccessful() else 1)
