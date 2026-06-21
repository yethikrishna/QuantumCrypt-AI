"""
Test Suite for QuantumCrypt AI - Post-Quantum Secure MPC Session Manager v5
Comprehensive tests covering all core functionality
"""
import json
import time
import unittest
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_mpc_session_manager_v5_2026_june import (
    MPCSessionManager, SessionState, ParticipantRole, ComputationType,
    KyberSimulatedKEM, ShamirSecretSharing, SessionAuditLog,
    SecureMPCComputationEngine
)


class TestKyberSimulatedKEM(unittest.TestCase):
    """Test CRYSTALS-Kyber simulated KEM"""
    
    def test_keypair_generation(self):
        """Test key pair generation"""
        kem = KyberSimulatedKEM(security_level=3)
        priv_key, pub_key = kem.generate_keypair()
        
        self.assertIsInstance(priv_key, bytes)
        self.assertIsInstance(pub_key, bytes)
        self.assertEqual(len(priv_key), 192)  # 1536 bits = 192 bytes
    
    def test_encapsulation_decapsulation(self):
        """Test key encapsulation and decapsulation"""
        kem = KyberSimulatedKEM()
        priv_key, pub_key = kem.generate_keypair()
        
        ciphertext, shared_secret1 = kem.encapsulate(pub_key)
        shared_secret2 = kem.decapsulate(priv_key, ciphertext)
        
        self.assertIsInstance(ciphertext, bytes)
        self.assertIsInstance(shared_secret1, bytes)
        self.assertEqual(len(shared_secret1), 32)


class TestShamirSecretSharing(unittest.TestCase):
    """Test Shamir's Secret Sharing"""
    
    def test_split_and_reconstruct(self):
        """Test secret splitting and reconstruction"""
        sss = ShamirSecretSharing()
        secret = 123456789
        
        shares = sss.split_secret(secret, 5, 3)
        self.assertEqual(len(shares), 5)
        
        # Reconstruct with threshold shares
        reconstructed = sss.reconstruct_secret(shares[:3])
        self.assertEqual(reconstructed, secret)
        
        # Reconstruct with more than threshold
        reconstructed2 = sss.reconstruct_secret(shares[:4])
        self.assertEqual(reconstructed2, secret)
    
    def test_insufficient_shares(self):
        """Test reconstruction fails with insufficient shares"""
        sss = ShamirSecretSharing()
        secret = 987654321
        
        shares = sss.split_secret(secret, 5, 3)
        
        # With only 2 shares (below threshold), result differs
        result = sss.reconstruct_secret(shares[:2])
        # Note: This won't fail but will give wrong value
        self.assertNotEqual(result, secret)
    
    def test_invalid_threshold(self):
        """Test threshold validation"""
        sss = ShamirSecretSharing()
        
        with self.assertRaises(ValueError):
            sss.split_secret(123, 3, 5)  # threshold > num_shares


class TestSessionAuditLog(unittest.TestCase):
    """Test tamper-evident audit log"""
    
    def test_audit_entry_addition(self):
        """Test adding audit entries"""
        audit = SessionAuditLog()
        
        audit.add_entry("test_event", "participant_1", {"key": "value"})
        self.assertEqual(len(audit.entries), 1)
        self.assertEqual(audit.entries[0].event_type, "test_event")
    
    def test_audit_integrity_verification(self):
        """Test audit log integrity verification"""
        audit = SessionAuditLog()
        
        audit.add_entry("event1", "p1", {"data": 1})
        audit.add_entry("event2", "p2", {"data": 2})
        audit.add_entry("event3", None, {"data": 3})
        
        self.assertTrue(audit.verify_integrity())
    
    def test_audit_tamper_detection(self):
        """Test that tampering is detected"""
        audit = SessionAuditLog()
        
        audit.add_entry("event1", "p1", {"data": 1})
        audit.add_entry("event2", "p2", {"data": 2})
        
        # Tamper with entry
        audit.entries[0].details["data"] = 999
        
        # Integrity check should fail
        self.assertFalse(audit.verify_integrity())


class TestSecureMPCComputationEngine(unittest.TestCase):
    """Test MPC computation engine"""
    
    def test_secure_sum(self):
        """Test secure sum computation"""
        engine = SecureMPCComputationEngine()
        
        inputs = [10, 20, 30, 40]
        result = engine.secure_sum(inputs)
        
        self.assertEqual(result, 100)
    
    def test_secure_average(self):
        """Test secure average computation"""
        engine = SecureMPCComputationEngine()
        
        inputs = [10, 20, 30]
        result = engine.secure_average(inputs)
        
        self.assertEqual(result, 20.0)
    
    def test_secure_max(self):
        """Test secure max computation"""
        engine = SecureMPCComputationEngine()
        
        inputs = [10, 50, 30, 20]
        result = engine.secure_max(inputs)
        
        self.assertEqual(result, 50)
    
    def test_private_set_intersection(self):
        """Test private set intersection"""
        engine = SecureMPCComputationEngine()
        
        set1 = {1, 2, 3, 4, 5}
        set2 = {4, 5, 6, 7, 8}
        set3 = {5, 6, 7, 8, 9}
        
        result = engine.private_set_intersection([set1, set2, set3])
        self.assertEqual(result, {5})


class TestMPCSessionManager(unittest.TestCase):
    """Main MPC Session Manager tests"""
    
    def test_session_creation(self):
        """Test session creation"""
        manager = MPCSessionManager()
        
        session_id = manager.create_session(
            "initiator_1",
            ComputationType.SUM,
            threshold=2,
            max_participants=3
        )
        
        self.assertIsNotNone(session_id)
        self.assertIsInstance(session_id, str)
        
        status = manager.get_session_status(session_id)
        self.assertIsNotNone(status)
        self.assertEqual(status["state"], "created")
        self.assertEqual(status["computation_type"], "secure_sum")
    
    def test_add_participants(self):
        """Test adding participants to session"""
        manager = MPCSessionManager()
        
        session_id = manager.create_session(
            "initiator_1",
            ComputationType.AVERAGE,
            threshold=2,
            max_participants=3
        )
        
        # Add participants
        result1 = manager.add_participant(session_id, "node_1", ParticipantRole.COMPUTE_NODE)
        result2 = manager.add_participant(session_id, "node_2", ParticipantRole.COMPUTE_NODE)
        result3 = manager.add_participant(session_id, "verifier_1", ParticipantRole.VERIFIER)
        
        self.assertTrue(result1)
        self.assertTrue(result2)
        self.assertTrue(result3)
        
        status = manager.get_session_status(session_id)
        self.assertEqual(status["participants"], 3)
    
    def test_max_participants_limit(self):
        """Test max participants limit enforcement"""
        manager = MPCSessionManager()
        
        session_id = manager.create_session(
            "initiator_1",
            ComputationType.SUM,
            threshold=2,
            max_participants=2
        )
        
        manager.add_participant(session_id, "node_1", ParticipantRole.COMPUTE_NODE)
        manager.add_participant(session_id, "node_2", ParticipantRole.COMPUTE_NODE)
        
        # Third participant should be rejected
        result = manager.add_participant(session_id, "node_3", ParticipantRole.COMPUTE_NODE)
        self.assertFalse(result)
    
    def test_key_exchange(self):
        """Test post-quantum key exchange"""
        manager = MPCSessionManager()
        
        session_id = manager.create_session(
            "initiator_1",
            ComputationType.SUM,
            threshold=2,
            max_participants=3
        )
        
        manager.add_participant(session_id, "node_1", ParticipantRole.COMPUTE_NODE)
        manager.add_participant(session_id, "node_2", ParticipantRole.COMPUTE_NODE)
        
        result = manager.perform_key_exchange(session_id)
        self.assertTrue(result)
        
        status = manager.get_session_status(session_id)
        self.assertEqual(status["state"], "secret_sharing")
    
    def test_secret_share_distribution(self):
        """Test secret share distribution"""
        manager = MPCSessionManager()
        
        session_id = manager.create_session(
            "initiator_1",
            ComputationType.SUM,
            threshold=2,
            max_participants=3
        )
        
        manager.add_participant(session_id, "node_1", ParticipantRole.COMPUTE_NODE)
        manager.add_participant(session_id, "node_2", ParticipantRole.COMPUTE_NODE)
        manager.perform_key_exchange(session_id)
        
        result = manager.distribute_secret_shares(session_id)
        self.assertTrue(result)
        
        status = manager.get_session_status(session_id)
        self.assertEqual(status["state"], "computing")
    
    def test_full_mpc_workflow_sum(self):
        """Test complete MPC workflow for secure sum"""
        manager = MPCSessionManager()
        
        # Create session
        session_id = manager.create_session(
            "initiator_1",
            ComputationType.SUM,
            threshold=2,
            max_participants=3
        )
        
        # Add participants
        manager.add_participant(session_id, "node_1", ParticipantRole.COMPUTE_NODE)
        manager.add_participant(session_id, "node_2", ParticipantRole.COMPUTE_NODE)
        
        # Key exchange
        manager.perform_key_exchange(session_id)
        
        # Distribute shares
        manager.distribute_secret_shares(session_id)
        
        # Submit private inputs
        manager.submit_private_input(session_id, "node_1", 100)
        manager.submit_private_input(session_id, "node_2", 200)
        
        # Execute computation
        result = manager.execute_computation(session_id)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.result_value, 300)
        self.assertEqual(result.participant_contributions, 2)
        
        # Verify result
        verified = manager.verify_result(session_id)
        self.assertTrue(verified)
        
        status = manager.get_session_status(session_id)
        self.assertEqual(status["state"], "completed")
        self.assertTrue(status["has_result"])
    
    def test_full_mpc_workflow_average(self):
        """Test complete MPC workflow for secure average"""
        manager = MPCSessionManager()
        
        session_id = manager.create_session(
            "initiator_1",
            ComputationType.AVERAGE,
            threshold=2,
            max_participants=4
        )
        
        manager.add_participant(session_id, "node_1", ParticipantRole.COMPUTE_NODE)
        manager.add_participant(session_id, "node_2", ParticipantRole.COMPUTE_NODE)
        manager.add_participant(session_id, "node_3", ParticipantRole.COMPUTE_NODE)
        
        manager.perform_key_exchange(session_id)
        manager.distribute_secret_shares(session_id)
        
        manager.submit_private_input(session_id, "node_1", 10)
        manager.submit_private_input(session_id, "node_2", 20)
        manager.submit_private_input(session_id, "node_3", 30)
        
        result = manager.execute_computation(session_id)
        manager.verify_result(session_id)
        
        self.assertEqual(result.result_value, 20.0)
    
    def test_audit_log_in_session(self):
        """Test audit log is maintained throughout session"""
        manager = MPCSessionManager()
        
        session_id = manager.create_session(
            "initiator_1",
            ComputationType.SUM,
            threshold=2,
            max_participants=3
        )
        
        manager.add_participant(session_id, "node_1", ParticipantRole.COMPUTE_NODE)
        manager.add_participant(session_id, "node_2", ParticipantRole.COMPUTE_NODE)
        manager.perform_key_exchange(session_id)
        manager.distribute_secret_shares(session_id)
        
        status = manager.get_session_status(session_id)
        
        # Should have audit entries for all operations
        self.assertGreater(status["audit_entries"], 0)
        self.assertTrue(status["audit_integrity_valid"])
    
    def test_get_session_result(self):
        """Test retrieving completed session result"""
        manager = MPCSessionManager()
        
        session_id = manager.create_session(
            "initiator_1",
            ComputationType.SUM,
            threshold=2,
            max_participants=3
        )
        
        manager.add_participant(session_id, "node_1", ParticipantRole.COMPUTE_NODE)
        manager.add_participant(session_id, "node_2", ParticipantRole.COMPUTE_NODE)
        manager.perform_key_exchange(session_id)
        manager.distribute_secret_shares(session_id)
        manager.submit_private_input(session_id, "node_1", 50)
        manager.submit_private_input(session_id, "node_2", 75)
        manager.execute_computation(session_id)
        manager.verify_result(session_id)
        
        # Get result
        final_result = manager.get_session_result(session_id)
        self.assertIsNotNone(final_result)
        self.assertEqual(final_result.result_value, 125)
        self.assertTrue(final_result.verified)
    
    def test_get_stats(self):
        """Test manager statistics"""
        manager = MPCSessionManager()
        
        # Create some sessions
        session1 = manager.create_session("i1", ComputationType.SUM)
        session2 = manager.create_session("i2", ComputationType.AVERAGE)
        
        stats = manager.get_stats()
        
        self.assertEqual(stats["active_sessions"], 2)
        self.assertIn("session_states", stats)
        self.assertEqual(stats["version"], "5.0.0")
    
    def test_invalid_session_operations(self):
        """Test operations on non-existent session"""
        manager = MPCSessionManager()
        
        result = manager.add_participant("invalid_session", "node_1", ParticipantRole.COMPUTE_NODE)
        self.assertFalse(result)
        
        status = manager.get_session_status("invalid_session")
        self.assertIsNone(status)
        
        result = manager.perform_key_exchange("invalid_session")
        self.assertFalse(result)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestKyberSimulatedKEM))
    suite.addTests(loader.loadTestsFromTestCase(TestShamirSecretSharing))
    suite.addTests(loader.loadTestsFromTestCase(TestSessionAuditLog))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureMPCComputationEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestMPCSessionManager))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Generate results JSON
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "module": "post_quantum_secure_mpc_session_manager_v5",
        "version": "5.0.0",
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful(),
        "test_cases": [
            "KyberSimulatedKEM",
            "ShamirSecretSharing",
            "SessionAuditLog",
            "SecureMPCComputationEngine",
            "MPCSessionManager"
        ],
        "pq_algorithm": "CRYSTALS-Kyber (simulated)",
        "security_level": 3
    }
    
    return results


if __name__ == "__main__":
    print("=" * 70)
    print("QuantumCrypt AI - Post-Quantum Secure MPC Session Manager v5 - Test Suite")
    print("=" * 70)
    print()
    
    results = run_tests()
    
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(json.dumps(results, indent=2))
    
    # Save results
    with open("test_results_mpc_session_manager_v5_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_mpc_session_manager_v5_2026_june.json")
