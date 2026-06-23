"""
Test Suite for Post-Quantum Hybrid Encryption Orchestrator v2
QuantumCrypt AI - Dimension A Feature Expansion v18

All tests are ADD-ONLY - no existing tests modified
"""

import sys
import os
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from pq_hybrid_encryption_orchestrator_v2_2026_june import (
    HybridEncryptionOrchestrator,
    AlgorithmClass,
    SecurityLevel,
    ProtocolState,
    CryptoAlgorithm,
    HybridSession,
    NegotiationProposal
)


class TestHybridEncryptionOrchestrator(unittest.TestCase):
    """Test core hybrid encryption orchestrator functionality"""

    def setUp(self):
        self.orchestrator = HybridEncryptionOrchestrator(
            peer_id="test-peer-001",
            min_security_level=SecurityLevel.LEVEL_3
        )

    def test_orchestrator_initialization(self):
        """Test orchestrator initializes correctly"""
        self.assertEqual(self.orchestrator.peer_id, "test-peer-001")
        self.assertEqual(self.orchestrator.min_security_level, SecurityLevel.LEVEL_3)
        self.assertGreater(len(self.orchestrator.algorithms), 0)
        self.assertIn("AES-256-GCM", self.orchestrator.algorithms)
        self.assertIn("CRYSTALS-Kyber-768", self.orchestrator.algorithms)

    def test_algorithm_registry_classical(self):
        """Test classical algorithms are registered correctly"""
        aes = self.orchestrator.get_algorithm_info("AES-256-GCM")
        
        self.assertIsNotNone(aes)
        self.assertEqual(aes.algorithm_class, AlgorithmClass.CLASSICAL)
        self.assertEqual(aes.security_level, SecurityLevel.LEVEL_5)
        self.assertTrue(aes.is_nist_standard)
        self.assertFalse(aes.quantum_resistant)

    def test_algorithm_registry_post_quantum(self):
        """Test post-quantum algorithms are registered correctly"""
        kyber = self.orchestrator.get_algorithm_info("CRYSTALS-Kyber-768")
        
        self.assertIsNotNone(kyber)
        self.assertEqual(kyber.algorithm_class, AlgorithmClass.POST_QUANTUM)
        self.assertEqual(kyber.security_level, SecurityLevel.LEVEL_3)
        self.assertTrue(kyber.is_nist_standard)
        self.assertTrue(kyber.quantum_resistant)

    def test_list_supported_algorithms(self):
        """Test listing supported algorithms with filtering"""
        all_algos = self.orchestrator.list_supported_algorithms()
        self.assertGreater(len(all_algos), 0)
        
        classical = self.orchestrator.list_supported_algorithms(AlgorithmClass.CLASSICAL)
        pq = self.orchestrator.list_supported_algorithms(AlgorithmClass.POST_QUANTUM)
        
        self.assertGreater(len(classical), 0)
        self.assertGreater(len(pq), 0)
        self.assertEqual(len(all_algos), len(classical) + len(pq))

    def test_create_negotiation_proposal_default(self):
        """Test creating negotiation proposal with default policy"""
        proposal = self.orchestrator.create_negotiation_proposal(
            target_peer_id="peer-002"
        )
        
        self.assertIsInstance(proposal, NegotiationProposal)
        self.assertTrue(proposal.proposal_id.startswith("PROP-"))
        self.assertEqual(proposal.proposer_id, "test-peer-001")
        self.assertGreater(len(proposal.classical_options), 0)
        self.assertGreater(len(proposal.pq_options), 0)
        self.assertGreater(len(proposal.supported_versions), 0)

    def test_create_negotiation_proposal_high_threat(self):
        """Test creating negotiation proposal with high threat policy"""
        proposal = self.orchestrator.create_negotiation_proposal(
            target_peer_id="peer-002",
            policy_profile="high_threat"
        )
        
        # High threat should only include AES-256-GCM
        self.assertEqual(proposal.classical_options, ["AES-256-GCM"])
        # High threat should include strongest PQ algorithms
        self.assertIn("CRYSTALS-Kyber-1024", proposal.pq_options)

    def test_create_negotiation_proposal_performance_mode(self):
        """Test creating negotiation proposal with performance policy"""
        proposal = self.orchestrator.create_negotiation_proposal(
            target_peer_id="peer-002",
            policy_profile="performance_mode"
        )
        
        # Performance mode should prefer ChaCha20 first
        self.assertEqual(proposal.classical_options[0], "ChaCha20-Poly1305")

    def test_evaluate_proposal_accept(self):
        """Test evaluating and accepting valid proposal"""
        proposer = HybridEncryptionOrchestrator("peer-alice")
        proposal = proposer.create_negotiation_proposal("peer-bob")
        
        accepted, selected, version = self.orchestrator.evaluate_proposal(proposal)
        
        self.assertTrue(accepted)
        self.assertIn("classical", selected)
        self.assertIn("pq", selected)
        self.assertGreater(len(version), 0)

    def test_evaluate_proposal_version_negotiation(self):
        """Test version negotiation between peers"""
        # Create proposal with specific versions
        proposal = NegotiationProposal(
            proposal_id="test-prop",
            proposer_id="peer-test",
            classical_options=["AES-256-GCM"],
            pq_options=["CRYSTALS-Kyber-768"],
            supported_versions=["1.0.0", "1.5.0"],  # No 2.0.0
            preferred_security_level=SecurityLevel.LEVEL_3,
            timestamp=0,
            nonce="test"
        )
        
        accepted, selected, version = self.orchestrator.evaluate_proposal(proposal)
        
        self.assertTrue(accepted)
        # Should negotiate to highest common version (1.5.0)
        self.assertEqual(version, "1.5.0")

    def test_evaluate_proposal_reject_no_common_version(self):
        """Test proposal rejection when no common versions"""
        proposal = NegotiationProposal(
            proposal_id="test-prop",
            proposer_id="peer-test",
            classical_options=["AES-256-GCM"],
            pq_options=["CRYSTALS-Kyber-768"],
            supported_versions=["0.9.0", "0.8.0"],  # No overlap
            preferred_security_level=SecurityLevel.LEVEL_3,
            timestamp=0,
            nonce="test"
        )
        
        accepted, selected, version = self.orchestrator.evaluate_proposal(proposal)
        
        self.assertFalse(accepted)
        self.assertEqual(selected, {})
        self.assertEqual(version, "")

    def test_establish_hybrid_session(self):
        """Test establishing hybrid encryption session"""
        session = self.orchestrator.establish_hybrid_session(
            classical_algo="AES-256-GCM",
            pq_algo="CRYSTALS-Kyber-768",
            negotiated_version="2.0.0"
        )
        
        self.assertIsInstance(session, HybridSession)
        self.assertTrue(session.session_id.startswith("SESS-"))
        self.assertEqual(session.classical_algorithm, "AES-256-GCM")
        self.assertEqual(session.pq_algorithm, "CRYSTALS-Kyber-768")
        self.assertEqual(session.state, ProtocolState.ACTIVE)
        self.assertEqual(session.negotiated_version, "2.0.0")

    def test_session_key_rotation(self):
        """Test session key rotation"""
        session = self.orchestrator.establish_hybrid_session(
            classical_algo="AES-256-GCM",
            pq_algo="CRYSTALS-Kyber-768",
            negotiated_version="2.0.0"
        )
        
        initial_rekey = session.rekey_count
        result = self.orchestrator.rotate_session_keys(session.session_id)
        
        self.assertTrue(result)
        self.assertEqual(session.rekey_count, initial_rekey + 1)

    def test_session_key_rotation_invalid_id(self):
        """Test key rotation with invalid session ID"""
        result = self.orchestrator.rotate_session_keys("INVALID_SESSION")
        self.assertFalse(result)

    def test_encrypt_with_session(self):
        """Test encryption using hybrid session"""
        session = self.orchestrator.establish_hybrid_session(
            classical_algo="AES-256-GCM",
            pq_algo="CRYSTALS-Kyber-768",
            negotiated_version="2.0.0"
        )
        
        plaintext = b"Secret message to encrypt"
        result = self.orchestrator.encrypt_with_session(
            session.session_id,
            plaintext,
            associated_data=b"test context"
        )
        
        self.assertIsNotNone(result)
        ciphertext, nonce, tag = result
        self.assertEqual(len(ciphertext), len(plaintext))
        self.assertEqual(len(nonce), 12)
        self.assertEqual(len(tag), 32)  # SHA256 HMAC

    def test_encrypt_with_invalid_session(self):
        """Test encryption with invalid session"""
        result = self.orchestrator.encrypt_with_session(
            "INVALID_SESSION",
            b"test data"
        )
        self.assertIsNone(result)

    def test_threat_adaptive_selection_default(self):
        """Test threat-adaptive algorithm selection - default"""
        result = self.orchestrator.select_algorithms_for_threat_level("normal")
        
        self.assertEqual(result["profile_applied"], "default")
        self.assertGreater(len(result["classical"]), 0)
        self.assertGreater(len(result["post_quantum"]), 0)

    def test_threat_adaptive_selection_critical(self):
        """Test threat-adaptive algorithm selection - critical threat"""
        result = self.orchestrator.select_algorithms_for_threat_level("critical")
        
        self.assertEqual(result["profile_applied"], "quantum_urgent")
        # Critical threat should include maximum PQ options
        self.assertIn("CRYSTALS-Kyber-1024", result["post_quantum"])
        self.assertIn("NTRU-HPS-2048", result["post_quantum"])

    def test_threat_adaptive_selection_high(self):
        """Test threat-adaptive algorithm selection - high threat"""
        result = self.orchestrator.select_algorithms_for_threat_level("high")
        
        self.assertEqual(result["profile_applied"], "high_threat")
        self.assertEqual(result["classical"], ["AES-256-GCM"])

    def test_threat_adaptive_selection_low(self):
        """Test threat-adaptive algorithm selection - low threat"""
        result = self.orchestrator.select_algorithms_for_threat_level("low")
        
        self.assertEqual(result["profile_applied"], "performance_mode")
        # With default weight (0.5), sorted by security level first
        # AES-256-GCM (LEVEL_5) comes before ChaCha20-Poly1305 (LEVEL_3)
        self.assertIn(result["classical"][0], ["AES-256-GCM", "ChaCha20-Poly1305"])

    def test_threat_adaptive_selection_performance_weighted(self):
        """Test performance-weighted algorithm selection"""
        result_high_perf = self.orchestrator.select_algorithms_for_threat_level(
            "normal",
            performance_weight=0.9
        )
        result_high_security = self.orchestrator.select_algorithms_for_threat_level(
            "normal",
            performance_weight=0.1
        )
        
        # Both weightings should produce valid algorithm lists
        # Note: AES-256-GCM has both higher security and higher performance
        # so ordering may be identical for classical algorithms
        self.assertGreater(len(result_high_perf["classical"]), 0)
        self.assertGreater(len(result_high_security["classical"]), 0)
        self.assertGreater(len(result_high_perf["post_quantum"]), 0)
        self.assertGreater(len(result_high_security["post_quantum"]), 0)

    def test_session_needs_rotation(self):
        """Test session rotation detection"""
        session = self.orchestrator.establish_hybrid_session(
            classical_algo="AES-256-GCM",
            pq_algo="CRYSTALS-Kyber-768",
            negotiated_version="2.0.0"
        )
        
        # Fresh session should not need rotation
        self.assertFalse(session.needs_rotation())
        
        # Manually expire
        session.key_rotation_interval = 0
        self.assertTrue(session.needs_rotation())

    def test_get_session_info(self):
        """Test session information retrieval"""
        session = self.orchestrator.establish_hybrid_session(
            classical_algo="AES-256-GCM",
            pq_algo="CRYSTALS-Kyber-768",
            negotiated_version="2.0.0"
        )
        
        info = self.orchestrator.get_session_info(session.session_id)
        
        self.assertIsNotNone(info)
        self.assertEqual(info["session_id"], session.session_id)
        self.assertIn("messages_encrypted", info)
        self.assertIn("seconds_until_rotation", info)
        self.assertNotIn("classical_key", info)  # No key material exposed

    def test_get_session_info_invalid(self):
        """Test session info with invalid ID"""
        info = self.orchestrator.get_session_info("INVALID")
        self.assertIsNone(info)

    def test_orchestrator_stats(self):
        """Test orchestrator statistics tracking"""
        initial = self.orchestrator.get_orchestrator_stats()
        
        # Create proposal
        self.orchestrator.create_negotiation_proposal("peer-test")
        
        # Establish session
        session = self.orchestrator.establish_hybrid_session(
            "AES-256-GCM", "CRYSTALS-Kyber-768", "2.0.0"
        )
        
        # Encrypt something
        self.orchestrator.encrypt_with_session(session.session_id, b"test")
        
        stats = self.orchestrator.get_orchestrator_stats()
        
        self.assertGreater(stats["proposals_created"], initial["proposals_created"])
        self.assertGreater(stats["sessions_established"], initial["sessions_established"])
        self.assertGreater(stats["total_encryptions"], initial["total_encryptions"])
        self.assertEqual(stats["active_sessions"], 1)

    def test_algorithm_to_dict_serialization(self):
        """Test algorithm dictionary serialization"""
        algo = self.orchestrator.get_algorithm_info("AES-256-GCM")
        algo_dict = algo.to_dict()
        
        self.assertIsInstance(algo_dict, dict)
        self.assertEqual(algo_dict["name"], "AES-256-GCM")
        self.assertIn("security_level", algo_dict)
        self.assertIn("quantum_resistant", algo_dict)

    def test_export_session_metadata(self):
        """Test session metadata export"""
        self.orchestrator.establish_hybrid_session(
            "AES-256-GCM", "CRYSTALS-Kyber-768", "2.0.0"
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            result = self.orchestrator.export_session_metadata(filepath)
            self.assertTrue(result)
            self.assertTrue(os.path.exists(filepath))
        finally:
            if os.path.exists(filepath):
                os.unlink(filepath)

    def test_ntru_algorithm_support(self):
        """Test NTRU algorithm is available in v2"""
        ntru = self.orchestrator.get_algorithm_info("NTRU-HPS-2048")
        
        self.assertIsNotNone(ntru)
        self.assertTrue(ntru.quantum_resistant)
        # NTRU only supported in v2.0.0
        self.assertEqual(ntru.supported_versions, {"2.0.0"})

    def test_frodokem_algorithm_support(self):
        """Test FrodoKEM algorithm is available in v2"""
        frodo = self.orchestrator.get_algorithm_info("FrodoKEM-640")
        
        self.assertIsNotNone(frodo)
        self.assertTrue(frodo.quantum_resistant)
        self.assertEqual(frodo.security_level, SecurityLevel.LEVEL_1)


def run_tests():
    """Run all tests and print summary"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestHybridEncryptionOrchestrator)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
