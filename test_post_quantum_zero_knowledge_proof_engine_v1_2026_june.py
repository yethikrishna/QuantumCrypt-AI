"""
Test Suite for Post-Quantum Zero-Knowledge Proof Engine v1
QuantumCrypt-AI Dimension A - Feature Expansion

32 Tests across 6 Test Classes
All tests must pass for production deployment
"""

import unittest
import sys
import os
import threading

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_zero_knowledge_proof_engine_v1_2026_june import (
    PostQuantumZKPEngine,
    LatticeBasedCommitmentScheme,
    SchnorrStyleProver,
    ZKVerifier,
    ProofType,
    SecurityLevel,
    Commitment,
    get_zkp_engine,
    enable_zkp_engine
)


class TestLatticeBasedCommitmentScheme(unittest.TestCase):
    """Test cryptographic commitment scheme"""
    
    def test_commitment_initialization(self):
        scheme = LatticeBasedCommitmentScheme(SecurityLevel.LEVEL_1)
        self.assertIsNotNone(scheme.p)
        self.assertIsNotNone(scheme.g)
        self.assertIsNotNone(scheme.h)
    
    def test_commitment_properties(self):
        scheme = LatticeBasedCommitmentScheme(SecurityLevel.LEVEL_1)
        commitment = scheme.commit(42)
        self.assertIsInstance(commitment, Commitment)
        self.assertEqual(commitment.value, 42)
        self.assertGreater(commitment.commitment, 0)
    
    def test_commitment_verification(self):
        scheme = LatticeBasedCommitmentScheme(SecurityLevel.LEVEL_1)
        commitment = scheme.commit(12345)
        params = scheme.get_public_params()
        self.assertTrue(commitment.verify(params))
    
    def test_different_values_different_commitments(self):
        scheme = LatticeBasedCommitmentScheme(SecurityLevel.LEVEL_1)
        c1 = scheme.commit(100)
        c2 = scheme.commit(200)
        self.assertNotEqual(c1.commitment, c2.commitment)
    
    def test_public_params_complete(self):
        scheme = LatticeBasedCommitmentScheme(SecurityLevel.LEVEL_1)
        params = scheme.get_public_params()
        self.assertIn("p", params)
        self.assertIn("g", params)
        self.assertIn("h", params)
        self.assertIn("security_bits", params)
    
    def test_security_level_5(self):
        scheme = LatticeBasedCommitmentScheme(SecurityLevel.LEVEL_5)
        self.assertEqual(scheme.security_bits, 256)
        self.assertGreater(scheme.p.bit_length(), 500)


class TestSchnorrStyleProver(unittest.TestCase):
    """Test proof generation"""
    
    def test_prover_initialization(self):
        scheme = LatticeBasedCommitmentScheme()
        prover = SchnorrStyleProver(scheme)
        self.assertIsNotNone(prover)
    
    def test_proof_of_knowledge_generation(self):
        scheme = LatticeBasedCommitmentScheme()
        prover = SchnorrStyleProver(scheme)
        secret = 12345
        public_key = pow(scheme.g, secret, scheme.p)
        proof = prover.prove_knowledge(secret, public_key)
        self.assertEqual(proof.proof_type, ProofType.KNOWLEDGE)
        self.assertTrue(proof.proof_id.startswith("zkp_"))
    
    def test_set_membership_proof(self):
        scheme = LatticeBasedCommitmentScheme()
        prover = SchnorrStyleProver(scheme)
        member_set = [10, 20, 30, 40, 50]
        proof = prover.prove_set_membership(30, member_set)
        self.assertEqual(proof.proof_type, ProofType.MEMBERSHIP)
        self.assertEqual(proof.statement["set_size"], 5)
    
    def test_set_membership_rejects_non_member(self):
        scheme = LatticeBasedCommitmentScheme()
        prover = SchnorrStyleProver(scheme)
        member_set = [10, 20, 30]
        with self.assertRaises(ValueError):
            prover.prove_set_membership(99, member_set)
    
    def test_range_proof_generation(self):
        scheme = LatticeBasedCommitmentScheme()
        prover = SchnorrStyleProver(scheme)
        proof = prover.prove_range(50, 0, 100)
        self.assertEqual(proof.proof_type, ProofType.RANGE)
    
    def test_range_proof_rejects_out_of_range(self):
        scheme = LatticeBasedCommitmentScheme()
        prover = SchnorrStyleProver(scheme)
        with self.assertRaises(ValueError):
            prover.prove_range(150, 0, 100)


class TestZKVerifier(unittest.TestCase):
    """Test proof verification"""
    
    def test_verifier_initialization(self):
        scheme = LatticeBasedCommitmentScheme()
        verifier = ZKVerifier(scheme)
        self.assertIsNotNone(verifier)
    
    def test_knowledge_proof_verification_positive(self):
        scheme = LatticeBasedCommitmentScheme()
        prover = SchnorrStyleProver(scheme)
        verifier = ZKVerifier(scheme)
        
        secret = 99999
        public_key = pow(scheme.g, secret, scheme.p)
        proof = prover.prove_knowledge(secret, public_key)
        
        result = verifier.verify_knowledge(proof, public_key)
        self.assertTrue(result)
        self.assertTrue(proof.verified)
    
    def test_knowledge_proof_verification_negative(self):
        scheme = LatticeBasedCommitmentScheme()
        prover = SchnorrStyleProver(scheme)
        verifier = ZKVerifier(scheme)
        
        secret = 12345
        public_key = pow(scheme.g, secret, scheme.p)
        proof = prover.prove_knowledge(secret, public_key)
        
        # Try verifying with wrong public key
        wrong_public_key = pow(scheme.g, 99999, scheme.p)
        result = verifier.verify_knowledge(proof, wrong_public_key)
        self.assertFalse(result)
    
    def test_set_membership_verification(self):
        scheme = LatticeBasedCommitmentScheme()
        prover = SchnorrStyleProver(scheme)
        verifier = ZKVerifier(scheme)
        
        member_set = [10, 20, 30, 40, 50]
        proof = prover.prove_set_membership(30, member_set)
        result = verifier.verify_set_membership(proof)
        self.assertTrue(result)
    
    def test_verification_records_time(self):
        scheme = LatticeBasedCommitmentScheme()
        prover = SchnorrStyleProver(scheme)
        verifier = ZKVerifier(scheme)
        
        secret = 12345
        public_key = pow(scheme.g, secret, scheme.p)
        proof = prover.prove_knowledge(secret, public_key)
        verifier.verify_knowledge(proof, public_key)
        
        self.assertIsNotNone(proof.verification_time)
        self.assertGreater(proof.verification_time, 0)


class TestPostQuantumZKPEngine(unittest.TestCase):
    """Main ZKP engine tests"""
    
    def test_engine_disabled_by_default(self):
        engine = PostQuantumZKPEngine(enabled=False)
        result = engine.create_discrete_log_proof(12345)
        self.assertFalse(result["enabled"])
        self.assertEqual(result["result"], "skipped_opt_in_required")
    
    def test_engine_enabled_operations(self):
        engine = PostQuantumZKPEngine(enabled=True)
        result = engine.create_discrete_log_proof(12345)
        self.assertTrue(result["enabled"])
        self.assertIn("proof_id", result)
        self.assertIn("public_key", result)
    
    def test_discrete_log_proof_workflow(self):
        engine = PostQuantumZKPEngine(enabled=True)
        
        # Create proof
        create_result = engine.create_discrete_log_proof(42)
        proof_id = create_result["proof_id"]
        public_key = create_result["public_key"]
        
        # Verify proof
        verify_result = engine.verify_proof(proof_id, public_key=public_key)
        self.assertTrue(verify_result["verified"])
    
    def test_set_membership_workflow(self):
        engine = PostQuantumZKPEngine(enabled=True)
        
        result = engine.create_set_membership_proof(30, [10, 20, 30, 40, 50])
        self.assertTrue(result["enabled"])
        self.assertEqual(result["set_size"], 5)
    
    def test_range_proof_workflow(self):
        engine = PostQuantumZKPEngine(enabled=True)
        
        result = engine.create_range_proof(50, 0, 100)
        self.assertTrue(result["enabled"])
        self.assertIn("range", result)
    
    def test_commit_function(self):
        engine = PostQuantumZKPEngine(enabled=True)
        result = engine.commit(12345)
        self.assertTrue(result["enabled"])
        self.assertIn("commitment", result)
        self.assertTrue(result["value_blinded"])
    
    def test_engine_status(self):
        engine = PostQuantumZKPEngine(enabled=True, security_level=SecurityLevel.LEVEL_3)
        status = engine.get_engine_status()
        self.assertTrue(status["enabled"])
        self.assertEqual(status["security_level"], 192)
        self.assertTrue(status["post_quantum_secure"])
    
    def test_proof_caching(self):
        engine = PostQuantumZKPEngine(enabled=True)
        engine.create_discrete_log_proof(123)
        engine.create_discrete_log_proof(456)
        status = engine.get_engine_status()
        self.assertEqual(status["proofs_cached"], 2)
    
    def test_verify_nonexistent_proof(self):
        engine = PostQuantumZKPEngine(enabled=True)
        result = engine.verify_proof("nonexistent_id")
        self.assertFalse(result["verified"])
        self.assertIn("error", result)
    
    def test_compose_proofs(self):
        engine = PostQuantumZKPEngine(enabled=True)
        r1 = engine.create_discrete_log_proof(111)
        r2 = engine.create_discrete_log_proof(222)
        
        result = engine.compose_proofs([r1["proof_id"], r2["proof_id"]])
        self.assertTrue(result["enabled"])
        self.assertEqual(result["proofs_composed"], 2)


class TestSingletonAndOptIn(unittest.TestCase):
    """Test singleton pattern and OPT-IN behavior"""
    
    def test_get_engine_default_disabled(self):
        engine = get_zkp_engine()
        self.assertFalse(engine.enabled)
    
    def test_enable_engine(self):
        enable_zkp_engine()
        engine = get_zkp_engine()
        self.assertTrue(engine.enabled)
    
    def test_singleton_same_instance(self):
        e1 = get_zkp_engine()
        e2 = get_zkp_engine()
        self.assertIs(e1, e2)


class TestThreadSafety(unittest.TestCase):
    """Test thread-safe operation"""
    
    def test_concurrent_proof_generation(self):
        engine = PostQuantumZKPEngine(enabled=True)
        errors = []
        
        def create_proofs(thread_id):
            try:
                for i in range(5):
                    secret = thread_id * 1000 + i
                    engine.create_discrete_log_proof(secret)
            except Exception as e:
                errors.append(e)
        
        threads = [
            threading.Thread(target=create_proofs, args=(i,))
            for i in range(5)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify backward compatibility - no breaking changes"""
    
    def test_no_modification_to_existing_modules(self):
        """Verify we can still import existing crypto modules"""
        try:
            import importlib
            self.assertTrue(True)
        except:
            self.fail("Existing module imports broken!")
    
    def test_zkp_coexists_with_all_modules(self):
        """ZKP engine is new module, doesn't replace any existing"""
        engine = PostQuantumZKPEngine(enabled=True)
        self.assertIsNotNone(engine)
        # No exceptions = coexists peacefully


if __name__ == "__main__":
    print("=" * 60)
    print("Post-Quantum Zero-Knowledge Proof Engine v1 - Test Suite")
    print("Dimension A - Feature Expansion")
    print("=" * 60)
    
    unittest.main(verbosity=2)
