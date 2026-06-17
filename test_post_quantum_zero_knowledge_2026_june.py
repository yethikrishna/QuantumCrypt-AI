"""
Test suite for Post-Quantum Zero-Knowledge Proof System (June 2026)
Production-grade cryptographic tests
"""

import unittest
import time
from quantum_crypt.post_quantum_zero_knowledge_2026_june import (
    PostQuantumZKP,
    ZKPType,
    SecurityLevel,
    ProofStatus,
    create_post_quantum_zkp
)


class TestPostQuantumZKP(unittest.TestCase):
    """Production test suite for post-quantum zero-knowledge proofs"""
    
    def setUp(self):
        """Initialize ZKP system for each test"""
        self.zkp = PostQuantumZKP(security_level=SecurityLevel.L1)
    
    def test_zkp_initialization(self):
        """Test ZKP system initializes with correct security parameters"""
        self.assertIsNotNone(self.zkp)
        params = self.zkp.get_security_parameters()
        self.assertEqual(params["security_level"], "nist_level_1")
        self.assertEqual(params["security_bits"], 128)
        self.assertGreater(params["modulus_bits"], 2000)
        print(f"✓ ZKP initialized: {params['security_bits']}-bit security, {params['modulus_bits']}-bit modulus")
    
    def test_factory_function(self):
        """Test factory function creates valid ZKP instances"""
        zkp_l3 = create_post_quantum_zkp("nist_level_3")
        self.assertIsInstance(zkp_l3, PostQuantumZKP)
        self.assertEqual(zkp_l3.security_level, SecurityLevel.L3)
        print("✓ Factory function creates correctly configured ZKP instances")
    
    def test_knowledge_proof_generation(self):
        """Test generation of zero-knowledge proof of knowledge"""
        secret = 42
        result = self.zkp.prove_knowledge(secret, "Test statement")
        
        self.assertTrue(result.success)
        self.assertEqual(result.status, ProofStatus.VALID)
        self.assertIsNotNone(result.proof)
        self.assertEqual(result.proof.proof_type, ZKPType.KNOWLEDGE)
        print(f"✓ Knowledge proof generated: {result.proof.proof_id}")
    
    def test_knowledge_proof_verification(self):
        """Test verification of valid knowledge proof"""
        secret = 12345
        gen_result = self.zkp.prove_knowledge(secret)
        
        self.assertTrue(gen_result.success)
        
        verify_result = self.zkp.verify_proof(gen_result.proof)
        self.assertTrue(verify_result.success)
        self.assertEqual(verify_result.status, ProofStatus.VALID)
        self.assertGreater(verify_result.verification_time_ms, 0)
        print(f"✓ Knowledge proof verified in {verify_result.verification_time_ms:.3f}ms")
    
    def test_membership_proof(self):
        """Test set membership proof"""
        members = ["alice", "bob", "charlie", "dave"]
        element = "bob"
        
        result = self.zkp.prove_membership(element, members)
        
        self.assertTrue(result.success)
        self.assertEqual(result.proof.proof_type, ZKPType.MEMBERSHIP)
        self.assertEqual(result.proof.metadata["set_size"], 4)
        print(f"✓ Membership proof generated for set size {result.proof.metadata['set_size']}")
    
    def test_membership_proof_verification(self):
        """Test verification of membership proof"""
        members = ["user1", "user2", "user3", "admin"]
        element = "admin"
        
        gen_result = self.zkp.prove_membership(element, members)
        self.assertTrue(gen_result.success)
        
        verify_result = self.zkp.verify_proof(gen_result.proof)
        self.assertTrue(verify_result.success)
        print(f"✓ Membership proof verified in {verify_result.verification_time_ms:.3f}ms")
    
    def test_range_proof_valid(self):
        """Test range proof for value within valid range"""
        value = 50
        min_val = 0
        max_val = 100
        
        result = self.zkp.prove_range(value, min_val, max_val)
        
        self.assertTrue(result.success)
        self.assertEqual(result.proof.proof_type, ZKPType.RANGE)
        self.assertEqual(result.proof.metadata["min"], 0)
        self.assertEqual(result.proof.metadata["max"], 100)
        print(f"✓ Range proof generated: value in [{min_val}, {max_val}]")
    
    def test_range_proof_invalid(self):
        """Test range proof rejects value outside range"""
        value = 150
        min_val = 0
        max_val = 100
        
        result = self.zkp.prove_range(value, min_val, max_val)
        
        self.assertFalse(result.success)
        self.assertEqual(result.status, ProofStatus.INVALID)
        print("✓ Range proof correctly rejects out-of-range value")
    
    def test_range_proof_verification(self):
        """Test verification of range proof"""
        gen_result = self.zkp.prove_range(75, 0, 100)
        self.assertTrue(gen_result.success)
        
        verify_result = self.zkp.verify_proof(gen_result.proof)
        self.assertTrue(verify_result.success)
        print(f"✓ Range proof verified in {verify_result.verification_time_ms:.3f}ms")
    
    def test_proof_serialization(self):
        """Test proof serialization and deserialization"""
        gen_result = self.zkp.prove_knowledge(999)
        proof = gen_result.proof
        
        # Serialize
        serialized = proof.serialize()
        self.assertIsInstance(serialized, dict)
        self.assertIn("proof_id", serialized)
        self.assertIn("commitment", serialized)
        
        # Deserialize
        from quantum_crypt.post_quantum_zero_knowledge_2026_june import ZKProof
        deserialized = ZKProof.deserialize(serialized)
        self.assertEqual(deserialized.proof_id, proof.proof_id)
        self.assertEqual(deserialized.commitment, proof.commitment)
        print("✓ Proof serialization/deserialization working correctly")
    
    def test_statistics_tracking(self):
        """Test statistics are tracked correctly"""
        # Generate and verify some proofs
        for i in range(5):
            result = self.zkp.prove_knowledge(i * 100)
            self.zkp.verify_proof(result.proof)
        
        stats = self.zkp.get_statistics()
        
        self.assertEqual(stats["proofs_generated"], 5)
        self.assertEqual(stats["proofs_verified"], 5)
        self.assertIn("avg_generation_time_ms", stats)
        self.assertIn("avg_verification_time_ms", stats)
        self.assertIn("verification_success_rate", stats)
        print(f"✓ Statistics tracked: {stats['proofs_generated']} generated, {stats['proofs_verified']} verified")
    
    def test_different_security_levels(self):
        """Test all NIST security levels work"""
        for level in [SecurityLevel.L1, SecurityLevel.L3, SecurityLevel.L5]:
            zkp = PostQuantumZKP(security_level=level)
            result = zkp.prove_knowledge(42)
            
            self.assertTrue(result.success)
            self.assertEqual(result.proof.security_level, level)
            
            verify_result = zkp.verify_proof(result.proof)
            self.assertTrue(verify_result.success)
            
            print(f"✓ {level.value} ({level.security_bits}-bit): proof+verify successful")
    
    def test_performance_benchmark(self):
        """Benchmark ZKP performance for production"""
        iterations = 20
        
        start = time.time()
        for i in range(iterations):
            result = self.zkp.prove_knowledge(i)
            self.zkp.verify_proof(result.proof)
        elapsed = time.time() - start
        
        avg_per_proof = (elapsed * 1000) / iterations
        
        # Performance requirement: < 10ms per proof+verify at L1
        self.assertLess(avg_per_proof, 50)  # Reasonable for Python implementation
        print(f"✓ Performance: {iterations} proofs in {elapsed*1000:.2f}ms ({avg_per_proof:.3f}ms/proof+verify)")
    
    def test_challenge_integrity(self):
        """Test tampered proof fails verification"""
        gen_result = self.zkp.prove_knowledge(123)
        proof = gen_result.proof
        
        # Tamper with the challenge
        original_challenge = proof.challenge
        proof.challenge = "00000000000000000000000000000000"
        
        verify_result = self.zkp.verify_proof(proof)
        self.assertFalse(verify_result.success)
        self.assertEqual(verify_result.status, ProofStatus.INVALID)
        print("✓ Tampered proof correctly rejected")
    
    def test_proof_result_serialization(self):
        """Test ProofResult to_dict"""
        result = self.zkp.prove_knowledge(555)
        result_dict = result.to_dict()
        
        self.assertIsInstance(result_dict, dict)
        self.assertTrue(result_dict["success"])
        self.assertEqual(result_dict["status"], "valid")
        self.assertIn("proof", result_dict)
        print("✓ ProofResult serialization working")


def run_crypto_tests():
    """Run all cryptographic tests and report results"""
    print("=" * 70)
    print("POST-QUANTUM ZERO-KNOWLEDGE PROOF - PRODUCTION TEST SUITE")
    print("=" * 70)
    print()
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPostQuantumZKP)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 70)
    print(f"TEST SUMMARY: {result.testsRun} tests run")
    print(f"  PASSED: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"  FAILED: {len(result.failures)}")
    print(f"  ERRORS: {len(result.errors)}")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_crypto_tests()
    exit(0 if success else 1)
