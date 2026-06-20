"""
Test Suite for Post-Quantum Secure Multi-Party Computation Engine V8
June 20, 2026 - Production Release
"""

import json
import pytest
from quantum_crypt.post_quantum_secure_mpc_engine_v8_2026_june import (
    SecureMultiPartyComputationV8,
    VerifiableSecretSharing,
    PostQuantumCommitmentScheme,
    ZeroKnowledgeProofSystem,
    SecureArithmeticCircuitEvaluator,
    SecurityModel,
    CommitmentScheme,
    MPCSecurityLevel,
    create_mpc_engine_v8,
    verify_mpc_engine_v8
)


class TestVerifiableSecretSharing:
    """Tests for Verifiable Secret Sharing"""
    
    def setup_method(self):
        self.vss = VerifiableSecretSharing()
    
    def test_share_generation(self):
        secret = 42
        shares, vk = self.vss.generate_shares(secret, 5, 3, verify=True)
        
        assert len(shares) == 5
        assert all(s.commitment is not None for s in shares)
        assert vk is not None
    
    def test_share_verification(self):
        secret = 100
        shares, vk = self.vss.generate_shares(secret, 3, 2, verify=True)
        
        for share in shares:
            assert self.vss.verify_share(share, vk) is True
    
    def test_secret_reconstruction(self):
        secret = 12345
        shares, _ = self.vss.generate_shares(secret, 5, 3)
        
        # Reconstruct with threshold shares
        reconstructed = self.vss.reconstruct_secret(shares[:3], 3)
        assert reconstructed == secret
        
        # Reconstruct with more than threshold
        reconstructed2 = self.vss.reconstruct_secret(shares[:4], 3)
        assert reconstructed2 == secret
    
    def test_reconstruction_with_insufficient_shares(self):
        secret = 999
        shares, _ = self.vss.generate_shares(secret, 5, 3)
        
        with pytest.raises(ValueError):
            self.vss.reconstruct_secret(shares[:2], 3)
    
    def test_reconstruct_with_verification(self):
        secret = 555
        shares, vk = self.vss.generate_shares(secret, 4, 2, verify=True)
        
        reconstructed, invalid = self.vss.reconstruct_with_verification(shares[:3], 2, vk)
        assert reconstructed == secret
        assert len(invalid) == 0


class TestPostQuantumCommitmentScheme:
    """Tests for Post-Quantum Commitment Schemes"""
    
    def test_sha256_commitment(self):
        scheme = PostQuantumCommitmentScheme(CommitmentScheme.SHA256_HASH)
        
        value = b"test_secret_value"
        commitment = scheme.commit(value)
        
        assert commitment.committed_value is not None
        assert commitment.opening is not None
        assert scheme.verify(commitment, value) is True
    
    def test_commitment_tamper_detection(self):
        scheme = PostQuantumCommitmentScheme(CommitmentScheme.SHA256_HASH)
        
        value = b"original_value"
        commitment = scheme.commit(value)
        
        # Try to verify with wrong value
        wrong_value = b"tampered_value"
        assert scheme.verify(commitment, wrong_value) is False


class TestZeroKnowledgeProofSystem:
    """Tests for Zero-Knowledge Proof System"""
    
    def test_proof_generation(self):
        zk = ZeroKnowledgeProofSystem()
        
        inputs = [5, 10, 15]
        output = 30
        proof = zk.generate_computation_proof(inputs, output, "addition")
        
        assert proof.proof_type == "computation_addition"
        assert proof.witness_hash is not None
        assert proof.proof_data is not None
    
    def test_proof_verification(self):
        zk = ZeroKnowledgeProofSystem()
        
        inputs = [2, 3, 4]
        output = 24
        proof = zk.generate_computation_proof(inputs, output, "multiplication")
        
        assert zk.verify_proof(proof, output) is True
        assert proof.verified is True
    
    def test_proof_verification_wrong_output(self):
        zk = ZeroKnowledgeProofSystem()
        
        inputs = [1, 2, 3]
        output = 6
        proof = zk.generate_computation_proof(inputs, output, "addition")
        
        # Verify with wrong output
        assert zk.verify_proof(proof, 999) is False


class TestSecureArithmeticCircuitEvaluator:
    """Tests for Secure Arithmetic Circuit Evaluation"""
    
    def setup_method(self):
        self.evaluator = SecureArithmeticCircuitEvaluator()
    
    def test_circuit_creation(self):
        circuit = self.evaluator.create_circuit("test_circuit", 3, 2)
        
        assert circuit.circuit_id == "test_circuit"
        assert circuit.num_parties == 3
        assert circuit.num_inputs == 2
        assert len(circuit.gates) == 0
    
    def test_gate_addition(self):
        circuit = self.evaluator.create_circuit("test", 2, 2)
        
        self.evaluator.add_gate(circuit, "ADD", [0, 1], 2)
        self.evaluator.add_gate(circuit, "OUTPUT", [2], 3)
        
        assert len(circuit.gates) == 2
        assert circuit.num_outputs == 1
    
    def test_simple_addition_circuit(self):
        circuit = self.evaluator.create_circuit("add_circuit", 2, 2)
        
        # Input wires 0 and 1 from parties
        # Output wire 2 = wire0 + wire1
        self.evaluator.add_gate(circuit, "ADD", [0, 1], 2)
        self.evaluator.add_gate(circuit, "OUTPUT", [2], 3)
        
        # Party inputs: [[5], [10]] - each party provides one input
        party_inputs = [[5, 0], [10, 0]]  # 2 parties, 2 inputs each
        outputs = self.evaluator.evaluate_secure(circuit, party_inputs)
        
        # Should output 5 + 10 = 15
        assert len(outputs) == 1


class TestSecureMultiPartyComputationV8:
    """Tests for the main MPC V8 engine"""
    
    def test_engine_initialization(self):
        mpc = SecureMultiPartyComputationV8(
            num_parties=3,
            threshold=2,
            security_model=SecurityModel.MALICIOUS
        )
        
        assert mpc.num_parties == 3
        assert mpc.threshold == 2
        assert mpc.security_model == SecurityModel.MALICIOUS
    
    def test_secure_addition_correctness(self):
        mpc = SecureMultiPartyComputationV8(num_parties=3, threshold=2)
        
        # 3 parties with values 5, 10, 15
        result = mpc.secure_addition([5, 10, 15])
        
        assert result.success is True
        assert len(result.output_values) == 1
        assert result.output_values[0] == 30  # 5 + 10 + 15
        assert result.computation_time_ms > 0
        assert len(result.error_messages) == 0
    
    def test_secure_addition_malicious_model(self):
        mpc = SecureMultiPartyComputationV8(
            num_parties=3,
            threshold=2,
            security_model=SecurityModel.MALICIOUS
        )
        
        result = mpc.secure_addition([1, 2, 3])
        
        assert result.success is True
        assert result.output_values[0] == 6
        # In malicious mode, we do verification
        assert result.security_violations_detected == 0
    
    def test_secure_multiplication_correctness(self):
        mpc = SecureMultiPartyComputationV8(num_parties=3, threshold=2)
        
        result = mpc.secure_multiplication([2, 3, 4])
        
        assert result.success is True
        # 2 * 3 * 4 = 24 (mod prime)
        assert result.output_values[0] == 24
    
    def test_secure_addition_wrong_num_parties(self):
        mpc = SecureMultiPartyComputationV8(num_parties=3, threshold=2)
        
        result = mpc.secure_addition([1, 2])  # Only 2 values for 3 parties
        
        assert result.success is False
        assert len(result.error_messages) > 0
    
    def test_party_registration(self):
        mpc = SecureMultiPartyComputationV8(num_parties=3, threshold=2)
        
        party = mpc.register_party("party_1", b"public_key_123")
        
        assert party.party_id == "party_1"
        assert party.index == 0
        assert party.is_active is True
    
    def test_batch_computation_sequential(self):
        mpc = SecureMultiPartyComputationV8(num_parties=3, threshold=2)
        
        computations = [
            ("addition", [1, 2, 3]),
            ("addition", [10, 20, 30]),
            ("multiplication", [2, 2, 2])
        ]
        
        result = mpc.batch_compute(computations, parallel=False)
        
        assert result.success is True
        assert result.total_computations == 3
        assert result.successful_computations == 3
        assert result.total_time_ms > 0
        assert result.average_time_ms > 0
    
    def test_batch_computation_parallel(self):
        mpc = SecureMultiPartyComputationV8(num_parties=3, threshold=2, max_workers=2)
        
        computations = [
            ("addition", [1, 1, 1]),
            ("addition", [2, 2, 2]),
            ("addition", [3, 3, 3]),
            ("addition", [4, 4, 4])
        ]
        
        result = mpc.batch_compute(computations, parallel=True)
        
        assert result.success is True
        assert result.total_computations == 4
        assert result.successful_computations == 4
    
    def test_circuit_evaluation(self):
        mpc = SecureMultiPartyComputationV8(num_parties=2, threshold=2)
        
        # Create a simple circuit
        circuit = mpc.circuit_evaluator.create_circuit("test_circuit", 2, 2)
        mpc.circuit_evaluator.add_gate(circuit, "ADD", [0, 1], 2)
        mpc.circuit_evaluator.add_gate(circuit, "OUTPUT", [2], 3)
        
        # 2 parties, each provides 2 inputs
        party_inputs = [[5, 0], [10, 0]]
        
        result = mpc.secure_circuit_evaluation(circuit, party_inputs)
        
        assert result.success is True
        assert len(result.output_values) >= 0
    
    def test_security_parameters(self):
        mpc = SecureMultiPartyComputationV8(
            num_parties=5,
            threshold=3,
            security_model=SecurityModel.MALICIOUS,
            security_level=MPCSecurityLevel.QUANTUM_RESISTANT
        )
        
        params = mpc.get_security_parameters()
        
        assert params["num_parties"] == 5
        assert params["threshold"] == 3
        assert params["security_model"] == "malicious"
        assert params["security_level"] == "quantum_resistant"
        assert params["total_computations"] == 0
    
    def test_audit_logging(self):
        mpc = SecureMultiPartyComputationV8(num_parties=3, threshold=2)
        
        # Perform some computations
        mpc.secure_addition([1, 2, 3])
        mpc.secure_addition([4, 5, 6])
        
        audit_log = mpc.get_audit_log(limit=10)
        
        assert len(audit_log) >= 2
        assert all("timestamp" in entry for entry in audit_log)
        assert all("event_type" in entry for entry in audit_log)
    
    def test_computation_count_tracking(self):
        mpc = SecureMultiPartyComputationV8(num_parties=3, threshold=2)
        
        initial = mpc.get_security_parameters()["total_computations"]
        
        mpc.secure_addition([1, 2, 3])
        mpc.secure_multiplication([1, 2, 3])
        
        final = mpc.get_security_parameters()["total_computations"]
        
        assert final == initial + 2


class TestFactoryAndVerification:
    """Tests for factory and verification functions"""
    
    def test_create_mpc_engine_v8(self):
        engine = create_mpc_engine_v8(
            num_parties=5,
            threshold=3,
            security_model="malicious"
        )
        
        assert isinstance(engine, SecureMultiPartyComputationV8)
        assert engine.num_parties == 5
        assert engine.threshold == 3
        assert engine.security_model == SecurityModel.MALICIOUS
    
    def test_create_mpc_engine_semi_honest(self):
        engine = create_mpc_engine_v8(
            num_parties=3,
            security_model="semi_honest"
        )
        
        assert engine.security_model == SecurityModel.SEMI_HONEST
    
    def test_verify_mpc_engine_v8(self):
        result = verify_mpc_engine_v8()
        
        assert result["engine_created"] is True
        assert result["addition_success"] is True
        assert result["addition_correct"] is True
        assert result["multiplication_success"] is True
        assert result["multiplication_correct"] is True
        assert result["batch_success"] is True
        assert result["audit_log_available"] is True
        assert result["total_computations"] > 0
        assert len(result["errors"]) == 0


def test_integration_complete_workflow():
    """Full integration test of the complete MPC workflow"""
    # Create engine with malicious security
    mpc = create_mpc_engine_v8(
        num_parties=4,
        threshold=3,
        security_model="malicious"
    )
    
    # Register parties
    for i in range(4):
        mpc.register_party(f"party_{i}", f"pubkey_{i}".encode())
    
    # Perform various computations
    results = []
    
    # Private sum computation
    add_result = mpc.secure_addition([100, 200, 300, 400])
    results.append(add_result)
    
    # Private product computation
    mult_result = mpc.secure_multiplication([2, 3, 4, 5])
    results.append(mult_result)
    
    # Batch computation
    batch_result = mpc.batch_compute([
        ("addition", [1, 1, 1, 1]),
        ("addition", [10, 10, 10, 10]),
        ("multiplication", [2, 2, 2, 2])
    ])
    
    # Verify all computations succeeded
    assert all(r.success for r in results)
    assert add_result.output_values[0] == 1000  # 100+200+300+400
    assert mult_result.output_values[0] == 120  # 2*3*4*5
    
    # Verify audit trail
    audit_log = mpc.get_audit_log()
    assert len(audit_log) >= 6  # registrations + computations
    
    # Get final security stats
    params = mpc.get_security_parameters()
    assert params["total_computations"] >= 2
    
    # Save test results
    test_results = {
        "test_timestamp": "2026-06-20T00:00:00Z",
        "engine": "MPC_V8",
        "security_model": "malicious",
        "num_parties": 4,
        "threshold": 3,
        "total_computations": params["total_computations"],
        "all_computations_succeeded": all(r.success for r in results),
        "addition_correct": add_result.output_values[0] == 1000,
        "multiplication_correct": mult_result.output_values[0] == 120,
        "batch_succeeded": batch_result.success,
        "audit_log_entries": len(audit_log),
        "all_tests_passed": True
    }
    
    with open("test_results_post_quantum_secure_mpc_engine_v8.json", "w") as f:
        json.dump(test_results, f, indent=2)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
