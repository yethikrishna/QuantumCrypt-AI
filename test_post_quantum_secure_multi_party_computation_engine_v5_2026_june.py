"""
Test suite for Post-Quantum Secure Multi-Party Computation Engine v5
Production-grade tests for QuantumCrypt-AI
"""

import pytest
import secrets
import hashlib
import hmac
from quantum_crypt.post_quantum_secure_multi_party_computation_engine_v5_2026_june import (
    SecureMPCEngineV5,
    PostQuantumCommitmentScheme,
    VerifiableSecretSharing,
    GarbledCircuitEvaluator,
    ZKProofSystem,
    SecurityLevel,
    CommitmentScheme,
    Commitment,
    create_mpc_engine_v5
)


class TestPostQuantumCommitmentScheme:
    """Tests for commitment scheme."""

    def test_commitment_binding(self):
        """Test commitment binding property - cannot open to different value."""
        scheme = PostQuantumCommitmentScheme()
        value1 = b"test value 1"
        value2 = b"test value 2"

        commitment = scheme.commit(value1)
        # Should verify with original value
        assert scheme.verify(commitment, value1) is True
        # Should NOT verify with different value (binding property)
        assert scheme.verify(commitment, value2) is False

    def test_commitment_hiding(self):
        """Test commitment hiding - commitment reveals nothing about value."""
        scheme = PostQuantumCommitmentScheme()
        value = b"secret data"
        commitment = scheme.commit(value)
        # Committed value should be hash, not revealing plaintext
        assert value not in commitment.committed_value
        assert len(commitment.committed_value) == 32  # SHA256 output

    def test_dilithium_commitment_scheme(self):
        """Test lattice-based commitment scheme."""
        scheme = PostQuantumCommitmentScheme(CommitmentScheme.DILITHIUM_COMMIT)
        value = b"test value"
        commitment = scheme.commit(value)
        assert scheme.verify(commitment, value) is True

    def test_commitment_with_custom_randomness(self):
        """Test commitment with explicit randomness."""
        scheme = PostQuantumCommitmentScheme()
        randomness = secrets.token_bytes(32)
        value = b"test"
        commitment = scheme.commit(value, randomness)
        assert commitment.opening == randomness
        assert scheme.verify(commitment, value) is True


class TestVerifiableSecretSharing:
    """Tests for VSS implementation."""

    def test_secret_split_and_reconstruct(self):
        """Test basic secret sharing works correctly."""
        vss = VerifiableSecretSharing(threshold=2)
        secret = 42
        shares, commitments = vss.split_secret(secret, num_parties=3)

        assert len(shares) == 3
        assert len(commitments) == 2  # threshold coefficients

        # Reconstruct with threshold shares
        reconstructed = vss.reconstruct_secret(shares[:2])
        assert reconstructed == secret

    def test_reconstruct_with_different_share_subsets(self):
        """Test reconstruction works with any threshold subset."""
        vss = VerifiableSecretSharing(threshold=3)
        secret = 12345
        shares, _ = vss.split_secret(secret, num_parties=5)

        # Different subsets should all reconstruct to same secret
        r1 = vss.reconstruct_secret(shares[:3])
        r2 = vss.reconstruct_secret(shares[1:4])
        r3 = vss.reconstruct_secret(shares[2:5])

        assert r1 == r2 == r3 == secret

    def test_share_verification(self):
        """Test share verification functionality."""
        vss = VerifiableSecretSharing(threshold=2)
        secret = 100
        shares, commitments = vss.split_secret(secret, num_parties=3)

        for x, y in shares:
            assert vss.verify_share(x, y, commitments) is True


class TestGarbledCircuitEvaluator:
    """Tests for garbled circuit implementation."""

    def test_free_xor_offset_generation(self):
        """Test free-XOR offset generation."""
        garbler = GarbledCircuitEvaluator(security_parameter=128)
        offset = garbler.generate_free_xor_offset()
        assert len(offset) == 16  # 128 bits
        assert garbler.global_offset == offset

    def test_wire_label_generation(self):
        """Test wire label generation."""
        garbler = GarbledCircuitEvaluator()
        label_0, label_1 = garbler.generate_wire_labels("wire1")
        assert len(label_0) == 16
        assert len(label_1) == 16
        assert label_0 != label_1

    def test_xor_bytes(self):
        """Test byte XOR utility."""
        garbler = GarbledCircuitEvaluator()
        a = b'\x01\x02\x03'
        b = b'\x04\x05\x06'
        result = garbler._xor_bytes(a, b)
        assert result == b'\x05\x07\x05'


class TestZKProofSystem:
    """Tests for zero-knowledge proof system."""

    def test_proof_generation(self):
        """Test ZK proof generation."""
        zk = ZKProofSystem()
        secret = 42
        randomness = secrets.token_bytes(32)
        commitment = hashlib.sha256(b"test").digest()

        proof = zk.prove_correct_sharing(secret, randomness, commitment)
        assert proof.proof_id is not None
        assert len(proof.proof_id) == 32
        assert len(proof.transcript) == 4

    def test_proof_verification(self):
        """Test ZK proof verification."""
        zk = ZKProofSystem()
        secret = 42
        randomness = secrets.token_bytes(32)
        commitment = hashlib.sha256(b"test_commitment").digest()

        proof = zk.prove_correct_sharing(secret, randomness, commitment)
        assert zk.verify_proof(proof, commitment) is True


class TestSecureMPCEngineV5:
    """Main test suite for MPC Engine v5."""

    def test_engine_initialization(self):
        """Test basic engine initialization."""
        engine = SecureMPCEngineV5(num_parties=3, threshold=2)
        assert engine.num_parties == 3
        assert engine.threshold == 2
        assert engine.security_level == SecurityLevel.MALICIOUS
        assert engine.vss is not None
        assert engine.commitment_scheme is not None

    def test_different_security_levels(self):
        """Test engine with different security levels."""
        engine_semi = SecureMPCEngineV5(security_level=SecurityLevel.SEMI_HONEST)
        engine_malicious = SecureMPCEngineV5(security_level=SecurityLevel.MALICIOUS)
        engine_verifiable = SecureMPCEngineV5(security_level=SecurityLevel.FULLY_VERIFIABLE)

        assert engine_semi.security_level == SecurityLevel.SEMI_HONEST
        assert engine_malicious.security_level == SecurityLevel.MALICIOUS
        assert engine_verifiable.security_level == SecurityLevel.FULLY_VERIFIABLE

    def test_party_registration(self):
        """Test party registration."""
        engine = SecureMPCEngineV5(num_parties=3, threshold=2)
        pubkey = secrets.token_bytes(32)

        engine.register_party("party1", pubkey)
        assert "party1" in engine.parties
        assert engine.parties["party1"].public_key == pubkey

    def test_secure_input(self):
        """Test secure input with commitment and proof."""
        engine = SecureMPCEngineV5(num_parties=3, threshold=2)
        engine.register_party("party1", secrets.token_bytes(32))

        result = engine.secure_input("party1", 42)

        assert result['party_id'] == "party1"
        assert 'commitment' in result
        assert 'proof_id' in result
        assert result['num_shares'] == 3
        assert 'latency_ms' in result
        assert result['security_level'] == 'malicious'

    def test_secure_input_unknown_party(self):
        """Test secure input rejects unknown parties."""
        engine = SecureMPCEngineV5()
        with pytest.raises(ValueError, match="Unknown party"):
            engine.secure_input("nonexistent", 42)

    def test_secure_sum_computation(self):
        """Test secure sum computation."""
        engine = SecureMPCEngineV5(num_parties=3, threshold=2)
        engine.register_party("party1", secrets.token_bytes(32))
        engine.register_party("party2", secrets.token_bytes(32))
        engine.register_party("party3", secrets.token_bytes(32))

        engine.secure_input("party1", 10)
        engine.secure_input("party2", 20)
        engine.secure_input("party3", 30)

        result = engine.compute_secure_sum(["party1", "party2", "party3"])

        assert result['computation_type'] == 'secure_sum'
        assert result['num_parties'] == 3
        assert result['malicious_security'] is True
        assert 'result_commitment' in result
        assert 'latency_ms' in result

    def test_secure_sum_missing_input(self):
        """Test secure sum requires all parties to have input."""
        engine = SecureMPCEngineV5()
        engine.register_party("party1", secrets.token_bytes(32))

        with pytest.raises(ValueError, match="no committed input"):
            engine.compute_secure_sum(["party1", "party2"])

    def test_secure_product_2party(self):
        """Test secure product with 2 parties (garbled circuits)."""
        engine = SecureMPCEngineV5(num_parties=2, threshold=2)
        engine.register_party("party1", secrets.token_bytes(32))
        engine.register_party("party2", secrets.token_bytes(32))

        result = engine.compute_secure_product(["party1", "party2"])
        assert result['computation_type'] == 'secure_product'
        assert result['protocol'] == 'garbled_circuit'
        assert result['free_xor_optimized'] is True

    def test_secure_product_multiparty(self):
        """Test secure product with multiple parties (BGW)."""
        engine = SecureMPCEngineV5(num_parties=4, threshold=3)
        engine.register_party("party1", secrets.token_bytes(32))
        engine.register_party("party2", secrets.token_bytes(32))
        engine.register_party("party3", secrets.token_bytes(32))
        engine.register_party("party4", secrets.token_bytes(32))

        result = engine.compute_secure_product(["party1", "party2", "party3"])
        assert result['protocol'] == 'bgw_mpc'

    def test_computation_verification(self):
        """Test computation integrity verification."""
        engine = SecureMPCEngineV5()
        result = engine.verify_computation_integrity("comp_001")
        assert result['verified'] is True
        assert result['malicious_behavior_detected'] is False

    def test_proactive_share_refresh(self):
        """Test proactive security share refresh."""
        engine = SecureMPCEngineV5(num_parties=3, threshold=2)
        engine.register_party("party1", secrets.token_bytes(32))
        engine.register_party("party2", secrets.token_bytes(32))
        engine.register_party("party3", secrets.token_bytes(32))

        result = engine.refresh_shares_proactively()
        assert result['operation'] == 'proactive_share_refresh'
        assert result['parties_refreshed'] == 3
        assert result['adaptive_security_enabled'] is True

    def test_security_metrics(self):
        """Test security metrics collection."""
        engine = SecureMPCEngineV5(num_parties=3, threshold=2)
        engine.register_party("party1", secrets.token_bytes(32))
        engine.secure_input("party1", 42)

        metrics = engine.get_security_metrics()
        assert metrics['engine_version'] == 'v5'
        assert metrics['security_level'] == 'malicious'
        assert metrics['configuration']['num_parties'] == 3
        assert metrics['configuration']['corruption_tolerance'] == 1
        assert metrics['operations']['total_computations'] >= 1
        assert metrics['features']['malicious_security'] is True
        assert metrics['features']['post_quantum_commitments'] is True
        assert metrics['features']['zero_knowledge_proofs'] is True

    def test_security_assurance_levels(self):
        """Test security assurance reporting."""
        engine = SecureMPCEngineV5(security_level=SecurityLevel.MALICIOUS)
        assurance = engine._get_security_assurance()
        assert assurance['adversary_model'] == 'active_with_abort'
        assert assurance['post_quantum'] is True
        assert assurance['zk_proofs'] is True

    def test_factory_function(self):
        """Test factory function creates correct instances."""
        engine1 = create_mpc_engine_v5(num_parties=3, threshold=2, security_level="malicious")
        engine2 = create_mpc_engine_v5(security_level="semi_honest")

        assert isinstance(engine1, SecureMPCEngineV5)
        assert engine1.security_level == SecurityLevel.MALICIOUS
        assert engine2.security_level == SecurityLevel.SEMI_HONEST


class TestIntegrationScenarios:
    """Integration tests for realistic MPC scenarios."""

    def test_3party_secure_computation_workflow(self):
        """Test full 3-party computation workflow."""
        engine = SecureMPCEngineV5(num_parties=3, threshold=2, security_level=SecurityLevel.MALICIOUS)

        # Register parties
        for i in range(3):
            engine.register_party(f"party{i+1}", secrets.token_bytes(32))

        # Input private values
        input_results = []
        for i in range(3):
            result = engine.secure_input(f"party{i+1}", 10 * (i + 1))
            input_results.append(result)

        # Verify all inputs committed
        assert len(engine.input_commitments) == 3

        # Compute secure sum
        sum_result = engine.compute_secure_sum(["party1", "party2", "party3"])

        # Verify integrity
        verify_result = engine.verify_computation_integrity("workflow_test")

        # Get final metrics
        metrics = engine.get_security_metrics()

        # Assert workflow completed
        assert sum_result['malicious_security'] is True
        assert verify_result['verified'] is True
        assert metrics['operations']['total_computations'] >= 3

    def test_malicious_security_detection_capability(self):
        """Test malicious security detection framework."""
        engine = SecureMPCEngineV5(
            num_parties=2,
            threshold=2,
            security_level=SecurityLevel.MALICIOUS
        )

        engine.register_party("alice", secrets.token_bytes(32))
        engine.register_party("bob", secrets.token_bytes(32))

        engine.secure_input("alice", 100)
        engine.secure_input("bob", 200)

        metrics = engine.get_security_metrics()

        # Verify malicious security features enabled
        assert metrics['features']['malicious_security'] is True
        assert metrics['features']['post_quantum_commitments'] is True
        assert metrics['features']['zero_knowledge_proofs'] is True

    def test_performance_benchmark(self):
        """Basic performance benchmark."""
        engine = SecureMPCEngineV5(num_parties=3, threshold=2)

        for i in range(3):
            engine.register_party(f"party{i+1}", secrets.token_bytes(32))

        # Perform multiple operations
        latencies = []
        for i in range(10):
            result = engine.secure_input("party1", i)
            latencies.append(result['latency_ms'])

        avg_latency = sum(latencies) / len(latencies)

        # Should complete in reasonable time (no hanging)
        assert avg_latency < 1000  # Less than 1 second average


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
