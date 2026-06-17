"""
Test suite for Post-Quantum Secure Multi-Signature Engine
Production-grade tests with real assertions
"""

import pytest
import hashlib
import secrets
from quantum_crypt.post_quantum_secure_multisig_2026_june import (
    PostQuantumMultisigEngine,
    SignatureAlgorithm,
    KeyShareStatus,
    KeyShare,
    PartialSignature,
    AggregatedSignature
)


class TestPostQuantumMultisigEngine:
    """Test suite for PostQuantumMultisigEngine"""

    def setup_method(self):
        """Setup test fixtures"""
        # Standard 2-of-3 multisig
        self.engine = PostQuantumMultisigEngine(
            threshold=2,
            total_signers=3,
            algorithm=SignatureAlgorithm.HYBRID_HASH
        )
        self.test_message = b"Test message for post-quantum multisig signing"

    def test_initialization(self):
        """Test proper initialization of multisig engine"""
        assert self.engine.threshold == 2
        assert self.engine.total_signers == 3
        assert self.engine.algorithm == SignatureAlgorithm.HYBRID_HASH
        assert len(self.engine.key_shares) == 0
        
        stats = self.engine.get_stats()
        assert stats["threshold"] == 2
        assert stats["total_signers"] == 3

    def test_initialization_invalid_threshold(self):
        """Test initialization with invalid threshold"""
        # Threshold > total signers should fail
        try:
            PostQuantumMultisigEngine(threshold=5, total_signers=3)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass
        
        # Threshold < 1 should fail
        try:
            PostQuantumMultisigEngine(threshold=0, total_signers=3)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_generate_key_shares(self):
        """Test key share generation"""
        shares = self.engine.generate_key_shares()
        
        assert len(shares) == 3
        assert all(isinstance(s, KeyShare) for s in shares)
        assert self.engine.master_secret is not None
        assert self.engine.master_public_key is not None
        assert len(self.engine.key_shares) == 3
        
        # All shares should have unique indices 1, 2, 3
        indices = [s.index for s in shares]
        assert sorted(indices) == [1, 2, 3]
        
        # All shares should have unique IDs
        share_ids = [s.share_id for s in shares]
        assert len(set(share_ids)) == 3

    def test_generate_key_shares_with_secret(self):
        """Test key share generation with custom master secret"""
        custom_secret = secrets.token_bytes(32)
        shares = self.engine.generate_key_shares(master_secret=custom_secret)
        
        assert len(shares) == 3
        assert self.engine.master_secret is not None

    def test_create_partial_signature(self):
        """Test partial signature creation"""
        shares = self.engine.generate_key_shares()
        
        partial_sig = self.engine.create_partial_signature(
            share_id=shares[0].share_id,
            message=self.test_message,
            signer_id="signer_1"
        )
        
        assert isinstance(partial_sig, PartialSignature)
        assert partial_sig.signer_id == "signer_1"
        assert len(partial_sig.signature) == 32  # SHA256
        assert len(partial_sig.nonce) == 32

    def test_create_partial_signature_invalid_share(self):
        """Test partial signature with invalid share"""
        self.engine.generate_key_shares()
        
        try:
            self.engine.create_partial_signature(
                share_id="invalid_share_id",
                message=self.test_message,
                signer_id="signer_1"
            )
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_verify_partial_signature_valid(self):
        """Test verification of valid partial signature"""
        shares = self.engine.generate_key_shares()
        
        partial_sig = self.engine.create_partial_signature(
            share_id=shares[0].share_id,
            message=self.test_message,
            signer_id="signer_1"
        )
        
        is_valid = self.engine.verify_partial_signature(partial_sig, self.test_message)
        assert is_valid is True

    def test_verify_partial_signature_wrong_message(self):
        """Test verification fails with wrong message"""
        shares = self.engine.generate_key_shares()
        
        partial_sig = self.engine.create_partial_signature(
            share_id=shares[0].share_id,
            message=self.test_message,
            signer_id="signer_1"
        )
        
        wrong_message = b"Different message"
        is_valid = self.engine.verify_partial_signature(partial_sig, wrong_message)
        assert is_valid is False

    def test_aggregate_signatures(self):
        """Test signature aggregation"""
        shares = self.engine.generate_key_shares()
        
        # Collect 2 partial signatures (meets threshold)
        sig1 = self.engine.create_partial_signature(
            shares[0].share_id, self.test_message, "signer_1"
        )
        sig2 = self.engine.create_partial_signature(
            shares[1].share_id, self.test_message, "signer_2"
        )
        
        aggregated = self.engine.aggregate_signatures(
            [sig1, sig2], self.test_message
        )
        
        assert isinstance(aggregated, AggregatedSignature)
        assert aggregated.threshold == 2
        assert aggregated.total_signers == 3
        assert len(aggregated.signatures) == 2
        assert len(aggregated.aggregated_value) == 32
        assert aggregated.signature_id.startswith("multisig_")

    def test_aggregate_signatures_below_threshold(self):
        """Test aggregation fails below threshold"""
        shares = self.engine.generate_key_shares()
        
        sig1 = self.engine.create_partial_signature(
            shares[0].share_id, self.test_message, "signer_1"
        )
        
        try:
            self.engine.aggregate_signatures([sig1], self.test_message)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_verify_aggregated_signature_valid(self):
        """Test verification of valid aggregated signature"""
        shares = self.engine.generate_key_shares()
        
        sig1 = self.engine.create_partial_signature(
            shares[0].share_id, self.test_message, "signer_1"
        )
        sig2 = self.engine.create_partial_signature(
            shares[1].share_id, self.test_message, "signer_2"
        )
        
        aggregated = self.engine.aggregate_signatures([sig1, sig2], self.test_message)
        
        is_valid = self.engine.verify_aggregated_signature(aggregated, self.test_message)
        assert is_valid is True

    def test_verify_aggregated_signature_wrong_message(self):
        """Test aggregated signature verification fails with wrong message"""
        shares = self.engine.generate_key_shares()
        
        sig1 = self.engine.create_partial_signature(
            shares[0].share_id, self.test_message, "signer_1"
        )
        sig2 = self.engine.create_partial_signature(
            shares[1].share_id, self.test_message, "signer_2"
        )
        
        aggregated = self.engine.aggregate_signatures([sig1, sig2], self.test_message)
        
        wrong_message = b"Completely different message"
        is_valid = self.engine.verify_aggregated_signature(aggregated, wrong_message)
        assert is_valid is False

    def test_revoke_key_share(self):
        """Test key share revocation"""
        shares = self.engine.generate_key_shares()
        share_id = shares[0].share_id
        
        result = self.engine.revoke_key_share(share_id)
        assert result is True
        assert self.engine.key_shares[share_id].status == KeyShareStatus.REVOKED
        
        # Revoked share cannot be used for signing
        try:
            self.engine.create_partial_signature(share_id, self.test_message, "signer_1")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_revoke_nonexistent_share(self):
        """Test revocation of nonexistent share"""
        result = self.engine.revoke_key_share("nonexistent")
        assert result is False

    def test_get_share_public_key(self):
        """Test public key retrieval"""
        shares = self.engine.generate_key_shares()
        
        pubkey = self.engine.get_share_public_key(shares[0].share_id)
        assert pubkey is not None
        assert len(pubkey) == 32
        
        # Nonexistent share returns None
        assert self.engine.get_share_public_key("invalid") is None

    def test_get_signing_status(self):
        """Test signing status retrieval"""
        shares = self.engine.generate_key_shares()
        
        # Initially no signatures
        status = self.engine.get_signing_status(self.test_message)
        assert status["collected_signatures"] == 0
        assert status["threshold_met"] is False
        
        # Add one signature
        self.engine.create_partial_signature(
            shares[0].share_id, self.test_message, "signer_1"
        )
        
        status = self.engine.get_signing_status(self.test_message)
        assert status["collected_signatures"] == 1
        assert status["threshold_met"] is False
        
        # Add second signature (meets threshold)
        self.engine.create_partial_signature(
            shares[1].share_id, self.test_message, "signer_2"
        )
        
        status = self.engine.get_signing_status(self.test_message)
        assert status["collected_signatures"] == 2
        assert status["threshold_met"] is True

    def test_get_stats(self):
        """Test statistics retrieval"""
        shares = self.engine.generate_key_shares()
        
        stats = self.engine.get_stats()
        
        assert stats["threshold"] == 2
        assert stats["total_signers"] == 3
        assert stats["valid_key_shares"] == 3
        assert stats["total_key_shares"] == 3
        assert stats["has_master_key"] is True
        assert stats["prime_bits"] > 0

    def test_export_public_info(self):
        """Test public info export (no secrets)"""
        self.engine.generate_key_shares()
        
        public_info = self.engine.export_public_info()
        
        assert "threshold" in public_info
        assert "total_signers" in public_info
        assert "master_public_key" in public_info
        assert "share_public_keys" in public_info
        assert "prime_bits" in public_info
        
        # Verify no secrets are exported
        assert "master_secret" not in public_info
        assert "share_value" not in str(public_info)

    def test_3_of_5_multisig(self):
        """Test 3-of-5 multisig configuration"""
        engine = PostQuantumMultisigEngine(threshold=3, total_signers=5)
        shares = engine.generate_key_shares()
        
        assert len(shares) == 5
        
        # Sign with 3 signers
        sigs = []
        for i in range(3):
            sig = engine.create_partial_signature(
                shares[i].share_id, self.test_message, f"signer_{i}"
            )
            sigs.append(sig)
        
        aggregated = engine.aggregate_signatures(sigs, self.test_message)
        assert engine.verify_aggregated_signature(aggregated, self.test_message) is True

    def test_different_algorithms(self):
        """Test different signature algorithms"""
        for algo in SignatureAlgorithm:
            engine = PostQuantumMultisigEngine(
                threshold=2,
                total_signers=3,
                algorithm=algo
            )
            shares = engine.generate_key_shares()
            assert len(shares) == 3
            
            sig1 = engine.create_partial_signature(
                shares[0].share_id, self.test_message, "signer_1"
            )
            sig2 = engine.create_partial_signature(
                shares[1].share_id, self.test_message, "signer_2"
            )
            
            aggregated = engine.aggregate_signatures([sig1, sig2], self.test_message)
            assert aggregated.algorithm == algo

    def test_lagrange_interpolation_reconstruction(self):
        """Test that Shamir secret sharing properly reconstructs secret"""
        engine = PostQuantumMultisigEngine(threshold=2, total_signers=3)
        shares = engine.generate_key_shares()
        original_secret = engine.master_secret
        
        # Get points from shares
        points = [(s.index, s.value) for s in shares[:2]]
        reconstructed = engine._lagrange_interpolation(points)
        
        assert reconstructed == original_secret

    def test_full_signing_workflow(self):
        """Test complete end-to-end signing workflow"""
        # 1. Setup multisig
        engine = PostQuantumMultisigEngine(threshold=2, total_signers=3)
        shares = engine.generate_key_shares()
        
        # 2. Distribute shares to signers
        signer_shares = {f"signer_{i+1}": shares[i] for i in range(3)}
        
        # 3. Collect partial signatures
        partial_sigs = []
        for signer_id, share in list(signer_shares.items())[:2]:
            sig = engine.create_partial_signature(
                share.share_id, self.test_message, signer_id
            )
            partial_sigs.append(sig)
        
        # 4. Aggregate signatures
        aggregated = engine.aggregate_signatures(partial_sigs, self.test_message)
        
        # 5. Verify final signature
        is_valid = engine.verify_aggregated_signature(aggregated, self.test_message)
        
        assert is_valid is True
        assert aggregated.threshold == 2
        assert len(aggregated.signatures) == 2


if __name__ == "__main__":
    # Run tests directly
    tester = TestPostQuantumMultisigEngine()
    tester.setup_method()
    
    print("=" * 60)
    print("Running PostQuantumMultisigEngine Production Tests")
    print("=" * 60)
    
    tests_passed = 0
    tests_failed = 0
    
    test_methods = [
        "test_initialization",
        "test_initialization_invalid_threshold",
        "test_generate_key_shares",
        "test_generate_key_shares_with_secret",
        "test_create_partial_signature",
        "test_create_partial_signature_invalid_share",
        "test_verify_partial_signature_valid",
        "test_verify_partial_signature_wrong_message",
        "test_aggregate_signatures",
        "test_aggregate_signatures_below_threshold",
        "test_verify_aggregated_signature_valid",
        "test_verify_aggregated_signature_wrong_message",
        "test_revoke_key_share",
        "test_revoke_nonexistent_share",
        "test_get_share_public_key",
        "test_get_signing_status",
        "test_get_stats",
        "test_export_public_info",
        "test_3_of_5_multisig",
        "test_different_algorithms",
        "test_lagrange_interpolation_reconstruction",
        "test_full_signing_workflow",
    ]
    
    for test_name in test_methods:
        try:
            tester.setup_method()  # Reset for each test
            getattr(tester, test_name)()
            print(f"✓ {test_name}")
            tests_passed += 1
        except Exception as e:
            print(f"✗ {test_name}: {str(e)[:80]}")
            tests_failed += 1
    
    print("=" * 60)
    print(f"Results: {tests_passed} passed, {tests_failed} failed")
    print("=" * 60)
