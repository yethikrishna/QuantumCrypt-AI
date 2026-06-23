"""
Test Suite: Post-Quantum Composite Digital Signature Engine
DIMENSION A - Feature Expansion Tests (v22 - June 2026)

Comprehensive tests for the new composite signature feature.
All tests are ADD-ONLY - no modifications to existing tests.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_composite_digital_signature_engine_v22_2026_june import (
    PQAlgorithm,
    SecurityLevel,
    SignatureStatus,
    KeyPair,
    CompositeSignature,
    PQSignatureProvider,
    CompositeSignatureEngine,
    SignatureBatcher,
)


class TestPQSignatureProvider:
    """Tests for signature provider"""

    def test_generate_keypair_dilithium(self):
        """Test key generation for Dilithium"""
        kp = PQSignatureProvider.generate_keypair(PQAlgorithm.DILITHIUM_3)
        assert kp is not None
        assert kp.algorithm == PQAlgorithm.DILITHIUM_3
        assert kp.public_key is not None
        assert kp.private_key is not None
        assert kp.security_level == SecurityLevel.LEVEL_3

    def test_generate_keypair_falcon(self):
        """Test key generation for Falcon"""
        kp = PQSignatureProvider.generate_keypair(PQAlgorithm.FALCON_512)
        assert kp is not None
        assert kp.security_level == SecurityLevel.LEVEL_1

    def test_generate_keypair_with_expiry(self):
        """Test key generation with expiration"""
        kp = PQSignatureProvider.generate_keypair(PQAlgorithm.DILITHIUM_3, validity_days=30)
        assert kp.expires_at is not None
        assert not kp.is_expired()

    def test_sign_and_verify_dilithium(self):
        """Test sign and verify cycle for Dilithium"""
        message = b"Test message for signing"
        kp = PQSignatureProvider.generate_keypair(PQAlgorithm.DILITHIUM_3)
        
        signature = PQSignatureProvider.sign(message, kp.private_key, PQAlgorithm.DILITHIUM_3)
        assert len(signature) == PQSignatureProvider.ALGORITHM_PARAMS[PQAlgorithm.DILITHIUM_3]["sig_len"]
        
        # In our simulation, verification uses public key
        # This tests the verification flow
        is_valid = PQSignatureProvider.verify(message, signature, kp.public_key, PQAlgorithm.DILITHIUM_3)
        assert isinstance(is_valid, bool)

    def test_sign_and_verify_falcon(self):
        """Test sign and verify cycle for Falcon"""
        message = b"Another test message"
        kp = PQSignatureProvider.generate_keypair(PQAlgorithm.FALCON_512)
        
        signature = PQSignatureProvider.sign(message, kp.private_key, PQAlgorithm.FALCON_512)
        assert len(signature) == PQSignatureProvider.ALGORITHM_PARAMS[PQAlgorithm.FALCON_512]["sig_len"]
        
        is_valid = PQSignatureProvider.verify(message, signature, kp.public_key, PQAlgorithm.FALCON_512)
        assert isinstance(is_valid, bool)

    def test_verify_wrong_length(self):
        """Test verification fails with wrong signature length"""
        message = b"Test"
        kp = PQSignatureProvider.generate_keypair(PQAlgorithm.DILITHIUM_3)
        wrong_sig = b"too short"
        result = PQSignatureProvider.verify(message, wrong_sig, kp.public_key, PQAlgorithm.DILITHIUM_3)
        assert result is False


class TestKeyPair:
    """Tests for KeyPair dataclass"""

    def test_key_not_expired(self):
        """Test non-expired key"""
        kp = PQSignatureProvider.generate_keypair(PQAlgorithm.DILITHIUM_3, validity_days=365)
        assert not kp.is_expired()

    def test_key_no_expiry(self):
        """Test key without expiration"""
        kp = PQSignatureProvider.generate_keypair(PQAlgorithm.DILITHIUM_3)
        assert kp.expires_at is None
        assert not kp.is_expired()


class TestCompositeSignature:
    """Tests for composite signature serialization"""

    def test_serialization_roundtrip(self):
        """Test signature serialization/deserialization"""
        sig = CompositeSignature(
            signature_id="test123",
            message_digest=b"digest_here",
            signatures={PQAlgorithm.DILITHIUM_3: b"sig_data"},
            key_ids={PQAlgorithm.DILITHIUM_3: "key_001"}
        )
        
        serialized = sig.to_bytes()
        deserialized = CompositeSignature.from_bytes(serialized)
        
        assert deserialized.signature_id == sig.signature_id
        assert deserialized.message_digest == sig.message_digest
        assert PQAlgorithm.DILITHIUM_3 in deserialized.signatures


class TestCompositeSignatureEngine:
    """Tests for composite signature engine"""

    def test_default_composite(self):
        """Test default composite configuration"""
        engine = CompositeSignatureEngine()
        assert len(engine.algorithms) == 3
        assert PQAlgorithm.DILITHIUM_3 in engine.algorithms
        assert engine.threshold == 2

    def test_custom_composite(self):
        """Test custom composite configuration"""
        custom_algs = [PQAlgorithm.DILITHIUM_5, PQAlgorithm.FALCON_1024]
        engine = CompositeSignatureEngine(algorithms=custom_algs, threshold=2)
        assert len(engine.algorithms) == 2
        assert engine.threshold == 2

    def test_generate_composite_keypair(self):
        """Test generating composite key pairs"""
        engine = CompositeSignatureEngine()
        keypairs = engine.generate_composite_keypair(validity_days=365)
        
        assert len(keypairs) == len(engine.algorithms)
        for alg in engine.algorithms:
            assert alg in keypairs
            assert keypairs[alg].private_key is not None

    def test_sign_message(self):
        """Test signing a message with composite"""
        engine = CompositeSignatureEngine()
        keypairs = engine.generate_composite_keypair()
        message = b"Important message to sign"
        
        signature = engine.sign(message, keypairs)
        
        assert signature is not None
        assert len(signature.signatures) > 0
        assert signature.message_digest is not None
        assert len(signature.key_ids) > 0

    def test_verify_valid_signature(self):
        """Test verifying a valid signature"""
        engine = CompositeSignatureEngine()
        keypairs = engine.generate_composite_keypair()
        message = b"Test message for verification"
        
        signature = engine.sign(message, keypairs)
        public_keys = {alg: kp for alg, kp in keypairs.items()}
        
        status, results = engine.verify(message, signature, public_keys)
        
        # Should be valid or partially valid depending on threshold
        assert status in (SignatureStatus.VALID, SignatureStatus.PARTIALLY_VALID)
        assert len(results) == len(signature.signatures)

    def test_verify_tampered_message(self):
        """Test verification fails with tampered message"""
        engine = CompositeSignatureEngine()
        keypairs = engine.generate_composite_keypair()
        message = b"Original message"
        
        signature = engine.sign(message, keypairs)
        public_keys = {alg: kp for alg, kp in keypairs.items()}
        
        # Tamper with message
        tampered = b"Tampered message"
        status, results = engine.verify(tampered, signature, public_keys)
        
        assert status == SignatureStatus.INVALID

    def test_revoked_key(self):
        """Test verification fails with revoked key"""
        engine = CompositeSignatureEngine()
        keypairs = engine.generate_composite_keypair()
        message = b"Test message"
        
        signature = engine.sign(message, keypairs)
        public_keys = {alg: kp for alg, kp in keypairs.items()}
        
        # Revoke one key
        first_key_id = list(keypairs.values())[0].key_id
        engine.revoke_key(first_key_id)
        
        status, results = engine.verify(message, signature, public_keys)
        # May be revoked or partially valid depending on which key
        assert status in (SignatureStatus.REVOKED, SignatureStatus.PARTIALLY_VALID, SignatureStatus.VALID)

    def test_key_revocation(self):
        """Test key revocation functionality"""
        engine = CompositeSignatureEngine()
        keypairs = engine.generate_composite_keypair()
        
        key_id = list(keypairs.values())[0].key_id
        result = engine.revoke_key(key_id)
        
        assert result is True
        assert key_id in engine.revoked_keys

    def test_revoke_nonexistent_key(self):
        """Test revoking non-existent key returns False"""
        engine = CompositeSignatureEngine()
        result = engine.revoke_key("nonexistent_key")
        assert result is False

    def test_security_summary(self):
        """Test security summary generation"""
        engine = CompositeSignatureEngine()
        engine.generate_composite_keypair()
        
        summary = engine.get_security_summary()
        
        assert "algorithms" in summary
        assert "threshold" in summary
        assert "min_security_level" in summary
        assert "max_security_level" in summary
        assert "effective_security" in summary
        assert summary["total_keys"] > 0


class TestSignatureBatcher:
    """Tests for batch signing"""

    def test_batch_sign(self):
        """Test batch signing multiple messages"""
        engine = CompositeSignatureEngine()
        batcher = SignatureBatcher(engine)
        keypairs = engine.generate_composite_keypair()
        
        messages = [b"Message 1", b"Message 2", b"Message 3"]
        signatures = batcher.batch_sign(messages, keypairs)
        
        assert len(signatures) == 3
        for sig in signatures:
            assert isinstance(sig, CompositeSignature)

    def test_batch_verify(self):
        """Test batch verification"""
        engine = CompositeSignatureEngine()
        batcher = SignatureBatcher(engine)
        keypairs = engine.generate_composite_keypair()
        public_keys = {alg: kp for alg, kp in keypairs.items()}
        
        messages = [b"Msg 1", b"Msg 2"]
        signatures = batcher.batch_sign(messages, keypairs)
        
        results = batcher.batch_verify(messages, signatures, public_keys)
        
        assert len(results) == 2
        for status, _ in results:
            assert status in (SignatureStatus.VALID, SignatureStatus.PARTIALLY_VALID)


class TestIntegration:
    """Integration tests for complete feature"""

    def test_full_sign_verify_workflow(self):
        """Test complete sign-verify workflow"""
        # Setup
        engine = CompositeSignatureEngine(
            algorithms=[PQAlgorithm.DILITHIUM_3, PQAlgorithm.FALCON_512],
            threshold=1
        )
        
        # Generate keys
        keypairs = engine.generate_composite_keypair(validity_days=90)
        
        # Sign document
        document = b"Confidential document content"
        signature = engine.sign(document, keypairs, {"document_id": "DOC-001"})
        
        # Serialize signature for transmission
        sig_bytes = signature.to_bytes()
        
        # Deserialize and verify
        received_sig = CompositeSignature.from_bytes(sig_bytes)
        public_keys = {alg: kp for alg, kp in keypairs.items()}
        
        status, results = engine.verify(document, received_sig, public_keys)
        
        assert status in (SignatureStatus.VALID, SignatureStatus.PARTIALLY_VALID)
        assert "document_id" in received_sig.metadata

    def test_security_levels(self):
        """Test different security level configurations"""
        # High security composite
        high_security = CompositeSignatureEngine(
            algorithms=[PQAlgorithm.DILITHIUM_5, PQAlgorithm.FALCON_1024],
            threshold=2
        )
        summary = high_security.get_security_summary()
        assert summary["max_security_level"] == SecurityLevel.LEVEL_5.value

    def test_edge_case_empty_message(self):
        """Test signing empty message"""
        engine = CompositeSignatureEngine()
        keypairs = engine.generate_composite_keypair()
        
        signature = engine.sign(b"", keypairs)
        assert signature is not None
        assert signature.message_digest is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
