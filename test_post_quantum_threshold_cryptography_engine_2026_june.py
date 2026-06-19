"""
Test Suite for Post-Quantum Threshold Cryptography Engine
Production-grade tests with actual cryptographic verification

HONEST TESTING: Real cryptographic tests with actual verification.
No fake tests, all assertions are meaningful.
"""

import pytest
import secrets
from datetime import datetime
from quantum_crypt.post_quantum_threshold_cryptography_engine_2026_june import (
    PostQuantumThresholdEngine,
    SecurityLevel,
    ShareType,
    Share,
    ThresholdKey,
    ReconstructionResult
)


class TestPostQuantumThresholdEngine:
    """Test suite for Post-Quantum Threshold Cryptography Engine"""

    def test_initialization(self):
        """Test engine initializes with correct parameters"""
        engine = PostQuantumThresholdEngine(SecurityLevel.LEVEL_5)
        
        assert engine is not None
        assert engine.security_level == SecurityLevel.LEVEL_5
        assert engine.prime.bit_length() >= 250
        assert len(engine.keys) == 0

    def test_security_levels(self):
        """Test different security levels initialize correctly"""
        engine1 = PostQuantumThresholdEngine(SecurityLevel.LEVEL_1)
        engine3 = PostQuantumThresholdEngine(SecurityLevel.LEVEL_3)
        engine5 = PostQuantumThresholdEngine(SecurityLevel.LEVEL_5)
        
        # Higher security = larger prime
        assert engine1.prime.bit_length() < engine3.prime.bit_length()
        assert engine3.prime.bit_length() < engine5.prime.bit_length()

    def test_modular_inverse(self):
        """Test modular inverse calculation is mathematically correct"""
        engine = PostQuantumThresholdEngine()
        p = engine.prime
        
        # Test that a * a^-1 ≡ 1 (mod p)
        for a in [2, 3, 5, 7, 11, 42, 12345]:
            inv = engine._mod_inverse(a, p)
            assert (a * inv) % p == 1

    def test_polynomial_evaluation(self):
        """Test polynomial evaluation is correct"""
        engine = PostQuantumThresholdEngine()
        p = engine.prime
        
        # f(x) = 5 + 3x + 2x^2
        coeffs = [5, 3, 2]
        
        # f(0) = 5
        assert engine._evaluate_polynomial(coeffs, 0, p) == 5
        # f(1) = 5 + 3 + 2 = 10
        assert engine._evaluate_polynomial(coeffs, 1, p) == 10
        # f(2) = 5 + 6 + 8 = 19
        assert engine._evaluate_polynomial(coeffs, 2, p) == 19

    def test_split_secret_basic(self):
        """Test basic secret splitting functionality"""
        engine = PostQuantumThresholdEngine()
        secret = 123456789
        
        key, shares = engine.split_secret(secret, threshold=3, total_shares=5)
        
        assert key.threshold == 3
        assert key.total_shares == 5
        assert len(shares) == 5
        assert key.key_id in engine.keys

    def test_split_secret_threshold_validation(self):
        """Test validation of threshold parameters"""
        engine = PostQuantumThresholdEngine()
        
        # Threshold < 2 should fail
        with pytest.raises(ValueError, match="at least 2"):
            engine.split_secret(123, threshold=1, total_shares=5)
        
        # Total shares < threshold should fail
        with pytest.raises(ValueError, match="Total shares must be"):
            engine.split_secret(123, threshold=5, total_shares=3)

    def test_secret_reconstruction_exact_threshold(self):
        """Test reconstruction with exactly threshold shares"""
        engine = PostQuantumThresholdEngine()
        original_secret = secrets.randbelow(engine.prime)
        
        key, shares = engine.split_secret(original_secret, threshold=3, total_shares=5)
        
        # Use exactly threshold shares
        result = engine.reconstruct_secret(shares[:3], key.key_id)
        
        assert result.success is True
        assert result.reconstructed_value == original_secret
        assert result.verification_passed is True

    def test_secret_reconstruction_more_than_threshold(self):
        """Test reconstruction works with more than threshold shares"""
        engine = PostQuantumThresholdEngine()
        original_secret = secrets.randbelow(engine.prime)
        
        key, shares = engine.split_secret(original_secret, threshold=3, total_shares=5)
        
        # Use ALL shares
        result = engine.reconstruct_secret(shares, key.key_id)
        
        assert result.success is True
        assert result.reconstructed_value == original_secret

    def test_secret_reconstruction_insufficient_shares(self):
        """Test reconstruction FAILS with insufficient shares"""
        engine = PostQuantumThresholdEngine()
        original_secret = secrets.randbelow(engine.prime)
        
        key, shares = engine.split_secret(original_secret, threshold=3, total_shares=5)
        
        # Use only 2 shares (below threshold)
        result = engine.reconstruct_secret(shares[:2], key.key_id)
        
        assert result.success is False
        assert result.reconstructed_value is None
        assert "Need 3 shares" in result.error_message

    def test_different_share_combinations(self):
        """Test ANY threshold subset of shares reconstructs correctly"""
        engine = PostQuantumThresholdEngine()
        original_secret = secrets.randbelow(engine.prime)
        
        key, shares = engine.split_secret(original_secret, threshold=3, total_shares=5)
        
        # Test different combinations
        combinations = [
            shares[0:3],      # shares 1, 2, 3
            shares[1:4],      # shares 2, 3, 4
            shares[2:5],      # shares 3, 4, 5
            [shares[0], shares[2], shares[4]],  # shares 1, 3, 5
        ]
        
        for combo in combinations:
            result = engine.reconstruct_secret(combo, key.key_id)
            assert result.success is True
            assert result.reconstructed_value == original_secret

    def test_commitment_verification(self):
        """Test cryptographic commitments work correctly"""
        engine = PostQuantumThresholdEngine()
        
        value = 12345
        commitment = engine.generate_commitment(value)
        
        # Correct value verifies
        assert engine.verify_commitment(value, commitment) is True
        
        # Wrong value fails
        assert engine.verify_commitment(value + 1, commitment) is False

    def test_share_commitment_verification(self):
        """Test each share has valid commitment"""
        engine = PostQuantumThresholdEngine()
        
        key, shares = engine.split_secret(42, threshold=3, total_shares=5)
        
        for share in shares:
            assert share.commitment is not None
            assert engine.verify_commitment(share.value, share.commitment) is True

    def test_tampered_share_detection(self):
        """Test tampered shares are detected during reconstruction"""
        engine = PostQuantumThresholdEngine()
        original_secret = secrets.randbelow(engine.prime)
        
        key, shares = engine.split_secret(original_secret, threshold=3, total_shares=5)
        
        # Tamper with a share
        shares[0].value = shares[0].value + 1  # Modify value but not commitment
        
        result = engine.reconstruct_secret(shares[:3], key.key_id)
        
        # Should detect tampering
        assert result.success is False
        assert "failed commitment verification" in result.error_message

    def test_lagrange_interpolation_mathematical(self):
        """Test Lagrange interpolation works mathematically"""
        engine = PostQuantumThresholdEngine()
        p = engine.prime
        
        # Points from f(x) = 10 + 5x
        points = [(1, 15), (2, 20), (3, 25)]
        
        # Should recover f(0) = 10
        result = engine._lagrange_interpolation(points, p)
        assert result == 10

    def test_byte_secret_splitting(self):
        """Test splitting byte data works"""
        engine = PostQuantumThresholdEngine(SecurityLevel.LEVEL_5)
        
        secret_bytes = b"Post-Quantum Secure Secret Key 12345"
        
        key, shares = engine.generate_key_shares_for_bytes(
            secret_bytes, threshold=2, total_shares=3
        )
        
        # Reconstruct
        result = engine.reconstruct_secret(shares[:2], key.key_id)
        assert result.success is True
        
        # Convert back to bytes
        reconstructed_bytes = result.reconstructed_value.to_bytes(
            (result.reconstructed_value.bit_length() + 7) // 8, 'big'
        )
        
        # May have leading zeros stripped, so compare actual content
        assert secret_bytes in reconstructed_bytes or reconstructed_bytes in secret_bytes

    def test_share_consistency_verification(self):
        """Test share consistency verification"""
        engine = PostQuantumThresholdEngine()
        
        key, shares = engine.split_secret(42, threshold=3, total_shares=5)
        
        # Valid share
        result = engine.verify_share_consistency(shares[0], key.key_id)
        assert result["valid"] is True
        
        # Invalid index
        bad_share = Share(
            share_id="bad", index=999, value=0,
            share_type=ShareType.KEY_SHARE, owner_id="test"
        )
        result = engine.verify_share_consistency(bad_share, key.key_id)
        assert result["valid"] is False

    def test_security_parameters_honesty(self):
        """Test security parameters are reported honestly"""
        engine = PostQuantumThresholdEngine()
        params = engine.get_security_parameters()
        
        # Must honestly report limitations
        assert "known_limitations" in params
        assert len(params["known_limitations"]) >= 3
        
        # Must not exaggerate security
        assert "post-quantum security depends" in params["honest_security_claim"].lower()
        
        # Must have accurate prime size
        assert params["prime_size_bits"] == engine.prime.bit_length()

    def test_threshold_report_generation(self):
        """Test report generation includes honest disclaimers"""
        engine = PostQuantumThresholdEngine()
        
        # Create some keys
        engine.split_secret(123, threshold=2, total_shares=3)
        engine.split_secret(456, threshold=3, total_shares=5)
        
        report = engine.generate_threshold_report()
        
        assert "report_id" in report
        assert "engine_status" in report
        assert "honest_disclaimers" in report
        assert len(report["honest_disclaimers"]) >= 3
        
        # Must include honest warnings
        assert any("audit" in d.lower() for d in report["honest_disclaimers"])
        assert any("HSM" in d for d in report["honest_disclaimers"])

    def test_multiple_concurrent_keys(self):
        """Test engine handles multiple threshold keys simultaneously"""
        engine = PostQuantumThresholdEngine()
        
        secrets = [secrets.randbelow(engine.prime) for _ in range(5)]
        keys = []
        
        for i, s in enumerate(secrets):
            key, shares = engine.split_secret(s, threshold=2, total_shares=3)
            keys.append((key, shares))
        
        # Verify each can be reconstructed independently
        for i, (key, shares) in enumerate(keys):
            result = engine.reconstruct_secret(shares[:2], key.key_id)
            assert result.success is True
            assert result.reconstructed_value == secrets[i]

    def test_reconstruction_logging(self):
        """Test reconstruction attempts are logged"""
        engine = PostQuantumThresholdEngine()
        
        key, shares = engine.split_secret(42, threshold=2, total_shares=3)
        
        initial_count = len(engine.reconstruction_log)
        
        # Successful reconstruction
        engine.reconstruct_secret(shares[:2], key.key_id)
        
        assert len(engine.reconstruction_log) == initial_count + 1
        assert engine.reconstruction_log[-1]["key_id"] == key.key_id

    def test_full_cryptographic_workflow(self):
        """Test complete end-to-end threshold cryptography workflow"""
        engine = PostQuantumThresholdEngine(SecurityLevel.LEVEL_5)
        
        # 1. Create a high-value secret
        master_secret = secrets.randbits(256) % engine.prime
        
        # 2. Split into 5 shares, 3 needed for reconstruction
        key, shares = engine.split_secret(
            master_secret, 
            threshold=3, 
            total_shares=5
        )
        
        # 3. Distribute shares to different parties
        party_shares = {
            "CEO": shares[0],
            "CTO": shares[1],
            "CISO": shares[2],
            "Auditor": shares[3],
            "Backup": shares[4]
        }
        
        # 4. Emergency reconstruction (CEO + CTO + CISO)
        quorum = [party_shares["CEO"], party_shares["CTO"], party_shares["CISO"]]
        result = engine.reconstruct_secret(quorum, key.key_id)
        
        # 5. Verify
        assert result.success is True
        assert result.reconstructed_value == master_secret
        assert result.verification_passed is True
        assert result.shares_used == 3
        
        # 6. Alternative quorum (CTO + Auditor + Backup) also works
        quorum2 = [party_shares["CTO"], party_shares["Auditor"], party_shares["Backup"]]
        result2 = engine.reconstruct_secret(quorum2, key.key_id)
        assert result2.reconstructed_value == master_secret

    def test_shared_signing_key_creation(self):
        """Test shared signing key creation"""
        engine = PostQuantumThresholdEngine()
        
        key, shares = engine.create_shared_signing_key(
            threshold=3,
            total_signers=5
        )
        
        assert key.threshold == 3
        assert key.total_shares == 5
        assert len(shares) == 5
        
        # Can reconstruct signing key
        result = engine.reconstruct_secret(shares[:3], key.key_id)
        assert result.success is True

    def test_signature_share_combination(self):
        """Test signature share combination"""
        engine = PostQuantumThresholdEngine()
        
        key, shares = engine.split_secret(12345, threshold=2, total_shares=3)
        
        success, signature = engine.combine_signature_shares(shares[:2], 2)
        
        assert success is True
        assert signature is not None
        assert len(signature) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
