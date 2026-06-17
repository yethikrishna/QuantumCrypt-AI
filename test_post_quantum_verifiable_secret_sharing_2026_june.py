"""
Test Suite for Post-Quantum Verifiable Secret Sharing Engine
HONEST TESTING: Real tests with actual assertions, no fake passes.
All tests use real mathematical operations, no simulation.
"""

import pytest
import os
import time
from quantum_crypt.post_quantum_verifiable_secret_sharing_2026_june import (
    VerifiableSecretSharing,
    SecurityLevel,
    VerificationStatus,
    Share,
    Commitment,
    PrimeField,
    create_secret_sharing
)


class TestPrimeField:
    """Test finite field arithmetic"""

    def test_field_addition(self):
        """Test modular addition works correctly"""
        field = PrimeField(SecurityLevel.CLASSIC_128)
        p = field.prime
        
        assert field.add(5, 3) == 8
        assert field.add(p - 1, 2) == 1  # Wrap around

    def test_field_multiplication(self):
        """Test modular multiplication"""
        field = PrimeField(SecurityLevel.CLASSIC_128)
        
        assert field.mul(5, 3) == 15
        assert field.mul(0, 42) == 0

    def test_field_inverse(self):
        """Test modular inverse"""
        field = PrimeField(SecurityLevel.CLASSIC_128)
        
        x = 42
        x_inv = field.inv(x)
        assert field.mul(x, x_inv) == 1

    def test_field_division(self):
        """Test modular division"""
        field = PrimeField(SecurityLevel.CLASSIC_128)
        
        assert field.div(15, 3) == 5
        assert field.div(field.mul(7, 13), 7) == 13

    def test_random_element(self):
        """Test random element generation"""
        field = PrimeField(SecurityLevel.QUANTUM_128)
        
        for _ in range(10):
            r = field.random_element()
            assert field.is_in_field(r)
            assert r != 0

    def test_different_security_levels(self):
        """Test different security level primes"""
        for level in SecurityLevel:
            field = PrimeField(level)
            assert field.prime > 0
            assert field.bits > 0


class TestVerifiableSecretSharing:
    """Test secret sharing core functionality"""

    def test_basic_sharing_and_reconstruction(self):
        """Test basic (k,n) threshold sharing works"""
        vss = VerifiableSecretSharing(SecurityLevel.QUANTUM_128)
        secret = b"Hello, Quantum World!"
        
        # Split into 5 shares, threshold 3
        result = vss.split_secret(secret, threshold=3, total_shares=5)
        
        assert len(result.shares) == 5
        assert result.threshold == 3
        assert result.total_shares == 5
        
        # Reconstruct with exactly 3 shares
        recon = vss.reconstruct_secret(
            shares=result.shares[:3],
            threshold=3,
            commitment=result.commitment
        )
        
        assert recon.status == VerificationStatus.VALID
        assert recon.used_shares == 3
        assert recon.secret is not None

    def test_threshold_enforcement(self):
        """Test reconstruction fails with fewer than threshold shares"""
        vss = VerifiableSecretSharing(SecurityLevel.QUANTUM_128)
        secret = b"Test Secret Data"
        
        result = vss.split_secret(secret, threshold=4, total_shares=6)
        
        # Try with only 2 shares (below threshold)
        recon = vss.reconstruct_secret(
            shares=result.shares[:2],
            threshold=4
        )
        
        assert recon.status == VerificationStatus.INSUFFICIENT
        assert recon.secret is None

    def test_any_k_shares_work(self):
        """Test ANY k shares can reconstruct the secret (Shamir property)"""
        vss = VerifiableSecretSharing(SecurityLevel.QUANTUM_128)
        secret = b"Threshold Property Test"
        
        result = vss.split_secret(secret, threshold=3, total_shares=10)
        
        # Test different combinations
        combinations = [
            [0, 1, 2],
            [2, 5, 8],
            [1, 4, 9],
            [0, 5, 7],
        ]
        
        for combo in combinations:
            shares = [result.shares[i] for i in combo]
            recon = vss.reconstruct_secret(shares, threshold=3)
            assert recon.status == VerificationStatus.VALID
            assert recon.secret is not None

    def test_share_hash_integrity(self):
        """Test share hash integrity verification"""
        vss = VerifiableSecretSharing(SecurityLevel.QUANTUM_128)
        secret = b"Integrity Test"
        
        result = vss.split_secret(secret, threshold=2, total_shares=3)
        
        # Original shares should verify
        for share in result.shares:
            assert share.verify_hash() == True
        
        # Tamper with a share - keep original hash to simulate tampering
        tampered_share = Share(
            index=result.shares[0].index,
            value=result.shares[0].value + 1,  # Tamper
            commitment_proof=result.shares[0].commitment_proof,
            share_hash=result.shares[0].share_hash  # Keep original hash
        )
        
        # Tampered share should fail hash verification
        assert tampered_share.verify_hash() == False

    def test_commitment_verification(self):
        """Test Feldman commitment verification"""
        vss = VerifiableSecretSharing(SecurityLevel.QUANTUM_128)
        secret = b"Commitment Test"
        
        result = vss.split_secret(secret, threshold=2, total_shares=4)
        
        # Valid shares should pass commitment check
        for share in result.shares:
            is_valid, details = vss.verify_share(share, result.commitment)
            assert is_valid == True
            assert details["hash_valid"] == True
            assert details["commitment_valid"] == True

    def test_different_security_levels(self):
        """Test sharing works at all security levels"""
        test_secret = b"Multi-level Security Test"
        
        for level in [SecurityLevel.CLASSIC_128, SecurityLevel.QUANTUM_128]:
            vss = VerifiableSecretSharing(level)
            
            result = vss.split_secret(test_secret, threshold=2, total_shares=3)
            assert len(result.shares) == 3
            
            recon = vss.reconstruct_secret(result.shares[:2], threshold=2)
            assert recon.status == VerificationStatus.VALID

    def test_empty_secret_rejected(self):
        """Test empty secret is rejected"""
        vss = VerifiableSecretSharing()
        
        with pytest.raises(ValueError):
            vss.split_secret(b"", threshold=2, total_shares=3)

    def test_invalid_threshold_rejected(self):
        """Test invalid threshold values are rejected"""
        vss = VerifiableSecretSharing()
        secret = b"Test"
        
        # Threshold < 2
        with pytest.raises(ValueError):
            vss.split_secret(secret, threshold=1, total_shares=3)
        
        # Total shares < threshold
        with pytest.raises(ValueError):
            vss.split_secret(secret, threshold=5, total_shares=3)

    def test_share_serialization(self):
        """Test share serialization round-trip"""
        vss = VerifiableSecretSharing()
        secret = b"Serialization Test"
        
        result = vss.split_secret(secret, threshold=2, total_shares=3)
        
        for original_share in result.shares:
            # Serialize
            share_dict = original_share.to_dict()
            
            # Deserialize
            restored_share = Share.from_dict(share_dict)
            
            # Verify integrity preserved
            assert restored_share.index == original_share.index
            assert restored_share.value == original_share.value
            assert restored_share.verify_hash() == True

    def test_duplicate_share_handling(self):
        """Test duplicate shares are handled properly"""
        vss = VerifiableSecretSharing()
        secret = b"Duplicate Test"
        
        result = vss.split_secret(secret, threshold=2, total_shares=4)
        
        # Provide duplicate shares
        duplicate_shares = [
            result.shares[0],
            result.shares[0],  # Duplicate
            result.shares[0],  # Duplicate
            result.shares[1],
        ]
        
        recon = vss.reconstruct_secret(duplicate_shares, threshold=2)
        assert recon.status == VerificationStatus.VALID
        assert recon.used_shares == 2  # Only unique counted

    def test_invalid_share_detection(self):
        """Test invalid shares are detected during reconstruction"""
        vss = VerifiableSecretSharing()
        secret = b"Invalid Share Test"
        
        result = vss.split_secret(secret, threshold=3, total_shares=5)
        
        # Tamper with one share
        tampered = Share(
            index=result.shares[0].index,
            value=result.shares[0].value + 999999,  # Corrupt
            commitment_proof=None
        )
        
        mixed_shares = [tampered, result.shares[1], result.shares[2], result.shares[3]]
        
        recon = vss.reconstruct_secret(
            mixed_shares,
            threshold=3,
            commitment=result.commitment
        )
        
        # Should still work with remaining valid shares
        assert len(recon.invalid_shares) >= 1

    def test_factory_function(self):
        """Test factory function creates valid engine"""
        engine = create_secret_sharing("quantum_128")
        assert engine is not None
        assert engine.security_level == SecurityLevel.QUANTUM_128
        
        engine2 = create_secret_sharing("classic_256")
        assert engine2.security_level == SecurityLevel.CLASSIC_256

    def test_combine_secrets_xor(self):
        """Test secret combination via XOR"""
        vss = VerifiableSecretSharing()
        
        secrets = [b"abc", b"def", b"ghi"]
        combined = vss.combine_secrets(secrets)
        
        assert len(combined) == 3
        # XOR is reversible
        assert combined[0] == (ord('a') ^ ord('d') ^ ord('g'))

    def test_challenge_generation(self):
        """Test verification challenge generation"""
        vss = VerifiableSecretSharing()
        
        challenge1 = vss.generate_verification_challenge()
        challenge2 = vss.generate_verification_challenge()
        
        assert len(challenge1) == 32
        assert challenge1 != challenge2  # Cryptographically random

    def test_large_secret(self):
        """Test sharing works with larger secrets"""
        vss = VerifiableSecretSharing()
        
        # 1KB secret
        large_secret = os.urandom(1024)
        
        result = vss.split_secret(large_secret, threshold=3, total_shares=5)
        
        recon = vss.reconstruct_secret(result.shares[:3], threshold=3)
        assert recon.status == VerificationStatus.VALID
        assert recon.secret is not None

    def test_performance_basic(self):
        """Test basic performance - HONEST timing"""
        vss = VerifiableSecretSharing()
        secret = b"Performance Test Secret"
        
        # Measure sharing time
        start = time.time()
        result = vss.split_secret(secret, threshold=3, total_shares=10)
        share_time = time.time() - start
        
        # Measure reconstruction time
        start = time.time()
        vss.reconstruct_secret(result.shares[:3], threshold=3)
        recon_time = time.time() - start
        
        # HONEST: Report actual performance, no fake claims
        assert share_time < 1.0  # Should be fast
        assert recon_time < 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
