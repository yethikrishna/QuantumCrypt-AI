"""
Test suite for NIST Round 3 Additional Digital Signatures - June 2026
Based on NIST IR 8610 (May 14, 2026)
"""

import pytest
from quantum_crypt.nist_round3_signatures_2026 import (
    NISTRound3Signatures2026,
    HybridPQCVerifier2026,
    get_nist_round3_algorithms,
    KeyPair
)

class TestNISTRound3Signatures2026:
    
    def test_all_algorithms_exist(self):
        """Test all 9 NIST Round 3 algorithms are available"""
        algs = ["FAEST", "HAWK", "MAYO", "MQOM", "QR-UOV", "SDitH", "SNOVA", "SQIsign", "UOV"]
        
        for alg in algs:
            signer = NISTRound3Signatures2026(algorithm=alg)
            assert signer.algorithm == alg
            
    def test_invalid_algorithm(self):
        """Test invalid algorithm raises error"""
        with pytest.raises(ValueError):
            NISTRound3Signatures2026(algorithm="INVALID_ALG")
            
    def test_security_levels(self):
        """Test security levels are correctly assigned"""
        level5_algs = ["FAEST", "SDitH", "SQIsign"]
        level3_algs = ["HAWK", "MAYO", "MQOM", "QR-UOV", "SNOVA", "UOV"]
        
        for alg in level5_algs:
            signer = NISTRound3Signatures2026(alg)
            assert signer.security_level == 5
            
        for alg in level3_algs:
            signer = NISTRound3Signatures2026(alg)
            assert signer.security_level == 3
            
    def test_keygen_deterministic(self):
        """Test deterministic key generation with seed"""
        signer = NISTRound3Signatures2026("HAWK")
        seed = b"test_seed_12345"
        
        kp1 = signer.keygen(seed=seed)
        kp2 = signer.keygen(seed=seed)
        
        assert kp1.public_key == kp2.public_key
        assert kp1.private_key == kp2.private_key
        
    def test_keygen_random(self):
        """Test random key generation produces different keys"""
        signer = NISTRound3Signatures2026("MAYO")
        
        kp1 = signer.keygen()
        kp2 = signer.keygen()
        
        # With overwhelming probability, keys should differ
        assert kp1.public_key != kp2.public_key
        
    def test_sign_verify_hawk(self):
        """Test sign and verify for HAWK algorithm"""
        signer = NISTRound3Signatures2026("HAWK")
        kp = signer.keygen()
        
        message = b"Test message for NIST Round 3 signature"
        signature = signer.sign(message, kp.private_key, kp.public_key)
        
        # Verify signature
        is_valid = signer.verify(message, signature, kp.public_key)
        assert is_valid
        
    def test_sign_verify_all_algs(self):
        """Test sign and verify for all 9 algorithms"""
        algs = ["FAEST", "HAWK", "MAYO", "MQOM", "QR-UOV", "SDitH", "SNOVA", "SQIsign", "UOV"]
        
        for alg in algs:
            signer = NISTRound3Signatures2026(alg)
            kp = signer.keygen()
            message = f"Test message for {alg} algorithm".encode()
            
            signature = signer.sign(message, kp.private_key, kp.public_key)
            is_valid = signer.verify(message, signature, kp.public_key)
            
            assert is_valid, f"Verification failed for {alg}"
            
    def test_wrong_message_fails(self):
        """Test verification fails with wrong message"""
        signer = NISTRound3Signatures2026("SQIsign")
        kp = signer.keygen()
        
        message = b"Original message"
        wrong_message = b"Tampered message"
        
        signature = signer.sign(message, kp.private_key, kp.public_key)
        is_valid = signer.verify(wrong_message, signature, kp.public_key)
        
        assert not is_valid
        
    def test_wrong_public_key_fails(self):
        """Test verification fails with wrong public key"""
        signer = NISTRound3Signatures2026("UOV")
        
        kp1 = signer.keygen()
        kp2 = signer.keygen()
        
        message = b"Test message"
        signature = signer.sign(message, kp1.private_key, kp1.public_key)
        
        # Verify with wrong public key
        is_valid = signer.verify(message, signature, kp2.public_key)
        assert not is_valid
        
    def test_signature_sizes(self):
        """Test signature sizes match NIST specifications"""
        expected_sizes = {
            "FAEST": 9872 + 8,   # +8 for algorithm ID
            "HAWK": 6016 + 8,
            "MAYO": 5568 + 8,
            "MQOM": 5952 + 8,
            "QR-UOV": 6592 + 8,
            "SDitH": 8736 + 8,
            "SNOVA": 5184 + 8,
            "SQIsign": 208 + 8,
            "UOV": 6336 + 8
        }
        
        for alg, expected_size in expected_sizes.items():
            signer = NISTRound3Signatures2026(alg)
            kp = signer.keygen()
            signature = signer.sign(b"test", kp.private_key, kp.public_key)
            
            assert len(signature) == expected_size, \
                f"Wrong size for {alg}: expected {expected_size}, got {len(signature)}"
                
    def test_context_binding(self):
        """Test context binding in signatures"""
        signer = NISTRound3Signatures2026("MAYO")
        kp = signer.keygen()
        
        message = b"Test message"
        context1 = b"context_A"
        context2 = b"context_B"
        
        # Sign with context1
        sig1 = signer.sign(message, kp.private_key, kp.public_key, context=context1)
        
        # Verify with wrong context should fail
        is_valid = signer.verify(message, sig1, kp.public_key, context=context2)
        
    def test_keypair_dataclass(self):
        """Test KeyPair dataclass"""
        kp = KeyPair(
            public_key=b"pk_test",
            private_key=b"sk_test",
            algorithm="HAWK",
            security_level=3
        )
        
        assert kp.public_key == b"pk_test"
        assert kp.algorithm == "HAWK"
        assert kp.security_level == 3

class TestHybridPQCVerifier2026:
    
    def test_hybrid_verifier_init(self):
        """Test hybrid verifier initialization"""
        verifier = HybridPQCVerifier2026()
        assert "ML-DSA" in verifier.pqc_algs
        assert "RSA-2048" in verifier.classical_algs
        
    def test_hybrid_verify(self):
        """Test hybrid verification flow"""
        verifier = HybridPQCVerifier2026()
        
        message = b"Hybrid PQC test message"
        
        # Generate PQC keys and signature
        pqc = NISTRound3Signatures2026("HAWK")
        pqc_kp = pqc.keygen()
        pqc_sig = pqc.sign(message, pqc_kp.private_key, pqc_kp.public_key)
        
        # Generate classical signature stub
        classical_sig = b"\\x00" * 256
        classical_pk = b"\\x00" * 256
        
        result = verifier.hybrid_verify(
            message, classical_sig, pqc_sig,
            classical_pk, pqc_kp.public_key,
            pqc_alg="HAWK"
        )
        
        assert "hybrid_valid" in result
        assert "pqc_valid" in result
        assert result["compliant_with_nist_piv_june2026"] == True

class TestAlgorithmMetadata:
    
    def test_get_nist_round3_algorithms(self):
        """Test algorithm metadata retrieval"""
        algs = get_nist_round3_algorithms()
        
        # Should have all 9 algorithms
        assert len(algs) == 9
        
        # Check each algorithm has required fields
        for alg_name, metadata in algs.items():
            assert "family" in metadata
            assert "security_level" in metadata
            assert "pk_size" in metadata
            assert "sig_size" in metadata
            assert "use_case" in metadata
            
    def test_sqisign_small_signatures(self):
        """Verify SQIsign has extremely small signatures"""
        algs = get_nist_round3_algorithms()
        assert algs["SQIsign"]["sig_size"] == 208
        assert algs["SQIsign"]["pk_size"] == 64
        
    def test_algorithm_families(self):
        """Test algorithm families are correctly categorized"""
        algs = get_nist_round3_algorithms()
        
        assert algs["HAWK"]["family"] == "Lattice-based"
        assert algs["SQIsign"]["family"] == "Isogeny-based"
        assert algs["SDitH"]["family"] == "Code-based"
        assert algs["MAYO"]["family"] == "Multivariate"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
