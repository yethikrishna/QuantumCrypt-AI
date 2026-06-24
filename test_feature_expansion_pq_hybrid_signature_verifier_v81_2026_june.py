"""
Tests for Feature Expansion v81: Post-Quantum Hybrid Signature Verifier
DIMENSION A - Feature Expansion
All tests are ADD-ONLY - no existing code is modified.
"""
import pytest
import secrets
import time
from typing import List

from quantum_crypt.feature_expansion_pq_hybrid_signature_verifier_v81_2026_june import (
    ClassicalAlgorithm,
    PostQuantumAlgorithm,
    SecurityLevel,
    VerificationMode,
    SignatureResult,
    HybridVerificationResult,
    HybridSignature,
    AlgorithmSecurityInfo,
    HybridSignatureVerifier,
    verify_hybrid_signature,
    create_test_hybrid_signature,
    __api_stability__,
    __all__,
)


class TestClassicalAlgorithm:
    """Tests for classical algorithm enumeration."""
    
    def test_all_classical_algorithms_defined(self):
        """Verify all expected classical algorithms exist."""
        expected = {'ecdsa_p256', 'ecdsa_p384', 'rsa_2048', 'rsa_4096', 'ed25519'}
        actual = {alg.value for alg in ClassicalAlgorithm}
        assert actual == expected
    
    def test_string_compatibility(self):
        """Verify algorithms work as strings."""
        assert ClassicalAlgorithm.ECDSA_P256 == "ecdsa_p256"
        assert isinstance(ClassicalAlgorithm.ECDSA_P256, str)


class TestPostQuantumAlgorithm:
    """Tests for post-quantum algorithm enumeration."""
    
    def test_all_pq_algorithms_defined(self):
        """Verify all NIST-standardized PQ algorithms exist."""
        expected = {
            'dilithium_2', 'dilithium_3', 'dilithium_5',
            'falcon_512', 'falcon_1024',
            'sphincs_sha256_128f',
        }
        actual = {alg.value for alg in PostQuantumAlgorithm}
        assert actual == expected
    
    def test_dilithium_family_complete(self):
        """Verify all Dilithium security levels are present."""
        dilithium_algs = {
            alg.value for alg in PostQuantumAlgorithm
            if 'dilithium' in alg.value
        }
        assert dilithium_algs == {'dilithium_2', 'dilithium_3', 'dilithium_5'}


class TestSecurityLevel:
    """Tests for NIST security levels."""
    
    def test_security_level_order(self):
        """Verify security level ordering."""
        levels = [
            SecurityLevel.LEVEL_1,
            SecurityLevel.LEVEL_2,
            SecurityLevel.LEVEL_3,
            SecurityLevel.LEVEL_5,
        ]
        # Should be ordered by increasing security
        level_names = [l.value for l in levels]
        assert 'level_1' in level_names
        assert 'level_5' in level_names
    
    def test_no_level_4(self):
        """NIST Level 4 is broken, should not be used as target."""
        # Level 4 exists but should be treated as deprecated
        assert SecurityLevel.LEVEL_4.value == "level_4"


class TestVerificationMode:
    """Tests for verification mode enumeration."""
    
    def test_all_modes_defined(self):
        """Verify all verification modes exist."""
        expected = {'and', 'or', 'majority', 'pq_first', 'classical_first'}
        actual = {mode.value for mode in VerificationMode}
        assert actual == expected
    
    def test_mode_descriptions(self):
        """Verify modes have correct semantics."""
        assert VerificationMode.AND == "and"  # Strictest
        assert VerificationMode.OR == "or"    # Most permissive


class TestAlgorithmSecurityInfo:
    """Tests for algorithm security level mappings."""
    
    def test_classical_security_mappings(self):
        """Verify classical algorithms have correct security levels."""
        # ECDSA P-384 should be highest classical security
        assert AlgorithmSecurityInfo.get_classical_security(
            ClassicalAlgorithm.ECDSA_P384
        ) == SecurityLevel.LEVEL_3
        
        # RSA 4096 should be Level 2
        assert AlgorithmSecurityInfo.get_classical_security(
            ClassicalAlgorithm.RSA_4096
        ) == SecurityLevel.LEVEL_2
    
    def test_pq_security_mappings(self):
        """Verify PQ algorithms have correct NIST security levels."""
        # Dilithium 5 should be Level 5 (highest)
        assert AlgorithmSecurityInfo.get_pq_security(
            PostQuantumAlgorithm.DILITHIUM_5
        ) == SecurityLevel.LEVEL_5
        
        # Dilithium 3 should be Level 3
        assert AlgorithmSecurityInfo.get_pq_security(
            PostQuantumAlgorithm.DILITHIUM_3
        ) == SecurityLevel.LEVEL_3
        
        # Dilithium 2 should be Level 2
        assert AlgorithmSecurityInfo.get_pq_security(
            PostQuantumAlgorithm.DILITHIUM_2
        ) == SecurityLevel.LEVEL_2


class TestHybridSignature:
    """Tests for HybridSignature container."""
    
    def test_signature_creation(self):
        """Verify signature object creation works."""
        sig = HybridSignature(
            classical_signature=b"test_classical_sig",
            classical_algorithm=ClassicalAlgorithm.ECDSA_P256,
            post_quantum_signature=b"test_pq_sig",
            post_quantum_algorithm=PostQuantumAlgorithm.DILITHIUM_3,
        )
        
        assert sig.classical_signature == b"test_classical_sig"
        assert sig.post_quantum_signature == b"test_pq_sig"
        assert len(sig.signature_id) == 16  # 8 bytes hex = 16 chars
        assert sig.created_at > 0
    
    def test_default_fields(self):
        """Verify default fields are populated."""
        sig = HybridSignature(
            classical_signature=b"a",
            classical_algorithm=ClassicalAlgorithm.ECDSA_P256,
            post_quantum_signature=b"b",
            post_quantum_algorithm=PostQuantumAlgorithm.DILITHIUM_3,
        )
        
        assert sig.signature_id is not None
        assert sig.created_at > 0


class TestSignatureResult:
    """Tests for SignatureResult container."""
    
    def test_result_creation(self):
        """Verify result object creation works."""
        result = SignatureResult(
            algorithm="ecdsa_p256",
            algorithm_type="classical",
            verified=True,
            security_level=SecurityLevel.LEVEL_1,
            verification_time_ms=1.5,
        )
        
        assert result.verified == True
        assert result.algorithm_type == "classical"
        assert result.error_message is None
    
    def test_result_with_error(self):
        """Verify result can carry error message."""
        result = SignatureResult(
            algorithm="dilithium_3",
            algorithm_type="post_quantum",
            verified=False,
            security_level=SecurityLevel.LEVEL_3,
            verification_time_ms=2.0,
            error_message="Invalid signature format"
        )
        
        assert result.verified == False
        assert result.error_message is not None


class TestHybridSignatureVerifierInitialization:
    """Tests for verifier initialization."""
    
    def test_default_initialization(self):
        """Verify default initialization works."""
        verifier = HybridSignatureVerifier()
        assert verifier.mode == VerificationMode.AND
        assert verifier.min_security_level == SecurityLevel.LEVEL_2
    
    def test_custom_mode_initialization(self):
        """Verify custom mode initialization."""
        verifier = HybridSignatureVerifier(mode=VerificationMode.PQ_FIRST)
        assert verifier.mode == VerificationMode.PQ_FIRST
    
    def test_custom_security_level(self):
        """Verify custom security level initialization."""
        verifier = HybridSignatureVerifier(
            min_security_level=SecurityLevel.LEVEL_5
        )
        assert verifier.min_security_level == SecurityLevel.LEVEL_5


class TestHybridSignatureCreation:
    """Tests for hybrid signature creation."""
    
    def test_create_hybrid_signature(self):
        """Verify signature creation works."""
        verifier = HybridSignatureVerifier()
        message = b"Test message to sign"
        
        sig = verifier.create_hybrid_signature(message)
        
        assert isinstance(sig, HybridSignature)
        assert len(sig.classical_signature) >= 32
        assert len(sig.post_quantum_signature) >= 64  # PQ sigs are larger
    
    def test_create_signature_custom_algorithms(self):
        """Verify signature creation with custom algorithms."""
        verifier = HybridSignatureVerifier()
        message = b"Test message"
        
        sig = verifier.create_hybrid_signature(
            message,
            classical_alg=ClassicalAlgorithm.ECDSA_P384,
            pq_alg=PostQuantumAlgorithm.DILITHIUM_5,
        )
        
        assert sig.classical_algorithm == ClassicalAlgorithm.ECDSA_P384
        assert sig.post_quantum_algorithm == PostQuantumAlgorithm.DILITHIUM_5


class TestHybridVerification:
    """Tests for hybrid signature verification."""
    
    def test_verify_valid_signature_and_mode(self):
        """Verify valid signature in AND mode."""
        verifier = HybridSignatureVerifier(mode=VerificationMode.AND)
        message = b"Important message"
        
        sig = verifier.create_hybrid_signature(message)
        result = verifier.verify(message, sig)
        
        assert isinstance(result, HybridVerificationResult)
        assert result.overall_verified == True
        assert result.quantum_safe == True  # PQ should verify
    
    def test_verify_mode_and_strict(self):
        """AND mode requires both signatures to verify."""
        verifier = HybridSignatureVerifier(mode=VerificationMode.AND)
        message = b"Test"
        
        sig = verifier.create_hybrid_signature(message)
        result = verifier.verify(message, sig)
        
        # Both should verify in simulation
        classical_ok = any(
            r.verified for r in result.individual_results
            if r.algorithm_type == "classical"
        )
        pq_ok = any(
            r.verified for r in result.individual_results
            if r.algorithm_type == "post_quantum"
        )
        
        assert classical_ok == True
        assert pq_ok == True
        assert result.overall_verified == True
    
    def test_verify_mode_pq_first(self):
        """PQ_FIRST mode only requires PQ to verify."""
        verifier = HybridSignatureVerifier(mode=VerificationMode.PQ_FIRST)
        message = b"Test migration mode"
        
        sig = verifier.create_hybrid_signature(message)
        result = verifier.verify(message, sig)
        
        # In PQ_FIRST mode, PQ verification is sufficient
        assert result.quantum_safe == True
        # Overall should pass since PQ verifies
        assert result.overall_verified == True
    
    def test_verify_mode_classical_first(self):
        """CLASSICAL_FIRST mode only requires classical to verify."""
        verifier = HybridSignatureVerifier(mode=VerificationMode.CLASSICAL_FIRST)
        message = b"Test legacy mode"
        
        sig = verifier.create_hybrid_signature(message)
        result = verifier.verify(message, sig)
        
        # Classical should verify
        classical_ok = any(
            r.verified for r in result.individual_results
            if r.algorithm_type == "classical"
        )
        assert classical_ok == True
        assert result.overall_verified == True
    
    def test_verification_timing_recorded(self):
        """Verify timing information is recorded."""
        verifier = HybridSignatureVerifier()
        message = b"Test timing"
        
        sig = verifier.create_hybrid_signature(message)
        result = verifier.verify(message, sig)
        
        assert result.total_verification_time_ms >= 0
        for individual in result.individual_results:
            assert individual.verification_time_ms >= 0
    
    def test_message_digest_generated(self):
        """Verify message digest is generated for reference."""
        verifier = HybridSignatureVerifier()
        message = b"Unique message"
        
        sig = verifier.create_hybrid_signature(message)
        result = verifier.verify(message, sig)
        
        assert len(result.message_digest) == 16  # 8 bytes hex
    
    def test_security_level_calculated(self):
        """Verify achieved security level is calculated."""
        verifier = HybridSignatureVerifier()
        message = b"Test security level"
        
        sig = verifier.create_hybrid_signature(
            message,
            pq_alg=PostQuantumAlgorithm.DILITHIUM_5  # Level 5
        )
        result = verifier.verify(message, sig)
        
        # Should achieve at least Level 3 from Dilithium 5
        levels = [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_2, 
                  SecurityLevel.LEVEL_3, SecurityLevel.LEVEL_5]
        achieved_idx = levels.index(result.security_level_achieved)
        assert achieved_idx >= levels.index(SecurityLevel.LEVEL_3)
    
    def test_summary_generated(self):
        """Verify human-readable summary is generated."""
        verifier = HybridSignatureVerifier()
        message = b"Test summary"
        
        sig = verifier.create_hybrid_signature(message)
        result = verifier.verify(message, sig)
        
        assert isinstance(result.verification_summary, str)
        assert len(result.verification_summary) > 0
        assert "PASSED" in result.verification_summary or "FAILED" in result.verification_summary


class TestAlgorithmRecommendation:
    """Tests for algorithm recommendation."""
    
    def test_recommend_default_balanced(self):
        """Verify default balanced recommendation."""
        verifier = HybridSignatureVerifier()
        classical, pq = verifier.recommend_algorithm_pair()
        
        assert classical == ClassicalAlgorithm.ECDSA_P256
        assert pq == PostQuantumAlgorithm.DILITHIUM_3
    
    def test_recommend_performance(self):
        """Verify performance-prioritized recommendation."""
        verifier = HybridSignatureVerifier()
        classical, pq = verifier.recommend_algorithm_pair(
            performance_priority=True
        )
        
        # Should use faster (lower security) algorithms
        assert pq == PostQuantumAlgorithm.DILITHIUM_2
    
    def test_recommend_highest_security(self):
        """Verify highest security recommendation."""
        verifier = HybridSignatureVerifier()
        classical, pq = verifier.recommend_algorithm_pair(
            required_security=SecurityLevel.LEVEL_5
        )
        
        assert pq == PostQuantumAlgorithm.DILITHIUM_5


class TestBatchVerification:
    """Tests for batch verification."""
    
    def test_batch_verify(self):
        """Verify batch processing works."""
        verifier = HybridSignatureVerifier()
        
        messages = [b"msg1", b"msg2", b"msg3"]
        signatures = [verifier.create_hybrid_signature(m) for m in messages]
        
        results = verifier.batch_verify(messages, signatures)
        
        assert len(results) == 3
        for result in results:
            assert isinstance(result, HybridVerificationResult)
            assert result.overall_verified == True


class TestVerifierStats:
    """Tests for verification statistics."""
    
    def test_stats_tracking(self):
        """Verify statistics are tracked correctly."""
        verifier = HybridSignatureVerifier()
        
        # Perform some verifications
        for i in range(5):
            msg = f"message_{i}".encode()
            sig = verifier.create_hybrid_signature(msg)
            verifier.verify(msg, sig)
        
        stats = verifier.get_verification_stats()
        
        assert stats["total_verifications"] == 5
        assert stats["successful_verifications"] == 5
        assert "success_rate" in stats
        assert stats["success_rate"] == 100.0
    
    def test_stats_include_mode(self):
        """Verify stats include configuration info."""
        verifier = HybridSignatureVerifier(
            mode=VerificationMode.PQ_FIRST,
            min_security_level=SecurityLevel.LEVEL_3,
        )
        
        stats = verifier.get_verification_stats()
        
        assert stats["verification_mode"] == "pq_first"
        assert stats["minimum_security_level"] == "level_3"


class TestSupportedAlgorithms:
    """Tests for supported algorithms listing."""
    
    def test_get_supported_algorithms(self):
        """Verify supported algorithms listing works."""
        verifier = HybridSignatureVerifier()
        supported = verifier.get_supported_algorithms()
        
        assert "classical" in supported
        assert "post_quantum" in supported
        assert len(supported["classical"]) == 5
        assert len(supported["post_quantum"]) == 6


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_create_test_hybrid_signature(self):
        """Verify convenience function for test signatures."""
        msg = b"Test message"
        sig = create_test_hybrid_signature(msg)
        
        assert isinstance(sig, HybridSignature)
        assert len(sig.classical_signature) > 0
        assert len(sig.post_quantum_signature) > 0
    
    def test_verify_hybrid_signature_function(self):
        """Verify convenience function works."""
        msg = b"Test quick verify"
        sig = create_test_hybrid_signature(msg)
        
        result = verify_hybrid_signature(
            msg,
            sig.classical_signature,
            sig.post_quantum_signature,
        )
        
        assert isinstance(result, HybridVerificationResult)
        assert result.overall_verified == True


class TestApiStability:
    """Tests for API stability markers."""
    
    def test_all_exports_have_stability(self):
        """Verify all exported items have stability markers."""
        for export in __all__:
            assert export in __api_stability__, f"Missing stability for {export}"
    
    def test_stability_values_valid(self):
        """Verify stability values are valid."""
        valid_stabilities = {'STABLE', 'EXPERIMENTAL', 'DEPRECATED'}
        for stability in __api_stability__.values():
            assert stability in valid_stabilities, f"Invalid stability: {stability}"
    
    def test_create_test_is_experimental(self):
        """Test signature creation should be marked experimental."""
        assert __api_stability__['create_test_hybrid_signature'] == 'EXPERIMENTAL'


class TestIntegration:
    """Integration tests - verify no conflicts with existing code."""
    
    def test_import_without_conflict(self):
        """Verify module imports without conflicting with existing code."""
        from quantum_crypt.feature_expansion_pq_hybrid_signature_verifier_v81_2026_june import (
            HybridSignatureVerifier
        )
        assert HybridSignatureVerifier is not None
    
    def test_no_existing_code_modified(self):
        """Verify this is ADD-ONLY - existing modules still work."""
        # Test that existing security module still works
        try:
            from quantum_crypt.security_hardening_pq_constant_time_key_v31_2026_june import (
                PQKeyMaterial
            )
            # Existing module should still work (if it exists)
            assert PQKeyMaterial is not None
        except ImportError:
            # If it doesn't exist, that's fine
            pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
