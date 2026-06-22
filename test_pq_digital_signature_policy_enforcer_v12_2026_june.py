"""
Test suite for Post-Quantum Digital Signature Policy Enforcer v12
DIMENSION A - FEATURE EXPANSION
QuantumCrypt-AI

Comprehensive tests covering:
- Key registration & management
- Signing & verification operations
- Policy enforcement & algorithm blocking
- Signature caching
- Hybrid classical + PQ signing
- Compliance reporting
- Thread safety
- Edge cases & boundary conditions
"""

import pytest
import time
import threading
from quantum_crypt.pq_digital_signature_policy_enforcer_v12_2026_june import (
    PQSignaturePolicyEnforcer,
    SignatureKey,
    SignatureResult,
    VerificationPolicy,
    PQSignatureAlgorithm,
    NISTSecurityLevel,
    SignaturePolicyAction,
    SignatureCache,
    HybridSigner,
    ALGORITHM_LEVELS
)


class TestSignatureCache:
    """Tests for SignatureCache implementation."""
    
    def test_cache_put_and_get(self):
        cache = SignatureCache(max_size=100, ttl_seconds=3600)
        msg = b"test message"
        sig = b"test signature"
        algo = PQSignatureAlgorithm.DILITHIUM_3
        
        cache.put(msg, sig, algo, True)
        result = cache.get(msg, sig, algo)
        assert result == True
    
    def test_cache_miss(self):
        cache = SignatureCache(max_size=100)
        result = cache.get(b"not_cached", b"sig", PQSignatureAlgorithm.FALCON_512)
        assert result is None
    
    def test_cache_eviction(self):
        cache = SignatureCache(max_size=10, ttl_seconds=3600)
        for i in range(20):
            cache.put(f"msg_{i}".encode(), f"sig_{i}".encode(), PQSignatureAlgorithm.DILITHIUM_2, True)
        # Should have evicted older entries
        assert cache.get(b"msg_0", b"sig_0", PQSignatureAlgorithm.DILITHIUM_2) is None
        assert cache.get(b"msg_19", b"sig_19", PQSignatureAlgorithm.DILITHIUM_2) == True
    
    def test_cache_clear(self):
        cache = SignatureCache(max_size=100)
        cache.put(b"test", b"sig", PQSignatureAlgorithm.DILITHIUM_5, True)
        cache.clear()
        assert cache.get(b"test", b"sig", PQSignatureAlgorithm.DILITHIUM_5) is None


class TestHybridSigner:
    """Tests for HybridSigner."""
    
    def test_hybrid_sign_and_verify(self):
        signer = HybridSigner()
        msg = b"Hello, Quantum World!"
        
        pq_key = SignatureKey(
            key_id="test_pq",
            algorithm=PQSignatureAlgorithm.DILITHIUM_3,
            nist_level=NISTSecurityLevel.LEVEL_3,
            public_key=b"test_pq_public",
            private_key=b"test_pq_private"
        )
        classical_key = SignatureKey(
            key_id="test_classical",
            algorithm=PQSignatureAlgorithm.ED25519,
            nist_level=NISTSecurityLevel.LEVEL_3,
            public_key=b"test_classical_public",
            private_key=b"test_classical_private"
        )
        
        pq_sig, classical_sig = signer.sign_hybrid(msg, pq_key, classical_key)
        pq_valid, classical_valid = signer.verify_hybrid(msg, pq_sig, classical_sig, pq_key, classical_key)
        
        assert pq_valid == True
        assert classical_valid == True
    
    def test_verify_tampered_message(self):
        signer = HybridSigner()
        msg = b"Original message"
        tampered = b"Tampered message"
        
        key = SignatureKey(
            key_id="test",
            algorithm=PQSignatureAlgorithm.DILITHIUM_2,
            nist_level=NISTSecurityLevel.LEVEL_2,
            public_key=b"test_public",
            private_key=b"test_private"
        )
        
        sig, _ = signer.sign_hybrid(msg, key, key)
        valid = signer._simulate_pq_verify(tampered, sig, key)
        assert valid == False


class TestSignatureKey:
    """Tests for SignatureKey."""
    
    def test_key_validity(self):
        key = SignatureKey(
            key_id="key1",
            algorithm=PQSignatureAlgorithm.DILITHIUM_5,
            nist_level=NISTSecurityLevel.LEVEL_5,
            public_key=b"pubkey"
        )
        assert key.is_valid() == True
    
    def test_revoked_key_invalid(self):
        key = SignatureKey(
            key_id="key2",
            algorithm=PQSignatureAlgorithm.FALCON_512,
            nist_level=NISTSecurityLevel.LEVEL_1,
            public_key=b"pubkey",
            is_revoked=True
        )
        assert key.is_valid() == False
    
    def test_expired_key_invalid(self):
        key = SignatureKey(
            key_id="key3",
            algorithm=PQSignatureAlgorithm.SPHINCS_SHA2_256F,
            nist_level=NISTSecurityLevel.LEVEL_5,
            public_key=b"pubkey",
            expires_at=time.time() - 1000
        )
        assert key.is_valid() == False
    
    def test_key_needs_rotation_by_count(self):
        key = SignatureKey(
            key_id="key4",
            algorithm=PQSignatureAlgorithm.DILITHIUM_3,
            nist_level=NISTSecurityLevel.LEVEL_3,
            public_key=b"pubkey",
            signatures_signed=2000000  # Over 1M threshold
        )
        assert key.needs_rotation() == True


class TestPQSignaturePolicyEnforcer:
    """Main tests for PQSignaturePolicyEnforcer."""
    
    @pytest.fixture
    def enforcer(self):
        return PQSignaturePolicyEnforcer(default_policy_id="default")
    
    @pytest.fixture
    def test_key(self, enforcer):
        key = SignatureKey(
            key_id="test_dilithium3",
            algorithm=PQSignatureAlgorithm.DILITHIUM_3,
            nist_level=NISTSecurityLevel.LEVEL_3,
            public_key=b"test_dilithium3_pub",
            private_key=b"test_dilithium3_priv"
        )
        enforcer.register_key(key)
        return key
    
    def test_register_key(self, enforcer):
        key = SignatureKey(
            key_id="new_key",
            algorithm=PQSignatureAlgorithm.FALCON_1024,
            nist_level=NISTSecurityLevel.LEVEL_5,
            public_key=b"pubkey"
        )
        enforcer.register_key(key)
        assert "new_key" in enforcer.keys
    
    def test_revoke_key(self, enforcer, test_key):
        result = enforcer.revoke_key("test_dilithium3")
        assert result == True
        assert enforcer.keys["test_dilithium3"].is_revoked == True
    
    def test_sign_success(self, enforcer, test_key):
        msg = b"Message to sign"
        result = enforcer.sign(msg, "test_dilithium3")
        assert result.success == True
        assert result.signature is not None
        assert result.algorithm == PQSignatureAlgorithm.DILITHIUM_3
    
    def test_sign_unknown_key(self, enforcer):
        result = enforcer.sign(b"test", "nonexistent_key")
        assert result.success == False
        assert "not found" in result.error_message
    
    def test_sign_revoked_key(self, enforcer, test_key):
        enforcer.revoke_key("test_dilithium3")
        result = enforcer.sign(b"test", "test_dilithium3")
        assert result.success == False
        assert "revoked" in result.error_message
    
    def test_verify_valid_signature(self, enforcer, test_key):
        msg = b"Test verification"
        sign_result = enforcer.sign(msg, "test_dilithium3")
        verify_result = enforcer.verify(msg, sign_result.signature, "test_dilithium3")
        assert verify_result.success == True
        assert verify_result.verification_result == True
    
    def test_strict_policy_blocks_classical(self, enforcer):
        classical_key = SignatureKey(
            key_id="classical_rsa",
            algorithm=PQSignatureAlgorithm.RSA_4096_SHA256,
            nist_level=NISTSecurityLevel.LEVEL_1,
            public_key=b"rsa_pub",
            private_key=b"rsa_priv"
        )
        enforcer.register_key(classical_key)
        
        # Strict policy blocks classical algorithms
        result = enforcer.sign(b"test", "classical_rsa", policy_id="strict")
        assert result.success == False
        assert result.policy_action == SignaturePolicyAction.BLOCK
    
    def test_standard_policy_warns_classical(self, enforcer):
        classical_key = SignatureKey(
            key_id="classical_ecdsa",
            algorithm=PQSignatureAlgorithm.ECDSA_P384_SHA384,
            nist_level=NISTSecurityLevel.LEVEL_3,
            public_key=b"ecdsa_pub",
            private_key=b"ecdsa_priv"
        )
        enforcer.register_key(classical_key)
        
        result = enforcer.sign(b"test", "classical_ecdsa", policy_id="standard")
        assert result.success == True
        assert result.policy_action == SignaturePolicyAction.UPGRADE
        assert len(result.policy_warnings) > 0
    
    def test_verification_caching(self, enforcer, test_key):
        msg = b"Cached verification test"
        sign_result = enforcer.sign(msg, "test_dilithium3")
        
        # First verify - cache miss
        v1 = enforcer.verify(msg, sign_result.signature, "test_dilithium3")
        assert enforcer.stats['cache_misses'] == 1
        
        # Second verify - cache hit
        v2 = enforcer.verify(msg, sign_result.signature, "test_dilithium3")
        assert enforcer.stats['cache_hits'] == 1
        assert v2.verification_result == True
    
    def test_compliance_report(self, enforcer, test_key):
        report = enforcer.get_compliance_report()
        assert 'statistics' in report
        assert 'keys' in report
        assert 'policies' in report
        assert report['keys']['total'] == 1
        assert report['keys']['active'] == 1
    
    def test_concurrent_signing(self, enforcer, test_key):
        """Test thread safety with concurrent signing operations."""
        
        def sign_messages(count):
            for i in range(count):
                msg = f"Concurrent message {i}".encode()
                enforcer.sign(msg, "test_dilithium3")
        
        threads = []
        for t in range(5):
            thread = threading.Thread(target=sign_messages, args=(20,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=10)
        
        assert enforcer.stats['signatures_created'] == 100


class TestVerificationPolicy:
    """Tests for VerificationPolicy."""
    
    def test_allows_algorithm_default(self):
        policy = VerificationPolicy(policy_id="test")
        assert policy.allows_algorithm(PQSignatureAlgorithm.DILITHIUM_3) == True
    
    def test_blocks_blocked_algorithm(self):
        policy = VerificationPolicy(
            policy_id="test",
            blocked_algorithms={PQSignatureAlgorithm.RSA_4096_SHA256}
        )
        assert policy.allows_algorithm(PQSignatureAlgorithm.RSA_4096_SHA256) == False
    
    def test_restricts_to_allowed_algorithms(self):
        policy = VerificationPolicy(
            policy_id="test",
            allowed_algorithms={PQSignatureAlgorithm.DILITHIUM_5, PQSignatureAlgorithm.FALCON_1024}
        )
        assert policy.allows_algorithm(PQSignatureAlgorithm.DILITHIUM_5) == True
        assert policy.allows_algorithm(PQSignatureAlgorithm.DILITHIUM_2) == False


class TestAlgorithmLevels:
    """Tests for ALGORITHM_LEVELS mapping."""
    
    def test_all_algorithms_have_levels(self):
        for algo in PQSignatureAlgorithm:
            assert algo in ALGORITHM_LEVELS
    
    def test_dilithium5_is_level5(self):
        assert ALGORITHM_LEVELS[PQSignatureAlgorithm.DILITHIUM_5] == NISTSecurityLevel.LEVEL_5
    
    def test_falcon512_is_level1(self):
        assert ALGORITHM_LEVELS[PQSignatureAlgorithm.FALCON_512] == NISTSecurityLevel.LEVEL_1


class TestEdgeCases:
    """Edge case tests."""
    
    @pytest.fixture
    def enforcer(self):
        return PQSignaturePolicyEnforcer(default_policy_id="default")
    
    @pytest.fixture
    def test_key(self, enforcer):
        key = SignatureKey(
            key_id="test_dilithium3",
            algorithm=PQSignatureAlgorithm.DILITHIUM_3,
            nist_level=NISTSecurityLevel.LEVEL_3,
            public_key=b"test_dilithium3_pub",
            private_key=b"test_dilithium3_priv"
        )
        enforcer.register_key(key)
        return key
    
    def test_empty_message_sign(self, enforcer, test_key):
        result = enforcer.sign(b"", "test_dilithium3")
        assert result.success == True
        assert result.signature is not None
    
    def test_large_message_sign(self, enforcer, test_key):
        large_msg = b"X" * 100000  # 100KB message (reduced for speed)
        result = enforcer.sign(large_msg, "test_dilithium3")
        assert result.success == True
    
    def test_key_without_private_key(self, enforcer):
        pub_only_key = SignatureKey(
            key_id="pub_only",
            algorithm=PQSignatureAlgorithm.DILITHIUM_2,
            nist_level=NISTSecurityLevel.LEVEL_2,
            public_key=b"only_public"
            # No private key
        )
        enforcer.register_key(pub_only_key)
        result = enforcer.sign(b"test", "pub_only")
        # Should still work with our simulation
        assert result.success == True
    
    def test_shutdown(self, enforcer):
        enforcer.shutdown()
        # Should not raise exceptions


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
