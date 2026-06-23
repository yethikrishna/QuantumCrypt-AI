"""
Test suite for Post-Quantum Hybrid Encryption Orchestrator v20
Real working tests - no mocks, no stubs.
Tests all functionality with actual cryptographic operations.
"""
import pytest
import time
from quantum_crypt.post_quantum_hybrid_encryption_orchestrator_v20_2026_june import (
    PostQuantumHybridEncryptionOrchestrator,
    SecurityLevel,
    ClassicalAlgorithm,
    PostQuantumAlgorithm,
    CipherSuite,
    SessionState,
    AlgorithmCapabilities,
    get_hybrid_encryption_orchestrator
)


class TestAlgorithmCapabilities:
    """Test AlgorithmCapabilities data class"""
    
    def test_capabilities_creation(self):
        """Test basic capabilities creation"""
        caps = AlgorithmCapabilities(
            supported_pq_algorithms={PostQuantumAlgorithm.CRYSTALS_KYBER_768},
            supported_classical_algorithms={ClassicalAlgorithm.X25519},
            max_security_level=SecurityLevel.LEVEL_3,
            peer_id="test-peer-001"
        )
        assert caps.peer_id == "test-peer-001"
        assert caps.max_security_level == SecurityLevel.LEVEL_3


class TestPostQuantumHybridEncryptionOrchestrator:
    """Main test suite for hybrid encryption orchestrator"""
    
    @pytest.fixture
    def orchestrator(self):
        """Create fresh orchestrator instance"""
        return PostQuantumHybridEncryptionOrchestrator(
            min_security_level=SecurityLevel.LEVEL_1,
            prefer_pq=True
        )
    
    @pytest.fixture
    def full_capabilities(self):
        """Create peer with full algorithm support"""
        return AlgorithmCapabilities(
            supported_pq_algorithms=set(PostQuantumAlgorithm),
            supported_classical_algorithms=set(ClassicalAlgorithm),
            supported_cipher_suites=set(CipherSuite),
            max_security_level=SecurityLevel.LEVEL_5,
            peer_id="peer-full-support"
        )
    
    @pytest.fixture
    def limited_capabilities(self):
        """Create peer with limited algorithm support - includes Level 3 classical"""
        return AlgorithmCapabilities(
            supported_pq_algorithms={
                PostQuantumAlgorithm.CRYSTALS_KYBER_512,
                PostQuantumAlgorithm.CRYSTALS_KYBER_768
            },
            supported_classical_algorithms={
                ClassicalAlgorithm.X25519,
                ClassicalAlgorithm.ECDH_P256,
                ClassicalAlgorithm.X448,  # Level 3 security
                ClassicalAlgorithm.ECDH_P384  # Level 3 security
            },
            supported_cipher_suites={
                CipherSuite.KYBER512_X25519_AES256GCM,
                CipherSuite.KYBER768_X25519_AES256GCM
            },
            max_security_level=SecurityLevel.LEVEL_3,
            peer_id="peer-limited-support"
        )
    
    @pytest.fixture
    def classical_only_capabilities(self):
        """Create classical-only peer (no PQ support)"""
        return AlgorithmCapabilities(
            supported_pq_algorithms=set(),  # No PQ support
            supported_classical_algorithms={ClassicalAlgorithm.X25519},
            supported_cipher_suites={CipherSuite.CLASSICAL_X25519_AES256GCM},
            max_security_level=SecurityLevel.LEVEL_1,
            peer_id="peer-classical-only"
        )
    
    def test_orchestrator_initialization(self, orchestrator):
        """Test orchestrator initialization"""
        assert orchestrator.min_security_level == SecurityLevel.LEVEL_1
        assert orchestrator.prefer_pq is True
        assert len(orchestrator._sessions) == 0
    
    def test_singleton_pattern(self):
        """Test singleton factory function"""
        orch1 = get_hybrid_encryption_orchestrator()
        orch2 = get_hybrid_encryption_orchestrator()
        assert orch1 is orch2
    
    def test_secure_random_generation(self, orchestrator):
        """Test cryptographically secure random generation"""
        rand1 = orchestrator._generate_secure_random(32)
        rand2 = orchestrator._generate_secure_random(32)
        
        assert len(rand1) == 32
        assert len(rand2) == 32
        assert rand1 != rand2  # Extremely unlikely to collide
    
    def test_hkdf_key_derivation(self, orchestrator):
        """Test real HKDF key derivation"""
        ikm = b"test_input_key_material_12345"
        salt = b"test_salt_value"
        
        key1 = orchestrator._hkdf_derive_key(ikm, salt, length=32)
        key2 = orchestrator._hkdf_derive_key(ikm, salt, length=32)
        key3 = orchestrator._hkdf_derive_key(ikm, b"different_salt", length=32)
        
        # Same inputs produce same output
        assert key1 == key2
        # Different salts produce different outputs
        assert key1 != key3
        # Correct length
        assert len(key1) == 32
    
    def test_shared_secret_combiner(self, orchestrator):
        """Test secure secret combining"""
        classical = orchestrator._generate_secure_random(32)
        pq = orchestrator._generate_secure_random(32)
        salt = orchestrator._generate_secure_random(32)
        
        combined1 = orchestrator._combine_shared_secrets(classical, pq, salt)
        combined2 = orchestrator._combine_shared_secrets(classical, pq, salt)
        
        # Same inputs produce same output
        assert combined1 == combined2
        # Output is correct length
        assert len(combined1) == 32
    
    def test_algorithm_negotiation_full_capabilities(self, orchestrator, full_capabilities):
        """Test algorithm negotiation with full capabilities"""
        suite, classical, pq = orchestrator.negotiate_best_algorithm(full_capabilities)
        
        assert suite is not None
        assert classical is not None
        assert pq is not None
        # Should select highest security PQ algorithm
        assert pq in [
            PostQuantumAlgorithm.CRYSTALS_KYBER_1024,
            PostQuantumAlgorithm.CRYSTALS_KYBER_768
        ]
    
    def test_algorithm_negotiation_limited(self, orchestrator, limited_capabilities):
        """Test algorithm negotiation with limited capabilities"""
        suite, classical, pq = orchestrator.negotiate_best_algorithm(limited_capabilities)
        
        assert suite is not None
        assert classical is not None
        assert pq is not None
        # Should be within limited set
        assert pq in [
            PostQuantumAlgorithm.CRYSTALS_KYBER_512,
            PostQuantumAlgorithm.CRYSTALS_KYBER_768
        ]
    
    def test_algorithm_negotiation_classical_fallback(self, orchestrator, classical_only_capabilities):
        """Test classical-only fallback negotiation"""
        suite, classical, pq = orchestrator.negotiate_best_algorithm(classical_only_capabilities)
        
        assert suite is not None
        assert classical is not None
        # No PQ algorithm available
        assert pq is None
    
    def test_session_establishment_full(self, orchestrator, full_capabilities):
        """Test full hybrid session establishment"""
        result = orchestrator.establish_hybrid_session(
            full_capabilities,
            requested_security_level=SecurityLevel.LEVEL_3
        )
        
        assert result.success is True
        assert result.session_id.startswith("pq_session_")
        assert len(result.combined_session_key) == 32
        assert len(result.classical_shared_secret) == 32
        assert len(result.pq_shared_secret) == 32
        assert result.pq_algorithm is not None
        assert result.security_level.value >= SecurityLevel.LEVEL_1.value
        assert result.operation_time_ms > 0
    
    def test_session_establishment_classical_fallback(self, orchestrator, classical_only_capabilities):
        """Test session establishment with classical-only fallback"""
        result = orchestrator.establish_hybrid_session(classical_only_capabilities)
        
        # Should succeed with fallback
        assert result.success is True
        assert result.session_id != ""
        # No PQ secret in classical-only mode
        assert result.pq_shared_secret == b""
        assert result.pq_algorithm is None
    
    def test_session_establishment_pq_enabled_flag(self, orchestrator, full_capabilities):
        """Test PQ enabled metadata flag"""
        result = orchestrator.establish_hybrid_session(full_capabilities)
        
        assert result.success is True
        assert result.metadata["pq_enabled"] is True
    
    def test_session_retrieval(self, orchestrator, full_capabilities):
        """Test session retrieval by ID"""
        result = orchestrator.establish_hybrid_session(full_capabilities)
        session = orchestrator.get_session(result.session_id)
        
        assert session is not None
        assert session.session_id == result.session_id
        assert session.state == SessionState.ESTABLISHED
        
        # Non-existent session
        assert orchestrator.get_session("nonexistent") is None
    
    def test_session_key_rotation(self, orchestrator, full_capabilities):
        """Test key rotation functionality"""
        result = orchestrator.establish_hybrid_session(full_capabilities)
        session = orchestrator.get_session(result.session_id)
        original_key = session.key_material["session_key"]
        
        # Perform rotation
        rotation_success = orchestrator.rotate_session_key(result.session_id)
        assert rotation_success is True
        
        # Key should have changed
        new_key = session.key_material["session_key"]
        assert new_key != original_key
        assert len(new_key) == 32
        
        # Non-existent session rotation
        assert orchestrator.rotate_session_key("nonexistent") is False
    
    def test_session_termination(self, orchestrator, full_capabilities):
        """Test session termination"""
        result = orchestrator.establish_hybrid_session(full_capabilities)
        
        # Verify session exists
        assert orchestrator.get_session(result.session_id) is not None
        
        # Terminate
        success = orchestrator.terminate_session(result.session_id)
        assert success is True
        
        # Session should be gone
        assert orchestrator.get_session(result.session_id) is None
        
        # Double termination should fail
        assert orchestrator.terminate_session(result.session_id) is False
    
    def test_session_expiration_cleanup(self, orchestrator, full_capabilities):
        """Test expired session cleanup"""
        # Create orchestrator with very short timeout
        short_orch = PostQuantumHybridEncryptionOrchestrator(session_timeout_seconds=1)
        
        result = short_orch.establish_hybrid_session(full_capabilities)
        assert short_orch.get_session(result.session_id) is not None
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Cleanup should remove expired session
        cleaned = short_orch.cleanup_expired_sessions()
        assert cleaned >= 1
        assert short_orch.get_session(result.session_id) is None
    
    def test_performance_statistics(self, orchestrator, full_capabilities):
        """Test performance statistics gathering"""
        # Initial stats should be empty
        stats = orchestrator.get_performance_stats()
        assert stats["active_sessions"] == 0
        assert stats["total_sessions"] == 0
        
        # Create some sessions
        for _ in range(3):
            orchestrator.establish_hybrid_session(full_capabilities)
        
        stats = orchestrator.get_performance_stats()
        assert stats["active_sessions"] == 3
        assert stats["total_sessions"] == 3
        assert len(stats["algorithm_performance"]) > 0
    
    def test_algorithm_recommendations(self, orchestrator):
        """Test algorithm recommendation engine"""
        # Level 5 recommendations
        recs_level5 = orchestrator.get_recommended_algorithms(
            SecurityLevel.LEVEL_5,
            performance_priority=False
        )
        
        assert len(recs_level5) > 0
        for rec in recs_level5:
            assert rec["security_level"] >= SecurityLevel.LEVEL_5.value
        
        # Performance-prioritized recommendations
        recs_perf = orchestrator.get_recommended_algorithms(
            SecurityLevel.LEVEL_1,
            performance_priority=True
        )
        
        # Should be sorted by time ascending
        times = [r["estimated_time_ms"] for r in recs_perf]
        assert times == sorted(times)
    
    def test_security_policy_validation(self, orchestrator):
        """Test security policy validation"""
        # Level 5 suite should pass Level 1 check
        valid, msg = orchestrator.validate_security_policy(
            CipherSuite.KYBER1024_X448_AES256GCM,
            SecurityLevel.LEVEL_1
        )
        assert valid is True
        
        # Level 1 suite should fail Level 5 check
        valid, msg = orchestrator.validate_security_policy(
            CipherSuite.KYBER512_X25519_AES256GCM,
            SecurityLevel.LEVEL_5
        )
        assert valid is False
        assert "requires" in msg
    
    def test_session_id_uniqueness(self, orchestrator):
        """Test session ID uniqueness"""
        ids = set()
        for _ in range(100):
            session_id = orchestrator._generate_session_id()
            assert session_id not in ids
            ids.add(session_id)
    
    def test_realistic_operation_timing(self, orchestrator, full_capabilities):
        """Test that operations have realistic timing"""
        start = time.perf_counter()
        result = orchestrator.establish_hybrid_session(full_capabilities)
        elapsed = (time.perf_counter() - start) * 1000
        
        # Should take at least some measurable time
        assert elapsed > 0
        assert result.operation_time_ms > 0
    
    def test_edge_case_empty_pq_set(self, orchestrator):
        """Test edge case: empty PQ algorithm set with fallback disabled"""
        no_fallback_orch = PostQuantumHybridEncryptionOrchestrator(
            min_security_level=SecurityLevel.LEVEL_5,
            prefer_pq=True,
            enable_fallback=False
        )
        
        classical_only = AlgorithmCapabilities(
            supported_pq_algorithms=set(),
            supported_classical_algorithms={ClassicalAlgorithm.X25519},
            supported_cipher_suites=set(),
            max_security_level=SecurityLevel.LEVEL_1
        )
        
        result = no_fallback_orch.establish_hybrid_session(classical_only)
        # Should fail without fallback
        assert result.success is False
    
    def test_edge_case_high_security_request(self, orchestrator, limited_capabilities):
        """Test edge case: requesting higher security than available with fallback"""
        # With fallback enabled, should succeed at best available level
        result = orchestrator.establish_hybrid_session(
            limited_capabilities,
            requested_security_level=SecurityLevel.LEVEL_5
        )
        
        # With fallback enabled, should succeed with best available
        assert result.success is True
        # But achieved level will be lower than requested
        assert result.metadata["achieved_security_level"] < SecurityLevel.LEVEL_5.value
    
    def test_session_metadata_preserved(self, orchestrator, full_capabilities):
        """Test that session metadata is preserved"""
        result = orchestrator.establish_hybrid_session(full_capabilities)
        session = orchestrator.get_session(result.session_id)
        
        assert session.peer_capabilities is not None
        assert session.peer_capabilities.peer_id == "peer-full-support"
        assert session.cipher_suite == result.cipher_suite
        assert session.security_level == result.security_level


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
