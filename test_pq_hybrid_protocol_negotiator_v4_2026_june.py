"""
Tests for Post-Quantum Hybrid Protocol Negotiator v4
QuantumCrypt-AI Feature Expansion (Dimension A)

Comprehensive test coverage for PQ algorithm negotiation.
ADD-ONLY implementation - no modifications to existing tests.
"""

import pytest
import json
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from quantum_crypt.pq_hybrid_protocol_negotiator_v4_2026_june import (
    PQHybridProtocolNegotiator,
    PQAlgorithm,
    PQAlgorithmType,
    SecurityLevel,
    UseCaseProfile,
    AlgorithmCapability,
    NegotiationResult,
    ProtocolSession,
    get_protocol_negotiator,
    negotiate_pq_algorithm
)


class TestPQAlgorithmEnum:
    """Tests for PQAlgorithm enum."""
    
    def test_all_algorithms_have_properties(self):
        """Test all algorithms have name, type, and security level."""
        for alg in PQAlgorithm:
            assert alg.name is not None
            assert alg.algorithm_type is not None
            assert alg.security_level is not None
    
    def test_algorithm_names_unique(self):
        """Test all algorithm names are unique."""
        names = [alg.name for alg in PQAlgorithm]
        assert len(names) == len(set(names))
    
    def test_security_levels_valid(self):
        """Test security levels are in valid range 1-5."""
        for alg in PQAlgorithm:
            assert 1 <= alg.security_level.value <= 5


class TestSecurityLevelEnum:
    """Tests for SecurityLevel enum."""
    
    def test_security_level_values(self):
        """Test security level values are correct."""
        assert SecurityLevel.LEVEL_1.value == 1
        assert SecurityLevel.LEVEL_2.value == 2
        assert SecurityLevel.LEVEL_3.value == 3
        assert SecurityLevel.LEVEL_4.value == 4
        assert SecurityLevel.LEVEL_5.value == 5


class TestUseCaseProfileEnum:
    """Tests for UseCaseProfile enum."""
    
    def test_all_profiles_have_min_security(self):
        """Test all use case profiles have minimum security."""
        for profile in UseCaseProfile:
            assert "min_security" in profile.value
            assert "preferred" in profile.value


class TestAlgorithmCapability:
    """Tests for AlgorithmCapability class."""
    
    def test_capability_creation(self):
        """Test capability creation."""
        cap = AlgorithmCapability(
            party_id="client1",
            supported_algorithms=["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-512"],
            preferred_order=["CRYSTALS-Kyber-768"]
        )
        assert cap.party_id == "client1"
        assert len(cap.supported_algorithms) == 2
    
    def test_capability_to_dict(self):
        """Test conversion to dictionary."""
        cap = AlgorithmCapability(
            party_id="test",
            supported_algorithms=["CRYSTALS-Kyber-768"],
            constraints={"max_key_size": 2048}
        )
        d = cap.to_dict()
        assert d["party_id"] == "test"
        assert d["constraints"]["max_key_size"] == 2048


class TestNegotiationResult:
    """Tests for NegotiationResult class."""
    
    def test_success_result(self):
        """Test successful negotiation result."""
        result = NegotiationResult(
            success=True,
            selected_algorithm="CRYSTALS-Kyber-768",
            common_algorithms=["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-512"]
        )
        assert result.success is True
        assert result.selected_algorithm == "CRYSTALS-Kyber-768"
        assert len(result.common_algorithms) == 2
    
    def test_failure_result(self):
        """Test failure negotiation result."""
        result = NegotiationResult(
            success=False,
            reason="no_common_algorithms"
        )
        assert result.success is False
        assert result.reason == "no_common_algorithms"
    
    def test_result_to_dict(self):
        """Test result conversion to dictionary."""
        result = NegotiationResult(
            success=True,
            selected_algorithm="CRYSTALS-Kyber-768",
            metadata={"parties": ["a", "b"]}
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["metadata"]["parties"] == ["a", "b"]


class TestProtocolSession:
    """Tests for ProtocolSession class."""
    
    def test_session_creation(self):
        """Test session creation."""
        session = ProtocolSession()
        assert session.session_id is not None
        assert session.status == "pending"
    
    def test_session_expiration(self):
        """Test session expiration logic."""
        session = ProtocolSession()
        session.expires_at = time.time() - 100  # Expired
        assert session.is_expired() is True
        
        session2 = ProtocolSession()
        session2.expires_at = time.time() + 100  # Not expired
        assert session2.is_expired() is False
        
        session3 = ProtocolSession()  # No expiration
        assert session3.is_expired() is False


class TestPQHybridProtocolNegotiator:
    """Tests for main negotiator class."""
    
    def test_negotiator_creation(self):
        """Test negotiator initialization."""
        negotiator = PQHybridProtocolNegotiator()
        assert len(negotiator.sessions) == 0
        assert len(negotiator.algorithm_database) > 0
    
    def test_create_session(self):
        """Test session creation."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        assert session_id is not None
        assert session_id in negotiator.sessions
    
    def test_create_session_with_ttl(self):
        """Test session creation with TTL."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session(ttl_seconds=3600)
        session = negotiator.sessions[session_id]
        assert session.expires_at is not None
    
    def test_register_party_capabilities(self):
        """Test registering party capabilities."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        result = negotiator.register_party_capabilities(
            session_id=session_id,
            party_id="client",
            supported_algorithms=["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-512"]
        )
        assert result is True
        session = negotiator.sessions[session_id]
        assert "client" in session.parties
    
    def test_register_invalid_session(self):
        """Test registering to invalid session."""
        negotiator = PQHybridProtocolNegotiator()
        result = negotiator.register_party_capabilities(
            session_id="nonexistent",
            party_id="client",
            supported_algorithms=["CRYSTALS-Kyber-768"]
        )
        assert result is False
    
    def test_negotiate_success(self):
        """Test successful negotiation between two parties."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        
        # Both parties support Kyber-768
        negotiator.register_party_capabilities(
            session_id, "client",
            ["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-512"]
        )
        negotiator.register_party_capabilities(
            session_id, "server",
            ["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024"]
        )
        
        result = negotiator.negotiate(session_id)
        assert result.success is True
        assert result.selected_algorithm == "CRYSTALS-Kyber-768"
    
    def test_negotiate_no_common(self):
        """Test negotiation with no common algorithms."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        
        negotiator.register_party_capabilities(
            session_id, "client", ["CRYSTALS-Kyber-512"]
        )
        negotiator.register_party_capabilities(
            session_id, "server", ["CRYSTALS-Kyber-1024"]
        )
        
        result = negotiator.negotiate(session_id)
        assert result.success is False
        assert result.reason == "no_common_algorithms"
    
    def test_negotiate_insufficient_parties(self):
        """Test negotiation with only one party."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        
        negotiator.register_party_capabilities(
            session_id, "client", ["CRYSTALS-Kyber-768"]
        )
        
        result = negotiator.negotiate(session_id)
        assert result.success is False
        assert result.reason == "insufficient_parties"
    
    def test_negotiate_invalid_session(self):
        """Test negotiation on invalid session."""
        negotiator = PQHybridProtocolNegotiator()
        result = negotiator.negotiate("nonexistent")
        assert result.success is False
        assert result.reason == "session_not_found"
    
    def test_negotiate_with_security_filter(self):
        """Test negotiation with minimum security level filter."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        
        negotiator.register_party_capabilities(
            session_id, "client",
            ["CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768"]  # Level 1 and 3
        )
        negotiator.register_party_capabilities(
            session_id, "server",
            ["CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768"]
        )
        
        # Require level 3 security - should filter out Kyber-512 (level 1)
        result = negotiator.negotiate(session_id, min_security_level=3)
        assert result.success is True
        assert result.selected_algorithm == "CRYSTALS-Kyber-768"
    
    def test_negotiate_with_use_case(self):
        """Test negotiation with use case optimization."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        
        algs = ["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-512", "CRYSTALS-Dilithium-3"]
        negotiator.register_party_capabilities(session_id, "client", algs)
        negotiator.register_party_capabilities(session_id, "server", algs)
        
        result = negotiator.negotiate(session_id, use_case="TLS_HANDSHAKE")
        assert result.success is True
    
    def test_get_session_status(self):
        """Test getting session status."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        
        status = negotiator.get_session_status(session_id)
        assert status is not None
        assert status["session_id"] == session_id
        assert status["is_expired"] is False
    
    def test_get_session_status_invalid(self):
        """Test getting status for invalid session."""
        negotiator = PQHybridProtocolNegotiator()
        status = negotiator.get_session_status("nonexistent")
        assert status is None
    
    def test_recommend_algorithms(self):
        """Test algorithm recommendations."""
        negotiator = PQHybridProtocolNegotiator()
        recs = negotiator.recommend_algorithms(use_case="GENERAL_PURPOSE")
        assert len(recs) > 0
        for rec in recs:
            assert "name" in rec
            assert "security_level" in rec
            assert "performance_score" in rec
    
    def test_recommend_by_type(self):
        """Test recommendations filtered by algorithm type."""
        negotiator = PQHybridProtocolNegotiator()
        kem_recs = negotiator.recommend_algorithms(
            algorithm_type="key_encapsulation_mechanism"
        )
        assert len(kem_recs) > 0
    
    def test_recommend_by_security(self):
        """Test recommendations filtered by security level."""
        negotiator = PQHybridProtocolNegotiator()
        high_sec = negotiator.recommend_algorithms(min_security=5)
        for rec in high_sec:
            assert rec["security_level"] >= 5
    
    def test_cleanup_expired_sessions(self):
        """Test cleanup of expired sessions."""
        negotiator = PQHybridProtocolNegotiator()
        
        # Create expired session
        expired_id = negotiator.create_session(ttl_seconds=-100)
        active_id = negotiator.create_session(ttl_seconds=3600)
        
        removed = negotiator.cleanup_expired_sessions()
        assert removed >= 1
        assert expired_id not in negotiator.sessions
        assert active_id in negotiator.sessions
    
    def test_generate_negotiation_token(self):
        """Test generating negotiation token."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        negotiator.register_party_capabilities(
            session_id, "client", ["CRYSTALS-Kyber-768"]
        )
        negotiator.register_party_capabilities(
            session_id, "server", ["CRYSTALS-Kyber-768"]
        )
        negotiator.negotiate(session_id)
        
        token = negotiator.generate_negotiation_token(session_id)
        assert token is not None
        assert "." in token  # Format: json.signature
    
    def test_verify_negotiation_token_valid(self):
        """Test valid token verification."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        negotiator.register_party_capabilities(
            session_id, "client", ["CRYSTALS-Kyber-768"]
        )
        negotiator.register_party_capabilities(
            session_id, "server", ["CRYSTALS-Kyber-768"]
        )
        negotiator.negotiate(session_id)
        
        token = negotiator.generate_negotiation_token(session_id)
        result = negotiator.verify_negotiation_token(token)
        assert result["valid"] is True
    
    def test_verify_negotiation_token_invalid(self):
        """Test invalid token verification."""
        negotiator = PQHybridProtocolNegotiator()
        result = negotiator.verify_negotiation_token("invalid.token")
        assert result["valid"] is False


class TestGlobalInstance:
    """Tests for global negotiator instance."""
    
    def test_get_protocol_negotiator(self):
        """Test getting global negotiator."""
        negotiator = get_protocol_negotiator()
        assert negotiator is not None
        assert isinstance(negotiator, PQHybridProtocolNegotiator)
    
    def test_get_protocol_negotiator_singleton(self):
        """Test negotiator is singleton."""
        n1 = get_protocol_negotiator()
        n2 = get_protocol_negotiator()
        assert n1 is n2
    
    def test_convenience_function(self):
        """Test convenience negotiation function."""
        result = negotiate_pq_algorithm(
            party1_algs=["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-512"],
            party2_algs=["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024"],
            use_case="TLS_HANDSHAKE"
        )
        assert result.success is True
        assert result.selected_algorithm == "CRYSTALS-Kyber-768"


class TestIntegrationScenarios:
    """Integration tests for real-world scenarios."""
    
    def test_tls_handshake_negotiation(self):
        """Test typical TLS handshake scenario."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session(use_case="TLS_HANDSHAKE")
        
        # Client (browser) capabilities
        negotiator.register_party_capabilities(
            session_id, "browser",
            ["CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "Kyber-768+X25519"],
            preferred_order=["Kyber-768+X25519", "CRYSTALS-Kyber-768"]
        )
        
        # Server capabilities
        negotiator.register_party_capabilities(
            session_id, "server",
            ["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024", "Kyber-768+X25519"],
            preferred_order=["Kyber-768+X25519"]
        )
        
        result = negotiator.negotiate(session_id, use_case="TLS_HANDSHAKE")
        assert result.success is True
        assert "Kyber" in result.selected_algorithm
    
    def test_multi_party_negotiation(self):
        """Test negotiation with 3+ parties."""
        negotiator = PQHybridProtocolNegotiator()
        session_id = negotiator.create_session()
        
        algs = ["CRYSTALS-Kyber-768"]
        negotiator.register_party_capabilities(session_id, "party1", algs)
        negotiator.register_party_capabilities(session_id, "party2", algs)
        negotiator.register_party_capabilities(session_id, "party3", algs)
        
        result = negotiator.negotiate(session_id)
        assert result.success is True
        assert result.selected_algorithm == "CRYSTALS-Kyber-768"


# Run tests and save results
if __name__ == "__main__":
    print("=" * 70)
    print("QuantumCrypt-AI PQ Hybrid Protocol Negotiator Tests v4")
    print("Dimension A: Feature Expansion - ADD-ONLY")
    print("=" * 70)
    
    # Run pytest
    import pytest
    result = pytest.main([__file__, "-v", "--tb=short"])
    
    print("\n" + "=" * 70)
    if result == 0:
        print("✓ ALL PROTOCOL NEGOTIATOR TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
    print("=" * 70)
    
    # Save results
    with open("test_results_pq_protocol_negotiator_v4_2026_june.json", "w") as f:
        json.dump({
            "test_module": "pq_hybrid_protocol_negotiator_v4",
            "dimension": "A - Feature Expansion",
            "status": "passed" if result == 0 else "failed",
            "timestamp": time.time()
        }, f)
    
    sys.exit(result)
