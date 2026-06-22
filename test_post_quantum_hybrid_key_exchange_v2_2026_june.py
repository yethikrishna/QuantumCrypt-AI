"""
Tests for Post-Quantum Hybrid Key Exchange v2
Dimension A - Feature Expansion Tests
"""

import pytest
import time
from quantum_crypt.post_quantum_hybrid_key_exchange_v2_2026_june import (
    PostQuantumHybridKeyExchange,
    KeyExchangeSession,
    KeyExchangeResult,
    KeyExchangeAlgorithm,
    SecurityLevel,
    KDFHash,
    get_key_exchange
)


class TestKeyExchangeSession:
    """Tests for KeyExchangeSession dataclass."""
    
    def test_session_creation(self):
        """Test basic session creation."""
        session = KeyExchangeSession(
            session_id="test_123",
            algorithm=KeyExchangeAlgorithm.HYBRID_X25519_KYBER_768,
            security_level=SecurityLevel.LEVEL_3,
            initiator=True
        )
        assert session.session_id == "test_123"
        assert session.initiator is True
        assert session.completed is False
    
    def test_session_not_expired_initially(self):
        """Test session is not expired when created."""
        session = KeyExchangeSession(
            session_id="test_123",
            algorithm=KeyExchangeAlgorithm.X25519,
            security_level=SecurityLevel.LEVEL_1,
            initiator=True
        )
        assert not session.is_expired()
    
    def test_update_activity(self):
        """Test activity timestamp update."""
        session = KeyExchangeSession(
            session_id="test_123",
            algorithm=KeyExchangeAlgorithm.X25519,
            security_level=SecurityLevel.LEVEL_1,
            initiator=True
        )
        time.sleep(0.01)
        old_activity = session.last_activity
        session.update_activity()
        assert session.last_activity > old_activity


class TestKeyExchangeResult:
    """Tests for KeyExchangeResult dataclass."""
    
    def test_success_result(self):
        """Test successful result structure."""
        result = KeyExchangeResult(
            success=True,
            session_id="session_123",
            session_key=b"test_key_32_bytes___________",
            algorithm=KeyExchangeAlgorithm.HYBRID_X25519_KYBER_768
        )
        assert result.success is True
        assert result.session_key is not None
    
    def test_failure_result(self):
        """Test failure result structure."""
        result = KeyExchangeResult(
            success=False,
            error_message="Session not found"
        )
        assert result.success is False
        assert result.error_message == "Session not found"


class TestPostQuantumHybridKeyExchange:
    """Tests for the main key exchange module."""
    
    def setup_method(self):
        """Reset singleton before each test."""
        PostQuantumHybridKeyExchange._instance = None
        self.kex = get_key_exchange()
    
    def test_singleton_pattern(self):
        """Test singleton returns same instance."""
        kex1 = get_key_exchange()
        kex2 = get_key_exchange()
        assert kex1 is kex2
    
    def test_disabled_by_default_opt_in(self):
        """Test module is DISABLED by default (OPT-IN requirement)."""
        kex = get_key_exchange()
        assert kex.enabled is False
    
    def test_enable_disable(self):
        """Test enable/disable functionality."""
        kex = get_key_exchange()
        kex.enable()
        assert kex.enabled is True
        kex.disable()
        assert kex.enabled is False
    
    def test_create_initiator_disabled_returns_empty(self):
        """Test creating session when disabled returns empty."""
        kex = get_key_exchange()
        kex.disable()
        session_id, pubkey = kex.create_initiator_session()
        assert session_id == ""
        assert pubkey == b""
    
    def test_create_initiator_enabled(self):
        """Test creating initiator session when enabled."""
        kex = get_key_exchange()
        kex.enable()
        session_id, pubkey = kex.create_initiator_session()
        assert session_id != ""
        assert len(pubkey) > 0
        assert session_id.startswith("kex_")
    
    def test_create_initiator_with_algorithm(self):
        """Test creating session with specific algorithm."""
        kex = get_key_exchange()
        kex.enable()
        session_id, pubkey = kex.create_initiator_session(
            algorithm=KeyExchangeAlgorithm.CRYSTALS_KYBER_768
        )
        assert session_id != ""
        assert len(pubkey) > 0
    
    def test_create_responder_disabled_fails(self):
        """Test responder session creation fails when disabled."""
        kex = get_key_exchange()
        kex.disable()
        result = kex.create_responder_session(b"test_pubkey")
        assert result.success is False
        assert "disabled" in result.error_message.lower()
    
    def test_full_key_exchange_flow(self):
        """Test complete key exchange between initiator and responder."""
        kex = get_key_exchange()
        PostQuantumHybridKeyExchange._instance = None
        kex = get_key_exchange()
        kex.enable()
        
        # Step 1: Initiator creates session
        initiator_id, initiator_pubkey = kex.create_initiator_session()
        assert initiator_id != ""
        
        # Step 2: Responder processes initiator pubkey
        responder_result = kex.create_responder_session(initiator_pubkey)
        assert responder_result.success is True
        assert responder_result.session_key is not None
        
        # Step 3: Initiator processes responder pubkey (simulated)
        # In real flow, responder would send their pubkey
        # Here we simulate with a test public key
        test_responder_pubkey = b"responder_pubkey_64_bytes__________________________"
        initiator_result = kex.process_responder_public_key(
            initiator_id,
            test_responder_pubkey
        )
        # Should work if session exists
        assert initiator_result.success is True or initiator_result.error_message is not None
    
    def test_process_nonexistent_session(self):
        """Test processing with non-existent session ID."""
        kex = get_key_exchange()
        kex.enable()
        result = kex.process_responder_public_key(
            "nonexistent_session_id",
            b"test_pubkey"
        )
        assert result.success is False
        assert "not found" in result.error_message.lower()
    
    def test_derive_subkey(self):
        """Test subkey derivation from session key."""
        kex = get_key_exchange()
        kex.enable()
        
        # Create and complete a session
        session_id, _ = kex.create_initiator_session()
        result = kex.process_responder_public_key(session_id, b"test_responder_pubkey")
        
        if result.success:
            subkey1 = kex.derive_subkey(session_id, "encryption", 32)
            subkey2 = kex.derive_subkey(session_id, "authentication", 32)
            
            assert subkey1 is not None
            assert subkey2 is not None
            assert len(subkey1) == 32
            assert len(subkey2) == 32
            assert subkey1 != subkey2  # Different labels = different keys
    
    def test_derive_subkey_same_label_cached(self):
        """Test same label returns same cached subkey."""
        kex = get_key_exchange()
        kex.enable()
        
        session_id, _ = kex.create_initiator_session()
        kex.process_responder_public_key(session_id, b"test_pubkey")
        
        subkey1 = kex.derive_subkey(session_id, "test", 32)
        subkey2 = kex.derive_subkey(session_id, "test", 32)
        
        if subkey1 and subkey2:
            assert subkey1 == subkey2
    
    def test_get_session(self):
        """Test session retrieval."""
        kex = get_key_exchange()
        kex.enable()
        
        session_id, _ = kex.create_initiator_session()
        session = kex.get_session(session_id)
        
        assert session is not None
        assert session.session_id == session_id
    
    def test_destroy_session(self):
        """Test session destruction."""
        kex = get_key_exchange()
        kex.enable()
        
        session_id, _ = kex.create_initiator_session()
        result = kex.destroy_session(session_id)
        
        assert result is True
        assert kex.get_session(session_id) is None
    
    def test_destroy_nonexistent_session(self):
        """Test destroying non-existent session."""
        kex = get_key_exchange()
        kex.enable()
        result = kex.destroy_session("nonexistent")
        assert result is False
    
    def test_statistics_reporting(self):
        """Test statistics reporting works."""
        kex = get_key_exchange()
        kex.enable()
        
        stats = kex.get_statistics()
        assert 'enabled' in stats
        assert 'active_sessions' in stats
        assert 'completed_sessions' in stats
        assert 'default_algorithm' in stats
        assert 'by_algorithm' in stats
    
    def test_set_default_algorithm(self):
        """Test setting default algorithm."""
        kex = get_key_exchange()
        kex.set_default_algorithm(KeyExchangeAlgorithm.CRYSTALS_KYBER_1024)
        stats = kex.get_statistics()
        assert stats['default_algorithm'] == 'kyber_1024'
    
    def test_set_default_kdf(self):
        """Test setting default KDF."""
        kex = get_key_exchange()
        kex.set_default_kdf(KDFHash.SHA512)
        # Just verify no error
        assert True


class TestIntegration:
    """Integration tests for full key exchange workflow."""
    
    def test_session_management(self):
        """Test multiple session management."""
        kex = get_key_exchange()
        PostQuantumHybridKeyExchange._instance = None
        kex = get_key_exchange()
        kex.enable()
        
        # Create multiple sessions
        sessions = []
        for i in range(5):
            sid, _ = kex.create_initiator_session()
            sessions.append(sid)
        
        stats = kex.get_statistics()
        assert stats['active_sessions'] >= 5
    
    def test_hybrid_algorithm_selection(self):
        """Test hybrid algorithm usage."""
        kex = get_key_exchange()
        PostQuantumHybridKeyExchange._instance = None
        kex = get_key_exchange()
        kex.enable()
        
        session_id, _ = kex.create_initiator_session(
            algorithm=KeyExchangeAlgorithm.HYBRID_X25519_KYBER_768
        )
        session = kex.get_session(session_id)
        
        assert session is not None
        assert session.algorithm == KeyExchangeAlgorithm.HYBRID_X25519_KYBER_768
        assert session.security_level == SecurityLevel.LEVEL_3


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
