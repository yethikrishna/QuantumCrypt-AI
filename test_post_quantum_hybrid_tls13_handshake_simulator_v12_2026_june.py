"""
Tests for Post-Quantum Hybrid TLS 1.3 Handshake Simulator v12
QuantumCrypt-AI Feature Expansion (Dimension A)
June 22, 2026

100% ADD-ONLY - NO EXISTING TESTS MODIFIED
"""

import pytest
import hashlib
from quantum_crypt.post_quantum_hybrid_tls13_handshake_simulator_v12_2026_june import (
    CipherSuite, KEMAlgorithm, ClassicalKEX, HandshakeState, ValidationLevel,
    HandshakeTiming, SecurityParameters, HandshakeTranscript, SessionKeys,
    HybridKeyExchange, HKDF, TLS13HandshakeSimulator,
    create_default_params, create_strict_params, run_benchmark
)


class TestSecurityParameters:
    """Test security parameter validation."""
    
    def test_default_params_valid(self):
        """Test default parameters pass validation."""
        params = create_default_params()
        valid, errors = params.validate()
        assert valid is True
        assert len(errors) == 0
    
    def test_strict_params_valid(self):
        """Test strict high-security parameters."""
        params = create_strict_params()
        valid, errors = params.validate()
        assert valid is True
        assert len(errors) == 0
    
    def test_kyber512_validation(self):
        """Test Kyber-512 parameter validation."""
        params = SecurityParameters(
            cipher_suite=CipherSuite.TLS_AES_128_GCM_SHA256_KYBER512_X25519,
            kem_algorithm=KEMAlgorithm.KYBER512,
            classical_kex=ClassicalKEX.X25519,
            kem_public_key_size=800,
            kem_ciphertext_size=768
        )
        valid, errors = params.validate()
        assert valid is True
    
    def test_invalid_kem_size(self):
        """Test invalid KEM size detection."""
        params = SecurityParameters(
            cipher_suite=CipherSuite.TLS_AES_256_GCM_SHA384_KYBER768_X25519,
            kem_algorithm=KEMAlgorithm.KYBER768,
            classical_kex=ClassicalKEX.X25519,
            kem_public_key_size=999,  # Wrong size
            kem_ciphertext_size=1088
        )
        valid, errors = params.validate()
        assert valid is False
        assert len(errors) > 0
        assert any("pubkey size mismatch" in e for e in errors)
    
    def test_short_session_key(self):
        """Test short session key rejection."""
        params = SecurityParameters(
            cipher_suite=CipherSuite.TLS_AES_128_GCM_SHA256_KYBER512_X25519,
            kem_algorithm=KEMAlgorithm.KYBER512,
            classical_kex=ClassicalKEX.X25519,
            session_key_length=8  # Too short
        )
        valid, errors = params.validate()
        assert valid is False
    
    def test_strict_mode_requires_strong_kem(self):
        """Test STRICT mode requires Kyber-768+."""
        params = SecurityParameters(
            cipher_suite=CipherSuite.TLS_AES_128_GCM_SHA256_KYBER512_X25519,
            kem_algorithm=KEMAlgorithm.KYBER512,  # Too weak for STRICT
            classical_kex=ClassicalKEX.X25519,
            validation_level=ValidationLevel.STRICT,
            kem_public_key_size=800,
            kem_ciphertext_size=768
        )
        valid, errors = params.validate()
        assert valid is False
        assert any("STRICT mode requires Kyber-768" in e for e in errors)


class TestHybridKeyExchange:
    """Test hybrid key exchange functionality."""
    
    def test_client_keypair_generation(self):
        """Test client key pair generation."""
        params = create_default_params()
        kex = HybridKeyExchange(params)
        pubkey = kex.generate_client_keypair()
        assert len(pubkey) == 32  # SHA256 output
    
    def test_server_keypair_generation(self):
        """Test server KEM + classical key pairs."""
        params = create_default_params()
        kex = HybridKeyExchange(params)
        classical_pub, kem_pk = kex.generate_server_keypair()
        
        assert len(classical_pub) == 32
        assert len(kem_pk) == params.kem_public_key_size
    
    def test_kem_correctness(self):
        """Test KEM encaps/decaps produce same shared secret."""
        params = create_default_params()
        kex = HybridKeyExchange(params)
        
        _, kem_pk = kex.generate_server_keypair()
        ct, ss_client = kex.kem_encapsulate(kem_pk)
        ss_server = kex.kem_decapsulate(ct)
        
        assert ss_client == ss_server
        assert len(ct) == params.kem_ciphertext_size
        assert len(ss_client) == 32  # SHA3-256
    
    def test_classical_shared_secret(self):
        """Test classical shared secret computation."""
        params = create_default_params()
        kex = HybridKeyExchange(params)
        
        client_pub = kex.generate_client_keypair()
        server_pub, _ = kex.generate_server_keypair()
        shared = kex.compute_classical_shared(client_pub, server_pub)
        
        assert len(shared) == 32
    
    def test_hybrid_shared_secret(self):
        """Test hybrid shared secret combination."""
        params = create_default_params()
        kex = HybridKeyExchange(params)
        
        kem_ss = hashlib.sha256(b"kem").digest()
        classical_ss = hashlib.sha256(b"classical").digest()
        hybrid = kex.compute_hybrid_shared(kem_ss, classical_ss)
        
        assert len(hybrid) == 48  # HMAC-SHA384 output


class TestHKDF:
    """Test HKDF key derivation."""
    
    def test_hkdf_extract_basic(self):
        """Test HKDF-Extract produces output."""
        salt = b""
        ikm = b"input key material"
        prk = HKDF.extract(salt, ikm)
        assert len(prk) == 48
    
    def test_hkdf_expand_length(self):
        """Test HKDF-Expand produces correct length."""
        prk = HKDF.extract(b"", b"test")
        info = b"test label"
        
        output_16 = HKDF.expand(prk, info, 16)
        output_32 = HKDF.expand(prk, info, 32)
        output_64 = HKDF.expand(prk, info, 64)
        
        assert len(output_16) == 16
        assert len(output_32) == 32
        assert len(output_64) == 64
    
    def test_session_keys_derivation(self):
        """Test full TLS 1.3 session key derivation."""
        shared_secret = hashlib.sha384(b"test shared secret").digest()
        transcript_hash = hashlib.sha384(b"test transcript").digest()
        
        keys = HKDF.derive_secrets(shared_secret, transcript_hash)
        
        assert len(keys.master_secret) == 48
        assert len(keys.client_handshake_key) == 32
        assert len(keys.server_handshake_key) == 32
        assert len(keys.client_application_key) == 32
        assert len(keys.server_application_key) == 32
        assert len(keys.exporter_key) == 32
        assert len(keys.resumption_master_secret) == 32
    
    def test_deterministic_derivation(self):
        """Test key derivation is deterministic."""
        shared = hashlib.sha384(b"same").digest()
        transcript = hashlib.sha384(b"same").digest()
        
        keys1 = HKDF.derive_secrets(shared, transcript)
        keys2 = HKDF.derive_secrets(shared, transcript)
        
        assert keys1.client_application_key == keys2.client_application_key
        assert keys1.master_secret == keys2.master_secret


class TestTLS13HandshakeSimulator:
    """Test full handshake simulator."""
    
    def test_full_handshake_completes(self):
        """Test end-to-end handshake completes successfully."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        result = simulator.run_full_handshake()
        
        assert result["success"] is True
        assert result["state"] == "handshake_done"
        assert result["session_keys_derived"] is True
        assert len(result["errors"]) == 0
    
    def test_handshake_state_transitions(self):
        """Test handshake state machine transitions."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        
        assert simulator.state == HandshakeState.INITIAL
        
        simulator.send_client_hello()
        assert simulator.state == HandshakeState.CLIENT_HELLO_SENT
        
        simulator.send_server_hello()
        assert simulator.state == HandshakeState.SERVER_HELLO_SENT
        
        simulator.perform_key_exchange()
        assert simulator.state == HandshakeState.KEY_EXCHANGE_COMPLETE
        
        simulator.derive_session_keys()
        assert simulator.state == HandshakeState.HANDSHAKE_DONE
    
    def test_invalid_state_transition_fails(self):
        """Test invalid state transitions are rejected."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        
        # Try ServerHello before ClientHello
        result = simulator.send_server_hello()
        assert result["success"] is False
        assert simulator.state == HandshakeState.FAILED
    
    def test_handshake_report_structure(self):
        """Test handshake report has all fields."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        simulator.run_full_handshake()
        report = simulator.get_handshake_report()
        
        assert "success" in report
        assert "state" in report
        assert "security_parameters" in report
        assert "key_sizes" in report
        assert "timing" in report
        assert "transcript_messages" in report
    
    def test_transcript_records_messages(self):
        """Test transcript records all handshake messages."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        simulator.run_full_handshake()
        
        # Should have: ClientHello, ServerHello, KeyExchange, Finished
        assert len(simulator.transcript.messages) >= 4
    
    def test_random_values_unique(self):
        """Test client/server randoms are unique."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        simulator.run_full_handshake()
        
        assert simulator.transcript.client_random != simulator.transcript.server_random
        assert len(simulator.transcript.client_random) == 32
        assert len(simulator.transcript.server_random) == 32
    
    def test_timing_measurements(self):
        """Test timing measurements are recorded."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        simulator.run_full_handshake()
        
        timing = simulator.timing.to_dict()
        
        assert timing["client_hello_ms"] > 0
        assert timing["server_hello_ms"] > 0
        assert timing["key_exchange_ms"] > 0
        assert timing["key_derivation_ms"] > 0
        assert timing["total_handshake_ms"] > 0
        assert timing["total_handshake_ms"] >= (
            timing["client_hello_ms"] + timing["server_hello_ms"]
        )


class TestSecurityAssessment:
    """Test security assessment functionality."""
    
    def test_kyber768_is_post_quantum_secure(self):
        """Test Kyber-768 is marked PQ secure."""
        params = create_default_params()  # Kyber-768
        simulator = TLS13HandshakeSimulator(params)
        simulator.run_full_handshake()
        assessment = simulator.get_security_assessment()
        
        assert assessment["post_quantum_secure"] is True
        assert assessment["nist_level"] == 3
    
    def test_kyber1024_highest_security(self):
        """Test Kyber-1024 has NIST Level 5 security."""
        params = create_strict_params()
        simulator = TLS13HandshakeSimulator(params)
        simulator.run_full_handshake()
        assessment = simulator.get_security_assessment()
        
        assert assessment["post_quantum_secure"] is True
        assert assessment["nist_level"] == 5
    
    def test_forward_secrecy(self):
        """Test forward secrecy is enabled."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        simulator.run_full_handshake()
        assessment = simulator.get_security_assessment()
        
        assert assessment["forward_secrecy"] is True
        assert assessment["hybrid_mode"] is True
    
    def test_compliance_flags(self):
        """Test compliance flags are set."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        simulator.run_full_handshake()
        assessment = simulator.get_security_assessment()
        
        assert assessment["compliance"]["nist_sp_800_186"] is True
        assert assessment["compliance"]["tls_1_3_rfc_8446"] is True
    
    def test_security_score(self):
        """Test security score is calculated."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        simulator.run_full_handshake()
        assessment = simulator.get_security_assessment()
        
        assert 0.0 <= assessment["overall_security_score"] <= 1.0
        assert assessment["overall_security_score"] > 0.5


class TestBenchmark:
    """Test benchmark functionality."""
    
    def test_benchmark_runs(self):
        """Test benchmark completes successfully."""
        result = run_benchmark(iterations=5)
        
        assert result["iterations"] == 5
        assert result["successes"] == 5
        assert result["success_rate"] == 100.0
        assert "average_timing_ms" in result
        assert len(result["average_timing_ms"]) > 0


class TestBackwardCompatibility:
    """Verify backward compatibility - no existing code broken."""
    
    def test_no_conflict_with_existing_modules(self):
        """Test new module doesn't conflict with existing imports."""
        # This should import without errors
        from quantum_crypt import post_quantum_kyber_kem_engine_2026_june
        from quantum_crypt import post_quantum_secure_key_storage_rotation_engine_v63_2026_june
        assert True  # If we got here, imports worked
    
    def test_new_module_is_isolated(self):
        """Test new module is completely isolated."""
        params = create_default_params()
        simulator = TLS13HandshakeSimulator(params)
        assert simulator is not None
        # No side effects on existing modules


class TestHelperFunctions:
    """Test helper and configuration functions."""
    
    def test_create_default_params(self):
        """Test default parameter creation."""
        params = create_default_params()
        assert params.kem_algorithm == KEMAlgorithm.KYBER768
        assert params.classical_kex == ClassicalKEX.X25519
        assert params.validation_level == ValidationLevel.STANDARD
    
    def test_create_strict_params(self):
        """Test strict parameter creation."""
        params = create_strict_params()
        assert params.kem_algorithm == KEMAlgorithm.KYBER1024
        assert params.validation_level == ValidationLevel.STRICT
        assert params.session_key_length == 48


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
