"""
Test Suite for Post-Quantum TLS 1.3 Implementation (June 2026)
Tests for NIST-compliant PQC TLS functionality
"""
import pytest
import hashlib
from quantum_crypt.post_quantum_tls_2026 import (
    PostQuantumTLS13,
    HybridCertificateChain2026,
    get_pqc_tls_migration_guide
)

class TestPostQuantumTLS13:
    """Test PQC TLS 1.3 Implementation"""
    
    def test_tls_initialization(self):
        """Test TLS handler initialization"""
        tls = PostQuantumTLS13(preferred_group=0xFE01)
        assert tls.preferred_group == 0xFE01
        assert 0xFE01 in tls.PQC_GROUPS
        assert tls.PQC_GROUPS[0xFE01]["name"] == "X25519MLKEM512"
    
    def test_client_hello_generation(self):
        """Test ClientHello with PQC extensions"""
        tls = PostQuantumTLS13()
        hello = tls.generate_client_hello()
        
        assert hello["type"] == "ClientHello"
        assert hello["version"] == "TLS 1.3"
        assert len(hello["client_random"]) == 32
        assert hello["pqc_enabled"] == True
        assert len(hello["key_shares"]) > 0
    
    def test_server_hello_response(self):
        """Test ServerHello PQC group selection"""
        tls = PostQuantumTLS13()
        client_hello = tls.generate_client_hello()
        server_hello = tls.generate_server_hello(client_hello)
        
        assert server_hello["type"] == "ServerHello"
        assert server_hello["pqc_enabled"] == True
        assert "MLKEM" in server_hello["selected_group_name"]
        assert server_hello["compliant_nist_june2026"] == True
    
    def test_shared_secret_computation(self):
        """Test PQC shared secret derivation"""
        tls = PostQuantumTLS13()
        client_hello = tls.generate_client_hello()
        server_hello = tls.generate_server_hello(client_hello)
        
        shared_secret, master_secret = tls.compute_shared_secret(client_hello, server_hello)
        
        assert len(shared_secret) == 48  # SHA384 output
        assert len(master_secret) == 48
        assert shared_secret != master_secret  # Different derivation
    
    def test_session_creation(self):
        """Test complete TLS session creation"""
        tls = PostQuantumTLS13()
        client_hello = tls.generate_client_hello()
        server_hello = tls.generate_server_hello(client_hello)
        
        session = tls.create_session(client_hello, server_hello)
        
        assert session.pqc_enabled == True
        assert len(session.client_random) == 32
        assert len(session.server_random) == 32
        assert "MLKEM" in session.pqc_algorithm
    
    def test_deployment_status(self):
        """Test deployment status report"""
        tls = PostQuantumTLS13()
        status = tls.get_deployment_status()
        
        assert status["report_date"] == "June 2026"
        assert "Chrome" in status["browser_support"]
        assert status["nist_compliance"]["fips_203_mlkem"] == True
        assert status["nist_compliance"]["fips_204_mldsa"] == True

class TestHybridCertificateChain:
    """Test Hybrid Certificate Chain Implementation"""
    
    def test_chain_initialization(self):
        """Test chain initialization"""
        chain = HybridCertificateChain2026()
        assert len(chain.classical_certs) == 0
        assert len(chain.pqc_certs) == 0
    
    def test_certificate_addition(self):
        """Test adding certificates to chain"""
        chain = HybridCertificateChain2026()
        
        classical_cert = hashlib.sha256(b"classical cert").digest()
        pqc_cert = hashlib.sha3_512(b"pqc cert").digest()
        
        chain.add_classical_certificate(classical_cert)
        chain.add_pqc_certificate(pqc_cert)
        
        assert len(chain.classical_certs) == 1
        assert len(chain.pqc_certs) == 1
    
    def test_dual_stack_build(self):
        """Test dual-stack chain construction"""
        chain = HybridCertificateChain2026()
        chain.add_classical_certificate(b"rsa-cert")
        chain.add_pqc_certificate(b"mldsa-cert")
        
        result = chain.build_dual_stack_chain()
        
        assert result["format"] == "NIST-PIV-Dual-Stack-June2026"
        assert result["backward_compatible"] == True
        assert result["key_encapsulation"] == "ML-KEM (FIPS 203)"
        assert result["digital_signature"] == "ML-DSA (FIPS 204)"
    
    def test_dual_verification(self):
        """Test hybrid signature verification"""
        chain = HybridCertificateChain2026()
        message = b"test message"
        
        classical_sig = hashlib.sha256(message).digest() + b"padding"
        pqc_sig = hashlib.sha3_512(message).digest() + b"padding"
        
        result = chain.verify_dual_stack(message, classical_sig, pqc_sig)
        
        assert "classical_valid" in result
        assert "pqc_valid" in result
        assert "hybrid_valid" in result

class TestMigrationGuide:
    """Test Migration Guide Functions"""
    
    def test_migration_guide_structure(self):
        """Test migration guide structure"""
        guide = get_pqc_tls_migration_guide()
        
        assert "phase1_immediate" in guide
        assert "phase2_transition" in guide
        assert "phase3_full_migration" in guide
        assert "nist_deadlines" in guide
        assert "browser_default_groups" in guide
    
    def test_migration_timelines(self):
        """Test migration timeline data"""
        guide = get_pqc_tls_migration_guide()
        
        assert guide["phase1_immediate"]["timeline"] == "Q2-Q3 2026"
        assert guide["nist_deadlines"]["federal_systems"] == "2030 (RSA-2048 deprecation)"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
