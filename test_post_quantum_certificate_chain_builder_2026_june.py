"""
Test suite for Post-Quantum Certificate Chain Builder
Real working tests with actual assertions
"""

import sys
import os
import time
import json

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_certificate_chain_builder_hybrid_kem_2026_june import (
    SignatureAlgorithm,
    KEMAlgorithm,
    CertificateStatus,
    Certificate,
    ValidationResult,
    HybridSignatureVerifier,
    HybridKEMEncapsulator,
    CertificateRevocationList,
    PostQuantumCertificateChainBuilder
)


def test_certificate_dataclass():
    """Test Certificate data class"""
    print("Testing Certificate dataclass...")
    
    cert = Certificate(
        cert_id="test_001",
        subject="Test Subject",
        issuer="Test Issuer",
        public_key="test_public_key",
        signature="test_signature",
        signature_algorithm=SignatureAlgorithm.HYBRID_ECDSA_DILITHIUM
    )
    
    assert cert.subject == "Test Subject", "Subject mismatch"
    assert cert.issuer == "Test Issuer", "Issuer mismatch"
    assert cert.serial_number != "", "Serial number should be auto-generated"
    assert cert.is_expired() == False, "New certificate should not be expired"
    assert cert.get_days_remaining() > 360, "Should have ~365 days remaining"
    assert len(cert.fingerprint()) == 64, "Fingerprint should be 64 chars"
    print("  ✓ Certificate creation and properties: PASS")
    
    print("  All Certificate tests PASSED\n")


def test_hybrid_signature_verifier():
    """Test hybrid signature verification"""
    print("Testing HybridSignatureVerifier...")
    
    verifier = HybridSignatureVerifier()
    test_data = "Test message to sign"
    test_key = "test_private_key_12345"
    
    # Test all algorithms
    algorithms = [
        SignatureAlgorithm.RSA_2048,
        SignatureAlgorithm.ECDSA_P256,
        SignatureAlgorithm.DILITHIUM_3,
        SignatureAlgorithm.HYBRID_ECDSA_DILITHIUM
    ]
    
    for algo in algorithms:
        signature = verifier._compute_signature(test_data, test_key, algo)
        is_valid, confidence = verifier.verify_signature(
            test_data, signature, test_key, algo
        )
        assert is_valid == True, f"Signature should validate for {algo.value}"
        assert 0 < confidence <= 1.0, f"Confidence should be in range for {algo.value}"
        print(f"  ✓ {algo.value} verification: PASS")
    
    # Test invalid signature
    is_valid, _ = verifier.verify_signature(
        test_data, "wrong_signature", test_key, SignatureAlgorithm.DILITHIUM_3
    )
    assert is_valid == False, "Invalid signature should fail"
    print("  ✓ Invalid signature rejection: PASS")
    
    print("  All HybridSignatureVerifier tests PASSED\n")


def test_hybrid_kem_encapsulator():
    """Test hybrid KEM encapsulation"""
    print("Testing HybridKEMEncapsulator...")
    
    kem = HybridKEMEncapsulator()
    public_key = "test_public_key_for_kem"
    private_key = "test_private_key_for_kem"
    
    # Test all KEM algorithms
    algorithms = [
        KEMAlgorithm.KYBER_512,
        KEMAlgorithm.KYBER_768,
        KEMAlgorithm.KYBER_1024,
        KEMAlgorithm.HYBRID_ECDH_KYBER
    ]
    
    for algo in algorithms:
        ciphertext, shared_secret, security = kem.encapsulate(public_key, algo)
        assert ciphertext != "", "Ciphertext should not be empty"
        assert shared_secret != "", "Shared secret should not be empty"
        assert security >= 128, f"Security level should be >= 128 for {algo.value}"
        print(f"  ✓ {algo.value} encapsulation (security={security} bits): PASS")
    
    # Test decapsulation
    ciphertext, _, _ = kem.encapsulate(public_key, KEMAlgorithm.KYBER_768)
    decapsulated = kem.decapsulate(ciphertext, private_key, KEMAlgorithm.KYBER_768)
    assert decapsulated is not None, "Decapsulation should succeed"
    print("  ✓ Decapsulation: PASS")
    
    print("  All HybridKEMEncapsulator tests PASSED\n")


def test_certificate_revocation_list():
    """Test CRL functionality"""
    print("Testing CertificateRevocationList...")
    
    crl = CertificateRevocationList()
    
    assert crl.is_revoked("cert_123") == False, "Should not be revoked initially"
    print("  ✓ Initial non-revoked status: PASS")
    
    crl.revoke("cert_123", "compromised")
    assert crl.is_revoked("cert_123") == True, "Should be revoked after revocation"
    assert crl.get_revocation_time("cert_123") is not None, "Should have revocation time"
    print("  ✓ Revocation and checking: PASS")
    
    print("  All CRL tests PASSED\n")


def test_certificate_chain_builder_basic():
    """Test basic certificate chain building"""
    print("Testing PostQuantumCertificateChainBuilder (basic)...")
    
    builder = PostQuantumCertificateChainBuilder()
    
    # Create root CA (self-signed trust anchor)
    root_ca = Certificate(
        cert_id="root_ca_001",
        subject="Root CA - QuantumCrypt",
        issuer="Root CA - QuantumCrypt",
        public_key="root_ca_public_key",
        signature="root_self_signed_signature",
        signature_algorithm=SignatureAlgorithm.HYBRID_ECDSA_DILITHIUM,
        is_ca=True,
        kem_algorithm=KEMAlgorithm.HYBRID_ECDH_KYBER
    )
    builder.add_trust_anchor(root_ca)
    
    stats = builder.get_statistics()
    assert stats['trust_anchors'] == 1, "Should have 1 trust anchor"
    print("  ✓ Trust anchor added: PASS")
    
    # Issue intermediate CA
    intermediate_ca = builder.issue_certificate(
        subject="Intermediate CA - QuantumCrypt",
        issuer_cert=root_ca,
        issuer_private_key="root_ca_private_key",
        is_ca=True,
        signature_algorithm=SignatureAlgorithm.HYBRID_ECDSA_DILITHIUM,
        validity_days=180
    )
    
    assert intermediate_ca.issuer == root_ca.subject, "Issuer mismatch"
    assert intermediate_ca.is_ca == True, "Intermediate should be CA"
    print("  ✓ Intermediate CA issued: PASS")
    
    # Issue end-entity certificate
    end_entity = builder.issue_certificate(
        subject="api.quantumcrypt.example.com",
        issuer_cert=intermediate_ca,
        issuer_private_key="intermediate_ca_private_key",
        is_ca=False,
        signature_algorithm=SignatureAlgorithm.HYBRID_ECDSA_DILITHIUM,
        validity_days=90
    )
    
    assert end_entity.issuer == intermediate_ca.subject, "Issuer mismatch"
    assert end_entity.is_ca == False, "End entity should not be CA"
    print("  ✓ End entity certificate issued: PASS")
    
    stats = builder.get_statistics()
    assert stats['total_certificates'] == 3, "Should have 3 certificates total"
    print("  ✓ Certificate count correct: PASS")
    
    print("  All basic chain builder tests PASSED\n")


def test_certificate_chain_building_and_validation():
    """Test full chain building and validation"""
    print("Testing PostQuantumCertificateChainBuilder (chain validation)...")
    
    builder = PostQuantumCertificateChainBuilder()
    
    # Create complete PKI hierarchy
    root_ca = Certificate(
        cert_id="root_ca",
        subject="Root Trust Anchor",
        issuer="Root Trust Anchor",
        public_key="root_pubkey",
        signature="root_sig",
        signature_algorithm=SignatureAlgorithm.HYBRID_ECDSA_DILITHIUM,
        is_ca=True
    )
    builder.add_trust_anchor(root_ca)
    
    # Issue intermediate
    intermediate = builder.issue_certificate(
        subject="Intermediate CA",
        issuer_cert=root_ca,
        issuer_private_key="root_privkey",
        is_ca=True
    )
    
    # Issue end entity
    end_entity = builder.issue_certificate(
        subject="server.example.com",
        issuer_cert=intermediate,
        issuer_private_key="intermediate_privkey",
        is_ca=False
    )
    
    # Build and validate chain
    chain, result = builder.build_chain(end_entity.cert_id)
    
    assert len(chain) == 3, f"Chain should have 3 certificates, got {len(chain)}"
    assert chain[0].subject == "server.example.com", "First should be end entity"
    assert chain[-1].subject == "Root Trust Anchor", "Last should be root CA"
    print("  ✓ Chain built correctly (3 levels): PASS")
    
    # Check validation result structure
    assert result.chain_length == 3, "Chain length mismatch"
    assert 'algorithm_security' in result.details, "Should have security details"
    assert 'post_quantum_ready' in result.details, "Should have PQ ready flag"
    print("  ✓ Validation result structure complete: PASS")
    
    # Check post-quantum status
    assert result.details['post_quantum_ready'] == True, "Should be post-quantum ready"
    pq_pct = result.details['algorithm_security']['post_quantum_percentage']
    assert pq_pct == 100, f"Should be 100% post-quantum, got {pq_pct}%"
    print(f"  ✓ Post-quantum ready ({pq_pct}%): PASS")
    
    print("  All chain validation tests PASSED\n")


def test_expiration_monitoring():
    """Test certificate expiration monitoring"""
    print("Testing expiration monitoring...")
    
    builder = PostQuantumCertificateChainBuilder()
    
    root_ca = Certificate(
        cert_id="root_ca",
        subject="Root CA",
        issuer="Root CA",
        public_key="root_pub",
        signature="root_sig",
        signature_algorithm=SignatureAlgorithm.DILITHIUM_3,
        is_ca=True
    )
    builder.add_trust_anchor(root_ca)
    
    # Issue certificate expiring soon (15 days)
    soon_expiring = builder.issue_certificate(
        subject="soon.expiring.com",
        issuer_cert=root_ca,
        issuer_private_key="root_priv",
        validity_days=15
    )
    
    # Issue certificate valid for long time (365 days)
    long_valid = builder.issue_certificate(
        subject="long.valid.com",
        issuer_cert=root_ca,
        issuer_private_key="root_priv",
        validity_days=365
    )
    
    # Check expiring certificates within 30 days
    expiring = builder.get_expiring_certificates(days_threshold=30)
    assert len(expiring) >= 1, "Should find at least 1 expiring certificate"
    
    soon_found = any(e['subject'] == "soon.expiring.com" for e in expiring)
    assert soon_found, "Soon expiring certificate should be found"
    print("  ✓ Expiring certificate detection: PASS")
    
    long_found = any(e['subject'] == "long.valid.com" for e in expiring)
    assert not long_found, "Long valid certificate should not be in expiring list"
    print("  ✓ Non-expiring certificate not flagged: PASS")
    
    print("  All expiration monitoring tests PASSED\n")


def test_statistics():
    """Test statistics generation"""
    print("Testing statistics generation...")
    
    builder = PostQuantumCertificateChainBuilder()
    
    stats = builder.get_statistics()
    assert stats['engine_version'] == "v1.0.0", "Version mismatch"
    assert stats['trust_anchors'] == 0, "Initial trust anchors should be 0"
    assert stats['total_certificates'] == 0, "Initial certs should be 0"
    assert len(stats['supported_signature_algorithms']) > 0, "Should support algorithms"
    print("  ✓ Initial statistics: PASS")
    
    # Add some certificates
    root = Certificate(
        cert_id="root",
        subject="Root",
        issuer="Root",
        public_key="pub",
        signature="sig",
        signature_algorithm=SignatureAlgorithm.DILITHIUM_3,
        is_ca=True
    )
    builder.add_trust_anchor(root)
    
    builder.issue_certificate("test.com", root, "priv", validity_days=30)
    
    stats = builder.get_statistics()
    assert stats['trust_anchors'] == 1, "Trust anchor count mismatch"
    assert stats['total_certificates'] == 2, "Total certs mismatch"
    print("  ✓ Updated statistics: PASS")
    
    print("  All statistics tests PASSED\n")


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("QuantumCrypt-AI: Certificate Chain Builder Test Suite")
    print("=" * 60 + "\n")
    
    test_cases = [
        test_certificate_dataclass,
        test_hybrid_signature_verifier,
        test_hybrid_kem_encapsulator,
        test_certificate_revocation_list,
        test_certificate_chain_builder_basic,
        test_certificate_chain_building_and_validation,
        test_expiration_monitoring,
        test_statistics
    ]
    
    passed = 0
    failed = 0
    results = []
    
    for test in test_cases:
        try:
            test()
            passed += 1
            results.append({"test": test.__name__, "status": "PASSED"})
        except AssertionError as e:
            failed += 1
            results.append({"test": test.__name__, "status": "FAILED", "error": str(e)})
            print(f"  FAILED: {e}\n")
        except Exception as e:
            failed += 1
            results.append({"test": test.__name__, "status": "ERROR", "error": str(e)})
            print(f"  ERROR: {e}\n")
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save results
    with open('test_results_certificate_chain_builder_2026_june.json', 'w') as f:
        json.dump({
            "test_suite": "PostQuantumCertificateChainBuilder",
            "timestamp": time.time(),
            "passed": passed,
            "failed": failed,
            "total": passed + failed,
            "results": results
        }, f, indent=2)
    
    print(f"\nResults saved to test_results_certificate_chain_builder_2026_june.json")
    
    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
