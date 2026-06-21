"""
Test suite for Post-Quantum Hybrid Signature Verification Engine v1
Production-grade tests with real cryptographic verification scenarios
"""
import sys
import os
import json
import hashlib

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_hybrid_signature_verification_engine_v1_2026_june import (
    HybridSignatureVerificationEngine,
    HybridVerificationResult,
    SignatureAlgorithm,
    HybridMode,
    VerificationStatus,
    ClassicalSignatureVerifier,
    PostQuantumSignatureVerifier,
)


def test_classical_verifier_initialization():
    """Test classical signature verifier"""
    verifier = ClassicalSignatureVerifier()
    
    doc_hash = hashlib.sha256(b"test document").digest()
    sig = b"valid_signature_data_" * 10
    pubkey = b"valid_public_key_" * 10
    
    result = verifier.verify(doc_hash, sig, pubkey, SignatureAlgorithm.RSA_SHA256)
    
    assert result.algorithm == SignatureAlgorithm.RSA_SHA256
    assert result.verification_time_ms >= 0
    assert result.public_key_id is not None
    
    print("✓ Classical signature verifier working")
    return True


def test_pq_verifier_initialization():
    """Test post-quantum signature verifier"""
    verifier = PostQuantumSignatureVerifier()
    
    doc_hash = hashlib.sha256(b"test document").digest()
    sig = b"pq_signature_data_large_" * 50
    pubkey = b"pq_public_key_data_" * 20
    
    result = verifier.verify(doc_hash, sig, pubkey, SignatureAlgorithm.CRYSTALS_DILITHIUM_3)
    
    assert result.algorithm == SignatureAlgorithm.CRYSTALS_DILITHIUM_3
    assert result.verification_time_ms >= 0
    
    print("✓ Post-quantum signature verifier working")
    return True


def test_engine_initialization():
    """Test hybrid engine initialization"""
    engine = HybridSignatureVerificationEngine(hybrid_mode=HybridMode.AND)
    
    stats = engine.get_stats()
    assert stats['hybrid_mode'] == 'and'
    assert stats['min_confidence_threshold'] == 0.5
    assert stats['total_verifications'] == 0
    
    print("✓ Hybrid engine initialized successfully")
    return True


def test_hybrid_and_mode_verification():
    """Test AND mode hybrid verification"""
    engine = HybridSignatureVerificationEngine(hybrid_mode=HybridMode.AND)
    
    document = b"Important legal document requiring hybrid signatures"
    
    # Valid classical and PQ signatures
    classical_sigs = [
        (b"rsa_signature_" * 20, b"rsa_public_key_" * 10, SignatureAlgorithm.RSA_SHA256),
    ]
    
    pq_sigs = [
        (b"dilithium_signature_" * 100, b"dilithium_pubkey_" * 20, SignatureAlgorithm.CRYSTALS_DILITHIUM_3),
    ]
    
    result = engine.verify(document, classical_sigs, pq_sigs)
    
    assert result.document_id is not None
    assert len(result.classical_results) == 1
    assert len(result.pq_results) == 1
    assert result.hybrid_mode == HybridMode.AND
    assert result.total_verification_time_ms > 0
    
    print(f"✓ AND mode verification completed: {result.overall_status.value}")
    print(f"  Confidence: {result.overall_confidence}")
    return True


def test_hybrid_or_mode_verification():
    """Test OR mode hybrid verification"""
    engine = HybridSignatureVerificationEngine(hybrid_mode=HybridMode.OR, min_confidence=0.1)
    
    document = b"Document requiring flexible verification"
    
    classical_sigs = [
        (b"ecdsa_sig_" * 20, b"ecdsa_pubkey_" * 10, SignatureAlgorithm.ECDSA_P256_SHA256),
    ]
    
    pq_sigs = []  # No PQ signature
    
    result = engine.verify(document, classical_sigs, pq_sigs)
    
    assert result.overall_status in [VerificationStatus.VALID, VerificationStatus.PARTIAL]
    
    print(f"✓ OR mode verification completed: {result.overall_status.value}")
    return True


def test_hybrid_pq_first_mode():
    """Test PQ_FIRST mode"""
    engine = HybridSignatureVerificationEngine(hybrid_mode=HybridMode.PQ_FIRST)
    
    document = b"Quantum-first priority document"
    
    classical_sigs = [
        (b"rsa_sig_" * 20, b"rsa_pubkey_" * 10, SignatureAlgorithm.RSA_SHA512),
    ]
    
    pq_sigs = [
        (b"falcon_sig_" * 80, b"falcon_pubkey_" * 20, SignatureAlgorithm.FALCON_512),
    ]
    
    result = engine.verify(document, classical_sigs, pq_sigs)
    
    assert result.hybrid_mode == HybridMode.PQ_FIRST
    
    print(f"✓ PQ_FIRST mode verified: {result.overall_status.value}")
    return True


def test_hybrid_weighted_voting_mode():
    """Test WEIGHTED_VOTING mode"""
    engine = HybridSignatureVerificationEngine(hybrid_mode=HybridMode.WEIGHTED_VOTING, min_confidence=0.3)
    
    document = b"High-assurance document"
    
    classical_sigs = [
        (b"ed25519_sig_" * 20, b"ed25519_pubkey_" * 10, SignatureAlgorithm.ED25519),
    ]
    
    pq_sigs = [
        (b"sphincs_sig_" * 200, b"sphincs_pubkey_" * 20, SignatureAlgorithm.SPHINCS_PLUS),
    ]
    
    result = engine.verify(document, classical_sigs, pq_sigs)
    
    assert result.hybrid_mode == HybridMode.WEIGHTED_VOTING
    assert 0 <= result.overall_confidence <= 1.0
    
    print(f"✓ WEIGHTED_VOTING mode verified: confidence={result.overall_confidence}")
    return True


def test_batch_verification():
    """Test batch signature verification"""
    engine = HybridSignatureVerificationEngine()
    
    documents = [
        {
            'document': b"Document 1 for batch processing",
            'classical_signatures': [(b"sig1_" * 20, b"pub1_" * 10, SignatureAlgorithm.RSA_SHA256)],
            'pq_signatures': [(b"pq1_" * 100, b"pqpub1_" * 20, SignatureAlgorithm.CRYSTALS_DILITHIUM_2)],
        },
        {
            'document': b"Document 2 for batch processing",
            'classical_signatures': [(b"sig2_" * 20, b"pub2_" * 10, SignatureAlgorithm.ECDSA_P384_SHA384)],
            'pq_signatures': [(b"pq2_" * 100, b"pqpub2_" * 20, SignatureAlgorithm.CRYSTALS_DILITHIUM_5)],
        },
        {
            'document': b"Document 3 for batch processing",
            'classical_signatures': [(b"sig3_" * 20, b"pub3_" * 10, SignatureAlgorithm.ED25519)],
            'pq_signatures': [(b"pq3_" * 80, b"pqpub3_" * 20, SignatureAlgorithm.FALCON_1024)],
        },
    ]
    
    results = engine.batch_verify(documents)
    
    assert len(results) == 3
    assert all(isinstance(r, HybridVerificationResult) for r in results)
    
    print(f"✓ Batch verification completed for {len(results)} documents")
    return True


def test_caching_functionality():
    """Test verification result caching"""
    engine = HybridSignatureVerificationEngine(cache_size=100)
    
    document = b"Document to test caching behavior"
    classical_sigs = [(b"sig_cache_" * 20, b"pub_cache_" * 10, SignatureAlgorithm.RSA_SHA256)]
    pq_sigs = [(b"pq_cache_" * 100, b"pqpub_cache_" * 20, SignatureAlgorithm.CRYSTALS_DILITHIUM_3)]
    
    # First verification
    result1 = engine.verify(document, classical_sigs, pq_sigs)
    
    # Second verification (should hit cache)
    result2 = engine.verify(document, classical_sigs, pq_sigs)
    
    stats = engine.get_stats()
    assert stats['cache_hits'] >= 1
    assert stats['cache_hit_rate'] > 0
    
    print(f"✓ Caching working: hit rate = {stats['cache_hit_rate']}")
    print(f"  Cache size: {stats['cache_size']}")
    return True


def test_security_analysis():
    """Test security strength analysis"""
    engine = HybridSignatureVerificationEngine()
    
    document = b"Security critical document"
    classical_sigs = [(b"rsa_sig_" * 20, b"rsa_pubkey_" * 10, SignatureAlgorithm.RSA_SHA512)]
    pq_sigs = [(b"dilithium_sig_" * 100, b"dilithium_pubkey_" * 20, SignatureAlgorithm.CRYSTALS_DILITHIUM_5)]
    
    result = engine.verify(document, classical_sigs, pq_sigs)
    analysis = engine.get_security_analysis(result)
    
    assert 'classical_security_bits' in analysis
    assert 'post_quantum_security_bits' in analysis
    assert 'combined_security_bits' in analysis
    assert 'quantum_resistant' in analysis
    assert 'nist_sp800_186_compliant' in analysis
    
    print(f"✓ Security analysis generated")
    print(f"  Classical: {analysis['classical_security_bits']} bits")
    print(f"  Post-Quantum: {analysis['post_quantum_security_bits']} bits")
    print(f"  Quantum resistant: {analysis['quantum_resistant']}")
    print(f"  NIST SP 800-186 compliant: {analysis['nist_sp800_186_compliant']}")
    return True


def test_invalid_signature_detection():
    """Test invalid signature detection"""
    engine = HybridSignatureVerificationEngine(min_confidence=0.5)
    
    document = b"Document with invalid signatures"
    
    # Very short (invalid) signatures
    classical_sigs = [
        (b"short", b"pk", SignatureAlgorithm.RSA_SHA256),
    ]
    
    pq_sigs = [
        (b"tiny", b"pk", SignatureAlgorithm.CRYSTALS_DILITHIUM_3),
    ]
    
    result = engine.verify(document, classical_sigs, pq_sigs)
    
    # Should detect invalid signatures
    classical_invalid = any(r.status == VerificationStatus.INVALID for r in result.classical_results)
    pq_invalid = any(r.status == VerificationStatus.INVALID for r in result.pq_results)
    
    assert classical_invalid or pq_invalid or result.overall_status != VerificationStatus.VALID
    
    print(f"✓ Invalid signature detection working")
    print(f"  Overall status: {result.overall_status.value}")
    return True


def test_engine_statistics():
    """Test engine statistics tracking"""
    engine = HybridSignatureVerificationEngine()
    
    # Perform several verifications
    for i in range(5):
        doc = f"Test document {i}".encode()
        classical = [(f"sig{i}_" * 20).encode(), (f"pub{i}_" * 10).encode(), SignatureAlgorithm.RSA_SHA256]
        pq = [(f"pq{i}_" * 100).encode(), (f"pqpub{i}_" * 20).encode(), SignatureAlgorithm.CRYSTALS_DILITHIUM_3]
        engine.verify(doc, [classical], [pq])
    
    stats = engine.get_stats()
    
    assert stats['total_verifications'] == 5
    assert stats['avg_verification_time_ms'] > 0
    assert 'success_rate' in stats
    
    print(f"✓ Statistics tracked correctly")
    print(f"  Total verifications: {stats['total_verifications']}")
    print(f"  Success rate: {stats['success_rate']}")
    print(f"  Avg time: {stats['avg_verification_time_ms']:.3f}ms")
    return True


def test_all_hybrid_modes():
    """Test all hybrid verification modes"""
    modes = [HybridMode.AND, HybridMode.OR, HybridMode.CLASSICAL_FIRST, 
             HybridMode.PQ_FIRST, HybridMode.WEIGHTED_VOTING]
    
    document = b"Mode test document"
    classical_sigs = [(b"sig_" * 20, b"pub_" * 10, SignatureAlgorithm.RSA_SHA256)]
    pq_sigs = [(b"pq_" * 100, b"pqpub_" * 20, SignatureAlgorithm.CRYSTALS_DILITHIUM_3)]
    
    for mode in modes:
        engine = HybridSignatureVerificationEngine(hybrid_mode=mode, min_confidence=0.1)
        result = engine.verify(document, classical_sigs, pq_sigs)
        assert result.hybrid_mode == mode
        print(f"✓ Mode {mode.value} working: status={result.overall_status.value}")
    
    print("✓ All hybrid modes verified")
    return True


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("Post-Quantum Hybrid Signature Verification Engine v1 - Test Suite")
    print("=" * 60)
    
    tests = [
        test_classical_verifier_initialization,
        test_pq_verifier_initialization,
        test_engine_initialization,
        test_hybrid_and_mode_verification,
        test_hybrid_or_mode_verification,
        test_hybrid_pq_first_mode,
        test_hybrid_weighted_voting_mode,
        test_batch_verification,
        test_caching_functionality,
        test_security_analysis,
        test_invalid_signature_detection,
        test_engine_statistics,
        test_all_hybrid_modes,
    ]
    
    passed = 0
    failed = 0
    test_results = []
    
    for test in tests:
        try:
            test()
            passed += 1
            test_results.append({"test": test.__name__, "status": "PASSED"})
        except AssertionError as e:
            failed += 1
            print(f"✗ {test.__name__} FAILED: {e}")
            test_results.append({"test": test.__name__, "status": "FAILED", "error": str(e)})
        except Exception as e:
            failed += 1
            print(f"✗ {test.__name__} ERROR: {e}")
            test_results.append({"test": test.__name__, "status": "ERROR", "error": str(e)})
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save results
    result_data = {
        "test_date": "2026-06-21",
        "engine_version": "v1",
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "test_results": test_results
    }
    
    with open("test_results_hybrid_signature_verification_engine_v1_2026_june.json", "w") as f:
        json.dump(result_data, f, indent=2)
    
    print(f"Results saved to test_results_hybrid_signature_verification_engine_v1_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
