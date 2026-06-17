"""
Test Suite for NIST Round 4 Signatures 2026
Tests based on NIST May 2026 PQC updates
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.nist_round4_signatures_2026 import (
    NISTPQCUpdate2026,
    PQCTLS13,
    MigrationReadinessAuditor
)
import json
import time


def test_nist_2026_updates():
    """Test NIST 2026 PQC updates"""
    print("=" * 60)
    print("Testing NIST PQC 2026 Updates (May 2026 Round 3)")
    print("=" * 60)

    pqc = NISTPQCUpdate2026()

    # Test 1: FIPS 203 ML-KEM
    print("\n1. Testing FIPS 203 (ML-KEM) status...")
    status = pqc.get_algorithm_status('ML-KEM')
    print(f"   ML-KEM: {status['status']}, NIST Approved: {status['nist_approved']}")
    assert status['nist_approved'] == True
    assert status['status'] == 'PUBLISHED'

    # Test 2: FIPS 204 ML-DSA
    print("\n2. Testing FIPS 204 (ML-DSA) status...")
    status = pqc.get_algorithm_status('ML-DSA')
    print(f"   ML-DSA: {status['status']}, Security Levels: {status['security_levels']}")
    assert status['nist_approved'] == True

    # Test 3: FIPS 205 SLH-DSA
    print("\n3. Testing FIPS 205 (SLH-DSA) status...")
    status = pqc.get_algorithm_status('SLH-DSA')
    print(f"   SLH-DSA: {status['status']}, Quantum Resistance: {status['quantum_resistance']}")
    assert status['nist_approved'] == True

    # Test 4: FIPS 206 Draft (FN-DSA)
    print("\n4. Testing FIPS 206 Draft (FN-DSA)...")
    status = pqc.get_algorithm_status('FN-DSA')
    print(f"   FN-DSA: {status['status']}, Expected Final: {status.get('expected_final', 'N/A')}")
    print(f"   Benefit: {status.get('benefit', 'N/A')}")

    # Test 5: Round 3 Additional Signatures (May 2026)
    print("\n5. Testing Round 3 Additional Signature Candidates...")
    for candidate in pqc.round3_candidates[:3]:  # Test first 3
        status = pqc.get_algorithm_status(candidate)
        print(f"   {candidate}: {status['status']}, Category: {status['category']}")
        assert status['round'] == 3

    # Test 6: FIPS 206 Key Generation
    print("\n6. Testing FIPS 206 (FN-DSA) key generation...")
    priv_key, pub_key, metadata = pqc.generate_fips206_keypair(512)
    print(f"   Private key size: {len(priv_key)} bytes")
    print(f"   Public key size: {len(pub_key)} bytes")
    print(f"   Expected signature size: {metadata['expected_signature_size']} bytes")
    assert len(priv_key) > 0
    assert len(pub_key) > 0

    print("\n✅ NIST 2026 Updates tests PASSED")
    return True


def test_compliance_verification():
    """Test compliance verification"""
    print("\n" + "=" * 60)
    print("Testing NIST Compliance Verification (2026 Regulatory)")
    print("=" * 60)

    pqc = NISTPQCUpdate2026()

    # Test compliance for standardized algorithms
    print("\n1. ML-KEM Compliance Check:")
    compliance = pqc.verify_compliance('ML-KEM')
    print(f"   Overall Compliant: {compliance['overall_compliant']}")
    print(f"   TLS 1.3 Ready: {compliance['compliance_checks']['tls_1_3_ready']}")
    print(f"   CNSA 2.0 Eligible: {compliance['compliance_checks']['cnsa_2_0_eligible']}")
    assert compliance['overall_compliant'] == True

    # Test compliance for draft algorithm
    print("\n2. FN-DSA (FIPS 206 Draft) Compliance Check:")
    compliance = pqc.verify_compliance('FN-DSA')
    print(f"   Overall Compliant: {compliance['overall_compliant']}")
    print(f"   Recommendations: {compliance['recommendations'][:2]}")

    # Test regulatory timeline
    print("\n3. Regulatory Timeline:")
    compliance = pqc.verify_compliance('ML-DSA')
    print(f"   TLS Mandatory By: {compliance['regulatory_timeline']['tls_mandatory']}")
    print(f"   CNSA Deadline: {compliance['regulatory_timeline']['cnsa_deadline']}")

    print("\n✅ Compliance Verification tests PASSED")
    return True


def test_pqc_tls13():
    """Test PQC TLS 1.3 implementation"""
    print("\n" + "=" * 60)
    print("Testing Post-Quantum TLS 1.3 (2026 Browser Deployment)")
    print("=" * 60)

    tls = PQCTLS13()

    # Test 1: Deployment status
    print("\n1. 2026 Browser Deployment Status:")
    deployment = tls.get_deployment_status()
    for browser, status in deployment.items():
        if browser != 'deployment_estimate':
            print(f"   {browser.title()}: {status}")
    print(f"   Global: {deployment['deployment_estimate']}")

    # Test 2: Handshake simulation
    print("\n2. PQC TLS 1.3 Handshake:")
    client_hello = {
        'cipher_suites': [
            'TLS_AES_256_GCM_SHA384_WITH_ML_KEM_768',
            'TLS_AES_128_GCM_SHA256'
        ]
    }
    success, result = tls.perform_pqc_handshake(client_hello)
    print(f"   Handshake Success: {success}")
    print(f"   Selected Cipher: {result['selected_cipher_suite']}")
    print(f"   Key Exchange: {result['key_exchange']}")
    print(f"   Browser Compatible: {result['browser_compatible']}")
    assert success == True

    # Test 3: Unsupported cipher suite
    print("\n3. Unsupported cipher suite fallback:")
    client_hello_old = {'cipher_suites': ['TLS_RSA_WITH_AES_256_CBC_SHA']}
    success, result = tls.perform_pqc_handshake(client_hello_old)
    print(f"   Handshake Success: {success}")
    assert success == False  # Should fail - no PQC support

    print("\n✅ PQC TLS 1.3 tests PASSED")
    return True


def test_migration_readiness():
    """Test migration readiness auditor"""
    print("\n" + "=" * 60)
    print("Testing PQC Migration Readiness Auditor (2026 Roadmap)")
    print("=" * 60)

    auditor = MigrationReadinessAuditor()

    # Test 1: Advanced organization
    print("\n1. Advanced Organization Assessment:")
    advanced_profile = {
        'crypto_inventory_complete': True,
        'crypto_agility': True,
        'hybrid_mode': True,
        'pqc_training': True,
        'pilot_completed': True
    }
    result = auditor.assess_readiness(advanced_profile)
    print(f"   Score: {result['readiness_score']}/100")
    print(f"   Level: {result['readiness_level']}")
    print(f"   Phase: {result['phase']}")
    print(f"   Migration Timeline: {result['timeline_projection']['full_migration']}")
    assert result['readiness_level'] == 'ADVANCED'

    # Test 2: Beginner organization
    print("\n2. Beginner Organization Assessment:")
    beginner_profile = {
        'crypto_inventory_complete': False,
        'crypto_agility': False,
        'hybrid_mode': False,
        'pqc_training': False,
        'pilot_completed': False
    }
    result = auditor.assess_readiness(beginner_profile)
    print(f"   Score: {result['readiness_score']}/100")
    print(f"   Level: {result['readiness_level']}")
    print(f"   Gaps: {result['gap_analysis'][:3]}")

    # Test 3: 2026 Migration Checklist
    print("\n3. 2026 Migration Checklist:")
    checklist = auditor.generate_2026_migration_checklist()
    for item in checklist[:5]:
        print(f"   {item}")

    print("\n✅ Migration Readiness tests PASSED")
    return True


def run_benchmark():
    """Run performance benchmark"""
    print("\n" + "=" * 60)
    print("Running Performance Benchmark")
    print("=" * 60)

    pqc = NISTPQCUpdate2026()
    tls = PQCTLS13()

    iterations = 100

    # Benchmark algorithm status lookups
    start_time = time.time()
    for i in range(iterations):
        pqc.get_algorithm_status('ML-KEM')
    lookup_time = time.time() - start_time
    avg_lookup = lookup_time / iterations * 1000

    # Benchmark key generation
    start_time = time.time()
    for i in range(iterations):
        pqc.generate_fips206_keypair(512)
    keygen_time = time.time() - start_time
    avg_keygen = keygen_time / iterations * 1000

    # Benchmark TLS handshake
    start_time = time.time()
    client_hello = {'cipher_suites': ['TLS_AES_256_GCM_SHA384_WITH_ML_KEM_768']}
    for i in range(iterations):
        tls.perform_pqc_handshake(client_hello)
    handshake_time = time.time() - start_time
    avg_handshake = handshake_time / iterations * 1000

    print(f"\nBenchmark Results ({iterations} iterations):")
    print(f"  Algorithm lookup:  {avg_lookup:.3f} ms avg")
    print(f"  Key generation:    {avg_keygen:.3f} ms avg")
    print(f"  TLS handshake:     {avg_handshake:.3f} ms avg")
    print(f"  Total time:        {lookup_time + keygen_time + handshake_time:.3f}s")

    benchmark_results = {
        'algorithm_lookup_ms_avg': round(avg_lookup, 3),
        'key_generation_ms_avg': round(avg_keygen, 3),
        'tls_handshake_ms_avg': round(avg_handshake, 3),
        'iterations': iterations,
        'timestamp': str(time.time())
    }

    with open('benchmark_results_nist2026.json', 'w') as f:
        json.dump(benchmark_results, f, indent=2)

    print(f"\n✅ Benchmark complete - results saved")
    return benchmark_results


if __name__ == "__main__":
    print("Starting QuantumCrypt-AI 2026 Test Suite\n")

    all_passed = True

    try:
        all_passed &= test_nist_2026_updates()
        all_passed &= test_compliance_verification()
        all_passed &= test_pqc_tls13()
        all_passed &= test_migration_readiness()
        benchmark = run_benchmark()
    except AssertionError as e:
        print(f"\n❌ Test FAILED: {e}")
        all_passed = False
    except Exception as e:
        print(f"\n❌ Test ERROR: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("✅ ALL TESTS PASSED")
    else:
        print("❌ SOME TESTS FAILED")
    print("=" * 60)

    sys.exit(0 if all_passed else 1)
