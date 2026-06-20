#!/usr/bin/env python3
"""
Test suite for Post-Quantum Algorithm Interoperability Matrix Generator
June 20, 2026 - Real production tests
"""

import json
import sys

sys.path.insert(0, '.')

from quantum_crypt.post_quantum_algorithm_interoperability_matrix_generator_2026_june import (
    PQAlgorithmInteroperabilityMatrixGenerator,
    PQAlgorithm,
    PQAlgorithmType,
    SecurityLevel,
    ImplementationLibrary,
    create_interop_matrix_generator,
    verify_interop_matrix_generator
)


def run_all_tests():
    """Run all real tests"""
    print("=" * 60)
    print("Testing PQ Algorithm Interoperability Matrix Generator")
    print("=" * 60)
    
    results = []
    
    # Test 1: Basic initialization
    print("\n[TEST 1] Basic initialization")
    try:
        generator = create_interop_matrix_generator()
        assert len(generator.algorithms) > 0, "Algorithms should be initialized"
        print(f"  ✓ Generator initialized with {len(generator.algorithms)} algorithms")
        results.append(("Initialization", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Initialization", False))
    
    # Test 2: Algorithm metadata
    print("\n[TEST 2] Algorithm metadata retrieval")
    try:
        generator = create_interop_matrix_generator()
        kyber = generator.get_algorithm_metadata(PQAlgorithm.KYBER_768)
        assert kyber is not None
        assert kyber.security_level == SecurityLevel.LEVEL_3
        assert kyber.nist_status == "standard"
        print(f"  ✓ Kyber-768 metadata loaded correctly")
        results.append(("Algorithm Metadata", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Algorithm Metadata", False))
    
    # Test 3: Algorithms by type
    print("\n[TEST 3] Get algorithms by type")
    try:
        generator = create_interop_matrix_generator()
        kems = generator.get_algorithms_by_type(PQAlgorithmType.KEY_ENCAPSULATION)
        sigs = generator.get_algorithms_by_type(PQAlgorithmType.DIGITAL_SIGNATURE)
        assert len(kems) > 0
        assert len(sigs) > 0
        print(f"  ✓ Found {len(kems)} KEMs, {len(sigs)} signatures")
        results.append(("Filter by Type", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Filter by Type", False))
    
    # Test 4: Interoperability score calculation
    print("\n[TEST 4] Interoperability score calculation")
    try:
        generator = create_interop_matrix_generator()
        score = generator.calculate_interoperability_score(
            PQAlgorithm.KYBER_768,
            ImplementationLibrary.OPENSSL_3_2,
            ImplementationLibrary.LIBOQS
        )
        assert score >= 0.0 and score <= 1.0
        print(f"  ✓ Interop score calculated: {score:.2f}")
        results.append(("Interop Score", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Interop Score", False))
    
    # Test 5: Run interoperability tests
    print("\n[TEST 5] Run interoperability tests")
    try:
        generator = create_interop_matrix_generator()
        test_results = generator.run_interoperability_tests(
            algorithms=[PQAlgorithm.KYBER_768, PQAlgorithm.DILITHIUM_3]
        )
        assert len(test_results) > 0
        print(f"  ✓ Ran {len(test_results)} interoperability tests")
        results.append(("Interop Tests", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Interop Tests", False))
    
    # Test 6: Generate matrix
    print("\n[TEST 6] Generate interoperability matrix")
    try:
        generator = create_interop_matrix_generator()
        matrix = generator.generate_interoperability_matrix(PQAlgorithm.KYBER_768)
        assert "matrix" in matrix
        assert "libraries" in matrix
        print(f"  ✓ Matrix generated for {matrix['algorithm']}")
        results.append(("Matrix Generation", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Matrix Generation", False))
    
    # Test 7: Generate Markdown matrix
    print("\n[TEST 7] Generate Markdown matrix")
    try:
        generator = create_interop_matrix_generator()
        md = generator.generate_markdown_matrix(PQAlgorithm.KYBER_768)
        assert len(md) > 0
        assert "Interoperability Matrix" in md
        print(f"  ✓ Markdown matrix generated ({len(md)} chars)")
        results.append(("Markdown Matrix", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Markdown Matrix", False))
    
    # Test 8: Migration recommendations
    print("\n[TEST 8] Migration recommendations")
    try:
        generator = create_interop_matrix_generator()
        recs = generator.generate_migration_recommendations(PQAlgorithm.X25519)
        assert len(recs) > 0
        print(f"  ✓ Generated {len(recs)} migration recommendations")
        results.append(("Migration Recommendations", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Migration Recommendations", False))
    
    # Test 9: Comparison report
    print("\n[TEST 9] Comparison report")
    try:
        generator = create_interop_matrix_generator()
        report = generator.generate_comparison_report()
        assert "summary" in report
        assert "kem_comparison" in report
        assert "signature_comparison" in report
        print(f"  ✓ Comparison report generated")
        print(f"    - Total algorithms: {report['summary']['total_algorithms']}")
        print(f"    - NIST Standard: {report['summary']['nist_standard']}")
        results.append(("Comparison Report", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Comparison Report", False))
    
    # Test 10: Full verification
    print("\n[TEST 10] Full verification suite")
    try:
        verify_result = verify_interop_matrix_generator()
        assert verify_result["test_passed"] == True
        print(f"  ✓ Full verification passed")
        print(f"    - Algorithms loaded: {verify_result['algorithms_loaded']}")
        print(f"    - Interop tests: {verify_result['interop_tests_run']}")
        results.append(("Full Verification", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        results.append(("Full Verification", False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    
    for name, ok in results:
        status = "✓ PASS" if ok else "✗ FAIL"
        print(f"  {status} - {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ ALL TESTS PASSED - Production ready!")
        return 0
    else:
        print(f"\n✗ {total - passed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
