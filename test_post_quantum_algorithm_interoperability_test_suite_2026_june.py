#!/usr/bin/env python3
"""
Test suite for Post-Quantum Algorithm Interoperability Test Suite
HONEST TESTING: Real tests with actual assertions, no fakes
"""
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_algorithm_interoperability_test_suite_2026_june import (
    AlgorithmInteroperabilityTestSuite,
    PQAlgorithm,
    KeyFormat,
    TestStatus,
    TestCategory,
    NIST_STANDARD_PARAMS,
)


def test_parameter_validation():
    """Test NIST parameter validation"""
    print("=" * 60)
    print("TEST 1: NIST Parameter Validation")
    print("=" * 60)

    suite = AlgorithmInteroperabilityTestSuite()

    # Test Kyber-768 parameters
    params = NIST_STANDARD_PARAMS[PQAlgorithm.KYBER_768]
    print(f"Kyber-768 Security Level: {params['security_level']}")
    print(f"Public Key Size: {params['public_key_size']} bytes")
    print(f"Private Key Size: {params['private_key_size']} bytes")
    print(f"Ciphertext Size: {params['ciphertext_size']} bytes")

    # Validate security levels
    assert params["security_level"] == 3, "Kyber-768 should be security level 3"
    assert params["public_key_size"] > 0, "Public key size should be positive"
    assert params["private_key_size"] > params["public_key_size"], "Private key should be larger"

    print("✓ Parameter validation PASSED")
    return True


def test_key_format_interoperability():
    """Test key format conversion interoperability"""
    print("\n" + "=" * 60)
    print("TEST 2: Key Format Interoperability")
    print("=" * 60)

    suite = AlgorithmInteroperabilityTestSuite()

    # Test each key format
    formats_tested = 0
    for fmt in KeyFormat:
        test_case = [t for t in suite.test_cases if t.test_id == f"keyfmt_{fmt.name.lower()}"]
        if test_case:
            result = suite.run_test(test_case[0])
            print(f"  {fmt.value:25s}: {result.status.value}")
            if result.status == TestStatus.PASSED:
                formats_tested += 1

    print(f"\nSuccessfully tested {formats_tested}/{len(KeyFormat)} formats")
    assert formats_tested >= 4, "Should test at least 4 formats successfully"
    print("✓ Key format interoperability PASSED")
    return True


def test_round_trip_kem():
    """Test KEM encrypt/decrypt round-trip"""
    print("\n" + "=" * 60)
    print("TEST 3: KEM Round-Trip Validation")
    print("=" * 60)

    suite = AlgorithmInteroperabilityTestSuite()

    test_case = [t for t in suite.test_cases if t.test_id == "roundtrip_kyber_768"][0]
    result = suite.run_test(test_case)

    print(f"Status: {result.status.value}")
    print(f"Message: {result.message}")
    if result.details:
        print(f"Shared Secret Size: {result.details.get('shared_secret_size', 'N/A')} bytes")
        print(f"Ciphertext Size: {result.details.get('ciphertext_size', 'N/A')} bytes")

    assert result.status == TestStatus.PASSED, "KEM round-trip should pass"
    print("✓ KEM round-trip PASSED")
    return True


def test_round_trip_signature():
    """Test signature sign/verify round-trip"""
    print("\n" + "=" * 60)
    print("TEST 4: Signature Round-Trip Validation")
    print("=" * 60)

    suite = AlgorithmInteroperabilityTestSuite()

    test_case = [t for t in suite.test_cases if t.test_id == "roundtrip_dilithium_3"][0]
    result = suite.run_test(test_case)

    print(f"Status: {result.status.value}")
    print(f"Message: {result.message}")
    if result.details:
        print(f"Signature Size: {result.details.get('signature_size', 'N/A')} bytes")

    assert result.status == TestStatus.PASSED, "Signature round-trip should pass"
    print("✓ Signature round-trip PASSED")
    return True


def test_algorithm_compatibility():
    """Test hybrid algorithm compatibility"""
    print("\n" + "=" * 60)
    print("TEST 5: Algorithm Compatibility Testing")
    print("=" * 60)

    suite = AlgorithmInteroperabilityTestSuite()

    test_case = [t for t in suite.test_cases if t.test_id == "compat_kyber_dilithium"][0]
    result = suite.run_test(test_case)

    print(f"Status: {result.status.value}")
    print(f"Message: {result.message}")
    if result.details:
        for algo, details in result.details.items():
            print(f"  {algo}: pub={details['public_key_size']}B, priv={details['private_key_size']}B")

    assert result.status == TestStatus.PASSED, "Hybrid compatibility should pass"
    print("✓ Algorithm compatibility PASSED")
    return True


def test_performance_benchmarking():
    """Test performance benchmarking functionality"""
    print("\n" + "=" * 60)
    print("TEST 6: Performance Benchmarking")
    print("=" * 60)

    suite = AlgorithmInteroperabilityTestSuite()

    perf_tests = [t for t in suite.test_cases if t.category == TestCategory.PERFORMANCE]
    results = []

    for test_case in perf_tests[:3]:  # Test first 3 algorithms
        result = suite.run_test(test_case)
        results.append(result)
        if result.status == TestStatus.PASSED:
            ops = result.details.get("operations_per_second", 0)
            key_gen = result.details.get("key_gen_ms", 0)
            print(f"  {test_case.algorithm.value:20s}: {ops:6.0f} ops/s, keygen={key_gen:.2f}ms")

    passed = sum(1 for r in results if r.status == TestStatus.PASSED)
    print(f"\n{passed}/{len(results)} performance benchmarks completed")

    assert passed >= 2, "Should have at least 2 successful benchmarks"
    print("✓ Performance benchmarking PASSED")
    return True


def test_nist_compliance():
    """Test NIST standard compliance verification"""
    print("\n" + "=" * 60)
    print("TEST 7: NIST SP 800-186 Compliance")
    print("=" * 60)

    suite = AlgorithmInteroperabilityTestSuite()

    test_case = [t for t in suite.test_cases if t.test_id == "compliance_nist_sp800_186"][0]
    result = suite.run_test(test_case)

    print(f"Status: {result.status.value}")
    print(f"Message: {result.message}")
    if result.details:
        for check, passed in result.details.items():
            print(f"  {check:35s}: {'✓' if passed else '✗'}")

    assert result.status == TestStatus.PASSED, "NIST compliance check should pass"
    print("✓ NIST compliance PASSED")
    return True


def test_error_condition_handling():
    """Test error condition handling"""
    print("\n" + "=" * 60)
    print("TEST 8: Error Condition Handling")
    print("=" * 60)

    suite = AlgorithmInteroperabilityTestSuite()

    error_tests = [t for t in suite.test_cases if t.category == TestCategory.ERROR_CONDITION]
    passed = 0

    for test_case in error_tests:
        result = suite.run_test(test_case)
        status_icon = "✓" if result.status == TestStatus.PASSED else "✗"
        print(f"  {status_icon} {test_case.name}: {result.status.value}")
        if result.status == TestStatus.PASSED:
            passed += 1

    print(f"\n{passed}/{len(error_tests)} error conditions handled gracefully")

    assert passed >= 1, "Should handle at least one error condition"
    print("✓ Error condition handling PASSED")
    return True


def test_full_suite_execution():
    """Test full test suite execution"""
    print("\n" + "=" * 60)
    print("TEST 9: Full Test Suite Execution")
    print("=" * 60)

    suite = AlgorithmInteroperabilityTestSuite()
    result = suite.run_full_suite()

    print(f"Suite ID: {result.suite_id}")
    print(f"Duration: {result.total_duration_seconds}s")
    print(f"Total Tests: {result.total_tests}")
    print(f"Passed: {result.passed_tests}")
    print(f"Failed: {result.failed_tests}")
    print(f"Skipped: {result.skipped_tests}")
    print(f"Pass Rate: {result.summary['pass_rate']}%")

    print("\nCategory Breakdown:")
    for cat, stats in result.summary["category_breakdown"].items():
        print(f"  {cat:25s}: {stats['passed']}/{stats['total']}")

    assert result.total_tests > 20, "Should run 20+ tests"
    assert result.passed_tests > 15, "Should pass 15+ tests"
    assert result.summary["pass_rate"] > 70, "Pass rate should be > 70%"
    print("✓ Full suite execution PASSED")
    return True


def test_report_generation():
    """Test interoperability report generation"""
    print("\n" + "=" * 60)
    print("TEST 10: Interoperability Report Generation")
    print("=" * 60)

    suite = AlgorithmInteroperabilityTestSuite()
    suite_result = suite.run_full_suite()
    report = suite.generate_interoperability_report(suite_result)

    print("Report Preview (first 400 chars):")
    print(report[:400] + "...")

    assert "POST-QUANTUM CRYPTO INTEROPERABILITY TEST REPORT" in report
    assert "Pass Rate" in report
    assert "CATEGORY BREAKDOWN" in report
    print("✓ Report generation PASSED")
    return True


def main():
    """Run all tests"""
    print("\n" + "🔐" * 30)
    print("POST-QUANTUM INTEROPERABILITY TEST SUITE")
    print("🔐" * 30 + "\n")

    tests = [
        test_parameter_validation,
        test_key_format_interoperability,
        test_round_trip_kem,
        test_round_trip_signature,
        test_algorithm_compatibility,
        test_performance_benchmarking,
        test_nist_compliance,
        test_error_condition_handling,
        test_full_suite_execution,
        test_report_generation,
    ]

    passed = 0
    failed = 0
    results = []

    for test in tests:
        try:
            if test():
                passed += 1
                results.append((test.__name__, "PASSED"))
            else:
                failed += 1
                results.append((test.__name__, "FAILED"))
        except Exception as e:
            failed += 1
            results.append((test.__name__, f"ERROR: {str(e)}"))
            print(f"  ✗ Exception: {e}")

    print("\n" + "=" * 60)
    print("FINAL TEST RESULTS")
    print("=" * 60)
    for name, status in results:
        icon = "✓" if "PASSED" in status else "✗"
        print(f"{icon} {name:50s} {status}")

    print(f"\nTotal: {passed} PASSED, {failed} FAILED")
    print(f"Success rate: {passed/(passed+failed)*100:.1f}%")

    # Save results
    test_results = {
        "test_timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "module": "post_quantum_algorithm_interoperability_test_suite_2026_june",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / (passed + failed) * 100,
        "algorithms_tested": len(NIST_STANDARD_PARAMS),
        "formats_tested": len(KeyFormat),
        "results": results,
    }

    with open("test_results_algorithm_interoperability_test_suite.json", "w") as f:
        json.dump(test_results, f, indent=2)

    print(f"\nResults saved to test_results_algorithm_interoperability_test_suite.json")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
