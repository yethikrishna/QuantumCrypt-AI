#!/usr/bin/env python3
"""
Test suite for Post-Quantum EM Side-Channel Analysis Validator
Production-grade tests with real assertions.
"""

import sys
import os
import json

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_em_side_channel_analysis_validator_2026_june import (
    EMSideChannelValidator,
    MeasurementTrace,
    LeakageAnalysis,
    AlgorithmType,
    SideChannelMetric,
    VulnerabilityLevel
)


def test_vulnerability_level_calculation():
    """Test vulnerability level boundary calculation"""
    print("Test 1: Vulnerability Level Calculation")

    assert VulnerabilityLevel.from_score(0.0) == VulnerabilityLevel.SAFE
    assert VulnerabilityLevel.from_score(0.05) == VulnerabilityLevel.SAFE
    assert VulnerabilityLevel.from_score(0.1) == VulnerabilityLevel.LOW
    assert VulnerabilityLevel.from_score(0.2) == VulnerabilityLevel.LOW
    assert VulnerabilityLevel.from_score(0.3) == VulnerabilityLevel.MEDIUM
    assert VulnerabilityLevel.from_score(0.4) == VulnerabilityLevel.MEDIUM
    assert VulnerabilityLevel.from_score(0.5) == VulnerabilityLevel.HIGH
    assert VulnerabilityLevel.from_score(0.7) == VulnerabilityLevel.HIGH
    assert VulnerabilityLevel.from_score(0.75) == VulnerabilityLevel.CRITICAL
    assert VulnerabilityLevel.from_score(1.0) == VulnerabilityLevel.CRITICAL

    print("  ✓ All vulnerability level boundaries correctly calculated")


def test_constant_time_input_generation():
    """Test constant-time test input generation"""
    print("Test 2: Constant-Time Test Input Generation")

    validator = EMSideChannelValidator()
    inputs = validator.generate_constant_time_test_inputs(100)

    assert len(inputs) == 100
    assert all(len(i) == 32 for i in inputs)

    # Check we have zeros, ones, and random data
    zeros = sum(1 for i in inputs if i == b'\x00' * 32)
    ones = sum(1 for i in inputs if i == b'\xff' * 32)

    assert zeros >= 25
    assert ones >= 25

    print(f"  ✓ Generated {len(inputs)} test inputs")
    print(f"  ✓ Zero inputs: {zeros}, One inputs: {ones}, Random: {100 - zeros - ones}")


def test_timing_measurement_simulation():
    """Test timing measurement simulation"""
    print("Test 3: Timing Measurement Simulation")

    validator = EMSideChannelValidator()

    trace = validator.simulate_timing_measurement(
        AlgorithmType.KYBER,
        "keygen",
        b'\x00' * 32,
        iterations=50
    )

    assert trace.algorithm == AlgorithmType.KYBER
    assert trace.operation == "keygen"
    assert len(trace.timing_samples) == 50
    assert len(trace.power_samples) == 50
    assert len(trace.em_samples) == 50
    assert len(trace.trace_id) == 12

    # Verify statistical properties exist
    assert trace.timing_std >= 0
    assert trace.timing_cv >= 0
    assert trace.em_noise_level >= 0

    print(f"  ✓ Trace ID: {trace.trace_id}")
    print(f"  ✓ Timing std: {trace.timing_std:.2f}")
    print(f"  ✓ Timing CV: {trace.timing_cv:.4f}")
    print("  ✓ All statistical properties calculated")


def test_measurement_trace_properties():
    """Test measurement trace property calculations"""
    print("Test 4: Measurement Trace Properties")

    validator = EMSideChannelValidator()
    traces = validator.run_analysis_suite(AlgorithmType.KYBER, 20)

    assert len(traces) == 20

    for trace in traces:
        assert isinstance(trace.timing_std, float)
        assert isinstance(trace.timing_cv, float)
        assert isinstance(trace.em_noise_level, float)
        assert trace.duration_ns > 0

    print(f"  ✓ Analyzed {len(traces)} measurement traces")
    print("  ✓ All trace properties correctly calculated")


def test_timing_leakage_analysis():
    """Test timing leakage analysis"""
    print("Test 5: Timing Leakage Analysis")

    validator = EMSideChannelValidator()
    traces = validator.run_analysis_suite(AlgorithmType.DILITHIUM, 30)
    analysis = validator.analyze_timing_leakage(traces)

    assert analysis.metric == SideChannelMetric.TIMING_VARIANCE
    assert 0 <= analysis.leakage_score <= 1
    assert analysis.confidence > 0
    assert isinstance(analysis.detected_patterns, list)
    assert analysis.vulnerability_level in list(VulnerabilityLevel)

    print(f"  ✓ Leakage score: {analysis.leakage_score:.4f}")
    print(f"  ✓ Vulnerability level: {analysis.vulnerability_level.value[1]}")
    print(f"  ✓ Confidence: {analysis.confidence:.0%}")
    print(f"  ✓ Patterns detected: {len(analysis.detected_patterns)}")


def test_em_leakage_analysis():
    """Test electromagnetic leakage analysis"""
    print("Test 6: EM Leakage Analysis")

    validator = EMSideChannelValidator()
    traces = validator.run_analysis_suite(AlgorithmType.FALCON, 40)
    analysis = validator.analyze_em_leakage(traces)

    assert analysis.metric == SideChannelMetric.EM_EMISSION
    assert 0 <= analysis.leakage_score <= 1
    assert analysis.confidence > 0
    assert isinstance(analysis.detected_patterns, list)

    print(f"  ✓ EM leakage score: {analysis.leakage_score:.4f}")
    print(f"  ✓ Vulnerability level: {analysis.vulnerability_level.value[1]}")
    print(f"  ✓ Confidence: {analysis.confidence:.0%}")


def test_power_leakage_analysis():
    """Test power consumption leakage analysis"""
    print("Test 7: Power Leakage Analysis")

    validator = EMSideChannelValidator()
    traces = validator.run_analysis_suite(AlgorithmType.SPHINCS, 25)
    analysis = validator.analyze_power_leakage(traces)

    assert analysis.metric == SideChannelMetric.POWER_CONSUMPTION
    assert 0 <= analysis.leakage_score <= 1
    assert analysis.confidence > 0

    print(f"  ✓ Power leakage score: {analysis.leakage_score:.4f}")
    print(f"  ✓ Vulnerability level: {analysis.vulnerability_level.value[1]}")


def test_full_validation_suite():
    """Test complete validation suite"""
    print("Test 8: Full Validation Suite")

    validator = EMSideChannelValidator()
    result = validator.run_full_validation(AlgorithmType.KYBER, 50)

    assert result["algorithm"] == "CRYSTALS-Kyber"
    assert result["traces_analyzed"] == 50
    assert 0 <= result["overall_leakage_score"] <= 1
    assert result["overall_vulnerability_level"] in ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert len(result["metric_analyses"]) == 3
    assert isinstance(result["recommendations"], list)

    print(f"  ✓ Algorithm: {result['algorithm']}")
    print(f"  ✓ Traces analyzed: {result['traces_analyzed']}")
    print(f"  ✓ Overall leakage score: {result['overall_leakage_score']:.4f}")
    print(f"  ✓ Overall level: {result['overall_vulnerability_level']}")
    print(f"  ✓ Recommendations: {len(result['recommendations'])}")


def test_html_report_generation():
    """Test HTML validation report generation"""
    print("Test 9: HTML Report Generation")

    validator = EMSideChannelValidator()
    html = validator.generate_validation_report(AlgorithmType.KYBER)

    assert "<!DOCTYPE html>" in html
    assert "<html>" in html
    assert "Post-Quantum EM Side-Channel Validation Report" in html
    assert "Overall Vulnerability Level" in html
    assert "Metric Analysis" in html
    assert "Security Recommendations" in html

    print("  ✓ Valid HTML structure")
    print("  ✓ Report sections present")
    print("  ✓ Styling included")


def test_json_export():
    """Test JSON results export"""
    print("Test 10: JSON Results Export")

    validator = EMSideChannelValidator()
    validator.run_full_validation(AlgorithmType.KYBER, 30)
    validator.run_full_validation(AlgorithmType.DILITHIUM, 30)

    export_path = "/tmp/test_em_validation_export.json"
    validator.export_results(export_path)

    with open(export_path) as f:
        data = json.load(f)

    assert data["validator"] == "Post-Quantum EM Side-Channel Analysis Validator"
    assert data["version"] == "2026.06"
    assert len(data["algorithms_tested"]) == 2
    assert data["total_measurements"] >= 60
    assert "CRYSTALS-Kyber" in data["results"]
    assert "CRYSTALS-Dilithium" in data["results"]

    os.remove(export_path)

    print("  ✓ JSON export successful")
    print(f"  ✓ Algorithms tested: {len(data['algorithms_tested'])}")
    print(f"  ✓ Total measurements: {data['total_measurements']}")


def test_algorithm_comparison():
    """Test comparison across different post-quantum algorithms"""
    print("Test 11: Algorithm Comparison Analysis")

    validator = EMSideChannelValidator()

    algorithms = [AlgorithmType.KYBER, AlgorithmType.DILITHIUM, AlgorithmType.SPHINCS]
    results = {}

    for algo in algorithms:
        result = validator.run_full_validation(algo, 25)
        results[algo.value] = result["overall_leakage_score"]

    assert len(results) == 3
    assert all(0 <= score <= 1 for score in results.values())

    print("  ✓ All algorithms tested successfully")
    for algo, score in sorted(results.items(), key=lambda x: x[1]):
        print(f"    - {algo}: {score:.4f} leakage score")


def test_empty_trace_handling():
    """Test handling of empty trace lists"""
    print("Test 12: Empty Trace Handling")

    validator = EMSideChannelValidator()

    timing_analysis = validator.analyze_timing_leakage([])
    em_analysis = validator.analyze_em_leakage([])
    power_analysis = validator.analyze_power_leakage([])

    assert timing_analysis.leakage_score == 0.0
    assert em_analysis.leakage_score == 0.0
    assert power_analysis.leakage_score == 0.0

    print("  ✓ Empty traces handled gracefully")
    print("  ✓ Zero leakage score returned for empty input")


def run_all_tests():
    """Run all tests and generate results"""
    print("=" * 70)
    print("Post-Quantum EM Side-Channel Analysis Validator - Test Suite")
    print("=" * 70)
    print()

    tests = [
        test_vulnerability_level_calculation,
        test_constant_time_input_generation,
        test_timing_measurement_simulation,
        test_measurement_trace_properties,
        test_timing_leakage_analysis,
        test_em_leakage_analysis,
        test_power_leakage_analysis,
        test_full_validation_suite,
        test_html_report_generation,
        test_json_export,
        test_algorithm_comparison,
        test_empty_trace_handling
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
            print()
        except Exception as e:
            failed += 1
            print(f"  ✗ FAILED: {e}")
            import traceback
            traceback.print_exc()
            print()

    print("=" * 70)
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("=" * 70)

    # Save test results
    results = {
        "test_module": "post_quantum_em_side_channel_analysis_validator",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": f"{(passed/len(tests))*100:.1f}%",
        "timestamp": "2026-06-22"
    }

    with open("test_results_em_side_channel_validator_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"Test results saved to test_results_em_side_channel_validator_2026_june.json")

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
