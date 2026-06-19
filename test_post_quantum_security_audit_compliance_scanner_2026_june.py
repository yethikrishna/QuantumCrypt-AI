"""
Test Suite for Post-Quantum Security Audit & Compliance Scanner
June 20, 2026 - Production Grade Tests

Real tests that verify actual functionality
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from quantum_crypt.post_quantum_security_audit_compliance_scanner_2026_june import (
    PostQuantumSecurityAuditScanner,
    AlgorithmCategory,
    NISTSecurityLevel,
    ComplianceStatus,
    RiskLevel,
    ComplianceFramework
)


def test_basic_audit_functionality():
    """Test basic security audit functionality"""
    print("=" * 60)
    print("TEST 1: Basic Security Audit Functionality")
    print("=" * 60)
    
    scanner = PostQuantumSecurityAuditScanner()
    
    # Test with mixed algorithms (quantum-safe and vulnerable)
    algorithms = [
        "Kyber-768",
        "Dilithium-3",
        "RSA-2048",
        "ECDSA-P256",
        "SHA-256",
        "AES-256"
    ]
    
    result = scanner.run_audit(algorithms, target_system="Production TLS Infrastructure")
    
    print(f"✓ Audit ID: {result.audit_id}")
    print(f"✓ Overall Compliance Score: {result.overall_compliance_score}%")
    print(f"✓ Algorithms Audited: {len(result.algorithm_assessments)}")
    print(f"✓ Quantum-Safe: {len(result.compliant_algorithms)}")
    print(f"✓ Quantum-Vulnerable: {len(result.non_compliant_algorithms)}")
    print(f"✓ Security Gaps: {len(result.security_gaps)}")
    print(f"✓ Findings: {len(result.findings)}")
    print(f"✓ Processing Time: {result.processing_time_ms:.2f}ms")
    
    # Verify results
    assert result.overall_compliance_score > 0
    assert len(result.algorithm_assessments) == 6
    assert "Kyber-768" in result.compliant_algorithms
    assert "RSA-2048" in result.non_compliant_algorithms
    
    print("✓ All basic assertions passed!")
    return True


def test_nist_compliance_checking():
    """Test NIST SP 800-186 compliance checking"""
    print("\n" + "=" * 60)
    print("TEST 2: NIST SP 800-186 Compliance Checking")
    print("=" * 60)
    
    scanner = PostQuantumSecurityAuditScanner()
    
    algorithms = ["Kyber-768", "Dilithium-3", "SHA-256"]
    result = scanner.run_audit(
        algorithms,
        frameworks=[ComplianceFramework.NIST_SP_800_186]
    )
    
    nist_score = result.compliance_by_framework.get("nist_sp_800_186", 0)
    print(f"✓ NIST SP 800-186 Compliance Score: {nist_score}%")
    
    for finding in result.findings:
        if finding.framework == ComplianceFramework.NIST_SP_800_186:
            status = "✓" if finding.status == ComplianceStatus.COMPLIANT else "✗"
            print(f"  {status} {finding.requirement}: {finding.status.value}")
    
    assert ComplianceFramework.NIST_SP_800_186 in result.frameworks_audited
    print("✓ NIST compliance checking working correctly!")
    return True


def test_quantum_vulnerability_detection():
    """Test quantum vulnerability detection for classic algorithms"""
    print("\n" + "=" * 60)
    print("TEST 3: Quantum Vulnerability Detection")
    print("=" * 60)
    
    scanner = PostQuantumSecurityAuditScanner()
    
    # Classic vulnerable algorithms
    algorithms = ["RSA-2048", "RSA-3072", "ECDSA-P256", "ECDH-P256", "X25519"]
    result = scanner.run_audit(algorithms)
    
    print(f"✓ Vulnerable Algorithms Detected:")
    for assessment in result.algorithm_assessments:
        if not assessment.quantum_safe:
            print(f"  ✗ {assessment.algorithm.name:15} -> Risk: {assessment.risk_level.value.upper()}")
            print(f"      {assessment.algorithm.quantum_risk_assessment}")
    
    # All classic asymmetric should be vulnerable
    assert all(not a.quantum_safe for a in result.algorithm_assessments)
    assert any(g.risk_level == RiskLevel.CRITICAL for g in result.security_gaps)
    
    print("✓ Quantum vulnerability detection working correctly!")
    return True


def test_security_gap_identification():
    """Test automatic security gap identification"""
    print("\n" + "=" * 60)
    print("TEST 4: Security Gap Identification")
    print("=" * 60)
    
    scanner = PostQuantumSecurityAuditScanner()
    
    algorithms = ["RSA-2048", "ECDSA-P256", "Unknown-Algorithm-123"]
    result = scanner.run_audit(algorithms)
    
    print(f"✓ Security Gaps Identified: {len(result.security_gaps)}")
    for gap in sorted(result.security_gaps, key=lambda g: g.priority):
        print(f"\n  [{gap.gap_id}] {gap.title}")
        print(f"      Risk: {gap.risk_level.value.upper()}")
        print(f"      Priority: {gap.priority}")
        print(f"      Affected: {', '.join(gap.affected_components)}")
        print(f"      Est. Effort: {gap.effort_estimate_hours} hours")
        print(f"      Remediation Steps: {len(gap.remediation_steps)}")
    
    assert len(result.security_gaps) >= 2  # Should find critical vulnerable and unknown gaps
    print("✓ Security gap identification working correctly!")
    return True


def test_report_generation():
    """Test executive summary and detailed report generation"""
    print("\n" + "=" * 60)
    print("TEST 5: Report Generation")
    print("=" * 60)
    
    scanner = PostQuantumSecurityAuditScanner()
    
    algorithms = ["Kyber-768", "Dilithium-3", "RSA-2048", "SHA-256"]
    result = scanner.run_audit(algorithms)
    
    print("✓ Executive Summary Generated:")
    print("-" * 40)
    print(result.executive_summary[:500] + "...")
    
    print("\n✓ Detailed Report Generated:")
    print("-" * 40)
    print(result.detailed_report[:500] + "...")
    
    assert "EXECUTIVE SUMMARY" in result.executive_summary
    assert "COMPLIANCE SCORES" in result.detailed_report
    assert len(result.recommendations_summary) > 0
    
    print("\n✓ Recommendations:")
    for i, rec in enumerate(result.recommendations_summary, 1):
        print(f"  {i}. {rec}")
    
    print("✓ Report generation working correctly!")
    return True


def test_json_export():
    """Test JSON export functionality"""
    print("\n" + "=" * 60)
    print("TEST 6: JSON Export Functionality")
    print("=" * 60)
    
    scanner = PostQuantumSecurityAuditScanner()
    
    algorithms = ["Kyber-512", "AES-256"]
    result = scanner.run_audit(algorithms)
    json_output = scanner.export_audit_json(result)
    
    # Validate JSON
    data = json.loads(json_output)
    assert "audit_id" in data
    assert "overall_compliance_score" in data
    assert "quantum_safe_count" in data
    
    print(f"✓ JSON Export Valid")
    print(f"  Audit ID: {data['audit_id']}")
    print(f"  Compliance Score: {data['overall_compliance_score']}%")
    print(f"  Quantum Safe: {data['quantum_safe_count']}/{data['algorithms_audited']}")
    print(f"  Processing Time: {data['processing_time_ms']}ms")
    
    print("✓ JSON export working correctly!")
    return True


def test_multiframework_audit():
    """Test audit against multiple compliance frameworks"""
    print("\n" + "=" * 60)
    print("TEST 7: Multi-Framework Compliance Audit")
    print("=" * 60)
    
    scanner = PostQuantumSecurityAuditScanner()
    
    algorithms = ["Kyber-768", "Dilithium-3", "SHA-384", "AES-256"]
    frameworks = [
        ComplianceFramework.NIST_SP_800_186,
        ComplianceFramework.FIPS_140_3,
        ComplianceFramework.CNSA_2_0
    ]
    
    result = scanner.run_audit(algorithms, frameworks=frameworks)
    
    print(f"✓ Frameworks Audited: {len(result.frameworks_audited)}")
    for framework, score in result.compliance_by_framework.items():
        print(f"  {framework:25} {score}%")
    
    assert len(result.frameworks_audited) == 3
    assert len(result.compliance_by_framework) == 3
    
    print("✓ Multi-framework audit working correctly!")
    return True


def test_unknown_algorithm_handling():
    """Test handling of unknown algorithms"""
    print("\n" + "=" * 60)
    print("TEST 8: Unknown Algorithm Handling")
    print("=" * 60)
    
    scanner = PostQuantumSecurityAuditScanner()
    
    algorithms = ["MyCustomCrypto", "SuperSecure-2048", "UnknownCipher"]
    result = scanner.run_audit(algorithms)
    
    print(f"✓ Unknown Algorithms Handled:")
    for assessment in result.algorithm_assessments:
        print(f"  ? {assessment.algorithm.name:20} -> Category: {assessment.algorithm.category.value}")
        print(f"      Risk: {assessment.risk_level.value.upper()}")
    
    # All should be unknown category
    assert all(a.algorithm.category == AlgorithmCategory.UNKNOWN for a in result.algorithm_assessments)
    assert any(g.risk_level == RiskLevel.HIGH for g in result.security_gaps)
    
    print("✓ Unknown algorithm handling working correctly!")
    return True


def test_audit_statistics():
    """Test audit statistics tracking"""
    print("\n" + "=" * 60)
    print("TEST 9: Audit Statistics Tracking")
    print("=" * 60)
    
    scanner = PostQuantumSecurityAuditScanner()
    
    # Run multiple audits
    for i in range(3):
        algorithms = ["Kyber-768", f"Test-Alg-{i}"]
        scanner.run_audit(algorithms)
    
    stats = scanner.get_audit_statistics()
    
    print(f"✓ Total Audits: {stats['total_audits']}")
    print(f"✓ Average Compliance Score: {stats['average_compliance_score']}%")
    print(f"✓ Total Gaps Identified: {stats['total_security_gaps_identified']}")
    
    assert stats["total_audits"] == 3
    print("✓ Audit statistics tracking working correctly!")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("\n" + "=" * 60)
    print("POST-QUANTUM SECURITY AUDIT SCANNER - TEST SUITE")
    print("June 20, 2026 - Production Grade")
    print("=" * 60 + "\n")
    
    tests = [
        test_basic_audit_functionality,
        test_nist_compliance_checking,
        test_quantum_vulnerability_detection,
        test_security_gap_identification,
        test_report_generation,
        test_json_export,
        test_multiframework_audit,
        test_unknown_algorithm_handling,
        test_audit_statistics
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result, None))
        except Exception as e:
            results.append((test.__name__, False, str(e)))
            print(f"✗ FAILED: {test.__name__}: {e}")
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, r, _ in results if r)
    total = len(results)
    
    for name, result, error in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status} {name}")
        if error:
            print(f"    Error: {error}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    # Save test results
    test_results = {
        "test_date": datetime.now().isoformat(),
        "module": "post_quantum_security_audit_compliance_scanner",
        "tests_passed": passed,
        "tests_total": total,
        "success_rate": passed / total if total > 0 else 0,
        "results": [{"name": n, "passed": r, "error": e} for n, r, e in results]
    }
    
    with open("test_results_post_quantum_security_audit.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to test_results_post_quantum_security_audit.json")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
