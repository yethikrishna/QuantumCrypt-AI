#!/usr/bin/env python3
"""
Test Suite for QuantumCrypt-AI: Post-Quantum Crypto Agility Policy Enforcement Engine
June 2026 Production-Grade Tests

This test suite verifies all functionality of the policy enforcement engine:
- NIST policy initialization
- Algorithm compliance checking
- Prohibited/deprecated/phase-out detection
- Key size validation
- Batch inventory scanning
- Compliance scoring
- Policy exception management
- Reporting functionality
- Risk assessment
"""
import json
import sys
import os
import tempfile

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.post_quantum_crypto_agility_policy_enforcement_engine_2026_june import (
    CryptoAgilityPolicyEngine,
    create_policy_engine,
    AlgorithmPolicy,
    AlgorithmStatus,
    RiskLevel,
    PolicyViolation,
    ComplianceResult
)


def run_tests():
    """Run all tests and report results"""
    print("=" * 70)
    print("QuantumCrypt-AI: Crypto Agility Policy Engine - Test Suite")
    print("=" * 70 + "\n")
    
    results = {
        'passed': 0,
        'failed': 0,
        'tests': []
    }
    
    def test(name, test_func):
        try:
            test_func()
            print(f"✅ PASS: {name}")
            results['passed'] += 1
            results['tests'].append({'name': name, 'status': 'PASS'})
        except AssertionError as e:
            print(f"❌ FAIL: {name} - {str(e)}")
            results['failed'] += 1
            results['tests'].append({'name': name, 'status': 'FAIL', 'error': str(e)})
        except Exception as e:
            print(f"❌ ERROR: {name} - {str(e)}")
            results['failed'] += 1
            results['tests'].append({'name': name, 'status': 'ERROR', 'error': str(e)})
    
    # Test 1: Engine initialization
    def test_engine_init():
        engine = create_policy_engine()
        assert engine is not None
        assert len(engine.policies) > 0
        assert engine.policy_name == "nist_800_186"
    
    test("Engine initialization with NIST policies", test_engine_init)
    
    # Test 2: Policy loaded for quantum-resistant algorithms
    def test_pq_algorithms_policies():
        engine = create_policy_engine()
        
        kyber = engine.get_policy("CRYSTALS-Kyber")
        assert kyber is not None
        assert kyber.status == AlgorithmStatus.APPROVED
        assert kyber.risk_level == RiskLevel.NONE
        
        dilithium = engine.get_policy("CRYSTALS-Dilithium")
        assert dilithium is not None
        assert dilithium.status == AlgorithmStatus.APPROVED
        assert dilithium.risk_level == RiskLevel.NONE
    
    test("Post-quantum algorithm policies loaded", test_pq_algorithms_policies)
    
    # Test 3: Prohibited algorithm detection (MD5)
    def test_prohibited_md5():
        engine = create_policy_engine()
        
        is_compliant, violations = engine.check_algorithm_compliance("MD5", 128)
        
        assert not is_compliant
        assert len(violations) >= 1
        prohibited = [v for v in violations if v.violation_type == "prohibited_algorithm"]
        assert len(prohibited) >= 1
        assert prohibited[0].severity == "critical"
    
    test("MD5 prohibited algorithm detection", test_prohibited_md5)
    
    # Test 4: Prohibited algorithm detection (SHA-1)
    def test_prohibited_sha1():
        engine = create_policy_engine()
        
        is_compliant, violations = engine.check_algorithm_compliance("SHA-1", 160)
        
        assert not is_compliant
        prohibited = [v for v in violations if v.violation_type == "prohibited_algorithm"]
        assert len(prohibited) >= 1
    
    test("SHA-1 prohibited algorithm detection", test_prohibited_sha1)
    
    # Test 5: Phase-out algorithm detection (RSA)
    def test_phase_out_rsa():
        engine = create_policy_engine()
        
        is_compliant, violations = engine.check_algorithm_compliance("RSA", 2048)
        
        assert not is_compliant
        phase_out = [v for v in violations if v.violation_type == "phase_out_algorithm"]
        assert len(phase_out) >= 1
        assert phase_out[0].severity == "medium"
    
    test("RSA phase-out (quantum vulnerable) detection", test_phase_out_rsa)
    
    # Test 6: Approved algorithm detection (AES)
    def test_approved_aes():
        engine = create_policy_engine()
        
        is_compliant, violations = engine.check_algorithm_compliance("AES", 256)
        
        assert is_compliant
        assert len(violations) == 0
    
    test("AES approved algorithm - no violations", test_approved_aes)
    
    # Test 7: Approved algorithm detection (Kyber)
    def test_approved_kyber():
        engine = create_policy_engine()
        
        is_compliant, violations = engine.check_algorithm_compliance("CRYSTALS-Kyber", 1024)
        
        assert is_compliant
        assert len(violations) == 0
    
    test("CRYSTALS-Kyber PQC algorithm - no violations", test_approved_kyber)
    
    # Test 8: Insufficient key size detection
    def test_insufficient_key_size():
        engine = create_policy_engine()
        
        # RSA minimum is 3072, using 2048 should trigger violation
        is_compliant, violations = engine.check_algorithm_compliance("RSA", 2048)
        
        keysize_violations = [v for v in violations if v.violation_type == "insufficient_key_size"]
        assert len(keysize_violations) >= 1
        assert keysize_violations[0].severity == "high"
    
    test("Insufficient key size detection for RSA", test_insufficient_key_size)
    
    # Test 9: Sufficient key size no violation
    def test_sufficient_key_size():
        engine = create_policy_engine()
        
        # RSA 4096 should meet key size requirement
        is_compliant, violations = engine.check_algorithm_compliance("RSA", 4096)
        
        keysize_violations = [v for v in violations if v.violation_type == "insufficient_key_size"]
        assert len(keysize_violations) == 0
    
    test("Sufficient key size (RSA 4096) - no key size violation", test_sufficient_key_size)
    
    # Test 10: Unknown algorithm handling
    def test_unknown_algorithm():
        engine = create_policy_engine()
        
        is_compliant, violations = engine.check_algorithm_compliance("UNKNOWN_ALGO", 0)
        
        assert not is_compliant
        unknown = [v for v in violations if v.violation_type == "unknown_algorithm"]
        assert len(unknown) >= 1
    
    test("Unknown algorithm handling", test_unknown_algorithm)
    
    # Test 11: Batch inventory scanning
    def test_batch_scan():
        engine = create_policy_engine()
        
        inventory = [
            ("AES", 256, "db/encryption"),
            ("RSA", 2048, "tls/cert"),
            ("MD5", 128, "legacy/checksum"),
        ]
        
        result = engine.batch_scan_inventory(inventory)
        
        assert result.total_algorithms_scanned == 3
        assert result.compliant_count >= 1  # AES is compliant
        assert result.violation_count >= 2  # RSA + MD5
        assert result.compliance_score > 0
    
    test("Batch inventory scanning", test_batch_scan)
    
    # Test 12: Compliance score calculation
    def test_compliance_score():
        engine = create_policy_engine()
        
        # All approved
        inventory = [
            ("AES", 256, "loc1"),
            ("SHA-2", 256, "loc2"),
            ("CRYSTALS-Kyber", 1024, "loc3"),
        ]
        
        result = engine.batch_scan_inventory(inventory)
        
        assert result.compliance_score == 100.0
        assert result.violation_count == 0
    
    test("100% compliance score for all approved", test_compliance_score)
    
    # Test 13: Risk level distribution
    def test_risk_distribution():
        engine = create_policy_engine()
        
        inventory = [
            ("RSA", 2048, "loc1"),      # CRITICAL
            ("ECDSA", 256, "loc2"),      # CRITICAL
            ("AES", 256, "loc3"),        # LOW
            ("SHA-2", 256, "loc4"),      # LOW
            ("CRYSTALS-Kyber", 1024, "loc5"),  # NONE
        ]
        
        result = engine.batch_scan_inventory(inventory)
        
        assert 'critical' in result.risk_summary
        assert result.risk_summary['critical'] >= 2
        assert 'low' in result.risk_summary
        assert 'none' in result.risk_summary
    
    test("Risk level distribution in scan results", test_risk_distribution)
    
    # Test 14: Recommendations generation
    def test_recommendations_generation():
        engine = create_policy_engine()
        
        inventory = [
            ("MD5", 128, "loc1"),  # Prohibited - triggers recommendations
        ]
        
        result = engine.batch_scan_inventory(inventory)
        
        assert len(result.recommendations) >= 1
        assert any("PROHIBITED" in rec for rec in result.recommendations)
    
    test("Automated recommendations generation", test_recommendations_generation)
    
    # Test 15: Policy exception request
    def test_exception_request():
        engine = create_policy_engine()
        
        exc_id = engine.request_exception("RSA", "security-team", "Legacy system migration")
        
        assert exc_id.startswith("EXC-")
        assert len(engine.exceptions) == 1
    
    test("Policy exception request", test_exception_request)
    
    # Test 16: Add custom policy
    def test_add_custom_policy():
        engine = create_policy_engine()
        
        custom_policy = AlgorithmPolicy(
            algorithm_name="CUSTOM_ALGO",
            algorithm_type="cipher",
            status=AlgorithmStatus.APPROVED,
            risk_level=RiskLevel.LOW,
            min_key_size=128
        )
        
        engine.add_policy(custom_policy)
        retrieved = engine.get_policy("CUSTOM_ALGO")
        
        assert retrieved is not None
        assert retrieved.algorithm_name == "CUSTOM_ALGO"
    
    test("Add custom algorithm policy", test_add_custom_policy)
    
    # Test 17: Remove policy
    def test_remove_policy():
        engine = create_policy_engine()
        
        # First verify it exists
        assert engine.get_policy("MD5") is not None
        
        # Remove it
        result = engine.remove_policy("MD5")
        assert result is True
        
        # Verify removed
        assert engine.get_policy("MD5") is None
    
    test("Remove algorithm policy", test_remove_policy)
    
    # Test 18: List policies
    def test_list_policies():
        engine = create_policy_engine()
        
        policies = engine.list_policies()
        
        assert len(policies) > 0
        algos = [p['algorithm'] for p in policies]
        assert "AES" in algos
        assert "RSA" in algos
        assert "CRYSTALS-Kyber" in algos
    
    test("List all policies", test_list_policies)
    
    # Test 19: Get engine stats
    def test_engine_stats():
        engine = create_policy_engine()
        
        stats = engine.get_engine_stats()
        
        assert 'total_policies' in stats
        assert stats['total_policies'] > 0
        assert 'policies_by_status' in stats
        assert 'policies_by_risk' in stats
    
    test("Engine statistics", test_engine_stats)
    
    # Test 20: Compliance report generation
    def test_compliance_report():
        engine = create_policy_engine()
        
        inventory = [("AES", 256, "loc1"), ("RSA", 2048, "loc2")]
        result = engine.batch_scan_inventory(inventory)
        
        report = engine.get_compliance_report(result)
        
        assert 'scan_id' in report
        assert 'summary' in report
        assert 'violations' in report
        assert 'recommendations' in report
        assert 'nist_compliant' in report
    
    test("Compliance report generation", test_compliance_report)
    
    # Test 21: Violation ID generation
    def test_violation_id_format():
        engine = create_policy_engine()
        
        vid = engine._generate_violation_id()
        
        assert vid.startswith("VIO-")
        assert len(vid) > 5
    
    test("Violation ID format", test_violation_id_format)
    
    # Test 22: Policy export
    def test_policy_export():
        engine = create_policy_engine()
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            filepath = f.name
        
        result = engine.export_policy(filepath)
        assert result is True
        
        # Verify file exists and has content
        with open(filepath) as f:
            data = json.load(f)
            assert 'policies' in data
            assert len(data['policies']) > 0
        
        os.unlink(filepath)
    
    test("Policy export to JSON", test_policy_export)
    
    # Test 23: Deprecated algorithm detection (3DES)
    def test_deprecated_3des():
        engine = create_policy_engine()
        
        is_compliant, violations = engine.check_algorithm_compliance("3DES", 168)
        
        assert not is_compliant
        deprecated = [v for v in violations if v.violation_type == "deprecated_algorithm"]
        assert len(deprecated) >= 1
        assert deprecated[0].severity == "high"
    
    test("3DES deprecated algorithm detection", test_deprecated_3des)
    
    # Test 24: Violation remediation message
    def test_violation_remediation():
        engine = create_policy_engine()
        
        is_compliant, violations = engine.check_algorithm_compliance("MD5", 128)
        
        assert len(violations) > 0
        assert len(violations[0].remediation) > 0
        assert "SHA-2" in violations[0].remediation or "SHA-3" in violations[0].remediation
    
    test("Violation includes remediation guidance", test_violation_remediation)
    
    # Test 25: Scan history tracking
    def test_scan_history():
        engine = create_policy_engine()
        
        initial = len(engine.scan_history)
        
        engine.batch_scan_inventory([("AES", 256, "loc1")])
        engine.batch_scan_inventory([("RSA", 2048, "loc2")])
        
        assert len(engine.scan_history) == initial + 2
    
    test("Scan history tracking", test_scan_history)
    
    # Summary
    print("\n" + "=" * 70)
    total = results['passed'] + results['failed']
    print(f"TEST SUMMARY: {results['passed']} PASSED / {results['failed']} FAILED / {total} TOTAL")
    print("=" * 70)
    
    # Save results
    with open('test_results_pqc_policy_enforcement_engine.json', 'w') as f:
        json.dump({
            'test_timestamp': __import__('time').time(),
            'total_tests': total,
            'passed': results['passed'],
            'failed': results['failed'],
            'pass_rate': results['passed'] / total if total > 0 else 0,
            'tests': results['tests']
        }, f, indent=2)
    
    print(f"\nTest results saved to: test_results_pqc_policy_enforcement_engine.json")
    
    return results['failed'] == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
