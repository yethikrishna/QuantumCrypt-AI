"""
Test Suite for Post-Quantum Migration Readiness Assessor
Production-grade testing of all functionality
"""

import json
import sys
from datetime import datetime

# Add the module path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_migration_readiness_assessor_2026_june import (
    PostQuantumMigrationReadinessAssessor,
    ReadinessLevel,
    RiskLevel,
    AlgorithmCategory,
    MigrationPriority
)


def run_tests():
    """Run all production tests."""
    print("=" * 70)
    print("POST-QUANTUM MIGRATION READINESS ASSESSOR - PRODUCTION TEST SUITE")
    print("=" * 70)
    print(f"Test started: {datetime.utcnow().isoformat()}")
    
    test_results = []
    all_passed = True
    
    # Test 1: Assessor Initialization
    print("\n[TEST 1] Assessor Initialization")
    try:
        assessor = PostQuantumMigrationReadinessAssessor()
        assert len(assessor.algorithm_quantum_scores) > 0
        print("  ✓ Assessor initialized with algorithm database")
        test_results.append(("Initialization", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Initialization", False))
        all_passed = False
    
    # Test 2: Algorithm Readiness Assessment - Vulnerable Classical
    print("\n[TEST 2] Algorithm Readiness - Vulnerable Classical")
    try:
        assessor = PostQuantumMigrationReadinessAssessor()
        # All classical vulnerable algorithms
        algo_inventory = {
            "RSA-2048": 100,
            "ECC-P256": 50,
            "ECDSA-P256": 30
        }
        assessment = assessor.assess_algorithm_readiness(algo_inventory)
        assert assessment.quantum_resistance_score < 20
        assert assessment.category == AlgorithmCategory.CLASSICAL_VULNERABLE
        assert assessment.risk_level == RiskLevel.CRITICAL
        assert assessment.migration_priority == MigrationPriority.IMMEDIATE
        print(f"  ✓ Vulnerable algorithms correctly assessed")
        print(f"    - Quantum resistance score: {assessment.quantum_resistance_score:.1f}/100")
        print(f"    - Risk level: {assessment.risk_level.value}")
        test_results.append(("Algorithm Vulnerable Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Algorithm Vulnerable Assessment", False))
        all_passed = False
    
    # Test 3: Algorithm Readiness - PQC Standardized
    print("\n[TEST 3] Algorithm Readiness - PQC Standardized")
    try:
        # All NIST standardized PQC algorithms
        algo_inventory = {
            "CRYSTALS-Kyber-768": 100,
            "CRYSTALS-Dilithium-3": 50
        }
        assessment = assessor.assess_algorithm_readiness(algo_inventory)
        assert assessment.quantum_resistance_score == 100
        assert assessment.nist_standardized == True
        print(f"  ✓ PQC algorithms correctly assessed")
        print(f"    - Quantum resistance score: {assessment.quantum_resistance_score:.1f}/100")
        test_results.append(("Algorithm PQC Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Algorithm PQC Assessment", False))
        all_passed = False
    
    # Test 4: Key Inventory Assessment
    print("\n[TEST 4] Key Inventory Assessment")
    try:
        key_metrics = {
            "total_keys": 1000,
            "classical_keys": 800,
            "post_quantum_keys": 150,
            "hybrid_keys": 50,
            "keys_with_rotation_enabled": 200,
            "keys_in_hsm": 500,
            "rotation_frequency_days": 180,
            "avg_key_age_days": 120,
            "expired_keys": 10,
            "weak_keys": 5
        }
        assessment = assessor.assess_key_inventory(key_metrics)
        assert assessment.total_keys == 1000
        assert assessment.classical_keys == 800
        assert assessment.post_quantum_keys == 150
        print("  ✓ Key inventory assessment completed")
        print(f"    - Total keys: {assessment.total_keys}")
        print(f"    - Classical keys: {assessment.classical_keys}")
        print(f"    - PQC keys: {assessment.post_quantum_keys}")
        test_results.append(("Key Inventory Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Key Inventory Assessment", False))
        all_passed = False
    
    # Test 5: Infrastructure Assessment
    print("\n[TEST 5] Infrastructure Assessment")
    try:
        infra_metrics = {
            "tls_version": "1.3",
            "tls_13_enabled": True,
            "cert_chain_pqc": False,
            "hsm_pqc_support": False,
            "library_versions": {"openssl": "3.0.0", "botan": "3.0.0"},
            "network_device_support": True,
            "cloud_provider_support": True,
            "api_gateway_support": False
        }
        assessment = assessor.assess_infrastructure(infra_metrics)
        assert assessment.tls_13_enabled == True
        assert assessment.tls_version_supported == "1.3"
        print("  ✓ Infrastructure assessment completed")
        print(f"    - TLS 1.3 enabled: {assessment.tls_13_enabled}")
        print(f"    - HSM PQC support: {assessment.hsm_pqc_support}")
        test_results.append(("Infrastructure Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Infrastructure Assessment", False))
        all_passed = False
    
    # Test 6: Interoperability Assessment
    print("\n[TEST 6] Interoperability Assessment")
    try:
        interop_metrics = {
            "internal_compat": 0.7,
            "external_compat": 0.4,
            "protocol_coverage": 0.6,
            "fallback_exists": True,
            "hybrid_supported": False,
            "cert_interop": 0.5
        }
        assessment = assessor.assess_interoperability(interop_metrics)
        assert assessment.internal_system_compatibility == 0.7
        assert assessment.fallback_mechanisms_exist == True
        print("  ✓ Interoperability assessment completed")
        test_results.append(("Interoperability Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Interoperability Assessment", False))
        all_passed = False
    
    # Test 7: Performance Assessment
    print("\n[TEST 7] Performance Assessment")
    try:
        perf_metrics = {
            "signature_impact": 15,
            "verification_impact": 10,
            "keygen_impact": 25,
            "memory_overhead": 20,
            "latency_ms": 2,
            "hw_accel": True
        }
        assessment = assessor.assess_performance(perf_metrics)
        assert assessment.overall_performance_score > 0
        assert assessment.hardware_acceleration_available == True
        print("  ✓ Performance assessment completed")
        print(f"    - Overall performance score: {assessment.overall_performance_score:.1f}/100")
        test_results.append(("Performance Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Performance Assessment", False))
        all_passed = False
    
    # Test 8: Compliance Assessment
    print("\n[TEST 8] Compliance Assessment")
    try:
        compliance_metrics = {
            "nist_186": False,
            "nist_56c": False,
            "cnsa_20": False,
            "timeline_met": False,
            "industry_compliance": {"HIPAA": True, "PCI-DSS": False},
            "docs_complete": True,
            "audit_trail": True
        }
        assessment = assessor.assess_compliance(compliance_metrics)
        assert assessment.cnsa_2_0_compliant == False
        assert assessment.documentation_complete == True
        print("  ✓ Compliance assessment completed")
        test_results.append(("Compliance Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Compliance Assessment", False))
        all_passed = False
    
    # Test 9: Full Assessment - NOT READY scenario
    print("\n[TEST 9] Full Assessment - NOT READY Scenario")
    try:
        report = assessor.perform_full_assessment(
            organization_id="test_org_not_ready",
            algorithm_inventory={"RSA-2048": 100, "ECC-P256": 50},
            key_metrics={
                "total_keys": 150,
                "classical_keys": 150,
                "post_quantum_keys": 0,
                "hybrid_keys": 0,
                "keys_with_rotation_enabled": 0,
                "keys_in_hsm": 0,
                "rotation_frequency_days": 365,
                "avg_key_age_days": 200,
                "expired_keys": 10,
                "weak_keys": 5
            },
            infra_metrics={
                "tls_version": "1.2",
                "tls_13_enabled": False,
                "cert_chain_pqc": False,
                "hsm_pqc_support": False,
                "library_versions": {},
                "network_device_support": False,
                "cloud_provider_support": False,
                "api_gateway_support": False
            },
            interop_metrics={
                "internal_compat": 0.2,
                "external_compat": 0.1,
                "protocol_coverage": 0.1,
                "fallback_exists": False,
                "hybrid_supported": False,
                "cert_interop": 0.1
            },
            perf_metrics={
                "signature_impact": 50,
                "verification_impact": 40,
                "keygen_impact": 60,
                "memory_overhead": 50,
                "latency_ms": 10,
                "hw_accel": False
            },
            compliance_metrics={
                "nist_186": False,
                "nist_56c": False,
                "cnsa_20": False,
                "timeline_met": False,
                "industry_compliance": {},
                "docs_complete": False,
                "audit_trail": False
            }
        )
        assert report.overall_readiness_level == ReadinessLevel.NOT_READY
        assert report.overall_readiness_score < 40
        assert len(report.migration_gaps) > 0
        assert len(report.recommendations) > 0
        print(f"  ✓ NOT_READY scenario correctly assessed")
        print(f"    - Overall score: {report.overall_readiness_score:.1f}/100")
        print(f"    - Readiness level: {report.overall_readiness_level.value}")
        print(f"    - Migration gaps identified: {len(report.migration_gaps)}")
        print(f"    - Estimated timeline: {report.migration_timeline_months:.1f} months")
        print(f"    - Estimated cost: ${report.estimated_cost_usd:,.0f}")
        test_results.append(("Full NOT_READY Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Full NOT_READY Assessment", False))
        all_passed = False
    
    # Test 10: Full Assessment - PARTIALLY_READY scenario
    print("\n[TEST 10] Full Assessment - PARTIALLY_READY Scenario")
    try:
        report = assessor.perform_full_assessment(
            organization_id="test_org_partial",
            algorithm_inventory={
                "RSA-2048": 50,
                "CRYSTALS-Kyber-768": 50,
                "AES-256": 100
            },
            key_metrics={
                "total_keys": 200,
                "classical_keys": 100,
                "post_quantum_keys": 80,
                "hybrid_keys": 20,
                "keys_with_rotation_enabled": 100,
                "keys_in_hsm": 150,
                "rotation_frequency_days": 90,
                "avg_key_age_days": 60,
                "expired_keys": 2,
                "weak_keys": 1
            },
            infra_metrics={
                "tls_version": "1.3",
                "tls_13_enabled": True,
                "cert_chain_pqc": False,
                "hsm_pqc_support": False,
                "library_versions": {"openssl": "3.2.0"},
                "network_device_support": True,
                "cloud_provider_support": True,
                "api_gateway_support": True
            },
            interop_metrics={
                "internal_compat": 0.6,
                "external_compat": 0.4,
                "protocol_coverage": 0.5,
                "fallback_exists": True,
                "hybrid_supported": True,
                "cert_interop": 0.5
            },
            perf_metrics={
                "signature_impact": 15,
                "verification_impact": 10,
                "keygen_impact": 20,
                "memory_overhead": 15,
                "latency_ms": 2,
                "hw_accel": True
            },
            compliance_metrics={
                "nist_186": True,
                "nist_56c": False,
                "cnsa_20": False,
                "timeline_met": False,
                "industry_compliance": {"HIPAA": True},
                "docs_complete": True,
                "audit_trail": True
            }
        )
        assert report.overall_readiness_level == ReadinessLevel.PARTIALLY_READY
        assert 40 <= report.overall_readiness_score < 70
        print(f"  ✓ PARTIALLY_READY scenario correctly assessed")
        print(f"    - Overall score: {report.overall_readiness_score:.1f}/100")
        print(f"    - Readiness level: {report.overall_readiness_level.value}")
        test_results.append(("Full PARTIALLY_READY Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Full PARTIALLY_READY Assessment", False))
        all_passed = False
    
    # Test 11: JSON Export
    print("\n[TEST 11] JSON Export")
    try:
        json_str = assessor.export_assessment_json("test_org_not_ready")
        assert json_str is not None
        data = json.loads(json_str)
        assert "overall_readiness_score" in data
        assert "migration_gaps" in data
        assert "recommendations" in data
        print("  ✓ JSON export successful")
        test_results.append(("JSON Export", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("JSON Export", False))
        all_passed = False
    
    # Test 12: Migration Gap Identification
    print("\n[TEST 12] Migration Gap Identification")
    try:
        report = assessor.get_assessment_report("test_org_not_ready")
        critical_gaps = [g for g in report.migration_gaps if g.risk_level == RiskLevel.CRITICAL]
        high_gaps = [g for g in report.migration_gaps if g.risk_level == RiskLevel.HIGH]
        print(f"  ✓ Migration gaps identified:")
        print(f"    - Critical gaps: {len(critical_gaps)}")
        print(f"    - High gaps: {len(high_gaps)}")
        print(f"    - Total gaps: {len(report.migration_gaps)}")
        test_results.append(("Migration Gap Identification", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Migration Gap Identification", False))
        all_passed = False
    
    # Test 13: Recommendations Generation
    print("\n[TEST 13] Recommendations Generation")
    try:
        report = assessor.get_assessment_report("test_org_not_ready")
        assert len(report.recommendations) > 0
        print("  ✓ Recommendations generated:")
        for i, rec in enumerate(report.recommendations[:5], 1):
            print(f"    {i}. {rec}")
        test_results.append(("Recommendations Generation", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Recommendations Generation", False))
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed_count = 0
    for name, passed in test_results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status} - {name}")
        if passed:
            passed_count += 1
    
    print(f"\nTotal: {passed_count}/{len(test_results)} tests passed")
    
    if all_passed:
        print("\n✅ ALL TESTS PASSED - Production ready!")
    else:
        print(f"\n❌ {len(test_results) - passed_count} TEST(S) FAILED")
    
    # Save results
    result_data = {
        "test_timestamp": datetime.utcnow().isoformat(),
        "total_tests": len(test_results),
        "passed_tests": passed_count,
        "all_passed": all_passed,
        "results": [{"name": n, "passed": p} for n, p in test_results]
    }
    
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_pqc_readiness_assessor.json", "w") as f:
        json.dump(result_data, f, indent=2)
    
    print(f"\nTest results saved to test_results_pqc_readiness_assessor.json")
    
    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
