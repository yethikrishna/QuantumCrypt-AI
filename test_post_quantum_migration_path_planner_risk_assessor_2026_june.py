#!/usr/bin/env python3
"""
Test suite for Post-Quantum Cryptography Migration Path Planner
QuantumCrypt-AI Production Tests
"""

import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_migration_path_planner_risk_assessor_2026_june import (
    PostQuantumMigrationPlanner,
    get_migration_planner,
    NIST_STANDARD_PQC,
    CLASSICAL_ALGORITHM_RISK,
    AlgorithmSecurityLevel,
    QuantumVulnerability
)


def run_tests():
    print("=" * 70)
    print("QuantumCrypt-AI: PQC Migration Path Planner - Test Suite")
    print("=" * 70)
    
    all_passed = True
    test_results = []
    
    # Test 1: Data integrity - NIST PQC Standards
    print("\n[TEST 1] NIST PQC Standards data integrity")
    try:
        assert len(NIST_STANDARD_PQC) == 4, "Should have 4 NIST-standard algorithms"
        assert 'CRYSTALS-Kyber' in NIST_STANDARD_PQC, "Kyber should be included"
        assert 'CRYSTALS-Dilithium' in NIST_STANDARD_PQC, "Dilithium should be included"
        assert 'FALCON' in NIST_STANDARD_PQC, "FALCON should be included"
        assert 'SPHINCS+' in NIST_STANDARD_PQC, "SPHINCS+ should be included"
        
        for name, info in NIST_STANDARD_PQC.items():
            assert info['nist_standard'] == True, f"{name} should be NIST standard"
            assert 'security_level' in info, f"{name} should have security level"
            assert 'use_cases' in info, f"{name} should have use cases"
        
        print("  ✓ PASSED: NIST PQC standards data is complete")
        test_results.append(("NIST PQC Standards Data", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("NIST PQC Standards Data", False))
        all_passed = False
    
    # Test 2: Data integrity - Classical Algorithm Risk
    print("\n[TEST 2] Classical Algorithm Risk data integrity")
    try:
        assert len(CLASSICAL_ALGORITHM_RISK) >= 11, "Should have comprehensive algorithm coverage"
        
        # Check critical algorithms
        assert CLASSICAL_ALGORITHM_RISK['RSA-2048']['vulnerability'] == QuantumVulnerability.CRITICAL
        assert CLASSICAL_ALGORITHM_RISK['ECC-P256']['vulnerability'] == QuantumVulnerability.CRITICAL
        assert CLASSICAL_ALGORITHM_RISK['AES-256']['vulnerability'] == QuantumVulnerability.QUANTUM_SAFE
        assert CLASSICAL_ALGORITHM_RISK['SHA-3']['vulnerability'] == QuantumVulnerability.QUANTUM_SAFE
        
        print("  ✓ PASSED: Classical algorithm risk data is comprehensive")
        test_results.append(("Classical Algorithm Risk Data", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Classical Algorithm Risk Data", False))
        all_passed = False
    
    # Test 3: Planner initialization
    print("\n[TEST 3] Planner initialization")
    try:
        planner = PostQuantumMigrationPlanner()
        assert planner.crypto_inventory == [], "Inventory should be empty initially"
        assert planner.assessment_results == {}, "Results should be empty initially"
        
        print("  ✓ PASSED: Planner initializes correctly")
        test_results.append(("Planner Initialization", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Planner Initialization", False))
        all_passed = False
    
    # Test 4: Add single crypto asset
    print("\n[TEST 4] Add single cryptographic asset")
    try:
        planner = PostQuantumMigrationPlanner()
        asset = {
            'system_name': 'Test TLS Server',
            'system_type': 'TLS_WEBSERVER',
            'algorithm': 'ECC-P256',
            'key_size': 256,
            'usage_count': 100,
            'business_impact': 'HIGH',
            'data_sensitivity': 'CONFIDENTIAL'
        }
        asset_id = planner.add_crypto_asset(asset)
        
        assert len(asset_id) == 12, "Asset ID should be 12 chars"
        assert len(planner.crypto_inventory) == 1, "Should have 1 asset"
        assert planner.crypto_inventory[0]['asset_id'] == asset_id, "ID should match"
        
        print(f"  ✓ PASSED: Asset added with ID: {asset_id}")
        test_results.append(("Add Single Asset", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Add Single Asset", False))
        all_passed = False
    
    # Test 5: Batch add assets
    print("\n[TEST 5] Batch add multiple assets")
    try:
        planner = PostQuantumMigrationPlanner()
        assets = [
            {'system_name': f'System {i}', 'system_type': 'SSH', 'algorithm': 'RSA-2048',
             'key_size': 2048, 'usage_count': 10, 'business_impact': 'MEDIUM', 
             'data_sensitivity': 'INTERNAL'}
            for i in range(5)
        ]
        asset_ids = planner.batch_add_assets(assets)
        
        assert len(asset_ids) == 5, "Should return 5 asset IDs"
        assert len(planner.crypto_inventory) == 5, "Should have 5 assets"
        assert len(set(asset_ids)) == 5, "All IDs should be unique"
        
        print("  ✓ PASSED: Batch added 5 assets successfully")
        test_results.append(("Batch Add Assets", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Batch Add Assets", False))
        all_passed = False
    
    # Test 6: Single asset vulnerability assessment
    print("\n[TEST 6] Single asset vulnerability assessment")
    try:
        planner = PostQuantumMigrationPlanner()
        asset = {
            'system_name': 'Critical Root CA',
            'system_type': 'ROOT_CA',
            'algorithm': 'RSA-4096',
            'key_size': 4096,
            'usage_count': 1000,
            'business_impact': 'HIGH',
            'data_sensitivity': 'CRITICAL'
        }
        planner.add_crypto_asset(asset)
        assessment = planner.assess_quantum_vulnerability(planner.crypto_inventory[0])
        
        assert 'qv_score' in assessment, "Should have QV score"
        assert 'composite_risk_score' in assessment, "Should have composite risk"
        assert 'migration_urgency' in assessment, "Should have urgency"
        assert 'recommended_replacement' in assessment, "Should have recommendation"
        
        assert 0 <= assessment['qv_score'] <= 100, "QV score should be 0-100"
        assert assessment['shor_algorithm_vulnerable'] == True, "RSA is Shor-vulnerable"
        
        print(f"    QV Score: {assessment['qv_score']}")
        print(f"    Vulnerability: {assessment['quantum_vulnerability_level']}")
        print(f"    Urgency: {assessment['migration_urgency']}")
        
        print("  ✓ PASSED: Single asset assessment works")
        test_results.append(("Single Asset Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Single Asset Assessment", False))
        all_passed = False
    
    # Test 7: Full assessment run
    print("\n[TEST 7] Full vulnerability assessment")
    try:
        planner = PostQuantumMigrationPlanner()
        test_assets = [
            {'system_name': 'TLS', 'system_type': 'TLS_WEBSERVER', 'algorithm': 'ECC-P256',
             'key_size': 256, 'usage_count': 50, 'business_impact': 'HIGH', 'data_sensitivity': 'CONFIDENTIAL'},
            {'system_name': 'DB', 'system_type': 'DATABASE_ENCRYPTION', 'algorithm': 'AES-256',
             'key_size': 256, 'usage_count': 10, 'business_impact': 'HIGH', 'data_sensitivity': 'CRITICAL'},
            {'system_name': 'VPN', 'system_type': 'VPN_GATEWAY', 'algorithm': 'ECC-P384',
             'key_size': 384, 'usage_count': 20, 'business_impact': 'HIGH', 'data_sensitivity': 'CONFIDENTIAL'},
        ]
        planner.batch_add_assets(test_assets)
        results = planner.run_full_assessment()
        
        assert results['total_assets_assessed'] == 3, "Should assess 3 assets"
        assert 'average_qv_score' in results, "Should have average QV"
        assert 'overall_quantum_readiness' in results, "Should have readiness score"
        assert 'risk_distribution' in results, "Should have risk distribution"
        
        print(f"    Total Assets: {results['total_assets_assessed']}")
        print(f"    Avg QV Score: {results['average_qv_score']}")
        print(f"    Overall Readiness: {results['overall_quantum_readiness']}/100")
        
        print("  ✓ PASSED: Full assessment runs correctly")
        test_results.append(("Full Assessment", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Full Assessment", False))
        all_passed = False
    
    # Test 8: Migration roadmap generation
    print("\n[TEST 8] Migration roadmap generation")
    try:
        planner = PostQuantumMigrationPlanner()
        test_assets = [
            {'system_name': 'Root CA', 'system_type': 'ROOT_CA', 'algorithm': 'RSA-4096',
             'key_size': 4096, 'usage_count': 1000, 'business_impact': 'HIGH', 'data_sensitivity': 'CRITICAL'},
            {'system_name': 'TLS', 'system_type': 'TLS_WEBSERVER', 'algorithm': 'ECC-P256',
             'key_size': 256, 'usage_count': 50, 'business_impact': 'HIGH', 'data_sensitivity': 'CONFIDENTIAL'},
        ]
        planner.batch_add_assets(test_assets)
        roadmap = planner.generate_migration_roadmap()
        
        assert len(roadmap) == 2, "Should have 2 roadmap items"
        for item in roadmap:
            assert 'migration_id' in item, "Should have migration ID"
            assert 'priority' in item, "Should have priority"
            assert 'target_algorithm' in item, "Should have target algorithm"
            assert 'estimated_effort_hours' in item, "Should have effort estimate"
            assert 'success_criteria' in item, "Should have success criteria"
            assert 'rollback_plan' in item, "Should have rollback plan"
        
        # Check prioritization (higher priority first)
        assert roadmap[0]['priority'] == 1, "First item should be priority 1"
        assert roadmap[1]['priority'] == 2, "Second item should be priority 2"
        
        print(f"    Roadmap items: {len(roadmap)}")
        print(f"    Top priority: {roadmap[0]['system_name']} ({roadmap[0]['urgency']})")
        
        print("  ✓ PASSED: Migration roadmap generated correctly")
        test_results.append(("Roadmap Generation", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Roadmap Generation", False))
        all_passed = False
    
    # Test 9: Executive summary generation
    print("\n[TEST 9] Executive summary generation")
    try:
        planner = PostQuantumMigrationPlanner()
        test_assets = [
            {'system_name': 'Root CA', 'system_type': 'ROOT_CA', 'algorithm': 'RSA-4096',
             'key_size': 4096, 'usage_count': 1000, 'business_impact': 'HIGH', 'data_sensitivity': 'CRITICAL'},
            {'system_name': 'Code Signing', 'system_type': 'CODE_SIGNING', 'algorithm': 'RSA-3072',
             'key_size': 3072, 'usage_count': 5, 'business_impact': 'HIGH', 'data_sensitivity': 'CRITICAL'},
            {'system_name': 'TLS', 'system_type': 'TLS_WEBSERVER', 'algorithm': 'ECC-P256',
             'key_size': 256, 'usage_count': 50, 'business_impact': 'HIGH', 'data_sensitivity': 'CONFIDENTIAL'},
            {'system_name': 'DB AES-256', 'system_type': 'DATABASE_ENCRYPTION', 'algorithm': 'AES-256',
             'key_size': 256, 'usage_count': 10, 'business_impact': 'HIGH', 'data_sensitivity': 'CRITICAL'},
        ]
        planner.batch_add_assets(test_assets)
        summary = planner.get_executive_summary()
        
        assert 'overall_quantum_readiness_score' in summary
        assert 'readiness_rating' in summary
        assert 'key_findings' in summary
        assert 'recommendations' in summary
        assert 'total_estimated_effort_hours' in summary
        
        assert len(summary['key_findings']) >= 5, "Should have at least 5 key findings"
        assert len(summary['recommendations']) >= 4, "Should have at least 4 recommendations"
        
        print(f"    Readiness Score: {summary['overall_quantum_readiness_score']}/100")
        print(f"    Readiness Rating: {summary['readiness_rating']}")
        print(f"    Total Effort: {summary['total_estimated_effort_hours']} hours")
        
        print("  ✓ PASSED: Executive summary generated correctly")
        test_results.append(("Executive Summary", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Executive Summary", False))
        all_passed = False
    
    # Test 10: Singleton pattern and report export
    print("\n[TEST 10] Singleton pattern and report export")
    try:
        planner1 = get_migration_planner()
        planner2 = get_migration_planner()
        assert planner1 is planner2, "Should return same singleton instance"
        
        # Test report export
        planner1.batch_add_assets([
            {'system_name': 'Test', 'system_type': 'SSH', 'algorithm': 'RSA-2048',
             'key_size': 2048, 'usage_count': 1, 'business_impact': 'MEDIUM', 'data_sensitivity': 'INTERNAL'}
        ])
        success = planner1.export_report('/tmp/pqc_migration_report.json')
        assert success == True, "Report export should succeed"
        
        # Verify file exists and is valid JSON
        with open('/tmp/pqc_migration_report.json') as f:
            report = json.load(f)
            assert 'executive_summary' in report
            assert 'migration_roadmap' in report
        
        print("  ✓ PASSED: Singleton and report export work")
        test_results.append(("Singleton & Report Export", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Singleton & Report Export", False))
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, ok in test_results if ok)
    total = len(test_results)
    
    for name, ok in test_results:
        status = "✓ PASS" if ok else "✗ FAIL"
        print(f"  {status} - {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    # Save test results
    test_output = {
        'test_timestamp': __import__('datetime').datetime.now().isoformat(),
        'module': 'post_quantum_migration_path_planner_risk_assessor',
        'passed': passed,
        'total': total,
        'success_rate': passed / total,
        'all_passed': all_passed,
        'test_details': [{'name': n, 'passed': o} for n, o in test_results]
    }
    
    with open('test_results_pqc_migration_path_planner.json', 'w') as f:
        json.dump(test_output, f, indent=2)
    
    print(f"\nTest results saved to test_results_pqc_migration_path_planner.json")
    
    if all_passed:
        print("\n✓ ALL TESTS PASSED! Feature is production-ready.")
        return 0
    else:
        print("\n✗ SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
