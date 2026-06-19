#!/usr/bin/env python3
"""
Test suite for Post-Quantum Migration Path Planner & Risk Assessor
June 2026 Production Release

REAL TESTS - NO EMPTY SHELLS
"""

import sys
import json
import importlib.util

# Load module directly
spec = importlib.util.spec_from_file_location(
    'migration_planner',
    '/home/user/autonomous-developer/QuantumCrypt-AI/quantum_crypt/post_quantum_migration_path_planner_risk_assessor_2026_june.py'
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

PostQuantumMigrationPlanner = module.PostQuantumMigrationPlanner
CryptoInventoryItem = module.CryptoInventoryItem
CryptoAlgorithmType = module.CryptoAlgorithmType
QuantumRiskLevel = module.QuantumRiskLevel
MigrationPriority = module.MigrationPriority
MigrationPhase = module.MigrationPhase


def run_tests():
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum Migration Planner Tests")
    print("=" * 70)
    
    planner = PostQuantumMigrationPlanner()
    passed = 0
    failed = 0
    
    # Test 1: Add inventory items
    print("\n[TEST 1] Add inventory items")
    try:
        item1 = CryptoInventoryItem(
            item_id="sys_001",
            algorithm_name="RSA-2048",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            key_size=2048,
            usage_context="TLS",
            system_name="Payment_Gateway",
            location="prod_us_east",
            data_sensitivity="restricted",
            business_impact="critical"
        )
        item2 = CryptoInventoryItem(
            item_id="sys_002",
            algorithm_name="ECDSA-P256",
            algorithm_type=CryptoAlgorithmType.SIGNATURE,
            key_size=256,
            usage_context="JWT_tokens",
            system_name="Auth_Service",
            location="prod_eu_west",
            data_sensitivity="confidential",
            business_impact="high"
        )
        item3 = CryptoInventoryItem(
            item_id="sys_003",
            algorithm_name="AES-256",
            algorithm_type=CryptoAlgorithmType.SYMMETRIC_ENCRYPTION,
            key_size=256,
            usage_context="data_at_rest",
            system_name="Database",
            location="prod_ap_south",
            data_sensitivity="confidential",
            business_impact="high"
        )
        item4 = CryptoInventoryItem(
            item_id="sys_004",
            algorithm_name="CRYSTALS-Kyber-768",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            key_size=768,
            usage_context="internal_api",
            system_name="Internal_API",
            location="staging",
            data_sensitivity="internal",
            business_impact="medium"
        )
        
        planner.add_inventory_item(item1)
        planner.add_inventory_item(item2)
        planner.add_inventory_item(item3)
        planner.add_inventory_item(item4)
        
        assert len(planner.inventory) == 4
        print(f"  ✓ PASS: Added {len(planner.inventory)} inventory items")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 2: Algorithm risk assessment - RSA-2048 (CRITICAL)
    print("\n[TEST 2] Risk assessment - RSA-2048")
    try:
        assessment = planner.assess_algorithm_risk("RSA-2048")
        assert assessment.risk_level == QuantumRiskLevel.CRITICAL
        assert assessment.risk_score >= 0.9
        assert len(assessment.recommended_replacements) > 0
        print(f"  ✓ PASS: RSA-2048 = CRITICAL risk (score={assessment.risk_score})")
        print(f"    Replacements: {assessment.recommended_replacements}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 3: Algorithm risk assessment - ECDSA-P256 (CRITICAL)
    print("\n[TEST 3] Risk assessment - ECDSA-P256")
    try:
        assessment = planner.assess_algorithm_risk("ECDSA-P256")
        assert assessment.risk_level == QuantumRiskLevel.CRITICAL
        print(f"  ✓ PASS: ECDSA-P256 = CRITICAL risk (score={assessment.risk_score})")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 4: Algorithm risk assessment - CRYSTALS-Kyber (QUANTUM_RESISTANT)
    print("\n[TEST 4] Risk assessment - CRYSTALS-Kyber-768")
    try:
        assessment = planner.assess_algorithm_risk("CRYSTALS-Kyber-768")
        assert assessment.risk_level == QuantumRiskLevel.QUANTUM_RESISTANT
        assert assessment.risk_score <= 0.1
        print(f"  ✓ PASS: CRYSTALS-Kyber-768 = QUANTUM_RESISTANT (score={assessment.risk_score})")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 5: Full inventory assessment
    print("\n[TEST 5] Full inventory assessment")
    try:
        results = planner.assess_all_inventory()
        assert results["total_items"] == 4
        assert results["by_risk_level"]["critical"] >= 2
        assert len(results["critical_systems"]) >= 1
        print(f"  ✓ PASS: Assessed {results['total_items']} items")
        print(f"    Risk breakdown: {dict(results['by_risk_level'])}")
        print(f"    Critical systems: {len(results['critical_systems'])}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 6: Migration priority calculation
    print("\n[TEST 6] Migration priority calculation")
    try:
        item = planner.inventory[0]  # RSA-2048, critical impact
        assessment = planner.assess_algorithm_risk(item.algorithm_name)
        priority = planner.calculate_migration_priority(item, assessment)
        assert priority == MigrationPriority.IMMEDIATE
        print(f"  ✓ PASS: RSA-2048 + critical impact = IMMEDIATE priority")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 7: Effort estimation
    print("\n[TEST 7] Migration effort estimation")
    try:
        item = planner.inventory[0]
        effort = planner.estimate_migration_effort(item, "CRYSTALS-Kyber-768")
        assert effort > 0
        print(f"  ✓ PASS: Estimated {effort} hours for migration")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 8: Generate migration tasks
    print("\n[TEST 8] Generate migration tasks")
    try:
        tasks = planner.generate_migration_tasks()
        # Should generate tasks for non-PQC algorithms (3 out of 4)
        assert len(tasks) >= 2
        immediate_tasks = [t for t in tasks if t.priority == MigrationPriority.IMMEDIATE]
        assert len(immediate_tasks) >= 1
        print(f"  ✓ PASS: Generated {len(tasks)} migration tasks")
        print(f"    Immediate: {len([t for t in tasks if t.priority == MigrationPriority.IMMEDIATE])}")
        print(f"    Phase 1: {len([t for t in tasks if t.phase == MigrationPhase.PHASE_1])}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 9: Generate milestones
    print("\n[TEST 9] Generate migration milestones")
    try:
        milestones = planner.generate_milestones()
        assert len(milestones) == 5
        assert milestones[0].phase == MigrationPhase.ASSESSMENT
        assert milestones[-1].phase == MigrationPhase.PHASE_3
        print(f"  ✓ PASS: Generated {len(milestones)} milestones")
        for m in milestones:
            print(f"    - {m.name}: {m.target_date}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 10: Generate full roadmap
    print("\n[TEST 10] Generate migration roadmap")
    try:
        roadmap = planner.generate_migration_roadmap()
        assert roadmap.total_algorithms == 4
        assert roadmap.critical_risk_count >= 2
        assert len(roadmap.phases) >= 3
        assert len(roadmap.milestones) == 5
        assert roadmap.total_effort_hours > 0
        print(f"  ✓ PASS: Generated roadmap {roadmap.roadmap_id}")
        print(f"    Systems: {roadmap.total_systems}, Algorithms: {roadmap.total_algorithms}")
        print(f"    Critical risk: {roadmap.critical_risk_count}, High risk: {roadmap.high_risk_count}")
        print(f"    Total effort: {roadmap.total_effort_hours} hours")
        print(f"    Completion: {roadmap.estimated_completion_date}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 11: Algorithm compatibility check
    print("\n[TEST 11] Algorithm compatibility check")
    try:
        result = planner.check_algorithm_compatibility("RSA-2048", "CRYSTALS-Kyber-768")
        assert result.is_compatible == True
        assert result.compatibility_score >= 0.8
        print(f"  ✓ PASS: RSA-2048 + Kyber-768 compatible (score={result.compatibility_score})")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 12: Executive summary
    print("\n[TEST 12] Executive summary")
    try:
        roadmap = planner.generate_migration_roadmap()
        summary = planner.get_executive_summary(roadmap)
        assert "urgent_actions_required" in summary
        assert "critical_systems_at_risk" in summary
        assert "total_migration_effort_fte" in summary
        print(f"  ✓ PASS: Executive summary generated")
        print(f"    Urgent action needed: {summary['urgent_actions_required']}")
        print(f"    Critical systems at risk: {summary['critical_systems_at_risk']}")
        print(f"    Effort: {summary['total_migration_effort_fte']} FTE-months")
        print(f"    Duration: {summary['estimated_duration_months']} months")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 13: Codebase scanning simulation
    print("\n[TEST 13] Codebase scanning simulation")
    try:
        patterns = ["RSA encryption", "ECDSA sign", "AES-256-GCM", "SHA256 hash"]
        discovered = planner.scan_codebase_for_crypto(patterns)
        assert len(discovered) >= 3
        print(f"  ✓ PASS: Discovered {len(discovered)} crypto usages")
        for d in discovered[:3]:
            print(f"    - {d.algorithm_name} in {d.location}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 14: Risk mitigation recommendations
    print("\n[TEST 14] Risk mitigation recommendations")
    try:
        roadmap = planner.generate_migration_roadmap()
        assert len(roadmap.risk_mitigation_recommendations) >= 3
        print(f"  ✓ PASS: {len(roadmap.risk_mitigation_recommendations)} recommendations")
        for rec in roadmap.risk_mitigation_recommendations[:3]:
            print(f"    - {rec[:60]}...")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 15: Compliance gap detection
    print("\n[TEST 15] Compliance gap detection")
    try:
        roadmap = planner.generate_migration_roadmap()
        assert len(roadmap.compliance_gaps) >= 1
        print(f"  ✓ PASS: Detected {len(roadmap.compliance_gaps)} compliance gaps")
        for gap in roadmap.compliance_gaps[:2]:
            print(f"    - {gap[:60]}...")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Test 16: Roadmap JSON export
    print("\n[TEST 16] Roadmap JSON export")
    try:
        roadmap = planner.generate_migration_roadmap()
        json_output = planner.export_roadmap_json(roadmap)
        parsed = json.loads(json_output)
        assert "summary" in parsed
        assert "phases" in parsed
        assert "milestones" in parsed
        print(f"  ✓ PASS: JSON export successful")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 70)
    
    # Save test results
    results = {
        "test_module": "post_quantum_migration_path_planner_risk_assessor_2026_june",
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "success_rate": passed / (passed + failed) * 100 if (passed + failed) > 0 else 0,
        "timestamp": __import__("time").time()
    }
    
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_pqc_migration_path_planner.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nTest results saved to test_results_pqc_migration_path_planner.json")
    print(f"Success rate: {results['success_rate']:.1f}%")
    
    return results


if __name__ == "__main__":
    results = run_tests()
    sys.exit(0 if results["failed"] == 0 else 1)
