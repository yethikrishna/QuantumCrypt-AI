#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Algorithm Recommendation & Selection Engine
June 19, 2026 - Production Grade Tests

Verifies all core functionality:
- Algorithm profile initialization
- Algorithm listing and filtering
- Security match scoring
- Performance match scoring
- Migration scoring
- Full recommendation generation
- Migration plan generation
- Edge cases and error handling
"""
import json
import sys
sys.path.insert(0, 'quantum_crypt')

from datetime import datetime
from post_quantum_algorithm_recommendation_selection_engine_2026_june import (
    PostQuantumAlgorithmSelector,
    SelectionCriteria,
    NISTSecurityLevel,
    NISTStatus,
    UseCaseCategory,
    AlgorithmType
)


def run_tests():
    """Execute all tests and return results."""
    test_results = {
        'tests_passed': 0,
        'tests_failed': 0,
        'test_details': [],
        'timestamp': datetime.now().isoformat()
    }

    selector = PostQuantumAlgorithmSelector()

    # Test 1: Algorithm Profile Initialization
    print("Test 1: Algorithm Profile Initialization")
    try:
        algorithms = selector.list_available_algorithms()
        assert len(algorithms) >= 10, f"Should have at least 10 algorithms, got {len(algorithms)}"
        
        kyber = selector.get_algorithm_profile("CRYSTALS-Kyber-768")
        assert kyber is not None, "CRYSTALS-Kyber-768 should exist"
        assert kyber.nist_status == NISTStatus.STANDARDIZED, "Kyber should be standardized"
        assert kyber.nist_security_level == NISTSecurityLevel.LEVEL_3
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Algorithm Profile Initialization',
            'status': 'PASSED',
            'message': f'Successfully loaded {len(algorithms)} algorithm profiles'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Algorithm Profile Initialization',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 2: Algorithm Filtering by Type
    print("\nTest 2: Algorithm Filtering by Type")
    try:
        kems = selector.list_available_algorithms(AlgorithmType.KEM)
        signatures = selector.list_available_algorithms(AlgorithmType.SIGNATURE)
        
        assert len(kems) >= 5, f"Should have KEM algorithms"
        assert len(signatures) >= 4, f"Should have signature algorithms"
        
        assert "CRYSTALS-Kyber-768" in kems
        assert "CRYSTALS-Dilithium-3" in signatures
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Algorithm Filtering by Type',
            'status': 'PASSED',
            'message': f'{len(kems)} KEMs, {len(signatures)} Signatures'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Algorithm Filtering by Type',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 3: Security Match Score Calculation
    print("\nTest 3: Security Match Score Calculation")
    try:
        criteria = SelectionCriteria(
            use_case=UseCaseCategory.TLS_HANDSHAKE,
            required_security_level=NISTSecurityLevel.LEVEL_3,
            performance_requirements={},
            platform_constraints=set(),
            compliance_requirements=set(),
            migration_timeline_months=12,
            risk_tolerance="conservative",
            resource_constraints={}
        )
        
        kyber_profile = selector.algorithm_profiles["CRYSTALS-Kyber-768"]
        score, notes = selector.calculate_security_match_score(kyber_profile, criteria)
        
        assert 0 <= score <= 100, "Score should be in valid range"
        assert isinstance(notes, list)
        assert score >= 80, "Standardized algorithm should score well"
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Security Match Score Calculation',
            'status': 'PASSED',
            'message': f'Score: {score:.1f}, Notes: {len(notes)}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Security Match Score Calculation',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 4: Performance Match Score Calculation
    print("\nTest 4: Performance Match Score Calculation")
    try:
        criteria = SelectionCriteria(
            use_case=UseCaseCategory.TLS_HANDSHAKE,
            required_security_level=NISTSecurityLevel.LEVEL_1,
            performance_requirements={},
            platform_constraints=set(),
            compliance_requirements=set(),
            migration_timeline_months=12,
            risk_tolerance="moderate",
            resource_constraints={}
        )
        
        kyber_profile = selector.algorithm_profiles["CRYSTALS-Kyber-512"]
        score, notes = selector.calculate_performance_match_score(kyber_profile, criteria)
        
        assert 0 <= score <= 100
        assert isinstance(notes, list)
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Performance Match Score Calculation',
            'status': 'PASSED',
            'message': f'Score: {score:.1f}, Notes: {len(notes)}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Performance Match Score Calculation',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 5: Migration Score Calculation
    print("\nTest 5: Migration Score Calculation")
    try:
        criteria = SelectionCriteria(
            use_case=UseCaseCategory.TLS_HANDSHAKE,
            required_security_level=NISTSecurityLevel.LEVEL_1,
            performance_requirements={},
            platform_constraints=set(),
            compliance_requirements=set(),
            migration_timeline_months=12,
            risk_tolerance="moderate",
            resource_constraints={}
        )
        
        kyber_profile = selector.algorithm_profiles["CRYSTALS-Kyber-512"]
        score, notes = selector.calculate_migration_score(kyber_profile, criteria)
        
        assert 0 <= score <= 100
        assert isinstance(notes, list)
        assert score >= 80, "Production-ready algorithm should have high migration score"
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Migration Score Calculation',
            'status': 'PASSED',
            'message': f'Score: {score:.1f}, Notes: {len(notes)}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Migration Score Calculation',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 6: TLS Handshake Recommendations
    print("\nTest 6: TLS Handshake Recommendations")
    try:
        criteria = SelectionCriteria(
            use_case=UseCaseCategory.TLS_HANDSHAKE,
            required_security_level=NISTSecurityLevel.LEVEL_3,
            performance_requirements={"max_latency_ms": 1.0},
            platform_constraints={"x86_64"},
            compliance_requirements={"FIPS 140-3"},
            migration_timeline_months=6,
            risk_tolerance="conservative",
            resource_constraints={}
        )
        
        recommendations = selector.recommend_algorithms(criteria, top_n=3)
        
        assert len(recommendations) >= 1, "Should get at least 1 recommendation"
        assert recommendations[0].match_score >= 0
        assert recommendations[0].suitability_rating in ["EXCELLENT_MATCH", "GOOD_MATCH", "FAIR_MATCH"]
        
        # Top recommendation for TLS should be Kyber
        assert "Kyber" in recommendations[0].algorithm_name
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'TLS Handshake Recommendations',
            'status': 'PASSED',
            'message': f'Top: {recommendations[0].algorithm_name} ({recommendations[0].match_score})'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'TLS Handshake Recommendations',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 7: Code Signing Recommendations
    print("\nTest 7: Code Signing Recommendations")
    try:
        criteria = SelectionCriteria(
            use_case=UseCaseCategory.CODE_SIGNING,
            required_security_level=NISTSecurityLevel.LEVEL_3,
            performance_requirements={},
            platform_constraints=set(),
            compliance_requirements=set(),
            migration_timeline_months=12,
            risk_tolerance="conservative",
            resource_constraints={}
        )
        
        recommendations = selector.recommend_algorithms(criteria, top_n=3)
        
        assert len(recommendations) >= 1
        # Should recommend Dilithium for code signing
        has_dilithium = any("Dilithium" in r.algorithm_name for r in recommendations)
        assert has_dilithium, "Dilithium should be recommended for code signing"
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Code Signing Recommendations',
            'status': 'PASSED',
            'message': f'Top: {recommendations[0].algorithm_name}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Code Signing Recommendations',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 8: IoT Constrained Device Recommendations
    print("\nTest 8: IoT Constrained Device Recommendations")
    try:
        criteria = SelectionCriteria(
            use_case=UseCaseCategory.IOT,
            required_security_level=NISTSecurityLevel.LEVEL_1,
            performance_requirements={},
            platform_constraints={"ARM", "embedded"},
            compliance_requirements=set(),
            migration_timeline_months=12,
            risk_tolerance="moderate",
            resource_constraints={"max_memory_mb": 2.0}
        )
        
        recommendations = selector.recommend_algorithms(criteria, top_n=5)
        
        assert len(recommendations) >= 1
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'IoT Constrained Device Recommendations',
            'status': 'PASSED',
            'message': f'Top: {recommendations[0].algorithm_name}'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'IoT Constrained Device Recommendations',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 9: Migration Plan Generation
    print("\nTest 9: Migration Plan Generation")
    try:
        plan = selector.generate_migration_plan("CRYSTALS-Kyber-768", timeline_months=12)
        
        assert plan['algorithm'] == "CRYSTALS-Kyber-768"
        assert 'migration_phases' in plan
        assert len(plan['migration_phases']) == 4
        assert 'key_considerations' in plan
        assert 'recommended_libraries' in plan
        assert len(plan['key_considerations']) >= 3
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Migration Plan Generation',
            'status': 'PASSED',
            'message': f'Generated {len(plan["migration_phases"])} phase plan'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Migration Plan Generation',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 10: Accelerated Migration Plan
    print("\nTest 10: Accelerated Migration Plan")
    try:
        plan = selector.generate_migration_plan("CRYSTALS-Dilithium-3", timeline_months=3)
        
        assert len(plan['migration_phases']) == 1
        assert plan['migration_phases'][0]['phase'] == 'Accelerated Migration'
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Accelerated Migration Plan',
            'status': 'PASSED',
            'message': 'Generated accelerated migration plan'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Accelerated Migration Plan',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 11: Invalid Algorithm Error Handling
    print("\nTest 11: Invalid Algorithm Error Handling")
    try:
        try:
            selector.generate_migration_plan("NonExistentAlgorithm")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "not found" in str(e)
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Invalid Algorithm Error Handling',
            'status': 'PASSED',
            'message': 'Correctly raised ValueError for unknown algorithm'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Invalid Algorithm Error Handling',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Test 12: Recommendation Assessment Structure
    print("\nTest 12: Recommendation Assessment Structure")
    try:
        criteria = SelectionCriteria(
            use_case=UseCaseCategory.DATA_AT_REST,
            required_security_level=NISTSecurityLevel.LEVEL_5,
            performance_requirements={},
            platform_constraints=set(),
            compliance_requirements=set(),
            migration_timeline_months=18,
            risk_tolerance="moderate",
            resource_constraints={}
        )
        
        recommendations = selector.recommend_algorithms(criteria, top_n=1)
        rec = recommendations[0]
        
        assert hasattr(rec, 'security_assessment')
        assert hasattr(rec, 'performance_assessment')
        assert hasattr(rec, 'compatibility_notes')
        assert hasattr(rec, 'risk_factors')
        assert hasattr(rec, 'implementation_recommendations')
        assert isinstance(rec.risk_factors, list)
        assert isinstance(rec.implementation_recommendations, list)
        
        test_results['tests_passed'] += 1
        test_results['test_details'].append({
            'test': 'Recommendation Assessment Structure',
            'status': 'PASSED',
            'message': 'All assessment fields properly populated'
        })
        print("  ✓ PASSED")
    except AssertionError as e:
        test_results['tests_failed'] += 1
        test_results['test_details'].append({
            'test': 'Recommendation Assessment Structure',
            'status': 'FAILED',
            'message': str(e)
        })
        print(f"  ✗ FAILED: {e}")

    # Print final summary
    print("\n" + "="*60)
    print(f"TEST SUMMARY: {test_results['tests_passed']} PASSED, {test_results['tests_failed']} FAILED")
    print("="*60)

    return test_results


if __name__ == "__main__":
    results = run_tests()
    
    # Save results to JSON
    with open('test_results_algorithm_recommendation_selection_engine.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_algorithm_recommendation_selection_engine.json")
    
    # Exit with appropriate code
    sys.exit(0 if results['tests_failed'] == 0 else 1)
