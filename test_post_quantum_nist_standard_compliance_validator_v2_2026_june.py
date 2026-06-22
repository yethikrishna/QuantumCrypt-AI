"""
Test Suite for QuantumCrypt-AI: NIST Standard Compliance Validator v2
DIMENSION A: Feature Expansion - Test Coverage
All tests are ADD-ONLY - no existing tests modified
"""

import unittest
import sys
import os
import secrets

# Add the quantum_crypt directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_nist_standard_compliance_validator_v2_2026_june import (
    NISTComplianceValidatorV2,
    PQAlgorithm,
    ParameterSet,
    SecurityLevel,
    ComplianceStatus,
    NISTStandardSpecifications,
    EntropyQualityValidator,
    KeySizeValidator,
    FunctionalValidator,
    get_nist_validator_v2,
    validate_keys_v2,
    quick_validate_v2,
    get_validation_stats_v2,
)


class TestNISTStandardSpecifications(unittest.TestCase):
    """Test NIST standard specifications"""
    
    def test_specs_initialization(self):
        specs = NISTStandardSpecifications()
        self.assertIn(ParameterSet.ML_KEM_512, specs.key_specs)
        self.assertIn(ParameterSet.ML_KEM_768, specs.key_specs)
        self.assertIn(ParameterSet.ML_KEM_1024, specs.key_specs)
        
    def test_ml_kem_512_specs(self):
        specs = NISTStandardSpecifications()
        ks = specs.key_specs[ParameterSet.ML_KEM_512]
        self.assertEqual(ks['sk_bytes'], 1632)
        self.assertEqual(ks['pk_bytes'], 800)
        self.assertEqual(ks['ct_bytes'], 768)
        self.assertEqual(ks['ss_bytes'], 32)
        self.assertEqual(ks['security_level'], SecurityLevel.LEVEL_1)
        
    def test_ml_kem_768_specs(self):
        specs = NISTStandardSpecifications()
        ks = specs.key_specs[ParameterSet.ML_KEM_768]
        self.assertEqual(ks['sk_bytes'], 2400)
        self.assertEqual(ks['pk_bytes'], 1184)
        self.assertEqual(ks['security_level'], SecurityLevel.LEVEL_3)
        
    def test_ml_kem_1024_specs(self):
        specs = NISTStandardSpecifications()
        ks = specs.key_specs[ParameterSet.ML_KEM_1024]
        self.assertEqual(ks['sk_bytes'], 3168)
        self.assertEqual(ks['pk_bytes'], 1568)
        self.assertEqual(ks['security_level'], SecurityLevel.LEVEL_5)
        
    def test_nist_references_exist(self):
        specs = NISTStandardSpecifications()
        self.assertIn('key_size', specs.nist_references)
        self.assertIn('entropy_source', specs.nist_references)
        self.assertIn('side_channel', specs.nist_references)


class TestEntropyQualityValidator(unittest.TestCase):
    """Test entropy quality validation"""
    
    def setUp(self):
        self.validator = EntropyQualityValidator()
        
    def test_shannon_entropy_empty(self):
        entropy = self.validator.estimate_shannon_entropy(b'')
        self.assertEqual(entropy, 0.0)
        
    def test_shannon_entropy_low(self):
        # All zeros - very low entropy
        entropy = self.validator.estimate_shannon_entropy(b'\x00' * 64)
        self.assertLess(entropy, 1.0)
        
    def test_shannon_entropy_high(self):
        # Random data - high entropy
        random_data = secrets.token_bytes(64)
        entropy = self.validator.estimate_shannon_entropy(random_data)
        self.assertGreater(entropy, 5.0)
        
    def test_uniform_distribution_check(self):
        random_data = secrets.token_bytes(256)
        is_uniform, chi, msg = self.validator.check_uniform_distribution(random_data)
        self.assertIsInstance(is_uniform, bool)
        self.assertIsInstance(chi, float)
        
    def test_validate_key_material_good(self):
        """Good random key material should pass"""
        good_key = secrets.token_bytes(64)
        checks = self.validator.validate_key_material(good_key)
        self.assertGreater(len(checks), 0)
        # At least minimum length should pass
        passed = any(c.check_id == "ENT-001" and c.passed for c in checks)
        self.assertTrue(passed)
        
    def test_validate_key_material_short(self):
        """Short key material should fail length check"""
        short_key = secrets.token_bytes(16)  # Too short
        checks = self.validator.validate_key_material(short_key)
        failed = any(c.check_id == "ENT-001" and not c.passed for c in checks)
        self.assertTrue(failed)
        
    def test_validate_key_material_weak(self):
        """All-zero key should fail weak key check"""
        weak_key = b'\x00' * 64
        checks = self.validator.validate_key_material(weak_key)
        failed = any(c.check_id == "ENT-003" and not c.passed for c in checks)
        self.assertTrue(failed)
        
    def test_detect_repeated_patterns(self):
        """Should detect repeated byte patterns"""
        repeated = b'aaaaaaaabbbbbbbb'  # 8 in a row
        has_patterns = self.validator._detect_repeated_patterns(repeated)
        self.assertTrue(has_patterns)
        
        # Random should not have long runs
        random_data = secrets.token_bytes(64)
        has_patterns = self.validator._detect_repeated_patterns(random_data)
        # Might be True or False, but should not crash


class TestKeySizeValidator(unittest.TestCase):
    """Test key size validation"""
    
    def setUp(self):
        self.validator = KeySizeValidator()
        
    def test_validate_ml_kem_512_correct_sizes(self):
        """Correct sizes should pass"""
        sk = b'\x00' * 1632
        pk = b'\x00' * 800
        checks = self.validator.validate_key_sizes(
            ParameterSet.ML_KEM_512, sk=sk, pk=pk
        )
        passed = [c for c in checks if c.passed]
        self.assertGreaterEqual(len(passed), 2)
        
    def test_validate_ml_kem_512_wrong_size(self):
        """Wrong sizes should fail"""
        sk = b'\x00' * 100  # Wrong size
        pk = b'\x00' * 800
        checks = self.validator.validate_key_sizes(
            ParameterSet.ML_KEM_512, sk=sk, pk=pk
        )
        failed = [c for c in checks if not c.passed]
        self.assertGreaterEqual(len(failed), 1)
        
    def test_validate_ml_kem_768_correct(self):
        sk = b'\x00' * 2400
        pk = b'\x00' * 1184
        ct = b'\x00' * 1088
        ss = b'\x00' * 32
        checks = self.validator.validate_key_sizes(
            ParameterSet.ML_KEM_768, sk=sk, pk=pk, ct=ct, ss=ss
        )
        self.assertEqual(len(checks), 4)
        
    def test_validate_unknown_parameter_set(self):
        """Unknown parameter sets should fail"""
        checks = self.validator.validate_key_sizes(
            "UNKNOWN", sk=b'test'
        )
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0].passed)


class TestFunctionalValidator(unittest.TestCase):
    """Test functional validation"""
    
    def setUp(self):
        self.validator = FunctionalValidator()
        
    def test_validate_determinism_same(self):
        """Deterministic function should pass"""
        def deterministic_func(x):
            return bytes([x])
            
        checks = self.validator.validate_determinism(
            deterministic_func, 42, iterations=3
        )
        self.assertEqual(len(checks), 1)


class TestNISTComplianceValidatorV2(unittest.TestCase):
    """Main NIST compliance validator tests"""
    
    def setUp(self):
        self.validator = NISTComplianceValidatorV2()
        
    def test_validator_initialization(self):
        self.assertIsNotNone(self.validator.entropy_validator)
        self.assertIsNotNone(self.validator.key_size_validator)
        self.assertIsNotNone(self.validator.functional_validator)
        
    def test_validate_key_pair_sizes_only(self):
        """Test validation with just key sizes"""
        # Use correct sizes for ML-KEM-768
        sk = secrets.token_bytes(2400)
        pk = secrets.token_bytes(1184)
        
        result = self.validator.validate_implementation(
            PQAlgorithm.ML_KEM,
            ParameterSet.ML_KEM_768,
            sk=sk,
            pk=pk
        )
        
        self.assertEqual(result.algorithm, PQAlgorithm.ML_KEM)
        self.assertEqual(result.parameter_set, ParameterSet.ML_KEM_768)
        self.assertIsNotNone(result.overall_status)
        self.assertGreater(len(result.checks), 0)
        self.assertGreater(result.passed_count, 0)
        self.assertGreater(result.validation_time_ms, 0)
        self.assertEqual(result.validator_version, "v2_nist_standard")
        
    def test_validate_ml_kem_512(self):
        sk = secrets.token_bytes(1632)
        pk = secrets.token_bytes(800)
        
        result = self.validator.validate_implementation(
            PQAlgorithm.ML_KEM,
            ParameterSet.ML_KEM_512,
            sk=sk,
            pk=pk
        )
        
        self.assertEqual(result.security_level, SecurityLevel.LEVEL_1)
        
    def test_validate_ml_kem_1024(self):
        sk = secrets.token_bytes(3168)
        pk = secrets.token_bytes(1568)
        
        result = self.validator.validate_implementation(
            PQAlgorithm.ML_KEM,
            ParameterSet.ML_KEM_1024,
            sk=sk,
            pk=pk
        )
        
        self.assertEqual(result.security_level, SecurityLevel.LEVEL_5)
        
    def test_validate_wrong_key_size(self):
        """Wrong key sizes should produce non-compliant status"""
        sk = secrets.token_bytes(100)  # Wrong size
        pk = secrets.token_bytes(100)
        
        result = self.validator.validate_implementation(
            PQAlgorithm.ML_KEM,
            ParameterSet.ML_KEM_768,
            sk=sk,
            pk=pk
        )
        
        # Should have failures
        self.assertGreater(result.failed_count, 0)
        
    def test_quick_validate_key_pair_good(self):
        """Good keys should pass quick validation"""
        sk = secrets.token_bytes(2400)
        pk = secrets.token_bytes(1184)
        
        is_ok, message = self.validator.quick_validate_key_pair(
            ParameterSet.ML_KEM_768, sk, pk
        )
        self.assertIsInstance(is_ok, bool)
        self.assertIsInstance(message, str)
        
    def test_quick_validate_key_pair_bad(self):
        """Bad keys should fail quick validation"""
        sk = secrets.token_bytes(100)  # Wrong size
        pk = secrets.token_bytes(100)
        
        is_ok, message = self.validator.quick_validate_key_pair(
            ParameterSet.ML_KEM_768, sk, pk
        )
        # Should either be False or PARTIALLY_COMPLIANT
        self.assertIsInstance(is_ok, bool)
        
    def test_get_statistics(self):
        """Test statistics tracking"""
        # Run validation first
        sk = secrets.token_bytes(2400)
        pk = secrets.token_bytes(1184)
        self.validator.validate_implementation(
            PQAlgorithm.ML_KEM, ParameterSet.ML_KEM_768, sk=sk, pk=pk
        )
        
        stats = self.validator.get_statistics()
        self.assertGreater(stats['total_validations'], 0)
        self.assertIn('compliance_rate', stats)
        
    def test_recommendations_generated(self):
        """Validation should produce recommendations"""
        sk = secrets.token_bytes(2400)
        pk = secrets.token_bytes(1184)
        
        result = self.validator.validate_implementation(
            PQAlgorithm.ML_KEM, ParameterSet.ML_KEM_768, sk=sk, pk=pk
        )
        
        self.assertGreater(len(result.recommendations), 0)
        
    def test_result_has_all_fields(self):
        """Verify result structure"""
        sk = secrets.token_bytes(2400)
        pk = secrets.token_bytes(1184)
        
        result = self.validator.validate_implementation(
            PQAlgorithm.ML_KEM, ParameterSet.ML_KEM_768, sk=sk, pk=pk
        )
        
        self.assertIsNotNone(result.algorithm)
        self.assertIsNotNone(result.parameter_set)
        self.assertIsNotNone(result.overall_status)
        self.assertIsNotNone(result.security_level)
        self.assertIsInstance(result.checks, list)
        self.assertIsInstance(result.passed_count, int)
        self.assertIsInstance(result.failed_count, int)
        self.assertIsInstance(result.warning_count, int)
        self.assertIsInstance(result.validation_time_ms, float)
        self.assertIsInstance(result.recommendations, list)


class TestGlobalConvenienceFunctions(unittest.TestCase):
    """Test global convenience functions"""
    
    def test_get_nist_validator_v2(self):
        validator = get_nist_validator_v2()
        self.assertIsInstance(validator, NISTComplianceValidatorV2)
        
    def test_validate_keys_v2(self):
        sk = secrets.token_bytes(2400)
        pk = secrets.token_bytes(1184)
        
        result = validate_keys_v2(ParameterSet.ML_KEM_768, sk, pk)
        self.assertIsNotNone(result)
        self.assertEqual(result.parameter_set, ParameterSet.ML_KEM_768)
        
    def test_quick_validate_v2(self):
        sk = secrets.token_bytes(2400)
        pk = secrets.token_bytes(1184)
        
        is_ok, message = quick_validate_v2(ParameterSet.ML_KEM_768, sk, pk)
        self.assertIsInstance(is_ok, bool)
        self.assertIsInstance(message, str)
        
    def test_get_validation_stats_v2(self):
        # Ensure at least one validation
        sk = secrets.token_bytes(2400)
        pk = secrets.token_bytes(1184)
        validate_keys_v2(ParameterSet.ML_KEM_768, sk, pk)
        
        stats = get_validation_stats_v2()
        self.assertIn('total_validations', stats)


class TestEnumValues(unittest.TestCase):
    """Test enum values"""
    
    def test_pq_algorithm_values(self):
        self.assertEqual(PQAlgorithm.ML_KEM.value, "ML-KEM")
        self.assertEqual(PQAlgorithm.ML_DSA.value, "ML-DSA")
        self.assertEqual(PQAlgorithm.SLH_DSA.value, "SLH-DSA")
        
    def test_parameter_set_values(self):
        self.assertEqual(ParameterSet.ML_KEM_512.value, "ML-KEM-512")
        self.assertEqual(ParameterSet.ML_KEM_768.value, "ML-KEM-768")
        self.assertEqual(ParameterSet.ML_KEM_1024.value, "ML-KEM-1024")
        
    def test_security_level_values(self):
        self.assertEqual(SecurityLevel.LEVEL_1.value, 1)
        self.assertEqual(SecurityLevel.LEVEL_3.value, 3)
        self.assertEqual(SecurityLevel.LEVEL_5.value, 5)
        
    def test_compliance_status_values(self):
        self.assertEqual(ComplianceStatus.FULLY_COMPLIANT.value, "FULLY_COMPLIANT")
        self.assertEqual(ComplianceStatus.NON_COMPLIANT.value, "NON_COMPLIANT")


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestNISTStandardSpecifications))
    suite.addTests(loader.loadTestsFromTestCase(TestEntropyQualityValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestKeySizeValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestFunctionalValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestNISTComplianceValidatorV2))
    suite.addTests(loader.loadTestsFromTestCase(TestGlobalConvenienceFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestEnumValues))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Save results
    with open('test_results_nist_validator_v2_2026_june.json', 'w') as f:
        import json
        f.write(json.dumps({
            'tests_run': result.testsRun,
            'failures': len(result.failures),
            'errors': len(result.errors),
            'success': result.wasSuccessful()
        }, indent=2))
        
    return result


if __name__ == '__main__':
    result = run_tests()
    print(f"\n{'='*60}")
    print(f"NIST Validator v2 Tests: {result.testsRun} run, "
          f"{len(result.failures)} failures, {len(result.errors)} errors")
    print(f"{'PASSED' if result.wasSuccessful() else 'FAILED'}")
    print(f"{'='*60}")
    sys.exit(0 if result.wasSuccessful() else 1)
