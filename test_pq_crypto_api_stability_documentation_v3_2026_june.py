"""
Test Suite for QuantumCrypt PQ Crypto API Stability Documentation v3
====================================================================
DIMENSION F: Documentation & API Stability

Tests verify:
1. NIST standard enums work correctly
2. Crypto decorators apply metadata correctly
3. Catalog registration and querying work
4. NIST compliance matrix generation works
5. No breaking changes to existing code
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

import unittest
import warnings

from pq_crypto_api_stability_documentation_v3_2026_june import (
    NISTStandard,
    StabilityLevel,
    SecurityLevel,
    SupportLevel,
    CryptoAPIMetadata,
    CryptoUsageExample,
    nist_standard_api,
    experimental_crypto_api,
    deprecated_crypto_api,
    PQCryptoStabilityCatalog,
    get_crypto_catalog,
    get_nist_compliance_report,
    get_standard_crypto_examples
)


class TestNISTEnums(unittest.TestCase):
    """Test NIST standardization enumerations"""
    
    def test_nist_standard_values(self):
        """Verify all NIST standard levels are defined"""
        self.assertEqual(NISTStandard.FIPS_STANDARD.value, "FIPS_STANDARD")
        self.assertEqual(NISTStandard.ROUND4_FINALIST.value, "ROUND4_FINALIST")
        self.assertEqual(NISTStandard.RESEARCH.value, "RESEARCH")
        self.assertEqual(NISTStandard.LEGACY_CLASSICAL.value, "LEGACY_CLASSICAL")
    
    def test_security_level_values(self):
        """Verify NIST security levels (1-5)"""
        self.assertEqual(SecurityLevel.LEVEL_1.value, "NIST_LEVEL_1")
        self.assertEqual(SecurityLevel.LEVEL_3.value, "NIST_LEVEL_3")
        self.assertEqual(SecurityLevel.LEVEL_5.value, "NIST_LEVEL_5")
    
    def test_stability_level_values(self):
        """Verify stability levels"""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")


class TestCryptoAPIMetadata(unittest.TestCase):
    """Test crypto API metadata dataclass"""
    
    def test_metadata_creation(self):
        """Test basic metadata creation"""
        metadata = CryptoAPIMetadata(
            name="TestKEM",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_3,
            support=SupportLevel.FULL_SUPPORT,
            version="1.0.0",
            since_version="1.0.0",
            description="Test KEM algorithm",
            algorithm_family="Kyber"
        )
        self.assertEqual(metadata.name, "TestKEM")
        self.assertEqual(metadata.algorithm_family, "Kyber")
        self.assertTrue(metadata.fips_compliant)  # Auto-set for FIPS_STANDARD
    
    def test_metadata_security_flags(self):
        """Test security feature flags"""
        metadata = CryptoAPIMetadata(
            name="SecureKEM",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_5,
            support=SupportLevel.FULL_SUPPORT,
            version="1.0.0",
            since_version="1.0.0",
            description="Secure implementation",
            algorithm_family="Kyber",
            constant_time=True,
            side_channel_resistant=True,
            thread_safe=True
        )
        self.assertTrue(metadata.constant_time)
        self.assertTrue(metadata.side_channel_resistant)
        self.assertTrue(metadata.thread_safe)


class TestCryptoDecorators(unittest.TestCase):
    """Test crypto API decorators"""
    
    def test_nist_standard_api_decorator(self):
        """Test NIST standard API decorator"""
        @nist_standard_api(
            nist_level=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_3,
            version="3.0.0",
            algorithm_family="Kyber"
        )
        def kyber_kem():
            return "key_exchange"
        
        self.assertTrue(hasattr(kyber_kem, '__crypto_metadata__'))
        self.assertEqual(kyber_kem.__crypto_metadata__.nist_standard, NISTStandard.FIPS_STANDARD)
        self.assertEqual(kyber_kem(), "key_exchange")  # Function still works
    
    def test_experimental_crypto_api_decorator(self):
        """Test experimental crypto decorator"""
        @experimental_crypto_api(version="0.5.0", algorithm_family="MPC")
        def experimental_mpc():
            return "research"
        
        self.assertEqual(
            experimental_mpc.__crypto_metadata__.stability,
            StabilityLevel.EXPERIMENTAL
        )
        self.assertGreater(len(experimental_mpc.__crypto_metadata__.limitations), 0)
        self.assertEqual(experimental_mpc(), "research")
    
    def test_deprecated_crypto_api_decorator(self):
        """Test deprecated crypto decorator emits warning"""
        @deprecated_crypto_api(
            version="2.0.0",
            removal_in="3.0.0",
            replacement="KyberKEMEngine"
        )
        def old_rsa():
            return "deprecated"
        
        self.assertEqual(
            old_rsa.__crypto_metadata__.stability,
            StabilityLevel.DEPRECATED
        )
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_rsa()
            self.assertEqual(len(w), 1)
            self.assertTrue(issubclass(w[-1].category, DeprecationWarning))
            self.assertIn("deprecation", str(w[-1].message).lower())
        
        self.assertEqual(result, "deprecated")
    
    def test_decorator_preserves_functionality(self):
        """Verify decorators don't break original crypto operations"""
        @nist_standard_api(
            nist_level=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_3,
            version="1.0.0",
            algorithm_family="Test"
        )
        def secure_multiply(a, b):
            return a * b
        
        self.assertEqual(secure_multiply(7, 6), 42)
        self.assertEqual(secure_multiply(0, 100), 0)


class TestPQCryptoStabilityCatalog(unittest.TestCase):
    """Test PQ Crypto catalog functionality"""
    
    def setUp(self):
        self.catalog = PQCryptoStabilityCatalog()
    
    def test_catalog_initialized_with_algorithms(self):
        """Test catalog initializes with standard PQ algorithms"""
        self.assertGreater(len(self.catalog._apis), 10)
    
    def test_kyber_in_catalog(self):
        """Verify Kyber KEM is cataloged as FIPS standard"""
        kyber = self.catalog.get_api_metadata("KyberKEMEngine")
        self.assertIsNotNone(kyber)
        self.assertEqual(kyber.nist_standard, NISTStandard.FIPS_STANDARD)
        self.assertEqual(kyber.stability, StabilityLevel.STABLE)
        self.assertTrue(kyber.fips_compliant)
    
    def test_dilithium_in_catalog(self):
        """Verify Dilithium is cataloged correctly"""
        dilithium = self.catalog.get_api_metadata("DilithiumSignatureEngine")
        self.assertIsNotNone(dilithium)
        self.assertEqual(dilithium.algorithm_family, "Dilithium")
        self.assertTrue(dilithium.fips_compliant)
    
    def test_sphincs_plus_in_catalog(self):
        """Verify SPHINCS+ is cataloged correctly"""
        sphincs = self.catalog.get_api_metadata("SPHINCSPlusEngine")
        self.assertIsNotNone(sphincs)
        self.assertEqual(sphincs.security_level, SecurityLevel.LEVEL_5)
    
    def test_list_by_nist_standard(self):
        """Test filtering by NIST standard status"""
        fips_algorithms = self.catalog.list_by_nist_standard(NISTStandard.FIPS_STANDARD)
        experimental = self.catalog.list_by_nist_standard(NISTStandard.RESEARCH)
        
        self.assertGreater(len(fips_algorithms), 0)
        self.assertGreater(len(experimental), 0)
        
        for algo in fips_algorithms:
            self.assertEqual(algo.nist_standard, NISTStandard.FIPS_STANDARD)
            self.assertTrue(algo.fips_compliant)
    
    def test_list_by_security_level(self):
        """Test filtering by NIST security level"""
        level5 = self.catalog.list_by_security_level(SecurityLevel.LEVEL_5)
        self.assertGreater(len(level5), 0)
        
        for algo in level5:
            self.assertEqual(algo.security_level, SecurityLevel.LEVEL_5)
    
    def test_get_compliance_matrix(self):
        """Test compliance matrix generation"""
        matrix = self.catalog.get_compliance_matrix()
        self.assertIn("total_algorithms", matrix)
        self.assertIn("by_nist_status", matrix)
        self.assertIn("by_security_level", matrix)
        self.assertIn("fips_compliant_count", matrix)
        self.assertGreater(matrix["total_algorithms"], 0)
        self.assertGreater(matrix["fips_compliant_count"], 0)
    
    def test_generate_readme_section(self):
        """Test README section generation"""
        readme = self.catalog.generate_readme_section()
        self.assertIsInstance(readme, str)
        self.assertIn("NIST Compliance", readme)
        self.assertIn("Kyber", readme)
        self.assertIn("Dilithium", readme)
        self.assertIn("SPHINCS+", readme)


class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions"""
    
    def test_get_crypto_catalog_singleton(self):
        """Test global catalog is singleton"""
        cat1 = get_crypto_catalog()
        cat2 = get_crypto_catalog()
        self.assertIs(cat1, cat2)
    
    def test_get_nist_compliance_report(self):
        """Test NIST compliance report generation"""
        report = get_nist_compliance_report()
        self.assertEqual(report["report_version"], "3.0.0")
        self.assertIn("compliance_matrix", report)
        self.assertTrue(report["nist_sp_800_186_compliant"])
    
    def test_get_standard_crypto_examples(self):
        """Test usage examples retrieval"""
        examples = get_standard_crypto_examples()
        self.assertIsInstance(examples, dict)
        self.assertIn("KyberKEMEngine", examples)
        self.assertIn("DilithiumSignatureEngine", examples)
        
        for api_name, api_examples in examples.items():
            for example in api_examples:
                self.assertIsInstance(example.title, str)
                self.assertIsInstance(example.code, str)
                self.assertIn(example.use_case, ["KEY_EXCHANGE", "SIGNATURE", "GENERAL"])


class TestCryptoUsageExample(unittest.TestCase):
    """Test usage example dataclass"""
    
    def test_example_creation(self):
        """Test example creation"""
        example = CryptoUsageExample(
            title="Test Key Exchange",
            description="Test KEM operation",
            code="kem.encapsulate(pk)",
            use_case="KEY_EXCHANGE",
            complexity="BASIC"
        )
        self.assertEqual(example.title, "Test Key Exchange")
        self.assertEqual(example.use_case, "KEY_EXCHANGE")
    
    def test_example_defaults(self):
        """Test example default values"""
        example = CryptoUsageExample(
            title="Test",
            description="Test",
            code="test"
        )
        self.assertEqual(example.use_case, "GENERAL")
        self.assertEqual(example.complexity, "BASIC")


class TestBackwardCompatibility(unittest.TestCase):
    """Verify ADD-ONLY philosophy - no breaking changes"""
    
    def test_module_imports_cleanly(self):
        """Module imports without side effects"""
        import pq_crypto_api_stability_documentation_v3_2026_june
        self.assertIsNotNone(pq_crypto_api_stability_documentation_v3_2026_june)
    
    def test_module_self_test(self):
        """Run module self-test"""
        import pq_crypto_api_stability_documentation_v3_2026_june as module
        report = module.get_nist_compliance_report()
        self.assertIsNotNone(report)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == "__main__":
    print("=" * 65)
    print("QuantumCrypt PQ Crypto API Stability Documentation v3 Tests")
    print("DIMENSION F: Documentation & API Stability")
    print("=" * 65)
    
    result = run_tests()
    
    print("\n" + "=" * 65)
    print(f"Tests Passed: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 65)
    
    if result.wasSuccessful():
        print("✓ ALL TESTS PASSED - Dimension F Implementation Successful")
    else:
        print("✗ SOME TESTS FAILED")
        sys.exit(1)
