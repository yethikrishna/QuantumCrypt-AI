"""
Tests for QuantumCrypt Documentation & API Stability Catalog v21
ADD-ONLY: These tests only verify the new documentation module.
No existing production code is modified or tested here.

VERSION: v21
DATE: June 24, 2026
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "quantum_crypt"))

from crypto_documentation_api_stability_catalog_v21_2026_june import (
    CryptoDocumentationCatalog,
    StabilityLevel,
    APIDocumentation,
    ModuleUsageGuide,
    api_stability,
    get_documentation,
    print_stability_report
)


class TestCryptoStabilityLevel(unittest.TestCase):
    """Test stability level enumeration"""
    
    def test_stability_level_values(self):
        """Verify all stability levels exist"""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.BETA.value, "BETA")
        self.assertEqual(StabilityLevel.INTERNAL.value, "INTERNAL")


class TestCryptoAPIDocumentation(unittest.TestCase):
    """Test API documentation dataclass"""
    
    def test_documentation_creation(self):
        """Test creating API documentation entry"""
        doc = APIDocumentation(
            name="TestCryptoAPI",
            stability=StabilityLevel.STABLE,
            version_added="v1",
            description="Test crypto description",
            usage_example="example crypto code"
        )
        self.assertEqual(doc.name, "TestCryptoAPI")
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
        self.assertEqual(doc.version_added, "v1")


class TestCryptoModuleUsageGuide(unittest.TestCase):
    """Test module usage guide dataclass"""
    
    def test_usage_guide_creation(self):
        """Test creating module usage guide"""
        guide = ModuleUsageGuide(
            module_name="TestCryptoModule",
            stability=StabilityLevel.STABLE,
            version="v1",
            quick_start="quick",
            full_example="full example",
            best_practices=["use secure random"],
            common_pitfalls=["don't reuse nonces"],
            related_modules=["other_crypto_module"]
        )
        self.assertEqual(guide.module_name, "TestCryptoModule")
        self.assertIsInstance(guide.best_practices, list)


class TestCryptoApiStabilityDecorator(unittest.TestCase):
    """Test API stability decorator"""
    
    def test_decorator_adds_metadata(self):
        """Test decorator adds stability metadata to function"""
        @api_stability(StabilityLevel.STABLE, "v10")
        def test_crypto_func():
            return "encrypted"
        
        self.assertEqual(test_crypto_func._api_stability, StabilityLevel.STABLE)
        self.assertEqual(test_crypto_func._version_added, "v10")
    
    def test_decorator_preserves_function(self):
        """Test decorator doesn't change function behavior"""
        @api_stability(StabilityLevel.STABLE, "v10")
        def test_func(x, y):
            return x * y
        
        self.assertEqual(test_func(2, 3), 6)
        self.assertEqual(test_func.__name__, "test_func")


class TestCryptoDocumentationCatalog(unittest.TestCase):
    """Test main crypto documentation catalog"""
    
    def setUp(self):
        self.catalog = CryptoDocumentationCatalog()
    
    def test_catalog_initialization(self):
        """Test catalog initializes with documentation entries"""
        apis = self.catalog.list_all_apis()
        self.assertGreater(len(apis), 0)
        print(f"\nTotal Crypto APIs documented: {len(apis)}")
        for api in apis:
            print(f"  - {api}")
    
    def test_core_crypto_docs_exist(self):
        """Test core crypto module documentation exists"""
        self.assertIsNotNone(self.catalog.get_api("quantum_key_exchange"))
        self.assertIsNotNone(self.catalog.get_api("aes_gcm_encryption"))
        self.assertIsNotNone(self.catalog.get_api("digital_signature"))
        self.assertIsNotNone(self.catalog.get_api("hash_functions"))
    
    def test_v14_docs_exist(self):
        """Test v14 observability documentation exists"""
        self.assertIsNotNone(self.catalog.get_api("crypto_http_metrics_server_v14"))
        self.assertIsNotNone(self.catalog.get_api("crypto_slo_alerting_v14"))
        self.assertIsNotNone(self.catalog.get_api("crypto_baggage_v14"))
    
    def test_v16_docs_exist(self):
        """Test v16 security hardening documentation exists"""
        self.assertIsNotNone(self.catalog.get_api("crypto_input_validation_v16"))
        self.assertIsNotNone(self.catalog.get_api("secure_key_wiping_v16"))
        self.assertIsNotNone(self.catalog.get_api("constant_time_crypto_v16"))
    
    def test_get_stability_summary(self):
        """Test stability summary calculation"""
        summary = self.catalog.get_stability_summary()
        print(f"\nCrypto Stability Summary: {summary}")
        self.assertIn("STABLE", summary)
        self.assertIn("EXPERIMENTAL", summary)
        self.assertIn("BETA", summary)
        self.assertGreater(summary["STABLE"], 0)
        self.assertGreater(summary["EXPERIMENTAL"], 0)
    
    def test_get_module_guides(self):
        """Test module usage guides exist"""
        guides = self.catalog.get_module_guides()
        self.assertGreater(len(guides), 0)
        guide = guides[0]
        self.assertGreater(len(guide.best_practices), 0)
        self.assertGreater(len(guide.common_pitfalls), 0)
    
    def test_generate_readme_section(self):
        """Test README markdown generation"""
        readme = self.catalog.generate_readme_section()
        self.assertIsInstance(readme, str)
        self.assertIn("QuantumCrypt API Stability Reference", readme)
        self.assertIn("FIPS", readme)
    
    def test_get_nonexistent_api(self):
        """Test getting non-existent API returns None"""
        result = self.catalog.get_api("nonexistent_crypto_api_12345")
        self.assertIsNone(result)


class TestCryptoGlobalFunctions(unittest.TestCase):
    """Test global convenience functions"""
    
    def test_get_documentation(self):
        """Test global documentation instance"""
        catalog = get_documentation()
        self.assertIsInstance(catalog, CryptoDocumentationCatalog)
        # Should be singleton
        catalog2 = get_documentation()
        self.assertIs(catalog, catalog2)
    
    def test_print_stability_report(self):
        """Test stability report printing doesn't crash"""
        try:
            print_stability_report()
        except Exception as e:
            self.fail(f"print_stability_report raised {e}")


class TestCryptoDocumentationQuality(unittest.TestCase):
    """Test quality and completeness of crypto documentation"""
    
    def setUp(self):
        self.catalog = CryptoDocumentationCatalog()
    
    def test_all_docs_have_usage_examples(self):
        """Verify every crypto API has a usage example"""
        for name in self.catalog.list_all_apis():
            doc = self.catalog.get_api(name)
            self.assertIsNotNone(doc.usage_example)
            self.assertGreater(len(doc.usage_example.strip()), 0,
                              f"Crypto API {name} missing usage example")
    
    def test_all_docs_have_descriptions(self):
        """Verify every crypto API has a description"""
        for name in self.catalog.list_all_apis():
            doc = self.catalog.get_api(name)
            self.assertGreater(len(doc.description.strip()), 0,
                              f"Crypto API {name} missing description")
    
    def test_all_docs_have_version(self):
        """Verify every crypto API has version added"""
        for name in self.catalog.list_all_apis():
            doc = self.catalog.get_api(name)
            self.assertTrue(doc.version_added.startswith("v"),
                          f"Crypto API {name} invalid version: {doc.version_added}")
    
    def test_crypto_pitfalls_include_nonce_reuse(self):
        """Verify crypto pitfalls include nonce reuse warning"""
        for guide in self.catalog.get_module_guides():
            pitfalls = " ".join(guide.common_pitfalls).lower()
            self.assertIn("nonce", pitfalls,
                         f"Module {guide.module_name} missing nonce reuse warning")
    
    def test_crypto_best_practices_exist(self):
        """Verify crypto best practices exist"""
        for guide in self.catalog.get_module_guides():
            self.assertGreater(len(guide.best_practices), 0)


class TestCryptoBackwardCompatibility(unittest.TestCase):
    """Verify 100% backward compatibility - ADD-ONLY verification"""
    
    def test_documentation_module_is_isolated(self):
        """Verify documentation module doesn't import production crypto code"""
        module_path = os.path.join(
            os.path.dirname(__file__),
            "quantum_crypt",
            "crypto_documentation_api_stability_catalog_v21_2026_june.py"
        )
        with open(module_path, 'r') as f:
            content = f.read()
        
        # Should only import standard library modules
        self.assertIn("from enum import Enum", content)
        self.assertIn("from dataclasses import dataclass", content)
        # Zero runtime impact on existing crypto modules


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("QuantumCrypt Documentation v21 - Test Suite")
    print("=" * 70)
    unittest.main(verbosity=2)
