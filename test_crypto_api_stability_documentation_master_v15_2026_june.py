"""
Tests for QuantumCrypt-AI Comprehensive API Stability Documentation Catalog v15
Session 115 - Dimension F Implementation
"""

import unittest
import json
from quantum_crypt.crypto_api_stability_documentation_master_v15_2026_june import (
    QuantumCryptDocumentationCatalog,
    StabilityLevel,
    CryptoCategory,
    APIDocumentation,
    ModuleSummary,
)


class TestStabilityLevelEnum(unittest.TestCase):
    """Test StabilityLevel enum values."""
    
    def test_stability_levels_exist(self):
        """All four stability levels should be defined."""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.INTERNAL.value, "INTERNAL")


class TestCryptoCategoryEnum(unittest.TestCase):
    """Test CryptoCategory enum values."""
    
    def test_crypto_categories_exist(self):
        """All crypto categories should be defined."""
        categories = [
            CryptoCategory.KEY_ENCAPSULATION,
            CryptoCategory.DIGITAL_SIGNATURE,
            CryptoCategory.SYMMETRIC_ENCRYPTION,
            CryptoCategory.HASH_FUNCTION,
            CryptoCategory.KEY_MANAGEMENT,
            CryptoCategory.RANDOM_GENERATION,
            CryptoCategory.SECURITY_HARDENING,
            CryptoCategory.ERROR_RESILIENCE,
            CryptoCategory.OBSERVABILITY,
            CryptoCategory.BENCHMARKING,
        ]
        for cat in categories:
            self.assertIsNotNone(cat.value)


class TestQuantumCryptDocumentationCatalogBasics(unittest.TestCase):
    """Test basic catalog initialization and core functionality."""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_catalog_initializes(self):
        """Catalog should initialize without errors."""
        self.assertIsNotNone(self.catalog)
    
    def test_catalog_has_modules(self):
        """Catalog should have registered modules."""
        modules = self.catalog.list_all_modules()
        self.assertGreater(len(modules), 0)
    
    def test_catalog_has_apis(self):
        """Catalog should have registered APIs."""
        apis = self.catalog.list_all_apis()
        self.assertGreater(len(apis), 0)
    
    def test_get_module_summary_exists(self):
        """Should get existing module summary."""
        summary = self.catalog.get_module_summary("pq_key_encapsulation_v5")
        self.assertIsNotNone(summary)
        self.assertEqual(summary.stability, StabilityLevel.STABLE)
    
    def test_get_module_summary_nonexistent(self):
        """Should return None for nonexistent module."""
        summary = self.catalog.get_module_summary("nonexistent_module_xyz")
        self.assertIsNone(summary)
    
    def test_get_api_documentation_exists(self):
        """Should get existing API documentation."""
        doc = self.catalog.get_api_documentation("KyberKEM.keygen")
        self.assertIsNotNone(doc)
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
    
    def test_get_api_documentation_nonexistent(self):
        """Should return None for nonexistent API."""
        doc = self.catalog.get_api_documentation("NonexistentClass.method")
        self.assertIsNone(doc)


class TestStabilityFiltering(unittest.TestCase):
    """Test API filtering by stability level."""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_filter_stable_apis(self):
        """Should filter and return only STABLE APIs."""
        stable_apis = self.catalog.list_all_apis(StabilityLevel.STABLE)
        self.assertGreater(len(stable_apis), 0)
        for api in stable_apis:
            self.assertEqual(api.stability, StabilityLevel.STABLE)
    
    def test_filter_experimental_apis(self):
        """Should filter and return only EXPERIMENTAL APIs."""
        experimental_apis = self.catalog.list_all_apis(StabilityLevel.EXPERIMENTAL)
        for api in experimental_apis:
            self.assertEqual(api.stability, StabilityLevel.EXPERIMENTAL)


class TestCategoryFiltering(unittest.TestCase):
    """Test module filtering by category."""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_filter_kem_modules(self):
        """Should filter key encapsulation modules."""
        modules = self.catalog.list_all_modules(CryptoCategory.KEY_ENCAPSULATION)
        for mod in modules:
            self.assertEqual(mod.category, CryptoCategory.KEY_ENCAPSULATION)
    
    def test_filter_security_hardening(self):
        """Should filter security hardening modules."""
        modules = self.catalog.list_all_modules(CryptoCategory.SECURITY_HARDENING)
        for mod in modules:
            self.assertEqual(mod.category, CryptoCategory.SECURITY_HARDENING)


class TestStabilitySummary(unittest.TestCase):
    """Test stability summary statistics."""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_stability_summary_structure(self):
        """Summary should have all required fields."""
        summary = self.catalog.get_stability_summary()
        required_fields = [
            "catalog_version",
            "generated_at",
            "total_apis",
            "total_modules",
            "stability_breakdown",
            "nist_standardized",
            "side_channel_resistant",
        ]
        for field in required_fields:
            self.assertIn(field, summary)
    
    def test_stability_summary_counts(self):
        """Counts should be accurate."""
        summary = self.catalog.get_stability_summary()
        self.assertEqual(summary["total_apis"], len(self.catalog.list_all_apis()))
        self.assertEqual(summary["total_modules"], len(self.catalog.list_all_modules()))
        self.assertGreater(summary["nist_standardized"], 0)
        self.assertGreater(summary["side_channel_resistant"], 0)


class TestJsonExport(unittest.TestCase):
    """Test JSON export functionality."""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_export_to_json(self):
        """Should export valid JSON."""
        json_str = self.catalog.export_to_json()
        data = json.loads(json_str)
        
        self.assertIn("catalog_version", data)
        self.assertIn("modules", data)
        self.assertIn("apis", data)
        self.assertGreater(len(data["modules"]), 0)
        self.assertGreater(len(data["apis"]), 0)


class TestReadmeGeneration(unittest.TestCase):
    """Test README Markdown generation."""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_generate_readme_section(self):
        """Should generate non-empty Markdown."""
        md = self.catalog.generate_readme_section()
        self.assertIsInstance(md, str)
        self.assertGreater(len(md), 0)
        self.assertIn("Crypto API Stability Reference", md)
        self.assertIn("NIST PQC Algorithm Support", md)
        self.assertIn("Kyber", md)
        self.assertIn("Dilithium", md)


class TestAPIDocumentationFields(unittest.TestCase):
    """Test that all documented APIs have required fields."""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_all_apis_have_signature(self):
        """Every API should have a signature field."""
        for api in self.catalog.list_all_apis():
            self.assertGreater(len(api.signature), 0)
            self.assertGreater(len(api.description), 0)
            self.assertIsNotNone(api.stability)
            self.assertIsNotNone(api.category)
    
    def test_all_apis_have_since_version(self):
        """Every API should have since_version."""
        for api in self.catalog.list_all_apis():
            self.assertGreater(len(api.since_version), 0)
    
    def test_side_channel_resistant_flag(self):
        """Side channel resistant flag should be boolean."""
        for api in self.catalog.list_all_apis():
            self.assertIsInstance(api.side_channel_resistant, bool)
    
    def test_nist_security_level(self):
        """NIST security level should be documented."""
        for api in self.catalog.list_all_apis():
            self.assertIsInstance(api.nist_security_level, str)


class TestModuleDocumentationFields(unittest.TestCase):
    """Test that all documented modules have required fields."""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_all_modules_have_description(self):
        """Every module should have a description."""
        for mod in self.catalog.list_all_modules():
            self.assertGreater(len(mod.description), 0)
            self.assertGreater(len(mod.module_name), 0)
            self.assertIsNotNone(mod.stability)
            self.assertIsNotNone(mod.category)
    
    def test_nist_standardized_flag(self):
        """NIST standardized flag should be boolean."""
        for mod in self.catalog.list_all_modules():
            self.assertIsInstance(mod.nist_standardized, bool)
    
    def test_all_modules_have_test_coverage(self):
        """Every module should have test_coverage field."""
        for mod in self.catalog.list_all_modules():
            self.assertIn(mod.test_coverage, ["HIGH", "MEDIUM", "LOW"])


class TestNISTStandardizedAlgorithms(unittest.TestCase):
    """Test NIST standardized algorithms are properly marked."""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_kyber_is_nist_standardized(self):
        """Kyber KEM should be marked as NIST standardized."""
        mod = self.catalog.get_module_summary("pq_key_encapsulation_v5")
        self.assertTrue(mod.nist_standardized)
    
    def test_dilithium_is_nist_standardized(self):
        """Dilithium signatures should be marked as NIST standardized."""
        mod = self.catalog.get_module_summary("pq_digital_signature_v4")
        self.assertTrue(mod.nist_standardized)
    
    def test_aes_is_nist_standardized(self):
        """AES-GCM should be marked as NIST standardized."""
        mod = self.catalog.get_module_summary("symmetric_encryption_engine_v3")
        self.assertTrue(mod.nist_standardized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
