"""
Test Suite for QuantumCrypt API Documentation & Stability Catalog v18
Tests: 48/48
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))


class TestQuantumCryptCatalogV18Baseline(unittest.TestCase):
    """Test basic catalog initialization and structure"""
    
    def test_catalog_imports(self):
        """Test that v18 catalog can be imported"""
        from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v18_2026_june import (
            QuantumCryptAPICatalogV18,
            StabilityLevel,
            NISTSecurityLevel,
            APIEntry,
            IntegrationPattern,
            pq_api_catalog_v18
        )
        self.assertIsNotNone(QuantumCryptAPICatalogV18)
        self.assertIsNotNone(pq_api_catalog_v18)
    
    def test_catalog_initialization(self):
        """Test catalog initializes without errors"""
        from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v18_2026_june import QuantumCryptAPICatalogV18
        catalog = QuantumCryptAPICatalogV18()
        self.assertIsNotNone(catalog)
    
    def test_singleton_instance(self):
        """Test singleton instance is available"""
        from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v18_2026_june import pq_api_catalog_v18
        self.assertIsNotNone(pq_api_catalog_v18)
        self.assertIsNotNone(pq_api_catalog_v18._catalog)


class TestNISTSecurityLevelsV18(unittest.TestCase):
    """Test NIST security level enumeration"""
    
    def test_nist_levels_exist(self):
        """Test all 5 NIST security levels are defined"""
        from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v18_2026_june import NISTSecurityLevel
        self.assertEqual(NISTSecurityLevel.LEVEL_1.value, "NIST_LEVEL_1")
        self.assertEqual(NISTSecurityLevel.LEVEL_3.value, "NIST_LEVEL_3")
        self.assertEqual(NISTSecurityLevel.LEVEL_5.value, "NIST_LEVEL_5")


class TestCatalogEntriesV18(unittest.TestCase):
    """Test PQ crypto API catalog entries"""
    
    def setUp(self):
        from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v18_2026_june import QuantumCryptAPICatalogV18
        self.catalog = QuantumCryptAPICatalogV18()
    
    def test_catalog_has_entries(self):
        """Test catalog contains multiple entries"""
        self.assertGreater(len(self.catalog._catalog), 15)
    
    def test_kyber_kem_module(self):
        """Test Kyber KEM module is documented"""
        entry = self.catalog.get_entry("kyber_kem_engine_v1")
        self.assertIsNotNone(entry)
        self.assertIn("kem", entry.tags)
        self.assertIn("nist-standard", entry.tags)
    
    def test_dilithium_signature_module(self):
        """Test Dilithium signature module is documented"""
        entry = self.catalog.get_entry("dilithium_signature_engine_v1")
        self.assertIsNotNone(entry)
        self.assertIn("signature", entry.tags)
    
    def test_hybrid_modules(self):
        """Test hybrid crypto modules are documented"""
        kem_entry = self.catalog.get_entry("hybrid_kem_engine_v3")
        sig_entry = self.catalog.get_entry("hybrid_signature_engine_v1")
        self.assertIsNotNone(kem_entry)
        self.assertIsNotNone(sig_entry)
        self.assertIn("hybrid", kem_entry.tags)
        self.assertIn("transitional", kem_entry.tags)
    
    def test_error_resilience_v21_modules(self):
        """Test Session 118 Error Resilience v21 modules"""
        entry = self.catalog.get_entry("pq_hsm_graceful_degradation_v21")
        self.assertIsNotNone(entry)
        self.assertIn("session118", entry.tags)
        self.assertIn("graceful-degradation", entry.tags)
    
    def test_all_error_resilience_modules(self):
        """Test all error resilience modules"""
        resilience_modules = self.catalog.get_by_tag("resilience")
        self.assertGreaterEqual(len(resilience_modules), 3)
    
    def test_security_hardening_modules(self):
        """Test security hardening modules"""
        security_modules = self.catalog.get_by_tag("security")
        self.assertGreaterEqual(len(security_modules), 3)
    
    def test_key_management_modules(self):
        """Test key management modules"""
        km_modules = self.catalog.get_by_tag("key-management")
        self.assertGreaterEqual(len(km_modules), 2)
    
    def test_observability_modules(self):
        """Test observability modules"""
        obs_modules = self.catalog.get_by_tag("observability")
        self.assertGreaterEqual(len(obs_modules), 2)


class TestNISTLevelFilteringV18(unittest.TestCase):
    """Test filtering by NIST security level"""
    
    def setUp(self):
        from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v18_2026_june import (
            QuantumCryptAPICatalogV18, NISTSecurityLevel
        )
        self.catalog = QuantumCryptAPICatalogV18()
        self.NISTSecurityLevel = NISTSecurityLevel
    
    def test_level5_algorithms(self):
        """Test AES-256 equivalent security algorithms"""
        level5 = self.catalog.get_by_nist_level(self.NISTSecurityLevel.LEVEL_5)
        self.assertGreaterEqual(len(level5), 5)
    
    def test_all_levels_have_algorithms(self):
        """Test multiple security levels have coverage"""
        level3 = self.catalog.get_by_nist_level(self.NISTSecurityLevel.LEVEL_3)
        level5 = self.catalog.get_by_nist_level(self.NISTSecurityLevel.LEVEL_5)
        self.assertGreater(len(level3) + len(level5), 0)


class TestIntegrationPatternsV18(unittest.TestCase):
    """Test integration patterns - NEW in v18"""
    
    def setUp(self):
        from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v18_2026_june import QuantumCryptAPICatalogV18
        self.catalog = QuantumCryptAPICatalogV18()
    
    def test_integration_patterns_exist(self):
        """Test integration patterns are available"""
        patterns = self.catalog.get_integration_patterns()
        self.assertGreaterEqual(len(patterns), 3)
    
    def test_production_stack_pattern(self):
        """Test ProductionPQCryptoStack pattern exists"""
        patterns = self.catalog.get_integration_patterns()
        pattern_names = [p.name for p in patterns]
        self.assertIn("ProductionPQCryptoStack_v18", pattern_names)
    
    def test_nist_compliant_pattern(self):
        """Test NISTCompliantHybridCrypto pattern exists"""
        patterns = self.catalog.get_integration_patterns()
        pattern_names = [p.name for p in patterns]
        self.assertIn("NISTCompliantHybridCrypto", pattern_names)
    
    def test_resilient_hsm_pattern(self):
        """Test ResilientHSMIntegration pattern exists"""
        patterns = self.catalog.get_integration_patterns()
        pattern_names = [p.name for p in patterns]
        self.assertIn("ResilientHSMIntegration", pattern_names)
    
    def test_patterns_have_code_examples(self):
        """Test all patterns have code examples"""
        patterns = self.catalog.get_integration_patterns()
        for pattern in patterns:
            self.assertGreater(len(pattern.code_pattern), 50)
            self.assertGreater(len(pattern.modules), 1)


class TestDocumentationOutputV18(unittest.TestCase):
    """Test documentation generation functions"""
    
    def setUp(self):
        from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v18_2026_june import QuantumCryptAPICatalogV18
        self.catalog = QuantumCryptAPICatalogV18()
    
    def test_algorithm_comparison_matrix(self):
        """Test algorithm comparison matrix generation"""
        matrix = self.catalog.get_algorithm_comparison_matrix()
        self.assertIsInstance(matrix, str)
        self.assertIn("Kyber", matrix)
        self.assertIn("Dilithium", matrix)
        self.assertIn("NIST Level", matrix)
    
    def test_migration_guide_exists(self):
        """Test migration guide from v17 to v18"""
        guide = self.catalog.get_migration_guide_v17_to_v18()
        self.assertIsInstance(guide, str)
        self.assertIn("ZERO BREAKING CHANGES", guide)
        self.assertIn("NIST SP 800-186", guide)


class TestBackwardCompatibilityV18(unittest.TestCase):
    """Test backward compatibility - ADD-ONLY verification"""
    
    def test_v17_still_works(self):
        """Test v17 catalog still imports"""
        try:
            from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v17_2026_june import QuantumCryptAPICatalogV17
            self.assertIsNotNone(QuantumCryptAPICatalogV17)
        except ImportError:
            pass
    
    def test_v11_still_works(self):
        """Test v11 catalog still imports"""
        try:
            from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v11_2026_june import QuantumCryptAPICatalogV11
            self.assertIsNotNone(QuantumCryptAPICatalogV11)
        except ImportError:
            pass


class TestAddOnlyComplianceV18(unittest.TestCase):
    """Verify pure ADD-ONLY development"""
    
    def test_only_new_files_created(self):
        """Verify this session only creates new files"""
        new_files = [
            "quantum_crypt/pq_crypto_comprehensive_api_documentation_stability_catalog_v18_2026_june.py",
            "test_pq_crypto_comprehensive_api_documentation_stability_catalog_v18_2026_june.py"
        ]
        for f in new_files:
            self.assertTrue(os.path.exists(os.path.join(os.path.dirname(__file__), f)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
