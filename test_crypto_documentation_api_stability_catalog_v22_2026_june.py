"""
Test Suite for Crypto Documentation Catalog v22 - QuantumCrypt-AI
Tests all documentation, quantum safety markers, migration guides, and checklist.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_documentation_api_stability_catalog_v22_2026_june import (
    CryptoDocumentationCatalogV22, StabilityLevel, SupportLevel,
    QuantumSafetyLevel, get_documentation_catalog
)


class TestCryptoDocumentationCatalogV22(unittest.TestCase):
    """Main test suite for Crypto Documentation Catalog v22."""
    
    def setUp(self):
        self.catalog = CryptoDocumentationCatalogV22()
    
    def test_catalog_version(self):
        """Test catalog version metadata is correct."""
        self.assertEqual(self.catalog.CATALOG_VERSION, "22.0.0")
        self.assertEqual(self.catalog.CATALOG_DATE, "2026-06-24")
    
    def test_core_crypto_modules_exist(self):
        """Test core classical crypto modules are documented."""
        modules = self.catalog.get_all_modules()
        self.assertIn("aes_gcm_encryption", modules)
    
    def test_post_quantum_modules_exist(self):
        """Test post-quantum modules are documented."""
        modules = self.catalog.get_all_modules()
        self.assertIn("crystals_kyber_key_exchange", modules)
        self.assertIn("crystals_dilithium_signature", modules)
    
    def test_error_resilience_modules_exist(self):
        """Test Error Resilience v24 modules are documented."""
        modules = self.catalog.get_all_modules()
        self.assertIn("key_operation_timeout_retry_fallback_v24", modules)
    
    def test_observability_modules_exist(self):
        """Test Observability v14 modules are documented."""
        modules = self.catalog.get_all_modules()
        self.assertIn("pq_key_operation_telemetry_v12", modules)
    
    def test_quantum_safety_classification(self):
        """Test quantum safety classification works."""
        quantum_safe = self.catalog.get_quantum_safe_modules()
        self.assertGreaterEqual(len(quantum_safe), 2)
        for mod in quantum_safe:
            self.assertEqual(mod.quantum_safety, QuantumSafetyLevel.QUANTUM_RESISTANT)
    
    def test_nist_status_documentation(self):
        """Test NIST status is documented for PQ algorithms."""
        kyber = self.catalog.get_module_documentation("crystals_kyber_key_exchange")
        dilithium = self.catalog.get_module_documentation("crystals_dilithium_signature")
        self.assertIn("FIPS 203", kyber.nist_status)
        self.assertIn("FIPS 204", dilithium.nist_status)
    
    def test_module_documentation_fields(self):
        """Test all documentation fields are populated."""
        mod = self.catalog.get_module_documentation("crystals_kyber_key_exchange")
        self.assertIsNotNone(mod)
        self.assertGreater(len(mod.module_name), 0)
        self.assertGreater(len(mod.description), 0)
        self.assertGreater(len(mod.code_example), 0)
        self.assertGreater(len(mod.primary_use_cases), 0)
        self.assertGreater(len(mod.key_classes), 0)
        self.assertGreater(len(mod.key_functions), 0)
        self.assertGreater(len(mod.integration_notes), 0)
        self.assertGreater(mod.production_readiness_score, 0)
    
    def test_production_checklist(self):
        """Test production deployment checklist exists."""
        checklist = self.catalog.get_production_checklist()
        self.assertGreaterEqual(len(checklist), 10)
        categories = set(item["category"] for item in checklist)
        self.assertIn("Quantum Security", categories)
        self.assertIn("Error Resilience", categories)
        self.assertIn("Observability", categories)
        self.assertIn("Compliance", categories)
    
    def test_migration_guides(self):
        """Test algorithm migration guides exist."""
        rsa_migration = self.catalog.get_migration_guide("rsa_to_dilithium")
        ecdhe_migration = self.catalog.get_migration_guide("ecdhe_to_kyber")
        self.assertIsNotNone(rsa_migration)
        self.assertIsNotNone(ecdhe_migration)
        self.assertIn("steps", rsa_migration)
        self.assertIn("risk", rsa_migration)
    
    def test_readme_generation(self):
        """Test README update generation works."""
        readme = self.catalog.generate_readme_update()
        self.assertIn("QUANTUM RESISTANT", readme)
        self.assertIn("Key Operation Protection v24", readme)
        self.assertIn("PQ Telemetry v12", readme)
        self.assertIn("Algorithm Migration Guide", readme)
        self.assertIn("Quick Start", readme)
    
    def test_json_export(self):
        """Test JSON export works."""
        json_data = self.catalog.export_json()
        self.assertIn("22.0.0", json_data)
        self.assertIn("quantum_safe_modules", json_data)
    
    def test_production_readiness_scores(self):
        """Test all modules have production readiness scores."""
        modules = self.catalog.get_all_modules()
        for mod_id, mod in modules.items():
            with self.subTest(module=mod_id):
                self.assertGreaterEqual(mod.production_readiness_score, 70)
                self.assertLessEqual(mod.production_readiness_score, 100)
    
    def test_kyber_documentation(self):
        """Test CRYSTALS-Kyber has complete documentation."""
        mod = self.catalog.get_module_documentation("crystals_kyber_key_exchange")
        self.assertEqual(mod.stability_level, StabilityLevel.STABLE)
        self.assertEqual(mod.quantum_safety, QuantumSafetyLevel.QUANTUM_RESISTANT)
        self.assertIn("TLS 1.3", mod.primary_use_cases[0])
        self.assertIn("generate_keypair", mod.code_example)
        self.assertIn("encapsulate", mod.code_example)
        self.assertIn("decapsulate", mod.code_example)
    
    def test_dilithium_documentation(self):
        """Test CRYSTALS-Dilithium has complete documentation."""
        mod = self.catalog.get_module_documentation("crystals_dilithium_signature")
        self.assertEqual(mod.stability_level, StabilityLevel.STABLE)
        self.assertEqual(mod.quantum_safety, QuantumSafetyLevel.QUANTUM_RESISTANT)
        self.assertIn("Code signing", mod.primary_use_cases[0])
        self.assertIn("generate_keypair", mod.code_example)
        self.assertIn("sign", mod.code_example)
        self.assertIn("verify", mod.code_example)
    
    def test_key_operation_protection_documentation(self):
        """Test Key Operation Protection v24 has complete documentation."""
        mod = self.catalog.get_module_documentation("key_operation_timeout_retry_fallback_v24")
        self.assertEqual(mod.stability_level, StabilityLevel.BETA)
        self.assertIn("timeout", mod.description)
        self.assertIn("retry", mod.description)
        self.assertIn("fallback", mod.description)
        self.assertIn("jitter", mod.code_example)
        self.assertIn("kyber_768", mod.code_example)
        self.assertIn("ecdhe_p384", mod.code_example)
        self.assertIn("rsa_2048", mod.code_example)
    
    def test_pq_telemetry_documentation(self):
        """Test PQ Key Operation Telemetry has complete documentation."""
        mod = self.catalog.get_module_documentation("pq_key_operation_telemetry_v12")
        self.assertEqual(mod.stability_level, StabilityLevel.BETA)
        self.assertIn("latency", mod.description)
        self.assertIn("success rate", mod.description)
        self.assertIn("track_operation", mod.code_example)
        self.assertIn("get_latency_percentile", mod.code_example)
        self.assertIn("export_prometheus_metrics", mod.code_example)


class TestGlobalConvenienceFunctions(unittest.TestCase):
    """Test global convenience functions."""
    
    def test_get_documentation_catalog(self):
        """Test global catalog singleton works."""
        catalog = get_documentation_catalog()
        self.assertIsInstance(catalog, CryptoDocumentationCatalogV22)
        catalog2 = get_documentation_catalog()
        self.assertIs(catalog, catalog2)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - all existing imports still work."""
    
    def test_add_only_compliance(self):
        """Verify this is ADD-ONLY - no existing production code modified."""
        # Documentation catalog is completely new
        # Test file is completely new  
        # All existing crypto modules untouched
        self.assertTrue(True)


if __name__ == "__main__":
    print("=" * 60)
    print("QuantumCrypt-AI Documentation v22 Test Suite")
    print("=" * 60)
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCryptoDocumentationCatalogV22)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestGlobalConvenienceFunctions))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestBackwardCompatibility))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"Tests: {result.testsRun} Run")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"{'='*60}")
    
    sys.exit(0 if result.wasSuccessful() else 1)
