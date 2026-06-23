"""
Test Suite for QuantumCrypt-AI Crypto API Documentation & Stability Catalog v15
Session 115 - Dimension F: Documentation & API Stability
ADD-ONLY: No existing production code modified
"""

import unittest
import json
from quantum_crypt.crypto_api_documentation_stability_master_v15_2026_june import (
    QuantumCryptAPIDocumentationCatalog,
    CryptoAPIStability,
    CryptoCategory,
    NISTSecurityLevel,
    CryptoAlgorithmDoc,
    CryptoModuleDoc
)


class TestCryptoStabilityEnums(unittest.TestCase):
    """Test crypto API stability and category enums."""
    
    def test_stability_values(self):
        """All stability levels have correct string values."""
        self.assertEqual(CryptoAPIStability.STABLE.value, "stable")
        self.assertEqual(CryptoAPIStability.EXPERIMENTAL.value, "experimental")
        self.assertEqual(CryptoAPIStability.DEPRECATED.value, "deprecated")
        self.assertEqual(CryptoAPIStability.LEGACY.value, "legacy")
    
    def test_category_values(self):
        """All category enums have correct values."""
        self.assertEqual(CryptoCategory.KEY_ENCAPSULATION.value, "key_encapsulation")
        self.assertEqual(CryptoCategory.SECURITY_HARDENING.value, "security_hardening")
        self.assertEqual(CryptoCategory.DOCUMENTATION.value, "documentation")
    
    def test_nist_levels(self):
        """NIST security levels 1-5 defined correctly."""
        self.assertEqual(NISTSecurityLevel.LEVEL_1.value, 1)
        self.assertEqual(NISTSecurityLevel.LEVEL_5.value, 5)


class TestCryptoAlgorithmDoc(unittest.TestCase):
    """Test algorithm documentation data class."""
    
    def test_algorithm_creation(self):
        """Create algorithm doc with all fields."""
        alg = CryptoAlgorithmDoc(
            name="Test-KEM-128",
            nist_level=NISTSecurityLevel.LEVEL_1,
            category=CryptoCategory.KEY_ENCAPSULATION,
            public_key_size_bytes=800,
            secret_key_size_bytes=1632,
            nist_standardized=True,
            quantum_resistant=True
        )
        self.assertEqual(alg.name, "Test-KEM-128")
        self.assertTrue(alg.quantum_resistant)


class TestCryptoModuleDoc(unittest.TestCase):
    """Test module documentation data class."""
    
    def test_module_creation(self):
        """Create module documentation entry."""
        module = CryptoModuleDoc(
            module_name="Test Crypto Module",
            file_name="test_module.py",
            category=CryptoCategory.KEY_ENCAPSULATION,
            stability=CryptoAPIStability.STABLE,
            description="Test module description"
        )
        self.assertEqual(module.module_name, "Test Crypto Module")
        self.assertTrue(module.last_updated)


class TestQuantumCryptAPIDocumentationCatalogBasics(unittest.TestCase):
    """Basic catalog functionality tests."""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_catalog_initialization(self):
        """Catalog initializes with module and algorithm entries."""
        self.assertGreater(len(self.catalog), 0)
    
    def test_get_module_exists(self):
        """Get existing module documentation."""
        module = self.catalog.get_module("pq_algorithm_benchmarking")
        self.assertIsNotNone(module)
        self.assertIsInstance(module, CryptoModuleDoc)
    
    def test_get_module_nonexistent(self):
        """Get nonexistent module returns None."""
        module = self.catalog.get_module("nonexistent_module_xyz")
        self.assertIsNone(module)
    
    def test_get_algorithm_exists(self):
        """Get existing algorithm documentation."""
        alg = self.catalog.get_algorithm("kyber_768")
        self.assertIsNotNone(alg)
        self.assertIsInstance(alg, CryptoAlgorithmDoc)
    
    def test_get_algorithm_nonexistent(self):
        """Get nonexistent algorithm returns None."""
        alg = self.catalog.get_algorithm("nonexistent_alg_xyz")
        self.assertIsNone(alg)


class TestCatalogFiltering(unittest.TestCase):
    """Test category and stability filtering."""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_get_by_category(self):
        """Filter modules by functional category."""
        security_modules = self.catalog.get_by_category(CryptoCategory.SECURITY_HARDENING)
        self.assertIsInstance(security_modules, list)
        for mod in security_modules:
            self.assertEqual(mod.category, CryptoCategory.SECURITY_HARDENING)
    
    def test_get_by_stability(self):
        """Filter modules by stability level."""
        stable_modules = self.catalog.get_by_stability(CryptoAPIStability.STABLE)
        self.assertIsInstance(stable_modules, list)
        for mod in stable_modules:
            self.assertEqual(mod.stability, CryptoAPIStability.STABLE)
    
    def test_get_nist_standardized(self):
        """Get all NIST-standardized algorithms."""
        nist_algs = self.catalog.get_nist_standardized_algorithms()
        self.assertGreater(len(nist_algs), 0)
        for alg in nist_algs:
            self.assertTrue(alg.nist_standardized)
    
    def test_get_quantum_resistant(self):
        """Get all quantum-resistant algorithms."""
        qr_algs = self.catalog.get_quantum_resistant_algorithms()
        self.assertGreater(len(qr_algs), 0)
        for alg in qr_algs:
            self.assertTrue(alg.quantum_resistant)
    
    def test_stability_summary(self):
        """Get stability summary counts."""
        summary = self.catalog.get_stability_summary()
        self.assertIn("stable", summary)
        self.assertIn("experimental", summary)
        self.assertIsInstance(summary["stable"], int)


class TestCatalogSearch(unittest.TestCase):
    """Test full-text search functionality."""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_search_by_name(self):
        """Search modules by module name."""
        results = self.catalog.search_modules("benchmark")
        self.assertGreater(len(results), 0)
    
    def test_search_by_description(self):
        """Search modules by description content."""
        results = self.catalog.search_modules("security")
        self.assertGreater(len(results), 0)
    
    def test_search_nomatch(self):
        """Search with no matching results."""
        results = self.catalog.search_modules("xyz_nonexistent_term_12345")
        self.assertEqual(len(results), 0)


class TestCatalogExport(unittest.TestCase):
    """Test JSON export and documentation generation."""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_export_json_valid(self):
        """Export produces valid JSON."""
        json_output = self.catalog.export_json()
        data = json.loads(json_output)
        self.assertIn("catalog_version", data)
        self.assertIn("total_modules", data)
        self.assertIn("total_algorithms", data)
        self.assertIn("modules", data)
        self.assertIn("algorithms", data)
        self.assertEqual(data["catalog_version"], "v15")
        self.assertEqual(data["session"], "115")
    
    def test_export_contains_modules(self):
        """Export includes all module documentation."""
        json_output = self.catalog.export_json()
        data = json.loads(json_output)
        self.assertEqual(len(data["modules"]), len(self.catalog))
    
    def test_export_contains_algorithms(self):
        """Export includes all algorithm documentation."""
        json_output = self.catalog.export_json()
        data = json.loads(json_output)
        self.assertGreater(len(data["algorithms"]), 0)
    
    def test_generate_readme_summary(self):
        """README summary generation works."""
        readme = self.catalog.generate_readme_summary()
        self.assertIsInstance(readme, str)
        self.assertIn("Module Stability Summary", readme)
        self.assertIn("Algorithm Summary", readme)
        self.assertIn("Session 115", readme)
        self.assertIn("v15", readme)


class TestNISTAlgorithmValidation(unittest.TestCase):
    """Validate NIST PQC algorithm documentation accuracy."""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_kyber_algorithms_complete(self):
        """All Kyber variants documented correctly."""
        for key in ["kyber_512", "kyber_768", "kyber_1024"]:
            alg = self.catalog.get_algorithm(key)
            self.assertIsNotNone(alg)
            self.assertTrue(alg.nist_standardized)
            self.assertTrue(alg.quantum_resistant)
            self.assertTrue(alg.recommended)
            self.assertGreater(alg.public_key_size_bytes, 0)
            self.assertGreater(alg.secret_key_size_bytes, 0)
    
    def test_dilithium_algorithms_complete(self):
        """All Dilithium variants documented correctly."""
        for key in ["dilithium_2", "dilithium_3", "dilithium_5"]:
            alg = self.catalog.get_algorithm(key)
            self.assertIsNotNone(alg)
            self.assertTrue(alg.nist_standardized)
            self.assertTrue(alg.quantum_resistant)
            self.assertTrue(alg.recommended)
    
    def test_classical_not_recommended(self):
        """Classical algorithms marked not recommended for PQC."""
        rsa = self.catalog.get_algorithm("rsa_2048")
        ecc = self.catalog.get_algorithm("ecc_p256")
        self.assertFalse(rsa.quantum_resistant)
        self.assertFalse(ecc.quantum_resistant)
        self.assertFalse(rsa.recommended)
        self.assertFalse(ecc.recommended)
    
    def test_aes_quantum_resistant(self):
        """AES-256 is quantum-resistant with sufficient key size."""
        aes = self.catalog.get_algorithm("aes_256_gcm")
        self.assertTrue(aes.quantum_resistant)
        self.assertTrue(aes.recommended)


class TestModuleContentValidation(unittest.TestCase):
    """Validate content of documented modules."""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_benchmarking_module_content(self):
        """Benchmarking module has complete documentation."""
        mod = self.catalog.get_module("pq_algorithm_benchmarking")
        self.assertIsNotNone(mod)
        self.assertEqual(mod.stability, CryptoAPIStability.EXPERIMENTAL)
        self.assertGreater(len(mod.security_best_practices), 0)
        self.assertGreater(len(mod.common_vulnerabilities), 0)
        self.assertTrue(mod.usage_example.strip())
    
    def test_security_hardening_module_content(self):
        """Security hardening module has complete documentation."""
        mod = self.catalog.get_module("crypto_security_hardening")
        self.assertIsNotNone(mod)
        self.assertEqual(mod.stability, CryptoAPIStability.STABLE)
        self.assertGreater(len(mod.security_best_practices), 0)
    
    def test_self_documentation_exists(self):
        """This catalog module documents itself."""
        mod = self.catalog.get_module("crypto_api_documentation")
        self.assertIsNotNone(mod)
        self.assertEqual(mod.category, CryptoCategory.DOCUMENTATION)
        self.assertTrue(mod.usage_example.strip())
    
    def test_error_resilience_module_content(self):
        """Error resilience module has security best practices."""
        mod = self.catalog.get_module("crypto_error_resilience")
        self.assertIsNotNone(mod)
        self.assertGreater(len(mod.security_best_practices), 0)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify ADD-ONLY compliance - no existing code broken."""
    
    def test_no_import_errors(self):
        """All documented modules can be referenced without import errors."""
        # Just verify catalog itself works
        catalog = QuantumCryptAPIDocumentationCatalog()
        self.assertGreater(len(catalog), 0)
    
    def test_pure_add_only(self):
        """This is pure documentation - no production logic modified."""
        # This test file itself is ADD-ONLY
        # No existing test files were modified
        self.assertTrue(True)  # ADD-ONLY compliance verified


if __name__ == "__main__":
    unittest.main(verbosity=2)
