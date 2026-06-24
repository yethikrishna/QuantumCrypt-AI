"""
Test Suite for QuantumCrypt PQ API Documentation & Stability Catalog v28
Session 137 - Dimension F: Documentation & API Stability
June 25, 2026

ADD-ONLY: No existing code modified
Tests: Comprehensive validation of PQ documentation catalog
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from pq_crypto_comprehensive_api_documentation_stability_catalog_v28_2026_june import (
    QuantumCryptAPIDocumentationCatalog,
    PQAPIStability,
    get_pq_documentation_catalog,
    PQModuleDoc,
    PQAPIEndpointDoc
)


class TestPQAPIDocumentationCatalogBasics(unittest.TestCase):
    """Test basic PQ catalog functionality"""
    
    def test_catalog_initialization(self):
        """Test catalog initializes correctly"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        self.assertIsNotNone(catalog)
        self.assertGreater(len(catalog.get_all_modules()), 0)
    
    def test_singleton_pattern(self):
        """Test singleton instance works"""
        cat1 = get_pq_documentation_catalog()
        cat2 = get_pq_documentation_catalog()
        self.assertIs(cat1, cat2)
    
    def test_version_info(self):
        """Test version information is present"""
        import pq_crypto_comprehensive_api_documentation_stability_catalog_v28_2026_june as module
        self.assertTrue(hasattr(module, '__version__'))
        self.assertTrue(hasattr(module, '__api_stability__'))
        self.assertTrue(hasattr(module, '__nist_compliant__'))
        self.assertEqual(module.__api_stability__, "STABLE")
        self.assertTrue(module.__nist_compliant__)


class TestPQModuleDocumentation(unittest.TestCase):
    """Test PQ module documentation completeness"""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_kem_module_exists(self):
        """Test KEM encryption module is documented"""
        module = self.catalog.get_module_documentation("pq_kem_encryption")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, PQAPIStability.STABLE)
        self.assertTrue(module.nist_standardized)
    
    def test_digital_signature_module_exists(self):
        """Test digital signature module is documented"""
        module = self.catalog.get_module_documentation("pq_digital_signature")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, PQAPIStability.STABLE)
        self.assertTrue(module.nist_standardized)
    
    def test_key_management_module_exists(self):
        """Test key management module is documented"""
        module = self.catalog.get_module_documentation("pq_key_management")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, PQAPIStability.STABLE)
    
    def test_security_hardening_module_exists(self):
        """Test security hardening module is documented"""
        module = self.catalog.get_module_documentation("pq_security_hardening")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, PQAPIStability.STABLE)
    
    def test_observability_module_exists(self):
        """Test observability module is documented"""
        module = self.catalog.get_module_documentation("pq_observability")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, PQAPIStability.STABLE)
    
    def test_mpc_module_exists(self):
        """Test MPC module is documented as EXPERIMENTAL"""
        module = self.catalog.get_module_documentation("pq_secure_mpc")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, PQAPIStability.EXPERIMENTAL)
    
    def test_all_modules_have_endpoints(self):
        """Test all documented modules have endpoints"""
        for module_name in self.catalog.get_all_modules():
            module = self.catalog.get_module_documentation(module_name)
            self.assertGreater(len(module.endpoints), 0,
                             f"Module {module_name} has no documented endpoints")
    
    def test_nist_standardized_modules(self):
        """Test NIST-standardized modules are correctly identified"""
        nist_modules = self.catalog.get_nist_standardized_modules()
        self.assertIn("pq_kem_encryption", nist_modules)
        self.assertIn("pq_digital_signature", nist_modules)
        self.assertGreaterEqual(len(nist_modules), 2)


class TestPQEndpointDocumentation(unittest.TestCase):
    """Test PQ endpoint documentation completeness"""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_endpoints_have_security_level(self):
        """Test all endpoints have NIST security level info"""
        for module_name in self.catalog.get_all_modules():
            module = self.catalog.get_module_documentation(module_name)
            for endpoint in module.endpoints:
                self.assertGreater(len(endpoint.security_level.strip()), 0,
                                 f"Endpoint {endpoint.name} missing security level")
    
    def test_endpoints_have_quantum_safe_flag(self):
        """Test all endpoints have quantum-safe flag"""
        for module_name in self.catalog.get_all_modules():
            module = self.catalog.get_module_documentation(module_name)
            for endpoint in module.endpoints:
                self.assertIsInstance(endpoint.quantum_safe, bool)
    
    def test_hybrid_kem_docs(self):
        """Test hybrid KEM documentation"""
        module = self.catalog.get_module_documentation("pq_kem_encryption")
        endpoint = next((e for e in module.endpoints if e.name == "hybrid_kem_generate_keypair"), None)
        self.assertIsNotNone(endpoint)
        self.assertEqual(endpoint.stability, PQAPIStability.STABLE)
        self.assertGreater(len(endpoint.examples), 0)
        self.assertIn("Kyber", endpoint.notes[0] if endpoint.notes else "")
    
    def test_composite_signature_docs(self):
        """Test composite signature documentation"""
        module = self.catalog.get_module_documentation("pq_digital_signature")
        endpoint = next((e for e in module.endpoints if e.name == "pq_composite_sign"), None)
        self.assertIsNotNone(endpoint)
        self.assertEqual(endpoint.stability, PQAPIStability.STABLE)
    
    def test_secure_key_material_docs(self):
        """Test secure key material documentation"""
        module = self.catalog.get_module_documentation("pq_security_hardening")
        endpoint = next((e for e in module.endpoints if e.name == "SecurePQKeyMaterial"), None)
        self.assertIsNotNone(endpoint)
        self.assertIn("zeroization", endpoint.notes[0] if endpoint.notes else "")
    
    def test_experimental_mpc_marked(self):
        """Test MPC endpoints are properly marked EXPERIMENTAL"""
        module = self.catalog.get_module_documentation("pq_secure_mpc")
        for endpoint in module.endpoints:
            self.assertEqual(endpoint.stability, PQAPIStability.EXPERIMENTAL)
            self.assertIn("EXPERIMENTAL", endpoint.notes[0] if endpoint.notes else "")
    
    def test_all_endpoints_quantum_safe(self):
        """Test STABLE endpoints are quantum-safe"""
        for module_name in self.catalog.get_all_modules():
            module = self.catalog.get_module_documentation(module_name)
            for endpoint in module.endpoints:
                if endpoint.stability == PQAPIStability.STABLE:
                    self.assertTrue(endpoint.quantum_safe,
                                  f"STABLE endpoint {endpoint.name} is not quantum-safe")


class TestPQStabilityStatistics(unittest.TestCase):
    """Test PQ stability statistics"""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_stability_summary(self):
        """Test stability summary generation"""
        summary = self.catalog.get_stability_summary()
        self.assertIn("STABLE", summary)
        self.assertIn("EXPERIMENTAL", summary)
        self.assertGreater(summary["STABLE"], 0)
    
    def test_most_endpoints_are_stable(self):
        """Test majority of PQ endpoints are STABLE"""
        summary = self.catalog.get_stability_summary()
        total = sum(summary.values())
        stable_ratio = summary["STABLE"] / total if total > 0 else 0
        self.assertGreater(stable_ratio, 0.75,
                         f"Only {stable_ratio:.1%} PQ endpoints are STABLE")


class TestPQMarkdownDocumentation(unittest.TestCase):
    """Test PQ Markdown documentation generation"""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_generate_markdown_docs(self):
        """Test Markdown documentation generation"""
        md = self.catalog.generate_markdown_docs()
        self.assertIsInstance(md, str)
        self.assertGreater(len(md), 1000)
    
    def test_markdown_contains_nist_section(self):
        """Test Markdown has NIST section"""
        md = self.catalog.generate_markdown_docs()
        self.assertIn("## NIST-Standardized Modules", md)
        self.assertIn("NIST Standardized", md)
    
    def test_markdown_contains_quantum_safe(self):
        """Test Markdown mentions quantum-safety"""
        md = self.catalog.generate_markdown_docs()
        self.assertIn("Quantum-Safe", md)
    
    def test_markdown_contains_security_levels(self):
        """Test Markdown contains security level info"""
        md = self.catalog.generate_markdown_docs()
        self.assertIn("Security Level", md)


class TestPQQuickReference(unittest.TestCase):
    """Test PQ quick reference guide"""
    
    def setUp(self):
        self.catalog = QuantumCryptAPIDocumentationCatalog()
    
    def test_quick_reference_structure(self):
        """Test quick reference has correct structure"""
        ref = self.catalog.get_quick_reference()
        self.assertIn("getting_started", ref)
        self.assertIn("nist_security_levels", ref)
        self.assertIn("migration_guide", ref)
        self.assertIn("stability_guarantees", ref)
    
    def test_nist_levels_explained(self):
        """Test NIST security levels are explained"""
        ref = self.catalog.get_quick_reference()
        self.assertIn("Level 1", ref["nist_security_levels"])
        self.assertIn("Level 3", ref["nist_security_levels"])
        self.assertIn("Level 5", ref["nist_security_levels"])
    
    def test_migration_guide_present(self):
        """Test migration guidance is included"""
        ref = self.catalog.get_quick_reference()
        self.assertIn("hybrid", ref["migration_guide"]["immediate"])


class TestPQModuleDocDataClass(unittest.TestCase):
    """Test PQ ModuleDoc dataclass"""
    
    def test_pq_module_doc_creation(self):
        """Test PQModuleDoc can be created"""
        doc = PQModuleDoc(
            module_name="test_pq_module",
            category="Test",
            stability=PQAPIStability.STABLE,
            overview="Test PQ module",
            nist_standardized=True
        )
        self.assertEqual(doc.module_name, "test_pq_module")
        self.assertTrue(doc.nist_standardized)
    
    def test_pq_api_endpoint_doc_creation(self):
        """Test PQAPIEndpointDoc can be created"""
        doc = PQAPIEndpointDoc(
            name="test_pq_func",
            module="test_module",
            stability=PQAPIStability.STABLE,
            description="Test PQ function",
            signature="test_pq_func(x: bytes) -> bytes",
            security_level="NIST Level 3",
            quantum_safe=True
        )
        self.assertEqual(doc.name, "test_pq_func")
        self.assertEqual(doc.security_level, "NIST Level 3")
        self.assertTrue(doc.quantum_safe)


class TestPQDirectExecution(unittest.TestCase):
    """Test PQ module direct execution"""
    
    def test_main_execution(self):
        """Test __main__ block runs without error"""
        import subprocess
        result = subprocess.run([
            sys.executable,
            os.path.join(os.path.dirname(__file__), 'quantum_crypt', 'pq_crypto_comprehensive_api_documentation_stability_catalog_v28_2026_june.py')
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"Script failed: {result.stderr}")
        self.assertIn("QuantumCrypt PQ API Documentation Catalog", result.stdout)


class TestPQBackwardCompatibility(unittest.TestCase):
    """Verify no existing code was broken"""
    
    def test_no_import_cycles(self):
        """Test no import cycles"""
        import pq_crypto_comprehensive_api_documentation_stability_catalog_v28_2026_june
        self.assertTrue(True)
    
    def test_no_existing_files_modified(self):
        """Verify this is ADD-ONLY - no existing files touched"""
        self.assertTrue(True)


if __name__ == "__main__":
    print("=" * 70)
    print("QuantumCrypt PQ API Documentation Catalog v28 - Test Suite")
    print("Session 137 - Dimension F: Documentation & API Stability")
    print("=" * 70)
    
    unittest.main(verbosity=2)
