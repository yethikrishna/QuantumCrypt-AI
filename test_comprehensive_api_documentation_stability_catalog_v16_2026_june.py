"""
Test Suite for QuantumCrypt-AI Documentation Catalog v16
Session 115 - Dimension F: Documentation & API Stability

Tests verify:
- Catalog initialization and module registration
- Stability level filtering works correctly
- Category filtering works correctly
- NIST algorithm filtering works correctly
- Report generation produces valid output
- JSON export functionality
- README snippet generation
- All documented modules have valid metadata
"""

import unittest
import json
import tempfile
import os
from quantum_crypt.comprehensive_api_documentation_stability_catalog_v16_2026_june import (
    QuantumCryptDocumentationCatalog,
    StabilityLevel,
    ModuleCategory,
    ModuleDocumentation,
    APIParameter,
    APIExample
)


class TestStabilityLevelEnum(unittest.TestCase):
    """Test StabilityLevel enum has all required values"""
    
    def test_has_all_stability_levels(self):
        levels = [level.value for level in StabilityLevel]
        self.assertIn("STABLE", levels)
        self.assertIn("EXPERIMENTAL", levels)
        self.assertIn("DEPRECATED", levels)
        self.assertIn("LEGACY", levels)
    
    def test_four_stability_levels_total(self):
        self.assertEqual(len(StabilityLevel), 4)


class TestModuleCategoryEnum(unittest.TestCase):
    """Test ModuleCategory enum has all required categories"""
    
    def test_has_core_categories(self):
        categories = [cat.value for cat in ModuleCategory]
        self.assertIn("POST_QUANTUM_KEY_ENCAPSULATION", categories)
        self.assertIn("POST_QUANTUM_SIGNATURES", categories)
        self.assertIn("HYBRID_PQC_CLASSICAL", categories)
        self.assertIn("BENCHMARKING_PERFORMANCE", categories)
        self.assertIn("SECURITY_HARDENING", categories)
        self.assertIn("ENTROPY_COLLECTION", categories)


class TestAPIParameter(unittest.TestCase):
    """Test APIParameter dataclass"""
    
    def test_parameter_creation(self):
        param = APIParameter(
            name="test_param",
            param_type="str",
            description="Test parameter",
            required=True,
            default_value=None
        )
        self.assertEqual(param.name, "test_param")
        self.assertEqual(param.param_type, "str")
        self.assertTrue(param.required)


class TestAPIExample(unittest.TestCase):
    """Test APIExample dataclass"""
    
    def test_example_creation(self):
        example = APIExample(
            title="Test Example",
            code="print('hello')",
            description="Test description"
        )
        self.assertEqual(example.title, "Test Example")
        self.assertIn("hello", example.code)


class TestModuleDocumentation(unittest.TestCase):
    """Test ModuleDocumentation dataclass with NIST extensions"""
    
    def test_documentation_creation(self):
        doc = ModuleDocumentation(
            module_name="Test Module",
            filename="test_module.py",
            category=ModuleCategory.PQC_KEM,
            stability=StabilityLevel.STABLE,
            version="v1",
            description="Test module description",
            main_class="TestClass",
            nist_standard=True,
            security_level=3
        )
        self.assertEqual(doc.module_name, "Test Module")
        self.assertTrue(doc.nist_standard)
        self.assertEqual(doc.security_level, 3)
    
    def test_to_dict_serialization_includes_nist_fields(self):
        doc = ModuleDocumentation(
            module_name="Test",
            filename="test.py",
            category=ModuleCategory.PQC_KEM,
            stability=StabilityLevel.STABLE,
            version="v1",
            description="Test",
            main_class="Test",
            nist_standard=True,
            security_level=5
        )
        result = doc.to_dict()
        self.assertIsInstance(result, dict)
        self.assertTrue(result["nist_standard"])
        self.assertEqual(result["security_level"], 5)


class TestQuantumCryptDocumentationCatalogBasics(unittest.TestCase):
    """Test basic catalog functionality"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_catalog_initializes_successfully(self):
        self.assertIsNotNone(self.catalog)
    
    def test_catalog_has_modules_registered(self):
        modules = self.catalog.get_all_documentation()
        self.assertGreater(len(modules), 0)
        print(f"\nTotal modules documented: {len(modules)}")
    
    def test_get_module_documentation_returns_none_for_missing(self):
        result = self.catalog.get_module_documentation("nonexistent_module_xyz")
        self.assertIsNone(result)
    
    def test_get_module_documentation_returns_doc_for_existing(self):
        result = self.catalog.get_module_documentation("pq_algorithm_benchmarking_suite")
        self.assertIsNotNone(result)
        self.assertIsInstance(result, ModuleDocumentation)


class TestStabilityFiltering(unittest.TestCase):
    """Test filtering modules by stability level"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_get_stable_modules(self):
        stable = self.catalog.get_modules_by_stability(StabilityLevel.STABLE)
        self.assertGreater(len(stable), 0)
        for mod in stable:
            self.assertEqual(mod.stability, StabilityLevel.STABLE)
        print(f"STABLE modules: {len(stable)}")
    
    def test_get_experimental_modules(self):
        experimental = self.catalog.get_modules_by_stability(StabilityLevel.EXPERIMENTAL)
        # v13 Benchmarking Suite should be experimental
        for mod in experimental:
            self.assertEqual(mod.stability, StabilityLevel.EXPERIMENTAL)
        print(f"EXPERIMENTAL modules: {len(experimental)}")


class TestCategoryFiltering(unittest.TestCase):
    """Test filtering modules by category"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_get_benchmarking_modules(self):
        bench_modules = self.catalog.get_modules_by_category(ModuleCategory.BENCHMARKING)
        self.assertGreaterEqual(len(bench_modules), 1)
    
    def test_get_kem_modules(self):
        kem_modules = self.catalog.get_modules_by_category(ModuleCategory.PQC_KEM)
        self.assertGreaterEqual(len(kem_modules), 1)
    
    def test_get_signature_modules(self):
        sig_modules = self.catalog.get_modules_by_category(ModuleCategory.PQC_SIGNATURE)
        self.assertGreaterEqual(len(sig_modules), 1)
    
    def test_get_hybrid_modules(self):
        hybrid_modules = self.catalog.get_modules_by_category(ModuleCategory.HYBRID_CRYPTO)
        self.assertGreaterEqual(len(hybrid_modules), 1)


class TestNISTAlgorithmFiltering(unittest.TestCase):
    """Test special NIST standard algorithm filtering"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_get_nist_standard_algorithms(self):
        nist_algs = self.catalog.get_nist_standard_algorithms()
        self.assertGreaterEqual(len(nist_algs), 3)  # Kyber + Dilithium + Hybrid
        for alg in nist_algs:
            self.assertTrue(alg.nist_standard, f"{alg.module_name} should be NIST standard")
        print(f"NIST Standard Algorithms: {len(nist_algs)}")


class TestStabilityReportGeneration(unittest.TestCase):
    """Test stability report generation with NIST counts"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_generate_stability_report(self):
        report = self.catalog.generate_stability_report()
        self.assertIsInstance(report, dict)
        self.assertIn("report_version", report)
        self.assertIn("total_modules_documented", report)
        self.assertIn("nist_standard_algorithms", report)
        self.assertIn("modules_by_stability", report)
        self.assertIn("modules_by_category", report)
    
    def test_report_has_valid_version(self):
        report = self.catalog.generate_stability_report()
        self.assertEqual(report["report_version"], "v16")
    
    def test_report_includes_nist_count(self):
        report = self.catalog.generate_stability_report()
        self.assertGreaterEqual(report["nist_standard_algorithms"], 3)
    
    def test_report_module_count_matches(self):
        report = self.catalog.generate_stability_report()
        actual_modules = len(self.catalog.get_all_documentation())
        self.assertEqual(report["total_modules_documented"], actual_modules)


class TestJSONExport(unittest.TestCase):
    """Test JSON export functionality"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_export_to_json_creates_valid_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            self.catalog.export_to_json(temp_path)
            
            # Verify file exists and is valid JSON
            self.assertTrue(os.path.exists(temp_path))
            with open(temp_path, 'r') as f:
                data = json.load(f)
            
            self.assertIn("catalog_version", data)
            self.assertIn("modules", data)
            self.assertGreater(len(data["modules"]), 0)
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestReadmeSnippetGeneration(unittest.TestCase):
    """Test README Markdown snippet generation"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_generate_readme_snippet(self):
        snippet = self.catalog.generate_readme_snippet()
        self.assertIsInstance(snippet, str)
        self.assertGreater(len(snippet), 0)
        # Should contain NIST reference
        self.assertIn("NIST", snippet)
        # Should contain markdown
        self.assertIn("#", snippet)
        self.assertIn("|", snippet)


class TestBenchmarkingSuiteDocumentation(unittest.TestCase):
    """Test specific documentation for v13 PQ Benchmarking Suite"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_benchmarking_suite_marked_experimental(self):
        doc = self.catalog.get_module_documentation("pq_algorithm_benchmarking_suite")
        self.assertIsNotNone(doc)
        # New v13 feature should be EXPERIMENTAL
        self.assertEqual(doc.stability, StabilityLevel.EXPERIMENTAL)
    
    def test_benchmarking_suite_has_examples(self):
        doc = self.catalog.get_module_documentation("pq_algorithm_benchmarking_suite")
        self.assertGreater(len(doc.examples), 0)
    
    def test_benchmarking_suite_has_public_methods(self):
        doc = self.catalog.get_module_documentation("pq_algorithm_benchmarking_suite")
        self.assertGreater(len(doc.public_methods), 0)
    
    def test_benchmarking_suite_has_parameters(self):
        doc = self.catalog.get_module_documentation("pq_algorithm_benchmarking_suite")
        self.assertGreater(len(doc.parameters), 0)


class TestNISTAlgorithmDocumentation(unittest.TestCase):
    """Test NIST PQC algorithm documentation"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_kyber_marked_nist_standard(self):
        doc = self.catalog.get_module_documentation("crystals_kyber")
        self.assertIsNotNone(doc)
        self.assertTrue(doc.nist_standard)
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
    
    def test_dilithium_marked_nist_standard(self):
        doc = self.catalog.get_module_documentation("crystals_dilithium")
        self.assertIsNotNone(doc)
        self.assertTrue(doc.nist_standard)
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
    
    def test_hybrid_marked_nist_standard(self):
        doc = self.catalog.get_module_documentation("hybrid_pqc_classical")
        self.assertIsNotNone(doc)
        self.assertTrue(doc.nist_standard)
        self.assertEqual(doc.stability, StabilityLevel.STABLE)


class TestSideChannelDocumentation(unittest.TestCase):
    """Test side-channel resistant primitives documentation"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_side_channel_marked_stable(self):
        doc = self.catalog.get_module_documentation("side_channel_resistant_primitives")
        self.assertIsNotNone(doc)
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
        self.assertEqual(doc.category, ModuleCategory.SECURITY_HARDENING)
    
    def test_side_channel_has_examples(self):
        doc = self.catalog.get_module_documentation("side_channel_resistant_primitives")
        self.assertGreater(len(doc.examples), 0)


class TestSelfReferentialDocumentation(unittest.TestCase):
    """Test that the catalog documents itself"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_catalog_documents_itself(self):
        doc = self.catalog.get_module_documentation("api_documentation_catalog_v16")
        self.assertIsNotNone(doc)
        self.assertEqual(doc.category, ModuleCategory.DOCUMENTATION)
        self.assertEqual(doc.stability, StabilityLevel.STABLE)


class TestAllModulesHaveValidMetadata(unittest.TestCase):
    """Comprehensive test that ALL registered modules have complete metadata"""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_all_modules_have_descriptions(self):
        for mod in self.catalog.get_all_documentation():
            with self.subTest(module=mod.module_name):
                self.assertGreater(len(mod.description), 0,
                    f"Module {mod.module_name} missing description")
    
    def test_all_modules_have_main_class(self):
        for mod in self.catalog.get_all_documentation():
            with self.subTest(module=mod.module_name):
                self.assertGreater(len(mod.main_class), 0,
                    f"Module {mod.module_name} missing main_class")
    
    def test_all_modules_have_valid_stability(self):
        for mod in self.catalog.get_all_documentation():
            with self.subTest(module=mod.module_name):
                self.assertIsInstance(mod.stability, StabilityLevel,
                    f"Module {mod.module_name} invalid stability")
    
    def test_all_modules_have_valid_category(self):
        for mod in self.catalog.get_all_documentation():
            with self.subTest(module=mod.module_name):
                self.assertIsInstance(mod.category, ModuleCategory,
                    f"Module {mod.module_name} invalid category")


# =====================================================================
# TEST RUNNER
# =====================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("QuantumCrypt-AI Documentation Catalog v16 - Test Suite")
    print("Session 115 - Dimension F: Documentation & API Stability")
    print("=" * 70)
    
    unittest.main(verbosity=2)
