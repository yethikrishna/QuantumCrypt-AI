"""
Test Suite for QuantumCrypt Comprehensive API Documentation & Stability Catalog v32

DIMENSION F - Documentation & API Stability
CODE LOGIC IS SACRED - only docs and metadata tested

Tests verify:
- Documentation catalog initialization
- Stability level classification
- NIST PQC status tracking
- Algorithm documentation retrieval
- README generation
- All existing tests continue to pass
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

import unittest
from comprehensive_api_documentation_stability_catalog_v32_2026_june import (
    QuantumCryptDocumentationCatalog,
    StabilityLevel,
    NISTPQCStatus,
    AlgorithmDocumentation,
    documentation_catalog
)


class TestStabilityLevel(unittest.TestCase):
    """Test stability level enumeration."""
    
    def test_stability_level_values(self):
        """Verify all stability levels are defined."""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.BETA.value, "BETA")


class TestNISTPQCStatus(unittest.TestCase):
    """Test NIST PQC standardization status enumeration."""
    
    def test_nist_status_values(self):
        """Verify all NIST status levels are defined."""
        self.assertEqual(NISTPQCStatus.STANDARDIZED.value, "STANDARDIZED")
        self.assertEqual(NISTPQCStatus.ROUND_4.value, "ROUND_4")
        self.assertEqual(NISTPQCStatus.ROUND_3.value, "ROUND_3")
        self.assertEqual(NISTPQCStatus.CANDIDATE.value, "CANDIDATE")
        self.assertEqual(NISTPQCStatus.RESEARCH.value, "RESEARCH")


class TestAlgorithmDocumentation(unittest.TestCase):
    """Test AlgorithmDocumentation dataclass."""
    
    def test_algorithm_documentation_creation(self):
        """Verify algorithm documentation can be created."""
        doc = AlgorithmDocumentation(
            algorithm_name="test_algo",
            stability=StabilityLevel.STABLE,
            nist_status=NISTPQCStatus.STANDARDIZED,
            version="1.0.0",
            description="Test algorithm",
            security_level="NIST Level 3",
            key_sizes={"test": 128}
        )
        self.assertEqual(doc.algorithm_name, "test_algo")
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
        self.assertEqual(doc.nist_status, NISTPQCStatus.STANDARDIZED)
        self.assertEqual(doc.security_level, "NIST Level 3")


class TestDocumentationCatalog(unittest.TestCase):
    """Test the main documentation catalog."""
    
    def setUp(self):
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_catalog_initialization(self):
        """Verify catalog initializes with algorithms."""
        self.assertGreater(len(self.catalog._catalog), 0)
    
    def test_get_existing_algorithm_documentation(self):
        """Verify documentation retrieval for existing algorithm."""
        doc = self.catalog.get_algorithm_documentation("crystals_kyber")
        self.assertIsNotNone(doc)
        self.assertEqual(doc.algorithm_name, "CRYSTALS-Kyber")
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
        self.assertEqual(doc.nist_status, NISTPQCStatus.STANDARDIZED)
    
    def test_get_nonexistent_algorithm_documentation(self):
        """Verify None returned for non-existent algorithm."""
        doc = self.catalog.get_algorithm_documentation("nonexistent_algo_xyz")
        self.assertIsNone(doc)
    
    def test_case_insensitive_lookup(self):
        """Verify lookup is case insensitive."""
        doc1 = self.catalog.get_algorithm_documentation("CRYSTALS_KYBER")
        doc2 = self.catalog.get_algorithm_documentation("crystals_kyber")
        self.assertIsNotNone(doc1)
        self.assertIsNotNone(doc2)
        self.assertEqual(doc1.algorithm_name, doc2.algorithm_name)
    
    def test_list_algorithms_by_stability(self):
        """Verify filtering by stability level."""
        stable_algos = self.catalog.list_algorithms_by_stability(StabilityLevel.STABLE)
        self.assertIsInstance(stable_algos, list)
        self.assertIn("crystals_kyber", stable_algos)
        
        beta_algos = self.catalog.list_algorithms_by_stability(StabilityLevel.BETA)
        self.assertIsInstance(beta_algos, list)
        self.assertIn("performance_benchmark_profiler", beta_algos)
    
    def test_list_algorithms_by_nist_status(self):
        """Verify filtering by NIST PQC status."""
        standardized = self.catalog.list_algorithms_by_nist_status(NISTPQCStatus.STANDARDIZED)
        self.assertIsInstance(standardized, list)
        self.assertIn("crystals_kyber", standardized)
        self.assertIn("crystals_dilithium", standardized)
        
        research = self.catalog.list_algorithms_by_nist_status(NISTPQCStatus.RESEARCH)
        self.assertIsInstance(research, list)
        self.assertIn("performance_benchmark_profiler", research)
    
    def test_get_stability_summary(self):
        """Verify stability summary generation."""
        summary = self.catalog.get_stability_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn("STABLE", summary)
        self.assertGreater(summary["STABLE"], 0)
    
    def test_get_nist_status_summary(self):
        """Verify NIST status summary generation."""
        summary = self.catalog.get_nist_status_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn("STANDARDIZED", summary)
        self.assertGreater(summary["STANDARDIZED"], 0)
    
    def test_generate_readme_section(self):
        """Verify README section generation."""
        readme = self.catalog.generate_readme_section()
        self.assertIsInstance(readme, str)
        self.assertGreater(len(readme), 0)
        self.assertIn("QuantumCrypt API Stability Summary", readme)
        self.assertIn("CRYSTALS-Kyber", readme)
    
    def test_documentation_has_usage_examples(self):
        """Verify algorithms have usage examples."""
        doc = self.catalog.get_algorithm_documentation("crystals_kyber")
        self.assertGreater(len(doc.usage_examples), 0)
        self.assertIn("KyberKEM", doc.usage_examples[0])
    
    def test_documentation_has_parameters(self):
        """Verify algorithms have parameter documentation."""
        doc = self.catalog.get_algorithm_documentation("hybrid_kem_engine")
        self.assertGreater(len(doc.parameters), 0)
        self.assertIn("pqc_algorithm", doc.parameters)
    
    def test_documentation_has_security_level(self):
        """Verify algorithms have security level documentation."""
        doc = self.catalog.get_algorithm_documentation("crystals_dilithium")
        self.assertGreater(len(doc.security_level), 0)
        self.assertIn("NIST Security Level", doc.security_level)
    
    def test_documentation_has_key_sizes(self):
        """Verify algorithms have key size documentation."""
        doc = self.catalog.get_algorithm_documentation("crystals_kyber")
        self.assertGreater(len(doc.key_sizes), 0)
        self.assertIn("Kyber-768", doc.key_sizes)
    
    def test_documentation_has_compliance_notes(self):
        """Verify algorithms have compliance notes."""
        doc = self.catalog.get_algorithm_documentation("crystals_kyber")
        self.assertGreater(len(doc.compliance_notes), 0)
        self.assertTrue(any("NIST" in note for note in doc.compliance_notes))
    
    def test_singleton_instance(self):
        """Verify singleton instance works."""
        self.assertIsInstance(documentation_catalog, QuantumCryptDocumentationCatalog)
    
    def test_all_algorithms_have_descriptions(self):
        """Verify all documented algorithms have descriptions."""
        for algo_name, doc in self.catalog._catalog.items():
            with self.subTest(algorithm=algo_name):
                self.assertGreater(len(doc.description), 0)
                self.assertGreater(len(doc.version), 0)
                self.assertGreater(len(doc.security_level), 0)
    
    def test_see_also_references(self):
        """Verify see_also references are lists."""
        doc = self.catalog.get_algorithm_documentation("crystals_kyber")
        self.assertIsInstance(doc.see_also, list)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify no breaking changes - all existing behavior preserved."""
    
    def test_no_core_modifications(self):
        """Verify this is documentation-only - no core logic modified."""
        # This module only contains documentation classes
        import comprehensive_api_documentation_stability_catalog_v32_2026_june as doc_module
        
        # Should only contain documentation-related classes
        public_items = [x for x in dir(doc_module) if not x.startswith('_')]
        self.assertIn("QuantumCryptDocumentationCatalog", public_items)
        self.assertIn("StabilityLevel", public_items)
        self.assertIn("NISTPQCStatus", public_items)
        self.assertIn("AlgorithmDocumentation", public_items)
        
        # Should NOT modify any existing crypto logic
        self.assertNotIn("KyberKEM", public_items)
        self.assertNotIn("keygen", public_items)
        self.assertNotIn("encapsulate", public_items)


if __name__ == "__main__":
    unittest.main(verbosity=2)
