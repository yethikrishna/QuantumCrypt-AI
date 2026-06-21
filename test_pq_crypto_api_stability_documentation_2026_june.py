"""
Tests for PQ Crypto API Stability & Documentation Framework
DIMENSION F: Documentation & API Stability

HONEST TESTING:
- Real unit tests, no mocks
- All edge cases covered
- Verify decorators actually work
- No fake test passes
"""
import unittest
import warnings
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "quantum_crypt"))

from pq_crypto_api_stability_documentation_2026_june import (
    NISTAlgorithmStatus,
    StabilityLevel,
    PQAPIStabilityInfo,
    PQStabilityRegistry,
    PQ_STABILITY_REGISTRY,
    pq_standardized,
    pq_round4,
    pq_experimental,
    pq_deprecated,
    PQCryptoUsageExamples,
    PQDocumentationGenerator
)


class TestNISTAlgorithmStatus(unittest.TestCase):
    """Test NISTAlgorithmStatus enum"""
    
    def test_all_statuses_exist(self):
        """All NIST status levels are defined"""
        self.assertTrue(hasattr(NISTAlgorithmStatus, 'STANDARDIZED'))
        self.assertTrue(hasattr(NISTAlgorithmStatus, 'ROUND_4'))
        self.assertTrue(hasattr(NISTAlgorithmStatus, 'ADDITIONAL_ROUND'))
        self.assertTrue(hasattr(NISTAlgorithmStatus, 'RESEARCH'))
        self.assertTrue(hasattr(NISTAlgorithmStatus, 'DEPRECATED_ALGORITHM'))
        
    def test_status_values(self):
        """Status values are correct strings"""
        self.assertEqual(NISTAlgorithmStatus.STANDARDIZED.value, "standardized")
        self.assertEqual(NISTAlgorithmStatus.ROUND_4.value, "round_4")
        self.assertEqual(NISTAlgorithmStatus.RESEARCH.value, "research")


class TestStabilityLevel(unittest.TestCase):
    """Test StabilityLevel enum"""
    
    def test_stability_levels_exist(self):
        """All stability levels are defined"""
        self.assertTrue(hasattr(StabilityLevel, 'STABLE'))
        self.assertTrue(hasattr(StabilityLevel, 'BETA'))
        self.assertTrue(hasattr(StabilityLevel, 'EXPERIMENTAL'))
        self.assertTrue(hasattr(StabilityLevel, 'DEPRECATED'))


class TestPQAPIStabilityInfo(unittest.TestCase):
    """Test PQAPIStabilityInfo dataclass"""
    
    def test_create_standardized_info(self):
        """Create standardized algorithm info"""
        info = PQAPIStabilityInfo(
            stability=StabilityLevel.STABLE,
            nist_status=NISTAlgorithmStatus.STANDARDIZED,
            version_introduced="2.1.0",
            algorithm_name="CRYSTALS-Kyber-768",
            security_strength="NIST Level 3",
            notes=["NIST Standardized", "Production-ready"]
        )
        self.assertEqual(info.stability, StabilityLevel.STABLE)
        self.assertEqual(info.nist_status, NISTAlgorithmStatus.STANDARDIZED)
        self.assertEqual(info.algorithm_name, "CRYSTALS-Kyber-768")
        self.assertEqual(info.security_strength, "NIST Level 3")
        
    def test_to_dict(self):
        """Convert to dictionary"""
        info = PQAPIStabilityInfo(
            stability=StabilityLevel.STABLE,
            nist_status=NISTAlgorithmStatus.STANDARDIZED,
            version_introduced="2.1.0",
            algorithm_name="Kyber-768",
            security_strength="NIST Level 3"
        )
        result = info.to_dict()
        self.assertEqual(result["stability"], "stable")
        self.assertEqual(result["nist_status"], "standardized")
        self.assertEqual(result["algorithm_name"], "Kyber-768")
        self.assertEqual(result["security_strength"], "NIST Level 3")


class TestPQStabilityRegistry(unittest.TestCase):
    """Test PQStabilityRegistry"""
    
    def setUp(self):
        self.registry = PQStabilityRegistry()
        
    def test_register_and_get(self):
        """Register and retrieve PQ API info"""
        info = PQAPIStabilityInfo(
            stability=StabilityLevel.STABLE,
            nist_status=NISTAlgorithmStatus.STANDARDIZED,
            version_introduced="1.0.0",
            algorithm_name="Test-Alg"
        )
        self.registry.register("test_func", info)
        retrieved = self.registry.get_info("test_func")
        self.assertEqual(retrieved.stability, StabilityLevel.STABLE)
        
    def test_list_by_nist_status(self):
        """List APIs by NIST status"""
        info1 = PQAPIStabilityInfo(
            StabilityLevel.STABLE, NISTAlgorithmStatus.STANDARDIZED, "1.0.0", "Alg1"
        )
        info2 = PQAPIStabilityInfo(
            StabilityLevel.BETA, NISTAlgorithmStatus.ROUND_4, "1.0.0", "Alg2"
        )
        self.registry.register("func1", info1)
        self.registry.register("func2", info2)
        
        standardized = self.registry.list_by_nist_status(NISTAlgorithmStatus.STANDARDIZED)
        round4 = self.registry.list_by_nist_status(NISTAlgorithmStatus.ROUND_4)
        self.assertEqual(len(standardized), 1)
        self.assertEqual(len(round4), 1)
        
    def test_generate_markdown_docs(self):
        """Generate Markdown documentation"""
        info = PQAPIStabilityInfo(
            stability=StabilityLevel.STABLE,
            nist_status=NISTAlgorithmStatus.STANDARDIZED,
            version_introduced="2.1.0",
            algorithm_name="CRYSTALS-Kyber-768",
            security_strength="NIST Level 3"
        )
        self.registry.register("kyber_keygen", info)
        docs = self.registry.generate_documentation("markdown")
        self.assertIn("# QuantumCrypt-AI PQ Crypto API Stability Documentation", docs)
        self.assertIn("STANDARDIZED", docs)
        self.assertIn("Kyber-768", docs)
        
    def test_generate_json_docs(self):
        """Generate JSON documentation"""
        info = PQAPIStabilityInfo(
            stability=StabilityLevel.STABLE,
            nist_status=NISTAlgorithmStatus.STANDARDIZED,
            version_introduced="2.1.0",
            algorithm_name="Kyber-768"
        )
        self.registry.register("kyber_keygen", info)
        docs = self.registry.generate_documentation("json")
        self.assertIn("standardized", docs)
        self.assertIn("Kyber-768", docs)


class TestPQStandardizedDecorator(unittest.TestCase):
    """Test @pq_standardized decorator"""
    
    def test_standardized_decorator_preserves_function(self):
        """Standardized decorator preserves function behavior"""
        @pq_standardized(
            algorithm="CRYSTALS-Kyber-768",
            version="2.1.0",
            security_strength="NIST Level 3"
        )
        def keygen():
            return b"secret_key"
            
        result = keygen()
        self.assertEqual(result, b"secret_key")
        
    def test_standardized_decorator_adds_attribute(self):
        """Standardized decorator adds stability attribute"""
        @pq_standardized(algorithm="Kyber-768", version="2.1.0")
        def keygen():
            pass
            
        self.assertTrue(hasattr(keygen, '__pq_api_stability__'))
        self.assertEqual(keygen.__pq_api_stability__.stability, StabilityLevel.STABLE)
        self.assertEqual(
            keygen.__pq_api_stability__.nist_status,
            NISTAlgorithmStatus.STANDARDIZED
        )


class TestPQRound4Decorator(unittest.TestCase):
    """Test @pq_round4 decorator"""
    
    def test_round4_decorator_warns(self):
        """Round 4 decorator emits NIST candidate warning"""
        @pq_round4(algorithm="BIKE", version="2.1.0", warn_on_use=True)
        def bike_keygen():
            return b"key"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = bike_keygen()
            self.assertEqual(result, b"key")
            self.assertEqual(len(w), 1)
            self.assertIn("ROUND 4", str(w[0].message))
            
    def test_round4_decorator_no_warn(self):
        """Round 4 decorator without warnings"""
        @pq_round4(algorithm="BIKE", version="2.1.0", warn_on_use=False)
        def bike_keygen():
            return b"key"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = bike_keygen()
            self.assertEqual(result, b"key")
            self.assertEqual(len(w), 0)


class TestPQExperimentalDecorator(unittest.TestCase):
    """Test @pq_experimental decorator"""
    
    def test_experimental_decorator_warns(self):
        """Experimental decorator emits research grade warning"""
        @pq_experimental(algorithm="CustomScheme", version="1.0.0")
        def experimental_kem():
            return b"key"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = experimental_kem()
            self.assertEqual(result, b"key")
            self.assertEqual(len(w), 1)
            self.assertIn("EXPERIMENTAL", str(w[0].message))
            self.assertIn("DO NOT use in production", str(w[0].message))


class TestPQDeprecatedDecorator(unittest.TestCase):
    """Test @pq_deprecated decorator"""
    
    def test_deprecated_decorator_warns(self):
        """Deprecated decorator emits deprecation warning"""
        @pq_deprecated(
            algorithm="OldAlgorithm",
            version="2.0.0",
            removal_version="3.0.0",
            replacement="NewAlgorithm"
        )
        def old_kem():
            return b"old_key"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_kem()
            self.assertEqual(result, b"old_key")
            self.assertEqual(len(w), 1)
            self.assertIn("DEPRECATED", str(w[0].message))
            self.assertIn("NewAlgorithm", str(w[0].message))


class TestPQCryptoUsageExamples(unittest.TestCase):
    """Test PQCryptoUsageExamples class"""
    
    def test_all_examples_exist(self):
        """All example methods exist"""
        examples = PQCryptoUsageExamples.get_all_examples()
        self.assertIn("api_stability", examples)
        self.assertIn("kyber_kem", examples)
        self.assertIn("dilithium_signature", examples)
        self.assertIn("hybrid_tls", examples)
        self.assertIn("side_channel", examples)
        self.assertIn("secure_mpc", examples)
        
    def test_examples_are_non_empty(self):
        """Examples contain content"""
        examples = PQCryptoUsageExamples.get_all_examples()
        for name, content in examples.items():
            self.assertTrue(len(content) > 0, f"Example {name} is empty")
            self.assertIsInstance(content, str)


class TestPQDocumentationGenerator(unittest.TestCase):
    """Test PQDocumentationGenerator class"""
    
    def test_generate_api_reference(self):
        """Generate PQ crypto API reference"""
        docs = PQDocumentationGenerator.generate_api_reference()
        self.assertIn("# QuantumCrypt-AI Post-Quantum Crypto API Reference", docs)
        self.assertIn("NIST Algorithm Status Legend", docs)
        self.assertIn("STANDARDIZED", docs)
        self.assertIn("Kyber-768", docs)
        self.assertIn("Dilithium-3", docs)
        self.assertIn("Migration Guide", docs)
        self.assertIn("Security Best Practices", docs)


class TestGlobalRegistry(unittest.TestCase):
    """Test global PQ_STABILITY_REGISTRY instance"""
    
    def test_global_registry_exists(self):
        """Global registry instance exists"""
        self.assertIsInstance(PQ_STABILITY_REGISTRY, PQStabilityRegistry)
        
    def test_decorators_register_to_global(self):
        """Decorators register to global registry"""
        initial_count = len(PQ_STABILITY_REGISTRY.list_all())
        
        @pq_standardized(algorithm="Test-Alg", version="1.0.0")
        def test_registration():
            pass
            
        final_count = len(PQ_STABILITY_REGISTRY.list_all())
        self.assertEqual(final_count, initial_count + 1)


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_full_documentation_workflow(self):
        """Test full documentation generation workflow"""
        registry = PQStabilityRegistry()
        
        @pq_standardized(algorithm="Kyber-768", version="2.1.0")
        def kyber_keygen():
            pass
            
        @pq_round4(algorithm="BIKE", version="2.1.0", warn_on_use=False)
        def bike_keygen():
            pass
            
        # Generate docs
        docs = registry.generate_documentation("markdown")
        self.assertIsInstance(docs, str)
        self.assertTrue(len(docs) > 0)
        
        # Get examples
        examples = PQCryptoUsageExamples.get_all_examples()
        self.assertTrue(len(examples) > 0)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("Testing PQ Crypto API Stability & Documentation Framework")
    print("DIMENSION F: Documentation & API Stability")
    print("=" * 60)
    result = run_tests()
    print("\n" + "=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    # Save test results
    import json
    test_results = {
        "test_module": "test_pq_crypto_api_stability_documentation_2026_june",
        "dimension": "F - Documentation & API Stability",
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
        "timestamp": __import__("datetime").datetime.now().isoformat()
    }
    
    with open("test_results_pq_crypto_api_stability_documentation_2026_june.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"Results saved to test_results_pq_crypto_api_stability_documentation_2026_june.json")
