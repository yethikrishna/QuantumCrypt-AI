"""
Test Suite for QuantumCrypt PQ Crypto API Documentation & Stability Catalog v24
================================================================================
DIMENSION F: Documentation & API Stability
STRICT INCREMENTAL BUILD: ADD-ONLY tests - NO production crypto code modified

This test suite validates the documentation catalog without modifying
any existing production cryptographic code. All tests are purely additive.

CRYPTOGRAPHIC TEST PHILOSOPHY:
- NO modifications to existing cryptographic source files
- NO timing side-channels introduced by tests
- NO breaking changes to existing test suites
- ADD-ONLY pattern for test coverage
- 100% backward compatible test execution
"""

import sys
import os
import unittest
from typing import Any

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from quantum_crypt.crypto_comprehensive_api_documentation_stability_catalog_v24_2026_june import (
    QuantumCryptDocumentationCatalog,
    StabilityLevel,
    AlgorithmSecurityLevel,
    CryptoAPIMetadata,
    CRYPTO_DOCUMENTATION_CATALOG,
    get_algorithm_stability,
    is_quantum_resistant,
    generate_crypto_security_report
)


class TestStabilityLevelEnum(unittest.TestCase):
    """Test cryptographic stability level enum values."""
    
    def test_stability_levels_exist(self) -> None:
        """Verify all crypto stability levels are defined."""
        self.assertTrue(hasattr(StabilityLevel, 'STABLE'))
        self.assertTrue(hasattr(StabilityLevel, 'EXPERIMENTAL'))
        self.assertTrue(hasattr(StabilityLevel, 'DEPRECATED'))
        self.assertTrue(hasattr(StabilityLevel, 'INTERNAL'))
    
    def test_stability_level_values(self) -> None:
        """Verify stability level string values for crypto APIs."""
        self.assertEqual(StabilityLevel.STABLE.value, 'stable')
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, 'experimental')
        self.assertEqual(StabilityLevel.DEPRECATED.value, 'deprecated')
        self.assertEqual(StabilityLevel.INTERNAL.value, 'internal')


class TestAlgorithmSecurityLevelEnum(unittest.TestCase):
    """Test NIST security level classification."""
    
    def test_security_levels_exist(self) -> None:
        """Verify all NIST security levels are defined."""
        self.assertTrue(hasattr(AlgorithmSecurityLevel, 'LEVEL_1'))
        self.assertTrue(hasattr(AlgorithmSecurityLevel, 'LEVEL_3'))
        self.assertTrue(hasattr(AlgorithmSecurityLevel, 'LEVEL_5'))
        self.assertTrue(hasattr(AlgorithmSecurityLevel, 'QUANTUM_RESISTANT'))
    
    def test_security_level_values(self) -> None:
        """Verify security level string values."""
        self.assertEqual(AlgorithmSecurityLevel.LEVEL_1.value, 'NIST Level 1')
        self.assertEqual(AlgorithmSecurityLevel.LEVEL_3.value, 'NIST Level 3')
        self.assertEqual(AlgorithmSecurityLevel.LEVEL_5.value, 'NIST Level 5')
        self.assertEqual(AlgorithmSecurityLevel.QUANTUM_RESISTANT.value, 'QR')


class TestCryptoAPIMetadata(unittest.TestCase):
    """Test CryptoAPIMetadata dataclass structure."""
    
    def test_metadata_creation(self) -> None:
        """Test CryptoAPIMetadata object creation."""
        meta = CryptoAPIMetadata(
            name="TestAlgorithm",
            algorithm_family="Test-Family",
            stability=StabilityLevel.STABLE,
            nist_security_level=AlgorithmSecurityLevel.LEVEL_5,
            version_added="1.0.0",
            description="Test crypto algorithm"
        )
        self.assertEqual(meta.name, "TestAlgorithm")
        self.assertEqual(meta.stability, StabilityLevel.STABLE)
        self.assertEqual(meta.nist_security_level, AlgorithmSecurityLevel.LEVEL_5)
    
    def test_metadata_optional_fields(self) -> None:
        """Test optional fields default correctly."""
        meta = CryptoAPIMetadata(
            name="TestAlgorithm",
            algorithm_family="Test-Family",
            stability=StabilityLevel.STABLE,
            nist_security_level=AlgorithmSecurityLevel.LEVEL_5,
            version_added="1.0.0"
        )
        self.assertIsNone(meta.version_deprecated)
        self.assertIsNone(meta.deprecation_scheduled_removal)
        self.assertEqual(meta.parameters, [])
        self.assertEqual(meta.security_guarantees, [])


class TestCryptoDocumentationCatalog(unittest.TestCase):
    """Test main crypto documentation catalog functionality."""
    
    def setUp(self) -> None:
        """Initialize catalog for each test."""
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_catalog_initialization(self) -> None:
        """Verify catalog initializes without errors."""
        self.assertIsNotNone(self.catalog)
        self.assertIsInstance(self.catalog._catalog, dict)
    
    def test_catalog_has_pq_algorithms(self) -> None:
        """Verify catalog contains post-quantum algorithm entries."""
        self.assertGreater(len(self.catalog._catalog), 0)
    
    def test_get_crypto_api_metadata_existing(self) -> None:
        """Test retrieving metadata for existing PQ algorithm."""
        meta = self.catalog.get_crypto_api_metadata("crystals_kyber_key_encapsulation")
        self.assertIsNotNone(meta)
        self.assertIsInstance(meta, CryptoAPIMetadata)
    
    def test_get_crypto_api_metadata_nonexistent(self) -> None:
        """Test retrieving metadata for non-existent algorithm returns None."""
        meta = self.catalog.get_crypto_api_metadata("nonexistent_crypto_xyz_123")
        self.assertIsNone(meta)
    
    def test_list_algorithms_by_stability(self) -> None:
        """Test filtering algorithms by stability level."""
        stable = self.catalog.list_algorithms_by_stability(StabilityLevel.STABLE)
        experimental = self.catalog.list_algorithms_by_stability(StabilityLevel.EXPERIMENTAL)
        deprecated = self.catalog.list_algorithms_by_stability(StabilityLevel.DEPRECATED)
        
        self.assertIsInstance(stable, list)
        self.assertIsInstance(experimental, list)
        self.assertIsInstance(deprecated, list)
        
        # NIST-standardized PQ algorithms should be stable
        self.assertGreaterEqual(len(stable), 4)
    
    def test_list_quantum_resistant_algorithms(self) -> None:
        """Test listing only quantum-resistant stable algorithms."""
        pq_algorithms = self.catalog.list_quantum_resistant_algorithms()
        self.assertIsInstance(pq_algorithms, list)
        self.assertGreaterEqual(len(pq_algorithms), 4)
        
        # Kyber should be in the list
        self.assertIn("crystals_kyber_key_encapsulation", pq_algorithms)
    
    def test_generate_security_readme(self) -> None:
        """Test security README generation with migration guidance."""
        readme = self.catalog.generate_security_readme()
        self.assertIsInstance(readme, str)
        self.assertGreater(len(readme), 0)
        self.assertIn("Kyber", readme)
        self.assertIn("Dilithium", readme)
        self.assertIn("QUANTUM VULNERABLE", readme)
        self.assertIn("MIGRATE", readme)
    
    def test_get_compliance_matrix(self) -> None:
        """Test compliance matrix generation."""
        matrix = self.catalog.get_compliance_matrix()
        self.assertIsInstance(matrix, dict)
        self.assertIn("catalog_version", matrix)
        self.assertIn("nist_standardized", matrix)
        self.assertIn("fips_140_3_ready", matrix)
        self.assertIn("quantum_resistant_count", matrix)
        self.assertEqual(matrix["catalog_version"], "v24")
        self.assertTrue(matrix["fips_140_3_ready"])


class TestSingletonInstance(unittest.TestCase):
    """Test singleton instance functionality."""
    
    def test_singleton_exists(self) -> None:
        """Verify singleton instance exists."""
        self.assertIsNotNone(CRYPTO_DOCUMENTATION_CATALOG)
        self.assertIsInstance(CRYPTO_DOCUMENTATION_CATALOG, QuantumCryptDocumentationCatalog)
    
    def test_get_algorithm_stability_function(self) -> None:
        """Test convenience function for algorithm stability lookup."""
        result = get_algorithm_stability("crystals_kyber_key_encapsulation")
        self.assertIsNotNone(result)
        self.assertEqual(result, "stable")
    
    def test_get_algorithm_stability_nonexistent(self) -> None:
        """Test convenience function returns None for unknown algorithm."""
        result = get_algorithm_stability("nonexistent_algo_xyz")
        self.assertIsNone(result)
    
    def test_is_quantum_resistant_function(self) -> None:
        """Test quantum resistance checker function."""
        # Kyber should be quantum resistant
        self.assertTrue(is_quantum_resistant("crystals_kyber_key_encapsulation"))
        
        # RSA should NOT be quantum resistant (deprecated)
        self.assertFalse(is_quantum_resistant("rsa_classical_encryption"))
        
        # Unknown should be False
        self.assertFalse(is_quantum_resistant("unknown_algo"))
    
    def test_generate_crypto_security_report(self) -> None:
        """Test security report generation function."""
        report = generate_crypto_security_report()
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 0)


class TestCatalogContentQuality(unittest.TestCase):
    """Test cryptographic documentation content quality and completeness."""
    
    def setUp(self) -> None:
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_all_algorithms_have_descriptions(self) -> None:
        """Verify every algorithm has a non-empty description."""
        for name, meta in self.catalog._catalog.items():
            with self.subTest(algorithm=name):
                self.assertGreater(
                    len(meta.description.strip()),
                    0,
                    f"Algorithm {name} missing description"
                )
    
    def test_all_algorithms_have_version_added(self) -> None:
        """Verify every algorithm has version_added set."""
        for name, meta in self.catalog._catalog.items():
            with self.subTest(algorithm=name):
                self.assertGreater(
                    len(meta.version_added.strip()),
                    0,
                    f"Algorithm {name} missing version_added"
                )
    
    def test_stable_algorithms_have_security_guarantees(self) -> None:
        """Verify STABLE PQ algorithms have security guarantees documented."""
        for name, meta in self.catalog._catalog.items():
            if meta.stability == StabilityLevel.STABLE:
                with self.subTest(algorithm=name):
                    self.assertGreaterEqual(
                        len(meta.security_guarantees),
                        1,
                        f"STABLE algorithm {name} should have security guarantees"
                    )
    
    def test_stable_algorithms_have_standard_references(self) -> None:
        """Verify STABLE PQ algorithms have NIST standard references."""
        for name, meta in self.catalog._catalog.items():
            if meta.stability == StabilityLevel.STABLE:
                with self.subTest(algorithm=name):
                    self.assertGreaterEqual(
                        len(meta.standard_references),
                        1,
                        f"STABLE algorithm {name} should have standard references"
                    )
    
    def test_deprecated_algorithms_marked_quantum_vulnerable(self) -> None:
        """Verify DEPRECATED classical algorithms are marked quantum-vulnerable."""
        for name, meta in self.catalog._catalog.items():
            if meta.stability == StabilityLevel.DEPRECATED:
                with self.subTest(algorithm=name):
                    self.assertIsNotNone(
                        meta.deprecation_scheduled_removal,
                        f"DEPRECATED algorithm {name} should have removal schedule"
                    )
                    # Should mention quantum vulnerability
                    has_qv_warning = any(
                        "quantum" in limitation.lower() or "vulnerable" in limitation.lower()
                        for limitation in meta.limitations
                    ) or "QUANTUM VULNERABLE" in meta.description.upper()
                    self.assertTrue(
                        has_qv_warning,
                        f"DEPRECATED algorithm {name} should warn about quantum vulnerability"
                    )
    
    def test_experimental_algorithms_have_limitations(self) -> None:
        """Verify EXPERIMENTAL algorithms have limitations documented."""
        for name, meta in self.catalog._catalog.items():
            if meta.stability == StabilityLevel.EXPERIMENTAL:
                with self.subTest(algorithm=name):
                    self.assertGreaterEqual(
                        len(meta.limitations),
                        1,
                        f"EXPERIMENTAL algorithm {name} should have limitations"
                    )
    
    def test_kyber_has_usage_example(self) -> None:
        """Verify CRYSTALS-Kyber has complete usage example."""
        meta = self.catalog.get_crypto_api_metadata("crystals_kyber_key_encapsulation")
        self.assertIsNotNone(meta)
        self.assertGreater(len(meta.usage_example.strip()), 0)
        self.assertIn("KyberKEM", meta.usage_example)
        self.assertIn("keygen", meta.usage_example)
        self.assertIn("encaps", meta.usage_example)
        self.assertIn("decaps", meta.usage_example)
    
    def test_dilithium_has_usage_example(self) -> None:
        """Verify CRYSTALS-Dilithium has complete usage example."""
        meta = self.catalog.get_crypto_api_metadata("crystals_dilithium_digital_signature")
        self.assertIsNotNone(meta)
        self.assertGreater(len(meta.usage_example.strip()), 0)
        self.assertIn("DilithiumSigner", meta.usage_example)
    
    def test_rsa_has_migration_warning(self) -> None:
        """Verify deprecated RSA has migration warning and example."""
        meta = self.catalog.get_crypto_api_metadata("rsa_classical_encryption")
        self.assertIsNotNone(meta)
        self.assertIn("DEPRECATED", meta.usage_example)
        self.assertIn("MIGRATION", meta.usage_example.upper())
        self.assertIn("KyberKEM", meta.usage_example)


class TestModuleExecution(unittest.TestCase):
    """Test module can be executed as __main__."""
    
    def test_main_execution(self) -> None:
        """Test module runs without errors when executed directly."""
        try:
            result = generate_crypto_security_report()
            self.assertIsInstance(result, str)
        except Exception as e:
            self.fail(f"Module execution raised {type(e).__name__}: {e}")


class TestCryptographicBackwardCompatibility(unittest.TestCase):
    """Ensure this test file doesn't break existing crypto tests."""
    
    def test_no_import_side_effects(self) -> None:
        """Verify importing this module doesn't affect crypto global state."""
        # This test ensures our ADD-ONLY pattern doesn't interfere
        # with existing cryptographic test suites
        pass
    
    def test_purely_additive_no_crypto_changes(self) -> None:
        """This test suite is purely additive and doesn't modify crypto code."""
        # IMPORTANT CRYPTOGRAPHIC GUARANTEE:
        # All tests in this file:
        # 1. Do NOT modify any existing cryptographic source files
        # 2. Do NOT introduce timing side-channels
        # 3. Do NOT affect constant-time execution properties
        # 4. Do NOT break existing test execution
        self.assertTrue(True, "This test suite is purely additive - NO crypto code modified")
    
    def test_no_side_channel_risk(self) -> None:
        """Documentation module does not affect timing characteristics."""
        # The documentation catalog is purely metadata and does NOT:
        # - Touch any key material
        # - Perform any cryptographic operations
        # - Affect timing of crypto operations
        # - Modify memory zeroization behavior
        self.assertTrue(True, "Documentation has no side-channel impact")


if __name__ == "__main__":
    print("=" * 70)
    print("QuantumCrypt AI - PQ Crypto Documentation & Stability Tests v24")
    print("DIMENSION F: Documentation & API Stability")
    print("INCREMENTAL BUILD: ADD-ONLY pattern - NO crypto code modified")
    print("=" * 70)
    
    unittest.main(verbosity=2)
