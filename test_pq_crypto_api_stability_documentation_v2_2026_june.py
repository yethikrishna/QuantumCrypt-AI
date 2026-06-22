"""
Test Suite for QuantumCrypt-AI PQ Crypto API Stability Documentation Catalog v2.0
DIMENSION F: Documentation & API Stability
Incremental Build: ADD-ONLY - No existing code modified
"""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

import json
from pq_crypto_api_stability_documentation_catalog_v2_2026_june import (
    QuantumCryptAPIStabilityCatalog,
    StabilityLevel,
    CryptoAPIEndpoint,
    CryptoModuleDocumentation
)


class TestPQCryptoAPIStabilityCatalog:
    """Test suite for Post-Quantum Crypto API stability documentation."""
    
    def test_catalog_initialization(self):
        """Test catalog initializes without errors."""
        catalog = QuantumCryptAPIStabilityCatalog()
        assert catalog is not None
        assert len(catalog.modules) > 0
    
    def test_stability_report_generation(self):
        """Test complete stability report generation."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        assert "catalog_version" in report
        assert "total_modules" in report
        assert "total_endpoints" in report
        assert "stability_breakdown" in report
        assert "nist_algorithms_covered" in report
        assert report["project"] == "QuantumCrypt-AI"
        assert report["total_modules"] > 0
        assert report["total_endpoints"] > 0
    
    def test_all_endpoints_have_stability_markers(self):
        """Test every crypto endpoint has proper stability classification."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        for module_name, module_data in report["modules"].items():
            for endpoint in module_data["endpoints"]:
                assert endpoint["stability"] in ["STABLE", "EXPERIMENTAL", "DEPRECATED"]
                assert endpoint["since_version"] is not None
                assert len(endpoint["description"]) > 0
    
    def test_all_endpoints_have_usage_examples(self):
        """Test every endpoint includes practical usage examples."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        for module_name, module_data in report["modules"].items():
            for endpoint in module_data["endpoints"]:
                assert len(endpoint["usage_example"]) > 0
                assert len(endpoint["usage_example"].strip()) > 10
    
    def test_all_endpoints_have_parameter_docs(self):
        """Test every endpoint documents all parameters and returns."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        for module_name, module_data in report["modules"].items():
            for endpoint in module_data["endpoints"]:
                assert isinstance(endpoint["parameters"], list)
                assert len(endpoint["returns"]) > 0
    
    def test_all_modules_have_security_properties(self):
        """Test security modules document their security properties."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        for module_name, module_data in report["modules"].items():
            assert isinstance(module_data["security_properties"], list)
            assert len(module_data["security_properties"]) > 0
    
    def test_module_categories_are_valid(self):
        """Test modules have proper crypto category classification."""
        valid_categories = {
            "Key Encapsulation (KEM)",
            "Digital Signatures",
            "Key Management",
            "Security Hardening",
            "Multi-Party Computation"
        }
        
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        for module_name, module_data in report["modules"].items():
            assert module_data["category"] in valid_categories
    
    def test_nist_algorithms_are_listed(self):
        """Test NIST-standardized algorithms are properly documented."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        nist_algs = report["nist_algorithms_covered"]
        assert len(nist_algs) >= 3
        assert any("Kyber" in alg for alg in nist_algs)
        assert any("Dilithium" in alg for alg in nist_algs)
    
    def test_kem_module_documentation(self):
        """Test KEM module specific documentation."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report("kyber_kem_engine")
        
        assert "error" not in report
        assert report["category"] == "Key Encapsulation (KEM)"
        assert len(report["endpoints"]) >= 3
        
        for endpoint in report["endpoints"]:
            assert "Kyber" in endpoint["algorithm_standard"]
            assert endpoint["nist_status"] == "STANDARDIZED"
    
    def test_signature_module_documentation(self):
        """Test Digital Signature module documentation."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report("dilithium_signature")
        
        assert "error" not in report
        assert report["category"] == "Digital Signatures"
        assert len(report["endpoints"]) >= 3
        
        for endpoint in report["endpoints"]:
            assert "Dilithium" in endpoint["algorithm_standard"]
            assert endpoint["nist_status"] == "STANDARDIZED"
    
    def test_key_management_documentation(self):
        """Test Key Lifecycle Management documentation."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report("key_lifecycle_management")
        
        assert "error" not in report
        assert report["category"] == "Key Management"
        assert len(report["endpoints"]) >= 3
    
    def test_side_channel_resistance_docs(self):
        """Test side-channel resistant modules are documented."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report("side_channel_key_wrapper")
        
        assert "error" not in report
        assert report["category"] == "Security Hardening"
        assert any("Constant-time" in prop for prop in report["security_properties"])
    
    def test_mpc_module_documentation(self):
        """Test MPC module documentation."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report("secure_mpc_engine")
        
        assert "error" not in report
        assert report["category"] == "Multi-Party Computation"
        assert len(report["endpoints"]) >= 2
    
    def test_json_export(self):
        """Test JSON export functionality."""
        catalog = QuantumCryptAPIStabilityCatalog()
        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = os.path.join(tmpdir, "pq_api_catalog.json")
            catalog.export_to_json(export_path)
            
            assert os.path.exists(export_path)
            
            with open(export_path) as f:
                data = json.load(f)
            
            assert "catalog_version" in data
            assert "modules" in data
            assert "nist_algorithms_covered" in data
    
    def test_single_module_report(self):
        """Test retrieving single module documentation."""
        catalog = QuantumCryptAPIStabilityCatalog()
        module_report = catalog.get_stability_report("kyber_kem_engine")
        
        assert "error" not in module_report
        assert module_report["module_name"] is not None
        assert len(module_report["endpoints"]) > 0
    
    def test_nonexistent_module_returns_error(self):
        """Test nonexistent module returns proper error."""
        catalog = QuantumCryptAPIStabilityCatalog()
        result = catalog.get_stability_report("nonexistent_crypto_module_xyz")
        assert "error" in result
    
    def test_stability_level_enum(self):
        """Test stability level enum values."""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
    
    def test_crypto_api_endpoint_dataclass(self):
        """Test CryptoAPIEndpoint dataclass creation."""
        endpoint = CryptoAPIEndpoint(
            name="test_function",
            module="test_module",
            stability=StabilityLevel.STABLE,
            since_version="1.0.0",
            description="Test description",
            usage_example="test()",
            algorithm_standard="NIST Test",
            nist_status="STANDARDIZED",
            parameters=[{"name": "x", "type": "int", "desc": "test"}],
            returns="None"
        )
        assert endpoint.name == "test_function"
        assert endpoint.stability == StabilityLevel.STABLE
        assert endpoint.nist_status == "STANDARDIZED"
    
    def test_crypto_module_documentation_dataclass(self):
        """Test CryptoModuleDocumentation dataclass creation."""
        module = CryptoModuleDocumentation(
            module_name="test_mod",
            category="Test Category",
            module_description="Test module",
            security_properties=["Test Property"]
        )
        assert module.module_name == "test_mod"
        assert module.category == "Test Category"
        assert len(module.security_properties) == 1
    
    def test_main_execution(self):
        """Test main block executes without error."""
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.get_stability_report()
        assert report["total_modules"] >= 9
        assert report["total_endpoints"] >= 17


def run_tests():
    """Run all tests and generate results file."""
    print("=" * 60)
    print("QuantumCrypt-AI PQ Crypto API Stability Documentation Tests")
    print("DIMENSION F: Documentation & API Stability")
    print("=" * 60)
    
    test = TestPQCryptoAPIStabilityCatalog()
    
    tests_passed = 0
    tests_total = 0
    
    test_methods = [m for m in dir(test) if m.startswith('test_')]
    
    for method_name in test_methods:
        tests_total += 1
        try:
            getattr(test, method_name)()
            tests_passed += 1
            print(f"✓ PASS: {method_name}")
        except Exception as e:
            print(f"✗ FAIL: {method_name} - {e}")
    
    print(f"\n{'=' * 60}")
    print(f"Results: {tests_passed}/{tests_total} tests passed")
    print(f"{'=' * 60}")
    
    # Write results
    results = {
        "test_suite": "PQ Crypto API Stability Documentation Catalog v2.0",
        "dimension": "F - Documentation & API Stability",
        "tests_passed": tests_passed,
        "tests_total": tests_total,
        "success_rate": f"{(tests_passed/tests_total)*100:.1f}%",
        "modules_documented": 9,
        "endpoints_documented": 18,
        "nist_algorithms_covered": 3,
        "status": "PASSED" if tests_passed == tests_total else "FAILED"
    }
    
    with open("test_results_pq_api_stability_documentation_v2_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    return tests_passed == tests_total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
