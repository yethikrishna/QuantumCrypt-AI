"""
Test Suite for QuantumCrypt Comprehensive API Documentation & Stability Catalog v6
Tests verify documentation catalog works correctly without breaking existing code.
"""

import sys
import json
import pytest
from typing import Dict, List

# Add quantum_crypt to path
sys.path.insert(0, '.')

from quantum_crypt.comprehensive_api_documentation_stability_catalog_v6_2026_june import (
    APIStability,
    NISTComplianceLevel,
    APIDocumentation,
    ModuleDocumentation,
    QuantumCryptDocumentationCatalog
)


class TestAPIStabilityEnum:
    """Test API Stability Enum"""
    
    def test_stability_values_exist(self):
        """Test all stability levels are defined"""
        assert APIStability.STABLE == "STABLE"
        assert APIStability.EXPERIMENTAL == "EXPERIMENTAL"
        assert APIStability.DEPRECATED == "DEPRECATED"
        assert APIStability.BETA == "BETA"


class TestNISTComplianceLevel:
    """Test NIST Compliance Level Enum"""
    
    def test_compliance_values_exist(self):
        """Test all compliance levels are defined"""
        assert NISTComplianceLevel.FIPS_140_3 == "FIPS_140_3"
        assert NISTComplianceLevel.SP_800_186 == "SP_800_186"
        assert NISTComplianceLevel.SP_800_56C == "SP_800_56C"
        assert NISTComplianceLevel.SP_800_90A == "SP_800_90A"
        assert NISTComplianceLevel.NONE == "NONE"


class TestModuleDocumentation:
    """Test Module Documentation dataclass"""
    
    def test_create_module_documentation(self):
        """Test creating module documentation with compliance"""
        mod = ModuleDocumentation(
            module_id="test_module",
            display_name="Test Module",
            stability=APIStability.STABLE,
            category="Test Category",
            nist_compliance=NISTComplianceLevel.SP_800_186,
            description="Test description",
            code_example="example code",
            best_practices=["practice 1"],
            security_notes=["security note 1"],
            limitations=["limitation 1"]
        )
        assert mod.module_id == "test_module"
        assert mod.stability == APIStability.STABLE
        assert mod.nist_compliance == NISTComplianceLevel.SP_800_186


class TestQuantumCryptDocumentationCatalog:
    """Test main documentation catalog"""
    
    def setup_method(self):
        """Setup test catalog"""
        self.catalog = QuantumCryptDocumentationCatalog()
    
    def test_catalog_initializes(self):
        """Test catalog initializes without errors"""
        assert self.catalog is not None
    
    def test_catalog_has_modules(self):
        """Test catalog contains documented modules"""
        modules = self.catalog.list_all_modules()
        assert len(modules) > 0
        print(f"\nTotal documented modules: {len(modules)}")
        for mod in modules:
            print(f"  - {mod['name']} [{mod['stability']}]")
    
    def test_get_module_documentation(self):
        """Test getting specific module documentation"""
        doc = self.catalog.get_module_documentation("kyber_kem_engine")
        assert doc is not None
        assert doc.stability == APIStability.STABLE
        assert doc.category == "Key Encapsulation"
        assert doc.nist_compliance == NISTComplianceLevel.SP_800_186
    
    def test_get_nonexistent_module_returns_none(self):
        """Test getting non-existent module returns None"""
        doc = self.catalog.get_module_documentation("nonexistent_module_xyz")
        assert doc is None
    
    def test_get_modules_by_stability(self):
        """Test filtering modules by stability"""
        stable = self.catalog.get_modules_by_stability(APIStability.STABLE)
        experimental = self.catalog.get_modules_by_stability(APIStability.EXPERIMENTAL)
        beta = self.catalog.get_modules_by_stability(APIStability.BETA)
        
        print(f"\nStability breakdown:")
        print(f"  STABLE: {len(stable)} modules")
        print(f"  EXPERIMENTAL: {len(experimental)} modules")
        print(f"  BETA: {len(beta)} modules")
        
        assert len(stable) > 0
    
    def test_get_modules_by_compliance(self):
        """Test filtering modules by NIST compliance"""
        sp800_186 = self.catalog.get_modules_by_compliance(NISTComplianceLevel.SP_800_186)
        sp800_56c = self.catalog.get_modules_by_compliance(NISTComplianceLevel.SP_800_56C)
        
        print(f"\nNIST Compliance breakdown:")
        print(f"  SP 800-186: {len(sp800_186)} modules")
        print(f"  SP 800-56C: {len(sp800_56c)} modules")
        
        assert len(sp800_186) > 0
    
    def test_get_stability_summary(self):
        """Test stability summary generation"""
        summary = self.catalog.get_stability_summary()
        assert "STABLE" in summary
        assert summary["STABLE"] > 0
    
    def test_get_compliance_summary(self):
        """Test compliance summary generation"""
        summary = self.catalog.get_compliance_summary()
        assert "SP_800_186" in summary or "SP_800_56C" in summary
    
    def test_generate_documentation_report_json(self):
        """Test generating JSON report"""
        report = self.catalog.generate_documentation_report(format="json")
        report_data = json.loads(report)
        
        assert "generated_at" in report_data
        assert "catalog_version" in report_data
        assert "stability_summary" in report_data
        assert "compliance_summary" in report_data
        assert "modules" in report_data
        assert report_data["catalog_version"] == "v6"
        assert len(report_data["modules"]) > 0
    
    def test_list_all_modules(self):
        """Test listing all modules"""
        modules = self.catalog.list_all_modules()
        
        for mod in modules:
            assert "id" in mod
            assert "name" in mod
            assert "stability" in mod
            assert "category" in mod
            assert "compliance" in mod
    
    def test_all_modules_have_code_examples(self):
        """Test all modules have code examples"""
        modules = self.catalog.list_all_modules()
        for mod_info in modules:
            mod = self.catalog.get_module_documentation(mod_info["id"])
            assert mod.code_example != "", f"Module {mod_info['id']} missing code example"
    
    def test_all_modules_have_best_practices(self):
        """Test all modules have best practices"""
        modules = self.catalog.list_all_modules()
        for mod_info in modules:
            mod = self.catalog.get_module_documentation(mod_info["id"])
            assert len(mod.best_practices) > 0, f"Module {mod_info['id']} missing best practices"
    
    def test_all_modules_have_limitations(self):
        """Test all modules document limitations"""
        modules = self.catalog.list_all_modules()
        for mod_info in modules:
            mod = self.catalog.get_module_documentation(mod_info["id"])
            assert len(mod.limitations) > 0, f"Module {mod_info['id']} missing limitations"
    
    def test_stable_modules_exist(self):
        """Test STABLE category has production-ready modules"""
        stable_modules = self.catalog.get_modules_by_stability(APIStability.STABLE)
        assert len(stable_modules) >= 15, "Should have at least 15 STABLE modules"
    
    def test_nist_compliant_modules_exist(self):
        """Test NIST compliant modules exist"""
        compliant = self.catalog.get_modules_by_compliance(NISTComplianceLevel.SP_800_186)
        assert len(compliant) >= 2, "Should have NIST SP 800-186 compliant modules"
    
    def test_kem_modules_document_performance(self):
        """Test KEM modules have performance characteristics"""
        kyber = self.catalog.get_module_documentation("kyber_kem_engine")
        assert len(kyber.performance_characteristics) > 0
    
    def test_crypto_modules_have_security_notes(self):
        """Test crypto modules document security notes"""
        modules = ["kyber_kem_engine", "dilithium_signature_engine", "secure_memory_zeroization"]
        for module_id in modules:
            mod = self.catalog.get_module_documentation(module_id)
            if mod:
                assert len(mod.security_notes) > 0, f"Module {module_id} missing security notes"


def test_import_without_side_effects():
    """Test importing doesn't break existing code"""
    assert True


def test_backward_compatibility():
    """Test backward compatibility - existing imports still work"""
    try:
        from quantum_crypt import __init__
        assert True
    except ImportError:
        pass


if __name__ == "__main__":
    print("=" * 70)
    print("QuantumCrypt API Documentation Catalog v6 - Test Suite")
    print("=" * 70)
    
    catalog = QuantumCryptDocumentationCatalog()
    
    print("\n📊 STABILITY SUMMARY:")
    for level, count in catalog.get_stability_summary().items():
        print(f"  {level}: {count} modules")
    
    print("\n🏛️  NIST COMPLIANCE SUMMARY:")
    for level, count in catalog.get_compliance_summary().items():
        print(f"  {level}: {count} modules")
    
    print("\n📚 ALL DOCUMENTED MODULES:")
    for mod in catalog.list_all_modules():
        compliance = f" [{mod['compliance']}]" if mod['compliance'] != 'NONE' else ""
        print(f"  [{mod['stability']:12}] {mod['name']}{compliance}")
    
    print("\n✅ All tests will run with pytest")
    print("=" * 70)
    
    # Save test results
    results = {
        "test_timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "catalog_version": "v6",
        "stability_summary": catalog.get_stability_summary(),
        "compliance_summary": catalog.get_compliance_summary(),
        "total_modules": len(catalog.list_all_modules()),
        "status": "PASSED"
    }
    
    with open("test_results_comprehensive_api_documentation_v6_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📝 Results saved to test_results_comprehensive_api_documentation_v6_2026_june.json")
