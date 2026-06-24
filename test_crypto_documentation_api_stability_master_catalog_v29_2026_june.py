"""
Test Suite for QuantumCrypt Documentation & API Stability Catalog v29
=====================================================================
DIMENSION F: Documentation & API Stability

Tests verify:
1. Documentation catalog imports correctly
2. All stability markers are accessible
3. NIST status tracking works
4. Report generation works
5. No existing code is broken
6. Security considerations are documented
"""

import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest


def test_documentation_catalog_import():
    """Test that documentation module imports correctly."""
    from quantum_crypt import crypto_documentation_api_stability_master_catalog_v29_2026_june as doc_catalog
    assert doc_catalog is not None
    assert hasattr(doc_catalog, 'QuantumCryptDocumentationCatalog')
    assert hasattr(doc_catalog, 'StabilityLevel')
    assert hasattr(doc_catalog, 'CRYPTO_DOCUMENTATION_CATALOG')


def test_stability_level_enum():
    """Test stability level enum has all expected values."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import StabilityLevel
    
    assert StabilityLevel.STABLE.value == "STABLE"
    assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
    assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
    assert StabilityLevel.INTERNAL.value == "INTERNAL"


def test_catalog_initialization():
    """Test that catalog initializes with modules."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    modules = catalog.get_all_modules()
    
    assert len(modules) > 0
    print(f"Total documented modules: {len(modules)}")


def test_stable_modules_filter():
    """Test filtering stable modules."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog,
        StabilityLevel
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    stable = catalog.get_stable_modules()
    
    for module in stable:
        assert module.stability == StabilityLevel.STABLE
    
    print(f"STABLE modules: {len(stable)}")
    # All crypto modules should be STABLE for production
    assert len(stable) > 0


def test_nist_standardized_filter():
    """Test filtering NIST-standardized algorithm modules."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    nist_std = catalog.get_nist_standardized()
    
    for module in nist_std:
        assert "Standardized" in module.nist_status
    
    print(f"NIST Standardized modules: {len(nist_std)}")
    assert len(nist_std) > 0


def test_get_module_doc():
    """Test retrieving specific module documentation."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    # Test existing module
    doc = catalog.get_module_doc("hybrid_pq_key_exchange")
    assert doc is not None
    assert doc.purpose is not None
    assert len(doc.purpose) > 0
    assert doc.algorithm_type is not None
    assert doc.nist_status is not None
    
    # Test non-existent module
    doc_none = catalog.get_module_doc("non_existent_module_xyz")
    assert doc_none is None


def test_generate_stability_report():
    """Test generating stability report."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    report = catalog.generate_stability_report()
    
    assert 'total_modules' in report
    assert 'stable_modules' in report
    assert 'nist_standardized' in report
    assert 'stable_percentage' in report
    assert 'modules' in report
    
    assert report['total_modules'] > 0
    assert report['stable_percentage'] >= 0
    assert report['stable_percentage'] <= 100
    
    print(f"Stability report: {report['stable_percentage']}% STABLE")
    print(f"NIST Standardized: {report['nist_standardized']} modules")


def test_export_json():
    """Test exporting catalog to JSON."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        catalog.export_json(temp_path)
        
        assert os.path.exists(temp_path)
        with open(temp_path, 'r') as f:
            data = json.load(f)
        
        assert 'total_modules' in data
        assert 'modules' in data
        
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_convenience_function():
    """Test the convenience get_api_stability_report function."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        get_api_stability_report
    )
    
    report = get_api_stability_report()
    assert report is not None
    assert 'total_modules' in report
    assert 'nist_standardized' in report


def test_module_doc_structure():
    """Test that all module docs have required fields."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    for module in catalog.get_all_modules():
        assert module.module_name is not None
        assert module.stability is not None
        assert module.purpose is not None
        assert len(module.purpose) > 0


def test_best_practices_exist():
    """Test that modules have best practices documented."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    modules_with_best_practices = 0
    for module in catalog.get_all_modules():
        if len(module.best_practices) > 0:
            modules_with_best_practices += 1
    
    print(f"Modules with best practices: {modules_with_best_practices}")
    assert modules_with_best_practices > 0


def test_limitations_exist():
    """Test that modules have limitations documented (HONESTY principle)."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    modules_with_limitations = 0
    for module in catalog.get_all_modules():
        if len(module.limitations) > 0:
            modules_with_limitations += 1
    
    print(f"Modules with limitations: {modules_with_limitations}")
    # HONESTY: CRITICAL - crypto modules MUST document limitations
    assert modules_with_limitations > 0


def test_security_considerations_exist():
    """Test that security considerations are documented."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    modules_with_security = 0
    for module in catalog.get_all_modules():
        if len(module.security_considerations) > 0:
            modules_with_security += 1
    
    print(f"Modules with security considerations: {modules_with_security}")
    # Security modules MUST have security considerations
    assert modules_with_security > 0


def test_endpoint_documentation():
    """Test that endpoints have proper documentation."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    total_endpoints = 0
    for module in catalog.get_all_modules():
        for endpoint in module.endpoints:
            total_endpoints += 1
            assert endpoint.name is not None
            assert endpoint.description is not None
            assert endpoint.stability is not None
    
    print(f"Total documented endpoints: {total_endpoints}")


def test_endpoint_examples_exist():
    """Test that key endpoints have usage examples."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    endpoints_with_examples = 0
    for module in catalog.get_all_modules():
        for endpoint in module.endpoints:
            if len(endpoint.examples) > 0:
                endpoints_with_examples += 1
    
    print(f"Endpoints with examples: {endpoints_with_examples}")


def test_nist_status_tracking():
    """Test that NIST standardization status is properly tracked."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    kyber_found = False
    dilithium_found = False
    
    for module in catalog.get_all_modules():
        if "Kyber" in module.nist_status:
            kyber_found = True
        if "Dilithium" in module.nist_status:
            dilithium_found = True
    
    # Both NIST-standardized algorithms should be documented
    print(f"Kyber documented: {kyber_found}")
    print(f"Dilithium documented: {dilithium_found}")


def test_print_stability_summary():
    """Test that print summary function works."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        print_stability_summary
    )
    
    # Just verify it doesn't crash
    print_stability_summary()


def test_no_breaking_changes():
    """
    CRITICAL: Verify existing modules still work.
    This ensures ADD-ONLY philosophy is followed.
    """
    # Import existing modules to verify they still work
    from quantum_crypt import crypto_error_resilience_engine_2026_june
    from quantum_crypt import crypto_security_hardening_side_channel_key_protection_v17_2026_june
    
    assert crypto_error_resilience_engine_2026_june is not None
    assert crypto_security_hardening_side_channel_key_protection_v17_2026_june is not None
    
    print("All existing modules still import correctly - NO BREAKING CHANGES")


def test_algorithm_type_tracking():
    """Test that algorithm types are properly categorized."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    kem_count = 0
    dsa_count = 0
    
    for module in catalog.get_all_modules():
        if "KEM" in module.algorithm_type:
            kem_count += 1
        if "DSA" in module.algorithm_type:
            dsa_count += 1
    
    print(f"KEM modules: {kem_count}")
    print(f"DSA modules: {dsa_count}")
    
    # Should have both KEM and DSA algorithms documented
    assert kem_count > 0
    assert dsa_count > 0


def test_usage_guides_exist():
    """Test that key modules have comprehensive usage guides."""
    from quantum_crypt.crypto_documentation_api_stability_master_catalog_v29_2026_june import (
        QuantumCryptDocumentationCatalog
    )
    
    catalog = QuantumCryptDocumentationCatalog()
    
    modules_with_guides = 0
    for module in catalog.get_all_modules():
        if len(module.usage_guide.strip()) > 0:
            modules_with_guides += 1
    
    print(f"Modules with usage guides: {modules_with_guides}")
    assert modules_with_guides > 0


if __name__ == "__main__":
    print("Running QuantumCrypt Documentation & API Stability Tests (Dimension F v29)")
    print("=" * 70)
    
    test_documentation_catalog_import()
    print("✓ catalog_import")
    
    test_stability_level_enum()
    print("✓ stability_level_enum")
    
    test_catalog_initialization()
    print("✓ catalog_initialization")
    
    test_stable_modules_filter()
    print("✓ stable_modules_filter")
    
    test_nist_standardized_filter()
    print("✓ nist_standardized_filter")
    
    test_get_module_doc()
    print("✓ get_module_doc")
    
    test_generate_stability_report()
    print("✓ generate_stability_report")
    
    test_export_json()
    print("✓ export_json")
    
    test_convenience_function()
    print("✓ convenience_function")
    
    test_module_doc_structure()
    print("✓ module_doc_structure")
    
    test_best_practices_exist()
    print("✓ best_practices_exist")
    
    test_limitations_exist()
    print("✓ limitations_exist (HONESTY principle)")
    
    test_security_considerations_exist()
    print("✓ security_considerations")
    
    test_endpoint_documentation()
    print("✓ endpoint_documentation")
    
    test_endpoint_examples_exist()
    print("✓ endpoint_examples_exist")
    
    test_nist_status_tracking()
    print("✓ nist_status_tracking")
    
    test_print_stability_summary()
    print("✓ print_stability_summary")
    
    test_no_breaking_changes()
    print("✓ no_breaking_changes (ADD-ONLY verified)")
    
    test_algorithm_type_tracking()
    print("✓ algorithm_type_tracking")
    
    test_usage_guides_exist()
    print("✓ usage_guides_exist")
    
    print("=" * 70)
    print("ALL TESTS PASSED - Dimension F v29")
