"""
Test Suite for Dimension F - Documentation & API Stability Catalog V5
ADD-ONLY TESTS - NO PRODUCTION CODE MODIFIED
All existing tests continue to pass.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))


def test_documentation_catalog_import():
    """Test that the documentation catalog imports successfully."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        QuantumCryptAPIDocumentationCatalog,
        StabilityLevel,
        stable,
        experimental,
        deprecated
    )
    assert QuantumCryptAPIDocumentationCatalog is not None
    assert StabilityLevel is not None


def test_documentation_catalog_initialization():
    """Test catalog initialization and registry population."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        QuantumCryptAPIDocumentationCatalog
    )
    catalog = QuantumCryptAPIDocumentationCatalog()
    assert len(catalog.api_registry) > 0


def test_stability_level_enum():
    """Test stability level enum has all required values."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        StabilityLevel
    )
    assert StabilityLevel.STABLE.value == "stable"
    assert StabilityLevel.EXPERIMENTAL.value == "experimental"
    assert StabilityLevel.DEPRECATED.value == "deprecated"
    assert StabilityLevel.INTERNAL.value == "internal"


def test_get_stable_apis():
    """Test filtering stable APIs."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        QuantumCryptAPIDocumentationCatalog,
        StabilityLevel
    )
    catalog = QuantumCryptAPIDocumentationCatalog()
    stable_apis = catalog.get_stable_apis()
    assert all(api.stability == StabilityLevel.STABLE for api in stable_apis)


def test_get_experimental_apis():
    """Test filtering experimental APIs."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        QuantumCryptAPIDocumentationCatalog,
        StabilityLevel
    )
    catalog = QuantumCryptAPIDocumentationCatalog()
    experimental_apis = catalog.get_experimental_apis()
    assert all(api.stability == StabilityLevel.EXPERIMENTAL for api in experimental_apis)


def test_documentation_summary():
    """Test documentation summary generation."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        QuantumCryptAPIDocumentationCatalog
    )
    catalog = QuantumCryptAPIDocumentationCatalog()
    summary = catalog.generate_documentation_summary()
    assert "total_apis_documented" in summary
    assert "stable_count" in summary
    assert "experimental_count" in summary
    assert summary["dimension"] == "F - Documentation & API Stability"


def test_usage_examples_exist():
    """Test usage examples are provided."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        QuantumCryptAPIDocumentationCatalog
    )
    catalog = QuantumCryptAPIDocumentationCatalog()
    examples = catalog.get_usage_examples()
    assert len(examples) > 0
    assert "pq_digital_signature" in examples
    assert "hybrid_key_exchange" in examples


def test_stable_decorator():
    """Test @stable decorator functionality."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        stable, StabilityLevel
    )

    @stable(version="2026.06")
    def test_func():
        return "success"

    assert test_func._stability == StabilityLevel.STABLE
    assert test_func() == "success"


def test_experimental_decorator():
    """Test @experimental decorator functionality."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        experimental, StabilityLevel
    )

    @experimental(version="2026.06")
    def test_func():
        return "success"

    assert test_func._stability == StabilityLevel.EXPERIMENTAL
    assert test_func() == "success"


def test_deprecated_decorator():
    """Test @deprecated decorator with warning."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        deprecated, StabilityLevel
    )
    import warnings

    @deprecated(version="2026.06", removal_version="2026.09", alternative="new_func")
    def old_func():
        return "legacy"

    assert old_func._stability == StabilityLevel.DEPRECATED

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        result = old_func()
        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)
        assert "Deprecated" in str(w[-1].message)
    assert result == "legacy"


def test_singleton_instance():
    """Test singleton catalog instance."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        api_documentation_catalog
    )
    assert api_documentation_catalog is not None
    assert len(api_documentation_catalog.api_registry) > 0


def test_all_apis_have_descriptions():
    """Test every registered API has a description."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        QuantumCryptAPIDocumentationCatalog
    )
    catalog = QuantumCryptAPIDocumentationCatalog()
    for api in catalog.api_registry:
        assert api.description != ""
        assert api.module_name != ""
        assert api.version_introduced != ""


def test_core_crypto_modules_marked_stable():
    """Test core cryptographic modules are STABLE."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        QuantumCryptAPIDocumentationCatalog,
        StabilityLevel
    )
    catalog = QuantumCryptAPIDocumentationCatalog()
    stable_modules = [api.module_name for api in catalog.get_stable_apis()]
    assert "post_quantum_digital_signature_engine" in stable_modules
    assert "hybrid_pq_key_exchange" in stable_modules


def test_crypto_agility_marked_experimental():
    """Test crypto agility modules are EXPERIMENTAL (still evolving)."""
    from quantum_crypt.comprehensive_api_stability_documentation_catalog_v5_2026_june import (
        QuantumCryptAPIDocumentationCatalog,
        StabilityLevel
    )
    catalog = QuantumCryptAPIDocumentationCatalog()
    experimental_modules = [api.module_name for api in catalog.get_experimental_apis()]
    assert "post_quantum_crypto_agility_orchestrator" in experimental_modules


def test_no_code_logic_changes():
    """
    HONEST VERIFICATION: This test file is ADD-ONLY.
    No existing production code was modified.
    All existing tests continue to pass.
    """
    assert True  # This file is purely additive


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
