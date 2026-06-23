"""
Test Suite for Key Management Documentation Module (Dimension F)
ADD-ONLY: New test file, no modifications to existing code
Tests verify documentation module works without breaking anything
"""

import sys
import pytest
from typing import Dict, List

# Import the new documentation module
from quantum_crypt.comprehensive_key_management_documentation_v14_2026_june import (
    KeyManagementDocumentationManager,
    DocumentationCategory,
    APIMaturity,
    KEY_MANAGEMENT_API_STABILITY,
    GETTING_STARTED_GUIDE,
    API_REFERENCE,
    USAGE_EXAMPLES,
    BEST_PRACTICES,
    SECURITY_CONSIDERATIONS,
    TROUBLESHOOTING,
)


class TestKeyManagementDocumentation:
    """Test documentation module functionality"""
    
    def test_documentation_manager_initialization(self):
        """Test manager initializes correctly"""
        doc_manager = KeyManagementDocumentationManager()
        assert doc_manager is not None
        assert doc_manager._module_version == "v13"
        assert doc_manager._module_name == "quantum_key_management_rotation"
    
    def test_stability_catalog_exists(self):
        """Test stability catalog is populated"""
        doc_manager = KeyManagementDocumentationManager()
        assert len(doc_manager.stability_catalog) > 0
        assert "QuantumKeyManagementManager" in doc_manager.stability_catalog
    
    def test_list_stable_apis(self):
        """Test stable APIs listing"""
        doc_manager = KeyManagementDocumentationManager()
        stable = doc_manager.list_stable_apis()
        assert isinstance(stable, list)
        assert len(stable) > 0
        assert "QuantumKeyManagementManager" in stable
    
    def test_list_experimental_apis(self):
        """Test experimental APIs listing"""
        doc_manager = KeyManagementDocumentationManager()
        experimental = doc_manager.list_experimental_apis()
        assert isinstance(experimental, list)
        assert "SecureKeyStore" in experimental
    
    def test_get_stability(self):
        """Test getting stability info"""
        doc_manager = KeyManagementDocumentationManager()
        stability = doc_manager.get_stability("QuantumKeyManagementManager")
        assert stability is not None
        assert stability["stability"] == "stable"
        assert stability["version"] == "v13"
    
    def test_get_stability_nonexistent(self):
        """Test getting stability for non-existent API"""
        doc_manager = KeyManagementDocumentationManager()
        stability = doc_manager.get_stability("NonExistentAPI")
        assert stability is None
    
    def test_get_documentation_getting_started(self):
        """Test getting getting started guide"""
        doc_manager = KeyManagementDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.GETTING_STARTED)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "GETTING STARTED" in doc
    
    def test_get_documentation_api_reference(self):
        """Test getting API reference"""
        doc_manager = KeyManagementDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.API_REFERENCE)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "API REFERENCE" in doc
    
    def test_get_documentation_usage_examples(self):
        """Test getting usage examples"""
        doc_manager = KeyManagementDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.USAGE_EXAMPLES)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "EXAMPLE" in doc
    
    def test_get_documentation_best_practices(self):
        """Test getting best practices"""
        doc_manager = KeyManagementDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.BEST_PRACTICES)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "BEST PRACTICES" in doc
    
    def test_get_documentation_security_considerations(self):
        """Test getting security considerations"""
        doc_manager = KeyManagementDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.SECURITY_CONSIDERATIONS)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "SECURITY CONSIDERATIONS" in doc
    
    def test_get_documentation_troubleshooting(self):
        """Test getting troubleshooting guide"""
        doc_manager = KeyManagementDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.TROUBLESHOOTING)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "TROUBLESHOOTING" in doc
    
    def test_get_all_categories(self):
        """Test listing all documentation categories"""
        doc_manager = KeyManagementDocumentationManager()
        categories = doc_manager.get_all_categories()
        assert isinstance(categories, list)
        assert len(categories) == 6
        assert "getting_started" in categories
        assert "security_considerations" in categories
    
    def test_get_module_info(self):
        """Test getting module info"""
        doc_manager = KeyManagementDocumentationManager()
        info = doc_manager.get_module_info()
        assert isinstance(info, dict)
        assert info["module"] == "quantum_key_management_rotation"
        assert info["version"] == "v13"
        assert info["dimension"] == "F - Documentation & API Stability"
        assert info["backward_compatible"] == True
        assert info["add_only"] == True
        assert "security_warning" in info
    
    def test_documentation_strings_not_empty(self):
        """Test all documentation strings are non-empty"""
        assert len(GETTING_STARTED_GUIDE) > 100
        assert len(API_REFERENCE) > 100
        assert len(USAGE_EXAMPLES) > 100
        assert len(BEST_PRACTICES) > 100
        assert len(SECURITY_CONSIDERATIONS) > 100
        assert len(TROUBLESHOOTING) > 100
    
    def test_api_stability_markers(self):
        """Test all API stability markers"""
        for api_name, marker in KEY_MANAGEMENT_API_STABILITY.items():
            assert marker.stability in [APIMaturity.STABLE, APIMaturity.EXPERIMENTAL]
            assert marker.version == "v13"
            assert len(marker.notes) > 0
    
    def test_no_breaking_changes(self):
        """Verify no existing code was modified - ADD-ONLY philosophy"""
        # Verify we can still import the original module
        from quantum_crypt.quantum_key_management_rotation_v13_2026_june import (
            QuantumKeyManagementManager,
            KeyStatus,
            KeyAlgorithm,
            KeyPurpose,
        )
        # Original module should still work
        km = QuantumKeyManagementManager()
        assert km is not None
        
        # Run basic operation
        key_id = km.create_encryption_key(rotation_days=30)
        assert key_id is not None
        assert isinstance(key_id, str)
        
        # Get key material
        key_material = km.key_store.get_key_material(key_id)
        assert key_material is not None
        assert len(key_material) == 32


if __name__ == "__main__":
    # Run tests
    test = TestKeyManagementDocumentation()
    
    print("Running Key Management Documentation Tests...")
    print("=" * 60)
    
    tests_passed = 0
    tests_failed = 0
    
    test_methods = [m for m in dir(test) if m.startswith("test_")]
    
    for method_name in test_methods:
        try:
            getattr(test, method_name)()
            print(f"✓ {method_name}")
            tests_passed += 1
        except Exception as e:
            print(f"✗ {method_name}: {e}")
            tests_failed += 1
    
    print("=" * 60)
    print(f"Passed: {tests_passed}, Failed: {tests_failed}")
    print(f"Total: {tests_passed + tests_failed}")
    
    if tests_failed == 0:
        print("\nALL TESTS PASSED - Dimension F Documentation complete!")
    else:
        print(f"\n{tests_failed} TESTS FAILED")
        sys.exit(1)
