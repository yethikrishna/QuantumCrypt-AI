"""
Test Suite for QuantumCrypt-AI Comprehensive API Stability Catalog v4
June 2026 Release

Tests verify:
- Catalog initialization and crypto module registration
- Stability level queries and filtering
- Security property validation
- Backward compatibility guarantees
- Endpoint documentation integrity
- NIST compliance tracking
"""

import pytest
import json

from quantum_crypt.comprehensive_api_stability_documentation_catalog_v4_2026_june import (
    QuantumCryptAPIStabilityCatalog,
    StabilityLevel,
    SecurityLevel,
    CryptoModule,
    CryptoEndpoint,
    get_stability_report,
    is_module_stable,
    get_all_stable_apis,
    is_nist_standardized,
    CRYPTO_API_CATALOG
)


class TestStabilityLevel:
    """Test StabilityLevel enum"""
    
    def test_stability_level_values(self):
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.BETA.value == "BETA"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"


class TestSecurityLevel:
    """Test SecurityLevel enum"""
    
    def test_security_level_values(self):
        assert SecurityLevel.LEVEL_128.value == "NIST_SECURITY_LEVEL_1"
        assert SecurityLevel.LEVEL_192.value == "NIST_SECURITY_LEVEL_3"
        assert SecurityLevel.LEVEL_256.value == "NIST_SECURITY_LEVEL_5"
        assert SecurityLevel.QUANTUM_RESISTANT.value == "QUANTUM_RESISTANT"


class TestCryptoModule:
    """Test CryptoModule dataclass"""
    
    def test_crypto_module_creation_minimal(self):
        module = CryptoModule(
            name="TestCryptoModule",
            stability=StabilityLevel.STABLE,
            module_path="test.crypto.module",
            description="Test crypto module",
            first_release="2026.6.0",
            last_updated="2026.6.22",
            maintainer="Test Crypto Team",
            security_level=SecurityLevel.LEVEL_256
        )
        assert module.name == "TestCryptoModule"
        assert module.nist_standardized is False  # Default
        assert module.side_channel_resistant is False  # Default
        assert module.constant_time is False  # Default
        assert module.memory_zeroization is False  # Default
    
    def test_crypto_module_with_security_properties(self):
        module = CryptoModule(
            name="FullCryptoModule",
            stability=StabilityLevel.STABLE,
            module_path="full.crypto.module",
            description="Full crypto module with security",
            first_release="2026.5.0",
            last_updated="2026.6.22",
            maintainer="Full Crypto Team",
            security_level=SecurityLevel.LEVEL_256,
            nist_standardized=True,
            side_channel_resistant=True,
            constant_time=True,
            memory_zeroization=True,
            tags=["crypto", "nist", "secure"],
            test_coverage=95.5,
            performance_sla={"ops_per_sec": 1000}
        )
        assert module.nist_standardized is True
        assert module.side_channel_resistant is True
        assert module.constant_time is True
        assert module.memory_zeroization is True
        assert len(module.tags) == 3
        assert module.test_coverage == 95.5


class TestCryptoEndpoint:
    """Test CryptoEndpoint dataclass"""
    
    def test_crypto_endpoint_creation(self):
        endpoint = CryptoEndpoint(
            name="test_crypto_endpoint",
            module="TestCryptoModule",
            signature="test(data: bytes) -> bytes",
            stability=StabilityLevel.STABLE,
            description="Test crypto endpoint",
            parameters=[{"name": "data", "type": "bytes", "required": True}],
            return_type="bytes"
        )
        assert endpoint.name == "test_crypto_endpoint"
        assert endpoint.since_version == "2026.6.0"  # Default


class TestQuantumCryptAPIStabilityCatalog:
    """Test main catalog class"""
    
    def test_catalog_initialization(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        assert catalog.VERSION == "2026.6.22"
        assert catalog.CATALOG_VERSION == "v4"
        assert len(catalog.modules) > 0
        assert len(catalog.endpoints) > 0
    
    def test_catalog_has_core_kem_modules(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        # Verify key KEM modules exist and are STABLE
        core_kem_nist = [
            "PostQuantumHybridKEM",
            "PostQuantumKyberKEMEngine"
        ]
        for module_name in core_kem_nist:
            assert module_name in catalog.modules
            assert catalog.modules[module_name].stability == StabilityLevel.STABLE
            assert catalog.modules[module_name].nist_standardized is True
        
        # HybridPQKeyExchangeForwardSecrecy is STABLE but NOT NIST-standardized
        assert "HybridPQKeyExchangeForwardSecrecy" in catalog.modules
        assert catalog.modules["HybridPQKeyExchangeForwardSecrecy"].stability == StabilityLevel.STABLE
        assert catalog.modules["HybridPQKeyExchangeForwardSecrecy"].nist_standardized is False
    
    def test_catalog_has_core_signature_modules(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        # Verify key signature modules
        core_sig = [
            "PostQuantumDilithiumSignatureEngine",
            "PostQuantumHybridSignatureEngineDilithium"
        ]
        for module_name in core_sig:
            assert module_name in catalog.modules
            assert catalog.modules[module_name].stability == StabilityLevel.STABLE
    
    def test_catalog_has_security_hardening_modules(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        # All security hardening modules should be STABLE
        hardening_modules = [
            "CryptoSecurityHardeningSideChannelResistantV3",
            "CryptoSecurityHardeningComprehensiveV2",
            "PostQuantumSecureMemoryZeroizerSideChannelProtected",
            "PostQuantumSecureMACManagerV32"
        ]
        for module_name in hardening_modules:
            assert module_name in catalog.modules
            assert catalog.modules[module_name].stability == StabilityLevel.STABLE
            assert catalog.modules[module_name].side_channel_resistant is True
            assert catalog.modules[module_name].memory_zeroization is True
    
    def test_get_module_stability(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        # STABLE module
        stability = catalog.get_module_stability("PostQuantumHybridKEM")
        assert stability == StabilityLevel.STABLE
        # BETA module
        stability = catalog.get_module_stability("HybridKEMMultiPartySessionManagerV3")
        assert stability == StabilityLevel.BETA
        # Non-existent module
        stability = catalog.get_module_stability("NonExistentModule")
        assert stability is None
    
    def test_get_stable_modules(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        stable = catalog.get_stable_modules()
        assert len(stable) > 0
        assert "PostQuantumHybridKEM" in stable
        assert "PostQuantumDilithiumSignatureEngine" in stable
        # BETA modules should NOT be in stable list
        assert "HybridKEMMultiPartySessionManagerV3" not in stable
    
    def test_get_beta_modules(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        beta = catalog.get_beta_modules()
        assert len(beta) > 0
        assert "HybridKEMMultiPartySessionManagerV3" in beta
        assert "PostQuantumSecureFileEncryptor" in beta
    
    def test_get_experimental_modules(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        experimental = catalog.get_experimental_modules()
        assert len(experimental) > 0
        assert "PostQuantumSecureStreamCipherEngine" in experimental
    
    def test_get_nist_standardized_modules(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        nist_modules = catalog.get_nist_standardized_modules()
        assert len(nist_modules) > 0
        assert "PostQuantumHybridKEM" in nist_modules
        assert "PostQuantumKyberKEMEngine" in nist_modules
        assert "PostQuantumDilithiumSignatureEngine" in nist_modules
        assert "SecureKeyDerivationFunction" in nist_modules
    
    def test_get_side_channel_resistant_modules(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        scr_modules = catalog.get_side_channel_resistant_modules()
        assert len(scr_modules) > 0
        # All security hardening modules should be side-channel resistant
        assert "CryptoSecurityHardeningSideChannelResistantV3" in scr_modules
        assert "PostQuantumSecureMemoryZeroizerSideChannelProtected" in scr_modules
    
    def test_generate_stability_report(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        report = catalog.generate_stability_report()
        
        # Verify report structure
        assert "catalog_version" in report
        assert "framework_version" in report
        assert "generated_at" in report
        assert "summary" in report
        assert "security_summary" in report
        assert "average_test_coverage" in report
        
        # Verify summary counts
        summary = report["summary"]
        assert summary["total_modules"] == (
            summary["stable"] + summary["beta"] + 
            summary["experimental"] + summary["deprecated"]
        )
        
        # Verify security summary
        security = report["security_summary"]
        assert "level_128" in security
        assert "level_192" in security
        assert "level_256" in security
        assert "constant_time" in security
        assert "memory_zeroization" in security
        
        # Most modules should be LEVEL_256 security
        assert security["level_256"] > security["level_128"]
        
        # Test coverage should be high
        assert report["average_test_coverage"] > 85.0
    
    def test_compatibility_matrix(self):
        catalog = QuantumCryptAPIStabilityCatalog()
        matrix = catalog.get_compatibility_matrix()
        
        assert "2026.6.x_compatible" in matrix
        assert "2026.5.x_compatible" in matrix
        assert "breaking_changes_since_2026.5" in matrix
        
        # CRITICAL: No breaking changes - INCREMENTAL PHILOSOPHY
        assert len(matrix["breaking_changes_since_2026.5"]) == 0
    
    def test_all_modules_have_security_level(self):
        """Verify EVERY crypto module has a security level"""
        catalog = QuantumCryptAPIStabilityCatalog()
        
        for name, module in catalog.modules.items():
            assert module.security_level is not None, \
                f"Module {name} missing security_level"
            # All modules should be at least LEVEL_128
            assert module.security_level in [
                SecurityLevel.LEVEL_128,
                SecurityLevel.LEVEL_192,
                SecurityLevel.LEVEL_256,
                SecurityLevel.QUANTUM_RESISTANT
            ]
    
    def test_stable_modules_have_performance_sla(self):
        """Verify all STABLE crypto modules have performance SLAs"""
        catalog = QuantumCryptAPIStabilityCatalog()
        
        for name, module in catalog.modules.items():
            if module.stability == StabilityLevel.STABLE:
                assert module.performance_sla is not None, \
                    f"STABLE module {name} missing performance SLA"
    
    def test_crypto_modules_metadata_integrity(self):
        """Verify all crypto modules have complete metadata"""
        catalog = QuantumCryptAPIStabilityCatalog()
        
        for name, module in catalog.modules.items():
            # Required fields must not be empty
            assert module.name, f"Module {name} missing name"
            assert module.module_path, f"Module {name} missing path"
            assert module.description, f"Module {name} missing description"
            assert module.first_release, f"Module {name} missing first_release"
            assert module.last_updated, f"Module {name} missing last_updated"
            assert module.maintainer, f"Module {name} missing maintainer"
            
            # Test coverage must be realistic
            assert module.test_coverage >= 70.0, \
                f"Module {name} test coverage too low: {module.test_coverage}"
            assert module.test_coverage <= 100.0
    
    def test_crypto_endpoints_integrity(self):
        """Verify all crypto endpoints have complete documentation"""
        catalog = QuantumCryptAPIStabilityCatalog()
        
        for name, endpoint in catalog.endpoints.items():
            assert endpoint.name, f"Endpoint {name} missing name"
            assert endpoint.module, f"Endpoint {name} missing module"
            assert endpoint.signature, f"Endpoint {name} missing signature"
            assert endpoint.description, f"Endpoint {name} missing description"
            assert endpoint.return_type, f"Endpoint {name} missing return_type"
            # The module referenced must exist
            assert endpoint.module in catalog.modules, \
                f"Endpoint {name} references non-existent module {endpoint.module}"


class TestConvenienceFunctions:
    """Test module-level convenience functions"""
    
    def test_get_stability_report(self):
        report = get_stability_report()
        assert report is not None
        assert "summary" in report
        assert "security_summary" in report
    
    def test_is_module_stable(self):
        assert is_module_stable("PostQuantumHybridKEM") is True
        assert is_module_stable("HybridKEMMultiPartySessionManagerV3") is False
        assert is_module_stable("NonExistent") is False
    
    def test_get_all_stable_apis(self):
        stable = get_all_stable_apis()
        assert len(stable) > 0
        assert "PostQuantumHybridKEM" in stable
    
    def test_is_nist_standardized(self):
        assert is_nist_standardized("PostQuantumHybridKEM") is True
        assert is_nist_standardized("PostQuantumSecureMPCEngineV36") is False
        assert is_nist_standardized("NonExistent") is False


class TestIncrementalBuildPhilosophy:
    """CRITICAL: Verify incremental build philosophy is maintained"""
    
    def test_no_deprecated_modules_yet(self):
        """No crypto modules should be deprecated yet - we only add, not remove"""
        catalog = QuantumCryptAPIStabilityCatalog()
        deprecated = [m for m in catalog.modules.values() 
                     if m.stability == StabilityLevel.DEPRECATED]
        assert len(deprecated) == 0, "No deprecations yet - ADD-ONLY philosophy"
    
    def test_all_2026_5_modules_still_present(self):
        """All modules from 2026.5.x must still exist"""
        catalog = QuantumCryptAPIStabilityCatalog()
        # Core modules from May 2026 must still exist and be STABLE
        may_2026_core = [
            "PostQuantumHybridKEM",
            "PostQuantumKyberKEMEngine",
            "PostQuantumDilithiumSignatureEngine",
            "PostQuantumHybridSignatureEngineDilithium",
            "SecureKeyDerivationFunction",
            "PostQuantumSecureMemoryZeroizerSideChannelProtected",
            "ShamirSecretSharingThreshold"
        ]
        for module_name in may_2026_core:
            assert module_name in catalog.modules, \
                f"Backward compatibility broken: {module_name} removed"
            assert catalog.modules[module_name].stability == StabilityLevel.STABLE, \
                f"Module {module_name} stability downgraded"
    
    def test_memory_zeroization_on_sensitive_modules(self):
        """All key-handling modules must have memory zeroization"""
        catalog = QuantumCryptAPIStabilityCatalog()
        sensitive_modules = [
            "PostQuantumHybridKEM",
            "PostQuantumKyberKEMEngine",
            "PostQuantumDilithiumSignatureEngine",
            "SecureKeyDerivationFunction",
            "PostQuantumSecureMemoryZeroizerSideChannelProtected"
        ]
        for module_name in sensitive_modules:
            module = catalog.modules[module_name]
            assert module.memory_zeroization is True, \
                f"Sensitive module {module_name} missing memory zeroization"


class TestReportSerialization:
    """Test report can be serialized for API responses"""
    
    def test_report_json_serializable(self):
        report = get_stability_report()
        # Should serialize without errors
        json_str = json.dumps(report, indent=2)
        assert json_str is not None
        assert len(json_str) > 0
    
    def test_security_summary_serializable(self):
        report = get_stability_report()
        security = report["security_summary"]
        # Security summary should serialize
        json_str = json.dumps(security)
        parsed = json.loads(json_str)
        assert parsed == security


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
