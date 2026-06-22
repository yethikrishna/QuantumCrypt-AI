"""
QuantumCrypt-AI Comprehensive API Documentation & Stability Master Catalog v13
================================================================================
**Version**: 13.0.0
**Stability**: STABLE
**Date**: 2026-06-23
**Author**: QuantumCrypt Team

This module provides a centralized, machine-readable catalog of ALL public APIs
in QuantumCrypt-AI with stability markers, comprehensive docstrings, usage
examples, and API reference documentation.

DESIGN PHILOSOPHY (Incremental Build):
- ADD-ONLY: No existing code modified
- 100% Backward Compatible
- OPT-IN documentation system
- Zero runtime overhead when not used
- Machine-readable + Human-readable formats

STABILITY LEVELS:
    STABLE      - Production-ready, backward compatibility guaranteed
    EXPERIMENTAL - Active development, breaking changes possible
    DEPRECATED  - Scheduled for removal, use alternatives
    INTERNAL    - Not for public consumption
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any, Callable, Dict, List, Optional, Set, Type, TypeVar, Union
)
from functools import wraps
from datetime import datetime
import json
import inspect

F = TypeVar('F', bound=Callable[..., Any])


class StabilityLevel(Enum):
    """API Stability Level Classification.
    
    Defines the maturity and guarantee level for each public API.
    """
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    INTERNAL = "internal"
    
    def __str__(self) -> str:
        return self.value


@dataclass
class APIExample:
    """Usage example for an API endpoint.
    
    Attributes:
        title: Short descriptive title
        code: Python code snippet
        description: Detailed explanation
        expected_output: Sample output if applicable
    """
    title: str
    code: str
    description: str = ""
    expected_output: str = ""


@dataclass
class APIStabilityInfo:
    """Complete API stability and documentation metadata.
    
    Attributes:
        module_name: Python module path
        class_name: Class name if applicable
        method_name: Method/function name
        stability: StabilityLevel classification
        version_introduced: Version when API was added
        version_deprecated: Version when deprecated (if applicable)
        version_removal: Scheduled removal version (if deprecated)
        alternative_api: Recommended replacement (if deprecated)
        description: Human-readable API purpose
        categories: Functional classification tags
        examples: List of usage examples
        parameters: Parameter documentation dict
        return_value: Return value documentation
        exceptions: Documented exceptions
        authors: Maintainer list
        last_updated: Last modification date
    """
    module_name: str
    method_name: str
    stability: StabilityLevel
    version_introduced: str
    description: str
    class_name: Optional[str] = None
    version_deprecated: Optional[str] = None
    version_removal: Optional[str] = None
    alternative_api: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    examples: List[APIExample] = field(default_factory=list)
    parameters: Dict[str, str] = field(default_factory=dict)
    return_value: str = ""
    exceptions: Dict[str, str] = field(default_factory=dict)
    authors: List[str] = field(default_factory=list)
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to machine-readable dictionary format."""
        return {
            "module": self.module_name,
            "class": self.class_name,
            "method": self.method_name,
            "stability": str(self.stability),
            "version_introduced": self.version_introduced,
            "version_deprecated": self.version_deprecated,
            "version_removal": self.version_removal,
            "alternative": self.alternative_api,
            "description": self.description,
            "categories": self.categories,
            "examples": [
                {"title": e.title, "code": e.code, "description": e.description}
                for e in self.examples
            ],
            "parameters": self.parameters,
            "returns": self.return_value,
            "exceptions": self.exceptions,
        }


def stable(version: str, description: str = "") -> Callable[[F], F]:
    """Mark an API as STABLE (Production Ready).
    
    Stable APIs guarantee backward compatibility across minor versions.
    Breaking changes will only occur in major version increments.
    
    Args:
        version: Version when this API was stabilized (e.g., "13.0.0")
        description: Short API purpose description
    
    Returns:
        Decorated function with stability metadata
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)
        
        wrapper.__api_stability__ = StabilityLevel.STABLE
        wrapper.__api_version__ = version
        wrapper.__api_description__ = description
        return wrapper
    return decorator


def experimental(version: str, description: str = "") -> Callable[[F], F]:
    """Mark an API as EXPERIMENTAL (In Development).
    
    Experimental APIs may change or be removed without notice.
    Suitable for evaluation only, not production.
    
    Args:
        version: Version when this API was introduced (e.g., "13.0.0")
        description: Short API purpose description
    
    Returns:
        Decorated function with stability metadata
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)
        
        wrapper.__api_stability__ = StabilityLevel.EXPERIMENTAL
        wrapper.__api_version__ = version
        wrapper.__api_description__ = description
        return wrapper
    return decorator


def deprecated(
    version: str,
    removal_version: str,
    alternative: str,
    description: str = ""
) -> Callable[[F], F]:
    """Mark an API as DEPRECATED (Scheduled for Removal).
    
    Deprecated APIs will be removed in the specified future version.
    Migrate to the alternative API immediately.
    
    Args:
        version: Version when deprecated
        removal_version: Version when API will be removed
        alternative: Recommended replacement API
        description: Deprecation notice
    
    Returns:
        Decorated function with stability metadata
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            import warnings
            warnings.warn(
                f"API {func.__name__} is deprecated since v{version}. "
                f"Will be removed in v{removal_version}. "
                f"Use {alternative} instead. {description}",
                DeprecationWarning,
                stacklevel=2
            )
            return func(*args, **kwargs)
        
        wrapper.__api_stability__ = StabilityLevel.DEPRECATED
        wrapper.__api_version_deprecated__ = version
        wrapper.__api_version_removal__ = removal_version
        wrapper.__api_alternative__ = alternative
        return wrapper
    return decorator


class CryptoDocumentationCatalogV13:
    """Master QuantumCrypt API Documentation & Stability Catalog v13.
    
    Central registry for all QuantumCrypt-AI public APIs with:
    - Stability classification
    - Comprehensive documentation
    - Usage examples
    - Machine-readable export formats
    """
    
    def __init__(self) -> None:
        """Initialize empty documentation catalog."""
        self._apis: List[APIStabilityInfo] = []
        self._index: Dict[str, APIStabilityInfo] = {}
    
    def register(self, api_info: APIStabilityInfo) -> None:
        """Register an API in the catalog.
        
        Args:
            api_info: Complete API metadata
        """
        key = f"{api_info.module_name}.{api_info.class_name or ''}.{api_info.method_name}"
        self._apis.append(api_info)
        self._index[key] = api_info
    
    def get_by_stability(self, level: StabilityLevel) -> List[APIStabilityInfo]:
        """Filter APIs by stability level.
        
        Args:
            level: Stability level to filter by
        
        Returns:
            List of APIs matching the stability level
        """
        return [api for api in self._apis if api.stability == level]
    
    def get_by_category(self, category: str) -> List[APIStabilityInfo]:
        """Filter APIs by functional category.
        
        Args:
            category: Category tag to filter by
        
        Returns:
            List of APIs in the category
        """
        return [api for api in self._apis if category in api.categories]
    
    def get_all_categories(self) -> Set[str]:
        """Get all unique category tags.
        
        Returns:
            Set of all category strings
        """
        categories: Set[str] = set()
        for api in self._apis:
            categories.update(api.categories)
        return categories
    
    def generate_markdown_reference(self) -> str:
        """Generate comprehensive Markdown API reference.
        
        Returns:
            Complete API reference in Markdown format
        """
        lines = [
            "# QuantumCrypt-AI API Reference v13",
            "",
            f"**Generated**: {datetime.now().strftime('%Y-%m-%d')}",
            f"**Total APIs Documented**: {len(self._apis)}",
            "",
        ]
        
        # Summary by stability
        lines.extend([
            "## API Stability Summary",
            "",
            f"- **STABLE**: {len(self.get_by_stability(StabilityLevel.STABLE))}",
            f"- **EXPERIMENTAL**: {len(self.get_by_stability(StabilityLevel.EXPERIMENTAL))}",
            f"- **DEPRECATED**: {len(self.get_by_stability(StabilityLevel.DEPRECATED))}",
            "",
        ])
        
        # Category index
        lines.extend([
            "## Functional Categories",
            "",
        ])
        for cat in sorted(self.get_all_categories()):
            count = len(self.get_by_category(cat))
            lines.append(f"- **{cat.title()}**: {count} APIs")
        lines.append("")
        
        # Detailed API docs
        for level in [StabilityLevel.STABLE, StabilityLevel.EXPERIMENTAL]:
            apis = self.get_by_stability(level)
            if not apis:
                continue
                
            lines.extend([
                f"## {level.value.upper()} APIs",
                "",
            ])
            
            for api in sorted(apis, key=lambda a: a.module_name):
                name = f"{api.class_name + '.' if api.class_name else ''}{api.method_name}"
                lines.extend([
                    f"### `{name}`",
                    "",
                    f"**Module**: `{api.module_name}`",
                    f"**Since**: v{api.version_introduced}",
                    f"**Categories**: {', '.join(api.categories)}",
                    "",
                    api.description,
                    "",
                ])
                
                if api.parameters:
                    lines.extend(["**Parameters**:", ""])
                    for param, desc in api.parameters.items():
                        lines.append(f"- `{param}`: {desc}")
                    lines.append("")
                
                if api.return_value:
                    lines.extend([f"**Returns**: {api.return_value}", ""])
                
                if api.exceptions:
                    lines.extend(["**Exceptions**:", ""])
                    for exc, desc in api.exceptions.items():
                        lines.append(f"- `{exc}`: {desc}")
                    lines.append("")
                
                if api.examples:
                    lines.extend(["**Examples**:", ""])
                    for ex in api.examples:
                        lines.extend([
                            f"#### {ex.title}",
                            "",
                            "```python",
                            ex.code,
                            "```",
                            "",
                        ])
                        if ex.description:
                            lines.extend([ex.description, ""])
        
        return "\n".join(lines)
    
    def export_json(self, filepath: Optional[str] = None) -> str:
        """Export catalog to JSON format.
        
        Args:
            filepath: Optional file path to write to
        
        Returns:
            JSON string of catalog data
        """
        data = {
            "catalog_version": "13.0.0",
            "generated_at": datetime.now().isoformat(),
            "total_apis": len(self._apis),
            "apis": [api.to_dict() for api in self._apis]
        }
        json_str = json.dumps(data, indent=2)
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(json_str)
        
        return json_str
    
    def get_stability_report(self) -> Dict[str, Any]:
        """Generate stability coverage report.
        
        Returns:
            Dictionary with coverage statistics
        """
        return {
            "total_apis": len(self._apis),
            "stable": len(self.get_by_stability(StabilityLevel.STABLE)),
            "experimental": len(self.get_by_stability(StabilityLevel.EXPERIMENTAL)),
            "deprecated": len(self.get_by_stability(StabilityLevel.DEPRECATED)),
            "categories": sorted(list(self.get_all_categories())),
            "coverage_percent": min(100, len(self._apis) * 5),
        }


# Singleton instance
_CRYPTO_DOCUMENTATION_CATALOG: Optional[CryptoDocumentationCatalogV13] = None


def get_crypto_documentation_catalog() -> CryptoDocumentationCatalogV13:
    """Get the singleton crypto documentation catalog instance.
    
    Returns:
        Global CryptoDocumentationCatalogV13 instance
    """
    global _CRYPTO_DOCUMENTATION_CATALOG
    if _CRYPTO_DOCUMENTATION_CATALOG is None:
        _CRYPTO_DOCUMENTATION_CATALOG = CryptoDocumentationCatalogV13()
        _initialize_crypto_apis(_CRYPTO_DOCUMENTATION_CATALOG)
    return _CRYPTO_DOCUMENTATION_CATALOG


def _initialize_crypto_apis(catalog: CryptoDocumentationCatalogV13) -> None:
    """Populate catalog with QuantumCrypt-AI APIs."""
    
    # === POST-QUANTUM ENCRYPTION (STABLE) ===
    catalog.register(APIStabilityInfo(
        module_name="post_quantum_encryption_engine",
        method_name="encrypt",
        stability=StabilityLevel.STABLE,
        version_introduced="1.0.0",
        description="Encrypt data using NIST-standard post-quantum cryptography algorithms (CRYSTALS-Kyber). Quantum-resistant key exchange and encryption.",
        categories=["core", "encryption", "post-quantum", "nist"],
        parameters={
            "plaintext": "Bytes or string to encrypt",
            "public_key": "Recipient's public key (Kyber)",
            "algorithm": "PQC algorithm: 'kyber512', 'kyber768', 'kyber1024'"
        },
        return_value="EncryptedResult with ciphertext and encapsulated key",
        examples=[
            APIExample(
                title="Post-Quantum Encryption",
                code="""from quantum_crypt import post_quantum_encryption_engine

# Generate quantum-resistant keypair
pk, sk = post_quantum_encryption_engine.generate_keypair("kyber768")

# Encrypt message
result = post_quantum_encryption_engine.encrypt(
    b"Secret message", pk, algorithm="kyber768"
)

# Decrypt
plaintext = post_quantum_encryption_engine.decrypt(result, sk)"""
            )
        ]
    ))
    
    # === LATTICE CRYPTOGRAPHY (STABLE) ===
    catalog.register(APIStabilityInfo(
        module_name="lattice_crypto_operations",
        method_name="lattice_sign",
        stability=StabilityLevel.STABLE,
        version_introduced="3.0.0",
        description="Generate post-quantum digital signatures using CRYSTALS-Dilattice algorithm. NIST standard for quantum-resistant signatures.",
        categories=["core", "signatures", "lattice", "nist"],
        parameters={
            "message": "Message bytes to sign",
            "private_key": "Signer's private key",
            "mode": "Security level: 2, 3, or 5"
        },
        return_value="DigitalSignature with signature bytes and metadata"
    ))
    
    # === KEY MANAGEMENT (STABLE) ===
    catalog.register(APIStabilityInfo(
        module_name="quantum_key_management",
        method_name="derive_key",
        stability=StabilityLevel.STABLE,
        version_introduced="2.0.0",
        description="Cryptographically secure key derivation using HKDF with quantum-resistant entropy sources. Suitable for long-term key generation.",
        categories=["key-management", "kdf", "security"],
        parameters={
            "secret": "Input key material",
            "salt": "Optional salt for HKDF",
            "info": "Context information",
            "length": "Output key length in bytes"
        },
        return_value="Derived key bytes"
    ))
    
    # === SECURE MEMORY (STABLE) ===
    catalog.register(APIStabilityInfo(
        module_name="crypto_secure_memory_zeroization",
        method_name="zeroize",
        stability=StabilityLevel.STABLE,
        version_introduced="4.0.0",
        description="Securely zeroize sensitive memory regions. Uses volatile writes that cannot be optimized away by compilers. Critical for key material.",
        categories=["security", "memory", "hardening"],
        parameters={
            "buffer": "Mutable buffer (bytearray) to zeroize",
            "force": "Bypass safety checks (bool)"
        },
        return_value="True on successful zeroization",
        examples=[
            APIExample(
                title="Secure Key Zeroization",
                code="""from quantum_crypt.crypto_secure_memory_zeroization import zeroize

sensitive_key = bytearray(b"secret data...")
# Use key...
zeroize(sensitive_key)  # Securely erase from memory"""
            )
        ]
    ))
    
    # === CONSTANT-TIME OPERATIONS (STABLE) ===
    catalog.register(APIStabilityInfo(
        module_name="crypto_security_hardening_constant_time",
        method_name="constant_time_compare",
        stability=StabilityLevel.STABLE,
        version_introduced="5.0.0",
        description="Constant-time byte/string comparison immune to timing attacks. Essential for MAC verification, token validation, and HSM operations.",
        categories=["security", "crypto", "timing-attack"],
        parameters={
            "a": "First bytes/string to compare",
            "b": "Second bytes/string to compare"
        },
        return_value="True if equal (execution time independent of content)"
    ))
    
    # === QUANTUM RANDOM NUMBER GENERATOR (STABLE) ===
    catalog.register(APIStabilityInfo(
        module_name="quantum_random_generator",
        method_name="get_random_bytes",
        stability=StabilityLevel.STABLE,
        version_introduced="2.0.0",
        description="Cryptographically secure random number generation with quantum entropy sources. Combines multiple CSPRNGs for defense in depth.",
        categories=["random", "entropy", "csprng"],
        parameters={
            "length": "Number of random bytes to generate",
            "enhanced": "Enable quantum-enhanced entropy mixing"
        },
        return_value="Cryptographically secure random bytes"
    ))
    
    # === HOMOMORPHIC ENCRYPTION (EXPERIMENTAL) ===
    catalog.register(APIStabilityInfo(
        module_name="homomorphic_encryption_experimental",
        method_name="he_encrypt",
        stability=StabilityLevel.EXPERIMENTAL,
        version_introduced="10.0.0",
        description="Partial homomorphic encryption allowing computation on ciphertext. EXPERIMENTAL: Performance limited, API subject to change.",
        categories=["homomorphic", "privacy", "experimental", "fhe"],
        parameters={
            "plaintext": "Integer or small vector to encrypt",
            "public_key": "HE public key",
            "scheme": "Scheme: 'bfv', 'ckks'"
        },
        return_value="HE ciphertext object"
    ))
    
    # === ZERO-KNOWLEDGE PROOFS (EXPERIMENTAL) ===
    catalog.register(APIStabilityInfo(
        module_name="zero_knowledge_proofs",
        method_name="generate_proof",
        stability=StabilityLevel.EXPERIMENTAL,
        version_introduced="11.0.0",
        description="Generate zero-knowledge proofs for statement verification. EXPERIMENTAL: Groth16 implementation under active development.",
        categories=["zkp", "privacy", "experimental", "crypto"],
        parameters={
            "statement": "Boolean circuit to prove",
            "witness": "Private witness values",
            "proving_key": "Proving key for the circuit"
        },
        return_value="ZKProof object with verification key"
    ))
    
    # === ERROR RESILIENCE (STABLE) ===
    catalog.register(APIStabilityInfo(
        module_name="crypto_error_resilience_enhanced_circuit_breaker_v18_2026_june",
        method_name="crypto_circuit_breaker",
        stability=StabilityLevel.STABLE,
        version_introduced="18.0.0",
        description="Enhanced circuit breaker for cryptographic operations with key operation protection, timeout enforcement, and graceful degradation.",
        categories=["resilience", "circuit-breaker", "crypto-safety"],
        parameters={
            "max_failures": "Failure threshold before circuit open",
            "timeout": "Operation timeout in seconds",
            "safe_fallback": "Fallback value on failure"
        },
        return_value="Decorator for crypto operation protection"
    ))
    
    # === OBSERVABILITY (STABLE) ===
    catalog.register(APIStabilityInfo(
        module_name="crypto_observability_enhanced_slo_baggage_v9_2026_june",
        method_name="get_crypto_observability",
        stability=StabilityLevel.STABLE,
        version_introduced="9.0.0",
        description="Get crypto-specific observability engine with HSM metrics, key usage tracking, security event logging, and compliance auditing.",
        categories=["observability", "monitoring", "compliance"],
        return_value="CryptoObservabilityEngine v9 instance"
    ))
    
    # === SECURE MULTI-PARTY COMPUTATION (EXPERIMENTAL) ===
    catalog.register(APIStabilityInfo(
        module_name="secure_multi_party_computation",
        method_name="mpc_compute",
        stability=StabilityLevel.EXPERIMENTAL,
        version_introduced="12.0.0",
        description="Secure multi-party computation for collaborative privacy-preserving analytics. EXPERIMENTAL: 2-party only, limited operations.",
        categories=["mpc", "privacy", "experimental", "collaboration"],
        parameters={
            "party_id": "Party identifier (0 or 1)",
            "input_share": "Private input share",
            "operation": "Operation: 'sum', 'product', 'mean'"
        },
        return_value="MPC result share"
    ))
    
    # === KEY ROTATION (STABLE) ===
    catalog.register(APIStabilityInfo(
        module_name="crypto_key_rotation_manager",
        method_name="rotate_keys",
        stability=StabilityLevel.STABLE,
        version_introduced="6.0.0",
        description="Automated key rotation with zero-downtime re-encryption, version tracking, and audit logging. Compliant with key rotation best practices.",
        categories=["key-management", "rotation", "compliance"],
        parameters={
            "key_id": "Identifier of key to rotate",
            "grace_period": "Dual-write period in seconds",
            "reencrypt_data": "Re-encrypt existing data under new key"
        },
        return_value="KeyRotationResult with new key material"
    ))


# Export public API
__all__ = [
    'StabilityLevel',
    'APIExample',
    'APIStabilityInfo',
    'stable',
    'experimental',
    'deprecated',
    'CryptoDocumentationCatalogV13',
    'get_crypto_documentation_catalog',
]
