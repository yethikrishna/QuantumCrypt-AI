"""
QuantumCrypt-AI Comprehensive API Documentation & Stability Catalog v27
=======================================================================
DIMENSION F: Documentation & API Stability

API STABILITY MARKERS:
- @stable: Production-ready, backward compatible, no breaking changes planned
- @experimental: Under active development, API may change
- @deprecated: Scheduled for removal, use alternative APIs

This module provides:
1. Comprehensive docstring catalog for all public APIs
2. API stability level markers
3. Usage examples and best practices
4. Migration guides for deprecated APIs
5. No production code logic changes - documentation ONLY
"""

import enum
import typing
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union


class StabilityLevel(enum.Enum):
    """API stability level classification."""
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    INTERNAL = "internal"


@dataclass
class APIDocumentation:
    """Documentation metadata for a single API endpoint."""
    module_name: str
    function_name: str
    stability: StabilityLevel
    signature: str
    docstring: str
    examples: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    version_introduced: str = "1.0.0"


@dataclass
class ModuleDocumentation:
    """Complete documentation for an entire module."""
    module_name: str
    description: str
    apis: List[APIDocumentation] = field(default_factory=list)
    usage_examples: List[str] = field(default_factory=list)
    best_practices: List[str] = field(default_factory=list)


class QuantumCryptDocumentationCatalog:
    """
    Comprehensive API documentation and stability catalog for QuantumCrypt-AI.
    
    @stable: Production-ready, fully tested, backward compatible
    """
    
    def __init__(self) -> None:
        """Initialize the documentation catalog."""
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._stability_counts: Dict[StabilityLevel, int] = {
            StabilityLevel.STABLE: 0,
            StabilityLevel.EXPERIMENTAL: 0,
            StabilityLevel.DEPRECATED: 0,
            StabilityLevel.INTERNAL: 0,
        }
        self._build_catalog()
    
    def _build_catalog(self) -> None:
        """Build the complete documentation catalog."""
        # Core Cryptographic Modules
        self._add_post_quantum_crypto()
        self._add_key_management()
        self._add_encryption_modules()
        self._add_security_hardening()
        self._add_error_resilience()
        self._add_audit_modules()
    
    def _add_post_quantum_crypto(self) -> None:
        """Add post-quantum cryptography module documentation."""
        module = ModuleDocumentation(
            module_name="post_quantum_crypto_engine",
            description="Post-quantum cryptographic primitives resistant to quantum computing attacks including CRYSTALS-Kyber and NIST-standardized algorithms.",
            best_practices=[
                "Use CRYSTALS-Kyber for key exchange in production",
                "Combine with classical algorithms for hybrid security",
                "Validate all key material before use",
                "Follow NIST SP 800-186 guidelines"
            ],
            usage_examples=[
                """
                pq_engine = PostQuantumCryptoEngine()
                public_key, secret_key = pq_engine.generate_keypair()
                ciphertext, shared_secret = pq_engine.encapsulate(public_key)
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="post_quantum_crypto_engine",
                function_name="PostQuantumCryptoEngine.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, algorithm: str = 'kyber768')",
                docstring="Initialize post-quantum crypto engine with specified algorithm.",
                examples=["engine = PostQuantumCryptoEngine(algorithm='kyber1024')"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="post_quantum_crypto_engine",
                function_name="PostQuantumCryptoEngine.generate_keypair",
                stability=StabilityLevel.STABLE,
                signature="generate_keypair(self) -> Tuple[bytes, bytes]",
                docstring="Generate post-quantum key pair (public, secret).",
                examples=["pk, sk = engine.generate_keypair()"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="post_quantum_crypto_engine",
                function_name="PostQuantumCryptoEngine.encapsulate",
                stability=StabilityLevel.STABLE,
                signature="encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]",
                docstring="KEM encapsulation - generate ciphertext and shared secret.",
                examples=["ct, ss = engine.encapsulate(public_key)"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="post_quantum_crypto_engine",
                function_name="PostQuantumCryptoEngine.decapsulate",
                stability=StabilityLevel.STABLE,
                signature="decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes",
                docstring="KEM decapsulation - recover shared secret.",
                examples=["shared_secret = engine.decapsulate(ciphertext, secret_key)"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="post_quantum_crypto_engine",
                function_name="PostQuantumCryptoEngine.get_supported_algorithms",
                stability=StabilityLevel.STABLE,
                signature="get_supported_algorithms(self) -> List[str]",
                docstring="List all supported post-quantum algorithms.",
                examples=["algos = engine.get_supported_algorithms()"],
                version_introduced="1.1.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _add_key_management(self) -> None:
        """Add key management module documentation."""
        module = ModuleDocumentation(
            module_name="key_management_system",
            description="Secure key management including key derivation, rotation, and hardware security module integration.",
            best_practices=[
                "Rotate keys regularly per security policy",
                "Use HKDF for key derivation",
                "Store keys in secure enclaves when possible",
                "Implement key backup and recovery procedures"
            ],
            usage_examples=[
                """
                kms = KeyManagementSystem()
                master_key = kms.generate_master_key()
                derived_key = kms.derive_key(master_key, context='encryption')
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="key_management_system",
                function_name="KeyManagementSystem.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, hsm_backed: bool = False)",
                docstring="Initialize key management system.",
                examples=["kms = KeyManagementSystem(hsm_backed=True)"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="key_management_system",
                function_name="KeyManagementSystem.generate_master_key",
                stability=StabilityLevel.STABLE,
                signature="generate_master_key(self) -> bytes",
                docstring="Generate cryptographically secure master key.",
                examples=["master_key = kms.generate_master_key()"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="key_management_system",
                function_name="KeyManagementSystem.derive_key",
                stability=StabilityLevel.STABLE,
                signature="derive_key(self, master: bytes, context: str, length: int = 32) -> bytes",
                docstring="Derive subkey using HKDF with context binding.",
                examples=["key = kms.derive_key(master, 'tls-session-001')"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="key_management_system",
                function_name="KeyManagementSystem.rotate_key",
                stability=StabilityLevel.STABLE,
                signature="rotate_key(self, old_key: bytes) -> Tuple[bytes, bytes]",
                docstring="Perform key rotation returning new key and transition token.",
                examples=["new_key, token = kms.rotate_key(old_key)"],
                version_introduced="1.2.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _add_encryption_modules(self) -> None:
        """Add encryption module documentation."""
        module = ModuleDocumentation(
            module_name="authenticated_encryption",
            description="Authenticated encryption with associated data (AEAD) using AES-GCM and ChaCha20-Poly1305.",
            best_practices=[
                "Always use authenticated encryption (not raw encryption)",
                "Never reuse nonces with the same key",
                "Include all relevant context in associated data",
                "Verify tags before decryption"
            ],
            usage_examples=[
                """
                aead = AuthenticatedEncryption()
                nonce = aead.generate_nonce()
                ciphertext, tag = aead.encrypt(key, nonce, plaintext, ad)
                plaintext = aead.decrypt(key, nonce, ciphertext, tag, ad)
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="authenticated_encryption",
                function_name="AuthenticatedEncryption.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, algorithm: str = 'aes-gcm')",
                docstring="Initialize AEAD cipher.",
                examples=["aead = AuthenticatedEncryption(algorithm='chacha20-poly1305')"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="authenticated_encryption",
                function_name="AuthenticatedEncryption.generate_nonce",
                stability=StabilityLevel.STABLE,
                signature="generate_nonce(self) -> bytes",
                docstring="Generate cryptographically secure nonce.",
                examples=["nonce = aead.generate_nonce()"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="authenticated_encryption",
                function_name="AuthenticatedEncryption.encrypt",
                stability=StabilityLevel.STABLE,
                signature="encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, ad: Optional[bytes] = None) -> Tuple[bytes, bytes]",
                docstring="Encrypt with authentication tag.",
                examples=["ct, tag = aead.encrypt(key, nonce, pt, ad)"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="authenticated_encryption",
                function_name="AuthenticatedEncryption.decrypt",
                stability=StabilityLevel.STABLE,
                signature="decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, ad: Optional[bytes] = None) -> bytes",
                docstring="Decrypt and verify authentication tag.",
                examples=["pt = aead.decrypt(key, nonce, ct, tag, ad)"],
                version_introduced="1.0.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _add_security_hardening(self) -> None:
        """Add security hardening module documentation."""
        module = ModuleDocumentation(
            module_name="crypto_security_hardening",
            description="Cryptographic security utilities including constant-time operations, memory zeroization, and side-channel resistance.",
            best_practices=[
                "Use constant-time comparisons for all secret material",
                "Zero all sensitive buffers after use",
                "Validate all cryptographic parameters",
                "Enable side-channel countermeasures"
            ],
            usage_examples=[
                """
                if constant_time_compare(received_tag, expected_tag):
                    process_valid()
                
                zeroize_memory(sensitive_key_buffer)
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="crypto_security_hardening",
                function_name="constant_time_compare",
                stability=StabilityLevel.STABLE,
                signature="constant_time_compare(a: bytes, b: bytes) -> bool",
                docstring="Timing-attack resistant comparison for cryptographic secrets.",
                examples=["if constant_time_compare(hash1, hash2):"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="crypto_security_hardening",
                function_name="zeroize_memory",
                stability=StabilityLevel.STABLE,
                signature="zeroize_memory(buffer: bytearray) -> None",
                docstring="Securely overwrite sensitive memory to prevent cold-boot attacks.",
                examples=["zeroize_memory(private_key_buffer)"],
                version_introduced="1.0.0"
            ),
            APIDocumentation(
                module_name="crypto_security_hardening",
                function_name="validate_key_strength",
                stability=StabilityLevel.STABLE,
                signature="validate_key_strength(key: bytes, min_bits: int = 128) -> bool",
                docstring="Validate cryptographic key meets minimum entropy requirements.",
                examples=["if validate_key_strength(key, min_bits=256):"],
                version_introduced="1.1.0"
            ),
            APIDocumentation(
                module_name="crypto_security_hardening",
                function_name="secure_random_bytes",
                stability=StabilityLevel.STABLE,
                signature="secure_random_bytes(length: int) -> bytes",
                docstring="Generate cryptographically secure random bytes.",
                examples=["iv = secure_random_bytes(16)"],
                version_introduced="1.0.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _add_error_resilience(self) -> None:
        """Add error resilience module documentation."""
        module = ModuleDocumentation(
            module_name="crypto_error_resilience",
            description="Error resilience for cryptographic operations including graceful degradation and secure fallback mechanisms.",
            best_practices=[
                "Implement graceful degradation for HSM failures",
                "Use circuit breakers for external crypto services",
                "Always have fallback algorithms",
                "Log all crypto failures securely"
            ],
            usage_examples=[
                """
                @crypto_retry(max_attempts=3)
                def sign_with_hsm(data):
                    return hsm.sign(data)
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="crypto_error_resilience",
                function_name="crypto_retry",
                stability=StabilityLevel.STABLE,
                signature="crypto_retry(max_attempts: int = 3, backoff_factor: float = 1.5)",
                docstring="Decorator for retry logic on transient crypto failures.",
                examples=["@crypto_retry(max_attempts=5)"],
                version_introduced="1.2.0"
            ),
            APIDocumentation(
                module_name="crypto_error_resilience",
                function_name="CryptoCircuitBreaker.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, failure_threshold: int = 5, recovery_timeout: int = 60)",
                docstring="Circuit breaker for crypto service protection.",
                examples=["breaker = CryptoCircuitBreaker(failure_threshold=10)"],
                version_introduced="1.2.0"
            ),
            APIDocumentation(
                module_name="crypto_error_resilience",
                function_name="crypto_fallback",
                stability=StabilityLevel.STABLE,
                signature="crypto_fallback(primary: Callable, fallback: Callable)",
                docstring="Graceful degradation with algorithm fallback.",
                examples=["result = crypto_fallback(hsm_sign, software_sign)"],
                version_introduced="1.3.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _add_audit_modules(self) -> None:
        """Add audit and compliance module documentation."""
        module = ModuleDocumentation(
            module_name="crypto_audit_logger",
            description="Cryptographic audit logging for compliance and forensic analysis (OPT-IN only).",
            best_practices=[
                "Log all key management operations",
                "Sign audit logs for integrity",
                "Enable immutable log storage",
                "Regular audit log review"
            ],
            usage_examples=[
                """
                audit = CryptoAuditLogger(enabled=True)
                audit.log_key_rotation(user_id, key_id, timestamp)
                """
            ]
        )
        
        module.apis.extend([
            APIDocumentation(
                module_name="crypto_audit_logger",
                function_name="CryptoAuditLogger.__init__",
                stability=StabilityLevel.STABLE,
                signature="__init__(self, enabled: bool = False, sign_logs: bool = True)",
                docstring="Initialize audit logger (disabled by default for performance).",
                examples=["audit = CryptoAuditLogger(enabled=True)"],
                version_introduced="1.1.0"
            ),
            APIDocumentation(
                module_name="crypto_audit_logger",
                function_name="CryptoAuditLogger.log_key_generation",
                stability=StabilityLevel.STABLE,
                signature="log_key_generation(self, operator_id: str, key_id: str) -> None",
                docstring="Log key generation event for audit trail.",
                examples=["audit.log_key_generation('admin', 'key-001')"],
                version_introduced="1.1.0"
            ),
            APIDocumentation(
                module_name="crypto_audit_logger",
                function_name="CryptoAuditLogger.log_encryption",
                stability=StabilityLevel.STABLE,
                signature="log_encryption(self, context: str, data_hash: str) -> None",
                docstring="Log encryption operation.",
                examples=["audit.log_encryption('user-data', sha256(data))"],
                version_introduced="1.1.0"
            ),
            APIDocumentation(
                module_name="crypto_audit_logger",
                function_name="CryptoAuditLogger.verify_log_integrity",
                stability=StabilityLevel.EXPERIMENTAL,
                signature="verify_log_integrity(self) -> bool",
                docstring="Verify audit log signature chain (experimental).",
                examples=["valid = audit.verify_log_integrity()"],
                version_introduced="1.4.0"
            )
        ])
        
        self._modules[module.module_name] = module
        self._update_counts(module)
    
    def _update_counts(self, module: ModuleDocumentation) -> None:
        """Update stability level counts."""
        for api in module.apis:
            self._stability_counts[api.stability] += 1
    
    def get_stability_summary(self) -> Dict[str, int]:
        """
        Get summary of API stability levels.
        
        @stable
        """
        return {
            level.value: count
            for level, count in self._stability_counts.items()
        }
    
    def get_module_documentation(self, module_name: str) -> Optional[ModuleDocumentation]:
        """
        Get documentation for a specific module.
        
        @stable
        """
        return self._modules.get(module_name)
    
    def list_all_modules(self) -> List[str]:
        """
        List all documented modules.
        
        @stable
        """
        return list(self._modules.keys())
    
    def generate_markdown_report(self) -> str:
        """
        Generate comprehensive markdown documentation report.
        
        @stable
        """
        lines = [
            "# QuantumCrypt-AI API Documentation & Stability Report v27",
            "",
            f"Generated: {datetime.utcnow().isoformat()}",
            "",
            "## Stability Summary",
            ""
        ]
        
        for level, count in self._stability_counts.items():
            lines.append(f"- **{level.value.upper()}**: {count} APIs")
        
        lines.extend(["", "## Module Documentation", ""])
        
        for module_name, module in sorted(self._modules.items()):
            lines.extend([
                f"### {module_name}",
                "",
                f"**Description**: {module.description}",
                "",
                "**Best Practices**:",
                ""
            ])
            
            for practice in module.best_practices:
                lines.append(f"- {practice}")
            
            lines.extend(["", "**APIs**:", ""])
            
            for api in module.apis:
                stability_icon = "✅" if api.stability == StabilityLevel.STABLE else "⚠️" if api.stability == StabilityLevel.EXPERIMENTAL else "❌"
                lines.append(f"- {stability_icon} `{api.function_name}` - **{api.stability.value}**")
                lines.append(f"  - Signature: `{api.signature}`")
                lines.append(f"  - Since: v{api.version_introduced}")
                if api.deprecation_notice:
                    lines.append(f"  - ⚠️ Deprecation: {api.deprecation_notice}")
            
            lines.append("")
        
        return "\n".join(lines)


# Singleton instance for easy import
documentation_catalog = QuantumCryptDocumentationCatalog()


def get_documentation_catalog() -> QuantumCryptDocumentationCatalog:
    """
    Get the global documentation catalog instance.
    
    @stable
    """
    return documentation_catalog


def print_stability_summary() -> None:
    """
    Print a quick summary of API stability levels.
    
    @stable
    """
    summary = documentation_catalog.get_stability_summary()
    print("QuantumCrypt-AI API Stability Summary v27")
    print("=" * 50)
    for level, count in summary.items():
        print(f"{level.upper():15} {count:3} APIs")
    print("=" * 50)


if __name__ == "__main__":
    print_stability_summary()
    print("\nModules documented:", len(documentation_catalog.list_all_modules()))
    for module in documentation_catalog.list_all_modules():
        print(f"  - {module}")
