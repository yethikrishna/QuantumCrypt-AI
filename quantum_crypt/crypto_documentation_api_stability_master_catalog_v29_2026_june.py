"""
QuantumCrypt AI - API Documentation & Stability Master Catalog v29
=================================================================

API STABILITY MARKERS:
- @STABLE: Production-ready, backward-compatible, no breaking changes
- @EXPERIMENTAL: New feature, subject to change, use with caution
- @DEPRECATED: Scheduled for removal, migrate to alternatives
- @INTERNAL: Not for public consumption, implementation detail

This module provides comprehensive documentation, usage examples,
and API stability metadata for all QuantumCrypt post-quantum modules.

ADD-ONLY PHILOSOPHY: This module is purely additive - no existing
code is modified, only documented and wrapped with metadata.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import json


class StabilityLevel(Enum):
    """API stability classification levels."""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"


@dataclass
class APIEndpointDoc:
    """Documentation metadata for a single API endpoint."""
    name: str
    module: str
    stability: StabilityLevel
    description: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    examples: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    migration_path: Optional[str] = None


@dataclass
class ModuleDoc:
    """Documentation metadata for an entire module."""
    module_name: str
    stability: StabilityLevel
    purpose: str
    algorithm_type: str = ""
    nist_status: str = ""
    endpoints: List[APIEndpointDoc] = field(default_factory=list)
    usage_guide: str = ""
    best_practices: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    security_considerations: List[str] = field(default_factory=list)


class QuantumCryptDocumentationCatalog:
    """
    @STABLE
    Master documentation and API stability catalog for QuantumCrypt AI.
    
    Provides:
    - API stability markers for all public endpoints
    - Comprehensive usage examples for PQ algorithms
    - NIST standardization status
    - Security considerations and best practices
    - Migration guides for deprecated algorithms
    """
    
    def __init__(self):
        self._modules: Dict[str, ModuleDoc] = {}
        self._build_catalog()
    
    def _build_catalog(self) -> None:
        """Build the complete documentation catalog."""
        self._add_key_exchange_modules()
        self._add_digital_signature_modules()
        self._add_certificate_modules()
        self._add_security_hardening_modules()
        self._add_error_resilience_modules()
        self._add_observability_modules()
    
    def _add_key_exchange_modules(self) -> None:
        """Add post-quantum key exchange module documentation."""
        
        # Hybrid PQ Key Exchange
        self._modules["hybrid_pq_key_exchange"] = ModuleDoc(
            module_name="post_quantum_hybrid_key_exchange_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Hybrid post-quantum + classical key exchange for TLS",
            algorithm_type="Key Encapsulation Mechanism (KEM)",
            nist_status="NIST SP 800-186 Standardized (CRYSTALS-Kyber)",
            usage_guide="""
            Usage Guide:
            ------------
            PRIMARY RECOMMENDED key exchange for production deployments.
            
            Hybrid Approach:
            - Combines CRYSTALS-Kyber (post-quantum)
            - With X25519 (classical ECDH)
            - Provides transitional security
            
            Security: Both must be broken to compromise the key
            """,
            best_practices=[
                "Always use hybrid mode during transition period",
                "Use Kyber-768 for balanced security/performance",
                "Implement proper key zeroization after use",
                "Rotate session keys frequently",
                "Validate all public key formats"
            ],
            limitations=[
                "Larger public keys than classical algorithms",
                "Higher computational overhead",
                "Requires TLS 1.3 for optimal integration"
            ],
            security_considerations=[
                "Side-channel resistance varies by implementation",
                "Ensure proper randomness for key generation",
                "Validate ciphertext bounds to prevent oracle attacks"
            ],
            endpoints=[
                APIEndpointDoc(
                    name="generate_hybrid_keypair",
                    module="post_quantum_hybrid_key_exchange_2026_june",
                    stability=StabilityLevel.STABLE,
                    description="Generate hybrid PQ + classical keypair",
                    parameters=[
                        {"name": "security_level", "type": "int", "desc": "128, 192, or 256 bits"},
                        {"name": "classical_alg", "type": "str", "desc": "X25519 or secp256r1"}
                    ],
                    returns="HybridKeyPair with both PQ and classical components",
                    examples=[
                        """
                        kem = HybridPQKeyExchange()
                        keypair = kem.generate_hybrid_keypair(
                            security_level=128,
                            classical_alg="X25519"
                        )
                        shared_secret = kem.encapsulate(keypair.public_key)
                        """
                    ]
                ),
                APIEndpointDoc(
                    name="encapsulate",
                    module="post_quantum_hybrid_key_exchange_2026_june",
                    stability=StabilityLevel.STABLE,
                    description="Encapsulate to generate shared secret and ciphertext"
                ),
                APIEndpointDoc(
                    name="decapsulate",
                    module="post_quantum_hybrid_key_exchange_2026_june",
                    stability=StabilityLevel.STABLE,
                    description="Decapsulate ciphertext to recover shared secret"
                )
            ]
        )
        
        # Forward Secrecy Extension
        self._modules["forward_secrecy_extension"] = ModuleDoc(
            module_name="hybrid_pq_key_exchange_forward_secrecy_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Forward secrecy extension for PQ key exchange",
            algorithm_type="Key Exchange with Ephemeral Keys",
            nist_status="Recommended Practice",
            best_practices=[
                "Generate new ephemeral keys per session",
                "Never reuse private keys",
                "Zeroize keys immediately after use"
            ],
            limitations=[
                "Higher computational cost per connection"
            ]
        )
    
    def _add_digital_signature_modules(self) -> None:
        """Add post-quantum digital signature module documentation."""
        
        # Dilithium Digital Signature
        self._modules["dilithium_signature"] = ModuleDoc(
            module_name="post_quantum_dilithium_signature_engine_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="CRYSTALS-Dilithium post-quantum digital signatures",
            algorithm_type="Digital Signature Algorithm (DSA)",
            nist_status="NIST FIPS 204 Standardized",
            usage_guide="""
            Usage Guide:
            ------------
            PRIMARY RECOMMENDED signature algorithm.
            
            Security Levels:
            - Dilithium2:  NIST Level 1 (128-bit)
            - Dilithium3:  NIST Level 3 (192-bit)  
            - Dilithium5:  NIST Level 5 (256-bit)
            
            Recommended: Dilithium3 for most applications
            """,
            best_practices=[
                "Use Dilithium3 as default security level",
                "Sign hashes, not raw messages",
                "Verify all signature components",
                "Implement signature batch verification where possible",
                "Store private keys in HSM when available"
            ],
            limitations=[
                "Signature sizes larger than ECDSA",
                "Public keys larger than classical counterparts",
                "Verification is fast but signing has overhead"
            ],
            security_considerations=[
                "Lattice-based security reduction",
                "Resistant to quantum Fourier transform attacks",
                "Ensure deterministic signing uses proper randomness"
            ],
            endpoints=[
                APIEndpointDoc(
                    name="sign",
                    module="post_quantum_dilithium_signature_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    description="Sign message with private key",
                    parameters=[
                        {"name": "message", "type": "bytes", "desc": "Message to sign"},
                        {"name": "private_key", "type": "bytes", "desc": "Dilithium private key"}
                    ],
                    returns="DigitalSignature object"
                ),
                APIEndpointDoc(
                    name="verify",
                    module="post_quantum_dilithium_signature_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    description="Verify signature authenticity",
                    returns="bool: True if valid signature"
                )
            ]
        )
        
        # Hybrid Digital Signature
        self._modules["hybrid_signature"] = ModuleDoc(
            module_name="post_quantum_digital_signature_hybrid_verification_engine_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Hybrid PQ + classical signature verification",
            algorithm_type="Hybrid DSA",
            nist_status="Recommended Transition Practice",
            best_practices=[
                "Use hybrid verification during migration",
                "Both signatures must validate",
                "Fail closed if either signature fails"
            ]
        )
    
    def _add_certificate_modules(self) -> None:
        """Add certificate management module documentation."""
        
        # Certificate Chain Builder
        self._modules["certificate_chain_builder"] = ModuleDoc(
            module_name="post_quantum_certificate_chain_builder_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Build and validate PQ certificate chains",
            usage_guide="""
            Usage Guide:
            ------------
            Creates X.509 certificate chains with PQ algorithms.
            
            Chain Structure:
            Root CA → Intermediate CA → End Entity
            
            Supports:
            - Composite certificates (PQ + classical)
            - Certificate Transparency integration
            - Path validation and constraint checking
            """,
            best_practices=[
                "Use composite certificates during transition",
                "Implement proper certificate pinning",
                "Check revocation status via OCSP/CRL",
                "Enforce name constraints",
                "Validate certificate policies"
            ],
            limitations=[
                "Larger certificate sizes",
                "Requires updated TLS stacks",
                "Browser support is evolving"
            ],
            security_considerations=[
                "Root CA keys must be stored offline in HSM",
                "Intermediate CAs should have limited lifetimes",
                "Monitor certificate transparency logs"
            ]
        )
        
        # Certificate Transparency
        self._modules["certificate_transparency"] = ModuleDoc(
            module_name="post_quantum_certificate_transparency_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Certificate Transparency (CT) log submission and monitoring",
            best_practices=[
                "Submit all certificates to multiple CT logs",
                "Monitor logs for unauthorized certificates",
                "Require SCTs in TLS handshakes"
            ]
        )
        
        # Certificate Revocation Checker
        self._modules["certificate_revocation"] = ModuleDoc(
            module_name="post_quantum_certificate_revocation_checker_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="OCSP and CRL-based certificate revocation checking",
            best_practices=[
                "Implement soft-fail during OCSP outages",
                "Cache revocation responses appropriately",
                "Support both OCSP and CRL fallbacks"
            ]
        )
    
    def _add_security_hardening_modules(self) -> None:
        """Add security hardening module documentation."""
        
        # Constant Time Execution Protector
        self._modules["constant_time_protector"] = ModuleDoc(
            module_name="post_quantum_constant_time_execution_protector_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Side-channel resistance through constant-time execution",
            usage_guide="""
            Usage Guide:
            ------------
            CRITICAL for cryptographic implementations.
            
            Provides:
            - Constant-time comparison helpers
            - Memory access pattern normalization
            - Branch elimination utilities
            - Timing side-channel mitigations
            
            Wrap ALL private key operations.
            """,
            best_practices=[
                "Never branch on secret data",
                "Use constant-time comparisons for all crypto ops",
                "Zeroize sensitive memory after use",
                "Test with timing analysis tools",
                "Avoid table lookups indexed by secrets"
            ],
            limitations=[
                "Compiler optimizations can re-introduce timing leaks",
                "CPU cache effects are hard to fully eliminate",
                "Requires careful implementation review"
            ],
            security_considerations=[
                "Side-channel attacks are a real threat in production",
                "Even nanosecond-scale leaks can be exploitable",
                "Defense in depth requires multiple mitigation layers"
            ]
        )
        
        # Side Channel Resistance
        self._modules["side_channel_resistance"] = ModuleDoc(
            module_name="crypto_security_hardening_side_channel_key_protection_v17_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Comprehensive side-channel attack mitigations",
            best_practices=[
                "Apply blinding to private key operations",
                "Mask intermediate values",
                "Add controlled timing jitter",
                "Shuffle memory access patterns"
            ]
        )
        
        # Input Validation Injection Protection
        self._modules["input_validation"] = ModuleDoc(
            module_name="crypto_security_hardening_input_validation_injection_protection_v17_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Input validation and algorithm injection protection",
            best_practices=[
                "Validate all algorithm parameters",
                "Use algorithm allowlists, not blocklists",
                "Reject weak or deprecated algorithms",
                "Sanitize all cryptographic inputs"
            ]
        )
    
    def _add_error_resilience_modules(self) -> None:
        """Add error resilience module documentation."""
        
        # Key Operation Protection
        self._modules["key_operation_protection"] = ModuleDoc(
            module_name="crypto_error_resilience_key_operation_protection_v17_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Timeout, retry, and circuit breaker for key operations",
            usage_guide="""
            Usage Guide:
            ------------
            Wrap all HSM and key operations to prevent cascade failures.
            
            Features:
            - Configurable operation timeouts
            - Exponential backoff retries
            - Circuit breaker on repeated failures
            - Graceful degradation paths
            """,
            best_practices=[
                "Set conservative timeouts for HSM operations",
                "Define clear fallback behaviors",
                "Monitor circuit breaker state",
                "Log all failed operations"
            ]
        )
        
        # Algorithm Fallback Chain
        self._modules["algorithm_fallback"] = ModuleDoc(
            module_name="crypto_error_resilience_algorithm_fallback_chain_v19_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Graceful algorithm fallback for compatibility",
            best_practices=[
                "Define fallback priority order explicitly",
                "Log algorithm negotiation results",
                "Prefer strongest mutually supported algorithm",
                "Fail secure on negotiation failure"
            ]
        )
    
    def _add_observability_modules(self) -> None:
        """Add observability module documentation."""
        
        # Structured Logging & Metrics
        self._modules["crypto_observability"] = ModuleDoc(
            module_name="crypto_observability_structured_logging_metrics_health_v25_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Structured logging, metrics collection, and health checks",
            usage_guide="""
            Usage Guide:
            ------------
            OPT-IN instrumentation - zero overhead when disabled.
            
            Metrics Collected:
            - Operation latency histograms
            - Success/failure counters
            - Algorithm usage statistics
            - Certificate expiration timelines
            
            All instrumentation is OPT-IN via config.
            """,
            best_practices=[
                "Enable only needed metrics in production",
                "Use sampling for high-throughput systems",
                "Never log sensitive key material",
                "Include trace IDs for correlation",
                "Set alerts on certificate expiry"
            ],
            limitations=[
                "Metrics have small performance overhead",
                "Logging increases I/O and storage"
            ]
        )
    
    def get_module_doc(self, module_name: str) -> Optional[ModuleDoc]:
        """
        @STABLE
        Get documentation for a specific module.
        """
        return self._modules.get(module_name)
    
    def get_all_modules(self) -> List[ModuleDoc]:
        """
        @STABLE
        Get list of all documented modules.
        """
        return list(self._modules.values())
    
    def get_stable_modules(self) -> List[ModuleDoc]:
        """
        @STABLE
        Get all modules marked STABLE for production use.
        """
        return [m for m in self._modules.values() 
                if m.stability == StabilityLevel.STABLE]
    
    def get_nist_standardized(self) -> List[ModuleDoc]:
        """
        @STABLE
        Get all NIST-standardized algorithm modules.
        """
        return [m for m in self._modules.values() 
                if "Standardized" in m.nist_status]
    
    def generate_stability_report(self) -> Dict[str, Any]:
        """
        @STABLE
        Generate comprehensive API stability report.
        """
        total = len(self._modules)
        stable = len(self.get_stable_modules())
        nist_std = len(self.get_nist_standardized())
        
        return {
            "total_modules": total,
            "stable_modules": stable,
            "nist_standardized": nist_std,
            "stable_percentage": round(stable / total * 100, 1) if total > 0 else 0,
            "modules": [
                {
                    "name": m.module_name,
                    "stability": m.stability.value,
                    "algorithm_type": m.algorithm_type,
                    "nist_status": m.nist_status,
                    "purpose": m.purpose
                }
                for m in self._modules.values()
            ]
        }
    
    def export_json(self, filepath: str) -> None:
        """
        @STABLE
        Export documentation catalog to JSON file.
        """
        report = self.generate_stability_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)


# Global instance for easy import
CRYPTO_DOCUMENTATION_CATALOG = QuantumCryptDocumentationCatalog()


def get_api_stability_report() -> Dict[str, Any]:
    """
    @STABLE
    Convenience function to get API stability report.
    """
    return CRYPTO_DOCUMENTATION_CATALOG.generate_stability_report()


def print_stability_summary() -> None:
    """
    @STABLE
    Print human-readable API stability summary.
    """
    report = get_api_stability_report()
    print("=" * 60)
    print("QuantumCrypt AI - API Stability Summary v29")
    print("=" * 60)
    print(f"Total Modules:      {report['total_modules']}")
    print(f"STABLE:             {report['stable_modules']} ({report['stable_percentage']}%)")
    print(f"NIST Standardized:  {report['nist_standardized']}")
    print()
    print("Module Stability Breakdown:")
    print("-" * 60)
    for mod in report['modules']:
        print(f"  [{mod['stability']:12}] {mod['name']}")
        if mod['nist_status']:
            print(f"                → {mod['nist_status']}")
    print("=" * 60)


if __name__ == "__main__":
    print_stability_summary()
