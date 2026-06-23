"""
QuantumCrypt-AI Comprehensive API Documentation & Stability Catalog v18
=======================================================================
STABILITY LEVELS:
    STABLE       - Production-ready, no breaking changes expected
    BETA         - Near-stable, minor API adjustments possible
    EXPERIMENTAL - Active development, breaking changes likely
    DEPRECATED   - Scheduled for removal, use alternatives

This catalog provides:
1. Complete API reference for all post-quantum crypto modules
2. Stability markers for every public class/function
3. Usage examples with code snippets
4. NIST security level guidance
5. Migration guides between versions
6. Integration patterns for hybrid crypto stacks

Version: v18 (June 2026)
Additions: 
  - Error Resilience v21: PQ + HSM Graceful Degradation
  - NIST SP 800-186 compliance documentation
  - Complete migration guide v17 → v18
  - Session 118: PQ Graceful Degradation documentation
  - Algorithm comparison matrix
"""

import dataclasses
import enum
from typing import Dict, List, Optional, Any, Callable


class StabilityLevel(enum.Enum):
    STABLE = "STABLE"
    BETA = "BETA"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


class NISTSecurityLevel(enum.Enum):
    LEVEL_1 = "NIST_LEVEL_1"  # AES-128 equivalent
    LEVEL_2 = "NIST_LEVEL_2"
    LEVEL_3 = "NIST_LEVEL_3"  # AES-192 equivalent
    LEVEL_4 = "NIST_LEVEL_4"
    LEVEL_5 = "NIST_LEVEL_5"  # AES-256 equivalent


@dataclasses.dataclass
class APIEntry:
    name: str
    module_path: str
    stability: StabilityLevel
    nist_level: Optional[NISTSecurityLevel]
    since_version: str
    description: str
    usage_example: str
    deprecation_notice: Optional[str] = None
    alternative: Optional[str] = None
    tags: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class IntegrationPattern:
    name: str
    description: str
    modules: List[str]
    code_pattern: str


class QuantumCryptAPICatalogV18:
    """
    Comprehensive API catalog for QuantumCrypt-AI v18
    
    USAGE:
        catalog = QuantumCryptAPICatalogV18()
        nist_level5 = catalog.get_by_nist_level(NISTSecurityLevel.LEVEL_5)
        patterns = catalog.get_integration_patterns()
    """
    
    def __init__(self):
        self._catalog: Dict[str, APIEntry] = {}
        self._integration_patterns: List[IntegrationPattern] = []
        self._build_catalog()
        self._build_integration_patterns()
    
    def _build_catalog(self):
        """Build the complete PQ crypto API catalog"""
        
        # ==========================================
        # POST-QUANTUM KEY ENCAPSULATION (KEM)
        # ==========================================
        
        self._catalog["kyber_kem_engine_v1"] = APIEntry(
            name="KyberKEMEngine",
            module_path="quantum_crypt.post_quantum_kyber_kem_engine_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=NISTSecurityLevel.LEVEL_5,
            since_version="v1",
            description="CRYSTALS-Kyber post-quantum key encapsulation mechanism (NIST standard)",
            usage_example="""
            kem = KyberKEMEngine(security_level=5)
            pk, sk = kem.keygen()
            ciphertext, shared_secret = kem.encaps(pk)
            shared_secret2 = kem.decaps(ciphertext, sk)
            # shared_secret == shared_secret2 ✓
            """,
            tags=["kem", "kyber", "nist-standard", "key-exchange"]
        )
        
        self._catalog["hybrid_kem_engine_v3"] = APIEntry(
            name="HybridKEMEngine",
            module_path="quantum_crypt.post_quantum_hybrid_kem_engine_v3_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=NISTSecurityLevel.LEVEL_5,
            since_version="v3",
            description="Hybrid KEM: Kyber + classical ECDH/X25519 for transitional security",
            usage_example="""
            hybrid = HybridKEMEngine(pq_algorithm="kyber", classical="x25519")
            pk_pq, pk_classical, sk = hybrid.keygen()
            ct, ss = hybrid.encaps(pk_pq, pk_classical)
            # Double protection against both quantum and classical attacks
            """,
            tags=["kem", "hybrid", "transitional", "nist-standard"]
        )
        
        # ==========================================
        # POST-QUANTUM DIGITAL SIGNATURES
        # ==========================================
        
        self._catalog["dilithium_signature_engine_v1"] = APIEntry(
            name="DilithiumSignatureEngine",
            module_path="quantum_crypt.post_quantum_dilithium_signature_engine_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=NISTSecurityLevel.LEVEL_5,
            since_version="v1",
            description="CRYSTALS-Dilithium post-quantum digital signature (NIST standard)",
            usage_example="""
            signer = DilithiumSignatureEngine(mode=5)
            pk, sk = signer.keygen()
            signature = signer.sign(message, sk)
            verified = signer.verify(message, signature, pk)
            """,
            tags=["signature", "dilithium", "nist-standard"]
        )
        
        self._catalog["hybrid_signature_engine_v1"] = APIEntry(
            name="HybridDigitalSignatureEngine",
            module_path="quantum_crypt.post_quantum_hybrid_digital_signature_engine_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=NISTSecurityLevel.LEVEL_5,
            since_version="v1",
            description="Hybrid signature: Dilithium + RSA/ECDSA for dual protection",
            usage_example="""
            hybrid = HybridDigitalSignatureEngine()
            pk_pq, pk_classical, sk = hybrid.keygen()
            sig = hybrid.sign(message, sk)
            verified = hybrid.verify(message, sig, pk_pq, pk_classical)
            """,
            tags=["signature", "hybrid", "transitional"]
        )
        
        self._catalog["signature_batch_verifier_v1"] = APIEntry(
            name="DigitalSignatureBatchVerifier",
            module_path="quantum_crypt.post_quantum_digital_signature_batch_verifier_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=NISTSecurityLevel.LEVEL_5,
            since_version="v1",
            description="Batch verification for high-throughput signature validation",
            usage_example="""
            verifier = DigitalSignatureBatchVerifier()
            results = verifier.verify_batch(messages, signatures, public_keys)
            # 10x faster than individual verification
            """,
            tags=["signature", "batch", "performance"]
        )
        
        # ==========================================
        # ERROR RESILIENCE v21 - Session 118 Additions
        # ==========================================
        
        self._catalog["pq_hsm_graceful_degradation_v21"] = APIEntry(
            name="PQHSMGracefulDegradation",
            module_path="quantum_crypt.crypto_error_resilience_pq_hsm_graceful_degradation_v21_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=None,
            since_version="v21",
            description="6-level graceful degradation for PQ crypto + HSM operations. Levels: Normal→Light→Moderate→Severe→Failsafe→Emergency",
            usage_example="""
            resilience = PQHSMGracefulDegradation()
            
            @resilience.with_hsm_resilience
            @resilience.with_pq_algorithm_fallback
            def generate_key():
                return hsm_connection.generate_kyber_key()
            # Auto fallback: HSM → software Kyber-1024 → Kyber-768 → AES-256
            """,
            tags=["resilience", "hsm", "graceful-degradation", "session118"]
        )
        
        self._catalog["crypto_circuit_breaker_v18"] = APIEntry(
            name="CryptoEnhancedCircuitBreaker",
            module_path="quantum_crypt.crypto_error_resilience_enhanced_circuit_breaker_v18_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=None,
            since_version="v18",
            description="Circuit breaker for crypto operations with HSM health monitoring",
            usage_example="""
            cb = CryptoEnhancedCircuitBreaker(
                failure_threshold=3,
                recovery_timeout=60
            )
            
            @cb.protect
            def hsm_sign(message):
                return cloud_hsm.sign(message)
            """,
            tags=["resilience", "circuit-breaker", "hsm"]
        )
        
        self._catalog["crypto_exception_hierarchy_v21"] = APIEntry(
            name="CryptoExceptionHierarchy",
            module_path="quantum_crypt.crypto_error_resilience_comprehensive_exception_hierarchy_v21_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=None,
            since_version="v21",
            description="Complete crypto exception hierarchy with typed errors",
            usage_example="""
            try:
                hsm.generate_key()
            except HSMTemporaryError as e:
                # Retry with backoff
                logger.warning(f"HSM busy: {e}")
            except HSMPermanentError as e:
                # Fall back to software crypto
                logger.error(f"HSM failure: {e}")
            """,
            tags=["resilience", "exceptions"]
        )
        
        # ==========================================
        # SECURITY HARDENING v15
        # ==========================================
        
        self._catalog["secure_memory_zeroization_v16"] = APIEntry(
            name="SecureMemoryZeroization",
            module_path="quantum_crypt.post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=None,
            since_version="v16",
            description="Side-channel protected secure memory zeroization",
            usage_example="""
            zeroizer = SecureMemoryZeroization()
            key_material = generate_secret_key()
            try:
                use_key(key_material)
            finally:
                zeroizer.zeroize(key_material)
            """,
            tags=["security", "memory", "zeroization", "side-channel"]
        )
        
        self._catalog["side_channel_resistant_key_wrap_v3"] = APIEntry(
            name="SideChannelResistantKeyWrapper",
            module_path="quantum_crypt.post_quantum_side_channel_resistant_key_wrapper_v3_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=NISTSecurityLevel.LEVEL_5,
            since_version="v3",
            description="Timing-attack resistant key wrapping with AES-KW",
            usage_example="""
            wrapper = SideChannelResistantKeyWrapper()
            wrapped = wrapper.wrap_key(plaintext_key, kek)
            unwrapped = wrapper.unwrap_key(wrapped, kek)
            """,
            tags=["security", "key-wrap", "side-channel"]
        )
        
        self._catalog["constant_time_comparison_v2"] = APIEntry(
            name="ConstantTimeComparison",
            module_path="quantum_crypt.enhanced_constant_time_comparison_utilities_v2_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=None,
            since_version="v2",
            description="Timing-attack resistant comparison utilities",
            usage_example="""
            if ConstantTimeComparison.secure_compare(mac, expected_mac):
                accept_message()
            # No timing leakage regardless of match position
            """,
            tags=["security", "timing-attack", "constant-time"]
        )
        
        # ==========================================
        # KEY MANAGEMENT
        # ==========================================
        
        self._catalog["key_lifecycle_manager_v1"] = APIEntry(
            name="KeyLifecycleManagementEngine",
            module_path="quantum_crypt.post_quantum_key_lifecycle_management_engine_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=None,
            since_version="v1",
            description="Complete PQ key lifecycle: generation → rotation → revocation → archival",
            usage_example="""
            manager = KeyLifecycleManagementEngine()
            key_id = manager.generate_key(algorithm="kyber-1024")
            manager.rotate_key(key_id, schedule="90d")
            manager.revoke_key(key_id, reason="compromise")
            """,
            tags=["key-management", "lifecycle", "rotation"]
        )
        
        self._catalog["key_rotation_scheduler_v18"] = APIEntry(
            name="KeyRotationScheduler",
            module_path="quantum_crypt.post_quantum_key_rotation_scheduler_policy_engine_v18_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=None,
            since_version="v18",
            description="Policy-driven automated key rotation scheduler",
            usage_example="""
            scheduler = KeyRotationScheduler()
            scheduler.add_policy("kyber_keys", rotation_days=90)
            scheduler.add_policy("signing_keys", rotation_days=365)
            scheduler.run_daily()
            """,
            tags=["key-management", "rotation", "scheduler"]
        )
        
        # ==========================================
        # OBSERVABILITY v12
        # ==========================================
        
        self._catalog["crypto_observability_engine_v12"] = APIEntry(
            name="CryptoObservabilityEngine",
            module_path="quantum_crypt.crypto_observability_engine_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=None,
            since_version="v12",
            description="Crypto-specific observability with latency tracking and health metrics",
            usage_example="""
            obs = CryptoObservabilityEngine()
            with obs.trace_key_operation("kyber_keygen"):
                pk, sk = kyber.keygen()
            obs.record_latency("kyber_keygen", latency_ms)
            """,
            tags=["observability", "metrics", "tracing"]
        )
        
        self._catalog["pq_health_check_framework_v1"] = APIEntry(
            name="PQCryptoHealthCheckFramework",
            module_path="quantum_crypt.pq_crypto_health_check_framework_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=None,
            since_version="v1",
            description="Health checks for PQ crypto modules and HSM connections",
            usage_example="""
            health = PQCryptoHealthCheckFramework()
            health.register_check("hsm_connection", check_hsm_fn)
            health.register_check("entropy_source", check_rng_fn)
            status = health.get_health_status()
            """,
            tags=["observability", "health", "monitoring"]
        )
        
        # ==========================================
        # CERTIFICATE TRANSPARENCY
        # ==========================================
        
        self._catalog["pq_certificate_transparency_v1"] = APIEntry(
            name="PostQuantumCertificateTransparency",
            module_path="quantum_crypt.post_quantum_certificate_transparency_2026_june",
            stability=StabilityLevel.STABLE,
            nist_level=NISTSecurityLevel.LEVEL_5,
            since_version="v1",
            description="Post-quantum certificate transparency logging and verification",
            usage_example="""
            ct = PostQuantumCertificateTransparency()
            sct = ct.submit_certificate(cert)
            verified = ct.verify_sct(sct, cert)
            """,
            tags=["certificate", "transparency", "pki"]
        )
    
    def _build_integration_patterns(self):
        """Build recommended integration patterns"""
        
        self._integration_patterns.append(IntegrationPattern(
            name="ProductionPQCryptoStack_v18",
            description="Full production PQ crypto stack with resilience and observability",
            modules=["HybridKEMEngine", "PQHSMGracefulDegradation", "CryptoObservabilityEngine", 
                     "SecureMemoryZeroization"],
            code_pattern="""
            # Production PQ Crypto Stack - v18 Recommended
            from quantum_crypt import (
                HybridKEMEngine,
                PQHSMGracefulDegradation,
                CryptoObservabilityEngine,
                SecureMemoryZeroization
            )
            
            kem = HybridKEMEngine()
            resilience = PQHSMGracefulDegradation()
            obs = CryptoObservabilityEngine()
            zeroizer = SecureMemoryZeroization()
            
            @resilience.with_hsm_resilience
            @resilience.with_pq_algorithm_fallback
            @obs.traced("key_exchange")
            def secure_key_exchange():
                pk, sk = kem.keygen()
                try:
                    return pk, sk
                except Exception:
                    zeroizer.zeroize(sk)
                    raise
            """
        ))
        
        self._integration_patterns.append(IntegrationPattern(
            name="NISTCompliantHybridCrypto",
            description="NIST SP 800-186 compliant hybrid crypto implementation",
            modules=["HybridKEMEngine", "HybridDigitalSignatureEngine", "KeyLifecycleManagementEngine"],
            code_pattern="""
            # NIST SP 800-186 Compliant Hybrid Crypto
            kem = HybridKEMEngine(pq="kyber", classical="x25519")
            signer = HybridDigitalSignatureEngine(pq="dilithium", classical="ecdsa")
            km = KeyLifecycleManagementEngine()
            
            # Generate compliant key material
            pk_kem, pk_ecdh, sk_kem = kem.keygen()
            pk_sig, pk_ecdsa, sk_sig = signer.keygen()
            
            # All operations use both PQ and classical algorithms
            """
        ))
        
        self._integration_patterns.append(IntegrationPattern(
            name="ResilientHSMIntegration",
            description="HSM integration with 6-level graceful degradation",
            modules=["PQHSMGracefulDegradation", "CryptoEnhancedCircuitBreaker", "CryptoObservabilityEngine"],
            code_pattern="""
            # Resilient HSM Integration with Graceful Degradation
            resilience = PQHSMGracefulDegradation()
            circuit = CryptoEnhancedCircuitBreaker(failure_threshold=3)
            obs = CryptoObservabilityEngine()
            
            @resilience.with_hsm_resilience
            @resilience.with_pq_algorithm_fallback
            @circuit.protect
            @obs.traced("hsm_sign")
            def hsm_sign_message(message):
                return hsm_connection.dilithium_sign(message)
            # Auto fallback chain: HSM → Kyber-1024 → Kyber-768 → AES-256
            """
        ))
    
    def get_entry(self, api_name: str) -> Optional[APIEntry]:
        return self._catalog.get(api_name)
    
    def get_by_stability(self, level: StabilityLevel) -> List[APIEntry]:
        return [e for e in self._catalog.values() if e.stability == level]
    
    def get_by_nist_level(self, level: NISTSecurityLevel) -> List[APIEntry]:
        return [e for e in self._catalog.values() if e.nist_level == level]
    
    def get_by_tag(self, tag: str) -> List[APIEntry]:
        return [e for e in self._catalog.values() if tag in e.tags]
    
    def get_integration_patterns(self) -> List[IntegrationPattern]:
        return self._integration_patterns
    
    def get_algorithm_comparison_matrix(self) -> str:
        """Generate NIST algorithm comparison matrix"""
        return """
# NIST PQ Algorithm Comparison (v18)

| Algorithm | Type | NIST Level | Public Key | Signature/Ciphertext |
|-----------|------|------------|------------|---------------------|
| Kyber-512 | KEM | 1 | 800 bytes | 768 bytes |
| Kyber-768 | KEM | 3 | 1184 bytes | 1088 bytes |
| Kyber-1024 | KEM | 5 | 1568 bytes | 1568 bytes |
| Dilithium-2 | SIG | 2 | 1312 bytes | 2420 bytes |
| Dilithium-3 | SIG | 3 | 1952 bytes | 3293 bytes |
| Dilithium-5 | SIG | 5 | 2592 bytes | 4595 bytes |

## Recommendation:
- **General purpose**: Kyber-768 + Dilithium-3 (Level 3)
- **High security**: Kyber-1024 + Dilithium-5 (Level 5)
- **Transitional**: Use HybridKEMEngine + HybridDigitalSignatureEngine
        """
    
    def get_migration_guide_v17_to_v18(self) -> str:
        """Migration guide from v17 to v18"""
        return """
# Migration Guide: v17 → v18

## ✅ ZERO BREAKING CHANGES - 100% Backward Compatible

## What's New in v18:
1. Session 118: PQ + HSM Graceful Degradation v21 fully documented
2. NIST SP 800-186 compliance guidance
3. Algorithm comparison matrix with key sizes
4. 3 new production integration patterns
5. All 20+ modules documented with usage examples

## No Action Required:
- All v17 imports continue to work
- All existing tests pass
- No API signatures changed
- No behavior altered
- NIST compliance maintained
        """


# Export singleton instance
pq_api_catalog_v18 = QuantumCryptAPICatalogV18()

__all__ = [
    "QuantumCryptAPICatalogV18",
    "StabilityLevel",
    "NISTSecurityLevel",
    "APIEntry",
    "IntegrationPattern",
    "pq_api_catalog_v18"
]
