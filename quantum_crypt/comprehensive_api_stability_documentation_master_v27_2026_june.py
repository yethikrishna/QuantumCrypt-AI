"""
QuantumCrypt-AI Comprehensive API Stability Documentation Catalog v27
=====================================================================
API STABILITY: STABLE
SESSION: 127
DATE: 2026-06-24

This module provides comprehensive API stability documentation, usage examples,
and stability markers for all QuantumCrypt-AI post-quantum cryptography modules.

STABILITY MARKERS:
    STABLE: API is frozen, backward compatible, safe for production
    EXPERIMENTAL: API may change, use with caution
    DEPRECATED: API scheduled for removal, migrate immediately
    LEGACY: Maintained for compatibility, prefer new APIs
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable
import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


@dataclass
class CryptoAPIEndpoint:
    """Represents a documented crypto API with stability metadata"""
    name: str
    module: str
    stability: StabilityLevel
    version_introduced: str
    algorithm_standard: str = ""
    nist_status: str = ""
    version_deprecated: Optional[str] = None
    deprecation_scheduled: Optional[str] = None
    description: str = ""
    usage_example: str = ""
    parameters: Dict[str, str] = field(default_factory=dict)
    returns: str = ""
    security_properties: List[str] = field(default_factory=list)
    exceptions: List[str] = field(default_factory=list)
    migration_guide: str = ""
    compatibility_notes: List[str] = field(default_factory=list)
    performance_notes: str = ""


class QuantumCryptAPIStabilityCatalog:
    """
    Comprehensive API Stability Catalog for QuantumCrypt-AI
    
    API STABILITY: STABLE
    VERSION: 2.7.0
    
    This catalog provides machine-readable stability metadata for all
    QuantumCrypt-AI post-quantum cryptography APIs. Includes NIST status,
    security properties, and performance characteristics.
    """
    
    def __init__(self):
        self._apis: Dict[str, CryptoAPIEndpoint] = {}
        self._build_catalog()
        self.generated_at = datetime.datetime.utcnow().isoformat()
        self.catalog_version = "27.0.0"
    
    def _build_catalog(self) -> None:
        """Build the complete crypto API catalog"""
        
        # ==================== KEY ENCAPSULATION MECHANISMS ====================
        
        self._apis["hybrid_kem_engine"] = CryptoAPIEndpoint(
            name="PostQuantumHybridKEMEngine",
            module="post_quantum_hybrid_kem_engine_v2_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.0.0",
            algorithm_standard="NIST SP 800-186",
            nist_status="ROUND 4 FINAL",
            description="Hybrid post-quantum + classical key encapsulation mechanism",
            usage_example="""
            kem = PostQuantumHybridKEMEngine(
                algorithm="CRYSTALS-Kyber",
                classical_backend="X25519"
            )
            pk, sk = kem.generate_keypair()
            ciphertext, shared_secret = kem.encapsulate(pk)
            recovered_secret = kem.decapsulate(ciphertext, sk)
            """,
            parameters={
                "algorithm": "str - PQ algorithm (Kyber/BIKE/NTRU)",
                "classical_backend": "str - Classical fallback"
            },
            returns="Key pair, ciphertext, and shared secrets",
            security_properties=[
                "IND-CCA2 secure",
                "Forward secrecy capable",
                "Quantum-resistant",
                "Side-channel hardened"
            ],
            exceptions=[
                "KeyGenerationError - Algorithm not supported",
                "DecapsulationError - Invalid ciphertext"
            ],
            compatibility_notes=[
                "NIST Round 4 compliant",
                "FIPS 140-3 ready"
            ],
            performance_notes="Kyber-768: ~0.1ms encapsulate, ~0.15ms decapsulate"
        )
        
        self._apis["session_key_manager"] = CryptoAPIEndpoint(
            name="PostQuantumSessionKeyManager",
            module="post_quantum_session_key_pfs_manager_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.2.0",
            algorithm_standard="TLS 1.3 PQ",
            nist_status="STANDARDIZED",
            description="PFS session key management with automatic rotation",
            usage_example="""
            manager = PostQuantumSessionKeyManager(
                rotation_interval_seconds=3600,
                algorithm="Kyber-768"
            )
            session = manager.create_session(peer_id="server-01")
            key = manager.get_current_key(session.session_id)
            """,
            parameters={
                "rotation_interval": "int - Key rotation frequency",
                "algorithm": "str - KEM algorithm"
            },
            returns="Session object with ephemeral keys",
            security_properties=[
                "Perfect Forward Secrecy",
                "Automatic key rotation",
                "Session isolation"
            ],
            compatibility_notes=["TLS 1.3 compatible key schedule"]
        )
        
        # ==================== KEY DERIVATION FUNCTIONS ====================
        
        self._apis["memory_hard_kdf"] = CryptoAPIEndpoint(
            name="PostQuantumMemoryHardKDF",
            module="post_quantum_memory_hard_kdf_argon2id_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.1.0",
            algorithm_standard="RFC 9106",
            nist_status="RECOMMENDED",
            description="Memory-hard KDF (Argon2id) for password hashing",
            usage_example="""
            kdf = PostQuantumMemoryHardKDF(
                time_cost=3,
                memory_cost=65536,
                parallelism=4
            )
            hash = kdf.derive(password, salt=salt)
            verified = kdf.verify(password, hash)
            """,
            parameters={
                "time_cost": "int - Iteration count",
                "memory_cost": "int - Memory in KB",
                "parallelism": "int - Thread count"
            },
            returns="Derived key hash with embedded parameters",
            security_properties=[
                "ASIC-resistant",
                "GPU-resistant",
                "Side-channel hardened"
            ],
            exceptions=["InvalidPasswordError", "ParameterError"],
            compatibility_notes=["OWASP recommended parameters"]
        )
        
        self._apis["hkdf_engine"] = CryptoAPIEndpoint(
            name="PostQuantumHKDFEngine",
            module="post_quantum_secure_key_derivation_engine_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.0.0",
            algorithm_standard="RFC 5869",
            nist_status="STANDARDIZED",
            description="HMAC-based Extract-and-Expand key derivation",
            usage_example="""
            hkdf = PostQuantumHKDFEngine(hash_algorithm="SHA3-512")
            derived = hkdf.derive_key(
                input_keying_material=shared_secret,
                salt=salt,
                info=b"tls13 key expansion",
                length=32
            )
            """,
            parameters={
                "hash_algorithm": "str - Hash function",
                "length": "int - Output bytes"
            },
            returns="Cryptographically strong derived key",
            security_properties=["PRF secure", "Context binding via info parameter"],
            compatibility_notes=["TLS 1.3, Signal protocol compatible"]
        )
        
        # ==================== SECURE RANDOM GENERATION ====================
        
        self._apis["secure_random"] = CryptoAPIEndpoint(
            name="PostQuantumSecureRandomGenerator",
            module="post_quantum_secure_random_generator_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="1.8.0",
            algorithm_standard="NIST SP 800-90A",
            nist_status="CERTIFIED",
            description="Cryptographically secure random number generator",
            usage_example="""
            rng = PostQuantumSecureRandomGenerator(entropy_source="system")
            key_material = rng.generate_bytes(32)  # 256-bit key
            iv = rng.generate_bytes(12)  # GCM IV
            nonce = rng.generate_uniform_int(low=0, high=2**64)
            """,
            parameters={"length": "int - Bytes to generate"},
            returns="Cryptographically secure random bytes",
            security_properties=[
                "Prediction-resistant",
                "Backtracking-resistant",
                "Multiple entropy sources"
            ],
            compatibility_notes=[
                "Uses os.urandom / BCryptGenRandom",
                "FIPS 140-3 certified when available"
            ]
        )
        
        # ==================== KEY MANAGEMENT ====================
        
        self._apis["key_lifecycle_manager"] = CryptoAPIEndpoint(
            name="PostQuantumKeyLifecycleManager",
            module="post_quantum_key_lifecycle_management_engine_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.3.0",
            algorithm_standard="NIST SP 800-57",
            nist_status="RECOMMENDED",
            description="Complete key lifecycle management (gen/rotate/revoke/archive)",
            usage_example="""
            klm = PostQuantumKeyLifecycleManager()
            key_id = klm.generate_key(
                key_type="kem",
                algorithm="Kyber-768",
                owner="service-x"
            )
            klm.rotate_key(key_id)
            klm.revoke_key(key_id, reason="compromise")
            """,
            parameters={
                "key_type": "str - kem/sign/kdf",
                "algorithm": "str - Specific algorithm"
            },
            returns="Key identifier and metadata",
            security_properties=[
                "Key versioning",
                "Audit logging",
                "Secure deletion"
            ],
            compatibility_notes=["HSM integration ready"]
        )
        
        self._apis["key_rotation_service"] = CryptoAPIEndpoint(
            name="PostQuantumKeyRotationService",
            module="post_quantum_key_management_rotation_service_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.4.0",
            description="Automated key rotation with zero-downtime",
            usage_example="""
            rotator = PostQuantumKeyRotationService()
            rotator.schedule_rotation(
                key_id="key-123",
                cron="0 0 * * *",  # Daily
                grace_period_seconds=3600
            )
            """,
            parameters={
                "grace_period": "int - Overlap for key migration"
            },
            returns="Rotation schedule confirmation",
            compatibility_notes=["Grace period prevents downtime during rotation"]
        )
        
        # ==================== SECURITY HARDENING ====================
        
        self._apis["side_channel_resistant"] = CryptoAPIEndpoint(
            name="SideChannelResistantKeyWrapper",
            module="post_quantum_side_channel_attack_resistant_key_wrapper_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.1.0",
            algorithm_standard="NIST SP 800-186",
            description="Side-channel attack resistant key operations",
            usage_example="""
            wrapper = SideChannelResistantKeyWrapper()
            wrapped = wrapper.wrap_key(plaintext_key, wrapping_key)
            unwrapped = wrapper.unwrap_key(wrapped, wrapping_key)
            # All operations use constant-time, branch-free implementations
            """,
            parameters={"key": "bytes - Key material"},
            returns="Wrapped key material",
            security_properties=[
                "Constant-time execution",
                "Branch-free logic",
                "Cache-timing resistant",
                "Power analysis mitigation"
            ],
            compatibility_notes=["FIPS 140-3 Level 3 requirements met"]
        )
        
        self._apis["rate_limiter_dos"] = CryptoAPIEndpoint(
            name="AdaptiveRateLimitingDoSProtection",
            module="crypto_security_hardening_adaptive_rate_limiting_dos_protection_v11_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.2.0",
            description="Adaptive rate limiting for crypto operation DoS protection",
            usage_example="""
            protector = AdaptiveRateLimitingDoSProtection(
                max_operations_per_second=1000,
                adaptive_detection=True
            )
            if protector.allow_operation(client_ip):
                result = perform_crypto_operation()
            """,
            parameters={
                "client_id": "str - Client identifier",
                "operation_cost": "int - Computational cost units"
            },
            returns="bool - Operation allowed",
            security_properties=[
                "Adaptive thresholding",
                "Attack pattern detection",
                "Token bucket algorithm"
            ]
        )
        
        # ==================== ZERO-KNOWLEDGE PROOFS ====================
        
        self._apis["zkp_verifier"] = CryptoAPIEndpoint(
            name="PostQuantumZeroKnowledgeProofVerifier",
            module="post_quantum_zero_knowledge_proof_verifier_engine_2026_june",
            stability=StabilityLevel.EXPERIMENTAL,
            version_introduced="2.5.0",
            algorithm_standard="NIST SP 800-186 (draft)",
            nist_status="RESEARCH",
            description="Post-quantum zero-knowledge proof verification",
            usage_example="""
            verifier = PostQuantumZeroKnowledgeProofVerifier(scheme="Fiat-Shamir")
            proof = prover.generate_proof(statement, witness)
            is_valid = verifier.verify(proof, statement)
            """,
            parameters={
                "proof": "bytes - ZKP proof",
                "statement": "bytes - Public statement"
            },
            returns="Verification result boolean",
            security_properties=[
                "Zero-knowledge property",
                "Computational soundness",
                "Quantum-resistant"
            ],
            compatibility_notes=["EXPERIMENTAL: Scheme under active research"],
            migration_guide="API expected to stabilize in v3.0"
        )
        
        # ==================== MULTI-PARTY COMPUTATION ====================
        
        self._apis["secure_mpc_engine"] = CryptoAPIEndpoint(
            name="PostQuantumSecureMPCEngine",
            module="post_quantum_secure_mpc_engine_v33_2026_june",
            stability=StabilityLevel.EXPERIMENTAL,
            version_introduced="2.5.0",
            description="Secure multi-party computation for threshold cryptography",
            usage_example="""
            mpc = PostQuantumSecureMPCEngine(parties=3, threshold=2)
            # Distributed key generation across parties
            partial_keys = mpc.generate_distributed_keypair()
            # Threshold signing
            signature_shares = []
            for party in parties:
                share = party.sign(message, partial_key)
                signature_shares.append(share)
            full_signature = mpc.combine_shares(signature_shares)
            """,
            parameters={
                "parties": "int - Total participants",
                "threshold": "int - Required for reconstruction"
            },
            returns="Combined cryptographic result",
            security_properties=[
                "t-out-of-n threshold",
                "Privacy preserving",
                "No single point of failure"
            ],
            compatibility_notes=["EXPERIMENTAL: Network protocol may change"]
        )
        
        # ==================== MIGRATION TOOLS ====================
        
        self._apis["migration_assessor"] = CryptoAPIEndpoint(
            name="PostQuantumMigrationReadinessAssessor",
            module="post_quantum_migration_readiness_assessor_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.4.0",
            description="Assess crypto infrastructure PQ migration readiness",
            usage_example="""
            assessor = PostQuantumMigrationReadinessAssessor()
            report = assessor.assess_system({
                "algorithms": ["RSA-2048", "ECDSA-P256"],
                "key_sizes": {"RSA": 2048, "ECC": 256},
                "protocols": ["TLS 1.2", "SSH"]
            })
            print(f"Readiness score: {report['overall_score']}/100")
            """,
            parameters={"system_info": "Dict - Current crypto inventory"},
            returns="Migration readiness assessment with recommendations",
            compatibility_notes=["Maps to NIST PQ migration timeline"]
        )
        
        self._apis["cert_transparency_auditor"] = CryptoAPIEndpoint(
            name="PostQuantumCertificateTransparencyAuditor",
            module="post_quantum_certificate_transparency_log_auditor_2026_june",
            stability=StabilityLevel.STABLE,
            version_introduced="2.4.0",
            description="Audit CT logs for post-quantum certificate adoption",
            usage_example="""
            auditor = PostQuantumCertificateTransparencyAuditor()
            results = auditor.audit_domain("example.com")
            pq_certs = results["pq_enabled_certificates"]
            """,
            parameters={"domain": "str - Domain to audit"},
            returns="CT log audit results with PQ status",
            compatibility_notes=["RFC 6962 compliant"]
        )
        
        # ==================== DEPRECATED APIs ====================
        
        self._apis["legacy_rsa_wrapper"] = CryptoAPIEndpoint(
            name="LegacyRSAWrapper",
            module="legacy_crypto_compat_layer",
            stability=StabilityLevel.DEPRECATED,
            version_introduced="1.0.0",
            version_deprecated="2.0.0",
            deprecation_scheduled="3.0.0",
            description="LEGACY: RSA wrapper for classical-only systems",
            usage_example="# DEPRECATED - Use PostQuantumHybridKEMEngine instead",
            migration_guide="""
            MIGRATION REQUIRED BY v3.0:
            
            BEFORE (deprecated):
                wrapper = LegacyRSAWrapper()
                ciphertext = wrapper.encrypt(data, public_key)
            
            AFTER (current - quantum-safe):
                kem = PostQuantumHybridKEMEngine(algorithm="Kyber-768")
                pk, sk = kem.generate_keypair()
                ct, ss = kem.encapsulate(pk)
            """,
            compatibility_notes=[
                "RSA is NOT quantum-resistant",
                "Migrate immediately to PQ algorithms"
            ]
        )
    
    def get_api(self, name: str) -> Optional[CryptoAPIEndpoint]:
        """Get crypto API metadata by name"""
        return self._apis.get(name)
    
    def list_apis(self, stability: Optional[StabilityLevel] = None) -> List[CryptoAPIEndpoint]:
        """List all crypto APIs, optionally filtered by stability level"""
        apis = list(self._apis.values())
        if stability:
            apis = [a for a in apis if a.stability == stability]
        return apis
    
    def get_nist_algorithms(self, status: str = None) -> List[CryptoAPIEndpoint]:
        """List APIs filtered by NIST standardization status"""
        apis = self.list_apis()
        if status:
            apis = [a for a in apis if status.upper() in a.nist_status.upper()]
        return apis
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get count of APIs by stability level"""
        summary = {}
        for level in StabilityLevel:
            count = sum(1 for a in self._apis.values() if a.stability == level)
            summary[level.value] = count
        return summary
    
    def generate_markdown_docs(self) -> str:
        """Generate comprehensive markdown documentation"""
        summary = self.get_stability_summary()
        
        md = f"""# QuantumCrypt-AI API Stability Documentation v27\n\n"""
        md += f"**Generated:** {self.generated_at}\n\n"
        md += "## Stability Summary\n\n"
        md += "| Level | Count | Description |\n"
        md += "|-------|-------|-------------|\n"
        md += f"| STABLE | {summary['STABLE']} | Production-ready, frozen API |\n"
        md += f"| EXPERIMENTAL | {summary['EXPERIMENTAL']} | May change, use with caution |\n"
        md += f"| DEPRECATED | {summary['DEPRECATED']} | Schedule for removal |\n"
        md += f"| LEGACY | {summary['LEGACY']} | Maintained for compatibility |\n\n"
        
        md += "## NIST Algorithm Status\n\n"
        md += "| Algorithm | NIST Status | Standard | Stability |\n"
        md += "|-----------|-------------|----------|-----------|\n"
        for api in self.list_apis():
            if api.nist_status:
                md += f"| {api.name} | {api.nist_status} | {api.algorithm_standard} | {api.stability.value} |\n"
        md += "\n"
        
        md += "## STABLE APIs (Production Ready)\n\n"
        for api in self.list_apis(StabilityLevel.STABLE):
            md += f"### {api.name}\n"
            md += f"- **Module:** `{api.module}`\n"
            md += f"- **Since:** v{api.version_introduced}\n"
            md += f"- **NIST:** {api.nist_status}\n"
            md += f"- **Description:** {api.description}\n"
            if api.security_properties:
                md += f"- **Security:** {', '.join(api.security_properties)}\n"
            if api.usage_example:
                md += f"- **Example:**\n```python{api.usage_example}\n```\n"
            md += "\n"
        
        md += "## DEPRECATION NOTICE\n\n"
        deprecated = self.list_apis(StabilityLevel.DEPRECATED)
        for api in deprecated:
            md += f"### ⚠️  {api.name} - DEPRECATED\n"
            md += f"- **Deprecated since:** v{api.version_deprecated}\n"
            md += f"- **Removal scheduled:** v{api.deprecation_scheduled}\n"
            md += f"- **Migration Guide:**\n{api.migration_guide}\n\n"
        
        return md
    
    def get_security_properties_matrix(self) -> Dict[str, List[str]]:
        """Get security properties matrix for all APIs"""
        matrix = {}
        for api in self._apis.values():
            matrix[api.name] = api.security_properties
        return matrix
    
    def validate_migration_readiness(self, current_algorithms: List[str]) -> Dict[str, Any]:
        """Validate migration readiness for a set of algorithms"""
        issues = []
        recommendations = []
        pq_ready = []
        needs_migration = []
        
        for algo in current_algorithms:
            if algo in ["RSA", "ECDSA", "DH"]:
                needs_migration.append(algo)
                recommendations.append(f"Migrate {algo} to post-quantum alternative")
            elif algo in ["Kyber", "CRYSTALS-Kyber", "Dilithium"]:
                pq_ready.append(algo)
        
        return {
            "pq_ready_algorithms": pq_ready,
            "needs_migration": needs_migration,
            "issues": issues,
            "recommendations": recommendations,
            "readiness_score": max(0, 100 - (len(needs_migration) * 20)),
            "overall_assessment": "READY" if len(needs_migration) == 0 else "ACTION_REQUIRED"
        }


# Singleton instance for global usage
_crypto_catalog = None

def get_crypto_stability_catalog() -> QuantumCryptAPIStabilityCatalog:
    """Get the global crypto API stability catalog singleton"""
    global _crypto_catalog
    if _crypto_catalog is None:
        _crypto_catalog = QuantumCryptAPIStabilityCatalog()
    return _crypto_catalog


def crypto_api_stability(level: StabilityLevel, since: str, nist_status: str = ""):
    """
    Decorator to mark crypto API stability level
    
    Usage:
        @crypto_api_stability(StabilityLevel.STABLE, since="2.0.0", nist_status="FINAL")
        def quantum_safe_operation():
            pass
    """
    def decorator(func: Callable) -> Callable:
        func._crypto_api_stability = {
            "level": level,
            "since": since,
            "nist_status": nist_status,
            "documented": True
        }
        return func
    return decorator


# Export public interface
__all__ = [
    "StabilityLevel",
    "CryptoAPIEndpoint",
    "QuantumCryptAPIStabilityCatalog",
    "get_crypto_stability_catalog",
    "crypto_api_stability"
]
