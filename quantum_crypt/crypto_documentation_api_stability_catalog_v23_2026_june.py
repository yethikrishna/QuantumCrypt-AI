"""
QuantumCrypt AI - Comprehensive Crypto API Documentation & Stability Catalog v23
================================================================================
STABILITY LEVEL: STABLE
LAST UPDATED: 2026-06-24
MODULE: quantum_crypt.crypto_documentation_api_stability_catalog_v23

This module provides comprehensive API documentation, usage examples,
and stability markers for all QuantumCrypt post-quantum crypto modules.

API STABILITY CLASSIFICATION:
- STABLE: Production-ready, backward compatible, no breaking changes
- EXPERIMENTAL: Under active development, API may change
- DEPRECATED: Scheduled for removal, migrate to alternatives
- LEGACY: Maintained for backward compatibility only
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
import json
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


@dataclass
class CryptoModuleDocumentation:
    """Documentation entry for a QuantumCrypt cryptographic module"""
    module_name: str
    stability_level: StabilityLevel
    description: str
    primary_class: str
    algorithm_type: str  # KEM, Signature, Hash, Symmetric, etc.
    nist_status: str  # Standardized, Finalist, Candidate, Research
    key_methods: List[str]
    usage_examples: List[str]
    dependencies: List[str]
    security_level: str = "NIST Security Level 1"
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    version: str = "1.0.0"


class QuantumCryptAPIDocumentationCatalog:
    """
    Comprehensive API Documentation Catalog for QuantumCrypt AI
    
    STABILITY LEVEL: STABLE
    
    This catalog provides:
    1. Complete post-quantum module inventory with stability classifications
    2. NIST standardization status for each algorithm
    3. Detailed usage examples with security parameters
    4. Algorithm comparison and recommendation guides
    5. Dependency graphs and integration patterns
    6. Deprecation notices and migration paths
    
    Usage Example:
        >>> catalog = QuantumCryptAPIDocumentationCatalog()
        >>> catalog.initialize()
        >>> docs = catalog.get_module_docs("hybrid_kem_engine")
        >>> print(docs.nist_status)
    """
    
    def __init__(self):
        self._modules: Dict[str, CryptoModuleDocumentation] = {}
        self._initialized = False
        self._catalog_version = "v23"
        self._generation_date = datetime.now().isoformat()
    
    def initialize(self) -> bool:
        """
        Initialize the documentation catalog with all crypto module entries
        
        Returns:
            bool: True if initialization successful
            
        STABILITY: STABLE
        """
        self._register_kem_modules()
        self._register_signature_modules()
        self._register_certificate_modules()
        self._register_entropy_modules()
        self._register_utility_modules()
        self._initialized = True
        return True
    
    def _register_kem_modules(self):
        """Register Key Encapsulation Mechanism modules"""
        
        # Hybrid KEM Engine - STABLE
        self._modules["hybrid_kem_engine"] = CryptoModuleDocumentation(
            module_name="post_quantum_hybrid_kem_engine_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Hybrid Post-Quantum Key Encapsulation Mechanism combining classical ECDH with CRYSTALS-Kyber for forward-secret key exchange resistant to quantum computer attacks.",
            primary_class="HybridKEMEngine",
            algorithm_type="Key Encapsulation Mechanism (KEM)",
            nist_status="NIST Standardized (FIPS 203)",
            security_level="NIST Security Level 5",
            key_methods=[
                "generate_keypair() -> Tuple[bytes, bytes]",
                "encapsulate(public_key: bytes) -> Tuple[bytes, bytes]",
                "decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes",
                "perform_hybrid_key_exchange(peer_pubkey: bytes) -> Dict",
                "get_security_parameters() -> Dict"
            ],
            usage_examples=[
                """kem = HybridKEMEngine()
pub_key, sec_key = kem.generate_keypair()
ciphertext, shared_secret = kem.encapsulate(pub_key)
recovered_secret = kem.decapsulate(ciphertext, sec_key)
assert shared_secret == recovered_secret""",
                """# TLS 1.3 style key exchange
client_kem = HybridKEMEngine()
server_kem = HybridKEMEngine()
client_pub, client_sec = client_kem.generate_keypair()
result = server_kem.perform_hybrid_key_exchange(client_pub)"""
            ],
            dependencies=["os", "hashlib", "hmac", "secrets"]
        )
        
        # Hybrid KEM Session Manager - STABLE
        self._modules["hybrid_kem_session_manager"] = CryptoModuleDocumentation(
            module_name="post_quantum_hybrid_kem_session_manager_enhanced_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Session management for hybrid KEM connections with key rotation, session resumption, and forward secrecy guarantees.",
            primary_class="HybridKEMSessionManager",
            algorithm_type="Session Management + KEM",
            nist_status="NIST Standardized",
            security_level="NIST Security Level 5",
            key_methods=[
                "create_session(peer_id: str) -> Dict",
                "rotate_session_keys(session_id: str) -> bool",
                "encrypt_session_data(session_id: str, data: bytes) -> bytes",
                "decrypt_session_data(session_id: str, data: bytes) -> bytes",
                "close_session(session_id: str) -> bool"
            ],
            usage_examples=[
                """manager = HybridKEMSessionManager()
session = manager.create_session("server_001")
encrypted = manager.encrypt_session_data(session['id'], b"Secret message")
decrypted = manager.decrypt_session_data(session['id'], encrypted)"""
            ],
            dependencies=["time", "uuid", "hashlib", "secrets"]
        )
    
    def _register_signature_modules(self):
        """Register Digital Signature modules"""
        
        # Dilithium Signature Engine - STABLE
        self._modules["dilithium_signature_engine"] = CryptoModuleDocumentation(
            module_name="post_quantum_dilithium_signature_engine_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="CRYSTALS-Dilithium post-quantum digital signature algorithm - NIST standardized lattice-based signature scheme.",
            primary_class="DilithiumSignatureEngine",
            algorithm_type="Digital Signature",
            nist_status="NIST Standardized (FIPS 204)",
            security_level="NIST Security Level 3",
            key_methods=[
                "generate_keypair() -> Tuple[bytes, bytes]",
                "sign(message: bytes, secret_key: bytes) -> bytes",
                "verify(message: bytes, signature: bytes, public_key: bytes) -> bool",
                "batch_verify(messages: List[bytes], signatures: List[bytes], pubkeys: List[bytes]) -> List[bool]"
            ],
            usage_examples=[
                """signer = DilithiumSignatureEngine()
pub_key, sec_key = signer.generate_keypair()
signature = signer.sign(b"Important document", sec_key)
valid = signer.verify(b"Important document", signature, pub_key)
assert valid == True""",
                """# Batch verification for performance
results = signer.batch_verify(messages, sigs, pubkeys)"""
            ],
            dependencies=["hashlib", "secrets"]
        )
        
        # Digital Signature Batch Verifier - STABLE
        self._modules["digital_signature_batch_verifier"] = CryptoModuleDocumentation(
            module_name="post_quantum_digital_signature_batch_verifier_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Optimized batch verification for post-quantum digital signatures with performance optimizations and parallel processing.",
            primary_class="DigitalSignatureBatchVerifier",
            algorithm_type="Signature Verification",
            nist_status="NIST Standardized",
            security_level="NIST Security Level 3",
            key_methods=[
                "batch_verify_signatures(verification_tasks: List[Dict]) -> Dict",
                "parallel_verify(tasks: List[Dict], workers: int) -> Dict",
                "get_verification_stats() -> Dict"
            ],
            usage_examples=[
                """verifier = DigitalSignatureBatchVerifier()
tasks = [
    {'message': m1, 'signature': s1, 'pubkey': pk1},
    {'message': m2, 'signature': s2, 'pubkey': pk2}
]
results = verifier.batch_verify_signatures(tasks)
print(f"Valid: {results['all_valid']}")"""
            ],
            dependencies=["concurrent.futures", "time"]
        )
    
    def _register_certificate_modules(self):
        """Register Certificate and PKI modules"""
        
        # Certificate Chain Builder - STABLE
        self._modules["certificate_chain_builder"] = CryptoModuleDocumentation(
            module_name="post_quantum_certificate_chain_builder_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Builds and validates post-quantum certificate chains with hybrid signature support and PQ X.509 compatibility.",
            primary_class="PQCryptoCertificateChainBuilder",
            algorithm_type="X.509 Certificate Chain",
            nist_status="Standardized",
            security_level="NIST Security Level 3",
            key_methods=[
                "build_certificate_chain(end_entity_cert: Dict, intermediates: List[Dict]) -> Dict",
                "validate_certificate_chain(chain: List[Dict]) -> Dict",
                "check_revocation_status(cert: Dict) -> str",
                "extract_public_key(cert: Dict) -> bytes"
            ],
            usage_examples=[
                """builder = PQCryptoCertificateChainBuilder()
chain = builder.build_certificate_chain(
    end_entity_cert=server_cert,
    intermediates=[ca_cert]
)
validation = builder.validate_certificate_chain(chain)
if validation['is_valid']:
    print("Certificate chain trusted")"""
            ],
            dependencies=["datetime", "json", "hashlib"]
        )
        
        # Certificate Chain Validator - STABLE
        self._modules["certificate_chain_validator"] = CryptoModuleDocumentation(
            module_name="post_quantum_certificate_chain_validator_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Comprehensive post-quantum certificate chain validation with CRL checking, OCSP support, and policy enforcement.",
            primary_class="PQCryptoCertificateChainValidator",
            algorithm_type="Certificate Validation",
            nist_status="Standardized",
            security_level="NIST Security Level 3",
            key_methods=[
                "validate_full_chain(cert_chain: List[Dict], trust_anchors: List[Dict]) -> Dict",
                "check_name_constraints(cert: Dict, constraints: Dict) -> bool",
                "validate_policy_constraints(chain: List[Dict]) -> Dict",
                "get_validation_path(chain: List[Dict]) -> List[str]"
            ],
            usage_examples=[
                """validator = PQCryptoCertificateChainValidator()
result = validator.validate_full_chain(
    cert_chain=received_chain,
    trust_anchors=root_certs
)
if result['trusted']:
    pubkey = validator.extract_public_key(chain[0])"""
            ],
            dependencies=["datetime", "ipaddress", "re"]
        )
        
        # Certificate Transparency Logger - STABLE
        self._modules["certificate_transparency_logger"] = CryptoModuleDocumentation(
            module_name="post_quantum_certificate_transparency_logger_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Certificate Transparency (CT) logging for post-quantum certificates with Merkle tree inclusion proofs.",
            primary_class="PQCryptoCertificateTransparencyLogger",
            algorithm_type="Certificate Transparency",
            nist_status="RFC 6962 Compliant",
            security_level="NIST Security Level 3",
            key_methods=[
                "submit_certificate_to_log(cert: Dict, log_url: str) -> Dict",
                "verify_sct(signed_certificate_timestamp: Dict) -> bool",
                "build_merkle_inclusion_proof(leaf_index: int) -> Dict",
                "verify_merkle_proof(proof: Dict, root_hash: bytes) -> bool"
            ],
            usage_examples=[
                """ct_logger = PQCryptoCertificateTransparencyLogger()
sct = ct_logger.submit_certificate_to_log(new_cert, ct_log_url)
if ct_logger.verify_sct(sct):
    print("Certificate logged in CT")"""
            ],
            dependencies=["hashlib", "base64", "json"]
        )
    
    def _register_entropy_modules(self):
        """Register Entropy and Randomness modules"""
        
        # Entropy Beacon Distillation Engine - STABLE
        self._modules["entropy_beacon_distillation_engine"] = CryptoModuleDocumentation(
            module_name="post_quantum_entropy_beacon_distillation_engine_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Cryptographically secure entropy distillation engine with multiple entropy sources, health testing, and NIST SP 800-90B compliance.",
            primary_class="EntropyBeaconDistillationEngine",
            algorithm_type="Cryptographically Secure RNG",
            nist_status="SP 800-90B, SP 800-90C",
            security_level="NIST Certified",
            key_methods=[
                "get_random_bytes(num_bytes: int) -> bytes",
                "add_entropy_source(source_name: str, entropy_data: bytes)",
                "run_health_tests() -> Dict",
                "reseed(additional_input: bytes = None) -> bool",
                "get_entropy_estimate() -> float"
            ],
            usage_examples=[
                """rng = EntropyBeaconDistillationEngine()
rng.add_entropy_source("hw_rng", hardware_noise)
health = rng.run_health_tests()
if health['passed']:
    key_material = rng.get_random_bytes(32)"""
            ],
            dependencies=["secrets", "os", "statistics", "time"]
        )
        
        # Entropy Health Monitor - STABLE
        self._modules["entropy_health_monitor"] = CryptoModuleDocumentation(
            module_name="post_quantum_entropy_health_monitor_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Continuous health monitoring for entropy sources with adaptive reseeding and stuck detection.",
            primary_class="EntropyHealthMonitor",
            algorithm_type="RNG Health Testing",
            nist_status="SP 800-90B Compliant",
            security_level="NIST Certified",
            key_methods=[
                "monitor_continuous(entropy_samples: List[bytes]) -> Dict",
                "detect_repetition_failure(samples: List[bytes]) -> bool",
                "detect_adaptive_proportion_failure(samples: List[bytes]) -> bool",
                "get_health_status() -> str"
            ],
            usage_examples=[
                """monitor = EntropyHealthMonitor()
status = monitor.monitor_continuous(entropy_samples)
if status['warning']:
    rng.reseed()  # Force reseed on health warning"""
            ],
            dependencies=["statistics", "collections", "math"]
        )
    
    def _register_utility_modules(self):
        """Register utility and integration modules"""
        
        # Crypto Agility Migration Engine - STABLE
        self._modules["crypto_agility_migration_engine"] = CryptoModuleDocumentation(
            module_name="post_quantum_crypto_agility_migration_engine_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Crypto agility engine for seamless algorithm migration with automatic fallback and version negotiation.",
            primary_class="CryptoAgilityMigrationEngine",
            algorithm_type="Crypto Agility Framework",
            nist_status="Framework",
            security_level="Multiple",
            key_methods=[
                "negotiate_algorithm(client_supported: List[str], server_priority: List[str]) -> str",
                "migrate_keys(old_algorithm: str, new_algorithm: str, key_data: bytes) -> Dict",
                "get_supported_algorithms() -> List[str]",
                "register_algorithm(name: str, implementation: Any) -> bool"
            ],
            usage_examples=[
                """agility = CryptoAgilityMigrationEngine()
selected = agility.negotiate_algorithm(
    client_supported=["Kyber-768", "Kyber-512", "X25519"],
    server_priority=["Kyber-768", "X25519"]
)
print(f"Negotiated: {selected}")"""
            ],
            dependencies=["typing", "packaging.version"]
        )
        
        # Algorithm Recommendation Engine - STABLE
        self._modules["algorithm_recommendation_engine"] = CryptoModuleDocumentation(
            module_name="post_quantum_algorithm_recommendation_selection_engine_2026_june",
            stability_level=StabilityLevel.STABLE,
            description="Intelligent algorithm recommendation engine based on use case, security requirements, and performance constraints.",
            primary_class="PQAlgorithmRecommendationEngine",
            algorithm_type="Recommendation Engine",
            nist_status="Framework",
            security_level="Adaptive",
            key_methods=[
                "recommend_kem(use_case: str, security_requirements: Dict) -> str",
                "recommend_signature(use_case: str, performance_target: Dict) -> str",
                "compare_algorithms(algorithms: List[str]) -> Dict",
                "get_algorithm_properties(algorithm_name: str) -> Dict"
            ],
            usage_examples=[
                """recommender = PQAlgorithmRecommendationEngine()
kem = recommender.recommend_kem(
    use_case="TLS_server",
    security_requirements={"level": "high", "forward_secrecy": True}
)
print(f"Recommended KEM: {kem}")"""
            ],
            dependencies=["typing", "json"]
        )
    
    def get_module_docs(self, module_name: str) -> Optional[CryptoModuleDocumentation]:
        """
        Get documentation for a specific crypto module
        
        Args:
            module_name: Name of the module (without version suffix)
            
        Returns:
            CryptoModuleDocumentation object or None if not found
            
        STABILITY: STABLE
        """
        if not self._initialized:
            self.initialize()
        
        # Try exact match first
        if module_name in self._modules:
            return self._modules[module_name]
        
        # Try partial match
        for key in self._modules:
            if module_name.lower() in key.lower():
                return self._modules[key]
        
        return None
    
    def get_all_modules(self) -> List[str]:
        """
        Get list of all documented crypto modules
        
        Returns:
            List of module names
            
        STABILITY: STABLE
        """
        if not self._initialized:
            self.initialize()
        return list(self._modules.keys())
    
    def get_modules_by_stability(self, level: StabilityLevel) -> List[CryptoModuleDocumentation]:
        """
        Get all modules with specific stability level
        
        Args:
            level: StabilityLevel to filter by
            
        Returns:
            List of CryptoModuleDocumentation objects
            
        STABILITY: STABLE
        """
        if not self._initialized:
            self.initialize()
        return [m for m in self._modules.values() if m.stability_level == level]
    
    def get_modules_by_algorithm_type(self, alg_type: str) -> List[CryptoModuleDocumentation]:
        """
        Get modules by algorithm type
        
        Args:
            alg_type: Algorithm type (KEM, Signature, etc.)
            
        Returns:
            List of matching CryptoModuleDocumentation
            
        STABILITY: STABLE
        """
        if not self._initialized:
            self.initialize()
        return [m for m in self._modules.values() 
                if alg_type.lower() in m.algorithm_type.lower()]
    
    def generate_catalog_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive catalog report with statistics
        
        Returns:
            Dictionary with catalog statistics
            
        STABILITY: STABLE
        """
        if not self._initialized:
            self.initialize()
        
        stats = {
            "catalog_version": self._catalog_version,
            "generation_date": self._generation_date,
            "total_modules": len(self._modules),
            "stability_breakdown": {
                level.value: len(self.get_modules_by_stability(level))
                for level in StabilityLevel
            },
            "algorithm_type_breakdown": {
                "KEM": len(self.get_modules_by_algorithm_type("KEM")),
                "Signature": len(self.get_modules_by_algorithm_type("Signature")),
                "Certificate": len(self.get_modules_by_algorithm_type("Certificate")),
                "Entropy": len(self.get_modules_by_algorithm_type("Entropy")),
            },
            "modules": [
                {
                    "name": name,
                    "stability": mod.stability_level.value,
                    "nist_status": mod.nist_status,
                    "security_level": mod.security_level,
                    "algorithm_type": mod.algorithm_type,
                    "primary_class": mod.primary_class
                }
                for name, mod in self._modules.items()
            ]
        }
        return stats
    
    def export_catalog_json(self, filepath: str) -> bool:
        """
        Export catalog to JSON file
        
        Args:
            filepath: Output file path
            
        Returns:
            True if successful
            
        STABILITY: STABLE
        """
        report = self.generate_catalog_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        return True
    
    def get_quick_start_guide(self) -> str:
        """
        Get quick start guide for QuantumCrypt API
        
        Returns:
            Quick start guide text
            
        STABILITY: STABLE
        """
        return """
QUANTUMCRYPT AI - QUICK START GUIDE
====================================

1. POST-QUANTUM KEY EXCHANGE:
   from quantum_crypt.post_quantum_hybrid_kem_engine_2026_june import HybridKEMEngine
   
   kem = HybridKEMEngine()
   pub_key, sec_key = kem.generate_keypair()
   ciphertext, shared_secret = kem.encapsulate(pub_key)

2. DIGITAL SIGNATURES:
   from quantum_crypt.post_quantum_dilithium_signature_engine_2026_june import DilithiumSignatureEngine
   
   signer = DilithiumSignatureEngine()
   pub_key, sec_key = signer.generate_keypair()
   signature = signer.sign(b"Document", sec_key)

3. RECOMMENDED PRODUCTION ALGORITHMS:
   - CRYSTALS-Kyber (KEM) - NIST FIPS 203
   - CRYSTALS-Dilithium (Signature) - NIST FIPS 204
   - Hybrid Classical+PQ for backward compatibility

4. SECURITY BEST PRACTICES:
   - Always use NIST Security Level 3+ for production
   - Enable forward secrecy with frequent key rotation
   - Use certificate transparency for all PQ certificates
"""


# Module export
__all__ = [
    'QuantumCryptAPIDocumentationCatalog',
    'CryptoModuleDocumentation',
    'StabilityLevel',
]

# Auto-initialize for import-time access
_default_catalog = QuantumCryptAPIDocumentationCatalog()
_default_catalog.initialize()
