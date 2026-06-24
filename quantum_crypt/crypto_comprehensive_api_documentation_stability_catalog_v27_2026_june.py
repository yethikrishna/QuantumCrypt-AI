"""
QuantumCrypt AI - Comprehensive API Documentation & Stability Catalog v27
========================================================================
STABILITY MARKERS: STABLE | EXPERIMENTAL | DEPRECATED

This module provides comprehensive documentation, usage examples, and API stability
markers for all QuantumCrypt post-quantum cryptography modules. This is an ADD-ONLY
module - no existing production code is modified.

API STABILITY LEGEND:
- STABLE: API is frozen, backward compatible, production-ready
- EXPERIMENTAL: API may change, suitable for testing only
- DEPRECATED: Will be removed in future version, use alternative

LAST UPDATED: 2026-06-24
SESSION: 134
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
import json
from datetime import datetime


class StabilityLevel(Enum):
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


class NISTSecurityLevel(Enum):
    LEVEL_1 = "NIST Security Level 1 (128-bit security)"
    LEVEL_3 = "NIST Security Level 3 (192-bit security)"
    LEVEL_5 = "NIST Security Level 5 (256-bit security)"


@dataclass
class CryptoModuleDocumentation:
    module_name: str
    stability: StabilityLevel
    algorithm_family: str
    nist_security_level: NISTSecurityLevel
    description: str
    primary_use_cases: List[str]
    key_classes: List[str]
    key_methods: List[str]
    key_sizes: Dict[str, int]
    performance_characteristics: str
    quantum_resistant: bool
    fips_compliant: bool
    thread_safe: bool
    dependencies: List[str]
    example_usage: str
    since_version: str
    standard_reference: str
    deprecation_notice: Optional[str] = None
    replacement_module: Optional[str] = None


@dataclass
class CryptoAPICatalog:
    catalog_version: str = "v27"
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    modules: Dict[str, CryptoModuleDocumentation] = field(default_factory=dict)

    def register_module(self, doc: CryptoModuleDocumentation) -> None:
        """Register a crypto module in the API catalog."""
        self.modules[doc.module_name] = doc

    def get_quantum_resistant_modules(self) -> List[str]:
        """Get list of all quantum-resistant modules."""
        return [name for name, doc in self.modules.items() 
                if doc.quantum_resistant]

    def get_fips_compliant_modules(self) -> List[str]:
        """Get list of all FIPS compliant modules."""
        return [name for name, doc in self.modules.items() 
                if doc.fips_compliant]

    def get_stable_modules(self) -> List[str]:
        """Get list of all STABLE modules."""
        return [name for name, doc in self.modules.items() 
                if doc.stability == StabilityLevel.STABLE]

    def get_experimental_modules(self) -> List[str]:
        """Get list of all EXPERIMENTAL modules."""
        return [name for name, doc in self.modules.items() 
                if doc.stability == StabilityLevel.EXPERIMENTAL]

    def export_to_json(self, filepath: str) -> None:
        """Export catalog to JSON for external tools."""
        export_data = {
            "catalog_version": self.catalog_version,
            "generated_at": self.generated_at,
            "modules": {
                name: {
                    "stability": doc.stability.value,
                    "algorithm_family": doc.algorithm_family,
                    "nist_security_level": doc.nist_security_level.value,
                    "quantum_resistant": doc.quantum_resistant,
                    "fips_compliant": doc.fips_compliant,
                    "since_version": doc.since_version
                }
                for name, doc in self.modules.items()
            }
        }
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)

    def generate_readme_summary(self) -> str:
        """Generate README summary for quick reference."""
        stable = len(self.get_stable_modules())
        experimental = len(self.get_experimental_modules())
        pq = len(self.get_quantum_resistant_modules())
        fips = len(self.get_fips_compliant_modules())
        
        return f"""
# QuantumCrypt API Stability Summary v27

## Module Count by Stability
- ✅ **STABLE**: {stable} modules - Production ready
- ⚠️  **EXPERIMENTAL**: {experimental} modules - Testing only
- 🔐 **Post-Quantum**: {pq} modules - Quantum resistant
- 📋 **FIPS Compliant**: {fips} modules - NIST validated

## Quick Start
Use STABLE + FIPS Compliant modules for production systems.
See individual module docstrings for detailed usage examples.

Generated: {self.generated_at}
"""


def build_quantumcrypt_api_catalog_v27() -> CryptoAPICatalog:
    """
    Build the complete QuantumCrypt API Documentation & Stability Catalog v27.
    This is the authoritative source for API stability information.
    """
    catalog = CryptoAPICatalog(catalog_version="v27")

    # =========================================================================
    # STABLE MODULES - Production Ready, NIST Standardized
    # =========================================================================

    catalog.register_module(CryptoModuleDocumentation(
        module_name="kyber_key_encapsulation",
        stability=StabilityLevel.STABLE,
        algorithm_family="CRYSTALS-Kyber",
        nist_security_level=NISTSecurityLevel.LEVEL_5,
        description="NIST-standardized post-quantum Key Encapsulation Mechanism (KEM)",
        primary_use_cases=[
            "TLS 1.3 key exchange",
            "VPN tunnel establishment",
            "Hybrid key exchange with ECDHE",
            "Secure session key establishment"
        ],
        key_classes=["KyberKEM", "Kyber512", "Kyber768", "Kyber1024"],
        key_methods=["keygen()", "encapsulate()", "decapsulate()"],
        key_sizes={
            "Kyber512_public": 800,
            "Kyber512_secret": 1632,
            "Kyber512_ciphertext": 768,
            "Kyber768_public": 1184,
            "Kyber768_secret": 2400,
            "Kyber768_ciphertext": 1088,
            "Kyber1024_public": 1568,
            "Kyber1024_secret": 3168,
            "Kyber1024_ciphertext": 1568
        },
        performance_characteristics="Kyber768: ~0.05ms keygen, ~0.03ms encap/decap",
        quantum_resistant=True,
        fips_compliant=True,
        thread_safe=True,
        dependencies=[],
        example_usage="""
from quantum_crypt import Kyber768

# Generate keypair
pk, sk = Kyber768.keygen()

# Encapsulate (sender)
ciphertext, shared_secret = Kyber768.encapsulate(pk)

# Decapsulate (receiver)
recovered_secret = Kyber768.decapsulate(ciphertext, sk)

assert shared_secret == recovered_secret  # Shared secrets match
""",
        since_version="v1.0",
        standard_reference="NIST FIPS 203 (CRYSALS-Kyber)"
    ))

    catalog.register_module(CryptoModuleDocumentation(
        module_name="dilithium_digital_signature",
        stability=StabilityLevel.STABLE,
        algorithm_family="CRYSTALS-Dilithium",
        nist_security_level=NISTSecurityLevel.LEVEL_5,
        description="NIST-standardized post-quantum digital signature algorithm",
        primary_use_cases=[
            "Code signing",
            "Document authentication",
            "Certificate signatures",
            "Blockchain transaction signing"
        ],
        key_classes=["Dilithium", "Dilithium2", "Dilithium3", "Dilithium5"],
        key_methods=["keygen()", "sign()", "verify()"],
        key_sizes={
            "Dilithium2_public": 1312,
            "Dilithium2_secret": 2528,
            "Dilithium2_signature": 2420,
            "Dilithium3_public": 1952,
            "Dilithium3_secret": 4000,
            "Dilithium3_signature": 3293,
            "Dilithium5_public": 2592,
            "Dilithium5_secret": 4864,
            "Dilithium5_signature": 4595
        },
        performance_characteristics="Dilithium3: ~0.1ms keygen, ~0.3ms sign, ~0.05ms verify",
        quantum_resistant=True,
        fips_compliant=True,
        thread_safe=True,
        dependencies=[],
        example_usage="""
from quantum_crypt import Dilithium3

# Generate signing keypair
vk, sk = Dilithium3.keygen()

# Sign message
signature = Dilithium3.sign(b"Important document", sk)

# Verify signature
is_valid = Dilithium3.verify(b"Important document", signature, vk)
assert is_valid
""",
        since_version="v1.0",
        standard_reference="NIST FIPS 204 (CRYSTALS-Dilithium)"
    ))

    catalog.register_module(CryptoModuleDocumentation(
        module_name="hybrid_kem_tls",
        stability=StabilityLevel.STABLE,
        algorithm_family="Hybrid PQ + Classical",
        nist_security_level=NISTSecurityLevel.LEVEL_5,
        description="Hybrid key exchange combining Kyber with classical ECDHE",
        primary_use_cases=[
            "TLS 1.3 hybrid mode",
            "Backward compatible key exchange",
            "Gradual PQ migration",
            "Defense in depth"
        ],
        key_classes=["HybridKEM", "HybridKyberX25519", "HybridKyberP256"],
        key_methods=["hybrid_keygen()", "hybrid_encapsulate()", "hybrid_decapsulate()"],
        key_sizes={"combined_public": 1552, "combined_ciphertext": 1216},
        performance_characteristics="~0.1ms per operation (Kyber768 + X25519)",
        quantum_resistant=True,
        fips_compliant=True,
        thread_safe=True,
        dependencies=["kyber_key_encapsulation", "ecdh_classical"],
        example_usage="""
from quantum_crypt import HybridKyberX25519

# Hybrid key exchange - both post-quantum and classical security
pk_pq, pk_classical, sk_combined = HybridKyberX25519.hybrid_keygen()

# Both secrets contribute to the shared key
ct_pq, ct_classical, shared = HybridKyberX25519.hybrid_encapsulate(pk_pq, pk_classical)
recovered = HybridKyberX25519.hybrid_decapsulate(ct_pq, ct_classical, sk_combined)

assert shared == recovered
""",
        since_version="v1.1",
        standard_reference="IETF TLS WG Hybrid PQ Specification"
    ))

    catalog.register_module(CryptoModuleDocumentation(
        module_name="aes_gcm_authenticated_encryption",
        stability=StabilityLevel.STABLE,
        algorithm_family="AES-GCM",
        nist_security_level=NISTSecurityLevel.LEVEL_5,
        description="Authenticated encryption with associated data (AEAD)",
        primary_use_cases=[
            "Bulk data encryption",
            "Secure messaging",
            "File encryption",
            "Network traffic encryption"
        ],
        key_classes=["AESGCM", "AES128GCM", "AES256GCM"],
        key_methods=["encrypt()", "decrypt()", "generate_nonce()"],
        key_sizes={"AES128_key": 16, "AES256_key": 32, "nonce": 12, "tag": 16},
        performance_characteristics="AES256-GCM: ~1.5 GB/sec (hardware accelerated)",
        quantum_resistant=False,  # AES-256 is considered quantum-resistant in practice
        fips_compliant=True,
        thread_safe=True,
        dependencies=[],
        example_usage="""
from quantum_crypt import AES256GCM

key = AES256GCM.generate_key()
nonce = AES256GCM.generate_nonce()

# Encrypt with authentication
ciphertext, tag = AES256GCM.encrypt(plaintext, key, nonce, associated_data)

# Decrypt and verify authentication
try:
    plaintext = AES256GCM.decrypt(ciphertext, tag, key, nonce, associated_data)
except InvalidTag:
    print("Authentication failed - tampering detected")
""",
        since_version="v1.0",
        standard_reference="NIST FIPS 197, FIPS 800-38D"
    ))

    catalog.register_module(CryptoModuleDocumentation(
        module_name="sha3_hash_functions",
        stability=StabilityLevel.STABLE,
        algorithm_family="SHA-3 / Keccak",
        nist_security_level=NISTSecurityLevel.LEVEL_5,
        description="NIST-standardized SHA-3 hash function family",
        primary_use_cases=[
            "Cryptographic hashing",
            "Merkle tree construction",
            "Digital signature prehashing",
            "Password hashing (with salt)"
        ],
        key_classes=["SHA3", "SHA3_256", "SHA3_512", "SHAKE128", "SHAKE256"],
        key_methods=["hash()", "update()", "finalize()", "squeeze()"],
        key_sizes={"SHA3_256_output": 32, "SHA3_512_output": 64},
        performance_characteristics="SHA3-256: ~500 MB/sec",
        quantum_resistant=True,
        fips_compliant=True,
        thread_safe=True,
        dependencies=[],
        example_usage="""
from quantum_crypt import SHA3_256, SHAKE256

# Standard hash
digest = SHA3_256.hash(b"Data to hash")

# Extendable-output function (XOF)
shake = SHAKE256()
shake.update(b"Seed data")
arbitrary_length_output = shake.squeeze(1000)  # 1000 bytes of output
""",
        since_version="v1.0",
        standard_reference="NIST FIPS 202 (SHA-3 Standard)"
    ))

    catalog.register_module(CryptoModuleDocumentation(
        module_name="hkdf_key_derivation",
        stability=StabilityLevel.STABLE,
        algorithm_family="HKDF",
        nist_security_level=NISTSecurityLevel.LEVEL_5,
        description="HMAC-based Key Derivation Function (RFC 5869)",
        primary_use_cases=[
            "Key derivation from shared secrets",
            "Multiple keys from single master",
            "Contextual key separation",
            "Salted key derivation"
        ],
        key_classes=["HKDF", "HKDF_SHA256", "HKDF_SHA512"],
        key_methods=["extract()", "expand()", "derive_key()"],
        key_sizes={"salt_recommended": 32, "info_context": "variable"},
        performance_characteristics="Sub-millisecond operation",
        quantum_resistant=True,
        fips_compliant=True,
        thread_safe=True,
        dependencies=["hmac", "sha_hash_functions"],
        example_usage="""
from quantum_crypt import HKDF_SHA256

# Derive multiple keys from one shared secret
master_secret = kyber_shared_secret

# Key for encryption
enc_key = HKDF_SHA256.derive_key(
    master_secret, 
    salt=salt,
    info=b"encryption-key-v1",
    length=32
)

# Separate key for authentication
auth_key = HKDF_SHA256.derive_key(
    master_secret,
    salt=salt, 
    info=b"authentication-key-v1",
    length=32
)
""",
        since_version="v1.0",
        standard_reference="IETF RFC 5869"
    ))

    # =========================================================================
    # EXPERIMENTAL MODULES - Testing Only, NIST Round 4 Candidates
    # =========================================================================

    catalog.register_module(CryptoModuleDocumentation(
        module_name="falcon_signature",
        stability=StabilityLevel.EXPERIMENTAL,
        algorithm_family="Falcon",
        nist_security_level=NISTSecurityLevel.LEVEL_5,
        description="Fast-Fourier lattice-based compact signature (NIST alternate)",
        primary_use_cases=[
            "Resource-constrained devices",
            "Small signature size requirements",
            "IoT device authentication",
            "High-volume signing operations"
        ],
        key_classes=["Falcon", "Falcon512", "Falcon1024"],
        key_methods=["keygen()", "sign()", "verify()"],
        key_sizes={
            "Falcon512_public": 897,
            "Falcon512_secret": 1281,
            "Falcon512_signature": 666
        },
        performance_characteristics="Very fast verification, compact signatures",
        quantum_resistant=True,
        fips_compliant=False,  # Pending standardization
        thread_safe=True,
        dependencies=["ntt_fft_acceleration"],
        example_usage="""
from quantum_crypt import Falcon512

# Compact signatures for constrained environments
vk, sk = Falcon512.keygen()
sig = Falcon512.sign(b"Sensor reading: 23.5C", sk)
# Signature only ~666 bytes - much smaller than Dilithium
valid = Falcon512.verify(b"Sensor reading: 23.5C", sig, vk)
""",
        since_version="v2.0-experimental",
        standard_reference="NIST PQC Alternate Candidate"
    ))

    catalog.register_module(CryptoModuleDocumentation(
        module_name="sphincs_plus_hash_based",
        stability=StabilityLevel.EXPERIMENTAL,
        algorithm_family="SPHINCS+",
        nist_security_level=NISTSecurityLevel.LEVEL_5,
        description="Stateless hash-based signature (NIST alternate)",
        primary_use_cases=[
            "Long-term signing keys",
            "Code signing with multi-decade security",
            "No-trust hardware scenarios",
            "Quantum security maximization"
        ],
        key_classes=["SPHINCSPlus", "SPHINCS_SHA256_128f", "SPHINCS_SHA256_256f"],
        key_methods=["keygen()", "sign()", "verify()"],
        key_sizes={
            "SPHINCS-256_public": 64,
            "SPHINCS-256_secret": 128,
            "SPHINCS-256_signature": 49216
        },
        performance_characteristics="Large signatures, no side-channel risks",
        quantum_resistant=True,
        fips_compliant=False,  # Pending standardization
        thread_safe=True,
        dependencies=["sha3_hash_functions"],
        example_usage="""
from quantum_crypt import SPHINCS_SHA256_256f

# Maximum security - hash-based, no lattice concerns
# Keys are tiny, signatures are large
vk, sk = SPHINCS_SHA256_256f.keygen()
sig = SPHINCS_SHA256_256f.sign(b"Root CA certificate", sk)
valid = SPHINCS_SHA256_256f.verify(b"Root CA certificate", sig, vk)
""",
        since_version="v2.0-experimental",
        standard_reference="NIST PQC Alternate Candidate"
    ))

    catalog.register_module(CryptoModuleDocumentation(
        module_name="post_quantum_certificate_builder",
        stability=StabilityLevel.EXPERIMENTAL,
        algorithm_family="PQ X.509",
        nist_security_level=NISTSecurityLevel.LEVEL_5,
        description="X.509 certificate builder with post-quantum algorithms",
        primary_use_cases=[
            "PQ certificate authority operations",
            "TLS certificate generation",
            "Code signing certificates",
            "PKI migration to post-quantum"
        ],
        key_classes=["PQCertificateBuilder", "PQCertificateValidator"],
        key_methods=["build_cert()", "sign_cert()", "validate_chain()"],
        key_sizes={"varies_by_algorithm": "see specific algorithm docs"},
        performance_characteristics="Certificate building ~10ms, validation ~1ms",
        quantum_resistant=True,
        fips_compliant=False,  # Pending X.509 PQ profile standardization
        thread_safe=True,
        dependencies=["dilithium_signature", "x509_parser"],
        example_usage="""
from quantum_crypt import PQCertificateBuilder, Dilithium3

# Build a post-quantum X.509 certificate
builder = PQCertificateBuilder()
builder.set_subject("CN=example.com")
builder.set_public_key(dilithium_pubkey, algorithm="Dilithium3")
builder.set_validity(days=365)

cert = builder.sign(ca_private_key, ca_certificate)
# Certificate ready for use in TLS servers
""",
        since_version="v2.1-experimental",
        standard_reference="IETF LAMPS WG PQ Certificate Profiles"
    ))

    catalog.register_module(CryptoModuleDocumentation(
        module_name="quantum_random_number_generator",
        stability=StabilityLevel.EXPERIMENTAL,
        algorithm_family="QRNG",
        nist_security_level=NISTSecurityLevel.LEVEL_5,
        description="Quantum entropy collector and randomness extractor",
        primary_use_cases=[
            "Cryptographic key generation",
            "High-security entropy sourcing",
            "DRBG seeding",
            "Gaming and lottery systems"
        ],
        key_classes=["QuantumRNG", "EntropyCollector", "NISTSP80090C"],
        key_methods=["get_random_bytes()", "health_check()", "reseed()"],
        key_sizes={"min_entropy_per_call": 256},
        performance_characteristics="Depends on hardware source",
        quantum_resistant=True,
        fips_compliant=False,  # Hardware dependent validation
        thread_safe=False,  # Hardware access needs serialization
        dependencies=["hardware_entropy_source"],
        example_usage="""
from quantum_crypt import QuantumRNG

# Use quantum mechanical entropy source
qrng = QuantumRNG()
if qrng.health_check():
    true_random_key = qrng.get_random_bytes(32)
    # Use for most sensitive key generation
else:
    # Fallback to certified DRBG
    true_random_key = fallback_drbg.generate(32)
""",
        since_version="v2.2-experimental",
        standard_reference="NIST SP 800-90C, ANSI X9.82"
    ))

    # =========================================================================
    # DEPRECATED MODULES - Use Replacements Instead
    # =========================================================================

    catalog.register_module(CryptoModuleDocumentation(
        module_name="classic_rsa_signature",
        stability=StabilityLevel.DEPRECATED,
        algorithm_family="RSA",
        nist_security_level=NISTSecurityLevel.LEVEL_1,
        description="Classic RSA signature - NOT quantum resistant",
        primary_use_cases=["Legacy system compatibility ONLY"],
        key_classes=["RSA", "RSA2048", "RSA4096"],
        key_methods=["keygen()", "sign()", "verify()"],
        key_sizes={"RSA4096_key": 512},
        performance_characteristics="Slow signing, very vulnerable to quantum computers",
        quantum_resistant=False,
        fips_compliant=True,
        thread_safe=True,
        dependencies=[],
        example_usage="LEGACY - USE dilithium_digital_signature INSTEAD",
        since_version="v0.9",
        standard_reference="NIST FIPS 186-5 (legacy only)",
        deprecation_notice="Quantum vulnerable - migrate to Dilithium immediately",
        replacement_module="dilithium_digital_signature"
    ))

    catalog.register_module(CryptoModuleDocumentation(
        module_name="classic_ecdh_key_exchange",
        stability=StabilityLevel.DEPRECATED,
        algorithm_family="ECC",
        nist_security_level=NISTSecurityLevel.LEVEL_1,
        description="Classic ECDH key exchange - NOT quantum resistant",
        primary_use_cases=["Legacy system compatibility ONLY"],
        key_classes=["ECDH", "X25519", "P256", "P384"],
        key_methods=["keygen()", "derive_shared_secret()"],
        key_sizes={"X25519_key": 32},
        performance_characteristics="Fast but completely broken by quantum computers",
        quantum_resistant=False,
        fips_compliant=True,
        thread_safe=True,
        dependencies=[],
        example_usage="LEGACY - USE hybrid_kem_tls INSTEAD",
        since_version="v0.9",
        standard_reference="NIST FIPS 186-5 (legacy only)",
        deprecation_notice="Quantum vulnerable - use hybrid mode immediately",
        replacement_module="hybrid_kem_tls"
    ))

    return catalog


# Global catalog instance
QUANTUMCRYPT_API_CATALOG_V27 = build_quantumcrypt_api_catalog_v27()


def get_module_documentation(module_name: str) -> Optional[CryptoModuleDocumentation]:
    """
    Get documentation for a specific crypto module.
    
    Args:
        module_name: Name of the module to lookup
        
    Returns:
        CryptoModuleDocumentation if found, None otherwise
        
    Stability: STABLE
    """
    return QUANTUMCRYPT_API_CATALOG_V27.modules.get(module_name)


def get_recommended_production_modules() -> List[str]:
    """
    Get list of recommended modules for production deployment.
    These are STABLE + FIPS Compliant + Quantum Resistant.
    
    Returns:
        List of recommended module names
        
    Stability: STABLE
    """
    catalog = QUANTUMCRYPT_API_CATALOG_V27
    return [
        name for name, doc in catalog.modules.items()
        if (doc.stability == StabilityLevel.STABLE and 
            doc.fips_compliant and 
            doc.quantum_resistant)
    ]


def print_stability_report() -> None:
    """
    Print a human-readable stability report to console.
    
    Stability: STABLE
    """
    catalog = QUANTUMCRYPT_API_CATALOG_V27
    recommended = get_recommended_production_modules()
    
    print("=" * 70)
    print("QuantumCrypt API Stability Report v27")
    print("=" * 70)
    print(f"\n✅ RECOMMENDED FOR PRODUCTION ({len(recommended)}):")
    for mod in sorted(recommended):
        doc = catalog.modules[mod]
        print(f"   - {mod} [{doc.nist_security_level.value}]")
    
    print(f"\n⚠️  EXPERIMENTAL ({len(catalog.get_experimental_modules())}):")
    for mod in sorted(catalog.get_experimental_modules()):
        print(f"   - {mod}")
    
    print(f"\n❌ DEPRECATED - QUANTUM VULNERABLE ({len([m for m, d in catalog.modules.items() if d.stability == StabilityLevel.DEPRECATED])}):")
    for mod, doc in catalog.modules.items():
        if doc.stability == StabilityLevel.DEPRECATED:
            print(f"   - {mod} → MIGRATE TO: {doc.replacement_module}")
    
    print(f"\n🔐 Post-Quantum: {len(catalog.get_quantum_resistant_modules())} modules")
    print(f"📋 FIPS Compliant: {len(catalog.get_fips_compliant_modules())} modules")
    print("\n" + "=" * 70)
    print(f"Generated: {catalog.generated_at}")
    print("=" * 70)


if __name__ == "__main__":
    print_stability_report()
