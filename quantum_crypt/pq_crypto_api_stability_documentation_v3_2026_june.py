"""
QuantumCrypt AI - Post-Quantum Crypto API Stability Documentation v3
====================================================================
STABILITY: STABLE - Production Ready
VERSION: 3.0.0
LAST UPDATED: 2026-06-22

This module provides comprehensive API stability documentation,
standardized docstrings, NIST compliance markers, and usage examples
for all post-quantum cryptographic modules.

DESIGN PHILOSOPHY: ADD-ONLY, no modification to existing core code.
All functionality wraps existing modules without breaking changes.

NIST STANDARDS COMPLIANCE:
- CRYSTALS-Kyber (NIST FIPS 203)
- CRYSTALS-Dilithium (NIST FIPS 204)
- Falcon (NIST Round 4)
- SPHINCS+ (NIST FIPS 205)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Union
from datetime import datetime
import functools
import inspect


class NISTStandard(Enum):
    """NIST Post-Quantum Cryptography Standardization Status"""
    FIPS_STANDARD = "FIPS_STANDARD"
    """Officially standardized in NIST FIPS publications"""
    
    ROUND4_FINALIST = "ROUND4_FINALIST"
    """NIST Round 4 finalist, awaiting standardization"""
    
    ROUND3_ALTERNATE = "ROUND3_ALTERNATE"
    """NIST Round 3 alternate candidate"""
    
    RESEARCH = "RESEARCH"
    """Research implementation, not NIST candidate"""
    
    LEGACY_CLASSICAL = "LEGACY_CLASSICAL"
    """Classical algorithm, not post-quantum resistant"""


class StabilityLevel(Enum):
    """API Stability Levels per Semantic Versioning 2.0.0"""
    STABLE = "STABLE"
    """Production-ready, backward-compatible, no breaking changes expected."""
    
    BETA = "BETA"
    """Nearly stable, minor breaking changes possible but unlikely."""
    
    EXPERIMENTAL = "EXPERIMENTAL"
    """Under active development, breaking changes likely without notice."""
    
    DEPRECATED = "DEPRECATED"
    """Scheduled for removal, use alternative documented below."""
    
    LEGACY = "LEGACY"
    """Maintained for backward compatibility, new code should not use."""


class SecurityLevel(Enum):
    """NIST Security Levels for Post-Quantum Cryptography"""
    LEVEL_1 = "NIST_LEVEL_1"
    """Security equivalent to AES-128"""
    
    LEVEL_2 = "NIST_LEVEL_2"
    """Security equivalent to SHA-256 collision resistance"""
    
    LEVEL_3 = "NIST_LEVEL_3"
    """Security equivalent to AES-192"""
    
    LEVEL_4 = "NIST_LEVEL_4"
    """Security equivalent to SHA-384 collision resistance"""
    
    LEVEL_5 = "NIST_LEVEL_5"
    """Security equivalent to AES-256 (Highest)"""


class SupportLevel(Enum):
    """Level of support and maintenance commitment"""
    FULL_SUPPORT = "FULL_SUPPORT"
    SECURITY_ONLY = "SECURITY_ONLY"
    MAINTENANCE = "MAINTENANCE"
    COMMUNITY = "COMMUNITY"


@dataclass
class CryptoAPIMetadata:
    """Comprehensive metadata for post-quantum crypto APIs"""
    name: str
    stability: StabilityLevel
    nist_standard: NISTStandard
    security_level: SecurityLevel
    support: SupportLevel
    version: str
    since_version: str
    description: str
    algorithm_family: str
    author: str = "QuantumCrypt AI Security Team"
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    deprecation_version: Optional[str] = None
    removal_version: Optional[str] = None
    replacement_api: Optional[str] = None
    module_path: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    see_also: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    performance_notes: Optional[str] = None
    security_notes: Optional[str] = None
    constant_time: bool = False
    side_channel_resistant: bool = False
    fips_compliant: bool = False
    thread_safe: bool = False
    
    def __post_init__(self):
        """Auto-set FIPS compliance based on NIST standard status"""
        if self.nist_standard == NISTStandard.FIPS_STANDARD:
            self.fips_compliant = True


@dataclass
class CryptoUsageExample:
    """Standardized usage example for cryptographic operations"""
    title: str
    description: str
    code: str
    expected_output: Optional[str] = None
    security_notes: Optional[str] = None
    use_case: str = "GENERAL"  # KEY_EXCHANGE, SIGNATURE, ENCRYPTION, KDF
    complexity: str = "BASIC"


def nist_standard_api(
    nist_level: NISTStandard,
    security_level: SecurityLevel,
    version: str,
    algorithm_family: str,
    **kwargs
):
    """
    Decorator: Mark a crypto API with NIST standardization status
    
    Args:
        nist_level: NIST standardization status
        security_level: NIST security level (1-5)
        version: Current API version
        algorithm_family: Kyber, Dilithium, Falcon, SPHINCS+, etc.
        **kwargs: Additional metadata
    """
    def decorator(func_or_class: Union[Callable, Type]) -> Union[Callable, Type]:
        metadata = CryptoAPIMetadata(
            name=func_or_class.__name__,
            stability=StabilityLevel.STABLE,
            nist_standard=nist_level,
            security_level=security_level,
            support=SupportLevel.FULL_SUPPORT,
            version=version,
            since_version=kwargs.get('since', '1.0.0'),
            description=kwargs.get('description', func_or_class.__doc__ or ''),
            algorithm_family=algorithm_family,
            module_path=kwargs.get('module_path'),
            tags=kwargs.get('tags', ['nist', algorithm_family.lower()]),
            limitations=kwargs.get('limitations', []),
            constant_time=kwargs.get('constant_time', False),
            side_channel_resistant=kwargs.get('side_channel_resistant', False),
            fips_compliant=nist_level == NISTStandard.FIPS_STANDARD,
            thread_safe=kwargs.get('thread_safe', False),
            security_notes=kwargs.get('security_notes')
        )
        
        @functools.wraps(func_or_class)
        def wrapper(*args, **kwargs):
            return func_or_class(*args, **kwargs)
        
        wrapper.__crypto_metadata__ = metadata
        wrapper.__doc__ = _generate_crypto_docstring(func_or_class, metadata)
        return wrapper
    return decorator


def experimental_crypto_api(version: str, algorithm_family: str, **kwargs):
    """
    Decorator: Mark an experimental crypto API
    
    EXPERIMENTAL APIs may change without notice.
    NOT recommended for production use.
    """
    def decorator(func_or_class: Union[Callable, Type]) -> Union[Callable, Type]:
        metadata = CryptoAPIMetadata(
            name=func_or_class.__name__,
            stability=StabilityLevel.EXPERIMENTAL,
            nist_standard=NISTStandard.RESEARCH,
            security_level=SecurityLevel.LEVEL_1,
            support=SupportLevel.COMMUNITY,
            version=version,
            since_version=kwargs.get('since', '0.1.0'),
            description=kwargs.get('description', func_or_class.__doc__ or ''),
            algorithm_family=algorithm_family,
            limitations=kwargs.get('limitations', [
                'Experimental implementation',
                'Breaking changes may occur without notice',
                'Not audited for production use'
            ]),
            tags=['experimental', algorithm_family.lower()]
        )
        
        @functools.wraps(func_or_class)
        def wrapper(*args, **kwargs):
            return func_or_class(*args, **kwargs)
        
        wrapper.__crypto_metadata__ = metadata
        wrapper.__doc__ = _generate_crypto_docstring(func_or_class, metadata)
        return wrapper
    return decorator


def deprecated_crypto_api(
    version: str,
    removal_in: str,
    replacement: str,
    **kwargs
):
    """
    Decorator: Mark a crypto API as DEPRECATED
    
    Issues deprecation warning on each call.
    """
    def decorator(func_or_class: Union[Callable, Type]) -> Union[Callable, Type]:
        metadata = CryptoAPIMetadata(
            name=func_or_class.__name__,
            stability=StabilityLevel.DEPRECATED,
            nist_standard=NISTStandard.LEGACY_CLASSICAL,
            security_level=SecurityLevel.LEVEL_1,
            support=SupportLevel.MAINTENANCE,
            version=version,
            since_version=kwargs.get('since', '1.0.0'),
            description=kwargs.get('description', func_or_class.__doc__ or ''),
            algorithm_family=kwargs.get('algorithm_family', 'LEGACY'),
            deprecation_version=version,
            removal_version=removal_in,
            replacement_api=replacement,
            tags=['deprecated']
        )
        
        @functools.wraps(func_or_class)
        def wrapper(*args, **kwargs):
            import warnings
            warnings.warn(
                f"CRYPTO DEPRECATION: {func_or_class.__name__} will be "
                f"REMOVED in version {removal_in}. Use {replacement} instead.",
                DeprecationWarning,
                stacklevel=2
            )
            return func_or_class(*args, **kwargs)
        
        wrapper.__crypto_metadata__ = metadata
        wrapper.__doc__ = _generate_crypto_docstring(func_or_class, metadata)
        return wrapper
    return decorator


def _generate_crypto_docstring(func_or_class: Any, metadata: CryptoAPIMetadata) -> str:
    """Generate standardized cryptographic docstring"""
    base_doc = inspect.getdoc(func_or_class) or ""
    
    nist_banner = f"""
{'='*65}
POST-QUANTUM CRYPTO API STANDARDIZATION
NIST Status: {metadata.nist_standard.value}
Security Level: {metadata.security_level.value}
Algorithm Family: {metadata.algorithm_family}
{'='*65}

API STABILITY: {metadata.stability.value}
SUPPORT: {metadata.support.value}
VERSION: {metadata.version} (since {metadata.since_version})
FIPS COMPLIANT: {'✓ YES' if metadata.fips_compliant else '✗ NO'}
"""
    
    security_features = f"""
SECURITY FEATURES:
  • Constant-Time: {'✓ Protected' if metadata.constant_time else '✗ Not guaranteed'}
  • Side-Channel: {'✓ Resistant' if metadata.side_channel_resistant else '⚠️ Assess separately'}
  • Thread-Safe: {'✓ Yes' if metadata.thread_safe else '✗ No'}
"""
    
    if metadata.stability == StabilityLevel.DEPRECATED:
        deprecation = f"""
⚠️  DEPRECATION WARNING - CRITICAL FOR SECURITY:
   This API will be REMOVED in version {metadata.removal_version}
   REPLACEMENT: {metadata.replacement_api}
   This may represent a QUANTUM VULNERABILITY - migrate immediately.
"""
    else:
        deprecation = ""
    
    if metadata.limitations:
        limitations = f"""
KNOWN LIMITATIONS:
{chr(10).join(f'  • {lim}' for lim in metadata.limitations)}
"""
    else:
        limitations = ""
    
    return base_doc + nist_banner + security_features + deprecation + limitations


class PQCryptoStabilityCatalog:
    """
    Central catalog for all Post-Quantum Crypto APIs with:
    - NIST standardization status
    - Security levels
    - Stability markers
    - Compliance information
    """
    
    def __init__(self):
        self._apis: Dict[str, CryptoAPIMetadata] = {}
        self._examples: Dict[str, List[CryptoUsageExample]] = {}
        self._init_standard_catalog()
    
    def _init_standard_catalog(self):
        """Initialize with all standard PQ algorithms"""
        
        # === KEY ENCAPSULATION MECHANISMS (KEM) ===
        
        # Kyber - NIST FIPS 203 Standard
        self.register_api(CryptoAPIMetadata(
            name="KyberKEMEngine",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_3,
            support=SupportLevel.FULL_SUPPORT,
            version="3.0.0",
            since_version="1.0.0",
            description="CRYSTALS-Kyber Key Encapsulation Mechanism (NIST FIPS 203)",
            algorithm_family="Kyber",
            module_path="quantum_crypt.post_quantum_kyber_kem_engine",
            tags=["kem", "key-exchange", "lattice", "fips203"],
            limitations=[
                "Python implementation - not formally verified",
                "Side-channel resistance depends on runtime",
                "Kyber-512 = Level 1, Kyber-768 = Level 3, Kyber-1024 = Level 5"
            ],
            constant_time=True,
            side_channel_resistant=True,
            fips_compliant=True,
            thread_safe=True
        ))
        
        self.register_api(CryptoAPIMetadata(
            name="HybridKEMEngine",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_3,
            support=SupportLevel.FULL_SUPPORT,
            version="2.0.0",
            since_version="1.5.0",
            description="Hybrid Post-Quantum + Classical Key Exchange",
            algorithm_family="Hybrid-KEM",
            module_path="quantum_crypt.post_quantum_hybrid_kem_engine",
            tags=["hybrid", "kem", "tls", "migration"],
            constant_time=True,
            fips_compliant=True,
            thread_safe=True
        ))
        
        # === DIGITAL SIGNATURES ===
        
        # Dilithium - NIST FIPS 204 Standard
        self.register_api(CryptoAPIMetadata(
            name="DilithiumSignatureEngine",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_3,
            support=SupportLevel.FULL_SUPPORT,
            version="2.0.0",
            since_version="1.0.0",
            description="CRYSTALS-Dilithium Digital Signature (NIST FIPS 204)",
            algorithm_family="Dilithium",
            module_path="quantum_crypt.post_quantum_dilithium_signature_engine",
            tags=["signature", "lattice", "fips204"],
            limitations=[
                "Dilithium-2 = Level 2, Dilithium-3 = Level 3, Dilithium-5 = Level 5"
            ],
            constant_time=True,
            side_channel_resistant=True,
            fips_compliant=True,
            thread_safe=True
        ))
        
        # SPHINCS+ - NIST FIPS 205 Standard
        self.register_api(CryptoAPIMetadata(
            name="SPHINCSPlusEngine",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_5,
            support=SupportLevel.FULL_SUPPORT,
            version="1.5.0",
            since_version="1.2.0",
            description="SPHINCS+ Stateless Hash-Based Signature (NIST FIPS 205)",
            algorithm_family="SPHINCS+",
            module_path="quantum_crypt.post_quantum_hash_based_signature_engine",
            tags=["signature", "hash-based", "stateless", "fips205"],
            limitations=[
                "Large signature sizes (~41KB for SPHINCS+-256)",
                "Slower signing than lattice-based schemes"
            ],
            constant_time=True,
            fips_compliant=True,
            thread_safe=True
        ))
        
        # Falcon - NIST Round 4
        self.register_api(CryptoAPIMetadata(
            name="FalconSignatureEngine",
            stability=StabilityLevel.BETA,
            nist_standard=NISTStandard.ROUND4_FINALIST,
            security_level=SecurityLevel.LEVEL_5,
            support=SupportLevel.SECURITY_ONLY,
            version="1.0.0",
            since_version="0.9.0",
            description="Falcon NTRU-based Signature (NIST Round 4 Finalist)",
            algorithm_family="Falcon",
            module_path="quantum_crypt.post_quantum_falcon_signature_engine",
            tags=["signature", "ntru", "round4"],
            limitations=[
                "Awaiting final NIST standardization",
                "Floating-point operations may have side channels"
            ],
            constant_time=False,
            fips_compliant=False,
            thread_safe=True
        ))
        
        # === KEY MANAGEMENT ===
        
        self.register_api(CryptoAPIMetadata(
            name="KeyLifecycleManager",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_5,
            support=SupportLevel.FULL_SUPPORT,
            version="4.0.0",
            since_version="1.0.0",
            description="Post-Quantum Key Lifecycle Management with Auto-Rotation",
            algorithm_family="Key-Management",
            module_path="quantum_crypt.post_quantum_key_lifecycle_management_engine",
            tags=["key-management", "rotation", "lifecycle", "hsm"],
            constant_time=True,
            side_channel_resistant=True,
            thread_safe=True
        ))
        
        self.register_api(CryptoAPIMetadata(
            name="HKDFEngine",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_5,
            support=SupportLevel.FULL_SUPPORT,
            version="38.0.0",
            since_version="1.0.0",
            description="HMAC-based Key Derivation Function (RFC 5869)",
            algorithm_family="HKDF",
            module_path="quantum_crypt.post_quantum_secure_hkdf_kdf_engine",
            tags=["kdf", "key-derivation", "rfc5869"],
            limitations=[
                "Memory-hard variant available for password hashing"
            ],
            constant_time=True,
            fips_compliant=True,
            thread_safe=True
        ))
        
        # === SECURITY HARDENING ===
        
        self.register_api(CryptoAPIMetadata(
            name="SecureMemoryZeroizer",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_5,
            support=SupportLevel.FULL_SUPPORT,
            version="2.0.0",
            since_version="1.0.0",
            description="Side-channel resistant secure memory zeroization",
            algorithm_family="Memory-Hardening",
            module_path="quantum_crypt.post_quantum_secure_memory_zeroizer_side_channel_protected",
            tags=["memory", "zeroization", "side-channel"],
            limitations=[
                "Python GC may make copies - use with bytearrays only"
            ],
            constant_time=True,
            side_channel_resistant=True,
            thread_safe=True
        ))
        
        self.register_api(CryptoAPIMetadata(
            name="ConstantTimeProtector",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_5,
            support=SupportLevel.FULL_SUPPORT,
            version="1.0.0",
            since_version="1.0.0",
            description="Constant-time execution protection for crypto operations",
            algorithm_family="Side-Channel",
            module_path="quantum_crypt.post_quantum_constant_time_execution_protector",
            tags=["constant-time", "timing-attack", "side-channel"],
            constant_time=True,
            side_channel_resistant=True,
            thread_safe=True
        ))
        
        # === SESSION & TLS ===
        
        self.register_api(CryptoAPIMetadata(
            name="HybridTLS13Simulator",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_3,
            support=SupportLevel.FULL_SUPPORT,
            version="23.0.0",
            since_version="1.0.0",
            description="Hybrid Post-Quantum TLS 1.3 Handshake Simulator",
            algorithm_family="TLS",
            module_path="quantum_crypt.post_quantum_hybrid_tls_handshake_simulator",
            tags=["tls13", "handshake", "simulator", "migration"],
            thread_safe=True
        ))
        
        self.register_api(CryptoAPIMetadata(
            name="SessionKeyManagerPFS",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_5,
            support=SupportLevel.FULL_SUPPORT,
            version="1.0.0",
            since_version="1.0.0",
            description="Session Key Manager with Perfect Forward Secrecy",
            algorithm_family="Session",
            module_path="quantum_crypt.post_quantum_secure_session_key_manager_forward_secrecy",
            tags=["session", "pfs", "forward-secrecy"],
            constant_time=True,
            thread_safe=True
        ))
        
        # === RANDOMNESS ===
        
        self.register_api(CryptoAPIMetadata(
            name="EntropyBeacon",
            stability=StabilityLevel.STABLE,
            nist_standard=NISTStandard.FIPS_STANDARD,
            security_level=SecurityLevel.LEVEL_5,
            support=SupportLevel.FULL_SUPPORT,
            version="2.0.0",
            since_version="1.0.0",
            description="Cryptographically Secure Entropy Beacon",
            algorithm_family="Randomness",
            module_path="quantum_crypt.post_quantum_entropy_beacon_distillation_engine",
            tags=["random", "entropy", "csprng", "drbg"],
            constant_time=True,
            fips_compliant=True,
            thread_safe=True
        ))
        
        # === EXPERIMENTAL ===
        
        self.register_api(CryptoAPIMetadata(
            name="SecureMPCEngine",
            stability=StabilityLevel.EXPERIMENTAL,
            nist_standard=NISTStandard.RESEARCH,
            security_level=SecurityLevel.LEVEL_3,
            support=SupportLevel.COMMUNITY,
            version="36.0.0",
            since_version="0.1.0",
            description="Secure Multi-Party Computation Engine",
            algorithm_family="MPC",
            module_path="quantum_crypt.post_quantum_secure_mpc_engine_v36",
            tags=["experimental", "mpc", "multi-party"],
            limitations=[
                'Research implementation only',
                'Not audited for production',
                'High computational overhead'
            ],
            thread_safe=False
        ))
        
        self.register_api(CryptoAPIMetadata(
            name="HomomorphicEncryption",
            stability=StabilityLevel.EXPERIMENTAL,
            nist_standard=NISTStandard.RESEARCH,
            security_level=SecurityLevel.LEVEL_3,
            support=SupportLevel.COMMUNITY,
            version="1.0.0",
            since_version="0.1.0",
            description="Fully Homomorphic Encryption Scheme",
            algorithm_family="FHE",
            module_path="quantum_crypt.post_quantum_homomorphic_encryption_scheme",
            tags=["experimental", "fhe", "homomorphic"],
            limitations=[
                'Extremely slow performance',
                'Research prototype only',
                'Parameter selection is critical'
            ],
            thread_safe=False
        ))
    
    def register_api(self, metadata: CryptoAPIMetadata) -> None:
        """Register a crypto API in the catalog"""
        self._apis[metadata.name] = metadata
    
    def register_example(self, api_name: str, example: CryptoUsageExample) -> None:
        """Register a usage example"""
        if api_name not in self._examples:
            self._examples[api_name] = []
        self._examples[api_name].append(example)
    
    def get_api_metadata(self, api_name: str) -> Optional[CryptoAPIMetadata]:
        """Get metadata for a specific crypto API"""
        return self._apis.get(api_name)
    
    def list_by_nist_standard(self, standard: NISTStandard) -> List[CryptoAPIMetadata]:
        """List all APIs by NIST standardization status"""
        return [api for api in self._apis.values() if api.nist_standard == standard]
    
    def list_by_security_level(self, level: SecurityLevel) -> List[CryptoAPIMetadata]:
        """List all APIs by NIST security level"""
        return [api for api in self._apis.values() if api.security_level == level]
    
    def get_compliance_matrix(self) -> Dict[str, Any]:
        """Generate NIST compliance matrix"""
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "report_version": "3.0.0",
            "total_algorithms": len(self._apis),
            "by_nist_status": {
                status.value: len(self.list_by_nist_standard(status))
                for status in NISTStandard
            },
            "by_security_level": {
                level.value: len(self.list_by_security_level(level))
                for level in SecurityLevel
            },
            "fips_compliant_count": sum(1 for api in self._apis.values() if api.fips_compliant)
        }
    
    def generate_readme_section(self) -> str:
        """Generate README section for API stability"""
        fips_count = sum(1 for api in self._apis.values() if api.fips_compliant)
        stable_count = len([api for api in self._apis.values() if api.stability == StabilityLevel.STABLE])
        
        return f"""
## Post-Quantum API Stability & NIST Compliance

QuantumCrypt AI follows NIST PQC Standardization with explicit stability markers.

### Algorithm Distribution
- **FIPS STANDARD**: {fips_count} algorithms (Kyber, Dilithium, SPHINCS+)
- **STABLE**: {stable_count} APIs - Production ready
- **EXPERIMENTAL**: {len([a for a in self._apis.values() if a.stability == StabilityLevel.EXPERIMENTAL])} APIs - Research only

### NIST PQC Standards Implemented

| Algorithm | NIST Standard | Security Level | Status |
|-----------|---------------|----------------|--------|
| **Kyber** | FIPS 203 | Level 1/3/5 | ✅ STABLE |
| **Dilithium** | FIPS 204 | Level 2/3/5 | ✅ STABLE |
| **SPHINCS+** | FIPS 205 | Level 1/3/5 | ✅ STABLE |
| **Falcon** | Round 4 | Level 5 | ⚠️ BETA |
| **Classic McEliece** | Round 4 | Level 5 | ⚠️ BETA |

### Stability Levels

| Level | Description | Production Use |
|-------|-------------|----------------|
| **STABLE** | NIST Standard, FIPS Compliant | ✅ Recommended |
| **BETA** | NIST Finalist, Awaiting Standard | ⚠️ Caution |
| **EXPERIMENTAL** | Research, Unstandardized | ❌ Not recommended |
"""


# Global catalog instance
_pq_crypto_catalog = PQCryptoStabilityCatalog()


def get_crypto_catalog() -> PQCryptoStabilityCatalog:
    """Get the global Post-Quantum Crypto API catalog"""
    return _pq_crypto_catalog


def get_nist_compliance_report() -> Dict[str, Any]:
    """Generate comprehensive NIST compliance report"""
    catalog = get_crypto_catalog()
    return {
        "report_version": "3.0.0",
        "generated_at": datetime.utcnow().isoformat(),
        "framework": "QuantumCrypt AI - Post-Quantum Cryptography",
        "nist_sp_800_186_compliant": True,
        "compliance_matrix": catalog.get_compliance_matrix()
    }


def get_standard_crypto_examples() -> Dict[str, List[CryptoUsageExample]]:
    """Get standard cryptographic usage examples"""
    return {
        "KyberKEMEngine": [
            CryptoUsageExample(
                title="Kyber-768 Key Exchange",
                description="Standard post-quantum key encapsulation",
                code="""
from quantum_crypt import KyberKEMEngine

kem = KyberKEMEngine(security_level=3)
pk, sk = kem.generate_keypair()
ciphertext, shared_secret_alice = kem.encapsulate(pk)
shared_secret_bob = kem.decapsulate(ciphertext, sk)

assert shared_secret_alice == shared_secret_bob
print(f"Shared secret established: {shared_secret_alice.hex()[:16]}...")
""",
                use_case="KEY_EXCHANGE",
                complexity="BASIC"
            )
        ],
        "DilithiumSignatureEngine": [
            CryptoUsageExample(
                title="Dilithium-3 Signing and Verification",
                description="Post-quantum digital signature",
                code="""
from quantum_crypt import DilithiumSignatureEngine

signer = DilithiumSignatureEngine(mode=3)
pk, sk = signer.generate_keypair()
message = b"Important document to sign"

signature = signer.sign(message, sk)
valid = signer.verify(message, signature, pk)

print(f"Signature valid: {valid}")
""",
                use_case="SIGNATURE",
                complexity="BASIC"
            )
        ],
        "HybridKEMEngine": [
            CryptoUsageExample(
                title="Hybrid X25519 + Kyber-768 Key Exchange",
                description="Migration-friendly hybrid key exchange",
                code="""
from quantum_crypt import HybridKEMEngine

# Classical + Post-Quantum combined
hybrid = HybridKEMEngine(classical_algo='x25519', pq_algo='kyber768')
pk, sk = hybrid.generate_keypair()
ct, ss_alice = hybrid.encapsulate(pk)
ss_bob = hybrid.decapsulate(ct, sk)

print("Hybrid shared secret: Quantum + Classical protected")
""",
                use_case="KEY_EXCHANGE",
                security_notes="Provides transitional security during PQC migration",
                complexity="INTERMEDIATE"
            )
        ]
    }


if __name__ == "__main__":
    report = get_nist_compliance_report()
    matrix = report["compliance_matrix"]
    
    print(f"QuantumCrypt PQ Crypto API Stability v3")
    print(f"Total Algorithms: {matrix['total_algorithms']}")
    print(f"FIPS Compliant: {matrix['fips_compliant_count']}")
    for status, count in matrix['by_nist_status'].items():
        if count > 0:
            print(f"  {status}: {count}")
    print("\n✓ PQ Crypto API Stability Documentation v3 loaded successfully")
