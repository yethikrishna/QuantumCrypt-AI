"""
QuantumCrypt-AI Comprehensive Post-Quantum API Documentation & Stability Catalog v14
June 2026 Release

API STABILITY MARKERS:
    @stable: Production-ready, backward compatible, no breaking changes
    @experimental: Under active development, API may change
    @deprecated: Scheduled for removal, use alternative instead
    @nist_standardized: NIST standardized post-quantum algorithms
    @research: Academic/research implementations, not production

This module provides:
1. Centralized PQ API stability registry
2. NIST algorithm compliance tracking
3. Comprehensive docstring templates
4. Usage examples for all PQ primitives
5. Algorithm migration guides
6. Security level reference documentation
"""

import enum
import functools
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=Callable[..., Any])


class SecurityLevel(enum.Enum):
    """NIST Security Levels for Post-Quantum Cryptography."""
    LEVEL_1 = 1  # AES-128 equivalent
    LEVEL_2 = 2  # SHA-256 collision resistance
    LEVEL_3 = 3  # AES-192 equivalent
    LEVEL_4 = 4  # SHA-384 collision resistance
    LEVEL_5 = 5  # AES-256 equivalent


class AlgorithmStandard(enum.Enum):
    """NIST Standardization Status."""
    NIST_STANDARD = "nist_standard"       # Final NIST standard
    NIST_ROUND_4 = "nist_round_4"         # Round 4 candidate
    NIST_ROUND_3 = "nist_round_3"         # Round 3 candidate
    RESEARCH = "research"                 # Academic/research only
    LEGACY_CLASSICAL = "legacy_classical" # Pre-quantum algorithms


class StabilityLevel(enum.Enum):
    """API Stability Level Classification."""
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    BETA = "beta"
    LEGACY = "legacy"


@dataclass
class PQAlgorithmMetadata:
    """Metadata for Post-Quantum Algorithm implementations."""
    name: str
    standard_status: AlgorithmStandard
    security_level: SecurityLevel
    stability: StabilityLevel
    version_added: str
    version_deprecated: Optional[str] = None
    replacement: Optional[str] = None
    key_size_bytes: int = 0
    signature_size_bytes: int = 0
    ciphertext_size_bytes: int = 0
    description: str = ""
    module: str = ""
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    tags: Set[str] = field(default_factory=set)
    nist_id: Optional[str] = None


@dataclass
class APIMetadata:
    """Metadata for general API endpoints."""
    name: str
    stability: StabilityLevel
    version_added: str
    version_deprecated: Optional[str] = None
    replacement: Optional[str] = None
    description: str = ""
    module: str = ""
    tags: Set[str] = field(default_factory=set)


class PQAPIStabilityRegistry:
    """
    Central registry for tracking Post-Quantum API stability.
    
    @stable - This registry itself is STABLE API
    
    Features:
    - Tracks NIST standardization status
    - Records security levels
    - Manages deprecation warnings
    - Generates compliance reports
    
    Usage:
        registry = PQAPIStabilityRegistry()
        
        @registry.mark_nist_standard(
            security_level=SecurityLevel.LEVEL_5,
            version="1.0.0"
        )
        def kyber_key_gen():
            pass
    """
    
    def __init__(self) -> None:
        self._algorithms: Dict[str, PQAlgorithmMetadata] = {}
        self._apis: Dict[str, APIMetadata] = {}
        self._modules: Dict[str, Set[str]] = {}
    
    def mark_nist_standard(
        self,
        security_level: SecurityLevel,
        version: str,
        description: str = "",
        nist_id: Optional[str] = None
    ) -> Callable[[T], T]:
        """
        Mark algorithm as NIST STANDARDIZED.
        
        These algorithms:
        - Are final NIST PQ standards
        - Have undergone full cryptanalysis
        - Are recommended for production use
        
        Args:
            security_level: NIST security level (1-5)
            version: Version when added
            description: Algorithm description
            nist_id: Official NIST identifier
            
        Returns:
            Decorated function/class
        """
        def decorator(func: T) -> T:
            metadata = PQAlgorithmMetadata(
                name=func.__qualname__,
                standard_status=AlgorithmStandard.NIST_STANDARD,
                security_level=security_level,
                stability=StabilityLevel.STABLE,
                version_added=version,
                description=description or func.__doc__ or "",
                module=func.__module__,
                nist_id=nist_id,
                tags={"nist_standard", "production", "stable"}
            )
            self._algorithms[func.__qualname__] = metadata
            self._register_module(func.__module__, func.__qualname__)
            return func
        return decorator
    
    def mark_experimental(
        self,
        security_level: SecurityLevel,
        version: str,
        description: str = ""
    ) -> Callable[[T], T]:
        """
        Mark algorithm as EXPERIMENTAL (research/academic).
        
        Experimental algorithms:
        - May not have full cryptanalysis
        - API subject to change
        - NOT recommended for production
        
        Args:
            security_level: Target security level
            version: Version when added
            description: Algorithm description
            
        Returns:
            Decorated function/class
        """
        def decorator(func: T) -> T:
            metadata = PQAlgorithmMetadata(
                name=func.__qualname__,
                standard_status=AlgorithmStandard.RESEARCH,
                security_level=security_level,
                stability=StabilityLevel.EXPERIMENTAL,
                version_added=version,
                description=description or func.__doc__ or "",
                module=func.__module__,
                tags={"experimental", "research", "not_production"}
            )
            self._algorithms[func.__qualname__] = metadata
            self._register_module(func.__module__, func.__qualname__)
            
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                logger.warning(
                    f"EXPERIMENTAL PQ ALGORITHM: {func.__qualname__} - "
                    "Research-only, NOT validated for production use."
                )
                return func(*args, **kwargs)
            return wrapper  # type: ignore
        return decorator
    
    def mark_deprecated(
        self,
        version: str,
        replacement: str,
        reason: str = ""
    ) -> Callable[[T], T]:
        """
        Mark algorithm/API as DEPRECATED.
        
        Args:
            version: Version when deprecated
            replacement: Recommended replacement algorithm
            reason: Deprecation reason
            
        Returns:
            Decorated function/class
        """
        def decorator(func: T) -> T:
            metadata = APIMetadata(
                name=func.__qualname__,
                stability=StabilityLevel.DEPRECATED,
                version_added="unknown",
                version_deprecated=version,
                replacement=replacement,
                description=reason,
                module=func.__module__,
                tags={"deprecated"}
            )
            self._apis[func.__qualname__] = metadata
            self._register_module(func.__module__, func.__qualname__)
            
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                logger.warning(
                    f"DEPRECATED PQ API: {func.__qualname__} - "
                    f"Use {replacement} instead. {reason}"
                )
                return func(*args, **kwargs)
            return wrapper  # type: ignore
        return decorator
    
    def _register_module(self, module: str, api_name: str) -> None:
        if module not in self._modules:
            self._modules[module] = set()
        self._modules[module].add(api_name)
    
    def get_algorithm_metadata(self, name: str) -> Optional[PQAlgorithmMetadata]:
        """Get metadata for a specific algorithm."""
        return self._algorithms.get(name)
    
    def list_by_security_level(self, level: SecurityLevel) -> List[PQAlgorithmMetadata]:
        """List all algorithms at given security level."""
        return [a for a in self._algorithms.values() if a.security_level == level]
    
    def list_nist_standards(self) -> List[PQAlgorithmMetadata]:
        """List all NIST standardized algorithms."""
        return [
            a for a in self._algorithms.values()
            if a.standard_status == AlgorithmStandard.NIST_STANDARD
        ]
    
    def generate_compliance_report(self) -> str:
        """
        Generate NIST PQ compliance report.
        
        Returns:
            Formatted compliance report string
        """
        nist_standard = len(self.list_nist_standards())
        level1 = len(self.list_by_security_level(SecurityLevel.LEVEL_1))
        level3 = len(self.list_by_security_level(SecurityLevel.LEVEL_3))
        level5 = len(self.list_by_security_level(SecurityLevel.LEVEL_5))
        
        report = [
            "=" * 80,
            "QUANTUMCRYPT-AI POST-QUANTUM COMPLIANCE REPORT",
            "=" * 80,
            f"Generated: {datetime.now().isoformat()}",
            f"Total Algorithms: {len(self._algorithms)}",
            f"Total APIs: {len(self._apis)}",
            "",
            "NIST STANDARDIZATION STATUS:",
            f"  ✅ NIST STANDARD:  {nist_standard:4d} algorithms",
            "",
            "SECURITY LEVELS (NIST):",
            f"  LEVEL 1 (AES-128): {level1:4d} algorithms",
            f"  LEVEL 3 (AES-192): {level3:4d} algorithms", 
            f"  LEVEL 5 (AES-256): {level5:4d} algorithms",
            "",
            "-" * 80,
            "\nNIST STANDARD ALGORITHMS:",
        ]
        
        for alg in sorted(self.list_nist_standards(), key=lambda x: x.name):
            report.append(
                f"  - {alg.name}: Level {alg.security_level.value} "
                f"(v{alg.version_added})"
            )
        
        report.extend(["", "=" * 80])
        return "\n".join(report)


# Global registry instance
pq_api_registry = PQAPIStabilityRegistry()


class PQDocstringTemplate:
    """
    Standardized docstring templates for Post-Quantum modules.
    
    @stable
    """
    
    @staticmethod
    def kem_algorithm(name: str, nist_level: int, key_size: int, ct_size: int) -> str:
        """Generate docstring for Key Encapsulation Mechanism."""
        security_map = {1: "AES-128", 3: "AES-192", 5: "AES-256"}
        return f"""
    {name} - Post-Quantum Key Encapsulation Mechanism
    
    CRYPTOGRAPHIC PROPERTIES:
        - NIST Security Level: {nist_level} ({security_map[nist_level]} equivalent)
        - Public Key Size: {key_size} bytes
        - Ciphertext Size: {ct_size} bytes
        - IND-CCA2 Secure: Yes
        - Side Channel Resistant: Yes
    
    USAGE EXAMPLE:
        >>> kem = {name}()
        >>> pk, sk = kem.keygen()
        >>> ct, ss = kem.encaps(pk)
        >>> ss2 = kem.decaps(ct, sk)
        >>> assert ss == ss2  # Shared secrets match
    
    KEY GENERATION:
        - Deterministic with proper seed
        - Constant-time implementation
        - Memory zeroization on completion
    
    API STABILITY: @stable
    REFERENCE: NIST FIPS 203 (Module-Lattice-Based KEM Standard)
    """
    
    @staticmethod
    def signature_algorithm(name: str, nist_level: int, sig_size: int) -> str:
        """Generate docstring for Digital Signature Algorithm."""
        security_map = {1: "AES-128", 3: "AES-192", 5: "AES-256"}
        return f"""
    {name} - Post-Quantum Digital Signature Algorithm
    
    CRYPTOGRAPHIC PROPERTIES:
        - NIST Security Level: {nist_level} ({security_map[nist_level]} equivalent)
        - Signature Size: {sig_size} bytes
        - EUF-CMA Secure: Yes
        - Side Channel Resistant: Yes
    
    USAGE EXAMPLE:
        >>> signer = {name}()
        >>> pk, sk = signer.keygen()
        >>> signature = signer.sign(message, sk)
        >>> valid = signer.verify(message, signature, pk)
        >>> assert valid
    
    SECURITY NOTES:
        - Deterministic signing (no randomness failures)
        - Constant-time verification
        - Protection against fault attacks
    
    API STABILITY: @stable
    REFERENCE: NIST FIPS 204/205 (Digital Signature Standards)
    """


class PQUsageExampleCatalog:
    """
    Comprehensive usage examples for all QuantumCrypt primitives.
    
    @stable
    """
    
    @staticmethod
    def get_kyber_examples() -> Dict[str, str]:
        """Get CRYSTALS-Kyber usage examples."""
        return {
            "basic_key_exchange": '''
    # CRYSTALS-Kyber Key Exchange (NIST Standard)
    from quantum_crypt import Kyber768
    
    # Alice generates keypair
    alice = Kyber768()
    pk_alice, sk_alice = alice.keygen()
    
    # Bob encapsulates to Alice's public key
    bob = Kyber768()
    ciphertext, shared_secret_bob = bob.encaps(pk_alice)
    
    # Alice decapsulates
    shared_secret_alice = alice.decaps(ciphertext, sk_alice)
    
    # Both have the same shared secret!
    assert shared_secret_alice == shared_secret_bob
    print("Key exchange complete!")
''',
            
            "hybrid_tls": '''
    # Hybrid Classical + PQ Key Exchange
    from quantum_crypt import HybridKeyExchange
    
    # X25519 + Kyber-768 hybrid
    exchange = HybridKeyExchange()
    exchange.add_classical("x25519")
    exchange.add_post_quantum("kyber768")
    
    # TLS 1.3 compatible key exchange
    client_keyshare = exchange.generate_client_hello()
    server_keyshare = exchange.generate_server_response(client_keyshare)
    master_secret = exchange.derive_master_secret()
'''
        }
    
    @staticmethod
    def get_dilithium_examples() -> Dict[str, str]:
        """Get CRYSTALS-Dilithium usage examples."""
        return {
            "basic_signing": '''
    # CRYSTALS-Dilithium Digital Signatures (NIST Standard)
    from quantum_crypt import Dilithium3
    
    signer = Dilithium3()
    pk, sk = signer.keygen()
    
    # Sign a document
    document = b"Important contract: $1,000,000"
    signature = signer.sign(document, sk)
    
    # Verify the signature
    is_valid = signer.verify(document, signature, pk)
    print(f"Signature valid: {is_valid}")
''',
            
            "batch_verification": '''
    # Batch Signature Verification
    from quantum_crypt import BatchVerifier
    
    verifier = BatchVerifier()
    for msg, sig, pk in many_signatures:
        verifier.add(msg, sig, pk)
    
    # Faster than verifying individually
    all_valid = verifier.verify_batch()
'''
        }


# Export public API
__all__ = [
    'SecurityLevel',
    'AlgorithmStandard',
    'StabilityLevel',
    'PQAlgorithmMetadata',
    'APIMetadata',
    'PQAPIStabilityRegistry',
    'pq_api_registry',
    'PQDocstringTemplate',
    'PQUsageExampleCatalog',
]
