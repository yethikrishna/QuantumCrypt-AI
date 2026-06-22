"""
QuantumCrypt-AI - Post-Quantum Crypto API Documentation & Stability Catalog v7
=====================================================================
DIMENSION F: Documentation & API Stability
=====================================================================
ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED
This module provides comprehensive API documentation, stability markers,
and usage examples for the QuantumCrypt-AI post-quantum cryptography platform.

API STABILITY LEVELS:
    STABLE: API is frozen, no breaking changes will occur
    EXPERIMENTAL: API may change, use with caution in production
    DEPRECATED: API will be removed in future version
    INTERNAL: Not for public use, implementation detail only
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import json
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Classification - Semantic Versioning Compliant."""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"
    
    def __str__(self) -> str:
        return self.value


@dataclass
class CryptoAPIEndpoint:
    """Metadata for a documented cryptographic API."""
    name: str
    module: str
    signature: str
    docstring: str
    stability: StabilityLevel
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    raises: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    since_version: str = "1.0.0"
    deprecation_notice: str = ""
    tags: Set[str] = field(default_factory=set)
    security_notes: List[str] = field(default_factory=list)
    nist_compliant: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dictionary."""
        return {
            "name": self.name,
            "module": self.module,
            "signature": self.signature,
            "docstring": self.docstring,
            "stability": str(self.stability),
            "parameters": self.parameters,
            "returns": self.returns,
            "raises": self.raises,
            "examples": self.examples,
            "since_version": self.since_version,
            "deprecation_notice": self.deprecation_notice,
            "tags": list(self.tags),
            "security_notes": self.security_notes,
            "nist_compliant": self.nist_compliant,
        }


@dataclass
class CryptoUsageExample:
    """Runnable usage example for a cryptographic API."""
    title: str
    code: str
    description: str
    security_considerations: List[str] = field(default_factory=list)
    expected_output: str = ""


class CryptoAPIDocumentationCatalog:
    """
    Comprehensive API Documentation & Stability Catalog for QuantumCrypt-AI.
    
    This catalog provides:
    1. Stability classification for all post-quantum crypto APIs
    2. Complete function signatures and parameter documentation
    3. NIST compliance status indicators
    4. Security notes and best practices
    5. Runnable usage examples with security considerations
    6. Deprecation notices and migration guides
    7. Export to JSON/Markdown formats
    
    STABILITY: STABLE
    SINCE: 1.0.0
    """
    
    def __init__(self) -> None:
        """Initialize empty documentation catalog."""
        self._apis: Dict[str, CryptoAPIEndpoint] = {}
        self._examples: Dict[str, List[CryptoUsageExample]] = {}
        self._modules: Set[str] = set()
        self._init_standard_apis()
    
    def _init_standard_apis(self) -> None:
        """Register all standard QuantumCrypt-AI APIs with stability markers."""
        
        # =====================================================================
        # POST-QUANTUM KEM APIS (STABLE, NIST COMPLIANT)
        # =====================================================================
        
        self.register_api(
            name="KyberKEM.generate_keypair",
            module="kyber_kem",
            signature="generate_keypair(security_level: int = 3) -> Tuple[bytes, bytes]",
            docstring="Generate CRYSTALS-Kyber key encapsulation mechanism keypair.",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "security_level", "type": "int", "description": "NIST security level (2, 3, or 5)"},
            ],
            returns="Tuple of (public_key, secret_key) as bytes",
            raises=[
                "ValueError if security_level not in {2, 3, 5}",
                "RuntimeError if random number generation fails",
            ],
            examples=[
                """
                kem = KyberKEM()
                pk, sk = kem.generate_keypair(security_level=3)
                ciphertext, shared_secret = kem.encapsulate(pk)
                recovered_secret = kem.decapsulate(ciphertext, sk)
                # shared_secret == recovered_secret
                """
            ],
            tags={"kem", "kyber", "nist", "key-exchange", "post-quantum"},
            security_notes=[
                "NIST FIPS 203 standardized algorithm",
                "Security level 3 = AES-192 equivalent strength",
                "Ephemeral keys recommended for forward secrecy",
            ],
            nist_compliant=True,
        )
        
        self.register_api(
            name="KyberKEM.encapsulate",
            module="kyber_kem",
            signature="encapsulate(public_key: bytes) -> Tuple[bytes, bytes]",
            docstring="Encapsulate shared secret using recipient's public key.",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "public_key", "type": "bytes", "description": "Recipient's Kyber public key"},
            ],
            returns="Tuple of (ciphertext, shared_secret)",
            raises=["ValueError for invalid public key format"],
            tags={"kem", "kyber", "encapsulation", "post-quantum"},
            security_notes=[
                "Shared secret is cryptographically random",
                "NIST FIPS 203 IND-CCA2 secure",
                "Ciphertext provides implicit key confirmation",
            ],
            nist_compliant=True,
        )
        
        self.register_api(
            name="KyberKEM.decapsulate",
            module="kyber_kem",
            signature="decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes",
            docstring="Decapsulate shared secret using private key.",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "ciphertext", "type": "bytes", "description": "KEM ciphertext"},
                {"name": "secret_key", "type": "bytes", "description": "Recipient's secret key"},
            ],
            returns="Recovered shared secret bytes",
            raises=["ValueError for invalid inputs or decapsulation failure"],
            tags={"kem", "kyber", "decapsulation", "post-quantum"},
            security_notes=[
                "NIST FIPS 203 standardized algorithm",
                "Rejection sampling provides side-channel resistance",
                "Fails safely on malformed ciphertext",
            ],
            nist_compliant=True,
        )
        
        # =====================================================================
        # POST-QUANTUM SIGNATURE APIS (STABLE, NIST COMPLIANT)
        # =====================================================================
        
        self.register_api(
            name="DilithiumSigner.generate_keypair",
            module="dilithium_signer",
            signature="generate_keypair(security_level: int = 3) -> Tuple[bytes, bytes]",
            docstring="Generate CRYSTALS-Dilithium digital signature keypair.",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "security_level", "type": "int", "description": "NIST security level (2, 3, or 5)"},
            ],
            returns="Tuple of (public_key, secret_key) as bytes",
            raises=["ValueError if security_level not in {2, 3, 5}"],
            examples=[
                """
                signer = DilithiumSigner()
                pk, sk = signer.generate_keypair()
                message = b"Important document"
                signature = signer.sign(message, sk)
                valid = signer.verify(message, signature, pk)
                # valid == True
                """
            ],
            tags={"signature", "dilithium", "nist", "signing", "post-quantum"},
            security_notes=[
                "NIST FIPS 204 standardized algorithm",
                "Deterministic signing with no randomness required",
            ],
            nist_compliant=True,
        )
        
        self.register_api(
            name="DilithiumSigner.sign",
            module="dilithium_signer",
            signature="sign(message: bytes, secret_key: bytes) -> bytes",
            docstring="Sign message using Dilithium secret key.",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "message", "type": "bytes", "description": "Message to sign"},
                {"name": "secret_key", "type": "bytes", "description": "Dilithium secret key"},
            ],
            returns="Digital signature bytes",
            raises=["ValueError for invalid key or message"],
            tags={"signature", "dilithium", "signing", "post-quantum"},
            security_notes=[
                "NIST FIPS 204 standardized algorithm",
                "Deterministic signing with rejection sampling",
                "Side-channel resistant implementation",
            ],
            nist_compliant=True,
        )
        
        self.register_api(
            name="DilithiumSigner.verify",
            module="dilithium_signer",
            signature="verify(message: bytes, signature: bytes, public_key: bytes) -> bool",
            docstring="Verify Dilithium digital signature.",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "message", "type": "bytes", "description": "Original message"},
                {"name": "signature", "type": "bytes", "description": "Signature to verify"},
                {"name": "public_key", "type": "bytes", "description": "Signer's public key"},
            ],
            returns="True if signature is valid, False otherwise",
            tags={"signature", "dilithium", "verification", "post-quantum"},
            security_notes=[
                "NIST FIPS 204 EUF-CMA secure",
                "No timing leak during verification",
                "Explicit rejection of malformed signatures",
            ],
            nist_compliant=True,
        )
        
        self.register_api(
            name="FalconSigner.generate_keypair",
            module="falcon_signer",
            signature="generate_keypair(security_level: int = 512) -> Tuple[bytes, bytes]",
            docstring="Generate FALCON lattice-based signature keypair.",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "security_level", "type": "int", "description": "Parameter set (512 or 1024)"},
            ],
            returns="Tuple of (public_key, secret_key)",
            tags={"signature", "falcon", "nist", "fast-signing", "post-quantum"},
            security_notes=["NIST round 4 finalist, smaller signatures than Dilithium"],
            nist_compliant=True,
        )
        
        # =====================================================================
        # HYBRID CRYPTO APIS (STABLE)
        # =====================================================================
        
        self.register_api(
            name="HybridKEM.generate_keypair",
            module="hybrid_kem",
            signature="generate_keypair() -> Tuple[bytes, bytes]",
            docstring="Generate hybrid (Kyber + X25519) KEM keypair.",
            stability=StabilityLevel.STABLE,
            returns="Tuple of (composite_public_key, composite_secret_key)",
            examples=[
                """
                hybrid = HybridKEM()
                pk, sk = hybrid.generate_keypair()
                ct, ss = hybrid.encapsulate(pk)
                # Both Kyber and X25519 shared secrets derived
                """
            ],
            tags={"hybrid", "kem", "classical+pq", "migration", "key-exchange"},
            security_notes=[
                "Dual protection: classical + post-quantum",
                "Recommended for migration scenarios",
                "Safe even if one algorithm is broken",
            ],
        )
        
        self.register_api(
            name="HybridSigner.generate_keypair",
            module="hybrid_signer",
            signature="generate_keypair() -> Tuple[bytes, bytes]",
            docstring="Generate hybrid (Dilithium + Ed25519) signature keypair.",
            stability=StabilityLevel.STABLE,
            returns="Tuple of (composite_public_key, composite_secret_key)",
            tags={"hybrid", "signature", "classical+pq", "migration"},
            security_notes=["Dual signature verification required"],
        )
        
        # =====================================================================
        # SYMMETRIC ENCRYPTION APIS (STABLE)
        # =====================================================================
        
        self.register_api(
            name="AESGCM.encrypt",
            module="aes_gcm",
            signature="encrypt(plaintext: bytes, key: bytes, nonce: Optional[bytes] = None, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]",
            docstring="Authenticated encryption with AES-GCM.",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "plaintext", "type": "bytes", "description": "Data to encrypt"},
                {"name": "key", "type": "bytes", "description": "16, 24, or 32 byte AES key"},
                {"name": "nonce", "type": "Optional[bytes]", "description": "12 byte nonce (generated if None)"},
                {"name": "associated_data", "type": "Optional[bytes]", "description": "Authenticated but unencrypted data"},
            ],
            returns="Tuple of (ciphertext, nonce, authentication_tag)",
            raises=[
                "ValueError for invalid key length",
                "ValueError for invalid nonce length",
            ],
            tags={"aes", "gcm", "encryption", "authenticated", "symmetric"},
            security_notes=[
                "NIST SP 800-38D compliant",
                "Nonce MUST be unique per encryption with same key",
                "96-bit nonce recommended by NIST",
            ],
        )
        
        self.register_api(
            name="AESGCM.decrypt",
            module="aes_gcm",
            signature="decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, associated_data: Optional[bytes] = None) -> bytes",
            docstring="Authenticated decryption with AES-GCM.",
            stability=StabilityLevel.STABLE,
            returns="Decrypted plaintext if authentication passes",
            raises=["ValueError if authentication fails or inputs invalid"],
            tags={"aes", "gcm", "decryption", "authenticated", "symmetric"},
        )
        
        self.register_api(
            name="ChaCha20Poly1305.encrypt",
            module="chacha20_poly1305",
            signature="encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> Tuple[bytes, bytes]",
            docstring="Authenticated encryption with ChaCha20-Poly1305.",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "plaintext", "type": "bytes", "description": "Data to encrypt"},
                {"name": "key", "type": "bytes", "description": "32 byte key"},
                {"name": "nonce", "type": "bytes", "description": "12 byte nonce"},
            ],
            returns="Tuple of (ciphertext, tag)",
            tags={"chacha20", "poly1305", "encryption", "stream-cipher"},
            security_notes=["RFC 8439 compliant, constant-time implementation"],
        )
        
        # =====================================================================
        # KEY DERIVATION APIS (STABLE)
        # =====================================================================
        
        self.register_api(
            name="HKDF.derive",
            module="hkdf",
            signature="derive(ikm: bytes, length: int, salt: Optional[bytes] = None, info: Optional[bytes] = None, hash_alg: str = 'sha256') -> bytes",
            docstring="HMAC-based Key Derivation Function (RFC 5869).",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "ikm", "type": "bytes", "description": "Input key material"},
                {"name": "length", "type": "int", "description": "Output length in bytes"},
                {"name": "salt", "type": "Optional[bytes]", "description": "Salt value (random recommended)"},
                {"name": "info", "type": "Optional[bytes]", "description": "Context/application specific info"},
                {"name": "hash_alg", "type": "str", "description": "Hash algorithm: sha256, sha384, sha512"},
            ],
            returns="Derived key bytes",
            raises=["ValueError if length exceeds maximum"],
            tags={"hkdf", "kdf", "key-derivation", "nist"},
            security_notes=[
                "NIST SP 800-56C compliant",
                "Always use salt for better security",
                "Use info parameter for domain separation",
            ],
        )
        
        self.register_api(
            name="Argon2id.hash",
            module="argon2",
            signature="hash(password: bytes, salt: Optional[bytes] = None, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4) -> Tuple[bytes, bytes]",
            docstring="Argon2id memory-hard password hashing.",
            stability=StabilityLevel.STABLE,
            parameters=[
                {"name": "password", "type": "bytes", "description": "Password to hash"},
                {"name": "salt", "type": "Optional[bytes]", "description": "16 byte salt (generated if None)"},
                {"name": "time_cost", "type": "int", "description": "Number of iterations"},
                {"name": "memory_cost", "type": "int", "description": "Memory usage in KB"},
                {"name": "parallelism", "type": "int", "description": "Parallel threads"},
            ],
            returns="Tuple of (hash_bytes, salt)",
            tags={"argon2", "password-hashing", "memory-hard", "kdf"},
            security_notes=[
                "OWASP recommended password hashing algorithm",
                "Winner of Password Hashing Competition",
                "Resistant to time-memory trade-off attacks",
            ],
        )
        
        # =====================================================================
        # KEY MANAGEMENT APIS (EXPERIMENTAL)
        # =====================================================================
        
        self.register_api(
            name="KeyLifecycleManager.generate_key",
            module="key_lifecycle_manager",
            signature="generate_key(algorithm: str, length: int) -> Dict[str, Any]",
            docstring="Generate and register a new key with lifecycle tracking.",
            stability=StabilityLevel.EXPERIMENTAL,
            parameters=[
                {"name": "algorithm", "type": "str", "description": "Key algorithm identifier"},
                {"name": "length", "type": "int", "description": "Key length in bits"},
            ],
            returns="Key metadata dictionary with ID, creation date, rotation schedule",
            since_version="1.2.0",
            tags={"key-management", "lifecycle", "rotation", "experimental"},
        )
        
        self.register_api(
            name="KeyLifecycleManager.rotate_key",
            module="key_lifecycle_manager",
            signature="rotate_key(key_id: str) -> Dict[str, Any]",
            docstring="Rotate existing key and archive old version.",
            stability=StabilityLevel.EXPERIMENTAL,
            since_version="1.2.0",
            tags={"key-management", "rotation", "forward-secrecy", "experimental"},
        )
        
        self.register_api(
            name="HSMWrapper.wrap_key",
            module="hsm_wrapper",
            signature="wrap_key(plaintext_key: bytes, wrapping_key_id: str) -> bytes",
            docstring="Wrap key under HSM protection.",
            stability=StabilityLevel.EXPERIMENTAL,
            since_version="1.3.0",
            tags={"hsm", "key-wrap", "hardware-security", "experimental"},
        )
        
        # =====================================================================
        # CERTIFICATE APIS (EXPERIMENTAL)
        # =====================================================================
        
        self.register_api(
            name="PQCertificateGenerator.generate_csr",
            module="pq_certificate",
            signature="generate_csr(subject: Dict[str, str], public_key: bytes, algorithm: str) -> bytes",
            docstring="Generate post-quantum Certificate Signing Request.",
            stability=StabilityLevel.EXPERIMENTAL,
            since_version="1.4.0",
            tags={"certificate", "csr", "x509", "experimental"},
        )
        
        self.register_api(
            name="PQCertificateVerifier.verify_chain",
            module="pq_certificate",
            signature="verify_chain(certificate_chain: List[bytes], trust_roots: List[bytes]) -> bool",
            docstring="Verify post-quantum certificate chain.",
            stability=StabilityLevel.EXPERIMENTAL,
            since_version="1.4.0",
            tags={"certificate", "verification", "chain", "experimental"},
        )
        
        # =====================================================================
        # SIDE-CHANNEL RESISTANCE APIS (EXPERIMENTAL)
        # =====================================================================
        
        self.register_api(
            name="SideChannelResistant.compare",
            module="side_channel",
            signature="compare(a: bytes, b: bytes) -> bool",
            docstring="Constant-time byte comparison resistant to timing attacks.",
            stability=StabilityLevel.EXPERIMENTAL,
            since_version="1.1.0",
            tags={"side-channel", "constant-time", "timing-attack", "experimental"},
        )
        
        self.register_api(
            name="SecureMemory.zeroize",
            module="secure_memory",
            signature="zeroize(buffer: bytearray) -> None",
            docstring="Securely zeroize sensitive memory buffer.",
            stability=StabilityLevel.EXPERIMENTAL,
            since_version="1.1.0",
            tags={"memory", "zeroization", "sensitive-data", "experimental"},
        )
        
        # =====================================================================
        # MULTI-PARTY COMPUTATION (EXPERIMENTAL)
        # =====================================================================
        
        self.register_api(
            name="ShamirSecretSharing.split",
            module="secret_sharing",
            signature="split(secret: bytes, threshold: int, shares: int) -> List[Tuple[int, bytes]]",
            docstring="Split secret into Shamir threshold shares.",
            stability=StabilityLevel.EXPERIMENTAL,
            parameters=[
                {"name": "secret", "type": "bytes", "description": "Secret to split"},
                {"name": "threshold", "type": "int", "description": "Minimum shares needed for reconstruction"},
                {"name": "shares", "type": "int", "description": "Total shares to create"},
            ],
            returns="List of (share_index, share_data) tuples",
            since_version="1.5.0",
            tags={"mpc", "secret-sharing", "shamir", "threshold", "experimental"},
        )
        
        self.register_api(
            name="ShamirSecretSharing.reconstruct",
            module="secret_sharing",
            signature="reconstruct(shares: List[Tuple[int, bytes]]) -> bytes",
            docstring="Reconstruct secret from threshold shares.",
            stability=StabilityLevel.EXPERIMENTAL,
            since_version="1.5.0",
            tags={"mpc", "secret-sharing", "shamir", "reconstruction", "experimental"},
        )
        
        # =====================================================================
        # DEPRECATED APIS
        # =====================================================================
        
        self.register_api(
            name="LegacyAES.encrypt_ecb",
            module="legacy_aes",
            signature="encrypt_ecb(plaintext: bytes, key: bytes) -> bytes",
            docstring="[DEPRECATED] AES-ECB encryption (INSECURE).",
            stability=StabilityLevel.DEPRECATED,
            deprecation_notice="ECB mode is insecure. Use AESGCM.encrypt() instead. Will be removed in v2.0.0",
            tags={"deprecated", "legacy", "insecure"},
        )
        
        # =====================================================================
        # INTERNAL APIS
        # =====================================================================
        
        self.register_api(
            name="CryptoEngine._initialize_backend",
            module="crypto_engine",
            signature="_initialize_backend() -> None",
            docstring="[INTERNAL] Initialize cryptographic backend.",
            stability=StabilityLevel.INTERNAL,
            tags={"internal", "implementation"},
        )
    
    def register_api(
        self,
        name: str,
        module: str,
        signature: str,
        docstring: str,
        stability: StabilityLevel,
        parameters: Optional[List[Dict[str, str]]] = None,
        returns: str = "",
        raises: Optional[List[str]] = None,
        examples: Optional[List[str]] = None,
        since_version: str = "1.0.0",
        deprecation_notice: str = "",
        tags: Optional[Set[str]] = None,
        security_notes: Optional[List[str]] = None,
        nist_compliant: bool = False,
    ) -> None:
        """Register a cryptographic API endpoint in the catalog."""
        endpoint = CryptoAPIEndpoint(
            name=name,
            module=module,
            signature=signature,
            docstring=docstring,
            stability=stability,
            parameters=parameters or [],
            returns=returns,
            raises=raises or [],
            examples=examples or [],
            since_version=since_version,
            deprecation_notice=deprecation_notice,
            tags=tags or set(),
            security_notes=security_notes or [],
            nist_compliant=nist_compliant,
        )
        self._apis[name] = endpoint
        self._modules.add(module)
    
    def get_api(self, name: str) -> Optional[CryptoAPIEndpoint]:
        """Get API documentation by name."""
        return self._apis.get(name)
    
    def search_apis(self, query: str) -> List[CryptoAPIEndpoint]:
        """Search APIs by name, module, or tag."""
        query_lower = query.lower()
        results = []
        for api in self._apis.values():
            if (query_lower in api.name.lower() or
                query_lower in api.module.lower() or
                any(query_lower in tag.lower() for tag in api.tags)):
                results.append(api)
        return results
    
    def get_apis_by_stability(self, stability: StabilityLevel) -> List[CryptoAPIEndpoint]:
        """Get all APIs with a specific stability level."""
        return [api for api in self._apis.values() if api.stability == stability]
    
    def get_nist_compliant_apis(self) -> List[CryptoAPIEndpoint]:
        """Get all NIST-standardized post-quantum APIs."""
        return [api for api in self._apis.values() if api.nist_compliant]
    
    def export_json(self) -> str:
        """Export entire catalog as JSON string."""
        data = {
            "catalog_version": "7.0.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_apis": len(self._apis),
            "nist_compliant_count": len(self.get_nist_compliant_apis()),
            "stability_counts": {
                str(level): len(self.get_apis_by_stability(level))
                for level in StabilityLevel
            },
            "apis": [api.to_dict() for api in self._apis.values()],
        }
        return json.dumps(data, indent=2)
    
    def export_markdown(self) -> str:
        """Export catalog as Markdown documentation."""
        lines = [
            "# QuantumCrypt-AI Post-Quantum Crypto API Reference",
            "",
            f"**Generated:** {datetime.utcnow().isoformat()} UTC",
            f"**Total APIs:** {len(self._apis)}",
            f"**NIST Compliant:** {len(self.get_nist_compliant_apis())}",
            "",
            "## Stability Legend",
            "",
            "- 🟢 **STABLE**: API is frozen, no breaking changes",
            "- 🟡 **EXPERIMENTAL**: May change, use with caution",
            "- 🔴 **DEPRECATED**: Will be removed in future version",
            "- ⚫ **INTERNAL**: Implementation detail, not for public use",
            "",
            "## NIST Compliance Legend",
            "",
            "- ✅ **NIST**: Standardized by NIST (FIPS 203, FIPS 204)",
            "",
        ]
        
        for stability in StabilityLevel:
            apis = self.get_apis_by_stability(stability)
            if not apis:
                continue
            
            icon = {
                StabilityLevel.STABLE: "🟢",
                StabilityLevel.EXPERIMENTAL: "🟡",
                StabilityLevel.DEPRECATED: "🔴",
                StabilityLevel.INTERNAL: "⚫",
            }[stability]
            
            lines.extend([
                f"## {icon} {stability.value} APIs ({len(apis)})",
                "",
            ])
            
            for api in sorted(apis, key=lambda a: a.name):
                nist_badge = " ✅ NIST" if api.nist_compliant else ""
                
                lines.extend([
                    f"### `{api.name}`{nist_badge}",
                    "",
                    f"**Module:** `{api.module}`",
                    f"**Since:** v{api.since_version}",
                    f"**Signature:** `{api.signature}`",
                    "",
                    f"{api.docstring}",
                    "",
                ])
                
                if api.parameters:
                    lines.extend(["**Parameters:**", ""])
                    for param in api.parameters:
                        lines.append(f"- `{param['name']}` ({param['type']}): {param['description']}")
                    lines.append("")
                
                if api.returns:
                    lines.extend([f"**Returns:** {api.returns}", ""])
                
                if api.raises:
                    lines.extend(["**Raises:**", ""])
                    for exc in api.raises:
                        lines.append(f"- {exc}")
                    lines.append("")
                
                if api.security_notes:
                    lines.extend(["**Security Notes:**", ""])
                    for note in api.security_notes:
                        lines.append(f"- ⚠️ {note}")
                    lines.append("")
                
                if api.deprecation_notice:
                    lines.extend([f"> **⚠️ DEPRECATION NOTICE:** {api.deprecation_notice}", ""])
                
                if api.examples:
                    lines.extend(["**Examples:**", ""])
                    for ex in api.examples:
                        lines.extend(["```python", ex.strip(), "```", ""])
                
                if api.tags:
                    lines.append(f"**Tags:** {', '.join(f'`{t}`' for t in sorted(api.tags))}")
                    lines.append("")
                
                lines.append("---")
                lines.append("")
        
        return "\n".join(lines)


# Singleton instance
_catalog_instance: Optional[CryptoAPIDocumentationCatalog] = None


def get_crypto_documentation_catalog() -> CryptoAPIDocumentationCatalog:
    """
    Get the global crypto API documentation catalog instance.
    
    Returns:
        Singleton CryptoAPIDocumentationCatalog instance
    
    STABILITY: STABLE
    """
    global _catalog_instance
    if _catalog_instance is None:
        _catalog_instance = CryptoAPIDocumentationCatalog()
    return _catalog_instance


def get_crypto_api_stability(api_name: str) -> Optional[str]:
    """Get stability level for a specific crypto API."""
    catalog = get_crypto_documentation_catalog()
    api = catalog.get_api(api_name)
    return str(api.stability) if api else None


def is_nist_compliant(api_name: str) -> bool:
    """Check if an API implements a NIST-standardized algorithm."""
    catalog = get_crypto_documentation_catalog()
    api = catalog.get_api(api_name)
    return api is not None and api.nist_compliant


def get_nist_algorithms() -> List[str]:
    """Get list of all NIST-compliant API names."""
    catalog = get_crypto_documentation_catalog()
    return [api.name for api in catalog.get_nist_compliant_apis()]


# =====================================================================
# CRYPTO USAGE EXAMPLES
# =====================================================================

CRYPTO_EXAMPLES: List[CryptoUsageExample] = [
    CryptoUsageExample(
        title="Post-Quantum Key Exchange",
        code="""
from quantum_crypt import KyberKEM

# Alice generates keypair
kem = KyberKEM()
alice_pk, alice_sk = kem.generate_keypair(security_level=3)

# Bob encapsulates secret using Alice's public key
ciphertext, shared_secret_bob = kem.encapsulate(alice_pk)

# Alice decapsulates to get same shared secret
shared_secret_alice = kem.decapsulate(ciphertext, alice_sk)

# Both parties now have identical shared secrets
assert shared_secret_alice == shared_secret_bob
""",
        description="Basic Kyber KEM key exchange",
        security_considerations=[
            "Keys should be ephemeral for forward secrecy",
            "Authenticate public keys to prevent MITM",
        ],
    ),
    CryptoUsageExample(
        title="Hybrid Migration Pattern",
        code="""
from quantum_crypt import HybridKEM

# Use hybrid (Kyber + X25519) during migration
hybrid = HybridKEM()
pk, sk = hybrid.generate_keypair()

# Safe even if one algorithm is compromised
ct, ss = hybrid.encapsulate(pk)
""",
        description="Recommended pattern for post-quantum migration",
        security_considerations=[
            "Hybrid mode provides defense in depth",
            "Safe transition strategy from classical crypto",
        ],
    ),
]
