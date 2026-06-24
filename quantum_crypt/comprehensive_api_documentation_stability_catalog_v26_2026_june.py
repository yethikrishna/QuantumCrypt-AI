"""
QuantumCrypt-AI Comprehensive API Documentation & Stability Catalog v26
=======================================================================
API Stability Markers: STABLE | BETA | EXPERIMENTAL | DEPRECATED
Last Updated: June 24, 2026
Catalog Version: 26

This catalog provides comprehensive documentation, stability markers,
usage examples, and API signatures for all QuantumCrypt-AI modules.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
import json
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    BETA = "BETA"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


@dataclass
class APIDocumentation:
    """Complete API Documentation Entry"""
    module_name: str
    class_name: str
    stability: StabilityLevel
    description: str
    primary_methods: List[str]
    method_signatures: Dict[str, str]
    usage_example: str
    parameters: Dict[str, str]
    return_values: Dict[str, str]
    exceptions: List[str]
    dependencies: List[str]
    thread_safe: bool
    performance_notes: str
    quantum_safe: bool = True
    deprecation_notice: Optional[str] = None
    since_version: str = "2026.6.24"


class QuantumCryptAPICatalog:
    """
    Comprehensive API Documentation and Stability Catalog for QuantumCrypt-AI
    
    STABILITY PHILOSOPHY:
    - STABLE: Production-ready, API frozen, backward compatible
    - BETA: Mostly stable, minor refinements possible
    - EXPERIMENTAL: Active development, breaking changes likely
    - DEPRECATED: Scheduled for removal, use alternatives
    
    QUANTUM-SAFE GUARANTEE:
    All marked modules implement post-quantum cryptography resistant
    to both classical and quantum computing attacks.
    
    USAGE:
        catalog = QuantumCryptAPICatalog()
        docs = catalog.get_documentation("QuantumKeyExchange")
        print(catalog.generate_markdown_report())
    """
    
    def __init__(self):
        self._catalog: Dict[str, APIDocumentation] = {}
        self._build_catalog()
    
    def _build_catalog(self):
        """Build the complete API documentation catalog"""
        
        # ==================== KEY EXCHANGE MODULES ====================
        
        self._catalog["QuantumKeyExchange"] = APIDocumentation(
            module_name="quantum_key_exchange_2026",
            class_name="QuantumKeyExchange",
            stability=StabilityLevel.STABLE,
            description="Post-quantum secure key exchange implementation using CRYSTALS-Kyber (NIST standard) for quantum-resistant key establishment between parties.",
            primary_methods=["generate_keypair", "encapsulate", "decapsulate", "perform_exchange"],
            method_signatures={
                "generate_keypair": "generate_keypair(security_level: int = 3) -> Tuple[PublicKey, PrivateKey]",
                "encapsulate": "encapsulate(public_key: PublicKey) -> Tuple[SharedSecret, Ciphertext]",
                "decapsulate": "decapsulate(private_key: PrivateKey, ciphertext: Ciphertext) -> SharedSecret",
                "perform_exchange": "perform_exchange(party_a: KeyPair, party_b_pub: PublicKey) -> SharedSecret"
            },
            usage_example="""
from quantum_crypt import QuantumKeyExchange

# Initialize with NIST security level 3
qke = QuantumKeyExchange(security_level=3)

# Party A generates keypair
sk_a, pk_a = qke.generate_keypair()

# Party B encapsulates secret using A's public key
shared_secret_b, ciphertext = qke.encapsulate(pk_a)

# Party A decapsulates to get the same shared secret
shared_secret_a = qke.decapsulate(sk_a, ciphertext)

# Both parties now have identical quantum-safe shared secrets
assert shared_secret_a == shared_secret_b
print(f"Quantum-safe key established: {shared_secret_a.hex()[:16]}...")
""",
            parameters={
                "security_level": "NIST security level (1-5), default=3",
                "public_key": "Recipient's public key for encapsulation",
                "private_key": "Recipient's private key for decapsulation",
                "ciphertext": "Encapsulated ciphertext"
            },
            return_values={
                "keypair": "(private_key, public_key) tuple",
                "shared_secret": "32/64-byte cryptographically secure shared secret",
                "ciphertext": "Encapsulated key material"
            },
            exceptions=["ValueError (invalid security level)", "CryptographyError"],
            dependencies=["cryptography"],
            thread_safe=True,
            performance_notes="~1.5ms keypair generation, FIPS 140-3 compliant",
            quantum_safe=True
        )
        
        self._catalog["NewHopeKeyExchange"] = APIDocumentation(
            module_name="newhope_key_exchange_2026",
            class_name="NewHopeKeyExchange",
            stability=StabilityLevel.BETA,
            description="Ring-LWE based post-quantum key exchange (NewHope protocol) providing lattice-based security as an alternative to CRYSTALS-Kyber.",
            primary_methods=["generate_seed", "compute_public", "compute_shared"],
            method_signatures={
                "generate_seed": "generate_seed() -> bytes",
                "compute_public": "compute_public(seed: bytes) -> PublicKey",
                "compute_shared": "compute_shared(secret_seed: bytes, peer_public: PublicKey) -> SharedSecret"
            },
            usage_example="""
from quantum_crypt import NewHopeKeyExchange

newhope = NewHopeKeyExchange()

# Alice's side
seed_alice = newhope.generate_seed()
pub_alice = newhope.compute_public(seed_alice)

# Bob's side
seed_bob = newhope.generate_seed()
pub_bob = newhope.compute_public(seed_bob)

# Compute shared secrets
ss_alice = newhope.compute_shared(seed_alice, pub_bob)
ss_bob = newhope.compute_shared(seed_bob, pub_alice)

assert ss_alice == ss_bob
""",
            parameters={"seed": "Cryptographically secure random seed"},
            return_values={
                "public_key": "1824-byte public key",
                "shared_secret": "32-byte shared secret"
            },
            exceptions=["ValueError"],
            dependencies=[],
            thread_safe=True,
            performance_notes="High-performance ring-LWE implementation",
            quantum_safe=True
        )
        
        # ==================== SIGNATURE MODULES ====================
        
        self._catalog["QuantumDigitalSignature"] = APIDocumentation(
            module_name="quantum_digital_signature_2026",
            class_name="QuantumDigitalSignature",
            stability=StabilityLevel.STABLE,
            description="Post-quantum digital signatures using CRYSTALS-Dilithium (NIST standard) for quantum-resistant authentication and non-repudiation.",
            primary_methods=["generate_keypair", "sign", "verify", "sign_batch"],
            method_signatures={
                "generate_keypair": "generate_keypair(security_level: int = 3) -> Tuple[SigningKey, VerifyKey]",
                "sign": "sign(private_key: SigningKey, message: bytes) -> Signature",
                "verify": "verify(public_key: VerifyKey, message: bytes, signature: Signature) -> bool",
                "sign_batch": "sign_batch(private_key: SigningKey, messages: List[bytes]) -> List[Signature]"
            },
            usage_example="""
from quantum_crypt import QuantumDigitalSignature

signer = QuantumDigitalSignature(security_level=3)

# Generate signing keypair
signing_key, verify_key = signer.generate_keypair()

# Sign a message
message = b"Important document requiring quantum-safe signature"
signature = signer.sign(signing_key, message)

# Verify signature
is_valid = signer.verify(verify_key, message, signature)
print(f"Signature valid: {is_valid}")

if is_valid:
    print("✓ Quantum-safe authentication verified")
""",
            parameters={
                "security_level": "NIST security level (2,3,5), default=3",
                "private_key": "Signing (private) key",
                "public_key": "Verification (public) key",
                "message": "Message bytes to sign/verify",
                "signature": "Digital signature bytes"
            },
            return_values={
                "keypair": "(signing_key, verify_key) tuple",
                "signature": "Quantum-safe digital signature",
                "is_valid": "Boolean verification result"
            },
            exceptions=["ValueError", "InvalidSignature"],
            dependencies=["cryptography"],
            thread_safe=True,
            performance_notes="~2ms signing, ~0.5ms verification",
            quantum_safe=True
        )
        
        self._catalog["SPHINCSPlusSignature"] = APIDocumentation(
            module_name="sphincs_plus_signature_2026",
            class_name="SPHINCSPlusSignature",
            stability=StabilityLevel.BETA,
            description="Stateless hash-based post-quantum signature scheme (SPHINCS+) providing NIST-standardized hash-based signatures with small public keys.",
            primary_methods=["keygen", "sign", "verify"],
            method_signatures={
                "keygen": "keygen(security_strength: int = 128) -> KeyPair",
                "sign": "sign(secret_key: bytes, message: bytes) -> Signature",
                "verify": "verify(public_key: bytes, message: bytes, signature: bytes) -> bool"
            },
            usage_example="""
from quantum_crypt import SPHINCSPlusSignature

sphincs = SPHINCSPlusSignature(security_strength=128)
sk, pk = sphincs.keygen()

signature = sphincs.sign(sk, b"Document to sign")
valid = sphincs.verify(pk, b"Document to sign", signature)

print(f"SPHINCS+ signature valid: {valid}")
""",
            parameters={"security_strength": "128 or 256 bits"},
            return_values={
                "signature": "Stateless hash-based signature"
            },
            exceptions=["ValueError"],
            dependencies=[],
            thread_safe=True,
            performance_notes="Stateless, no state management required",
            quantum_safe=True
        )
        
        # ==================== ENCRYPTION MODULES ====================
        
        self._catalog["QuantumResistantAES"] = APIDocumentation(
            module_name="quantum_resistant_aes_2026",
            class_name="QuantumResistantAES",
            stability=StabilityLevel.STABLE,
            description="AES-GCM with quantum-resistant key derivation and enhanced side-channel protection. Uses SHA-3 derived keys and constant-time operations.",
            primary_methods=["generate_key", "encrypt", "decrypt", "encrypt_file", "decrypt_file"],
            method_signatures={
                "generate_key": "generate_key(strength: int = 256) -> Key",
                "encrypt": "encrypt(key: Key, plaintext: bytes, associated_data: bytes = b'') -> CiphertextWithTag",
                "decrypt": "decrypt(key: Key, ciphertext: CiphertextWithTag) -> bytes",
                "encrypt_file": "encrypt_file(key: Key, input_path: str, output_path: str) -> None",
                "decrypt_file": "decrypt_file(key: Key, input_path: str, output_path: str) -> None"
            },
            usage_example="""
from quantum_crypt import QuantumResistantAES

qraes = QuantumResistantAES()
key = qraes.generate_key(strength=256)

# Encrypt
plaintext = b"Secret message with quantum protection"
encrypted = qraes.encrypt(key, plaintext, associated_data=b"v1.0")

# Decrypt
decrypted = qraes.decrypt(key, encrypted)
assert decrypted == plaintext

print(f"Original: {plaintext}")
print(f"Encrypted size: {len(encrypted.ciphertext)} bytes")
""",
            parameters={
                "strength": "Key strength: 128, 192, or 256 bits",
                "key": "Encryption key",
                "plaintext": "Data to encrypt",
                "ciphertext": "Encrypted data with authentication tag",
                "associated_data": "Authenticated but unencrypted data"
            },
            return_values={
                "key": "Cryptographically secure symmetric key",
                "ciphertext": "Authenticated ciphertext with nonce and tag"
            },
            exceptions=["ValueError", "InvalidTag", "DecryptionError"],
            dependencies=["cryptography", "pynacl"],
            thread_safe=True,
            performance_notes="Hardware-accelerated AES-NI when available",
            quantum_safe=True
        )
        
        self._catalog["HybridQuantumEncryption"] = APIDocumentation(
            module_name="hybrid_quantum_encryption_2026",
            class_name="HybridQuantumEncryption",
            stability=StabilityLevel.STABLE,
            description="Hybrid encryption combining classical (AES) and post-quantum (Kyber) encryption for defense-in-depth against both current and future threats.",
            primary_methods=["hybrid_encrypt", "hybrid_decrypt", "wrap_key", "unwrap_key"],
            method_signatures={
                "hybrid_encrypt": "hybrid_encrypt(plaintext: bytes, recipient_pub: PublicKey) -> HybridCiphertext",
                "hybrid_decrypt": "hybrid_decrypt(ciphertext: HybridCiphertext, recipient_sk: PrivateKey) -> bytes",
                "wrap_key": "wrap_key(key_to_wrap: bytes, wrapping_pub: PublicKey) -> WrappedKey",
                "unwrap_key": "unwrap_key(wrapped_key: WrappedKey, wrapping_sk: PrivateKey) -> bytes"
            },
            usage_example="""
from quantum_crypt import HybridQuantumEncryption, QuantumKeyExchange

# Setup
qke = QuantumKeyExchange()
sk, pk = qke.generate_keypair()

# Hybrid encryption
hybrid = HybridQuantumEncryption()
message = b"Double-protected secret message"

# Encrypt with both classical and quantum layers
encrypted = hybrid.hybrid_encrypt(message, pk)

# Decrypt requires both layers to succeed
decrypted = hybrid.hybrid_decrypt(encrypted, sk)

assert decrypted == message
print("✓ Dual-layer hybrid decryption successful")
print(f"  - Classical layer: AES-256-GCM")
print(f"  - Quantum layer: CRYSTALS-Kyber")
""",
            parameters={
                "plaintext": "Message to encrypt",
                "recipient_pub": "Recipient's post-quantum public key",
                "recipient_sk": "Recipient's post-quantum private key"
            },
            return_values={
                "ciphertext": "Dual-layer encrypted message bundle"
            },
            exceptions=["ValueError", "DecryptionError"],
            dependencies=["cryptography"],
            thread_safe=True,
            performance_notes="Defense-in-depth with minimal performance overhead",
            quantum_safe=True
        )
        
        # ==================== HASH MODULES ====================
        
        self._catalog["QuantumResistantHash"] = APIDocumentation(
            module_name="quantum_resistant_hash_2026",
            class_name="QuantumResistantHash",
            stability=StabilityLevel.STABLE,
            description="Quantum-resistant hash functions including SHA-3, SHAKE, and BLAKE3 with protection against Grover's algorithm attacks.",
            primary_methods=["hash", "hash_file", "extendable_output", "keyed_hash"],
            method_signatures={
                "hash": "hash(data: bytes, algorithm: str = 'sha3_256') -> Digest",
                "hash_file": "hash_file(filepath: str, algorithm: str = 'sha3_256') -> Digest",
                "extendable_output": "extendable_output(data: bytes, output_length: int) -> bytes",
                "keyed_hash": "keyed_hash(key: bytes, data: bytes) -> MAC"
            },
            usage_example="""
from quantum_crypt import QuantumResistantHash

hasher = QuantumResistantHash()

# Standard SHA3-256
digest = hasher.hash(b"Important data", algorithm="sha3_256")
print(f"SHA3-256: {digest.hex()}")

# SHAKE256 extendable output (any length)
xof = hasher.extendable_output(b"Seed data", output_length=100)
print(f"XOF 100 bytes: {xof.hex()[:32]}...")

# Keyed hash (MAC)
mac = hasher.keyed_hash(secret_key, b"Authenticated message")
""",
            parameters={
                "data": "Input data to hash",
                "algorithm": "'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'blake3'",
                "output_length": "Desired output length for XOF"
            },
            return_values={
                "digest": "Cryptographic hash digest",
                "mac": "Keyed message authentication code"
            },
            exceptions=["ValueError (unknown algorithm)"],
            dependencies=["cryptography", "blake3"],
            thread_safe=True,
            performance_notes="BLAKE3 provides highest throughput for large data",
            quantum_safe=True
        )
        
        # ==================== RANDOMNESS MODULES ====================
        
        self._catalog["QuantumRandomGenerator"] = APIDocumentation(
            module_name="quantum_random_generator_2026",
            class_name="QuantumRandomGenerator",
            stability=StabilityLevel.STABLE,
            description="Cryptographically secure random number generator with multiple entropy sources and health testing. Suitable for key generation and secrets.",
            primary_methods=["random_bytes", "random_int", "random_uniform", "gen_key", "health_check"],
            method_signatures={
                "random_bytes": "random_bytes(length: int) -> bytes",
                "random_int": "random_int(min_val: int, max_val: int) -> int",
                "random_uniform": "random_uniform() -> float",
                "gen_key": "gen_key(bits: int = 256) -> bytes",
                "health_check": "health_check() -> HealthStatus"
            },
            usage_example="""
from quantum_crypt import QuantumRandomGenerator

rng = QuantumRandomGenerator()

# Verify RNG health before use
health = rng.health_check()
if health.passed:
    print(f"✓ RNG health check passed (entropy: {health.entropy:.1f} bits)")
    
    # Generate cryptographically secure random bytes
    key = rng.gen_key(256)
    nonce = rng.random_bytes(12)
    
    print(f"Generated 256-bit key: {key.hex()[:32]}...")
    print(f"Generated nonce: {nonce.hex()}")
else:
    print("⚠️ RNG health check failed - entropy source compromised!")
""",
            parameters={
                "length": "Number of random bytes to generate",
                "bits": "Key size in bits (multiples of 8)"
            },
            return_values={
                "bytes": "Cryptographically secure random bytes",
                "health_status": "Entropy health and quality metrics"
            },
            exceptions=["RNGHealthError", "ValueError"],
            dependencies=["secrets"],
            thread_safe=True,
            performance_notes="System CSPRNG with continuous health testing",
            quantum_safe=True
        )
        
        # ==================== KEY MANAGEMENT MODULES ====================
        
        self._catalog["QuantumKeyManager"] = APIDocumentation(
            module_name="quantum_key_manager_2026",
            class_name="QuantumKeyManager",
            stability=StabilityLevel.BETA,
            description="Secure key management with key wrapping, rotation, derivation, and zeroization. Implements HSM-like key protection in software.",
            primary_methods=["wrap_key", "unwrap_key", "derive_key", "rotate_key", "zeroize"],
            method_signatures={
                "wrap_key": "wrap_key(target_key: Key, wrapping_key: Key) -> WrappedKey",
                "unwrap_key": "unwrap_key(wrapped_key: WrappedKey, wrapping_key: Key) -> Key",
                "derive_key": "derive_key(master: Key, context: bytes, length: int) -> Key",
                "rotate_key": "rotate_key(old_key: Key, policy: RotationPolicy) -> Key",
                "zeroize": "zeroize(key_buffer: bytearray) -> None"
            },
            usage_example="""
from quantum_crypt import QuantumKeyManager, QuantumRandomGenerator

km = QuantumKeyManager()
rng = QuantumRandomGenerator()

# Generate master key
master_key = rng.gen_key(256)

# Derive context-specific subkeys
encryption_key = km.derive_key(master_key, b"encryption/v1", 32)
signing_key = km.derive_key(master_key, b"signing/v1", 64)

# Securely zeroize sensitive data when done
sensitive_buffer = bytearray(encryption_key)
km.zeroize(sensitive_buffer)
print("✓ Sensitive key material securely zeroized")
""",
            parameters={
                "target_key": "Key to wrap/protect",
                "wrapping_key": "Key encryption key",
                "context": "Key derivation context for domain separation"
            },
            return_values={
                "wrapped_key": "Securely wrapped key material"
            },
            exceptions=["ValueError", "KeyWrapError"],
            dependencies=["cryptography"],
            thread_safe=True,
            performance_notes="Secure zeroization uses memset_s via ctypes",
            quantum_safe=True
        )
        
        # ==================== CERTIFICATE MODULES ====================
        
        self._catalog["PostQuantumCertificate"] = APIDocumentation(
            module_name="post_quantum_certificate_2026",
            class_name="PostQuantumCertificate",
            stability=StabilityLevel.BETA,
            description="X.509 certificate handling with post-quantum signature algorithms for quantum-safe PKI operations.",
            primary_methods=["generate_csr", "sign_certificate", "verify_certificate", "extract_pubkey"],
            method_signatures={
                "generate_csr": "generate_csr(subject: DN, keypair: KeyPair) -> CSR",
                "sign_certificate": "sign_certificate(csr: CSR, ca_keypair: KeyPair, validity_days: int) -> Certificate",
                "verify_certificate": "verify_certificate(cert: Certificate, ca_pubkey: PublicKey) -> bool",
                "extract_pubkey": "extract_pubkey(cert: Certificate) -> PublicKey"
            },
            usage_example="""
from quantum_crypt import PostQuantumCertificate, QuantumDigitalSignature

pki = PostQuantumCertificate()
signer = QuantumDigitalSignature()

# Generate CA keypair
ca_sk, ca_pk = signer.generate_keypair()

# Generate server CSR
server_sk, server_pk = signer.generate_keypair()
csr = pki.generate_csr({"CN": "server.example.com"}, (server_sk, server_pk))

# Sign certificate with CA
cert = pki.sign_certificate(csr, (ca_sk, ca_pk), validity_days=365)

# Verify certificate chain
is_valid = pki.verify_certificate(cert, ca_pk)
print(f"Certificate valid: {is_valid}")
""",
            parameters={
                "subject": "Distinguished name dictionary",
                "keypair": "Post-quantum keypair"
            },
            return_values={
                "certificate": "Post-quantum X.509 certificate"
            },
            exceptions=["ValueError", "CertificateError"],
            dependencies=["cryptography"],
            thread_safe=True,
            performance_notes="X.509 compatible with post-quantum extensions",
            quantum_safe=True
        )
        
        # ==================== SECURE COMMUNICATION MODULES ====================
        
        self._catalog["QuantumTLSWrapper"] = APIDocumentation(
            module_name="quantum_tls_wrapper_2026",
            class_name="QuantumTLSWrapper",
            stability=StabilityLevel.EXPERIMENTAL,
            description="Experimental post-quantum TLS 1.3 wrapper with hybrid key exchange for quantum-resistant network communication.",
            primary_methods=["create_server_context", "create_client_context", "wrap_socket", "get_negotiated_cipher"],
            method_signatures={
                "create_server_context": "create_server_context(cert_chain: str, key: str) -> TLSContext",
                "create_client_context": "create_client_context(ca_certs: Optional[str]) -> TLSContext",
                "wrap_socket": "wrap_socket(sock: socket, context: TLSContext, server_side: bool) -> SecureSocket",
                "get_negotiated_cipher": "get_negotiated_cipher(secure_socket: SecureSocket) -> str"
            },
            usage_example="""
from quantum_crypt import QuantumTLSWrapper

qtls = QuantumTLSWrapper()

# Server side
server_ctx = qtls.create_server_context("server.crt", "server.key")
secure_conn = qtls.wrap_socket(client_socket, server_ctx, server_side=True)

# Client side
client_ctx = qtls.create_client_context("ca.crt")
secure_client = qtls.wrap_socket(raw_socket, client_ctx, server_side=False)

cipher = qtls.get_negotiated_cipher(secure_client)
print(f"Negotiated: {cipher}")
""",
            parameters={
                "cert_chain": "Path to certificate chain",
                "key": "Path to private key"
            },
            return_values={
                "context": "TLS context with post-quantum extensions"
            },
            exceptions=["TLSHandshakeError", "ValueError"],
            dependencies=["ssl"],
            thread_safe=True,
            performance_notes="Experimental - requires OpenSSL 3.2+ with PQ patches",
            quantum_safe=True
        )
        
        # ==================== SECURITY UTILITIES ====================
        
        self._catalog["SecureMemory"] = APIDocumentation(
            module_name="secure_memory_2026",
            class_name="SecureMemory",
            stability=StabilityLevel.STABLE,
            description="Secure memory utilities including constant-time comparison, secure zeroization, and protected memory allocation for sensitive data.",
            primary_methods=["constant_time_compare", "zeroize", "secure_alloc", "wipe_buffer", "mlock"],
            method_signatures={
                "constant_time_compare": "constant_time_compare(a: bytes, b: bytes) -> bool",
                "zeroize": "zeroize(buffer: bytearray) -> None",
                "secure_alloc": "secure_alloc(size: int) -> bytearray",
                "wipe_buffer": "wipe_buffer(buffer: bytearray) -> None",
                "mlock": "mlock(buffer: bytearray) -> bool"
            },
            usage_example="""
from quantum_crypt import SecureMemory

secmem = SecureMemory()

# ALWAYS use constant-time comparison for secrets!
secret_a = b"supersecretkey123"
secret_b = get_user_input()

# This prevents timing side-channel attacks
if secmem.constant_time_compare(secret_a, secret_b):
    print("Access granted")
else:
    print("Access denied")

# Always zeroize sensitive buffers after use
sensitive = bytearray(b"temporary secret")
secmem.zeroize(sensitive)
print("✓ Buffer securely wiped")
""",
            parameters={
                "a, b": "Byte strings to compare",
                "buffer": "Mutable buffer to zeroize"
            },
            return_values={
                "is_equal": "True if equal (constant time)"
            },
            exceptions=["ValueError"],
            dependencies=["ctypes"],
            thread_safe=True,
            performance_notes="Constant-time operations prevent timing attacks",
            quantum_safe=True
        )
    
    def get_documentation(self, class_name: str) -> Optional[APIDocumentation]:
        """Get documentation for a specific API class"""
        return self._catalog.get(class_name)
    
    def list_all_apis(self, stability_filter: Optional[StabilityLevel] = None) -> List[str]:
        """List all APIs, optionally filtered by stability level"""
        if stability_filter:
            return [name for name, doc in self._catalog.items() 
                   if doc.stability == stability_filter]
        return list(self._catalog.keys())
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get count of APIs by stability level"""
        summary = {"STABLE": 0, "BETA": 0, "EXPERIMENTAL": 0, "DEPRECATED": 0}
        for doc in self._catalog.values():
            summary[doc.stability.value] += 1
        return summary
    
    def generate_markdown_report(self) -> str:
        """Generate comprehensive markdown documentation report"""
        summary = self.get_stability_summary()
        quantum_safe_count = sum(1 for doc in self._catalog.values() if doc.quantum_safe)
        
        report = f"""# QuantumCrypt-AI API Documentation Catalog v26
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total APIs Documented:** {len(self._catalog)}
**Quantum-Safe APIs:** {quantum_safe_count}/{len(self._catalog)}

## Stability Summary
| Stability Level | Count |
|-----------------|-------|
| 🟢 STABLE | {summary['STABLE']} |
| 🟡 BETA | {summary['BETA']} |
| 🟠 EXPERIMENTAL | {summary['EXPERIMENTAL']} |
| 🔴 DEPRECATED | {summary['DEPRECATED']} |

---

## Quantum-Safe Guarantee
All documented modules implement post-quantum cryptography
resistant to both classical and quantum computing attacks.

---

## Complete API Documentation
"""
        
        for stability in [StabilityLevel.STABLE, StabilityLevel.BETA, 
                         StabilityLevel.EXPERIMENTAL, StabilityLevel.DEPRECATED]:
            apis = self.list_all_apis(stability)
            if not apis:
                continue
                
            badge = "🟢" if stability == StabilityLevel.STABLE else \
                   "🟡" if stability == StabilityLevel.BETA else \
                   "🟠" if stability == StabilityLevel.EXPERIMENTAL else "🔴"
            
            report += f"\n### {badge} {stability.value} APIs\n\n"
            
            for api_name in sorted(apis):
                doc = self._catalog[api_name]
                report += f"\n#### `{doc.class_name}`\n\n"
                report += f"**Module:** `{doc.module_name}.py`  \n"
                report += f"**Since:** v{doc.since_version}  \n"
                report += f"**Thread Safe:** {'✓ Yes' if doc.thread_safe else '✗ No'}  \n"
                report += f"**Quantum-Safe:** {'✓ Yes' if doc.quantum_safe else '✗ No'}  \n\n"
                report += f"**Description:** {doc.description}\n\n"
                
                report += "**Primary Methods:**\n"
                for method in doc.primary_methods:
                    report += f"- `{method}`\n"
                
                report += "\n**Method Signatures:**\n"
                for method, sig in doc.method_signatures.items():
                    report += f"- `{sig}`\n"
                
                report += "\n**Usage Example:**\n```python\n"
                report += doc.usage_example.strip()
                report += "\n```\n\n"
                
                report += "**Performance:** " + doc.performance_notes + "\n\n"
                report += "---\n"
        
        return report
    
    def export_json(self) -> str:
        """Export catalog as JSON"""
        export_data = {}
        for name, doc in self._catalog.items():
            export_data[name] = {
                "class_name": doc.class_name,
                "module_name": doc.module_name,
                "stability": doc.stability.value,
                "description": doc.description,
                "primary_methods": doc.primary_methods,
                "method_signatures": doc.method_signatures,
                "thread_safe": doc.thread_safe,
                "quantum_safe": doc.quantum_safe,
                "performance_notes": doc.performance_notes,
                "since_version": doc.since_version
            }
        return json.dumps(export_data, indent=2)


# Export catalog instance
__all__ = ["QuantumCryptAPICatalog", "StabilityLevel", "APIDocumentation"]

if __name__ == "__main__":
    catalog = QuantumCryptAPICatalog()
    print(catalog.generate_markdown_report())
