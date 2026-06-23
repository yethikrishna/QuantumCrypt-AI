"""
QuantumCrypt-AI Comprehensive Documentation & API Stability Catalog v21
=======================================================================
STABLE / EXPERIMENTAL / DEPRECATED API MARKERS + USAGE EXAMPLES

ADD-ONLY: This module adds documentation only. No production logic changes.
All existing code behavior is 100% preserved.

VERSION: v21
DATE: June 24, 2026
AUTHOR: yethikrishna
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import functools


class StabilityLevel(Enum):
    """API Stability Classification"""
    STABLE = "STABLE"           # Production-ready, backward compatible
    EXPERIMENTAL = "EXPERIMENTAL"  # New, subject to change
    DEPRECATED = "DEPRECATED"   # Will be removed in future versions
    BETA = "BETA"               # Testing phase, mostly stable
    INTERNAL = "INTERNAL"       # Internal use only, no guarantees


@dataclass
class APIDocumentation:
    """Documentation metadata for a module or function"""
    name: str
    stability: StabilityLevel
    version_added: str
    description: str
    usage_example: str
    parameters: Dict[str, str] = field(default_factory=dict)
    returns: str = ""
    exceptions: List[str] = field(default_factory=list)
    deprecation_notice: str = ""
    module_path: str = ""
    last_updated: str = datetime.now().isoformat()


@dataclass
class ModuleUsageGuide:
    """Complete usage guide for a module"""
    module_name: str
    stability: StabilityLevel
    version: str
    quick_start: str
    full_example: str
    best_practices: List[str]
    common_pitfalls: List[str]
    related_modules: List[str]


def api_stability(
    stability: StabilityLevel,
    version_added: str,
    deprecation_notice: str = ""
):
    """
    Decorator to mark API stability level.
    ADD-ONLY: No runtime behavior change, only metadata.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        
        wrapper._api_stability = stability
        wrapper._version_added = version_added
        wrapper._deprecation_notice = deprecation_notice
        return wrapper
    return decorator


class CryptoDocumentationCatalog:
    """Central catalog for all QuantumCrypt API documentation"""
    
    def __init__(self):
        self._apis: Dict[str, APIDocumentation] = {}
        self._modules: Dict[str, ModuleUsageGuide] = {}
        self._init_core_crypto_docs()
        self._init_v14_docs()
        self._init_v16_docs()
    
    def _init_core_crypto_docs(self):
        """Initialize documentation for core crypto modules"""
        
        # Quantum-Safe Key Exchange - STABLE
        self._apis["quantum_key_exchange"] = APIDocumentation(
            name="QuantumKeyExchange",
            stability=StabilityLevel.STABLE,
            version_added="v1",
            description="Post-quantum key exchange using CRYSTALS-Kyber algorithm. NIST-standardized quantum-resistant key encapsulation mechanism.",
            usage_example="""
from quantum_crypt.quantum_key_exchange import QuantumKeyExchange

# Alice generates keypair
alice = QuantumKeyExchange()
alice_pk = alice.generate_keypair()

# Bob encapsulates secret using Alice's pubkey
bob = QuantumKeyExchange()
shared_secret_bob, ciphertext = bob.encapsulate(alice_pk)

# Alice decapsulates to get same shared secret
shared_secret_alice = alice.decapsulate(ciphertext)

assert shared_secret_alice == shared_secret_bob  # Same key!
""",
            parameters={
                "key_size": "int - Security level (2 for NIST Level 2)",
                "random_seed": "Optional[bytes] - Deterministic key generation"
            },
            returns="32-byte shared secret for symmetric encryption",
            exceptions=["ValueError on invalid public key", "TypeError on malformed ciphertext"]
        )
        
        # AES-GCM Encryption - STABLE
        self._apis["aes_gcm_encryption"] = APIDocumentation(
            name="AESGCMEncryption",
            stability=StabilityLevel.STABLE,
            version_added="v2",
            description="Authenticated encryption with AES-GCM. Provides confidentiality, integrity, and authentication in one step.",
            usage_example="""
from quantum_crypt.aes_gcm import AESGCMEncryption

crypto = AESGCMEncryption()
key = crypto.generate_key()  # 256-bit key

# Encrypt with associated data (AEAD)
ciphertext, nonce, tag = crypto.encrypt(
    plaintext=b"Secret message",
    key=key,
    associated_data=b"user:12345"
)

# Decrypt and verify
plaintext = crypto.decrypt(ciphertext, key, nonce, tag, associated_data=b"user:12345")
""",
            parameters={
                "plaintext": "bytes - Data to encrypt",
                "key": "bytes - 16/24/32 byte AES key",
                "associated_data": "bytes - Authenticated but not encrypted metadata"
            },
            returns="Tuple of (ciphertext, nonce, authentication tag)"
        )
        
        # Digital Signature - STABLE
        self._apis["digital_signature"] = APIDocumentation(
            name="DigitalSignature",
            stability=StabilityLevel.STABLE,
            version_added="v3",
            description="Post-quantum digital signatures using CRYSTALS-Dilithium. NIST-standardized signature algorithm.",
            usage_example="""
from quantum_crypt.digital_signature import DigitalSignature

signer = DigitalSignature()
priv_key, pub_key = signer.generate_keypair()

# Sign message
signature = signer.sign(b"Important document", priv_key)

# Verify signature
is_valid = signer.verify(b"Important document", signature, pub_key)
print(f"Signature valid: {is_valid}")
""",
            parameters={
                "message": "bytes - Message to sign/verify",
                "private_key": "bytes - Signer's private key",
                "public_key": "bytes - Signer's public key"
            },
            returns="Signature bytes (for sign) or boolean (for verify)"
        )
        
        # Hash Functions - STABLE
        self._apis["hash_functions"] = APIDocumentation(
            name="HashFunctions",
            stability=StabilityLevel.STABLE,
            version_added="v4",
            description="Cryptographic hash functions including SHA-256, SHA-3, and BLAKE3. HMAC and key derivation support.",
            usage_example="""
from quantum_crypt.hash_functions import HashFunctions

hasher = HashFunctions()

# Basic hash
digest = hasher.sha256(b"Hello, World!")

# HMAC for authentication
mac = hasher.hmac_sha256(b"message", b"secret_key")

# Password hashing (slow, memory-hard)
hashed_pw = hasher.argon2_hash("user_password", salt=b"random_salt")
""",
            parameters={
                "data": "bytes - Input to hash",
                "key": "bytes - HMAC key",
                "salt": "bytes - Salt for password hashing"
            },
            returns="Hash digest bytes or hex string"
        )
    
    def _init_v14_docs(self):
        """Initialize documentation for v14 Observability modules"""
        
        # Crypto HTTP Metrics Server - EXPERIMENTAL (v14)
        self._apis["crypto_http_metrics_server_v14"] = APIDocumentation(
            name="CryptoHTTPMetricsServer v14",
            stability=StabilityLevel.EXPERIMENTAL,
            version_added="v14",
            description="Embedded HTTP server for cryptographic operations metrics export. Tracks encryption latency, key generation rates, and error counts.",
            usage_example="""
from quantum_crypt.feature_expansion_http_metrics_server_v14_2026_june import CryptoMetricsHTTPServer

# Start crypto metrics server
server = CryptoMetricsHTTPServer(port=8001)
server.start()

# Track crypto operations
server.record_encryption("AES-GCM", latency_seconds=0.001)
server.record_key_generation("Kyber-768")
server.record_hash_computation("SHA-256")

# Metrics available at: http://localhost:8001/metrics
""",
            parameters={
                "host": "str - Bind address",
                "port": "int - Listen port",
                "enable_crypto_metrics": "bool - Track detailed crypto stats"
            },
            returns="Running metrics server instance"
        )
        
        # Crypto SLO Alerting - EXPERIMENTAL (v14)
        self._apis["crypto_slo_alerting_v14"] = APIDocumentation(
            name="CryptoSLOAlertingEngine v14",
            stability=StabilityLevel.EXPERIMENTAL,
            version_added="v14",
            description="SLO monitoring specifically for cryptographic operations including HSM availability, key rotation timing, and encryption error rates.",
            usage_example="""
from quantum_crypt.crypto_observability_slo_alerting_baggage_enhanced_v14_2026_june import CryptoSLOAlertingEngine

engine = CryptoSLOAlertingEngine()

# Monitor encryption error rate SLO: 99.99% success
engine.add_crypto_slo(
    name="encryption_success_rate",
    algorithm="AES-GCM",
    target=0.9999,
    window_seconds=3600
)

# Record operations
engine.record_encryption_success("AES-GCM")
engine.record_key_rotation_success()

alerts = engine.evaluate_crypto_slos()
""",
            parameters={
                "name": "str - SLO identifier",
                "algorithm": "str - Cryptographic algorithm name",
                "target": "float - Target success rate",
                "window_seconds": "int - Evaluation window"
            },
            returns="List of crypto-specific alert objects"
        )
        
        # Crypto Baggage Manager - BETA (v14)
        self._apis["crypto_baggage_v14"] = APIDocumentation(
            name="CryptoBaggageManager v14",
            stability=StabilityLevel.BETA,
            version_added="v14",
            description="Cryptographic context propagation with key IDs, request tracing, and audit trail metadata.",
            usage_example="""
from quantum_crypt.crypto_observability_slo_alerting_baggage_enhanced_v14_2026_june import CryptoBaggageManager

baggage = CryptoBaggageManager()

with baggage.new_crypto_operation("data_encryption"):
    baggage.set_key_context(key_id="hsm-key-001", algorithm="AES-GCM")
    baggage.set_audit_context(user="security-admin", purpose="db-encryption")
    
    # Perform encryption - context automatically logged
    result = encrypt_data(data, key)
    
    baggage.record_crypto_success(bytes_processed=len(data))
""",
            parameters={
                "operation": "str - Crypto operation name",
                "key_id": "str - Key identifier for audit",
                "user": "str - User performing operation"
            },
            returns="Context manager for crypto operation lifecycle"
        )
    
    def _init_v16_docs(self):
        """Initialize documentation for v16 Security Hardening modules"""
        
        # Crypto Input Validation - STABLE (v16)
        self._apis["crypto_input_validation_v16"] = APIDocumentation(
            name="CryptoInputValidation v16",
            stability=StabilityLevel.STABLE,
            version_added="v16",
            description="Validation for cryptographic inputs including key format validation, algorithm parameter checking, and side-channel attack mitigations.",
            usage_example="""
from quantum_crypt.crypto_security_hardening_input_validation_injection_protection_v17_2026_june import CryptoInputValidation

validator = CryptoInputValidation()

# Validate AES key
if validator.is_valid_aes_key(user_provided_key):
    encrypt(data, user_provided_key)
else:
    raise SecurityError("Invalid key material")

# Validate nonce format
if not validator.is_valid_nonce(nonce, algorithm="AES-GCM"):
    abort_operation()
""",
            parameters={
                "key_material": "bytes - Key to validate",
                "nonce": "bytes - Nonce/IV to validate",
                "algorithm": "str - Algorithm identifier"
            },
            returns="Boolean indicating validity, or ValidationResult object"
        )
        
        # Secure Key Wiping - STABLE (v16)
        self._apis["secure_key_wiping_v16"] = APIDocumentation(
            name="SecureKeyWiping v16",
            stability=StabilityLevel.STABLE,
            version_added="v16",
            description="Secure memory zeroization specifically for cryptographic keys with multiple overwrite passes and cache flushing.",
            usage_example="""
from quantum_crypt.crypto_security_hardening_input_validation_injection_protection_v17_2026_june import SecureKeyWiping

# Use context manager for automatic key wiping
with SecureKeyWiping.allocate_key_buffer(32) as key_buffer:
    # Load sensitive key material
    key_buffer[:] = get_sensitive_key()
    perform_encryption(key_buffer)
# Buffer is now securely zeroized (3 passes + memory barrier)

# Manual wiping
SecureKeyWiping.wipe_key(key_material, passes=3)
""",
            parameters={
                "buffer": "bytearray - Mutable key buffer",
                "passes": "int - Number of overwrite passes (default: 3)",
                "flush_cache": "bool - Flush CPU caches after wipe"
            },
            returns="Context manager or None (in-place modification)"
        )
        
        # Constant-Time Crypto Primitives - STABLE (v16)
        self._apis["constant_time_crypto_v16"] = APIDocumentation(
            name="ConstantTimeCrypto v16",
            stability=StabilityLevel.STABLE,
            version_added="v16",
            description="Timing-attack resistant cryptographic primitives including constant-time MAC verification, signature comparison, and key equality checks.",
            usage_example="""
from quantum_crypt.crypto_security_hardening_input_validation_injection_protection_v17_2026_june import ConstantTimeCrypto

# Safe signature verification - no timing leak
if ConstantTimeCrypto.verify_signature(received_sig, expected_sig):
    accept_message()

# Safe HMAC comparison
if ConstantTimeCrypto.verify_hmac(user_hmac, computed_hmac):
    authenticate_request()
""",
            parameters={"a": "bytes", "b": "bytes - Cryptographic values to compare"},
            returns="bool - True if equal, execution time independent of similarity"
        )
    
    def get_module_guides(self) -> List[ModuleUsageGuide]:
        """Get complete usage guides for all major modules"""
        return [
            ModuleUsageGuide(
                module_name="Getting Started - Quantum-Safe Encryption",
                stability=StabilityLevel.STABLE,
                version="v16+",
                quick_start="""
# 3-Line Quantum-Safe Encryption
from quantum_crypt import QuantumCrypt

crypto = QuantumCrypt()
encrypted_data = crypto.encrypt(b"Secret data", recipient_pubkey)
""",
                full_example="""
# Production Quantum-Safe Communication Flow
from quantum_crypt import QuantumCrypt
from quantum_crypt.crypto_observability_slo_alerting_baggage_enhanced_v14_2026_june import CryptoBaggageManager

# Initialize with FIPS compliance
crypto = QuantumCrypt(
    enable_quantum_safe=True,
    fips_mode=True,
    enable_audit_logging=True
)

# Trace every crypto operation
with CryptoBaggageManager().new_crypto_operation("user_data_encryption") as ctx:
    ctx.set_key_context(key_id="prod-master-001", algorithm="Kyber-768")
    ctx.set_audit_context(user=current_user.id, purpose="pii_encryption")
    
    # 1. Key exchange (quantum-safe)
    shared_secret = crypto.key_exchange(recipient_pubkey)
    
    # 2. Encrypt with authenticated encryption
    ciphertext, nonce, tag = crypto.aes_gcm_encrypt(
        pii_data,
        shared_secret,
        ad=f"user:{current_user.id}".encode()
    )
    
    # 3. Sign for integrity (quantum-safe)
    signature = crypto.sign(ciphertext, signing_key)
    
    ctx.record_crypto_success(bytes_processed=len(pii_data))

return ciphertext, nonce, tag, signature
""",
                best_practices=[
                    "Always use context managers for automatic key wiping",
                    "Enable audit logging for all production crypto operations",
                    "Rotate keys before crypto period expires",
                    "Use FIPS mode for regulatory compliance",
                    "Monitor crypto SLOs for HSM availability and latency"
                ],
                common_pitfalls=[
                    "❌ Reusing nonces with AES-GCM - catastrophic failure",
                    "❌ Hardcoding keys in source code",
                    "❌ Using small key sizes for long-term storage",
                    "❌ Not validating input before crypto operations",
                    "❌ Skipping signature verification for 'trusted' data"
                ],
                related_modules=[
                    "QuantumKeyExchange",
                    "AESGCMEncryption",
                    "DigitalSignature",
                    "SecureKeyWiping",
                    "CryptoBaggageManager"
                ]
            )
        ]
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get count of APIs by stability level"""
        counts = {level.value: 0 for level in StabilityLevel}
        for api in self._apis.values():
            counts[api.stability.value] += 1
        return counts
    
    def get_api(self, name: str) -> Optional[APIDocumentation]:
        """Get documentation for specific API"""
        return self._apis.get(name)
    
    def list_all_apis(self) -> List[str]:
        """List all documented API names"""
        return sorted(self._apis.keys())
    
    def generate_readme_section(self) -> str:
        """Generate markdown README section for documentation"""
        summary = self.get_stability_summary()
        return f"""
## QuantumCrypt API Stability Reference

| Stability Level | Count | Description |
|-----------------|-------|-------------|
| 🟢 STABLE | {summary['STABLE']} | Production-ready, FIPS-compliant |
| 🟡 BETA | {summary['BETA']} | Testing phase, mostly stable |
| 🟠 EXPERIMENTAL | {summary['EXPERIMENTAL']} | New features, subject to change |
| 🔴 DEPRECATED | {summary['DEPRECATED']} | Will be removed |
| ⚪ INTERNAL | {summary['INTERNAL']} | Internal use only |

### Module Versions
- Core Cryptography: v1+ (STABLE, FIPS 140-3 compliant)
- Post-Quantum Algorithms: v4+ (STABLE, NIST-standardized)
- Security Hardening: v16+ (STABLE)
- Observability & Metrics: v14+ (EXPERIMENTAL/BETA)
- Audit & Compliance: v10+ (STABLE)
"""


# Global catalog instance
CRYPTO_DOCUMENTATION_CATALOG = CryptoDocumentationCatalog()


def get_documentation() -> CryptoDocumentationCatalog:
    """Get the global crypto documentation catalog instance"""
    return CRYPTO_DOCUMENTATION_CATALOG


def print_stability_report():
    """Print human-readable stability report"""
    catalog = get_documentation()
    summary = catalog.get_stability_summary()
    
    print("=" * 60)
    print("QuantumCrypt-AI API Stability Report v21")
    print("=" * 60)
    print(f"\nTotal APIs Documented: {len(catalog.list_all_apis())}")
    print("\nStability Breakdown:")
    
    for level, count in summary.items():
        if count > 0:
            icon = "🟢" if level == "STABLE" else "🟡" if level == "BETA" else "🟠" if level == "EXPERIMENTAL" else "🔴"
            print(f"  {icon} {level:15} {count:3d} APIs")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    print_stability_report()
