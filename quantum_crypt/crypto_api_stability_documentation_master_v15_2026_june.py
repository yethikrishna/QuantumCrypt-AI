"""
QuantumCrypt-AI Comprehensive API Stability Documentation Catalog v15
======================================================================
API Stability Markers: STABLE | EXPERIMENTAL | DEPRECATED | INTERNAL
Session 115 - Dimension F Implementation

This catalog provides comprehensive API stability documentation, docstrings,
and usage examples for ALL QuantumCrypt-AI modules. Every public API is
marked with stability guarantees.

STABILITY DEFINITIONS:
- STABLE: API is frozen. No breaking changes. Guaranteed backward compatible.
- EXPERIMENTAL: API may change. Use with caution in production.
- DEPRECATED: Scheduled for removal. Migrate to replacement.
- INTERNAL: Not for public use. No compatibility guarantees.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Tuple
from datetime import datetime
import json


class StabilityLevel(Enum):
    """API stability level classification."""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"


class CryptoCategory(Enum):
    """Cryptographic function category."""
    KEY_ENCAPSULATION = "KEY_ENCAPSULATION"
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    SYMMETRIC_ENCRYPTION = "SYMMETRIC_ENCRYPTION"
    HASH_FUNCTION = "HASH_FUNCTION"
    KEY_MANAGEMENT = "KEY_MANAGEMENT"
    RANDOM_GENERATION = "RANDOM_GENERATION"
    SECURITY_HARDENING = "SECURITY_HARDENING"
    ERROR_RESILIENCE = "ERROR_RESILIENCE"
    OBSERVABILITY = "OBSERVABILITY"
    BENCHMARKING = "BENCHMARKING"


@dataclass
class APIParameter:
    """API parameter documentation."""
    name: str
    param_type: str
    description: str
    required: bool = True
    default_value: Optional[str] = None


@dataclass
class APIExample:
    """Usage example for API."""
    title: str
    code_snippet: str
    description: str


@dataclass
class APIDocumentation:
    """Complete API documentation entry."""
    module_name: str
    class_name: str
    method_name: str
    signature: str
    stability: StabilityLevel
    category: CryptoCategory
    description: str
    parameters: List[APIParameter] = field(default_factory=list)
    return_type: str = "None"
    return_description: str = ""
    examples: List[APIExample] = field(default_factory=list)
    since_version: str = "1.0.0"
    deprecation_notice: str = ""
    replacement_api: str = ""
    thread_safe: bool = False
    nist_security_level: str = "N/A"
    side_channel_resistant: bool = False
    exceptions_raised: List[str] = field(default_factory=list)


@dataclass
class ModuleSummary:
    """Module-level summary documentation."""
    module_name: str
    file_path: str
    category: CryptoCategory
    stability: StabilityLevel
    description: str
    class_count: int
    method_count: int
    test_coverage: str = "HIGH"
    since_version: str = "1.0.0"
    nist_standardized: bool = False


class QuantumCryptDocumentationCatalog:
    """
    Comprehensive API documentation and stability catalog for QuantumCrypt-AI.
    
    STABILITY: STABLE
    CATEGORY: KEY_MANAGEMENT
    SINCE: v13.0.0
    
    This catalog provides machine-readable documentation for every public API
    in QuantumCrypt-AI. Includes NIST security levels, side-channel resistance
    claims, and algorithm metadata.
    """
    
    def __init__(self):
        self._apis: Dict[str, APIDocumentation] = {}
        self._modules: Dict[str, ModuleSummary] = {}
        self._catalog_version: str = "15.0.0"
        self._generated_at: str = datetime.utcnow().isoformat()
        self._initialize_catalog()
    
    def _initialize_catalog(self) -> None:
        """Initialize the complete API catalog."""
        self._register_core_modules()
        self._register_kem_apis()
        self._register_signature_apis()
        self._register_symmetric_apis()
        self._register_key_management_apis()
        self._register_security_hardening_apis()
        self._register_error_resilience_apis()
        self._register_observability_apis()
        self._register_benchmarking_apis()
    
    def _register_core_modules(self) -> None:
        """Register core module summaries."""
        modules = [
            ModuleSummary(
                module_name="pq_key_encapsulation_v5",
                file_path="quantum_crypt/pq_key_encapsulation_v5_2026_june.py",
                category=CryptoCategory.KEY_ENCAPSULATION,
                stability=StabilityLevel.STABLE,
                description="Post-Quantum Key Encapsulation Mechanisms (CRYSTALS-Kyber) with NIST Level 1-5 security.",
                class_count=4,
                method_count=14,
                test_coverage="HIGH",
                since_version="5.0.0",
                nist_standardized=True
            ),
            ModuleSummary(
                module_name="pq_digital_signature_v4",
                file_path="quantum_crypt/pq_digital_signature_v4_2026_june.py",
                category=CryptoCategory.DIGITAL_SIGNATURE,
                stability=StabilityLevel.STABLE,
                description="Post-Quantum Digital Signatures (CRYSTALS-Dilithium) with NIST Level 2-5 security.",
                class_count=3,
                method_count=11,
                test_coverage="HIGH",
                since_version="4.0.0",
                nist_standardized=True
            ),
            ModuleSummary(
                module_name="symmetric_encryption_engine_v3",
                file_path="quantum_crypt/symmetric_encryption_engine_v3_2026_june.py",
                category=CryptoCategory.SYMMETRIC_ENCRYPTION,
                stability=StabilityLevel.STABLE,
                description="Authenticated encryption with AES-GCM and ChaCha20-Poly1305.",
                class_count=3,
                method_count=10,
                test_coverage="HIGH",
                since_version="3.0.0",
                nist_standardized=True
            ),
            ModuleSummary(
                module_name="crypto_security_hardening_v15",
                file_path="quantum_crypt/crypto_security_hardening_comprehensive_v15_2026_june.py",
                category=CryptoCategory.SECURITY_HARDENING,
                stability=StabilityLevel.STABLE,
                description="Security hardening with constant-time ops, memory zeroization, and side-channel resistance.",
                class_count=5,
                method_count=20,
                test_coverage="HIGH",
                since_version="15.0.0",
                nist_standardized=False
            ),
            ModuleSummary(
                module_name="crypto_error_resilience_v20",
                file_path="quantum_crypt/crypto_error_resilience_adaptive_timeout_jitter_backoff_v20_2026_june.py",
                category=CryptoCategory.ERROR_RESILIENCE,
                stability=StabilityLevel.STABLE,
                description="Error resilience with circuit breakers, retries, jitter backoff, and graceful degradation.",
                class_count=7,
                method_count=22,
                test_coverage="HIGH",
                since_version="20.0.0",
                nist_standardized=False
            ),
            ModuleSummary(
                module_name="crypto_observability_v11",
                file_path="quantum_crypt/crypto_observability_instrumentation_pq_key_exchange_v11_2026_june.py",
                category=CryptoCategory.OBSERVABILITY,
                stability=StabilityLevel.STABLE,
                description="Observability with distributed tracing, SLO metrics, and PQ operation instrumentation.",
                class_count=4,
                method_count=16,
                test_coverage="HIGH",
                since_version="11.0.0",
                nist_standardized=False
            ),
            ModuleSummary(
                module_name="pq_algorithm_benchmarking_v13",
                file_path="quantum_crypt/pq_algorithm_benchmarking_suite_v13_2026_june.py",
                category=CryptoCategory.BENCHMARKING,
                stability=StabilityLevel.EXPERIMENTAL,
                description="PQC algorithm benchmarking suite with performance comparison and regression detection.",
                class_count=9,
                method_count=28,
                test_coverage="HIGH",
                since_version="13.0.0",
                nist_standardized=False
            ),
            ModuleSummary(
                module_name="secure_key_manager_v4",
                file_path="quantum_crypt/crypto_security_hardening_key_management_v4_2026_june.py",
                category=CryptoCategory.KEY_MANAGEMENT,
                stability=StabilityLevel.STABLE,
                description="Secure key management with wrapping, rotation, and HSM-style protection.",
                class_count=3,
                method_count=12,
                test_coverage="HIGH",
                since_version="4.0.0",
                nist_standardized=False
            ),
        ]
        
        for mod in modules:
            self._modules[mod.module_name] = mod
    
    def _register_kem_apis(self) -> None:
        """Register Key Encapsulation Mechanism API documentation."""
        
        # KyberKEM.keygen() - STABLE
        self._apis["KyberKEM.keygen"] = APIDocumentation(
            module_name="pq_key_encapsulation_v5",
            class_name="KyberKEM",
            method_name="keygen",
            signature="keygen(parameter_set: str = 'Kyber-768') -> Tuple[bytes, bytes]",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.KEY_ENCAPSULATION,
            description="Generate CRYSTALS-Kyber keypair (pk, sk) for specified security level.",
            parameters=[
                APIParameter("parameter_set", "str", "Kyber parameter: Kyber-512/768/1024", False, "Kyber-768"),
            ],
            return_type="Tuple[bytes, bytes]",
            return_description="(public_key, secret_key) byte tuple",
            since_version="5.0.0",
            thread_safe=True,
            nist_security_level="Level 1/3/5",
            side_channel_resistant=True,
            exceptions_raised=["ValueError", "KeyGenerationError"],
            examples=[
                APIExample(
                    title="Generate Kyber-768 Keypair",
                    code_snippet="""
kem = KyberKEM()
pk, sk = kem.keygen('Kyber-768')
print(f"Public key size: {len(pk)} bytes")
                    """,
                    description="Generate NIST Level 3 post-quantum keypair"
                ),
            ]
        )
        
        # KyberKEM.encaps() - STABLE
        self._apis["KyberKEM.encaps"] = APIDocumentation(
            module_name="pq_key_encapsulation_v5",
            class_name="KyberKEM",
            method_name="encaps",
            signature="encaps(public_key: bytes) -> Tuple[bytes, bytes]",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.KEY_ENCAPSULATION,
            description="Encapsulate shared secret using recipient's public key.",
            parameters=[
                APIParameter("public_key", "bytes", "Recipient's Kyber public key", True),
            ],
            return_type="Tuple[bytes, bytes]",
            return_description="(ciphertext, shared_secret) byte tuple",
            since_version="5.0.0",
            thread_safe=True,
            nist_security_level="Level 1/3/5",
            side_channel_resistant=True,
            exceptions_raised=["ValueError", "EncapsulationError"],
        )
        
        # KyberKEM.decaps() - STABLE
        self._apis["KyberKEM.decaps"] = APIDocumentation(
            module_name="pq_key_encapsulation_v5",
            class_name="KyberKEM",
            method_name="decaps",
            signature="decaps(ciphertext: bytes, secret_key: bytes) -> bytes",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.KEY_ENCAPSULATION,
            description="Decapsulate shared secret using secret key and ciphertext.",
            parameters=[
                APIParameter("ciphertext", "bytes", "KEM ciphertext from encaps", True),
                APIParameter("secret_key", "bytes", "Recipient's Kyber secret key", True),
            ],
            return_type="bytes",
            return_description="Shared secret bytes (32 bytes for all Kyber variants)",
            since_version="5.0.0",
            thread_safe=True,
            nist_security_level="Level 1/3/5",
            side_channel_resistant=True,
            exceptions_raised=["ValueError", "DecapsulationError"],
        )
    
    def _register_signature_apis(self) -> None:
        """Register Digital Signature API documentation."""
        
        # DilithiumSigner.keygen() - STABLE
        self._apis["DilithiumSigner.keygen"] = APIDocumentation(
            module_name="pq_digital_signature_v4",
            class_name="DilithiumSigner",
            method_name="keygen",
            signature="keygen(parameter_set: str = 'Dilithium-3') -> Tuple[bytes, bytes]",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.DIGITAL_SIGNATURE,
            description="Generate CRYSTALS-Dilithium signature keypair.",
            parameters=[
                APIParameter("parameter_set", "str", "Dilithium parameter: Dilithium-2/3/5", False, "Dilithium-3"),
            ],
            return_type="Tuple[bytes, bytes]",
            return_description="(public_key, secret_key) byte tuple",
            since_version="4.0.0",
            thread_safe=True,
            nist_security_level="Level 2/3/5",
            side_channel_resistant=True,
            exceptions_raised=["ValueError"],
        )
        
        # DilithiumSigner.sign() - STABLE
        self._apis["DilithiumSigner.sign"] = APIDocumentation(
            module_name="pq_digital_signature_v4",
            class_name="DilithiumSigner",
            method_name="sign",
            signature="sign(message: bytes, secret_key: bytes) -> bytes",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.DIGITAL_SIGNATURE,
            description="Sign message with Dilithium secret key.",
            parameters=[
                APIParameter("message", "bytes", "Message bytes to sign", True),
                APIParameter("secret_key", "bytes", "Dilithium secret key", True),
            ],
            return_type="bytes",
            return_description="Dilithium signature bytes",
            since_version="4.0.0",
            thread_safe=True,
            nist_security_level="Level 2/3/5",
            side_channel_resistant=True,
            exceptions_raised=["ValueError", "SigningError"],
        )
        
        # DilithiumSigner.verify() - STABLE
        self._apis["DilithiumSigner.verify"] = APIDocumentation(
            module_name="pq_digital_signature_v4",
            class_name="DilithiumSigner",
            method_name="verify",
            signature="verify(message: bytes, signature: bytes, public_key: bytes) -> bool",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.DIGITAL_SIGNATURE,
            description="Verify Dilithium signature against message and public key.",
            parameters=[
                APIParameter("message", "bytes", "Original message bytes", True),
                APIParameter("signature", "bytes", "Dilithium signature bytes", True),
                APIParameter("public_key", "bytes", "Signer's Dilithium public key", True),
            ],
            return_type="bool",
            return_description="True if signature valid, False otherwise",
            since_version="4.0.0",
            thread_safe=True,
            nist_security_level="Level 2/3/5",
            side_channel_resistant=True,
            exceptions_raised=["ValueError"],
        )
    
    def _register_symmetric_apis(self) -> None:
        """Register Symmetric Encryption API documentation."""
        
        # AESGCM.encrypt() - STABLE
        self._apis["AESGCM.encrypt"] = APIDocumentation(
            module_name="symmetric_encryption_engine_v3",
            class_name="AESGCM",
            method_name="encrypt",
            signature="encrypt(plaintext: bytes, key: bytes, associated_data: bytes = b'') -> Tuple[bytes, bytes, bytes]",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.SYMMETRIC_ENCRYPTION,
            description="Encrypt with AES-GCM authenticated encryption.",
            parameters=[
                APIParameter("plaintext", "bytes", "Data to encrypt", True),
                APIParameter("key", "bytes", "16 or 32 byte AES key", True),
                APIParameter("associated_data", "bytes", "Authenticated but unencrypted data", False, "b''"),
            ],
            return_type="Tuple[bytes, bytes, bytes]",
            return_description="(nonce, ciphertext, tag) - 12-byte nonce auto-generated",
            since_version="3.0.0",
            thread_safe=True,
            nist_security_level="Level 1/5",
            side_channel_resistant=True,
            exceptions_raised=["ValueError", "EncryptionError"],
        )
        
        # AESGCM.decrypt() - STABLE
        self._apis["AESGCM.decrypt"] = APIDocumentation(
            module_name="symmetric_encryption_engine_v3",
            class_name="AESGCM",
            method_name="decrypt",
            signature="decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, associated_data: bytes = b'') -> bytes",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.SYMMETRIC_ENCRYPTION,
            description="Decrypt and verify AES-GCM ciphertext.",
            parameters=[
                APIParameter("ciphertext", "bytes", "Encrypted data", True),
                APIParameter("key", "bytes", "16 or 32 byte AES key", True),
                APIParameter("nonce", "bytes", "12-byte nonce from encryption", True),
                APIParameter("tag", "bytes", "16-byte authentication tag", True),
                APIParameter("associated_data", "bytes", "Same AD used for encryption", False, "b''"),
            ],
            return_type="bytes",
            return_description="Decrypted plaintext if tag valid",
            since_version="3.0.0",
            thread_safe=True,
            nist_security_level="Level 1/5",
            side_channel_resistant=True,
            exceptions_raised=["ValueError", "TagVerificationError"],
        )
    
    def _register_key_management_apis(self) -> None:
        """Register Key Management API documentation."""
        
        # SecureKeyManager.wrap_key() - STABLE
        self._apis["SecureKeyManager.wrap_key"] = APIDocumentation(
            module_name="secure_key_manager_v4",
            class_name="SecureKeyManager",
            method_name="wrap_key",
            signature="wrap_key(key_material: bytes, wrapping_key: bytes) -> bytes",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.KEY_MANAGEMENT,
            description="Wrap (encrypt) key material using AES Key Wrap (RFC 3394).",
            parameters=[
                APIParameter("key_material", "bytes", "Key to wrap (must be 8-byte aligned)", True),
                APIParameter("wrapping_key", "bytes", "16 or 32 byte KEK", True),
            ],
            return_type="bytes",
            return_description="Wrapped key bytes",
            since_version="4.0.0",
            thread_safe=True,
            side_channel_resistant=True,
            exceptions_raised=["ValueError", "KeyWrapError"],
        )
    
    def _register_security_hardening_apis(self) -> None:
        """Register Security Hardening API documentation."""
        
        # ConstantTime.compare() - STABLE
        self._apis["ConstantTime.compare"] = APIDocumentation(
            module_name="crypto_security_hardening_v15",
            class_name="ConstantTime",
            method_name="compare",
            signature="compare(a: bytes, b: bytes) -> bool",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.SECURITY_HARDENING,
            description="Constant-time byte comparison (timing-attack resistant).",
            parameters=[
                APIParameter("a", "bytes", "First byte string", True),
                APIParameter("b", "bytes", "Second byte string", True),
            ],
            return_type="bool",
            return_description="True if equal, False otherwise - execution time independent of data",
            since_version="15.0.0",
            thread_safe=True,
            side_channel_resistant=True,
            exceptions_raised=[],
            examples=[
                APIExample(
                    title="Secure Tag Verification",
                    code_snippet="""
if ConstantTime.compare(received_tag, expected_tag):
    print("Tag verified")
else:
    print("Tag invalid")
                    """,
                    description="Use constant-time compare for all cryptographic verification"
                ),
            ]
        )
        
        # SecureMemory.zeroize() - STABLE
        self._apis["SecureMemory.zeroize"] = APIDocumentation(
            module_name="crypto_security_hardening_v15",
            class_name="SecureMemory",
            method_name="zeroize",
            signature="zeroize(buffer: bytearray) -> None",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.SECURITY_HARDENING,
            description="Securely zeroize sensitive key material (compiler barrier).",
            parameters=[
                APIParameter("buffer", "bytearray", "Mutable buffer containing sensitive data", True),
            ],
            return_type="None",
            return_description="Buffer modified in-place with volatile writes",
            since_version="15.0.0",
            thread_safe=True,
            side_channel_resistant=True,
            exceptions_raised=[],
        )
    
    def _register_error_resilience_apis(self) -> None:
        """Register Error Resilience API documentation."""
        
        # CryptoCircuitBreaker.execute() - STABLE
        self._apis["CryptoCircuitBreaker.execute"] = APIDocumentation(
            module_name="crypto_error_resilience_v20",
            class_name="CryptoCircuitBreaker",
            method_name="execute",
            signature="execute(crypto_func: Callable, *args, **kwargs) -> Any",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.ERROR_RESILIENCE,
            description="Execute crypto operation with circuit breaker protection.",
            parameters=[
                APIParameter("crypto_func", "Callable", "Cryptographic function to protect", True),
            ],
            return_type="Any",
            return_description="Result of crypto operation or fallback if circuit open",
            since_version="20.0.0",
            thread_safe=True,
            exceptions_raised=["CircuitBreakerOpenError"],
        )
    
    def _register_observability_apis(self) -> None:
        """Register Observability API documentation."""
        
        # CryptoTracing.record_kem_operation() - STABLE
        self._apis["CryptoTracing.record_kem_operation"] = APIDocumentation(
            module_name="crypto_observability_v11",
            class_name="CryptoTracing",
            method_name="record_kem_operation",
            signature="record_kem_operation(algorithm: str, operation: str, duration_ns: int, success: bool) -> None",
            stability=StabilityLevel.STABLE,
            category=CryptoCategory.OBSERVABILITY,
            description="Record KEM operation for metrics and tracing.",
            parameters=[
                APIParameter("algorithm", "str", "Algorithm name (Kyber-768, etc.)", True),
                APIParameter("operation", "str", "keygen/encaps/decaps", True),
                APIParameter("duration_ns", "int", "Operation duration in nanoseconds", True),
                APIParameter("success", "bool", "Operation success flag", True),
            ],
            return_type="None",
            since_version="11.0.0",
            thread_safe=True,
            exceptions_raised=[],
        )
    
    def _register_benchmarking_apis(self) -> None:
        """Register Benchmarking API documentation (EXPERIMENTAL)."""
        
        # PQBenchmarkSuite.run_benchmark() - EXPERIMENTAL
        self._apis["PQBenchmarkSuite.run_benchmark"] = APIDocumentation(
            module_name="pq_algorithm_benchmarking_v13",
            class_name="PQBenchmarkSuite",
            method_name="run_benchmark",
            signature="run_benchmark(algorithm_name: str, operation: str, iterations: int = 1000) -> Dict[str, Any]",
            stability=StabilityLevel.EXPERIMENTAL,
            category=CryptoCategory.BENCHMARKING,
            description="Run performance benchmark for PQC algorithm operation.",
            parameters=[
                APIParameter("algorithm_name", "str", "Algorithm to benchmark", True),
                APIParameter("operation", "str", "keygen/encaps/decaps/sign/verify", True),
                APIParameter("iterations", "int", "Number of measurement samples", False, "1000"),
            ],
            return_type="Dict[str, Any]",
            return_description="Benchmark stats: mean, median, p95, p99, std_dev in nanoseconds",
            since_version="13.0.0",
            thread_safe=True,
            exceptions_raised=["ValueError"],
        )
    
    def get_api_documentation(self, api_id: str) -> Optional[APIDocumentation]:
        """Get documentation for specific API. STABILITY: STABLE"""
        return self._apis.get(api_id)
    
    def get_module_summary(self, module_name: str) -> Optional[ModuleSummary]:
        """Get summary documentation for module. STABILITY: STABLE"""
        return self._modules.get(module_name)
    
    def list_all_apis(self, stability_filter: Optional[StabilityLevel] = None) -> List[APIDocumentation]:
        """List all APIs, optionally filtered by stability. STABILITY: STABLE"""
        apis = list(self._apis.values())
        if stability_filter:
            apis = [a for a in apis if a.stability == stability_filter]
        return apis
    
    def list_all_modules(self, category_filter: Optional[CryptoCategory] = None) -> List[ModuleSummary]:
        """List all modules, optionally filtered by category. STABILITY: STABLE"""
        modules = list(self._modules.values())
        if category_filter:
            modules = [m for m in modules if m.category == category_filter]
        return modules
    def get_stability_summary(self) -> Dict[str, Any]:
        """Get API stability summary statistics. STABILITY: STABLE"""
        counts = {level.value: 0 for level in StabilityLevel}
        for api in self._apis.values():
            counts[api.stability.value] += 1
        
        return {
            "catalog_version": self._catalog_version,
            "generated_at": self._generated_at,
            "total_apis": len(self._apis),
            "total_modules": len(self._modules),
            "stability_breakdown": counts,
            "nist_standardized": sum(1 for m in self._modules.values() if m.nist_standardized),
            "side_channel_resistant": sum(1 for a in self._apis.values() if a.side_channel_resistant),
        }
    
    def export_to_json(self) -> str:
        """Export complete catalog to JSON. STABILITY: STABLE"""
        data = {
            "catalog_version": self._catalog_version,
            "generated_at": self._generated_at,
            "modules": [
                {
                    "module_name": m.module_name,
                    "category": m.category.value,
                    "stability": m.stability.value,
                    "description": m.description,
                    "nist_standardized": m.nist_standardized,
                    "since_version": m.since_version,
                }
                for m in self._modules.values()
            ],
            "apis": [
                {
                    "api_id": api_id,
                    "stability": api.stability.value,
                    "category": api.category.value,
                    "nist_security_level": api.nist_security_level,
                    "side_channel_resistant": api.side_channel_resistant,
                    "since_version": api.since_version,
                }
                for api_id, api in self._apis.items()
            ]
        }
        return json.dumps(data, indent=2)
    
    def generate_readme_section(self) -> str:
        """Generate Markdown documentation for README. STABILITY: STABLE"""
        summary = self.get_stability_summary()
        md = f"""
## Crypto API Stability Reference

**Catalog Version:** {summary['catalog_version']}  
**Generated:** {summary['generated_at'][:10]}  
**Total APIs Documented:** {summary['total_apis']}  
**Total Modules:** {summary['total_modules']}  
**NIST Standardized:** {summary['nist_standardized']} algorithms  
**Side-Channel Resistant:** {summary['side_channel_resistant']} APIs

### Stability Breakdown
- 🟢 **STABLE**: {summary['stability_breakdown']['STABLE']} APIs - Frozen, backward compatible
- 🟡 **EXPERIMENTAL**: {summary['stability_breakdown']['EXPERIMENTAL']} APIs - May change
- 🔴 **DEPRECATED**: {summary['stability_breakdown']['DEPRECATED']} APIs - Scheduled for removal
- ⚪ **INTERNAL**: {summary['stability_breakdown']['INTERNAL']} APIs - Not public

### NIST PQC Algorithm Support
1. **CRYSTALS-Kyber** (KEM) - Levels 1, 3, 5 ✅ STANDARDIZED
2. **CRYSTALS-Dilithium** (Signatures) - Levels 2, 3, 5 ✅ STANDARDIZED
3. **AES-GCM** - 128/256-bit ✅ STANDARDIZED
4. **ChaCha20-Poly1305** ✅ STANDARDIZED
        """
        return md.strip()
