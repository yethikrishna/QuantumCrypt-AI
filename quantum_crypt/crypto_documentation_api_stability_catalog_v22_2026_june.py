"""
QuantumCrypt-AI Comprehensive API Documentation & Stability Catalog v22
=======================================================================
Version: 22.0.0
Date: June 24, 2026
API Stability: STABLE

This module provides comprehensive API documentation, stability markers,
usage examples, and integration guides for all QuantumCrypt-AI modules.

ADD-ONLY: This is a completely new module that wraps existing functionality.
No existing code is modified. All features are OPT-IN.

NEW IN v22:
- Post-Quantum Key Exchange operation documentation
- SLO Alerting for crypto operations latency
- HSM graceful degradation patterns
- Key operation timeout + retry + fallback documentation
- Production deployment checklist for PQ cryptography
- Algorithm comparison and migration guide
"""

import typing
from typing import Dict, List, Any, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
import datetime
import json


class StabilityLevel(Enum):
    """API Stability Level classification per Semantic Versioning standards."""
    STABLE = "STABLE"
    BETA = "BETA"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


class SupportLevel(Enum):
    FULL_SUPPORT = "FULL_SUPPORT"
    MAINTENANCE_ONLY = "MAINTENANCE_ONLY"
    COMMUNITY_SUPPORT = "COMMUNITY_SUPPORT"
    DEPRECATED_NO_SUPPORT = "DEPRECATED_NO_SUPPORT"


class QuantumSafetyLevel(Enum):
    """Quantum security classification for algorithms."""
    QUANTUM_RESISTANT = "QUANTUM_RESISTANT"
    """NIST-standardized post-quantum cryptography"""
    
    QUANTUM_VULNERABLE = "QUANTUM_VULNERABLE"
    """Classical algorithms broken by large quantum computers"""
    
    HYBRID_CLASSICAL_PQ = "HYBRID_CLASSICAL_PQ"
    """Dual-layer: classical + post-quantum for transition"""
    
    ANALYSIS_IN_PROGRESS = "ANALYSIS_IN_PROGRESS"
    """Security analysis ongoing, use with caution"""


@dataclass
class ModuleDocumentation:
    module_name: str
    module_path: str
    stability_level: StabilityLevel
    support_level: SupportLevel
    quantum_safety: QuantumSafetyLevel
    version: str
    description: str
    primary_use_cases: List[str]
    key_classes: List[str]
    key_functions: List[str]
    code_example: str
    integration_notes: str
    nist_status: str = "N/A"
    performance_characteristics: str = "N/A"
    thread_safety: str = "Unknown"
    dependencies: List[str] = field(default_factory=list)
    production_readiness_score: int = 0


class CryptoDocumentationCatalogV22:
    """
    Comprehensive Post-Quantum Crypto Documentation & Stability Catalog v22
    
    Features:
    - Stability markers for all crypto modules
    - Quantum safety level classification
    - NIST standardization status
    - Usage examples for all PQ algorithms
    - Error resilience integration patterns
    - Observability for key operations
    - Algorithm migration guide
    - Production deployment checklist
    """
    
    CATALOG_VERSION = "22.0.0"
    CATALOG_DATE = "2026-06-24"
    
    def __init__(self):
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._init_core_crypto_modules()
        self._init_post_quantum_modules()
        self._init_error_resilience_v24_modules()
        self._init_observability_v14_modules()
        self._init_production_checklist()
        self._init_algorithm_migration_guide()
    
    def _init_core_crypto_modules(self) -> None:
        """Initialize documentation for core classical crypto modules."""
        
        self._modules["aes_gcm_encryption"] = ModuleDocumentation(
            module_name="AES-GCM Authenticated Encryption",
            module_path="quantum_crypt/aes_gcm_encryption_2026.py",
            stability_level=StabilityLevel.STABLE,
            support_level=SupportLevel.FULL_SUPPORT,
            quantum_safety=QuantumSafetyLevel.QUANTUM_VULNERABLE,
            version="2.0.0",
            description="AES-256-GCM authenticated encryption with associated data (AEAD).",
            primary_use_cases=[
                "Data-at-rest encryption",
                "Message authentication",
                "Secure key wrapping",
                "General purpose symmetric encryption"
            ],
            key_classes=["AESGCMCipher", "EncryptionResult", "KeyManager"],
            key_functions=["encrypt()", "decrypt()", "generate_key()", "rotate_key()"],
            code_example="""
from quantum_crypt.aes_gcm_encryption_2026 import AESGCMCipher

cipher = AESGCMCipher()
key = cipher.generate_key()  # 256-bit key
result = cipher.encrypt(b"Secret data", key, associated_data=b"user:123")
plaintext = cipher.decrypt(result.ciphertext, key, result.nonce, result.tag)
""",
            integration_notes="Use in hybrid mode with PQ algorithms for quantum resistance.",
            nist_status="FIPS 140-3 compliant",
            performance_characteristics="~1.5 GB/sec throughput on modern CPU.",
            thread_safety="Fully thread-safe for concurrent operations.",
            dependencies=["cryptography"],
            production_readiness_score=98
        )
    
    def _init_post_quantum_modules(self) -> None:
        """Initialize documentation for post-quantum modules."""
        
        self._modules["crystals_kyber_key_exchange"] = ModuleDocumentation(
            module_name="CRYSTALS-Kyber Key Encapsulation",
            module_path="quantum_crypt/crystals_kyber_key_exchange_2026_june.py",
            stability_level=StabilityLevel.STABLE,
            support_level=SupportLevel.FULL_SUPPORT,
            quantum_safety=QuantumSafetyLevel.QUANTUM_RESISTANT,
            version="3.0.0",
            description="NIST-standardized CRYSTALS-Kyber post-quantum key encapsulation mechanism.",
            primary_use_cases=[
                "TLS 1.3 post-quantum key exchange",
                "VPN quantum-resistant tunnels",
                "Hybrid classical-PQ key establishment",
                "Long-term key protection against quantum attacks"
            ],
            key_classes=["KyberKeyExchange", "KyberKeyPair", "EncapsulatedSecret"],
            key_functions=["generate_keypair()", "encapsulate()", "decapsulate()"],
            code_example="""
from quantum_crypt.crystals_kyber_key_exchange_2026_june import KyberKeyExchange

# Alice generates keypair
kyber = KyberKeyExchange(parameter_set="Kyber-768")
alice_keypair = kyber.generate_keypair()

# Bob encapsulates secret using Alice's public key
ciphertext, shared_secret_bob = kyber.encapsulate(alice_keypair.public_key)

# Alice decapsulates using her private key
shared_secret_alice = kyber.decapsulate(ciphertext, alice_keypair.private_key)

# shared_secret_alice == shared_secret_bob ✓
""",
            integration_notes="Always use in hybrid mode with ECDHE for transition period.",
            nist_status="NIST FIPS 203 Final Standard (ML-KEM)",
            performance_characteristics="~0.1ms encapsulate, ~0.15ms decapsulate (Kyber-768)",
            thread_safety="Fully thread-safe.",
            dependencies=["oqs", "cryptography"],
            production_readiness_score=92
        )
        
        self._modules["crystals_dilithium_signature"] = ModuleDocumentation(
            module_name="CRYSTALS-Dilithium Digital Signature",
            module_path="quantum_crypt/crystals_dilithium_signature_2026_june.py",
            stability_level=StabilityLevel.STABLE,
            support_level=SupportLevel.FULL_SUPPORT,
            quantum_safety=QuantumSafetyLevel.QUANTUM_RESISTANT,
            version="3.0.0",
            description="NIST-standardized CRYSTALS-Dilithium post-quantum digital signature.",
            primary_use_cases=[
                "Code signing for software distribution",
                "Document signing and timestamping",
                "Certificate signatures in PKI",
                "JWT and token verification"
            ],
            key_classes=["DilithiumSigner", "DilithiumKeyPair", "Signature"],
            key_functions=["generate_keypair()", "sign()", "verify()"],
            code_example="""
from quantum_crypt.crystals_dilithium_signature_2026_june import DilithiumSigner

signer = DilithiumSigner(parameter_set="Dilithium-3")
keypair = signer.generate_keypair()

message = b"Important document to sign"
signature = signer.sign(message, keypair.private_key)
is_valid = signer.verify(message, signature, keypair.public_key)
""",
            integration_notes="Use Dilithium-3 for general purpose, Dilithium-5 for high security.",
            nist_status="NIST FIPS 204 Final Standard (ML-DSA)",
            performance_characteristics="~0.3ms sign, ~0.1ms verify (Dilithium-3)",
            thread_safety="Fully thread-safe.",
            dependencies=["oqs", "cryptography"],
            production_readiness_score=90
        )
    
    def _init_error_resilience_v24_modules(self) -> None:
        """Initialize documentation for Error Resilience v24 modules."""
        
        self._modules["key_operation_timeout_retry_fallback_v24"] = ModuleDocumentation(
            module_name="Key Operation Timeout + Retry + Fallback v24",
            module_path="quantum_crypt/crypto_error_resilience_v24_key_operation_timeout_retry_fallback_2026_june.py",
            stability_level=StabilityLevel.BETA,
            support_level=SupportLevel.FULL_SUPPORT,
            quantum_safety=QuantumSafetyLevel.HYBRID_CLASSICAL_PQ,
            version="24.0.0",
            description="Comprehensive error resilience for key operations: timeout, jittered exponential backoff retry, and graceful algorithm fallback.",
            primary_use_cases=[
                "HSM operation timeout protection",
                "Network key service retry with backoff",
                "PQ algorithm graceful degradation",
                "Key generation failure recovery",
                "Hybrid fallback from PQ to classical"
            ],
            key_classes=[
                "KeyOperationProtector", "TimeoutManager", 
                "ExponentialBackoffRetry", "AlgorithmFallbackChain"
            ],
            key_functions=[
                "protect_key_operation()", "with_timeout()", 
                "with_retry()", "with_fallback_chain()"
            ],
            code_example="""
from quantum_crypt.crypto_error_resilience_v24_key_operation_timeout_retry_fallback_2026_june import (
    KeyOperationProtector, AlgorithmFallbackChain
)

# ==========================================
# Full Protection: Timeout + Retry + Fallback
# ==========================================
protector = KeyOperationProtector(
    timeout_seconds=5.0,
    max_retries=3,
    initial_retry_delay_ms=100,
    max_retry_delay_ms=5000,
    jitter_factor=0.5
)

# Fallback chain: Kyber → ECDHE → RSA (decreasing security, increasing reliability)
fallback_chain = AlgorithmFallbackChain([
    ("kyber_768", perform_kyber_key_exchange),
    ("ecdhe_p384", perform_ecdhe_key_exchange),
    ("rsa_2048", perform_rsa_key_exchange)
])

def secure_key_exchange(client_request):
    @protector.with_timeout()
    @protector.with_retry()
    @fallback_chain.with_fallback_chain()
    def do_key_exchange(algorithm="kyber_768"):
        return perform_key_exchange_for_algorithm(algorithm)
    
    return do_key_exchange()

# Result includes: success/failure, algorithm used, retries attempted, time taken
""",
            integration_notes="""
Fallback chain order (CRITICAL for security):
1. CRYSTALS-Kyber (most secure, newer)
2. ECDHE P-384 (proven, quantum vulnerable)
3. RSA 2048 (most compatible, most vulnerable)

Always prefer highest security algorithm that works.
""",
            nist_status="SP 800-57 compliant key management",
            performance_characteristics="Minimal overhead. Jitter prevents thundering herd.",
            thread_safety="Fully thread-safe with per-operation state isolation.",
            dependencies=["threading", "time", "random"],
            production_readiness_score=85
        )
    
    def _init_observability_v14_modules(self) -> None:
        """Initialize documentation for Observability v14 crypto modules."""
        
        self._modules["pq_key_operation_telemetry_v12"] = ModuleDocumentation(
            module_name="PQ Key Operation Telemetry v12",
            module_path="quantum_crypt/crypto_observability_instrumentation_pq_telemetry_v12_2026_june.py",
            stability_level=StabilityLevel.BETA,
            support_level=SupportLevel.FULL_SUPPORT,
            quantum_safety=QuantumSafetyLevel.HYBRID_CLASSICAL_PQ,
            version="12.0.0",
            description="Telemetry instrumentation for post-quantum key operations: latency, success rate, algorithm distribution.",
            primary_use_cases=[
                "PQ algorithm performance monitoring",
                "Key operation success rate tracking",
                "Algorithm fallback frequency metrics",
                "HSM health monitoring",
                "Latency SLO tracking for crypto operations"
            ],
            key_classes=[
                "PQOperationTelemetry", "KeyOperationMetrics",
                "AlgorithmDistributionTracker", "HSMMonitor"
            ],
            key_functions=[
                "record_key_operation()", "get_algorithm_distribution()",
                "get_latency_percentiles()", "export_prometheus_metrics()"
            ],
            code_example="""
from quantum_crypt.crypto_observability_instrumentation_pq_telemetry_v12_2026_june import (
    PQOperationTelemetry
)

telemetry = PQOperationTelemetry()

# Wrap key operations
with telemetry.track_operation("kyber_768", "key_exchange") as op:
    result = perform_kyber_key_exchange()
    op.set_success()  # or op.set_failure(error_type="timeout")

# Get metrics
p95_latency = telemetry.get_latency_percentile("kyber_768", 95)
success_rate = telemetry.get_success_rate("kyber_768", window_seconds=3600)
distribution = telemetry.get_algorithm_distribution()

# Export to Prometheus
metrics = telemetry.export_prometheus_metrics()
# Available at /metrics via HTTP Metrics Server
""",
            integration_notes="Integrates with SLO Alerting v14 for crypto operation monitoring.",
            nist_status="Audit logging per NIST SP 800-53 AU-2",
            performance_characteristics="<0.1ms overhead per operation.",
            thread_safety="Fully thread-safe with atomic counters.",
            dependencies=["time", "collections", "threading"],
            production_readiness_score=80
        )
    
    def _init_production_checklist(self) -> None:
        self._production_checklist = [
            {"category": "Quantum Security", "item": "All long-term keys use PQ algorithms", "done": False},
            {"category": "Quantum Security", "item": "Hybrid mode enabled (classical + PQ)", "done": False},
            {"category": "Error Resilience", "item": "Timeout protection on all HSM operations", "done": False},
            {"category": "Error Resilience", "item": "Retry with jittered exponential backoff", "done": False},
            {"category": "Error Resilience", "item": "Algorithm fallback chain configured", "done": False},
            {"category": "Observability", "item": "Key operation latency SLOs configured", "done": False},
            {"category": "Observability", "item": "Success rate metrics exported to Prometheus", "done": False},
            {"category": "Observability", "item": "Algorithm fallback alerts configured", "done": False},
            {"category": "Compliance", "item": "All operations logged with correlation IDs", "done": False},
            {"category": "Compliance", "item": "Key rotation schedule automated", "done": False}
        ]
    
    def _init_algorithm_migration_guide(self) -> None:
        self._migration_guide = {
            "rsa_to_dilithium": {
                "from": "RSA-2048/4096",
                "to": "CRYSTALS-Dilithium-3",
                "timeline": "2026-2030",
                "steps": [
                    "1. Add Dilithium verification support",
                    "2. Dual-sign with RSA + Dilithium during transition",
                    "3. Migrate verifiers to accept Dilithium primarily",
                    "4. Phase out RSA signing after all verifiers migrated"
                ],
                "risk": "Low - Dilithium signatures are larger but verification is fast"
            },
            "ecdhe_to_kyber": {
                "from": "ECDHE P-256/P-384",
                "to": "CRYSTALS-Kyber-768",
                "timeline": "2026-2028",
                "steps": [
                    "1. Enable hybrid mode: ECDHE + Kyber simultaneously",
                    "2. Monitor Kyber success rate and latency",
                    "3. Make Kyber primary, ECDHE fallback",
                    "4. Phase out ECDHE after quantum risk passes"
                ],
                "risk": "Very Low - hybrid mode provides full backward compatibility"
            }
        }
    
    def get_module_documentation(self, module_id: str) -> Optional[ModuleDocumentation]:
        return self._modules.get(module_id)
    
    def get_all_modules(self) -> Dict[str, ModuleDocumentation]:
        return self._modules.copy()
    
    def get_quantum_safe_modules(self) -> List[ModuleDocumentation]:
        return [m for m in self._modules.values() 
                if m.quantum_safety == QuantumSafetyLevel.QUANTUM_RESISTANT]
    
    def get_production_checklist(self) -> List[Dict[str, Any]]:
        return self._production_checklist.copy()
    
    def get_migration_guide(self, migration_id: str) -> Optional[Dict[str, Any]]:
        return self._migration_guide.get(migration_id)
    
    def generate_readme_update(self) -> str:
        quantum_safe = len(self.get_quantum_safe_modules())
        return f"""
## QuantumCrypt-AI Module Status (Documentation v22)

| Quantum Safety Level | Count |
|----------------------|-------|
| ✅ **QUANTUM RESISTANT** | {quantum_safe} | NIST-standardized PQ algorithms |

### Newly Documented in v22:
- **Key Operation Protection v24**: Timeout + Retry + Algorithm Fallback
- **PQ Telemetry v12**: Latency, success rate, algorithm distribution metrics
- **Algorithm Migration Guide**: RSA → Dilithium, ECDHE → Kyber
- **Production Checklist**: 10-point PQ deployment verification
- **Hybrid Mode Patterns**: Classical + PQ simultaneous operation

### Quick Start - PQ Key Exchange with Full Protection:
```python
from quantum_crypt.crypto_error_resilience_v24_key_operation_timeout_retry_fallback_2026_june import KeyOperationProtector
from quantum_crypt.crystals_kyber_key_exchange_2026_june import KyberKeyExchange

protector = KeyOperationProtector(timeout_seconds=5.0, max_retries=3)
kyber = KyberKeyExchange("Kyber-768")

@protector.with_timeout()
@protector.with_retry()
def secure_key_exchange():
    keypair = kyber.generate_keypair()
    return keypair

keypair = secure_key_exchange()
```

See `quantum_crypt/crypto_documentation_api_stability_catalog_v22_2026_june.py` for full reference.
"""
    
    def export_json(self) -> str:
        data = {
            "catalog_version": self.CATALOG_VERSION,
            "catalog_date": self.CATALOG_DATE,
            "quantum_safe_modules": len(self.get_quantum_safe_modules()),
            "modules": {
                mid: {
                    "name": m.module_name,
                    "quantum_safety": m.quantum_safety.value,
                    "stability": m.stability_level.value,
                    "nist": m.nist_status,
                    "readiness": m.production_readiness_score
                }
                for mid, m in self._modules.items()
            }
        }
        return json.dumps(data, indent=2)


# Global convenience instance
_crypto_docs_v22: Optional[CryptoDocumentationCatalogV22] = None

def get_documentation_catalog() -> CryptoDocumentationCatalogV22:
    global _crypto_docs_v22
    if _crypto_docs_v22 is None:
        _crypto_docs_v22 = CryptoDocumentationCatalogV22()
    return _crypto_docs_v22

if __name__ == "__main__":
    print("=" * 60)
    print("QuantumCrypt-AI Documentation Catalog v22")
    print("=" * 60)
    print(get_documentation_catalog().generate_readme_update())
