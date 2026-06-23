"""
QuantumCrypt-AI Comprehensive API Documentation & Stability Catalog v16
=======================================================================
SESSION 115 - DIMENSION F: DOCUMENTATION & API STABILITY

This catalog provides comprehensive documentation, stability markers,
and usage examples for ALL QuantumCrypt-AI production modules.

STABILITY MARKERS:
    @STABLE - Production-ready, backward compatible, no breaking changes planned
    @EXPERIMENTAL - New feature, API may change, use with caution
    @DEPRECATED - Scheduled for removal, migrate to replacement module
    @LEGACY - Maintained for compatibility, no active development

API STABILITY GUARANTEE:
    - STABLE modules: Semantic versioning, deprecation cycle >= 6 months
    - EXPERIMENTAL modules: Breaking changes possible, changelog provided
    - DEPRECATED modules: Will be removed in next major version
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import json


class StabilityLevel(Enum):
    """API Stability Classification Levels"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


class ModuleCategory(Enum):
    """Module Functional Categories"""
    PQC_KEM = "POST_QUANTUM_KEY_ENCAPSULATION"
    PQC_SIGNATURE = "POST_QUANTUM_SIGNATURES"
    CLASSICAL_CRYPTO = "CLASSICAL_CRYPTOGRAPHY"
    HYBRID_CRYPTO = "HYBRID_PQC_CLASSICAL"
    KEY_MANAGEMENT = "KEY_MANAGEMENT"
    SECURITY_HARDENING = "SECURITY_HARDENING"
    ERROR_RESILIENCE = "ERROR_RESILIENCE"
    OBSERVABILITY = "OBSERVABILITY"
    BENCHMARKING = "BENCHMARKING_PERFORMANCE"
    DOCUMENTATION = "DOCUMENTATION"
    ENTROPY = "ENTROPY_COLLECTION"


@dataclass
class APIParameter:
    """API Parameter Documentation"""
    name: str
    param_type: str
    description: str
    required: bool = True
    default_value: Optional[Any] = None


@dataclass
class APIExample:
    """Usage Example Documentation"""
    title: str
    code: str
    description: str
    expected_output: str = ""


@dataclass
class ModuleDocumentation:
    """Complete Module Documentation Entry"""
    module_name: str
    filename: str
    category: ModuleCategory
    stability: StabilityLevel
    version: str
    description: str
    main_class: str
    public_methods: List[str] = field(default_factory=list)
    parameters: List[APIParameter] = field(default_factory=list)
    examples: List[APIExample] = field(default_factory=list)
    deprecation_notice: str = ""
    replacement_module: str = ""
    introduced_version: str = "1.0.0"
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    nist_standard: bool = False
    security_level: int = 1

    def to_dict(self) -> Dict[str, Any]:
        """Serialize documentation to dictionary"""
        return {
            "module_name": self.module_name,
            "filename": self.filename,
            "category": self.category.value,
            "stability": self.stability.value,
            "version": self.version,
            "description": self.description,
            "main_class": self.main_class,
            "public_methods": self.public_methods,
            "parameters": [p.__dict__ for p in self.parameters],
            "examples": [e.__dict__ for e in self.examples],
            "deprecation_notice": self.deprecation_notice,
            "replacement_module": self.replacement_module,
            "introduced_version": self.introduced_version,
            "last_updated": self.last_updated,
            "nist_standard": self.nist_standard,
            "security_level": self.security_level
        }


class QuantumCryptDocumentationCatalog:
    """
    @STABLE
    Comprehensive API Documentation Catalog v16
    
    Central registry for all QuantumCrypt-AI module documentation
    with stability markers, NIST compliance status, and usage examples.
    
    Usage:
        catalog = QuantumCryptDocumentationCatalog()
        docs = catalog.get_all_documentation()
        report = catalog.generate_stability_report()
        nist_algs = catalog.get_nist_standard_algorithms()
    """
    
    def __init__(self):
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._build_catalog()
    
    def _build_catalog(self):
        """Build the complete documentation catalog"""
        
        # =====================================================================
        # PQC BENCHMARKING MODULE (Session 114 - NEW v13 FEATURE)
        # =====================================================================
        
        self._modules["pq_algorithm_benchmarking_suite"] = ModuleDocumentation(
            module_name="PQ Algorithm Benchmarking Suite",
            filename="pq_algorithm_benchmarking_suite_v13_2026_june.py",
            category=ModuleCategory.BENCHMARKING,
            stability=StabilityLevel.EXPERIMENTAL,
            version="v13",
            description="Comprehensive post-quantum algorithm benchmarking suite with micro-benchmarking, statistical analysis, performance ranking, and regression detection for all NIST PQC standards.",
            main_class="PQBenchmarkSuite",
            public_methods=[
                "register_algorithm() - Register algorithm implementation for benchmarking",
                "benchmark_key_generation() - Benchmark keypair generation performance",
                "benchmark_encapsulation() - Benchmark KEM encapsulation",
                "benchmark_decapsulation() - Benchmark KEM decapsulation",
                "benchmark_signing() - Benchmark signature generation",
                "benchmark_verification() - Benchmark signature verification",
                "benchmark_all() - Run complete benchmark suite",
                "rank_by_performance() - Rank algorithms by speed",
                "detect_regression() - Performance regression vs baseline",
                "generate_json_report() - Full benchmark report export",
                "get_summary_statistics() - Performance summary by category"
            ],
            parameters=[
                APIParameter("warmup_iterations", "int", "JIT warmup iterations", required=False, default_value="100"),
                APIParameter("measurement_samples", "int", "Benchmark sample count", required=False, default_value="1000"),
                APIParameter("regression_threshold_pct", "float", "Regression alert threshold", required=False, default_value="10.0"),
                APIParameter("enable_thread_safety", "bool", "RLock concurrent access protection", required=False, default_value="True")
            ],
            examples=[
                APIExample(
                    title="Benchmark All NIST PQC Algorithms",
                    code="""
from quantum_crypt.pq_algorithm_benchmarking_suite_v13_2026_june import PQBenchmarkSuite

suite = PQBenchmarkSuite()
results = suite.benchmark_all()
rankings = suite.rank_by_performance(category_filter="KEM")
print("Fastest KEM algorithms:")
for rank, alg in enumerate(rankings, 1):
    print(f"{rank}. {alg['algorithm_name']}: {alg['mean_time_us']:.2f}μs")
                    """,
                    description="Run complete benchmark and rank KEM algorithms by performance"
                ),
                APIExample(
                    title="Performance Regression Detection",
                    code="""
suite.capture_baseline()
# ... run benchmarks over time ...
regressions = suite.detect_regression()
for alg, change in regressions.items():
    print(f"{alg}: {change['percent_change']:+.1f}% regression")
                    """,
                    description="Detect performance regressions against baseline"
                )
            ],
            introduced_version="v13"
        )
        
        # =====================================================================
        # NIST PQC KEM ALGORITHMS
        # =====================================================================
        
        self._modules["crystals_kyber"] = ModuleDocumentation(
            module_name="CRYSTALS-Kyber KEM",
            filename="pqc_crystals_kyber_implementation_2026_june.py",
            category=ModuleCategory.PQC_KEM,
            stability=StabilityLevel.STABLE,
            version="v1",
            description="NIST Standard CRYSTALS-Kyber Post-Quantum Key Encapsulation Mechanism. MLWE-based lattice cryptography with IND-CCA2 security.",
            main_class="KyberKEM",
            public_methods=[
                "keygen() - Generate (pk, sk) keypair",
                "encaps(pk) - Generate (ct, ss) ciphertext and shared secret",
                "decaps(ct, sk) - Recover shared secret from ciphertext",
                "get_security_level() - NIST security level (1/3/5)",
                "get_key_sizes() - Public/secret key sizes in bytes"
            ],
            introduced_version="v1",
            nist_standard=True,
            security_level=3
        )
        
        # =====================================================================
        # NIST PQC SIGNATURE ALGORITHMS
        # =====================================================================
        
        self._modules["crystals_dilithium"] = ModuleDocumentation(
            module_name="CRYSTALS-Dilithium Signature",
            filename="pqc_crystals_dilithium_implementation_2026_june.py",
            category=ModuleCategory.PQC_SIGNATURE,
            stability=StabilityLevel.STABLE,
            version="v1",
            description="NIST Standard CRYSTALS-Dilithium Post-Quantum Digital Signature. Module-Lattice-based signature scheme with strong unforgeability.",
            main_class="DilithiumSignature",
            public_methods=[
                "keygen() - Generate (pk, sk) keypair",
                "sign(message, sk) - Generate digital signature",
                "verify(message, sig, pk) - Verify signature validity",
                "get_security_level() - NIST security level (2/3/5)",
                "get_signature_size() - Signature size in bytes"
            ],
            introduced_version="v1",
            nist_standard=True,
            security_level=3
        )
        
        # =====================================================================
        # HYBRID PQC-CLASSICAL CRYPTOGRAPHY
        # =====================================================================
        
        self._modules["hybrid_pqc_classical"] = ModuleDocumentation(
            module_name="Hybrid PQC-Classical Key Exchange",
            filename="hybrid_pqc_classical_key_exchange_2026_june.py",
            category=ModuleCategory.HYBRID_CRYPTO,
            stability=StabilityLevel.STABLE,
            version="v1",
            description="Dual-security hybrid key exchange combining NIST PQC (Kyber) with classical ECC for transition period security.",
            main_class="HybridKeyExchange",
            public_methods=[
                "generate_hybrid_keypair() - (PQC + ECC) dual keypair",
                "hybrid_encapsulate() - Dual encapsulation for both schemes",
                "hybrid_decapsulate() - Dual decapsulation with KDF combining",
                "get_combined_shared_secret() - HKDF-combined shared secret",
                "verify_both_security_proofs() - Validate both schemes completed"
            ],
            examples=[
                APIExample(
                    title="Hybrid Key Exchange",
                    code="""
from quantum_crypt.hybrid_pqc_classical_key_exchange_2026_june import HybridKeyExchange

hybrid = HybridKeyExchange()
server_pk, server_sk = hybrid.generate_hybrid_keypair()
ct, ss_client = hybrid.hybrid_encapsulate(server_pk)
ss_server = hybrid.hybrid_decapsulate(ct, server_sk)
assert ss_client == ss_server, "Key exchange failed!"
                    """,
                    description="Perform hybrid PQC+ECC key exchange with forward secrecy"
                )
            ],
            introduced_version="v1",
            nist_standard=True,
            security_level=5
        )
        
        # =====================================================================
        # KEY MANAGEMENT
        # =====================================================================
        
        self._modules["secure_key_manager"] = ModuleDocumentation(
            module_name="Secure Key Manager with Zeroization",
            filename="secure_key_manager_with_zeroization_2026_june.py",
            category=ModuleCategory.KEY_MANAGEMENT,
            stability=StabilityLevel.STABLE,
            version="v1",
            description="Secure key lifecycle management with memory zeroization, key wrapping, and TPM-compatible key storage interface.",
            main_class="SecureKeyManager",
            public_methods=[
                "generate_and_wrap_key() - Generate AES key with wrap",
                "unwrap_and_decrypt_key() - Unwrap with authentication",
                "zeroize_key() - Secure memory overwrite",
                "rotate_key() - Automated key rotation",
                "get_key_usage_metrics() - Key access audit log"
            ],
            introduced_version="v1"
        )
        
        # =====================================================================
        # SECURITY HARDENING MODULES
        # =====================================================================
        
        self._modules["side_channel_resistant_primitives"] = ModuleDocumentation(
            module_name="Side-Channel Resistant Primitives",
            filename="side_channel_resistant_crypto_primitives_2026_june.py",
            category=ModuleCategory.SECURITY_HARDENING,
            stability=StabilityLevel.STABLE,
            version="v1",
            description="Timing-attack resistant implementations: constant-time comparison, masked operations, branch-free arithmetic.",
            main_class="SideChannelResistant",
            public_methods=[
                "constant_time_compare() - Timing-attack safe equality check",
                "constant_time_select() - Branch-free conditional selection",
                "masked_arithmetic() - First-order DPA masking",
                "verify_constant_time_execution() - Runtime variance test"
            ],
            examples=[
                APIExample(
                    title="Constant-Time Comparison",
                    code="""
from quantum_crypt.side_channel_resistant_crypto_primitives_2026_june import SideChannelResistant

scr = SideChannelResistant()
# SAFE: No timing leakage
result = scr.constant_time_compare(hmac_calculated, hmac_received)
                    """,
                    description="Use constant-time comparison to prevent timing attacks"
                )
            ],
            introduced_version="v1"
        )
        
        # =====================================================================
        # ERROR RESILIENCE MODULES
        # =====================================================================
        
        self._modules["crypto_error_resilience"] = ModuleDocumentation(
            module_name="Cryptographic Error Resilience",
            filename="crypto_error_resilience_circuit_breaker_v20_2026_june.py",
            category=ModuleCategory.ERROR_RESILIENCE,
            stability=StabilityLevel.STABLE,
            version="v20",
            description="Cryptographic operation error resilience with circuit breaker, exponential backoff with jitter, and graceful degradation fallback.",
            main_class="CryptoResilienceManager",
            public_methods=[
                "execute_crypto_with_timeout() - Timeout-protected operation",
                "execute_with_retry_backoff() - Retry with jittered exponential backoff",
                "check_circuit_breaker() - Get circuit health status",
                "get_degraded_algorithm() - Fallback algorithm selection",
                "record_failure() - Failure tracking for circuit breaker"
            ],
            introduced_version="v8"
        )
        
        # =====================================================================
        # OBSERVABILITY MODULES
        # =====================================================================
        
        self._modules["crypto_observability_tracing"] = ModuleDocumentation(
            module_name="Cryptographic Observability Tracing",
            filename="crypto_observability_distributed_tracing_v7_2026_june.py",
            category=ModuleCategory.OBSERVABILITY,
            stability=StabilityLevel.STABLE,
            version="v7",
            description="Distributed tracing for cryptographic operations with latency tracking, algorithm telemetry, and security event correlation.",
            main_class="CryptoTracer",
            public_methods=[
                "trace_key_generation() - Trace key generation with metrics",
                "trace_encryption() - Trace encryption operation timing",
                "trace_decryption() - Trace decryption operation timing",
                "add_security_baggage() - Correlation context propagation",
                "export_otel_spans() - OpenTelemetry compatible export"
            ],
            introduced_version="v3"
        )
        
        # =====================================================================
        # ENTROPY COLLECTION
        # =====================================================================
        
        self._modules["entropy_health_monitor"] = ModuleDocumentation(
            module_name="Entropy Health Monitor",
            filename="entropy_health_monitor_validator_2026_june.py",
            category=ModuleCategory.ENTROPY,
            stability=StabilityLevel.STABLE,
            version="v1",
            description="Cryptographic entropy source health monitoring with NIST SP 800-90B validation and continuous randomness testing.",
            main_class="EntropyHealthMonitor",
            public_methods=[
                "collect_entropy_sample() - Collect and test entropy sample",
                "run_nist_sp800_90b_tests() - Full NIST randomness battery",
                "get_entropy_estimate() - Min-entropy calculation",
                "check_entropy_health() - Health status with alerting",
                "reseed_if_needed() - Auto-reseed on low entropy detection"
            ],
            introduced_version="v1"
        )
        
        # =====================================================================
        # DOCUMENTATION MODULES (SELF-REFERENTIAL)
        # =====================================================================
        
        self._modules["api_documentation_catalog_v16"] = ModuleDocumentation(
            module_name="API Documentation Catalog v16",
            filename="comprehensive_api_documentation_stability_catalog_v16_2026_june.py",
            category=ModuleCategory.DOCUMENTATION,
            stability=StabilityLevel.STABLE,
            version="v16",
            description="This documentation catalog - Comprehensive API documentation with stability markers, NIST compliance status, and usage examples for all QuantumCrypt-AI modules.",
            main_class="QuantumCryptDocumentationCatalog",
            introduced_version="v16"
        )
    
    def get_module_documentation(self, module_key: str) -> Optional[ModuleDocumentation]:
        """Get documentation for specific module"""
        return self._modules.get(module_key)
    
    def get_all_documentation(self) -> List[ModuleDocumentation]:
        """Get documentation for all modules"""
        return list(self._modules.values())
    
    def get_modules_by_stability(self, stability: StabilityLevel) -> List[ModuleDocumentation]:
        """Get all modules with specific stability level"""
        return [m for m in self._modules.values() if m.stability == stability]
    
    def get_modules_by_category(self, category: ModuleCategory) -> List[ModuleDocumentation]:
        """Get all modules in specific category"""
        return [m for m in self._modules.values() if m.category == category]
    
    def get_nist_standard_algorithms(self) -> List[ModuleDocumentation]:
        """Get all NIST-standardized PQC modules"""
        return [m for m in self._modules.values() if m.nist_standard]
    
    def generate_stability_report(self) -> Dict[str, Any]:
        """Generate comprehensive stability summary report"""
        total_modules = len(self._modules)
        by_stability = {
            level.value: len(self.get_modules_by_stability(level))
            for level in StabilityLevel
        }
        by_category = {
            cat.value: len(self.get_modules_by_category(cat))
            for cat in ModuleCategory
        }
        nist_count = len(self.get_nist_standard_algorithms())
        
        return {
            "report_version": "v16",
            "generated_at": datetime.now().isoformat(),
            "total_modules_documented": total_modules,
            "nist_standard_algorithms": nist_count,
            "modules_by_stability": by_stability,
            "modules_by_category": by_category,
            "stability_breakdown_percent": {
                level: round(count / total_modules * 100, 1)
                for level, count in by_stability.items()
                if total_modules > 0
            }
        }
    
    def export_to_json(self, filepath: str) -> None:
        """Export complete catalog to JSON file"""
        data = {
            "catalog_version": "v16",
            "generated_at": datetime.now().isoformat(),
            "modules": [m.to_dict() for m in self._modules.values()]
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def generate_readme_snippet(self) -> str:
        """Generate Markdown documentation snippet for README"""
        report = self.generate_stability_report()
        md = "# QuantumCrypt-AI API Stability Overview v16\n\n"
        md += f"**NIST Standard Algorithms Documented:** {report['nist_standard_algorithms']}\n\n"
        md += "## Stability Breakdown\n\n"
        md += "| Stability Level | Module Count | Percentage |\n"
        md += "|-----------------|--------------|------------|\n"
        for level, count in report["modules_by_stability"].items():
            pct = report["stability_breakdown_percent"].get(level, 0)
            md += f"| {level} | {count} | {pct}% |\n"
        md += "\n## Module Categories\n\n"
        for cat, count in report["modules_by_category"].items():
            if count > 0:
                md += f"- **{cat}**: {count} modules\n"
        return md


# =====================================================================
# USAGE EXAMPLE - RUN THIS FILE TO SEE CATALOG
# =====================================================================
if __name__ == "__main__":
    catalog = QuantumCryptDocumentationCatalog()
    
    print("=" * 70)
    print("QuantumCrypt-AI API Documentation Catalog v16 - Session 115")
    print("=" * 70)
    
    report = catalog.generate_stability_report()
    print(f"\nTotal Modules Documented: {report['total_modules_documented']}")
    print(f"NIST Standard Algorithms: {report['nist_standard_algorithms']}")
    print("\nModules by Stability:")
    for level, count in report["modules_by_stability"].items():
        print(f"  {level}: {count}")
    
    print("\nModules by Category:")
    for cat, count in report["modules_by_category"].items():
        if count > 0:
            print(f"  {cat}: {count}")
    
    print("\n" + "=" * 70)
    print("Documentation catalog loaded successfully!")
    print("=" * 70)
