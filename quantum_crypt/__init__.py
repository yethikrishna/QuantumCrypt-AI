"""
QuantumCrypt-AI - Post-Quantum Cryptography Framework
June 19, 2026 - Enhanced with Dilithium Digital Signatures

Production-grade post-quantum cryptography implementations including:
- CRYSTALS-Kyber Key Encapsulation Mechanism (KEM)
- CRYSTALS-Dilithium Digital Signatures
- Hash-based Signatures (SPHINCS+)
- Hybrid Encryption Engines
- Key Management & Rotation Systems
"""

# Kyber KEM (NIST PQC Standard for Key Exchange)
from .post_quantum_kyber_kem_engine_2026_june import KyberKEM, run_kyber_demo

# Dilithium Digital Signatures (NIST PQC Standard for Signing)
from .post_quantum_dilithium_signature_engine_2026_june import (
    SecurityParams,
    KeyPair,
    Signature,
    OptimizedPolynomial,
    DilithiumSignatureEngine
)

# Hash-based Signature Engine (SPHINCS+ style)
from .post_quantum_hash_based_signature_engine_2026_june import (
    HashBasedSignatureEngine,
    HashSignature,
    HashKeyPair,
    WinternitzOTS,
    HyperTree
)

# Hybrid Encryption Engine (Classic + Post-Quantum)
from .post_quantum_hybrid_encryption_engine_2026_june import (
    HybridEncryptionEngine,
    EncryptionResult,
    HybridKeyPair,
    Ciphertext
)

# Hybrid KEM Encryption Engine
from .post_quantum_hybrid_kem_encryption_engine_2026_june import (
    HybridKEMEngine,
    KEMResult,
    KEMKeyPair
)

# Forward Secrecy Engine
from .post_quantum_forward_secrecy_engine_2026_june import (
    ForwardSecrecyEngine,
    SessionKey,
    KeyRotationEvent
)

# Key Diversification Engine
from .post_quantum_key_diversification_engine_2026_june import (
    KeyDiversificationEngine,
    DerivedKey,
    DiversificationResult
)

# Key Management & Rotation Engine
from .post_quantum_key_management_rotation_engine_2026_june import (
    KeyManagementRotationEngine,
    ManagedKey,
    RotationEvent,
    KeyStatus
)

# Password Hashing Engine (Memory-Hard)
from .post_quantum_password_hashing_engine_2026_june import (
    PasswordHashingEngine,
    PasswordHash,
    HashParams
)

# Secret Sharing Engine (Shamir)
from .post_quantum_secret_sharing_engine_2026_june import (
    SecretSharingEngine,
    SecretShare,
    SharingResult
)

# Secure Audit Logger
from .post_quantum_secure_audit_logger_2026_june import (
    SecureAuditLogger,
    AuditEvent,
    AuditLogEntry
)

# Enhanced Secure Audit Logger
from .post_quantum_secure_audit_logger_enhanced_2026_june import (
    EnhancedSecureAuditLogger,
    EnhancedAuditEvent,
    IntegrityProof
)

# Secure Backup with Shamir Secret Sharing
from .post_quantum_secure_backup_shamir_secret_sharing_2026_june import (
    SecureBackupEngine,
    BackupFragment,
    BackupResult,
    RecoveryResult
)

# Key Backup & Recovery Engine
from .post_quantum_key_backup_recovery_engine_2026_june import (
    KeyBackupRecoveryEngine,
    BackupRecord,
    RecoveryEvent
)

# HSM Integration Engine
from .post_quantum_hsm_integration_engine_2026_june import (
    HSMIntegrationEngine,
    HSMKey,
    HSMOperation
)

# HSM Key Wrapper with Side-Channel Protection
from .post_quantum_hsm_key_wrapper_side_channel_protected_2026_june import (
    HSMKeyWrapper,
    WrappedKey,
    ProtectionLevel
)

# Entropy Health Monitor
from .post_quantum_entropy_health_monitor_2026_june import (
    EntropyHealthMonitor,
    EntropySource,
    HealthReport
)

# Entropy Health Monitor & Collector
from .post_quantum_entropy_health_monitor_collector_2026_june import (
    EntropyHealthMonitorCollector,
    EntropySample,
    CollectionResult
)

# Certificate Chain Validator
from .post_quantum_certificate_chain_validator_2026_june import (
    CertificateChainValidator,
    CertificateInfo,
    ValidationResult
)

# Certificate Transparency
from .post_quantum_certificate_transparency_2026_june import (
    CertificateTransparency,
    CTLogEntry,
    SCT
)

# Certificate Transparency Logger
from .post_quantum_certificate_transparency_logger_2026_june import (
    CertificateTransparencyLogger,
    LogOperation
)

# Certificate Transparency Verifier
from .post_quantum_certificate_transparency_verifier_2026_june import (
    CertificateTransparencyVerifier,
    VerificationProof
)

# API Gateway Middleware
from .post_quantum_api_gateway_middleware_2026_june import (
    PostQuantumAPIGateway,
    ProtectedRequest,
    GatewayResult
)

# Crypto Agility Migration Engine
from .post_quantum_crypto_agility_migration_engine_2026_june import (
    CryptoAgilityEngine,
    MigrationPlan,
    AlgorithmTransition
)

# Algorithm Benchmark Profiler
from .post_quantum_crypto_algorithm_benchmark_profiler_2026_june import (
    AlgorithmBenchmarkProfiler,
    BenchmarkResult,
    PerformanceMetrics
)

# Benchmark Suite
from .post_quantum_crypto_benchmark_suite_2026_june import (
    PostQuantumBenchmarkSuite,
    BenchmarkTest,
    SuiteResult
)

# Inventory & Compliance Scanner
from .post_quantum_crypto_inventory_compliance_scanner_2026_june import (
    CryptoInventoryScanner,
    InventoryItem,
    ComplianceReport
)

# Policy Enforcement Auditor
from .post_quantum_crypto_policy_enforcement_auditor_2026_june import (
    PolicyEnforcementAuditor,
    PolicyRule,
    AuditFinding
)

# Algorithm Compatibility Migration Advisor
from .post_quantum_algorithm_compatibility_migration_advisor_2026_june import (
    CompatibilityMigrationAdvisor,
    CompatibilityReport,
    MigrationRecommendation
)

# Algorithm Health Monitor & Key Rotation Advisor
from .post_quantum_algorithm_health_monitor_key_rotation_advisor_2026_june import (
    AlgorithmHealthMonitor,
    HealthMetrics,
    RotationAdvice
)

# Algorithm Interoperability Test Suite
from .post_quantum_algorithm_interoperability_test_suite_2026_june import (
    InteroperabilityTestSuite,
    InteropTest,
    InteropResult
)

# Algorithm Performance Autotuner
from .post_quantum_algorithm_performance_autotuner_2026_june import (
    PerformanceAutotuner,
    TuningParameters,
    OptimizationResult
)

# Policy Compliance Validator
from .post_quantum_policy_compliance_validator_2026_june import (
    PolicyComplianceValidator,
    ComplianceCheck,
    ValidationResult
)

# Memory-Hard KDF Enhanced
from .post_quantum_memory_hard_kdf_enhanced_2026_june import (
    MemoryHardKDF,
    KDFResult,
    MemoryHardParams
)

# Migration Readiness Assessor
from .post_quantum_migration_readiness_assessor_2026_june import (
    MigrationReadinessAssessor,
    ReadinessReport,
    ReadinessScore
)

# Key Rotation Rekey Manager
from .post_quantum_key_rotation_rekey_manager_2026_june import (
    KeyRotationRekeyManager,
    RekeyEvent,
    RotationSchedule
)
# Constant-Time Execution Protector (June 19, 2026 Production Release)
# Side-channel attack protection: constant-time comparisons, timing jitter,
# statistical leak detection, branch prediction mitigation
from .post_quantum_constant_time_execution_protector_2026_june import (
    ConstantTimeExecutor,
    ProtectionLevel,
    LeakSeverity,
    TimingMeasurement,
    TimingLeakDetection,
    ProtectionResult,
    create_constant_time_protector
)

__version__ = "2026.6.19.2"

__all__ = [
    # Core Algorithms
    'KyberKEM',
    'DilithiumSignatureEngine',
    'HashBasedSignatureEngine',
    'HybridEncryptionEngine',
    'HybridKEMEngine',
    
    # Key Management
    'KeyManagementRotationEngine',
    'KeyDiversificationEngine',
    'KeyBackupRecoveryEngine',
    'KeyRotationRekeyManager',
    
    # Security
    'ForwardSecrecyEngine',
    'PasswordHashingEngine',
    'SecretSharingEngine',
    'SecureBackupEngine',
    'MemoryHardKDF',
    'ConstantTimeExecutor',
    'create_constant_time_protector',
    
    # HSM Integration
    'HSMIntegrationEngine',
    'HSMKeyWrapper',
    
    # Entropy
    'EntropyHealthMonitor',
    'EntropyHealthMonitorCollector',
    
    # Certificates
    'CertificateChainValidator',
    'CertificateTransparency',
    'CertificateTransparencyLogger',
    'CertificateTransparencyVerifier',
    
    # Auditing
    'SecureAuditLogger',
    'EnhancedSecureAuditLogger',
    
    # API & Middleware
    'PostQuantumAPIGateway',
    
    # Migration & Compliance
    'CryptoAgilityEngine',
    'MigrationReadinessAssessor',
    'CompatibilityMigrationAdvisor',
    'AlgorithmHealthMonitor',
    'CryptoInventoryScanner',
    'PolicyEnforcementAuditor',
    'PolicyComplianceValidator',
    
    # Benchmarking & Testing
    'AlgorithmBenchmarkProfiler',
    'PostQuantumBenchmarkSuite',
    'InteroperabilityTestSuite',
    'PerformanceAutotuner',
    
    # Data Classes
    'KeyPair',
    'Signature',
    'HashSignature',
    'HashKeyPair',
    'EncryptionResult',
    'HybridKeyPair',
    'Ciphertext',
    'KEMResult',
    'KEMKeyPair',
    'SessionKey',
    'DerivedKey',
    'ManagedKey',
    'PasswordHash',
    'SecretShare',
    'BackupFragment',
    'AuditEvent',
]

# Post-Quantum Entropy Quality Validator (June 19, 2026 Production Release)
# Real NIST SP 800-90B statistical tests, entropy estimation, health monitoring
from .post_quantum_entropy_quality_validator_2026_june import (
    EntropySourceType,
    HealthStatus,
    RandomnessTestType,
    EntropyMeasurement,
    EntropyPoolHealth,
    ValidationResult,
    BaseRandomnessTest,
    FrequencyTest,
    ChiSquareTest,
    AutocorrelationTest,
    RunsTest,
    EntropyEstimator,
    EntropyQualityValidator,
    create_entropy_validator,
)
__all__.extend([
    'EntropySourceType',
    'HealthStatus',
    'RandomnessTestType',
    'EntropyMeasurement',
    'EntropyPoolHealth',
    'ValidationResult',
    'BaseRandomnessTest',
    'FrequencyTest',
    'ChiSquareTest',
    'AutocorrelationTest',
    'RunsTest',
    'EntropyEstimator',
    'EntropyQualityValidator',
    'create_entropy_validator',
])

__version__ = "2026.6.19.4"
