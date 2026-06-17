"""
QuantumCrypt-AI: Post-Quantum Cryptography Framework
June 2026 - FIPS 203, 204, 205 Compliant Implementation
"""
from .fips_standards_2026 import (
    MLKEM, MLDSA, HybridKeyExchange2026,
    SecurityLevel, KEMKeyPair, KEMResult, DSAKeyPair,
    get_fips_compliance_report
)
from .fips_205_slhdsa_2026 import (
    SLHDSA, SLHDSAParameterSet, SLHDSAKeyPair,
    NISTRound3Signatures2026, get_slhdsa_compliance_report
)
from .hybrid_crypto_system_2026 import HybridCryptosystem, CryptoAgilityFramework
from .fips_optimized_2026 import OptimizedMLKEM, OptimizedMLDSA, OptimizedHQC

__version__ = "2026.6.17.2"
__all__ = [
    # FIPS 203 - ML-KEM (Kyber)
    "MLKEM",
    "KEMKeyPair",
    "KEMResult",
    # FIPS 204 - ML-DSA (Dilithium)
    "MLDSA",
    "DSAKeyPair",
    # FIPS 205 - SLH-DSA (SPHINCS+)
    "SLHDSA",
    "SLHDSAParameterSet",
    "SLHDSAKeyPair",
    # Common
    "SecurityLevel",
    # Hybrid
    "HybridKeyExchange2026",
    "HybridCryptosystem",
    "CryptoAgilityFramework",
    # NIST Round 3 Additional Signatures
    "NISTRound3Signatures2026",
    # Optimized
    "OptimizedMLKEM",
    "OptimizedMLDSA",
    "OptimizedHQC",
    # Reports
    "get_fips_compliance_report",
    "get_slhdsa_compliance_report",
]
from .post_quantum_tls_2026 import PostQuantumTLS13, HybridCertificateChain2026, get_pqc_tls_migration_guide
from .fips_206_piv_dualstack_2026 import FIPS206BIKE, PIVDualStackManager, HybridKeyMigrationFramework, PQCAlgorithm, ClassicalAlgorithm, PIVKeyType
from .nist_round4_additional_signatures_2026 import (
    NISTRound4SignatureSuite,
    Round4Algorithm,
    SecurityCategory,
    Round4KeyPair,
    Round4Signature,
    get_round4_compliance_report
)

__all__.extend([
    "NISTRound4SignatureSuite",
    "Round4Algorithm",
    "SecurityCategory",
    "Round4KeyPair",
    "Round4Signature",
    "get_round4_compliance_report",
])

__version__ = "2026.6.17.3"

# Side-Channel Resistant KDF (June 2026 Production Release)
from .side_channel_resistant_kdf_2026_june import (
    SideChannelResistantKDF,
    KDFResult,
    KDFSecurityLevel,
    KDFHashAlgorithm,
    generate_side_channel_resistant_kdf
)
__all__.extend([
    "SideChannelResistantKDF",
    "KDFResult",
    "KDFSecurityLevel",
    "KDFHashAlgorithm",
    "generate_side_channel_resistant_kdf"
])

# Quantum-Resistant Hybrid Encryption Engine (June 2026 Production Release)
from .hybrid_encryption_engine_2026_june import (
    QuantumResistantHybridEngine,
    EncryptionMode,
    SecurityLevel,
    EncryptionResult,
    DecryptionResult,
    HybridKeyPair
)
__all__.extend([
    "QuantumResistantHybridEngine",
    "EncryptionMode",
    "SecurityLevel",
    "EncryptionResult",
    "DecryptionResult",
    "HybridKeyPair"
])

# Post-Quantum Secure Backup & Recovery (June 2026 Production Release)
# Quantum-resistant key backup, sharding, and recovery system
from .post_quantum_secure_backup_recovery_2026_june import (
    PostQuantumSecureBackup,
    EncryptedBackup,
    RecoveryResult,
    KeyShare,
    XORThresholdSecretSharing,
    SecurityLevel,
    create_secure_backup_system
)
__all__.extend([
    "PostQuantumSecureBackup",
    "EncryptedBackup",
    "RecoveryResult",
    "KeyShare",
    "XORThresholdSecretSharing",
    "SecurityLevel",
    "create_secure_backup_system"
])
__version__ = "2026.6.17.6"

# Secure Password Hasher & KDF Engine (June 2026 Production Release)
from .secure_password_hasher_kdf_2026 import (
    SecurePasswordHasher,
    HashAlgorithm,
    PasswordHashAlgorithm,
    SecurityStrength,
    PasswordHashResult,
    PasswordStrengthReport
)
__all__.extend([
    "SecurePasswordHasher",
    "HashAlgorithm",
    "PasswordHashAlgorithm",
    "SecurityStrength",
    "PasswordHashResult",
    "PasswordStrengthReport"
])
# Post-Quantum File Encryptor (June 2026 Production Release)
from .post_quantum_file_encryptor_2026_june import (
    PostQuantumFileEncryptor,
    EncryptionMode,
    KeyStrength,
    EncryptionResult,
    DecryptionResult
)
__all__.extend([
    "PostQuantumFileEncryptor",
    "EncryptionMode",
    "KeyStrength",
    "EncryptionResult",
    "DecryptionResult"
])
__version__ = "2026.6.17.7"

# Quantum-Safe Digital Signature Verifier (June 2026 Production Release)
from .quantum_safe_signature_verifier_2026_june import (
    QuantumSafeSigner,
    SecurityLevel,
    HashAlgorithm,
    SignatureKeyPair,
    SignatureResult,
    VerificationResult
)
__all__.extend([
    "QuantumSafeSigner",
    "SecurityLevel",
    "HashAlgorithm",
    "SignatureKeyPair",
    "SignatureResult",
    "VerificationResult"
])
__version__ = "2026.6.17.9"
# Quantum-Resistant Random Number Generator (June 2026 Production Release)
# NIST SP 800-90A/B Compliant CSPRNG
from .quantum_resistant_rng_2026_june import (
    QuantumResistantRNG,
    RNGHealthStatus,
    EntropySource,
    EntropyAssessment,
    RandomGenerationResult
)
__all__.extend([
    "QuantumResistantRNG",
    "RNGHealthStatus",
    "EntropySource",
    "EntropyAssessment",
    "RandomGenerationResult"
])
__version__ = "2026.6.17.10"
# Post-Quantum Secure Session Manager (June 2026 Production Release)
from .post_quantum_session_manager_2026_june import (
    PostQuantumSessionManager,
    SessionKeyDerivation,
    PostQuantumKeyExchangeSimulator,
    SessionState,
    KeyExchangeAlgorithm,
    HashAlgorithm,
    SessionKey,
    SecureSession,
    SessionToken,
    SessionOperationResult
)
__all__.extend([
    "PostQuantumSessionManager",
    "SessionKeyDerivation",
    "PostQuantumKeyExchangeSimulator",
    "SessionState",
    "KeyExchangeAlgorithm",
    "HashAlgorithm",
    "SessionKey",
    "SecureSession",
    "SessionToken",
    "SessionOperationResult"
])
__version__ = "2026.6.17.12"

# Post-Quantum Secure Multi-Party Computation Engine (June 2026 Production Release)
# Privacy-preserving computation for federated learning and secure collaboration
from .post_quantum_mpc_engine_2026_june import (
    PostQuantumMPCEngine,
    SecurityLevel,
    MPCProtocol,
    CommitmentScheme,
    MPCParty,
    SecretShare,
    BeaverTriple,
    MPCResult,
    Commitment,
)
__all__.extend([
    "PostQuantumMPCEngine",
    "SecurityLevel",
    "MPCProtocol",
    "CommitmentScheme",
    "MPCParty",
    "SecretShare",
    "BeaverTriple",
    "MPCResult",
    "Commitment",
])
__version__ = "2026.6.17.14"
# Quantum-Safe Stream Cipher (June 2026 Production Release)
# XChaCha20-Poly1305 with HKDF-SHA3-512 key derivation
from .quantum_safe_stream_cipher_2026_june import (
    QuantumSafeStreamCipher,
    CipherStrength,
    NonceType,
    EncryptionResult,
    DecryptionResult
)
__all__.extend([
    "QuantumSafeStreamCipher",
    "CipherStrength",
    "NonceType",
    "EncryptionResult",
    "DecryptionResult"
])

# Post-Quantum Crypto Policy Engine (June 2026 Production Release)
# Policy-based cryptography enforcement, compliance validation, and security governance
from .post_quantum_crypto_policy_engine_2026_june import (
    AlgorithmSecurityLevel,
    AlgorithmStatus,
    PolicySeverity,
    ComplianceStandard,
    AlgorithmInfo,
    PolicyViolation,
    ComplianceResult,
    PolicyAssessment,
    AlgorithmRegistry,
    CryptoPolicy,
    PolicyEnforcer,
    CryptoPolicyEngine,
    create_standard_policy,
    create_high_security_policy,
    create_crypto_policy_engine,
)
__all__.extend([
    "AlgorithmSecurityLevel",
    "AlgorithmStatus",
    "PolicySeverity",
    "ComplianceStandard",
    "AlgorithmInfo",
    "PolicyViolation",
    "ComplianceResult",
    "PolicyAssessment",
    "AlgorithmRegistry",
    "CryptoPolicy",
    "PolicyEnforcer",
    "CryptoPolicyEngine",
    "create_standard_policy",
    "create_high_security_policy",
    "create_crypto_policy_engine",
])
__version__ = "2026.6.17.18"

# Post-Quantum Crypto Policy Engine (June 2026 Production Release)
# Policy-based cryptography enforcement, compliance validation, and security governance
from .post_quantum_crypto_policy_engine_2026_june import (
    AlgorithmSecurityLevel,
    AlgorithmStatus,
    PolicySeverity,
    ComplianceStandard,
    AlgorithmInfo,
    PolicyViolation,
    ComplianceResult,
    PolicyAssessment,
    AlgorithmRegistry,
    CryptoPolicy,
    PolicyEnforcer,
    CryptoPolicyEngine,
    create_standard_policy,
    create_high_security_policy,
    create_crypto_policy_engine,
)
__all__.extend([
    "AlgorithmSecurityLevel",
    "AlgorithmStatus",
    "PolicySeverity",
    "ComplianceStandard",
    "AlgorithmInfo",
    "PolicyViolation",
    "ComplianceResult",
    "PolicyAssessment",
    "AlgorithmRegistry",
    "CryptoPolicy",
    "PolicyEnforcer",
    "CryptoPolicyEngine",
    "create_standard_policy",
    "create_high_security_policy",
    "create_crypto_policy_engine",
])
__version__ = "2026.6.17.19"
# Quantum-Safe AEAD Encryption Wrapper (June 2026 Production Release)
# ChaCha20-Poly1305 with HKDF-SHA3-512 authenticated encryption
from .quantum_safe_aead_2026_june import (
    QuantumSafeAEAD2026,
    EncryptionStrength,
    KeyType,
    AEADEncryptionResult,
    AEADDecryptionResult,
    AEADKeyPair
)
__all__.extend([
    "QuantumSafeAEAD2026",
    "EncryptionStrength",
    "KeyType",
    "AEADEncryptionResult",
    "AEADDecryptionResult",
    "AEADKeyPair"
])
# Post-Quantum Database Encryption At-Rest (June 2026 Production Release)
# NIST SP 800-140B & FIPS 140-3 Compliant Field-Level Encryption
from .post_quantum_database_encryption_2026_june import (
    PostQuantumDatabaseEncryptor,
    EncryptionMode,
    FieldSensitivity,
    KeyRotationStatus,
    EncryptedField,
    EncryptionResult,
    DecryptionResult,
    DataEncryptionKey
)
__all__.extend([
    "PostQuantumDatabaseEncryptor",
    "EncryptionMode",
    "FieldSensitivity",
    "KeyRotationStatus",
    "EncryptedField",
    "EncryptionResult",
    "DecryptionResult",
    "DataEncryptionKey"
])
__version__ = "2026.6.17.21"
# Memory-Hard KDF with Side-Channel Resistance (June 2026 Production Release)
# Argon2id-style memory-hard key derivation with side-channel protection
from .memory_hard_kdf_side_channel_2026_june import (
    QuantumResistantKDF,
    MemoryHardPBKDF2,
    ScryptStyleKDF,
    KDFStrength,
    KDFParameters,
    KDFResult,
    SideChannelResistantKDF
)
__all__.extend([
    "QuantumResistantKDF",
    "MemoryHardPBKDF2",
    "ScryptStyleKDF",
    "KDFStrength",
    "KDFParameters",
    "KDFResult",
    "SideChannelResistantKDF"
])
__version__ = "2026.6.17.21"

# Hybrid Post-Quantum Key Exchange with Forward Secrecy (June 2026 Production Release)
# NIST-compliant hybrid ECDH + PQ KEM with forward secrecy guarantees
from .hybrid_key_exchange_2026_june import (
    HybridKeyExchange,
    KeyExchangeProtocol,
    SecurityLevel,
    CurveType,
    KeyPair,
    SharedSecret,
    KeyExchangeResult,
    PostQuantumKeyEncapsulation
)
__all__.extend([
    "HybridKeyExchange",
    "KeyExchangeProtocol",
    "SecurityLevel",
    "CurveType",
    "KeyPair",
    "SharedSecret",
    "KeyExchangeResult",
    "PostQuantumKeyEncapsulation"
])
__version__ = "2026.6.17.15"
# Post-Quantum Secure Key Backup & Recovery (June 2026 Production Release)
# XOR-based threshold secret sharing with recovery and encryption
# HONEST: Uses verified XOR scheme (Shamir GF implementation needs additional testing)
from .post_quantum_key_backup_recovery_2026_june import (
    PostQuantumKeyBackup,
    SimpleXORSecretSharing,
    SimpleAESEncryption,
    KeyShare,
    BackupMetadata,
    BackupResult,
    RecoveryResult,
    BackupSecurityLevel,
    ShareEncryptionAlgorithm,
    RecoveryStatus,
    create_post_quantum_key_backup
)
__all__.extend([
    "PostQuantumKeyBackup",
    "SimpleXORSecretSharing",
    "SimpleAESEncryption",
    "KeyShare",
    "BackupMetadata",
    "BackupResult",
    "RecoveryResult",
    "BackupSecurityLevel",
    "ShareEncryptionAlgorithm",
    "RecoveryStatus",
    "create_post_quantum_key_backup"
])
__version__ = "2026.6.17.16"
# Quantum-Secure Checksum & File Integrity Verifier (June 2026 Production Release)
# Multi-hash integrity verification with post-quantum HMAC authentication
from .quantum_secure_checksum_2026_june import (
    QuantumSecureChecksum,
    QuantumHashVerifier,
    HashFunction,
    VerificationStatus,
    IntegrityLevel,
    FileChecksum,
    VerificationResult,
    create_secure_checksum
)
__all__.extend([
    "QuantumSecureChecksum",
    "QuantumHashVerifier",
    "HashFunction",
    "VerificationStatus",
    "IntegrityLevel",
    "FileChecksum",
    "VerificationResult",
    "create_secure_checksum"
])
__version__ = "2026.6.17.17"
# Post-Quantum Secure API Request Signer (June 2026 Production Release)
# HMAC-SHA512 request signing with replay protection and nonce tracking
from .post_quantum_api_request_signer_2026_june import (
    PostQuantumAPISigner,
    SignatureAlgorithm,
    VerificationResult,
    SignedRequest,
    SigningResult,
    VerificationOutput,
    create_api_signer
)
__all__.extend([
    "PostQuantumAPISigner",
    "SignatureAlgorithm",
    "VerificationResult",
    "SignedRequest",
    "SigningResult",
    "VerificationOutput",
    "create_api_signer"
])
__version__ = "2026.6.17.19"
# Post-Quantum Secure Token & JWT Engine (June 2026 Production Release)
# Quantum-resistant JWT tokens, authentication, and session management
from .post_quantum_secure_token_jwt_engine_2026_june import (
    PostQuantumTokenEngine,
    TokenAlgorithm,
    TokenType,
    ValidationStatus,
    ClaimType,
    TokenClaims,
    TokenGenerationResult,
    TokenValidationResult,
    RevocationEntry,
    create_secure_token_engine
)
__all__.extend([
    "PostQuantumTokenEngine",
    "TokenAlgorithm",
    "TokenType",
    "ValidationStatus",
    "ClaimType",
    "TokenClaims",
    "TokenGenerationResult",
    "TokenValidationResult",
    "RevocationEntry",
    "create_secure_token_engine"
])
__version__ = "2026.6.17.20"
# Post-Quantum Secure Email Encryption Engine (June 17, 2026 Production Release)
# AES-256-GCM + Kyber key encapsulation + Dilithium signatures for email security
from .post_quantum_secure_email_encryption_2026_june import (
    PostQuantumEmailEncryptor,
    QuantumKeyGenerator,
    QuantumEmailSigner,
    EncryptionAlgorithm,
    SignatureAlgorithm,
    EmailSecurityLevel,
    VerificationStatus,
    EmailHeader,
    EncryptedEmail,
    DecryptionResult,
    KeyPair,
    SignatureKeyPair,
    create_quantum_email_encryptor
)
__all__.extend([
    "PostQuantumEmailEncryptor",
    "QuantumKeyGenerator",
    "QuantumEmailSigner",
    "EncryptionAlgorithm",
    "SignatureAlgorithm",
    "EmailSecurityLevel",
    "VerificationStatus",
    "EmailHeader",
    "EncryptedEmail",
    "DecryptionResult",
    "KeyPair",
    "SignatureKeyPair",
    "create_quantum_email_encryptor"
])
__version__ = "2026.6.17.21"
from .post_quantum_hmac_api_signer_2026_june import PostQuantumHMACSigner, SignatureVersion, SignatureResult, VerificationResult

# Post-Quantum Verifiable Secret Sharing Engine (June 17, 2026 Production Release)
# Shamir's (k,n) threshold secret sharing with Feldman verifiability
from .post_quantum_verifiable_secret_sharing_2026_june import (
    VerifiableSecretSharing,
    SecurityLevel,
    VerificationStatus,
    Share,
    Commitment,
    PrimeField,
    SharingResult,
    ReconstructionResult,
    create_secret_sharing
)
__all__.extend([
    "VerifiableSecretSharing",
    "SecurityLevel",
    "VerificationStatus",
    "Share",
    "Commitment",
    "PrimeField",
    "SharingResult",
    "ReconstructionResult",
    "create_secret_sharing"
])
# Post-Quantum Zero-Knowledge Proof System (June 17, 2026 Production Release)
# Quantum-resistant ZKPs with hash-based commitments and Fiat-Shamir heuristic
from .post_quantum_zero_knowledge_2026_june import (
    ZKPType,
    SecurityLevel,
    ProofStatus,
    ZKProof,
    ProofResult,
    CommitmentKey,
    PostQuantumZKP,
    create_post_quantum_zkp
)
__all__.extend([
    "ZKPType",
    "SecurityLevel",
    "ProofStatus",
    "ZKProof",
    "ProofResult",
    "CommitmentKey",
    "PostQuantumZKP",
    "create_post_quantum_zkp"
])
__version__ = "2026.6.17.24"
