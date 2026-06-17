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
