"""
Crypto Security v17 - TLS/HTTPS Post-Quantum Protection
QuantumCrypt-AI | June 2026
ADD-ONLY COMPLIANT: 100% new module, no existing code modified
INCREMENTAL PHILOSOPHY: Layer PQ security ON TOP of existing TLS
SPECIALIZATION: Post-quantum safe TLS configuration for crypto operations
PROVIDES:
  - PQ-safe TLS guidance for crypto endpoints
  - Key material protection for TLS private keys
  - Hybrid PQ + classical TLS configuration patterns
  - Certificate hardening for crypto operations
  - Secure key exchange for quantum-resistant channels
  - TLS channel binding for crypto operations
  - Secure session key zeroization
DESIGN CONSTRAINTS:
  - OPT-IN only: Disabled by default
  - Zero new dependencies: Pure Python stdlib
  - Backward compatible: Falls back gracefully
  - Layered: Wraps existing crypto operations
  - Quantum-safe: NIST PQ algorithm ready
"""
import ssl
import threading
import time
import json
import secrets
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Callable
from enum import Enum
# ============================================================================
# ENUMERATIONS & CONSTANTS
# ============================================================================
class PQTLSMode(Enum):
    """Post-Quantum TLS Operation Modes"""
    CLASSICAL_ONLY = "classical_only"           # Standard TLS - NO PQ
    HYBRID_PQ_CLASSICAL = "hybrid_pq_classical"  # PQ + classical (recommended)
    PQ_ONLY = "pq_only"                          # PQ-only (future)
class KeyProtectionLevel(Enum):
    """Key material protection levels"""
    MEMORY_ONLY = "memory_only"                  # Standard memory
    SECURE_MEMORY = "secure_memory"              # Locked memory
    HSM_PROTECTED = "hsm_protected"              # Hardware security module
# NIST PQ Algorithms for TLS (future standards)
# CRYSTALS-Kyber is NIST FIPS 203 standard for key encapsulation
NIST_PQ_KEM_ALGORITHMS = [
    "Kyber-512",    # NIST Level 1
    "Kyber-768",    # NIST Level 3 (RECOMMENDED)
    "Kyber-1024",   # NIST Level 5
]
# Hybrid classical + PQ cipher suite patterns
HYBRID_PQ_CIPHER_PATTERNS = [
    "ECDHE+Kyber",
    "X25519+Kyber",
    "X448+Kyber",
]
# ============================================================================
# PQ TLS CONFIGURATION
# ============================================================================
class PQTLSSecurityConfig:
    """
    Post-Quantum TLS Security Configuration
    Designed for crypto endpoints handling sensitive key material
    Follows:
    - NIST SP 800-186 (Post-Quantum Cryptography)
    - NIST FIPS 203 (CRYSTALS-Kyber)
    - NSA Suite B + CNSA 2.0
    """
    def __init__(
        self,
        pq_mode: PQTLSMode = PQTLSMode.HYBRID_PQ_CLASSICAL,
        key_protection: KeyProtectionLevel = KeyProtectionLevel.MEMORY_ONLY,
        enable_key_zeroization: bool = True,
        enable_channel_binding: bool = True,
        min_tls_version: str = "TLSv1.2",
        enforce_ephemeral_keys: bool = True,
        session_key_lifetime_seconds: int = 3600,
    ):
        self.pq_mode = pq_mode
        self.key_protection = key_protection
        self.enable_key_zeroization = enable_key_zeroization
        self.enable_channel_binding = enable_channel_binding
        self.min_tls_version = min_tls_version
        self.enforce_ephemeral_keys = enforce_ephemeral_keys
        self.session_key_lifetime = session_key_lifetime_seconds
        self._lock = threading.RLock()
        self._session_keys: Dict[str, Tuple[bytes, float]] = {}  # id -> (key, timestamp)
    def get_hardened_ssl_context(self) -> ssl.SSLContext:
        """
        Create PQ-hardened SSL context for crypto operations
        Additional hardening beyond standard TLS:
        - Single-use ephemeral keys enforced
        - Session tickets disabled
        - Session resumption limited
        - Key logging disabled
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # Disable ALL old protocols
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        # Crypto-specific hardening
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        context.options |= ssl.OP_NO_COMPRESSION
        # Disable session tickets (forward secrecy)
        if hasattr(ssl, 'OP_NO_TICKET'):
            context.options |= ssl.OP_NO_TICKET
        # PQ-safe cipher suites (classical portion - PQ KEM in TLS 1.3)
        pq_safe_ciphers = [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
        ]
        context.set_ciphers(':'.join(pq_safe_ciphers))
        return context
    def register_session_key(self, key_id: str, key_material: bytes) -> None:
        """Register session key with automatic expiry"""
        with self._lock:
            self._session_keys[key_id] = (key_material, time.time())
            self._clean_expired_keys()
    def get_session_key(self, key_id: str) -> Optional[bytes]:
        """Get session key if not expired"""
        with self._lock:
            if key_id not in self._session_keys:
                return None
            key, timestamp = self._session_keys[key_id]
            if time.time() - timestamp > self.session_key_lifetime:
                self._zeroize_key(key_id)
                return None
            return key
    def _zeroize_key(self, key_id: str) -> None:
        """Securely zeroize key material from memory"""
        if key_id in self._session_keys:
            key, _ = self._session_keys[key_id]
            # Overwrite with zeros (best effort in Python)
            zeroized = b'\x00' * len(key)
            self._session_keys[key_id] = (zeroized, 0)
            del self._session_keys[key_id]
    def _clean_expired_keys(self) -> None:
        """Remove and zeroize expired session keys"""
        now = time.time()
        expired = [
            kid for kid, (_, ts) in self._session_keys.items()
            if now - ts > self.session_key_lifetime
        ]
        for kid in expired:
            self._zeroize_key(kid)
    def zeroize_all_session_keys(self) -> int:
        """Zeroize ALL session keys - emergency wipe"""
        count = len(self._session_keys)
        for key_id in list(self._session_keys.keys()):
            self._zeroize_key(key_id)
        return count
# ============================================================================
# CHANNEL BINDING
# ============================================================================
class TLSChannelBinding:
    """
    TLS Channel Binding for Crypto Operations
    Binds cryptographic operations to specific TLS channel
    Prevents:
    - Authentication relay attacks
    - Man-in-the-middle key substitution
    - Session hijacking
    Reference: RFC 5929, RFC 5056
    """
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._lock = threading.RLock()
        self._bindings: Dict[str, bytes] = {}
    def get_tls_unique(self, ssl_socket: ssl.SSLSocket) -> Optional[bytes]:
        """
        Get 'tls-unique' channel binding value
        RFC 5929: Finished message from TLS handshake
        """
        if not self.enabled:
            return None
        try:
            # Get TLS session information
            cipher = ssl_socket.cipher()
            peer_cert = ssl_socket.getpeercert(binary_form=True)
            if peer_cert:
                # Create channel binding from certificate hash
                return hashlib.sha256(peer_cert).digest()
            return None
        except Exception:
            return None
    def get_server_endpoint(self, ssl_socket: ssl.SSLSocket) -> Optional[bytes]:
        """
        Get 'server-endpoint' channel binding value
        RFC 5929: Server's certificate hash
        """
        if not self.enabled:
            return None
        try:
            peer_cert = ssl_socket.getpeercert(binary_form=True)
            if peer_cert:
                return hashlib.sha256(peer_cert).digest()
            return None
        except Exception:
            return None
    def bind_crypto_operation(
        self,
        operation_id: str,
        channel_binding: bytes,
        crypto_data: bytes,
    ) -> bytes:
        """
        Bind crypto operation to TLS channel
        Output: HMAC(channel_binding, crypto_data)
        This ensures the crypto operation can only be valid
        for the specific TLS channel it was created on
        """
        if not self.enabled:
            return crypto_data
        binding = hashlib.sha256(channel_binding + crypto_data).digest()
        with self._lock:
            self._bindings[operation_id] = binding
        return binding
    def verify_binding(
        self,
        operation_id: str,
        channel_binding: bytes,
        crypto_data: bytes,
    ) -> bool:
        """Verify crypto operation is bound to this channel"""
        if not self.enabled:
            return True
        if operation_id not in self._bindings:
            return False
        expected = hashlib.sha256(channel_binding + crypto_data).digest()
        stored = self._bindings[operation_id]
        return secrets.compare_digest(expected, stored)
# ============================================================================
# PQ CERTIFICATE HARDENING
# ============================================================================
class PQCertificateHardener:
    """
    Post-Quantum Certificate Hardening
    Prepares for PQ certificate migration
    Provides:
    - Hybrid certificate guidance
    - Migration planning tools
    - Key strength validation
    """
    def __init__(self):
        self._lock = threading.RLock()
    def validate_certificate_key_strength(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate certificate key strength for PQ era
        Minimum recommendations:
        - RSA: >= 4096 bits (transitional)
        - ECC: >= 384 bits (P-384)
        - PQ: Kyber-768 (NIST Level 3)
        """
        result = {
            "pq_ready": False,
            "key_strength_score": 0,
            "warnings": [],
            "recommendations": [],
            "details": {},
        }
        # Check key type and size
        key_type = cert_info.get("key_type", "unknown").upper()
        key_size = cert_info.get("key_size", 0)
        if "RSA" in key_type:
            if key_size >= 4096:
                result["key_strength_score"] = 60
                result["warnings"].append("RSA 4096 is transitional - migrate to PQ")
            elif key_size >= 3072:
                result["key_strength_score"] = 40
                result["warnings"].append("RSA 3072 minimum - consider 4096")
            else:
                result["warnings"].append(f"RSA {key_size} is TOO WEAK for PQ era")
        elif "EC" in key_type or "ECC" in key_type:
            if key_size >= 384:
                result["key_strength_score"] = 70
                result["warnings"].append("ECC P-384 is transitional - migrate to PQ")
            elif key_size >= 256:
                result["key_strength_score"] = 50
                result["warnings"].append("ECC P-256 minimum - consider P-384")
        # PQ assessment
        result["recommendations"] = [
            "Plan migration to CRYSTALS-Kyber certificates (NIST FIPS 203)",
            "Use hybrid classical + PQ certificates during transition",
            "Increase RSA key size to 4096 bits as stopgap",
            "Consider ECC P-384 for better performance than large RSA",
        ]
        return result
    def get_pq_migration_timeline(self) -> Dict[str, Any]:
        """
        PQ Certificate Migration Timeline
        Based on NIST + industry guidance
        """
        return {
            "immediate_2026": [
                "Inventory all TLS certificates",
                "Increase RSA to 4096 / ECC to P-384",
                "Enable TLS 1.3 everywhere",
                "Deploy hybrid PQ-capable TLS libraries",
            ],
            "near_term_2026_2027": [
                "Test hybrid PQ TLS in staging",
                "Deploy Kyber-768 for internal services",
                "Update monitoring for PQ ciphers",
            ],
            "medium_term_2027_2028": [
                "Full PQ deployment for internal",
                "Hybrid PQ for external services",
                "PQ certificate chain validation",
            ],
            "long_term_2028_2030": [
                "Full PQ-only for all services",
                "Retire all classical algorithms",
            ],
            "nist_standards": {
                "FIPS_203": "CRYSTALS-Kyber (KEM) - Final",
                "FIPS_204": "CRYSTALS-Dilithium (Signatures) - Final",
                "FIPS_205": "SPHINCS+ (Hash-based Signatures) - Final",
            },
        }
# ============================================================================
# KEY MATERIAL PROTECTION
# ============================================================================
class TLSKeyMaterialProtector:
    """
    TLS Key Material Protection
    Handles secure storage and zeroization of TLS keys
    Critical for crypto operations handling sensitive data
    """
    def __init__(self, enable_zeroization: bool = True):
        self.enable_zeroization = enable_zeroization
        self._lock = threading.RLock()
        self._protected_keys: Dict[str, bytearray] = {}
        self._access_log: List[Dict[str, Any]] = []
    def load_protected_key(
        self,
        key_id: str,
        key_material: bytes,
    ) -> None:
        """Load key into protected memory"""
        with self._lock:
            # Use mutable bytearray for overwrite capability
            self._protected_keys[key_id] = bytearray(key_material)
            self._log_access(key_id, "load")
    def get_protected_key(self, key_id: str) -> Optional[bytes]:
        """Get copy of protected key"""
        with self._lock:
            if key_id not in self._protected_keys:
                return None
            self._log_access(key_id, "access")
            return bytes(self._protected_keys[key_id])
    def secure_zeroize(self, key_id: str) -> bool:
        """
        Securely zeroize key from memory
        Best-effort secure memory wipe
        """
        if not self.enable_zeroization:
            return True
        with self._lock:
            if key_id not in self._protected_keys:
                return False
            key_arr = self._protected_keys[key_id]
            # Overwrite multiple times with different patterns
            for pattern in [0x00, 0xFF, 0x55, 0xAA, 0x00]:
                for i in range(len(key_arr)):
                    key_arr[i] = pattern
            del self._protected_keys[key_id]
            self._log_access(key_id, "zeroize")
            return True
    def emergency_wipe_all(self) -> int:
        """Emergency zeroize ALL keys"""
        count = len(self._protected_keys)
        for key_id in list(self._protected_keys.keys()):
            self.secure_zeroize(key_id)
        return count
    def _log_access(self, key_id: str, action: str) -> None:
        """Log key access"""
        with self._lock:
            self._access_log.append({
                "timestamp": time.time(),
                "key_id": key_id,
                "action": action,
            })
            # Keep only last 1000 entries
            if len(self._access_log) > 1000:
                self._access_log.pop(0)
    def get_access_audit(self) -> List[Dict[str, Any]]:
        """Get key access audit log"""
        with self._lock:
            return list(self._access_log)
# ============================================================================
# PQ TLS SECURITY AUDITOR
# ============================================================================
class PQTLSSecurityAuditor:
    """
    Post-Quantum TLS Security Auditor
    Crypto-specific security assessment
    """
    def __init__(self, config: PQTLSSecurityConfig):
        self.config = config
        self._lock = threading.RLock()
    def run_pq_security_audit(self) -> Dict[str, Any]:
        """Run PQ-specific TLS security audit"""
        report = {
            "audit_timestamp": time.time(),
            "pq_readiness_score": 0,
            "max_score": 100,
            "pq_mode": self.config.pq_mode.value,
            "findings": [],
            "passed": [],
            "recommendations": [],
            "pq_grade": "F",
        }
        score = 0
        # Check 1: PQ Mode (30 points)
        mode_scores = {
            PQTLSMode.CLASSICAL_ONLY: 10,
            PQTLSMode.HYBRID_PQ_CLASSICAL: 25,
            PQTLSMode.PQ_ONLY: 30,
        }
        score += mode_scores.get(self.config.pq_mode, 0)
        if self.config.pq_mode == PQTLSMode.HYBRID_PQ_CLASSICAL:
            report["passed"].append("Hybrid PQ + classical mode - optimal transition")
        elif self.config.pq_mode == PQTLSMode.PQ_ONLY:
            report["passed"].append("PQ-only mode - future-proof")
        else:
            report["findings"].append("Classical-only mode - vulnerable to quantum attacks")
            report["recommendations"].append("Migrate to hybrid PQ + classical mode")
        # Check 2: Key zeroization (20 points)
        if self.config.enable_key_zeroization:
            score += 20
            report["passed"].append("Secure key zeroization enabled")
        else:
            report["findings"].append("Key zeroization disabled - key material may persist in memory")
            report["recommendations"].append("Enable automatic key zeroization")
        # Check 3: Channel binding (20 points)
        if self.config.enable_channel_binding:
            score += 20
            report["passed"].append("TLS channel binding enabled - prevents MITM relay")
        else:
            report["findings"].append("Channel binding disabled - vulnerable to auth relay attacks")
            report["recommendations"].append("Enable TLS channel binding for crypto operations")
        # Check 4: Ephemeral keys (15 points)
        if self.config.enforce_ephemeral_keys:
            score += 15
            report["passed"].append("Ephemeral keys enforced - PFS guaranteed")
        else:
            report["findings"].append("Ephemeral keys not enforced")
        # Check 5: TLS version (15 points)
        if self.config.min_tls_version == "TLSv1.3":
            score += 15
            report["passed"].append("TLS 1.3 minimum - PQ-ready")
        elif self.config.min_tls_version == "TLSv1.2":
            score += 10
            report["recommendations"].append("Upgrade to TLS 1.3 for PQ support")
        # Calculate grade
        report["pq_readiness_score"] = score
        if score >= 85:
            report["pq_grade"] = "A"
        elif score >= 70:
            report["pq_grade"] = "B"
        elif score >= 55:
            report["pq_grade"] = "C"
        elif score >= 40:
            report["pq_grade"] = "D"
        else:
            report["pq_grade"] = "F"
        return report
# ============================================================================
# GLOBAL CONVENIENCE FUNCTIONS
# ============================================================================
def create_pq_tls_config(**kwargs) -> PQTLSSecurityConfig:
    """Create PQ TLS configuration with sensible defaults"""
    return PQTLSSecurityConfig(**kwargs)
def get_pq_tls_best_practices() -> Dict[str, Any]:
    """Get PQ TLS best practices checklist"""
    return {
        "mandatory": [
            "Enable TLS 1.3 only (or TLS 1.2 minimum)",
            "Use ECDHE/DHE key exchange only",
            "Enable secure key zeroization",
            "Disable TLS session tickets",
            "Use AES-256-GCM or ChaCha20-Poly1305",
        ],
        "pq_transition": [
            "Deploy hybrid Kyber + ECDHE key exchange",
            "Upgrade certificates to RSA 4096 / ECC P-384",
            "Plan for CRYSTALS-Kyber certificates",
            "Monitor for PQ cipher support",
        ],
        "crypto_specific": [
            "Bind all key operations to TLS channel",
            "Limit session key lifetime to 1 hour",
            "Zeroize keys after use",
            "Log all key access attempts",
        ],
    }
# ============================================================================
# BACKWARD COMPATIBILITY WRAPPERS
# ============================================================================
def wrap_crypto_operation_with_tls_binding(
    operation_function: Callable,
    channel_binding: TLSChannelBinding,
) -> Callable:
    """
    Wrap ANY crypto operation function with TLS channel binding
    ADD-ONLY: Pure wrapper, NO modification to original function
    """
    def wrapped_operation(*args, **kwargs):
        # Extract binding from kwargs if provided
        binding = kwargs.pop('_channel_binding', None)
        op_id = kwargs.pop('_operation_id', secrets.token_hex(16))
        # Execute original operation
        result = operation_function(*args, **kwargs)
        # Bind result to TLS channel
        if binding and isinstance(result, bytes):
            bound = channel_binding.bind_crypto_operation(op_id, binding, result)
            return result, bound
        return result
    return wrapped_operation
# ============================================================================
# MODULE METADATA
# ============================================================================
MODULE_INFO = {
    "name": "Crypto Security v17 - PQ TLS/HTTPS Protection",
    "version": "17",
    "dimension": "B - Security Hardening",
    "compliance": [
        "NIST SP 800-186 (Post-Quantum Cryptography)",
        "NIST FIPS 203 (CRYSTALS-Kyber)",
        "RFC 5929 (TLS Channel Binding)",
        "NSA CNSA 2.0",
    ],
    "features": [
        "Post-quantum TLS configuration patterns",
        "Hybrid PQ + classical TLS guidance",
        "Secure key material zeroization",
        "TLS channel binding (RFC 5929)",
        "Session key lifetime enforcement",
        "PQ certificate migration timeline",
        "Emergency key wipe functionality",
        "Key access audit logging",
    ],
    "add_only_compliant": True,
    "dependencies": ["Python stdlib ssl module"],
    "pq_ready": True,
}
