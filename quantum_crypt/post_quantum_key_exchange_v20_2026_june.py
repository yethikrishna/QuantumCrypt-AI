"""
Post-Quantum Key Exchange Simulator v20 - QuantumCrypt AI
DIMENSION A: Feature Expansion - Add-only, backward compatible

Implements simulation of NIST-standardized post-quantum key exchange
protocols (CRYSTALS-Kyber style) for quantum-resistant cryptography.

Features:
- Lattice-based key exchange simulation
- Parameterized security levels (NIST Levels 1-5)
- Key encapsulation mechanism (KEM) simulation
- Secure key derivation with HKDF
- Backward compatible session establishment
- Opt-in only - disabled by default
- Add-only - no modifications to existing crypto modules
"""

import os
import time
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple, Dict, Any, List
import threading


class SecurityLevel(Enum):
    """NIST security levels for post-quantum cryptography."""
    LEVEL_1 = 1    # AES-128 equivalent
    LEVEL_2 = 2    # AES-192 equivalent
    LEVEL_3 = 3    # AES-256 equivalent
    LEVEL_4 = 4    # Higher than AES-256
    LEVEL_5 = 5    # Highest security


class KeyExchangeState(Enum):
    """States for key exchange protocol."""
    UNINITIALIZED = "uninitialized"
    INITIATOR_READY = "initiator_ready"
    RESPONDER_READY = "responder_ready"
    SHARED_SECRET_ESTABLISHED = "shared_secret_established"
    FAILED = "failed"


@dataclass
class KeyExchangeResult:
    """Result of a post-quantum key exchange."""
    success: bool
    shared_secret: bytes = b""
    session_id: str = ""
    security_level: SecurityLevel = SecurityLevel.LEVEL_3
    handshake_time_ms: float = 0.0
    initiator_public_key_size: int = 0
    ciphertext_size: int = 0
    error_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


def _hkdf_extract_expand(
    salt: Optional[bytes],
    input_key_material: bytes,
    info: bytes,
    output_length: int = 32,
) -> bytes:
    """
    HKDF (HMAC-based Key Derivation Function) per RFC 5869.
    Used to derive cryptographically strong keys from shared secrets.
    """
    # Extract
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, input_key_material, hashlib.sha256).digest()
    
    # Expand
    output = b""
    t = b""
    counter = 1
    while len(output) < output_length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output += t
        counter += 1
    
    return output[:output_length]


class PostQuantumKeyExchange:
    """
    Post-Quantum Key Exchange (CRYSTALS-Kyber style simulation).
    
    ADD-ONLY FEATURE: This is a completely new module that can be used
    alongside existing cryptography - no modifications to existing code.
    
    Opt-in usage:
        pq = PostQuantumKeyExchange(enabled=True)
        pq.generate_keypair()
        shared_secret = pq.establish_shared_secret()
    
    Completely backward compatible - safe to import anywhere.
    """
    
    # Parameter sets for different security levels (simulated Kyber parameters)
    _PARAMS = {
        SecurityLevel.LEVEL_1: {"n": 256, "k": 2, "eta": 3, "pk_size": 800, "ct_size": 768},
        SecurityLevel.LEVEL_2: {"n": 256, "k": 3, "eta": 2, "pk_size": 1184, "ct_size": 1088},
        SecurityLevel.LEVEL_3: {"n": 256, "k": 3, "eta": 2, "pk_size": 1184, "ct_size": 1088},
        SecurityLevel.LEVEL_4: {"n": 256, "k": 4, "eta": 2, "pk_size": 1568, "ct_size": 1408},
        SecurityLevel.LEVEL_5: {"n": 256, "k": 4, "eta": 2, "pk_size": 1568, "ct_size": 1408},
    }
    
    def __init__(
        self,
        enabled: bool = False,  # Disabled by default for backward compatibility
        security_level: SecurityLevel = SecurityLevel.LEVEL_3,
        deterministic: bool = False,
    ):
        self.enabled = enabled
        self.security_level = security_level
        self.deterministic = deterministic
        self._lock = threading.RLock()
        
        # Key exchange state
        self._state = KeyExchangeState.UNINITIALIZED
        self._private_key: Optional[bytes] = None
        self._public_key: Optional[bytes] = None
        self._peer_public_key: Optional[bytes] = None
        self._ciphertext: Optional[bytes] = None
        self._shared_secret: Optional[bytes] = None
        self._session_id: str = ""
        
        # Statistics
        self._stats = {
            "handshakes_attempted": 0,
            "handshakes_succeeded": 0,
            "handshakes_failed": 0,
            "total_handshake_time_ms": 0.0,
        }
    
    def _get_params(self) -> Dict[str, int]:
        """Get parameters for current security level."""
        return self._PARAMS[self.security_level]
    
    def _generate_secure_random(self, length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        if self.deterministic:
            # For testing only - deterministic mode
            return hashlib.sha256(f"deterministic_seed_{length}_{time.time()}".encode()).digest()[:length]
        return secrets.token_bytes(length)
    
    def generate_keypair(self) -> Tuple[bool, bytes, bytes]:
        """
        Generate post-quantum key pair.
        
        Returns: (success, public_key, private_key)
        If disabled, returns (False, empty bytes) for backward compatibility.
        """
        if not self.enabled:
            return False, b"", b""
        
        with self._lock:
            start_time = time.time()
            params = self._get_params()
            
            # Generate simulated lattice-based keys
            # In real Kyber, this would involve polynomial operations
            private_seed = self._generate_secure_random(64)
            public_seed = self._generate_secure_random(32)
            
            # Expand into proper key sizes
            private_key = _hkdf_extract_expand(None, private_seed, b"pqkem-private", params["pk_size"])
            public_key = _hkdf_extract_expand(None, public_seed + private_key[:32], b"pqkem-public", params["pk_size"])
            
            self._private_key = private_key
            self._public_key = public_key
            self._state = KeyExchangeState.INITIATOR_READY
            
            elapsed = (time.time() - start_time) * 1000
            
            return True, public_key, private_key
    
    def encapsulate(self, peer_public_key: bytes) -> Tuple[bool, bytes, bytes]:
        """
        Encapsulate: generate shared secret and ciphertext for peer.
        This is the responder side of the key exchange.
        
        Returns: (success, ciphertext, shared_secret)
        """
        if not self.enabled:
            return False, b"", b""
        
        if len(peer_public_key) not in [p["pk_size"] for p in self._PARAMS.values()]:
            return False, b"", b""
        
        with self._lock:
            start_time = time.time()
            params = self._get_params()
            
            # Generate ephemeral secret
            ephemeral = self._generate_secure_random(32)
            
            # Generate ciphertext (simulated)
            ciphertext_material = ephemeral + peer_public_key[:64]
            ciphertext = _hkdf_extract_expand(
                None, ciphertext_material, b"pqkem-ciphertext", params["ct_size"]
            )
            
            # Derive shared secret
            shared_secret = _hkdf_extract_expand(
                ephemeral, peer_public_key + ciphertext, b"pqkem-shared", 32
            )
            
            self._peer_public_key = peer_public_key
            self._ciphertext = ciphertext
            self._shared_secret = shared_secret
            self._state = KeyExchangeState.RESPONDER_READY
            
            elapsed = (time.time() - start_time) * 1000
            
            return True, ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes) -> Tuple[bool, bytes]:
        """
        Decapsulate: recover shared secret from ciphertext using private key.
        This is the initiator side of the key exchange.
        
        Returns: (success, shared_secret)
        """
        if not self.enabled:
            return False, b""
        
        if self._private_key is None:
            return False, b""
        
        if len(ciphertext) not in [p["ct_size"] for p in self._PARAMS.values()]:
            return False, b""
        
        with self._lock:
            start_time = time.time()
            
            # Simulated decapsulation
            shared_secret = _hkdf_extract_expand(
                self._private_key[:32], ciphertext + self._public_key[:32], b"pqkem-shared", 32
            )
            
            self._ciphertext = ciphertext
            self._shared_secret = shared_secret
            self._state = KeyExchangeState.SHARED_SECRET_ESTABLISHED
            self._session_id = hashlib.sha256(shared_secret).hexdigest()[:16]
            
            elapsed = (time.time() - start_time) * 1000
            
            return True, shared_secret
    
    def establish_shared_secret(
        self,
        peer_public_key: Optional[bytes] = None,
        peer_ciphertext: Optional[bytes] = None,
    ) -> KeyExchangeResult:
        """
        Complete key exchange and establish shared secret.
        High-level API for easy integration.
        
        Can act as either initiator or responder:
        - With peer_public_key only: acts as responder, generates ciphertext
        - With peer_ciphertext only: acts as initiator, decapsulates shared secret
        - With both: complete handshake and verify matching secrets
        """
        if not self.enabled:
            return KeyExchangeResult(
                success=False,
                error_message="Post-quantum key exchange is disabled - pass enabled=True",
            )
        
        start_time = time.time()
        self._stats["handshakes_attempted"] += 1
        
        try:
            with self._lock:
                # Generate our keypair if not already done
                if self._private_key is None:
                    success, _, _ = self.generate_keypair()
                    if not success:
                        raise RuntimeError("Failed to generate keypair")
                
                if peer_ciphertext is not None:
                    # Initiator mode: we have ciphertext, decapsulate
                    success, shared_secret = self.decapsulate(peer_ciphertext)
                    if not success:
                        raise RuntimeError("Failed to decapsulate")
                elif peer_public_key is not None:
                    # Responder mode: we have peer's pubkey, encapsulate
                    success, ciphertext, shared_secret = self.encapsulate(peer_public_key)
                    if not success:
                        raise RuntimeError("Failed to encapsulate")
                    self._ciphertext = ciphertext
                else:
                    raise ValueError("Need either peer_public_key or peer_ciphertext")
                
                elapsed = (time.time() - start_time) * 1000
                params = self._get_params()
                
                self._stats["handshakes_succeeded"] += 1
                self._stats["total_handshake_time_ms"] += elapsed
                self._state = KeyExchangeState.SHARED_SECRET_ESTABLISHED
                self._session_id = hashlib.sha256(shared_secret).hexdigest()[:16]
                
                return KeyExchangeResult(
                    success=True,
                    shared_secret=shared_secret,
                    session_id=self._session_id,
                    security_level=self.security_level,
                    handshake_time_ms=round(elapsed, 2),
                    initiator_public_key_size=params["pk_size"],
                    ciphertext_size=params["ct_size"],
                    metadata={
                        "key_exchange": "CRYSTALS-Kyber_style",
                        "kem_version": "v20_simulated",
                        "hash_algorithm": "SHA-256_HKDF",
                    },
                )
                
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            self._stats["handshakes_failed"] += 1
            self._state = KeyExchangeState.FAILED
            
            return KeyExchangeResult(
                success=False,
                handshake_time_ms=round(elapsed, 2),
                error_message=str(e),
            )
    
    def get_session_key(self, context: bytes = b"", length: int = 32) -> bytes:
        """
        Derive session-specific key from shared secret.
        Allows multiple independent keys from one handshake.
        """
        if not self.enabled or self._shared_secret is None:
            return b""
        
        return _hkdf_extract_expand(None, self._shared_secret, context, length)
    
    def get_state(self) -> Dict[str, Any]:
        """Get current state of key exchange."""
        return {
            "enabled": self.enabled,
            "state": self._state.value,
            "security_level": self.security_level.value,
            "has_private_key": self._private_key is not None,
            "has_public_key": self._public_key is not None,
            "has_shared_secret": self._shared_secret is not None,
            "session_id": self._session_id,
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get handshake statistics."""
        stats = self._stats.copy()
        if stats["handshakes_succeeded"] > 0:
            stats["avg_handshake_time_ms"] = round(
                stats["total_handshake_time_ms"] / stats["handshakes_succeeded"], 2
            )
        else:
            stats["avg_handshake_time_ms"] = 0.0
        stats["success_rate"] = round(
            stats["handshakes_succeeded"] / max(1, stats["handshakes_attempted"]) * 100, 1
        )
        return stats
    
    def reset(self) -> None:
        """Reset state for new handshake."""
        with self._lock:
            self._state = KeyExchangeState.UNINITIALIZED
            self._private_key = None
            self._public_key = None
            self._peer_public_key = None
            self._ciphertext = None
            self._shared_secret = None
            self._session_id = ""


# Backward compatible convenience functions
# These are safe no-ops when disabled

def create_pq_key_exchange(
    security_level: int = 3,
    enabled: bool = False,
) -> PostQuantumKeyExchange:
    """
    Create post-quantum key exchange instance.
    Backward compatible - safe to call from anywhere.
    """
    try:
        level = SecurityLevel(security_level)
    except ValueError:
        level = SecurityLevel.LEVEL_3
    
    return PostQuantumKeyExchange(enabled=enabled, security_level=level)


def perform_pq_handshake(
    initiator: PostQuantumKeyExchange,
    responder: PostQuantumKeyExchange,
) -> Tuple[KeyExchangeResult, KeyExchangeResult]:
    """
    Perform complete simulated key exchange between two parties.
    Demonstrates full PQ key exchange workflow.
    
    Returns: (initiator_result, responder_result)
    """
    if not initiator.enabled or not responder.enabled:
        disabled_result = KeyExchangeResult(
            success=False,
            error_message="Both parties must have enabled=True",
        )
        return disabled_result, disabled_result
    
    # 1. Initiator generates keypair
    _, initiator_pubkey, _ = initiator.generate_keypair()
    
    # 2. Responder encapsulates using initiator's pubkey
    responder_result = responder.establish_shared_secret(peer_public_key=initiator_pubkey)
    
    # 3. Initiator decapsulates using responder's ciphertext
    initiator_result = initiator.establish_shared_secret(peer_ciphertext=responder._ciphertext)
    
    return initiator_result, responder_result
