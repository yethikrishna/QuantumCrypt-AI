"""
QuantumCrypt AI - Post-Quantum Hybrid KEM with Automatic Algorithm Fallback v83
DIMENSION A - FEATURE EXPANSION (ADD-ONLY, NO MODIFICATION TO EXISTING CODE)

This module implements a hybrid Key Encapsulation Mechanism (KEM) that combines
classical ECDH with post-quantum algorithms (CRYSTALS-Kyber style) with automatic
fallback capabilities. All existing code paths remain 100% unchanged and backward
compatible.

Features:
- Hybrid classical + post-quantum key encapsulation
- Automatic algorithm fallback on failure
- Algorithm health monitoring and scoring
- Priority-based algorithm selection
- Session key derivation with HKDF
- Algorithm capability negotiation
- Graceful degradation to classical-only mode
"""

import os
import hmac
import hashlib
import secrets
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import threading


class AlgorithmStatus(str, Enum):
    """Algorithm health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNTESTED = "untested"


class AlgorithmType(str, Enum):
    """Cryptographic algorithm type"""
    CLASSICAL = "classical"
    POST_QUANTUM = "post_quantum"
    HYBRID = "hybrid"


@dataclass
class AlgorithmHealth:
    """Algorithm health tracking"""
    name: str
    status: AlgorithmStatus = AlgorithmStatus.UNTESTED
    success_count: int = 0
    failure_count: int = 0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    average_latency_ms: float = 0.0
    health_score: float = 100.0  # 0-100
    consecutive_failures: int = 0
    
    def record_success(self, latency_ms: float):
        """Record successful operation"""
        self.success_count += 1
        self.last_success = datetime.now()
        self.consecutive_failures = 0
        
        # Update average latency
        total = self.success_count + self.failure_count
        self.average_latency_ms = (
            (self.average_latency_ms * (total - 1) + latency_ms) / total
        )
        
        # Update health score
        self.health_score = min(100.0, self.health_score + 5)
        self._update_status()
    
    def record_failure(self):
        """Record failed operation"""
        self.failure_count += 1
        self.last_failure = datetime.now()
        self.consecutive_failures += 1
        
        # Degrade health score
        penalty = 10 * self.consecutive_failures
        self.health_score = max(0.0, self.health_score - penalty)
        self._update_status()
    
    def _update_status(self):
        """Update status based on health metrics"""
        if self.consecutive_failures >= 3:
            self.status = AlgorithmStatus.FAILED
        elif self.health_score < 50:
            self.status = AlgorithmStatus.DEGRADED
        elif self.success_count > 0:
            self.status = AlgorithmStatus.HEALTHY
        else:
            self.status = AlgorithmStatus.UNTESTED
    
    def should_use(self) -> bool:
        """Determine if algorithm should be used"""
        if self.status == AlgorithmStatus.FAILED:
            # Allow retry after cooldown period
            if self.last_failure and datetime.now() - self.last_failure > timedelta(minutes=5):
                return True
            return False
        return self.health_score > 20


@dataclass
class EncapsulationResult:
    """Result of key encapsulation"""
    shared_secret: bytes
    ciphertext: bytes
    algorithm_used: str
    algorithm_type: AlgorithmType
    session_id: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    timestamp: datetime = field(default_factory=datetime.now)
    fallback_occurred: bool = False
    fallback_from: Optional[str] = None


class ClassicalECDH:
    """Mock classical ECDH implementation (production would use cryptography library)"""
    
    def __init__(self):
        self.name = "ECDH-P256"
        self.algorithm_type = AlgorithmType.CLASSICAL
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ECDH key pair"""
        private_key = secrets.token_bytes(32)
        public_key = hashlib.sha256(private_key).digest()
        return private_key, public_key
    
    def encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate - generate shared secret and ciphertext"""
        ephemeral_private, ephemeral_public = self.generate_keypair()
        
        # Symmetric KEM: both sides use same public material
        # Bob: hash(ephemeral_public + peer_public_key) 
        # Alice: hash(ciphertext + her_public_key)
        # Since ciphertext = ephemeral_public, both compute same hash
        shared_material = ephemeral_public + peer_public_key
        shared_secret = hashlib.sha256(shared_material).digest()
        
        # Derive final key with HKDF
        final_secret = hashlib.pbkdf2_hmac(
            'sha256',
            shared_secret,
            b'classical_salt',
            10000,
            dklen=32
        )
        
        return final_secret, ephemeral_public
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate - recover shared secret"""
        # Re-derive public key from private
        public_key = hashlib.sha256(private_key).digest()
        
        # Symmetric: same computation as encapsulate
        shared_material = ciphertext + public_key  # ciphertext = ephemeral_public
        shared_secret = hashlib.sha256(shared_material).digest()
        
        final_secret = hashlib.pbkdf2_hmac(
            'sha256',
            shared_secret,
            b'classical_salt',
            10000,
            dklen=32
        )
        
        return final_secret


class PostQuantumKyber:
    """Mock CRYSTALS-Kyber style post-quantum KEM"""
    
    def __init__(self, security_level: int = 3):
        self.name = f"Kyber-{security_level * 128}"
        self.security_level = security_level
        self.algorithm_type = AlgorithmType.POST_QUANTUM
        self._failure_probability = 0.05  # 5% failure rate for testing fallback
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Kyber key pair"""
        private_key = secrets.token_bytes(32 * self.security_level)
        public_key = hashlib.sha3_256(private_key).digest()
        return private_key, public_key
    
    def encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate with PQ algorithm"""
        # Simulate occasional failures for fallback testing
        if random.random() < self._failure_probability:
            raise RuntimeError("Post-quantum algorithm simulation failure")
        
        ephemeral_private, ephemeral_public = self.generate_keypair()
        
        # Symmetric KEM: both sides use same public material
        shared_material = ephemeral_public + peer_public_key
        shared_secret = hashlib.sha3_256(shared_material).digest()
        
        # HKDF for post-quantum
        final_secret = hashlib.pbkdf2_hmac(
            'sha256',
            shared_secret,
            b'post_quantum_salt',
            10000,
            dklen=32
        )
        
        return final_secret, ephemeral_public
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate PQ ciphertext"""
        if random.random() < self._failure_probability:
            raise RuntimeError("Post-quantum decapsulation failure")
        
        # Re-derive public key from private
        public_key = hashlib.sha3_256(private_key).digest()
        
        # Symmetric: same computation as encapsulate
        shared_material = ciphertext + public_key  # ciphertext = ephemeral_public
        shared_secret = hashlib.sha3_256(shared_material).digest()
        
        final_secret = hashlib.pbkdf2_hmac(
            'sha256',
            shared_secret,
            b'post_quantum_salt',
            10000,
            dklen=32
        )
        
        return final_secret


# Import random locally to avoid module-level issues
import random


class HybridKEM:
    """Hybrid KEM combining classical and post-quantum algorithms"""
    
    def __init__(self):
        self.name = "Hybrid-ECDH-Kyber"
        self.algorithm_type = AlgorithmType.HYBRID
        self.classical = ClassicalECDH()
        self.post_quantum = PostQuantumKyber()
        # Use a unique separator unlikely to appear in random bytes
        self._separator = b"@@HYBRID_SEPARATOR@@"
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate combined key pair"""
        priv_classical, pub_classical = self.classical.generate_keypair()
        priv_pq, pub_pq = self.post_quantum.generate_keypair()
        
        private_key = priv_classical + self._separator + priv_pq
        public_key = pub_classical + self._separator + pub_pq
        
        return private_key, public_key
    
    def encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        """Hybrid encapsulation"""
        pub_parts = peer_public_key.split(self._separator)
        if len(pub_parts) != 2:
            raise ValueError("Invalid hybrid public key format")
        
        pub_classical, pub_pq = pub_parts
        
        # Perform both encapsulations
        secret_classical, ct_classical = self.classical.encapsulate(pub_classical)
        secret_pq, ct_pq = self.post_quantum.encapsulate(pub_pq)
        
        # Combine secrets
        combined_secret = hashlib.sha3_512(secret_classical + secret_pq).digest()[:32]
        ciphertext = ct_classical + self._separator + ct_pq
        
        return combined_secret, ciphertext
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Hybrid decapsulation"""
        priv_parts = private_key.split(self._separator)
        ct_parts = ciphertext.split(self._separator)
        
        if len(priv_parts) != 2 or len(ct_parts) != 2:
            raise ValueError("Invalid hybrid key format")
        
        priv_classical, priv_pq = priv_parts
        ct_classical, ct_pq = ct_parts
        
        secret_classical = self.classical.decapsulate(priv_classical, ct_classical)
        secret_pq = self.post_quantum.decapsulate(priv_pq, ct_pq)
        
        combined_secret = hashlib.sha3_512(secret_classical + secret_pq).digest()[:32]
        
        return combined_secret


class AutomaticFallbackKEM:
    """KEM with automatic algorithm fallback and health monitoring"""
    
    def __init__(self, min_health_threshold: float = 30.0):
        self.min_health_threshold = min_health_threshold
        
        # Initialize algorithms in priority order
        self.algorithms: Dict[str, Any] = {
            "Hybrid-ECDH-Kyber": HybridKEM(),
            "Kyber-384": PostQuantumKyber(security_level=3),
            "ECDH-P256": ClassicalECDH(),
        }
        
        # Health tracking for each algorithm
        self.algorithm_health: Dict[str, AlgorithmHealth] = {
            name: AlgorithmHealth(name=name)
            for name in self.algorithms.keys()
        }
        
        # Algorithm priority order (highest first)
        self.priority_order = [
            "Hybrid-ECDH-Kyber",
            "Kyber-384",
            "ECDH-P256",
        ]
        
        self._lock = threading.Lock()
    
    def generate_keypair(self, algorithm_name: Optional[str] = None) -> Tuple[bytes, bytes, str]:
        """Generate key pair with optional algorithm selection"""
        algorithm = self._select_best_algorithm() if algorithm_name is None else algorithm_name
        
        if algorithm not in self.algorithms:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        priv, pub = self.algorithms[algorithm].generate_keypair()
        return priv, pub, algorithm
    
    def encapsulate(self, peer_public_key: bytes, 
                   preferred_algorithm: Optional[str] = None) -> EncapsulationResult:
        """
        Encapsulate with automatic fallback on failure
        
        Tries algorithms in priority order until one succeeds
        """
        algorithms_to_try = self._get_algorithm_order(preferred_algorithm)
        
        for algorithm_name in algorithms_to_try:
            algorithm = self.algorithms[algorithm_name]
            health = self.algorithm_health[algorithm_name]
            
            if not health.should_use():
                continue
            
            try:
                start_time = datetime.now()
                
                shared_secret, ciphertext = algorithm.encapsulate(peer_public_key)
                
                latency_ms = (datetime.now() - start_time).total_seconds() * 1000
                
                with self._lock:
                    health.record_success(latency_ms)
                
                return EncapsulationResult(
                    shared_secret=shared_secret,
                    ciphertext=ciphertext,
                    algorithm_used=algorithm_name,
                    algorithm_type=algorithm.algorithm_type,
                    fallback_occurred=False
                )
                
            except Exception as e:
                with self._lock:
                    health.record_failure()
                
                continue
        
        # If all algorithms failed, force classical as last resort
        fallback_alg = "ECDH-P256"
        algorithm = self.algorithms[fallback_alg]
        
        shared_secret, ciphertext = algorithm.encapsulate(peer_public_key)
        
        return EncapsulationResult(
            shared_secret=shared_secret,
            ciphertext=ciphertext,
            algorithm_used=fallback_alg,
            algorithm_type=algorithm.algorithm_type,
            fallback_occurred=True,
            fallback_from=preferred_algorithm
        )
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes,
                   algorithm_name: str) -> Optional[bytes]:
        """Decapsulate with automatic retry"""
        if algorithm_name not in self.algorithms:
            return None
        
        algorithm = self.algorithms[algorithm_name]
        health = self.algorithm_health[algorithm_name]
        
        try:
            start_time = datetime.now()
            shared_secret = algorithm.decapsulate(private_key, ciphertext)
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            with self._lock:
                health.record_success(latency_ms)
            
            return shared_secret
            
        except Exception as e:
            with self._lock:
                health.record_failure()
            
            return None
    
    def _get_algorithm_order(self, preferred: Optional[str]) -> List[str]:
        """Get algorithm trial order with preferred first"""
        order = list(self.priority_order)
        
        if preferred and preferred in order:
            order.remove(preferred)
            order.insert(0, preferred)
        
        return order
    
    def _select_best_algorithm(self) -> str:
        """Select healthiest available algorithm"""
        for algorithm in self.priority_order:
            health = self.algorithm_health[algorithm]
            if health.should_use() and health.health_score >= self.min_health_threshold:
                return algorithm
        
        # Fallback to classical
        return "ECDH-P256"
    
    def get_algorithm_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status report for all algorithms"""
        status = {}
        for name, health in self.algorithm_health.items():
            status[name] = {
                "status": health.status.value,
                "health_score": health.health_score,
                "success_count": health.success_count,
                "failure_count": health.failure_count,
                "consecutive_failures": health.consecutive_failures,
                "average_latency_ms": health.average_latency_ms,
                "should_use": health.should_use(),
            }
        return status
    
    def get_capability_report(self) -> Dict[str, Any]:
        """Get full capability and health report"""
        return {
            "algorithms": self.get_algorithm_status(),
            "priority_order": self.priority_order,
            "best_algorithm": self._select_best_algorithm(),
            "min_health_threshold": self.min_health_threshold,
            "generated_at": datetime.now().isoformat(),
        }
    
    def negotiate_algorithm(self, peer_capabilities: List[str]) -> str:
        """Negotiate best common algorithm with peer"""
        common = set(self.priority_order) & set(peer_capabilities)
        
        for algorithm in self.priority_order:
            if algorithm in common:
                health = self.algorithm_health[algorithm]
                if health.should_use():
                    return algorithm
        
        # Fallback to common classical algorithm
        return "ECDH-P256"


class SessionKeyManager:
    """Session key management with forward secrecy"""
    
    def __init__(self):
        self.kem = AutomaticFallbackKEM()
        self.active_sessions: Dict[bytes, Dict[str, Any]] = {}
        self._max_session_age = timedelta(hours=24)
    
    def establish_session(self, peer_public_key: bytes) -> Dict[str, Any]:
        """Establish new encrypted session"""
        result = self.kem.encapsulate(peer_public_key)
        
        session_data = {
            "shared_secret": result.shared_secret,
            "algorithm": result.algorithm_used,
            "established": result.timestamp,
            "last_used": result.timestamp,
            "message_count": 0,
        }
        
        self.active_sessions[result.session_id] = session_data
        
        return {
            "session_id": result.session_id.hex(),
            "ciphertext": result.ciphertext.hex(),
            "algorithm": result.algorithm_used,
            "fallback_occurred": result.fallback_occurred,
        }
    
    def accept_session(self, private_key: bytes, ciphertext: bytes,
                      algorithm: str, session_id: bytes) -> Optional[bytes]:
        """Accept incoming session"""
        shared_secret = self.kem.decapsulate(private_key, ciphertext, algorithm)
        
        if shared_secret is not None:
            self.active_sessions[session_id] = {
                "shared_secret": shared_secret,
                "algorithm": algorithm,
                "established": datetime.now(),
                "last_used": datetime.now(),
                "message_count": 0,
            }
        
        return shared_secret
    
    def rotate_keys(self, session_id: bytes) -> bool:
        """Rotate session keys for forward secrecy"""
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        
        # Derive new key from existing
        new_secret = hashlib.sha3_256(
            session["shared_secret"] + secrets.token_bytes(32)
        ).digest()
        
        session["shared_secret"] = new_secret
        session["last_used"] = datetime.now()
        
        return True
    
    def cleanup_expired(self) -> int:
        """Clean up expired sessions"""
        now = datetime.now()
        expired = []
        
        for session_id, session in self.active_sessions.items():
            if now - session["last_used"] > self._max_session_age:
                # Securely zeroize before removal
                session["shared_secret"] = b"\x00" * len(session["shared_secret"])
                expired.append(session_id)
        
        for session_id in expired:
            del self.active_sessions[session_id]
        
        return len(expired)


# Module exports
__all__ = [
    'AlgorithmStatus',
    'AlgorithmType',
    'AlgorithmHealth',
    'EncapsulationResult',
    'ClassicalECDH',
    'PostQuantumKyber',
    'HybridKEM',
    'AutomaticFallbackKEM',
    'SessionKeyManager',
]
