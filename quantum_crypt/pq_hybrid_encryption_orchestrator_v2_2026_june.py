"""
Post-Quantum Hybrid Encryption Orchestrator v2
QuantumCrypt AI - Dimension A Feature Expansion v18

ADD-ONLY INCREMENTAL FEATURE - NO EXISTING CODE MODIFIED
Backward compatible - fully opt-in, no breaking changes

Capabilities:
- Automatic algorithm negotiation between peers
- Protocol versioning and backward compatibility handling
- Hybrid key exchange orchestration (classical + PQ)
- Threat-adaptive cipher suite selection
- Session key management with rotation policies
- Algorithm fallback and graceful degradation
"""

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict


class AlgorithmClass(Enum):
    """Categories of cryptographic algorithms"""
    CLASSICAL = "classical"
    POST_QUANTUM = "post_quantum"
    HYBRID = "hybrid"


class SecurityLevel(Enum):
    """NIST security levels"""
    LEVEL_1 = 1  # 128-bit security
    LEVEL_3 = 3  # 192-bit security
    LEVEL_5 = 5  # 256-bit security


class ProtocolState(Enum):
    """States of the negotiation protocol"""
    INIT = "init"
    PROPOSE = "propose"
    ACCEPT = "accept"
    CONFIRM = "confirm"
    ACTIVE = "active"
    RENEGOTIATE = "renegotiate"
    FAILED = "failed"


@dataclass
class CryptoAlgorithm:
    """Represents a cryptographic algorithm"""
    name: str
    algorithm_class: AlgorithmClass
    security_level: SecurityLevel
    is_nist_standard: bool
    performance_score: float  # 0-10, higher is faster
    quantum_resistant: bool
    supported_versions: Set[str] = field(default_factory=set)
    min_key_size: int = 256

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "algorithm_class": self.algorithm_class.value,
            "security_level": self.security_level.value,
            "is_nist_standard": self.is_nist_standard,
            "performance_score": self.performance_score,
            "quantum_resistant": self.quantum_resistant,
            "supported_versions": list(self.supported_versions),
            "min_key_size": self.min_key_size
        }


@dataclass
class HybridSession:
    """Represents an active hybrid encryption session"""
    session_id: str
    classical_algorithm: str
    pq_algorithm: str
    negotiated_version: str
    security_level: SecurityLevel
    created_at: float
    state: ProtocolState
    classical_key: bytes = field(repr=False)
    pq_key: bytes = field(repr=False)
    combined_key: bytes = field(repr=False)
    key_rotation_interval: int = 3600  # 1 hour default
    last_rotation: float = field(default_factory=time.time)
    messages_encrypted: int = 0
    rekey_count: int = 0

    def needs_rotation(self) -> bool:
        """Check if session key needs rotation"""
        return (time.time() - self.last_rotation) > self.key_rotation_interval

    def get_session_info(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "classical_algorithm": self.classical_algorithm,
            "pq_algorithm": self.pq_algorithm,
            "negotiated_version": self.negotiated_version,
            "security_level": self.security_level.value,
            "created_at": self.created_at,
            "state": self.state.value,
            "key_rotation_interval": self.key_rotation_interval,
            "messages_encrypted": self.messages_encrypted,
            "rekey_count": self.rekey_count,
            "seconds_until_rotation": max(0, int(self.key_rotation_interval - (time.time() - self.last_rotation)))
        }


@dataclass
class NegotiationProposal:
    """Algorithm negotiation proposal"""
    proposal_id: str
    proposer_id: str
    classical_options: List[str]
    pq_options: List[str]
    supported_versions: List[str]
    preferred_security_level: SecurityLevel
    timestamp: float
    nonce: str


class HybridEncryptionOrchestrator:
    """
    Post-Quantum Hybrid Encryption Orchestrator v2
    Manages algorithm negotiation, hybrid key composition,
    and threat-adaptive cipher suite selection.
    """

    PROTOCOL_VERSION = "2.0.0"
    SUPPORTED_VERSIONS = {"1.0.0", "1.5.0", "2.0.0"}

    def __init__(self, peer_id: str, min_security_level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.peer_id = peer_id
        self.min_security_level = min_security_level
        self.sessions: Dict[str, HybridSession] = {}
        self.proposals: Dict[str, NegotiationProposal] = {}
        self.negotiation_callbacks: Dict[str, Callable] = {}
        self.orchestrator_stats = defaultdict(int, {
            "proposals_created": 0,
            "proposals_accepted": 0,
            "proposals_rejected": 0,
            "sessions_established": 0,
            "key_rotations_performed": 0,
            "total_encryptions": 0
        })
        
        self._init_algorithm_registry()
        self._init_threat_based_policies()

    def _init_algorithm_registry(self) -> None:
        """Initialize supported algorithm registry"""
        self.algorithms: Dict[str, CryptoAlgorithm] = {
            # Classical algorithms
            "AES-256-GCM": CryptoAlgorithm(
                name="AES-256-GCM",
                algorithm_class=AlgorithmClass.CLASSICAL,
                security_level=SecurityLevel.LEVEL_5,
                is_nist_standard=True,
                performance_score=9.2,
                quantum_resistant=False,
                supported_versions={"1.0.0", "1.5.0", "2.0.0"},
                min_key_size=256
            ),
            "ChaCha20-Poly1305": CryptoAlgorithm(
                name="ChaCha20-Poly1305",
                algorithm_class=AlgorithmClass.CLASSICAL,
                security_level=SecurityLevel.LEVEL_3,
                is_nist_standard=True,
                performance_score=8.8,
                quantum_resistant=False,
                supported_versions={"1.0.0", "1.5.0", "2.0.0"},
                min_key_size=256
            ),
            # Post-Quantum algorithms
            "CRYSTALS-Kyber-768": CryptoAlgorithm(
                name="CRYSTALS-Kyber-768",
                algorithm_class=AlgorithmClass.POST_QUANTUM,
                security_level=SecurityLevel.LEVEL_3,
                is_nist_standard=True,
                performance_score=7.5,
                quantum_resistant=True,
                supported_versions={"1.5.0", "2.0.0"},
                min_key_size=768
            ),
            "CRYSTALS-Kyber-1024": CryptoAlgorithm(
                name="CRYSTALS-Kyber-1024",
                algorithm_class=AlgorithmClass.POST_QUANTUM,
                security_level=SecurityLevel.LEVEL_5,
                is_nist_standard=True,
                performance_score=6.8,
                quantum_resistant=True,
                supported_versions={"1.5.0", "2.0.0"},
                min_key_size=1024
            ),
            "NTRU-HPS-2048": CryptoAlgorithm(
                name="NTRU-HPS-2048",
                algorithm_class=AlgorithmClass.POST_QUANTUM,
                security_level=SecurityLevel.LEVEL_3,
                is_nist_standard=True,
                performance_score=7.8,
                quantum_resistant=True,
                supported_versions={"2.0.0"},
                min_key_size=2048
            ),
            "FrodoKEM-640": CryptoAlgorithm(
                name="FrodoKEM-640",
                algorithm_class=AlgorithmClass.POST_QUANTUM,
                security_level=SecurityLevel.LEVEL_1,
                is_nist_standard=True,
                performance_score=5.5,
                quantum_resistant=True,
                supported_versions={"2.0.0"},
                min_key_size=640
            )
        }

    def _init_threat_based_policies(self) -> None:
        """Initialize threat-based algorithm selection policies"""
        self.threat_policies = {
            "default": {
                "classical": ["AES-256-GCM", "ChaCha20-Poly1305"],
                "pq": ["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024"]
            },
            "high_threat": {
                "classical": ["AES-256-GCM"],
                "pq": ["CRYSTALS-Kyber-1024", "NTRU-HPS-2048"]
            },
            "performance_mode": {
                "classical": ["ChaCha20-Poly1305", "AES-256-GCM"],
                "pq": ["CRYSTALS-Kyber-768"]
            },
            "quantum_urgent": {
                "classical": ["AES-256-GCM"],
                "pq": ["CRYSTALS-Kyber-1024", "NTRU-HPS-2048", "FrodoKEM-640"]
            }
        }

    def create_negotiation_proposal(
        self,
        target_peer_id: str,
        policy_profile: str = "default",
        preferred_security: Optional[SecurityLevel] = None
    ) -> NegotiationProposal:
        """
        Create a negotiation proposal for a peer
        
        Args:
            target_peer_id: Target peer identifier
            policy_profile: Threat policy profile
            preferred_security: Preferred security level
            
        Returns:
            NegotiationProposal with algorithm options
        """
        if preferred_security is None:
            preferred_security = self.min_security_level
        
        policy = self.threat_policies.get(policy_profile, self.threat_policies["default"])
        
        # Filter algorithms by compatibility
        classical_options = [
            algo for algo in policy["classical"]
            if self._is_algorithm_compatible(algo, preferred_security)
        ]
        
        pq_options = [
            algo for algo in policy["pq"]
            if self._is_algorithm_compatible(algo, preferred_security)
        ]
        
        proposal = NegotiationProposal(
            proposal_id=self._generate_id("PROP"),
            proposer_id=self.peer_id,
            classical_options=classical_options,
            pq_options=pq_options,
            supported_versions=sorted(list(self.SUPPORTED_VERSIONS)),
            preferred_security_level=preferred_security,
            timestamp=time.time(),
            nonce=secrets.token_hex(16)
        )
        
        self.proposals[proposal.proposal_id] = proposal
        self.orchestrator_stats["proposals_created"] += 1
        
        return proposal

    def evaluate_proposal(
        self,
        proposal: NegotiationProposal
    ) -> Tuple[bool, Dict[str, str], str]:
        """
        Evaluate incoming negotiation proposal
        
        Args:
            proposal: Received negotiation proposal
            
        Returns:
            (accepted, selected_algorithms, negotiated_version)
        """
        # Find common supported versions
        common_versions = self.SUPPORTED_VERSIONS.intersection(proposal.supported_versions)
        if not common_versions:
            self.orchestrator_stats["proposals_rejected"] += 1
            return False, {}, ""
        
        # Use highest common version
        negotiated_version = sorted(common_versions)[-1]
        
        # Find intersection of supported classical algorithms
        classical_intersection = []
        for algo in proposal.classical_options:
            if algo in self.algorithms:
                if self._is_algorithm_compatible(algo, proposal.preferred_security_level):
                    classical_intersection.append(algo)
        
        # Find intersection of supported PQ algorithms
        pq_intersection = []
        for algo in proposal.pq_options:
            if algo in self.algorithms:
                if self._is_algorithm_compatible(algo, proposal.preferred_security_level):
                    pq_intersection.append(algo)
        
        if not classical_intersection or not pq_intersection:
            self.orchestrator_stats["proposals_rejected"] += 1
            return False, {}, ""
        
        # Select best algorithms (prefer higher performance)
        selected = {
            "classical": max(classical_intersection, key=lambda a: self.algorithms[a].performance_score),
            "pq": max(pq_intersection, key=lambda a: self.algorithms[a].performance_score)
        }
        
        self.orchestrator_stats["proposals_accepted"] += 1
        return True, selected, negotiated_version

    def establish_hybrid_session(
        self,
        classical_algo: str,
        pq_algo: str,
        negotiated_version: str,
        peer_session_id: Optional[str] = None
    ) -> HybridSession:
        """
        Establish a new hybrid encryption session
        
        Args:
            classical_algo: Selected classical algorithm
            pq_algo: Selected PQ algorithm
            negotiated_version: Protocol version
            peer_session_id: Optional peer session ID for matching
            
        Returns:
            New HybridSession
        """
        session_id = peer_session_id or self._generate_id("SESS")
        
        # Generate keys (simulated secure key generation)
        classical_key = secrets.token_bytes(32)  # 256-bit
        pq_key = secrets.token_bytes(128)  # 1024-bit equivalent
        
        # Combine keys using cryptographically secure method
        combined_key = self._compose_hybrid_key(classical_key, pq_key)
        
        session = HybridSession(
            session_id=session_id,
            classical_algorithm=classical_algo,
            pq_algorithm=pq_algo,
            negotiated_version=negotiated_version,
            security_level=self.algorithms[pq_algo].security_level,
            created_at=time.time(),
            state=ProtocolState.ACTIVE,
            classical_key=classical_key,
            pq_key=pq_algo,
            combined_key=combined_key
        )
        
        self.sessions[session_id] = session
        self.orchestrator_stats["sessions_established"] += 1
        
        return session

    def rotate_session_keys(self, session_id: str) -> bool:
        """
        Perform key rotation on an active session
        
        Args:
            session_id: Session identifier
            
        Returns:
            Success status
        """
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        # Generate new keys
        new_classical = secrets.token_bytes(32)
        new_pq = secrets.token_bytes(128)
        
        # Update session
        session.classical_key = new_classical
        session.pq_key = new_pq
        session.combined_key = self._compose_hybrid_key(new_classical, new_pq)
        session.last_rotation = time.time()
        session.rekey_count += 1
        
        self.orchestrator_stats["key_rotations_performed"] += 1
        return True

    def encrypt_with_session(
        self,
        session_id: str,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> Optional[Tuple[bytes, bytes, bytes]]:
        """
        Encrypt data using hybrid session
        
        Args:
            session_id: Session identifier
            plaintext: Data to encrypt
            associated_data: Optional AEAD associated data
            
        Returns:
            (ciphertext, nonce, tag) or None if session invalid
        """
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        if session.state != ProtocolState.ACTIVE:
            return None
        
        # Auto-rotate if needed
        if session.needs_rotation():
            self.rotate_session_keys(session_id)
        
        # Simulated AEAD encryption
        nonce = secrets.token_bytes(12)
        keystream = hashlib.sha256(session.combined_key + nonce).digest() * (len(plaintext) // 32 + 1)
        ciphertext = bytes(a ^ b for a, b in list(zip(plaintext, keystream))[:len(plaintext)])
        tag = hmac.new(session.combined_key, ciphertext + nonce + (associated_data or b''), hashlib.sha256).digest()
        
        session.messages_encrypted += 1
        self.orchestrator_stats["total_encryptions"] += 1
        
        return (ciphertext, nonce, tag)

    def select_algorithms_for_threat_level(
        self,
        threat_level: str,
        performance_weight: float = 0.5
    ) -> Dict[str, List[str]]:
        """
        Threat-adaptive algorithm selection
        
        Args:
            threat_level: Current threat assessment
            performance_weight: 0-1 weight for performance vs security
            
        Returns:
            Recommended algorithm lists
        """
        if threat_level in ["critical", "severe"]:
            profile = "quantum_urgent"
        elif threat_level == "high":
            profile = "high_threat"
        elif threat_level in ["low", "minimal"]:
            profile = "performance_mode"
        else:
            profile = "default"
        
        policy = self.threat_policies[profile]
        
        # Reorder based on performance weight
        if performance_weight > 0.7:
            classical_sorted = sorted(policy["classical"], key=lambda a: self.algorithms[a].performance_score, reverse=True)
            pq_sorted = sorted(policy["pq"], key=lambda a: self.algorithms[a].performance_score, reverse=True)
        else:
            classical_sorted = sorted(policy["classical"], key=lambda a: self.algorithms[a].security_level.value, reverse=True)
            pq_sorted = sorted(policy["pq"], key=lambda a: self.algorithms[a].security_level.value, reverse=True)
        
        return {
            "classical": classical_sorted,
            "post_quantum": pq_sorted,
            "profile_applied": profile
        }

    def get_algorithm_info(self, algorithm_name: str) -> Optional[CryptoAlgorithm]:
        """Get detailed algorithm information"""
        return self.algorithms.get(algorithm_name)

    def list_supported_algorithms(self, algorithm_class: Optional[AlgorithmClass] = None) -> List[CryptoAlgorithm]:
        """List all supported algorithms, optionally filtered"""
        if algorithm_class:
            return [a for a in self.algorithms.values() if a.algorithm_class == algorithm_class]
        return list(self.algorithms.values())

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information"""
        if session_id not in self.sessions:
            return None
        return self.sessions[session_id].get_session_info()

    def get_orchestrator_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics"""
        return {
            **dict(self.orchestrator_stats),
            "active_sessions": len([s for s in self.sessions.values() if s.state == ProtocolState.ACTIVE]),
            "total_sessions": len(self.sessions),
            "pending_proposals": len(self.proposals),
            "protocol_version": self.PROTOCOL_VERSION,
            "min_security_level": self.min_security_level.value
        }

    def export_session_metadata(self, filepath: str) -> bool:
        """Export session metadata (no key material)"""
        try:
            data = {
                "export_time": datetime.now(timezone.utc).isoformat(),
                "peer_id": self.peer_id,
                "protocol_version": self.PROTOCOL_VERSION,
                "sessions": [s.get_session_info() for s in self.sessions.values()],
                "stats": self.get_orchestrator_stats()
            }
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False

    def _is_algorithm_compatible(
        self,
        algorithm_name: str,
        required_security: SecurityLevel
    ) -> bool:
        """Check if algorithm meets requirements"""
        if algorithm_name not in self.algorithms:
            return False
        
        algo = self.algorithms[algorithm_name]
        return algo.security_level.value >= required_security.value

    def _compose_hybrid_key(self, classical_key: bytes, pq_key: bytes) -> bytes:
        """
        Compose hybrid key using HKDF-like construction
        Both keys contribute to the final session key
        """
        combined = classical_key + pq_key
        return hashlib.sha512(combined).digest()[:32]

    def _generate_id(self, prefix: str) -> str:
        """Generate unique identifier"""
        return f"{prefix}-{secrets.token_hex(8).upper()}"
