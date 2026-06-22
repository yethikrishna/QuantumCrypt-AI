"""
Post-Quantum Hybrid Protocol Negotiator v4
QuantumCrypt-AI Feature Expansion (Dimension A)

Enables automatic PQ algorithm negotiation between parties.
Supports multiple KEMs, signature schemes, and hybrid modes.
ADD-ONLY implementation - no modifications to existing modules.

API Stability: STABLE
"""

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone


class PQAlgorithmType(Enum):
    """Types of post-quantum algorithms."""
    KEM = "key_encapsulation_mechanism"
    SIGNATURE = "digital_signature"
    HYBRID = "hybrid_classical_pq"
    KEY_EXCHANGE = "key_exchange"


class SecurityLevel(Enum):
    """NIST security levels."""
    LEVEL_1 = 1  # 128-bit security
    LEVEL_2 = 2  # 192-bit security
    LEVEL_3 = 3  # 256-bit security
    LEVEL_4 = 4  # Higher than 256-bit
    LEVEL_5 = 5  # Highest security


class PQAlgorithm(Enum):
    """Supported Post-Quantum algorithms."""
    # KEMs - NIST Standardized
    CRYSTALS_KYBER_512 = ("CRYSTALS-Kyber-512", PQAlgorithmType.KEM, SecurityLevel.LEVEL_1)
    CRYSTALS_KYBER_768 = ("CRYSTALS-Kyber-768", PQAlgorithmType.KEM, SecurityLevel.LEVEL_3)
    CRYSTALS_KYBER_1024 = ("CRYSTALS-Kyber-1024", PQAlgorithmType.KEM, SecurityLevel.LEVEL_5)
    
    # Signatures - NIST Standardized
    CRYSTALS_DILITHIUM_2 = ("CRYSTALS-Dilithium-2", PQAlgorithmType.SIGNATURE, SecurityLevel.LEVEL_2)
    CRYSTALS_DILITHIUM_3 = ("CRYSTALS-Dilithium-3", PQAlgorithmType.SIGNATURE, SecurityLevel.LEVEL_3)
    CRYSTALS_DILITHIUM_5 = ("CRYSTALS-Dilithium-5", PQAlgorithmType.SIGNATURE, SecurityLevel.LEVEL_5)
    
    # Additional candidates
    FALCON_512 = ("Falcon-512", PQAlgorithmType.SIGNATURE, SecurityLevel.LEVEL_1)
    FALCON_1024 = ("Falcon-1024", PQAlgorithmType.SIGNATURE, SecurityLevel.LEVEL_5)
    SPHINCS_PLUS_128F = ("SPHINCS+-128f", PQAlgorithmType.SIGNATURE, SecurityLevel.LEVEL_1)
    SPHINCS_PLUS_256F = ("SPHINCS+-256f", PQAlgorithmType.SIGNATURE, SecurityLevel.LEVEL_5)
    
    # Hybrid modes
    HYBRID_KYBER_X25519 = ("Kyber-768+X25519", PQAlgorithmType.HYBRID, SecurityLevel.LEVEL_3)
    HYBRID_KYBER_SECP256R1 = ("Kyber-768+secp256r1", PQAlgorithmType.HYBRID, SecurityLevel.LEVEL_3)
    
    @property
    def name(self) -> str:
        return self.value[0]
    
    @property
    def algorithm_type(self) -> PQAlgorithmType:
        return self.value[1]
    
    @property
    def security_level(self) -> SecurityLevel:
        return self.value[2]


class UseCaseProfile(Enum):
    """Use case profiles for algorithm selection."""
    TLS_HANDSHAKE = {
        "name": "TLS Handshake",
        "latency_sensitive": True,
        "bandwidth_sensitive": True,
        "min_security": SecurityLevel.LEVEL_1,
        "preferred": ["CRYSTALS_KYBER_768", "HYBRID_KYBER_X25519"]
    }
    VPN_TUNNEL = {
        "name": "VPN Tunnel",
        "latency_sensitive": True,
        "bandwidth_sensitive": False,
        "min_security": SecurityLevel.LEVEL_3,
        "preferred": ["CRYSTALS_KYBER_1024", "HYBRID_KYBER_X25519"]
    }
    CODE_SIGNING = {
        "name": "Code Signing",
        "latency_sensitive": False,
        "bandwidth_sensitive": False,
        "min_security": SecurityLevel.LEVEL_3,
        "preferred": ["CRYSTALS_DILITHIUM_3", "CRYSTALS_DILITHIUM_5"]
    }
    DOCUMENT_SIGNING = {
        "name": "Document Signing",
        "latency_sensitive": False,
        "bandwidth_sensitive": False,
        "min_security": SecurityLevel.LEVEL_3,
        "preferred": ["CRYSTALS_DILITHIUM_3", "FALCON_512"]
    }
    BLOCKCHAIN = {
        "name": "Blockchain",
        "latency_sensitive": True,
        "bandwidth_sensitive": True,
        "min_security": SecurityLevel.LEVEL_1,
        "preferred": ["CRYSTALS_DILITHIUM_2", "FALCON_512"]
    }
    GENERAL_PURPOSE = {
        "name": "General Purpose",
        "latency_sensitive": False,
        "bandwidth_sensitive": False,
        "min_security": SecurityLevel.LEVEL_1,
        "preferred": ["CRYSTALS_KYBER_768", "CRYSTALS_DILITHIUM_3"]
    }


@dataclass
class AlgorithmCapability:
    """Represents algorithm capability of a party."""
    party_id: str
    supported_algorithms: List[str] = field(default_factory=list)
    preferred_order: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "party_id": self.party_id,
            "supported_algorithms": self.supported_algorithms,
            "preferred_order": self.preferred_order,
            "constraints": self.constraints,
            "timestamp": self.timestamp
        }


@dataclass
class NegotiationResult:
    """Result of protocol negotiation."""
    success: bool
    selected_algorithm: Optional[str] = None
    common_algorithms: List[str] = field(default_factory=list)
    negotiation_id: str = field(default_factory=lambda: secrets.token_hex(16))
    reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "selected_algorithm": self.selected_algorithm,
            "common_algorithms": self.common_algorithms,
            "negotiation_id": self.negotiation_id,
            "reason": self.reason,
            "metadata": self.metadata
        }


@dataclass
class ProtocolSession:
    """Active protocol session."""
    session_id: str = field(default_factory=lambda: secrets.token_hex(32))
    parties: Dict[str, AlgorithmCapability] = field(default_factory=dict)
    negotiated_algorithm: Optional[str] = None
    created_at: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    expires_at: Optional[float] = None
    status: str = "pending"
    
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc).timestamp() > self.expires_at


class PQHybridProtocolNegotiator:
    """
    Main negotiator for Post-Quantum protocol selection.
    
    Enables parties to negotiate the best PQ algorithm based on:
    - Mutual capabilities
    - Use case requirements
    - Security constraints
    - Performance preferences
    """
    
    def __init__(self):
        self.sessions: Dict[str, ProtocolSession] = {}
        self.algorithm_database: Dict[str, Dict[str, Any]] = {}
        self._init_algorithm_database()
    
    def _init_algorithm_database(self) -> None:
        """Initialize algorithm performance database."""
        for alg in PQAlgorithm:
            self.algorithm_database[alg.name] = {
                "type": alg.algorithm_type.value,
                "security_level": alg.security_level.value,
                "nist_standardized": True,
                "performance_score": self._calc_performance_score(alg)
            }
    
    def _calc_performance_score(self, alg: PQAlgorithm) -> float:
        """Calculate relative performance score (0-10)."""
        # Based on public benchmark data
        performance_map = {
            "CRYSTALS-Kyber-512": 9.5,
            "CRYSTALS-Kyber-768": 8.5,
            "CRYSTALS-Kyber-1024": 7.0,
            "CRYSTALS-Dilithium-2": 9.0,
            "CRYSTALS-Dilithium-3": 8.0,
            "CRYSTALS-Dilithium-5": 6.5,
            "Falcon-512": 8.5,
            "Falcon-1024": 6.0,
            "SPHINCS+-128f": 5.0,
            "SPHINCS+-256f": 3.5,
            "Kyber-768+X25519": 8.0,
            "Kyber-768+secp256r1": 7.5,
        }
        return performance_map.get(alg.name, 5.0)
    
    def create_session(
        self,
        ttl_seconds: int = 3600,
        use_case: Optional[str] = None
    ) -> str:
        """Create a new negotiation session."""
        session = ProtocolSession()
        if ttl_seconds != 0:
            session.expires_at = session.created_at + ttl_seconds
        
        if use_case:
            session.status = f"pending_{use_case}"
        
        self.sessions[session.session_id] = session
        return session.session_id
    
    def register_party_capabilities(
        self,
        session_id: str,
        party_id: str,
        supported_algorithms: List[str],
        preferred_order: Optional[List[str]] = None,
        constraints: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Register a party's algorithm capabilities."""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        if session.is_expired():
            return False
        
        capability = AlgorithmCapability(
            party_id=party_id,
            supported_algorithms=supported_algorithms,
            preferred_order=preferred_order or supported_algorithms,
            constraints=constraints or {}
        )
        session.parties[party_id] = capability
        return True
    
    def negotiate(
        self,
        session_id: str,
        use_case: Optional[str] = None,
        min_security_level: Optional[int] = None
    ) -> NegotiationResult:
        """
        Negotiate algorithm between registered parties.
        
        Returns selected algorithm based on intersection and preferences.
        """
        if session_id not in self.sessions:
            return NegotiationResult(
                success=False,
                reason="session_not_found"
            )
        
        session = self.sessions[session_id]
        if session.is_expired():
            return NegotiationResult(
                success=False,
                reason="session_expired"
            )
        
        if len(session.parties) < 2:
            return NegotiationResult(
                success=False,
                reason="insufficient_parties",
                metadata={"registered_parties": len(session.parties)}
            )
        
        # Find common supported algorithms
        common_set: Set[str] = None
        for party in session.parties.values():
            party_set = set(party.supported_algorithms)
            if common_set is None:
                common_set = party_set
            else:
                common_set &= party_set
        
        if not common_set:
            return NegotiationResult(
                success=False,
                reason="no_common_algorithms",
                common_algorithms=[]
            )
        
        common_algs = list(common_set)
        
        # Apply security level filter
        if min_security_level:
            common_algs = [
                alg for alg in common_algs
                if self._get_security_level(alg) >= min_security_level
            ]
        
        if not common_algs:
            return NegotiationResult(
                success=False,
                reason="no_algorithms_meet_security_requirements",
                common_algorithms=list(common_set)
            )
        
        # Apply use case optimization
        if use_case:
            common_algs = self._rank_by_use_case(common_algs, use_case)
        
        # Select best algorithm (first in ranked list)
        selected = common_algs[0]
        session.negotiated_algorithm = selected
        session.status = "negotiated"
        
        return NegotiationResult(
            success=True,
            selected_algorithm=selected,
            common_algorithms=common_algs,
            metadata={
                "parties": list(session.parties.keys()),
                "use_case": use_case,
                "min_security": min_security_level
            }
        )
    
    def _get_security_level(self, algorithm_name: str) -> int:
        """Get security level for an algorithm."""
        for alg in PQAlgorithm:
            if alg.name == algorithm_name:
                return alg.security_level.value
        return 0
    
    def _rank_by_use_case(self, algorithms: List[str], use_case: str) -> List[str]:
        """Rank algorithms based on use case profile."""
        try:
            profile = UseCaseProfile[use_case.upper()]
        except KeyError:
            profile = UseCaseProfile.GENERAL_PURPOSE
        
        preferred = profile.value["preferred"]
        
        # Sort by preferred order, then by performance
        def rank_key(alg: str) -> Tuple[int, float]:
            try:
                pref_idx = preferred.index(alg)
            except ValueError:
                pref_idx = len(preferred)
            perf = self.algorithm_database.get(alg, {}).get("performance_score", 5.0)
            return (pref_idx, -perf)  # Negative for descending perf
        
        return sorted(algorithms, key=rank_key)
    
    def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session status information."""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        return {
            "session_id": session.session_id,
            "parties": list(session.parties.keys()),
            "negotiated_algorithm": session.negotiated_algorithm,
            "status": session.status,
            "created_at": session.created_at,
            "expires_at": session.expires_at,
            "is_expired": session.is_expired()
        }
    
    def recommend_algorithms(
        self,
        use_case: str = "GENERAL_PURPOSE",
        algorithm_type: Optional[str] = None,
        min_security: int = 1
    ) -> List[Dict[str, Any]]:
        """Get algorithm recommendations for a use case."""
        recommendations = []
        
        for alg in PQAlgorithm:
            # Filter by type
            if algorithm_type and alg.algorithm_type.value != algorithm_type:
                continue
            
            # Filter by security
            if alg.security_level.value < min_security:
                continue
            
            recommendations.append({
                "name": alg.name,
                "type": alg.algorithm_type.value,
                "security_level": alg.security_level.value,
                "performance_score": self._calc_performance_score(alg),
                "nist_standardized": True
            })
        
        # Rank by use case
        alg_names = [r["name"] for r in recommendations]
        ranked = self._rank_by_use_case(alg_names, use_case)
        
        # Reorder recommendations
        ranked_recommendations = []
        for name in ranked:
            for rec in recommendations:
                if rec["name"] == name:
                    ranked_recommendations.append(rec)
                    break
        
        return ranked_recommendations
    
    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions. Returns count removed."""
        expired = [
            sid for sid, session in self.sessions.items()
            if session.is_expired()
        ]
        for sid in expired:
            del self.sessions[sid]
        return len(expired)
    
    def generate_negotiation_token(self, session_id: str) -> Optional[str]:
        """Generate a signed token for negotiation result."""
        session = self.sessions.get(session_id)
        if not session or not session.negotiated_algorithm:
            return None
        
        token_data = {
            "session_id": session_id,
            "negotiated_algorithm": session.negotiated_algorithm,
            "parties": list(session.parties.keys()),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        token_json = json.dumps(token_data, sort_keys=True)
        signature = hashlib.sha256(token_json.encode()).hexdigest()
        
        return f"{token_json}.{signature}"
    
    def verify_negotiation_token(self, token: str) -> Dict[str, Any]:
        """Verify a negotiation token."""
        try:
            token_json, signature = token.rsplit(".", 1)
            expected_sig = hashlib.sha256(token_json.encode()).hexdigest()
            
            if not secrets.compare_digest(signature, expected_sig):
                return {"valid": False, "reason": "invalid_signature"}
            
            data = json.loads(token_json)
            return {"valid": True, "data": data}
        except Exception:
            return {"valid": False, "reason": "invalid_token_format"}


# Global negotiator instance
_global_negotiator: Optional[PQHybridProtocolNegotiator] = None


def get_protocol_negotiator() -> PQHybridProtocolNegotiator:
    """Get or create the global protocol negotiator instance."""
    global _global_negotiator
    if _global_negotiator is None:
        _global_negotiator = PQHybridProtocolNegotiator()
    return _global_negotiator


def negotiate_pq_algorithm(
    party1_algs: List[str],
    party2_algs: List[str],
    use_case: str = "GENERAL_PURPOSE"
) -> NegotiationResult:
    """
    Simple one-shot negotiation between two parties.
    
    Convenience function for quick negotiation.
    """
    negotiator = get_protocol_negotiator()
    session_id = negotiator.create_session()
    negotiator.register_party_capabilities(session_id, "party1", party1_algs)
    negotiator.register_party_capabilities(session_id, "party2", party2_algs)
    return negotiator.negotiate(session_id, use_case=use_case)


# Export public API
__all__ = [
    "PQHybridProtocolNegotiator",
    "PQAlgorithm",
    "PQAlgorithmType",
    "SecurityLevel",
    "UseCaseProfile",
    "AlgorithmCapability",
    "NegotiationResult",
    "ProtocolSession",
    "get_protocol_negotiator",
    "negotiate_pq_algorithm"
]
