"""
QuantumCrypt AI - Post-Quantum Hybrid Encryption Orchestrator v17
Dimension A - Feature Expansion (Incremental Build)

Add-only feature: Hybrid encryption orchestrator that automatically selects
and combines classical + post-quantum algorithms based on security requirements,
performance constraints, and threat model analysis.
Does NOT modify any existing code - completely new module.

API Stability: STABLE
Backward Compatible: YES
"""

import hashlib
import secrets
import time
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import defaultdict
from enum import Enum
import threading


class AlgorithmType(Enum):
    """Types of encryption algorithms."""
    CLASSICAL_SYMMETRIC = "classical_symmetric"
    CLASSICAL_ASYMMETRIC = "classical_asymmetric"
    PQ_LATTICE = "pq_lattice"
    PQ_CODEBASED = "pq_codebased"
    PQ_HASHBASED = "pq_hashbased"
    PQ_MULTIVARIATE = "pq_multivariate"
    PQ_ISOGENY = "pq_isogeny"


class SecurityLevel(Enum):
    """NIST security levels for post-quantum algorithms."""
    LEVEL_1 = 1  # 128-bit classical security
    LEVEL_2 = 2  # 192-bit classical security
    LEVEL_3 = 3  # 256-bit classical security
    LEVEL_4 = 4
    LEVEL_5 = 5


class ThreatModel(Enum):
    """Threat models for encryption selection."""
    STANDARD = "standard"
    QUANTUM_RESISTANT = "quantum_resistant"
    NATION_STATE = "nation_state"
    LONG_TERM_STORAGE = "long_term_storage"
    REAL_TIME_COMM = "real_time_communication"


@dataclass
class AlgorithmProfile:
    """Profile of an encryption algorithm."""
    name: str
    algorithm_type: AlgorithmType
    security_level: SecurityLevel
    key_size_bits: int
    block_size_bits: int
    latency_ms_per_mb: float
    throughput_mbps: float
    memory_usage_mb: float
    nist_standardized: bool = False
    hardware_accelerated: bool = False
    side_channel_resistant: bool = False


@dataclass
class EncryptionResult:
    """Result of encryption operation."""
    success: bool
    ciphertext: Optional[bytes] = None
    algorithm_used: str = ""
    key_id: str = ""
    security_level: int = 0
    encryption_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""


@dataclass
class HybridEncryptionPolicy:
    """Policy for hybrid encryption selection."""
    policy_id: str
    name: str
    threat_model: ThreatModel
    min_security_level: SecurityLevel
    max_latency_ms: float
    min_throughput_mbps: float
    require_pq_algorithm: bool = True
    require_classical_fallback: bool = True
    preferred_pq_algorithms: List[str] = field(default_factory=list)
    preferred_classical_algorithms: List[str] = field(default_factory=list)


class AlgorithmRegistry:
    """Registry of available encryption algorithms."""
    
    def __init__(self):
        self.algorithms: Dict[str, AlgorithmProfile] = {}
        self._lock = threading.RLock()
        self._initialize_default_algorithms()
    
    def _initialize_default_algorithms(self):
        """Initialize with standard algorithm profiles."""
        # Classical algorithms
        self.register_algorithm(AlgorithmProfile(
            name="AES-256-GCM",
            algorithm_type=AlgorithmType.CLASSICAL_SYMMETRIC,
            security_level=SecurityLevel.LEVEL_5,
            key_size_bits=256,
            block_size_bits=128,
            latency_ms_per_mb=0.1,
            throughput_mbps=1000.0,
            memory_usage_mb=1.0,
            nist_standardized=True,
            hardware_accelerated=True,
            side_channel_resistant=True
        ))
        
        self.register_algorithm(AlgorithmProfile(
            name="ChaCha20-Poly1305",
            algorithm_type=AlgorithmType.CLASSICAL_SYMMETRIC,
            security_level=SecurityLevel.LEVEL_3,
            key_size_bits=256,
            block_size_bits=512,
            latency_ms_per_mb=0.15,
            throughput_mbps=800.0,
            memory_usage_mb=0.5,
            nist_standardized=True,
            hardware_accelerated=False,
            side_channel_resistant=True
        ))
        
        # Post-Quantum algorithms (NIST standardized)
        self.register_algorithm(AlgorithmProfile(
            name="CRYSTALS-Kyber-768",
            algorithm_type=AlgorithmType.PQ_LATTICE,
            security_level=SecurityLevel.LEVEL_3,
            key_size_bits=1184,
            block_size_bits=1088,
            latency_ms_per_mb=5.0,
            throughput_mbps=50.0,
            memory_usage_mb=5.0,
            nist_standardized=True,
            hardware_accelerated=False,
            side_channel_resistant=False
        ))
        
        self.register_algorithm(AlgorithmProfile(
            name="CRYSTALS-Kyber-1024",
            algorithm_type=AlgorithmType.PQ_LATTICE,
            security_level=SecurityLevel.LEVEL_5,
            key_size_bits=1568,
            block_size_bits=1568,
            latency_ms_per_mb=8.0,
            throughput_mbps=30.0,
            memory_usage_mb=8.0,
            nist_standardized=True,
            hardware_accelerated=False,
            side_channel_resistant=False
        ))
        
        self.register_algorithm(AlgorithmProfile(
            name="CRYSTALS-Dilithium-3",
            algorithm_type=AlgorithmType.PQ_LATTICE,
            security_level=SecurityLevel.LEVEL_3,
            key_size_bits=1952,
            block_size_bits=3293,
            latency_ms_per_mb=10.0,
            throughput_mbps=20.0,
            memory_usage_mb=10.0,
            nist_standardized=True,
            hardware_accelerated=False,
            side_channel_resistant=False
        ))
        
        # Additional PQ candidates
        self.register_algorithm(AlgorithmProfile(
            name="FrodoKEM-640",
            algorithm_type=AlgorithmType.PQ_LATTICE,
            security_level=SecurityLevel.LEVEL_1,
            key_size_bits=9616,
            block_size_bits=9720,
            latency_ms_per_mb=50.0,
            throughput_mbps=5.0,
            memory_usage_mb=20.0,
            nist_standardized=False,
            hardware_accelerated=False,
            side_channel_resistant=True
        ))
        
        self.register_algorithm(AlgorithmProfile(
            name="SPHINCS+-SHA256-128f",
            algorithm_type=AlgorithmType.PQ_HASHBASED,
            security_level=SecurityLevel.LEVEL_1,
            key_size_bits=32,
            block_size_bits=17088,
            latency_ms_per_mb=100.0,
            throughput_mbps=1.0,
            memory_usage_mb=15.0,
            nist_standardized=True,
            hardware_accelerated=False,
            side_channel_resistant=True
        ))
    
    def register_algorithm(self, profile: AlgorithmProfile) -> None:
        """Register a new algorithm profile."""
        with self._lock:
            self.algorithms[profile.name] = profile
    
    def get_algorithm(self, name: str) -> Optional[AlgorithmProfile]:
        """Get algorithm profile by name."""
        with self._lock:
            return self.algorithms.get(name)
    
    def get_algorithms_by_type(self, algo_type: AlgorithmType) -> List[AlgorithmProfile]:
        """Get all algorithms of a specific type."""
        with self._lock:
            return [a for a in self.algorithms.values() if a.algorithm_type == algo_type]
    
    def get_algorithms_by_security_level(self, min_level: SecurityLevel) -> List[AlgorithmProfile]:
        """Get all algorithms meeting minimum security level."""
        with self._lock:
            return [a for a in self.algorithms.values() if a.security_level.value >= min_level.value]


class HybridEncryptionOrchestrator:
    """
    Main hybrid encryption orchestrator.
    NEW ADD-ONLY FEATURE - Does not modify any existing modules.
    
    Automatically selects and combines classical + post-quantum algorithms
    based on policy, threat model, and performance requirements.
    """
    
    def __init__(self, default_policy: Optional[HybridEncryptionPolicy] = None):
        self.algorithm_registry = AlgorithmRegistry()
        self.policies: Dict[str, HybridEncryptionPolicy] = {}
        self.active_keys: Dict[str, Dict[str, Any]] = {}
        self.encryption_stats: Dict[str, Any] = defaultdict(int)
        self._lock = threading.RLock()
        
        # Set default policy
        if default_policy is None:
            default_policy = HybridEncryptionPolicy(
                policy_id="default-balanced",
                name="Balanced Security-Performance",
                threat_model=ThreatModel.QUANTUM_RESISTANT,
                min_security_level=SecurityLevel.LEVEL_3,
                max_latency_ms=100.0,
                min_throughput_mbps=10.0,
                require_pq_algorithm=True,
                require_classical_fallback=True
            )
        self.default_policy = default_policy
        self.register_policy(default_policy)
    
    def register_policy(self, policy: HybridEncryptionPolicy) -> None:
        """Register an encryption policy."""
        with self._lock:
            self.policies[policy.policy_id] = policy
    
    def select_algorithms(
        self,
        data_size_bytes: int,
        policy_id: Optional[str] = None,
        custom_constraints: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[AlgorithmProfile], Dict[str, Any]]:
        """
        Select optimal algorithms based on policy and constraints.
        
        Args:
            data_size_bytes: Size of data to encrypt
            policy_id: Policy to use (uses default if None)
            custom_constraints: Optional additional constraints
            
        Returns:
            Tuple of (selected_algorithms, selection_metadata)
        """
        policy = self.default_policy
        if policy_id and policy_id in self.policies:
            policy = self.policies[policy_id]
        
        metadata = {
            "policy_used": policy.policy_id,
            "threat_model": policy.threat_model.value,
            "data_size_bytes": data_size_bytes
        }
        
        # Get candidate algorithms
        candidates = self.algorithm_registry.get_algorithms_by_security_level(
            policy.min_security_level
        )
        
        selected: List[AlgorithmProfile] = []
        
        # Select classical algorithm for performance
        classical_candidates = [
            a for a in candidates 
            if a.algorithm_type in [AlgorithmType.CLASSICAL_SYMMETRIC, AlgorithmType.CLASSICAL_ASYMMETRIC]
            and a.throughput_mbps >= policy.min_throughput_mbps
        ]
        
        if classical_candidates:
            # Sort by throughput (highest first)
            classical_candidates.sort(key=lambda x: -x.throughput_mbps)
            selected.append(classical_candidates[0])
        
        # Select PQ algorithm for quantum resistance
        if policy.require_pq_algorithm:
            pq_candidates = [
                a for a in candidates
                if a.algorithm_type in [AlgorithmType.PQ_LATTICE, AlgorithmType.PQ_CODEBASED,
                                       AlgorithmType.PQ_HASHBASED, AlgorithmType.PQ_MULTIVARIATE]
                and a.latency_ms_per_mb <= policy.max_latency_ms
            ]
            
            if pq_candidates:
                # Prefer NIST standardized, then lower latency
                pq_candidates.sort(key=lambda x: (0 if x.nist_standardized else 1, x.latency_ms_per_mb))
                selected.append(pq_candidates[0])
        
        metadata["selected_count"] = len(selected)
        metadata["classical_selected"] = any(
            a.algorithm_type in [AlgorithmType.CLASSICAL_SYMMETRIC, AlgorithmType.CLASSICAL_ASYMMETRIC]
            for a in selected
        )
        metadata["pq_selected"] = any(
            a.algorithm_type not in [AlgorithmType.CLASSICAL_SYMMETRIC, AlgorithmType.CLASSICAL_ASYMMETRIC]
            for a in selected
        )
        
        return selected, metadata
    
    def encrypt(
        self,
        plaintext: bytes,
        policy_id: Optional[str] = None,
        context: Optional[str] = None
    ) -> EncryptionResult:
        """
        Encrypt data using hybrid encryption.
        
        Args:
            plaintext: Data to encrypt
            policy_id: Policy to use
            context: Optional context for key derivation
            
        Returns:
            EncryptionResult with ciphertext and metadata
        """
        start_time = time.time()
        result = EncryptionResult(success=False)
        
        if not plaintext:
            result.error_message = "Empty plaintext provided"
            return result
        
        try:
            # Select algorithms
            algorithms, selection_meta = self.select_algorithms(
                len(plaintext), policy_id
            )
            
            if not algorithms:
                result.error_message = "No suitable algorithms found for policy"
                return result
            
            # Generate key material
            key_material = secrets.token_bytes(64)
            context_str = context or "default-context"
            key_id = hashlib.sha256(f"{key_material}|{context_str}|{time.time()}".encode()).hexdigest()[:16]
            
            # Perform hybrid encryption (layered)
            current_data = plaintext
            used_algorithms = []
            
            for algo in algorithms:
                # Simple encryption simulation - in real implementation this would call actual crypto
                salt = secrets.token_bytes(16)
                key = hashlib.pbkdf2_hmac('sha256', key_material, salt, 100000, dklen=algo.key_size_bits // 8)
                
                # XOR with derived key stream (demonstration only)
                # Real implementation would use actual algorithm implementations
                key_stream = hashlib.sha3_512(key + current_data[:64]).digest()
                while len(key_stream) < len(current_data):
                    key_stream += hashlib.sha3_512(key_stream).digest()
                
                encrypted = bytes(a ^ b for a, b in zip(current_data, key_stream[:len(current_data)]))
                current_data = salt + encrypted
                
                used_algorithms.append(algo.name)
            
            result.ciphertext = current_data
            result.algorithm_used = "+".join(used_algorithms)
            result.key_id = f"QC-KEY-{key_id.upper()}"
            result.security_level = max(a.security_level.value for a in algorithms)
            result.metadata = selection_meta
            result.metadata["algorithms_details"] = [
                {"name": a.name, "type": a.algorithm_type.value, "nist_std": a.nist_standardized}
                for a in algorithms
            ]
            result.success = True
            
            with self._lock:
                self.encryption_stats["total_encryptions"] += 1
                self.encryption_stats["total_bytes_encrypted"] += len(plaintext)
                for algo in used_algorithms:
                    self.encryption_stats[f"algo_{algo}_uses"] += 1
            
        except Exception as e:
            result.error_message = f"Encryption failed: {str(e)}"
        
        result.encryption_time_ms = (time.time() - start_time) * 1000
        return result
    
    def decrypt(
        self,
        ciphertext: bytes,
        key_material: bytes,
        algorithm_chain: List[str]
    ) -> Tuple[bool, Optional[bytes], str]:
        """
        Decrypt data (reverse of encrypt).
        
        Args:
            ciphertext: Encrypted data
            key_material: Original key material
            algorithm_chain: List of algorithms used in encryption order
            
        Returns:
            Tuple of (success, plaintext, message)
        """
        try:
            current_data = ciphertext
            
            # Reverse algorithm chain
            for algo_name in reversed(algorithm_chain):
                algo = self.algorithm_registry.get_algorithm(algo_name)
                if not algo:
                    return False, None, f"Unknown algorithm: {algo_name}"
                
                # Extract salt and decrypt
                salt = current_data[:16]
                encrypted = current_data[16:]
                
                key = hashlib.pbkdf2_hmac('sha256', key_material, salt, 100000, dklen=algo.key_size_bits // 8)
                
                # Reverse XOR (demonstration only)
                key_stream = hashlib.sha3_512(key + encrypted[:64]).digest()
                while len(key_stream) < len(encrypted):
                    key_stream += hashlib.sha3_512(key_stream).digest()
                
                decrypted = bytes(a ^ b for a, b in zip(encrypted, key_stream[:len(encrypted)]))
                current_data = decrypted
            
            return True, current_data, "Decryption successful"
            
        except Exception as e:
            return False, None, f"Decryption failed: {str(e)}"
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        with self._lock:
            stats = dict(self.encryption_stats)
            stats.update({
                "registered_policies": len(self.policies),
                "available_algorithms": len(self.algorithm_registry.algorithms),
                "active_keys": len(self.active_keys)
            })
        return stats
    
    def recommend_policy(
        self,
        use_case: str,
        data_sensitivity: str
    ) -> HybridEncryptionPolicy:
        """
        Recommend an appropriate policy based on use case.
        
        Args:
            use_case: "storage", "communication", "signing", "key_exchange"
            data_sensitivity: "low", "medium", "high", "critical"
            
        Returns:
            Recommended HybridEncryptionPolicy
        """
        sensitivity_map = {
            "low": SecurityLevel.LEVEL_1,
            "medium": SecurityLevel.LEVEL_2,
            "high": SecurityLevel.LEVEL_3,
            "critical": SecurityLevel.LEVEL_5
        }
        
        threat_map = {
            "storage": ThreatModel.LONG_TERM_STORAGE,
            "communication": ThreatModel.REAL_TIME_COMM,
            "signing": ThreatModel.QUANTUM_RESISTANT,
            "key_exchange": ThreatModel.NATION_STATE
        }
        
        security_level = sensitivity_map.get(data_sensitivity.lower(), SecurityLevel.LEVEL_3)
        threat_model = threat_map.get(use_case.lower(), ThreatModel.QUANTUM_RESISTANT)
        
        policy_id = f"auto-{use_case}-{data_sensitivity}".lower()
        
        return HybridEncryptionPolicy(
            policy_id=policy_id,
            name=f"Auto-generated for {use_case} ({data_sensitivity})",
            threat_model=threat_model,
            min_security_level=security_level,
            max_latency_ms=50.0 if use_case == "communication" else 500.0,
            min_throughput_mbps=50.0 if use_case == "communication" else 5.0,
            require_pq_algorithm=data_sensitivity in ["high", "critical"]
        )


# Singleton instance for global use
_orchestrator_instance: Optional[HybridEncryptionOrchestrator] = None

def get_encryption_orchestrator() -> HybridEncryptionOrchestrator:
    """Get or create the global hybrid encryption orchestrator instance."""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = HybridEncryptionOrchestrator()
    return _orchestrator_instance
