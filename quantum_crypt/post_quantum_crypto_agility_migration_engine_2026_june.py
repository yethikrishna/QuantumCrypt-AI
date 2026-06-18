"""
Post-Quantum Cryptographic Agility & Migration Engine - QuantumCrypt-AI
June 2026 Production Implementation

Real, working crypto agility and migration system for post-quantum transition.
Provides algorithm inventory, vulnerability assessment, migration planning,
and automated fallback mechanisms for quantum-safe transition.
"""

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from collections import defaultdict
from enum import Enum
from datetime import datetime, timedelta
import json


class CryptoAlgorithmType(Enum):
    """Types of cryptographic algorithms."""
    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    ENCRYPTION = "encryption"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    RNG = "rng"


class QuantumRiskLevel(Enum):
    """Quantum vulnerability risk levels."""
    CRITICAL = "critical"    # Shor's algorithm vulnerable
    HIGH = "high"           # Known quantum attacks exist
    MEDIUM = "medium"       # Theoretical quantum risk
    LOW = "low"            # Believed quantum-resistant
    NONE = "none"          # Proven post-quantum secure


class MigrationStatus(Enum):
    """Migration status for algorithms."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    DEPRECATED = "deprecated"
    MIGRATED = "migrated"
    BLOCKED = "blocked"


@dataclass
class CryptoAlgorithm:
    """Cryptographic algorithm metadata."""
    name: str
    algorithm_type: CryptoAlgorithmType
    quantum_risk: QuantumRiskLevel
    nist_approved: bool
    standard_status: str  # final, draft, experimental, deprecated
    key_sizes: List[int]
    recommended: bool
    migration_path: List[str] = field(default_factory=list)
    deprecation_date: Optional[datetime] = None
    notes: str = ""


@dataclass
class CryptoUsageRecord:
    """Record of algorithm usage in the system."""
    record_id: str
    algorithm_name: str
    location: str  # file, service, endpoint, etc.
    context: str
    key_size: int
    first_seen: datetime
    last_seen: datetime
    usage_count: int = 1
    risk_assessed: bool = False


@dataclass
class MigrationRecommendation:
    """Actionable migration recommendation."""
    recommendation_id: str
    priority: str  # critical, high, medium, low
    algorithm_name: str
    current_risk: QuantumRiskLevel
    recommended_algorithm: str
    estimated_effort: str  # low, medium, high
    migration_complexity: str
    breaking_changes: bool
    rollback_strategy: str
    implementation_notes: str


@dataclass
class MigrationTask:
    """Specific migration task to execute."""
    task_id: str
    algorithm_from: str
    algorithm_to: str
    location: str
    status: MigrationStatus
    priority: int
    assigned_team: str = ""
    deadline: Optional[datetime] = None
    dependencies: List[str] = field(default_factory=list)
    completed_date: Optional[datetime] = None


class PostQuantumCryptoAgilityMigrationEngine:
    """
    Production-grade cryptographic agility and migration engine.
    
    Features:
    - Cryptographic algorithm inventory tracking
    - Quantum vulnerability assessment
    - Automated migration path generation
    - Hybrid fallback mechanism support
    - Migration task management
    - Compliance reporting for quantum readiness
    - Real-time crypto usage monitoring
    """

    # NIST Post-Quantum Cryptography Standardization Finalists + Classical
    CRYPTO_ALGORITHMS = {
        # Key Exchange / KEM
        "RSA-2048": CryptoAlgorithm(
            name="RSA-2048",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            quantum_risk=QuantumRiskLevel.CRITICAL,
            nist_approved=True,
            standard_status="deprecated",
            key_sizes=[2048],
            recommended=False,
            migration_path=["CRYSTALS-Kyber-512", "X25519+Kyber-512"],
            notes="Shor's algorithm breaks RSA efficiently"
        ),
        "RSA-3072": CryptoAlgorithm(
            name="RSA-3072",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            quantum_risk=QuantumRiskLevel.CRITICAL,
            nist_approved=True,
            standard_status="deprecated",
            key_sizes=[3072],
            recommended=False,
            migration_path=["CRYSTALS-Kyber-768", "X25519+Kyber-768"],
            notes="Shor's algorithm breaks RSA efficiently"
        ),
        "RSA-4096": CryptoAlgorithm(
            name="RSA-4096",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            quantum_risk=QuantumRiskLevel.CRITICAL,
            nist_approved=True,
            standard_status="deprecated",
            key_sizes=[4096],
            recommended=False,
            migration_path=["CRYSTALS-Kyber-1024", "X448+Kyber-1024"],
            notes="Shor's algorithm breaks RSA efficiently"
        ),
        "X25519": CryptoAlgorithm(
            name="X25519",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            quantum_risk=QuantumRiskLevel.CRITICAL,
            nist_approved=True,
            standard_status="final",
            key_sizes=[256],
            recommended=False,
            migration_path=["CRYSTALS-Kyber-512", "X25519+Kyber-512"],
            notes="ECC vulnerable to Shor's algorithm"
        ),
        "X448": CryptoAlgorithm(
            name="X448",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            quantum_risk=QuantumRiskLevel.CRITICAL,
            nist_approved=True,
            standard_status="final",
            key_sizes=[448],
            recommended=False,
            migration_path=["CRYSTALS-Kyber-768", "X448+Kyber-768"],
            notes="ECC vulnerable to Shor's algorithm"
        ),
        "CRYSTALS-Kyber-512": CryptoAlgorithm(
            name="CRYSTALS-Kyber-512",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            quantum_risk=QuantumRiskLevel.NONE,
            nist_approved=True,
            standard_status="final",
            key_sizes=[512],
            recommended=True,
            migration_path=[],
            notes="NIST PQC Standard - ML-KEM-512"
        ),
        "CRYSTALS-Kyber-768": CryptoAlgorithm(
            name="CRYSTALS-Kyber-768",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            quantum_risk=QuantumRiskLevel.NONE,
            nist_approved=True,
            standard_status="final",
            key_sizes=[768],
            recommended=True,
            migration_path=[],
            notes="NIST PQC Standard - ML-KEM-768"
        ),
        "CRYSTALS-Kyber-1024": CryptoAlgorithm(
            name="CRYSTALS-Kyber-1024",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            quantum_risk=QuantumRiskLevel.NONE,
            nist_approved=True,
            standard_status="final",
            key_sizes=[1024],
            recommended=True,
            migration_path=[],
            notes="NIST PQC Standard - ML-KEM-1024"
        ),
        "X25519+Kyber-512": CryptoAlgorithm(
            name="X25519+Kyber-512",
            algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
            quantum_risk=QuantumRiskLevel.LOW,
            nist_approved=True,
            standard_status="final",
            key_sizes=[256, 512],
            recommended=True,
            migration_path=["CRYSTALS-Kyber-512"],
            notes="Hybrid mode for transition period"
        ),
        
        # Signatures
        "ECDSA-P256": CryptoAlgorithm(
            name="ECDSA-P256",
            algorithm_type=CryptoAlgorithmType.SIGNATURE,
            quantum_risk=QuantumRiskLevel.CRITICAL,
            nist_approved=True,
            standard_status="final",
            key_sizes=[256],
            recommended=False,
            migration_path=["CRYSTALS-Dilithium-2", "ECDSA+Dilithium-2"],
            notes="ECC vulnerable to Shor's algorithm"
        ),
        "ECDSA-P384": CryptoAlgorithm(
            name="ECDSA-P384",
            algorithm_type=CryptoAlgorithmType.SIGNATURE,
            quantum_risk=QuantumRiskLevel.CRITICAL,
            nist_approved=True,
            standard_status="final",
            key_sizes=[384],
            recommended=False,
            migration_path=["CRYSTALS-Dilithium-3", "ECDSA+Dilithium-3"],
            notes="ECC vulnerable to Shor's algorithm"
        ),
        "CRYSTALS-Dilithium-2": CryptoAlgorithm(
            name="CRYSTALS-Dilithium-2",
            algorithm_type=CryptoAlgorithmType.SIGNATURE,
            quantum_risk=QuantumRiskLevel.NONE,
            nist_approved=True,
            standard_status="final",
            key_sizes=[128],
            recommended=True,
            migration_path=[],
            notes="NIST PQC Standard - ML-DSA-44"
        ),
        "CRYSTALS-Dilithium-3": CryptoAlgorithm(
            name="CRYSTALS-Dilithium-3",
            algorithm_type=CryptoAlgorithmType.SIGNATURE,
            quantum_risk=QuantumRiskLevel.NONE,
            nist_approved=True,
            standard_status="final",
            key_sizes=[192],
            recommended=True,
            migration_path=[],
            notes="NIST PQC Standard - ML-DSA-65"
        ),
        "CRYSTALS-Dilithium-5": CryptoAlgorithm(
            name="CRYSTALS-Dilithium-5",
            algorithm_type=CryptoAlgorithmType.SIGNATURE,
            quantum_risk=QuantumRiskLevel.NONE,
            nist_approved=True,
            standard_status="final",
            key_sizes=[256],
            recommended=True,
            migration_path=[],
            notes="NIST PQC Standard - ML-DSA-87"
        ),
        "SPHINCS+-SHA2-128f": CryptoAlgorithm(
            name="SPHINCS+-SHA2-128f",
            algorithm_type=CryptoAlgorithmType.SIGNATURE,
            quantum_risk=QuantumRiskLevel.NONE,
            nist_approved=True,
            standard_status="final",
            key_sizes=[128],
            recommended=True,
            migration_path=[],
            notes="NIST PQC Standard - Stateless hash-based"
        ),
        
        # Hash functions
        "SHA-256": CryptoAlgorithm(
            name="SHA-256",
            algorithm_type=CryptoAlgorithmType.HASH,
            quantum_risk=QuantumRiskLevel.MEDIUM,
            nist_approved=True,
            standard_status="final",
            key_sizes=[256],
            recommended=True,
            migration_path=["SHA3-256"],
            notes="Grover's algorithm provides quadratic speedup"
        ),
        "SHA-384": CryptoAlgorithm(
            name="SHA-384",
            algorithm_type=CryptoAlgorithmType.HASH,
            quantum_risk=QuantumRiskLevel.MEDIUM,
            nist_approved=True,
            standard_status="final",
            key_sizes=[384],
            recommended=True,
            migration_path=["SHA3-384"],
            notes="Grover's algorithm provides quadratic speedup"
        ),
        "SHA-512": CryptoAlgorithm(
            name="SHA-512",
            algorithm_type=CryptoAlgorithmType.HASH,
            quantum_risk=QuantumRiskLevel.MEDIUM,
            nist_approved=True,
            standard_status="final",
            key_sizes=[512],
            recommended=True,
            migration_path=["SHA3-512"],
            notes="Grover's algorithm provides quadratic speedup"
        ),
        "SHA3-256": CryptoAlgorithm(
            name="SHA3-256",
            algorithm_type=CryptoAlgorithmType.HASH,
            quantum_risk=QuantumRiskLevel.LOW,
            nist_approved=True,
            standard_status="final",
            key_sizes=[256],
            recommended=True,
            migration_path=[],
            notes="Sponge construction - better quantum resistance"
        ),
        "SHA3-512": CryptoAlgorithm(
            name="SHA3-512",
            algorithm_type=CryptoAlgorithmType.HASH,
            quantum_risk=QuantumRiskLevel.LOW,
            nist_approved=True,
            standard_status="final",
            key_sizes=[512],
            recommended=True,
            migration_path=[],
            notes="Sponge construction - better quantum resistance"
        ),
    }

    def __init__(self, organization_name: str = "Default"):
        """
        Initialize the crypto agility engine.
        
        Args:
            organization_name: Name of organization for reporting
        """
        self.organization_name = organization_name
        self._lock = threading.RLock()
        
        # Crypto usage inventory
        self._crypto_usage: Dict[str, CryptoUsageRecord] = {}
        self._usage_by_algorithm: Dict[str, List[str]] = defaultdict(list)
        
        # Migration tracking
        self._migration_tasks: Dict[str, MigrationTask] = {}
        self._migration_history: List[Dict[str, Any]] = []
        
        # Hybrid mode configuration
        self._hybrid_mode_enabled: Dict[str, bool] = {}
        self._fallback_algorithms: Dict[str, str] = {}
        
        # Counters and metrics
        self.total_scans_performed = 0
        self.total_algorithms_detected = 0
        self.migrations_completed = 0
        self.migrations_in_progress = 0

    def register_crypto_usage(self, 
                            algorithm_name: str,
                            location: str,
                            context: str = "",
                            key_size: int = 0) -> str:
        """
        Register usage of a cryptographic algorithm.
        
        Args:
            algorithm_name: Name of the algorithm
            location: Where it's used (file, endpoint, service)
            context: Additional context
            key_size: Key size in bits
            
        Returns:
            record_id: Unique identifier for this usage
        """
        record_id = self._generate_id()
        now = datetime.now()
        
        with self._lock:
            # Check for existing record at same location
            existing_id = None
            for rid, record in self._crypto_usage.items():
                if record.algorithm_name == algorithm_name and record.location == location:
                    existing_id = rid
                    break
            
            if existing_id:
                # Update existing record
                record = self._crypto_usage[existing_id]
                record.last_seen = now
                record.usage_count += 1
                return existing_id
            
            # Create new record
            record = CryptoUsageRecord(
                record_id=record_id,
                algorithm_name=algorithm_name,
                location=location,
                context=context,
                key_size=key_size,
                first_seen=now,
                last_seen=now
            )
            
            self._crypto_usage[record_id] = record
            self._usage_by_algorithm[algorithm_name].append(record_id)
            self.total_algorithms_detected += 1
        
        return record_id

    def assess_quantum_vulnerability(self, algorithm_name: str) -> Dict[str, Any]:
        """
        Assess quantum vulnerability of a specific algorithm.
        
        Args:
            algorithm_name: Algorithm to assess
            
        Returns:
            Vulnerability assessment details
        """
        algo = self.CRYPTO_ALGORITHMS.get(algorithm_name)
        
        if algo is None:
            return {
                "algorithm": algorithm_name,
                "found": False,
                "risk_level": "unknown",
                "risk_score": -1,
                "message": "Algorithm not in database"
            }
        
        risk_scores = {
            QuantumRiskLevel.CRITICAL: 100,
            QuantumRiskLevel.HIGH: 75,
            QuantumRiskLevel.MEDIUM: 50,
            QuantumRiskLevel.LOW: 25,
            QuantumRiskLevel.NONE: 0
        }
        
        usage_count = len(self._usage_by_algorithm.get(algorithm_name, []))
        
        return {
            "algorithm": algorithm_name,
            "found": True,
            "algorithm_type": algo.algorithm_type.value,
            "risk_level": algo.quantum_risk.value,
            "risk_score": risk_scores[algo.quantum_risk],
            "nist_approved": algo.nist_approved,
            "standard_status": algo.standard_status,
            "recommended": algo.recommended,
            "usage_count": usage_count,
            "migration_path": algo.migration_path,
            "notes": algo.notes
        }

    def get_crypto_inventory(self, 
                           risk_filter: Optional[QuantumRiskLevel] = None,
                           type_filter: Optional[CryptoAlgorithmType] = None) -> List[Dict[str, Any]]:
        """
        Get complete cryptographic inventory with filtering.
        
        Args:
            risk_filter: Optional risk level filter
            type_filter: Optional algorithm type filter
            
        Returns:
            List of inventory items
        """
        inventory = []
        
        with self._lock:
            for record in self._crypto_usage.values():
                algo = self.CRYPTO_ALGORITHMS.get(record.algorithm_name)
                
                if algo is None:
                    continue
                    
                if risk_filter and algo.quantum_risk != risk_filter:
                    continue
                    
                if type_filter and algo.algorithm_type != type_filter:
                    continue
                
                inventory.append({
                    "record_id": record.record_id,
                    "algorithm": record.algorithm_name,
                    "algorithm_type": algo.algorithm_type.value,
                    "risk_level": algo.quantum_risk.value,
                    "location": record.location,
                    "context": record.context,
                    "key_size": record.key_size,
                    "usage_count": record.usage_count,
                    "first_seen": record.first_seen.isoformat(),
                    "last_seen": record.last_seen.isoformat(),
                    "nist_approved": algo.nist_approved,
                    "recommended": algo.recommended
                })
        
        return sorted(inventory, key=lambda x: x["risk_level"])

    def generate_migration_recommendations(self, 
                                         priority_threshold: str = "medium") -> List[MigrationRecommendation]:
        """
        Generate prioritized migration recommendations.
        
        Args:
            priority_threshold: Minimum priority to include
            
        Returns:
            List of migration recommendations
        """
        recommendations = []
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold_level = priority_order.get(priority_threshold, 2)
        
        with self._lock:
            # Group usage by algorithm
            algorithm_usage: Dict[str, int] = defaultdict(int)
            for record in self._crypto_usage.values():
                algorithm_usage[record.algorithm_name] += record.usage_count
            
            for algo_name, usage_count in algorithm_usage.items():
                algo = self.CRYPTO_ALGORITHMS.get(algo_name)
                
                if algo is None or algo.recommended or not algo.migration_path:
                    continue
                
                # Determine priority
                risk_priority_map = {
                    QuantumRiskLevel.CRITICAL: "critical",
                    QuantumRiskLevel.HIGH: "high",
                    QuantumRiskLevel.MEDIUM: "medium",
                    QuantumRiskLevel.LOW: "low",
                    QuantumRiskLevel.NONE: "low"
                }
                priority = risk_priority_map.get(algo.quantum_risk, "medium")
                
                if priority_order.get(priority, 3) > threshold_level:
                    continue
                
                target_algo = algo.migration_path[0] if algo.migration_path else ""
                
                # Estimate effort based on usage count and complexity
                if usage_count < 5:
                    effort = "low"
                    complexity = "simple"
                elif usage_count < 20:
                    effort = "medium"
                    complexity = "moderate"
                else:
                    effort = "high"
                    complexity = "complex"
                
                recommendations.append(MigrationRecommendation(
                    recommendation_id=self._generate_id(),
                    priority=priority,
                    algorithm_name=algo_name,
                    current_risk=algo.quantum_risk,
                    recommended_algorithm=target_algo,
                    estimated_effort=effort,
                    migration_complexity=complexity,
                    breaking_changes=algo.algorithm_type in [CryptoAlgorithmType.KEY_EXCHANGE, CryptoAlgorithmType.SIGNATURE],
                    rollback_strategy="Enable hybrid mode with fallback to original algorithm",
                    implementation_notes=f"Affects {usage_count} usage locations. {algo.notes}"
                ))
        
        # Sort by priority
        return sorted(
            recommendations,
            key=lambda r: priority_order.get(r.priority, 3)
        )

    def create_migration_task(self,
                            algorithm_from: str,
                            algorithm_to: str,
                            location: str,
                            priority: int = 1,
                            deadline_days: int = 90) -> str:
        """
        Create a specific migration task.
        
        Args:
            algorithm_from: Source algorithm
            algorithm_to: Target algorithm
            location: Location to migrate
            priority: Task priority (1=highest)
            deadline_days: Days until deadline
            
        Returns:
            task_id: Created task identifier
        """
        task_id = self._generate_id()
        
        task = MigrationTask(
            task_id=task_id,
            algorithm_from=algorithm_from,
            algorithm_to=algorithm_to,
            location=location,
            status=MigrationStatus.NOT_STARTED,
            priority=priority,
            deadline=datetime.now() + timedelta(days=deadline_days)
        )
        
        with self._lock:
            self._migration_tasks[task_id] = task
            self.migrations_in_progress += 1
        
        return task_id

    def update_migration_status(self, task_id: str, status: MigrationStatus) -> bool:
        """
        Update migration task status.
        
        Args:
            task_id: Task to update
            status: New status
            
        Returns:
            success: True if updated
        """
        with self._lock:
            if task_id not in self._migration_tasks:
                return False
            
            task = self._migration_tasks[task_id]
            old_status = task.status
            task.status = status
            
            if status == MigrationStatus.MIGRATED and old_status != MigrationStatus.MIGRATED:
                task.completed_date = datetime.now()
                self.migrations_completed += 1
                self.migrations_in_progress = max(0, self.migrations_in_progress - 1)
                
                self._migration_history.append({
                    "task_id": task_id,
                    "from": task.algorithm_from,
                    "to": task.algorithm_to,
                    "completed": datetime.now().isoformat(),
                    "location": task.location
                })
            
        return True

    def enable_hybrid_mode(self, algorithm_classic: str, algorithm_pq: str) -> bool:
        """
        Enable hybrid mode (classical + post-quantum) for transition.
        
        Args:
            algorithm_classic: Classical algorithm
            algorithm_pq: Post-quantum algorithm
            
        Returns:
            success: True if enabled
        """
        key = f"{algorithm_classic}+{algorithm_pq}"
        with self._lock:
            self._hybrid_mode_enabled[key] = True
            self._fallback_algorithms[algorithm_pq] = algorithm_classic
        return True

    def get_readiness_score(self) -> Dict[str, Any]:
        """
        Calculate overall quantum readiness score.
        
        Returns:
            Readiness assessment with score 0-100
        """
        if not self._crypto_usage:
            return {
                "readiness_score": 0,
                "message": "No crypto usage registered",
                "breakdown": {}
            }
        
        risk_scores = {
            QuantumRiskLevel.CRITICAL: 0,
            QuantumRiskLevel.HIGH: 25,
            QuantumRiskLevel.MEDIUM: 50,
            QuantumRiskLevel.LOW: 75,
            QuantumRiskLevel.NONE: 100
        }
        
        total_score = 0
        count = 0
        breakdown = defaultdict(int)
        
        with self._lock:
            for record in self._crypto_usage.values():
                algo = self.CRYPTO_ALGORITHMS.get(record.algorithm_name)
                if algo:
                    total_score += risk_scores[algo.quantum_risk]
                    breakdown[algo.quantum_risk.value] += 1
                    count += 1
        
        readiness_score = round(total_score / count, 1) if count > 0 else 0
        
        # Determine readiness level
        if readiness_score >= 80:
            level = "ADVANCED"
            description = "Well-prepared for quantum threats"
        elif readiness_score >= 60:
            level = "PROGRESSING"
            description = "Making good progress on migration"
        elif readiness_score >= 40:
            level = "BEGINNING"
            description = "Starting migration journey"
        else:
            level = "AT RISK"
            description = "Significant quantum vulnerabilities exist"
        
        return {
            "readiness_score": readiness_score,
            "readiness_level": level,
            "description": description,
            "algorithms_assessed": count,
            "risk_breakdown": dict(breakdown),
            "migrations_completed": self.migrations_completed,
            "migrations_in_progress": self.migrations_in_progress
        }

    def generate_compliance_report(self) -> Dict[str, Any]:
        """
        Generate quantum readiness compliance report.
        
        Returns:
            Complete compliance report
        """
        readiness = self.get_readiness_score()
        inventory = self.get_crypto_inventory()
        recommendations = self.generate_migration_recommendations()
        
        critical_count = len(self.get_crypto_inventory(risk_filter=QuantumRiskLevel.CRITICAL))
        high_count = len(self.get_crypto_inventory(risk_filter=QuantumRiskLevel.HIGH))
        
        return {
            "organization": self.organization_name,
            "report_date": datetime.now().isoformat(),
            "readiness": readiness,
            "executive_summary": {
                "total_algorithms": len(inventory),
                "critical_vulnerabilities": critical_count,
                "high_vulnerabilities": high_count,
                "recommendations_pending": len(recommendations),
                "action_required": critical_count > 0 or high_count > 0
            },
            "inventory_summary": inventory,
            "top_recommendations": [
                {
                    "priority": r.priority,
                    "from": r.algorithm_name,
                    "to": r.recommended_algorithm,
                    "effort": r.estimated_effort
                }
                for r in recommendations[:5]
            ]
        }

    def get_migration_tasks(self, status_filter: Optional[MigrationStatus] = None) -> List[Dict[str, Any]]:
        """Get all migration tasks, optionally filtered."""
        tasks = []
        with self._lock:
            for task in self._migration_tasks.values():
                if status_filter and task.status != status_filter:
                    continue
                tasks.append({
                    "task_id": task.task_id,
                    "from": task.algorithm_from,
                    "to": task.algorithm_to,
                    "location": task.location,
                    "status": task.status.value,
                    "priority": task.priority,
                    "deadline": task.deadline.isoformat() if task.deadline else None,
                    "completed": task.completed_date.isoformat() if task.completed_date else None
                })
        return sorted(tasks, key=lambda t: t["priority"])

    @staticmethod
    def _generate_id() -> str:
        """Generate unique identifier."""
        return secrets.token_hex(8)

    def __str__(self) -> str:
        readiness = self.get_readiness_score()
        return (f"PostQuantumCryptoAgilityEngine(org={self.organization_name}, "
                f"readiness={readiness['readiness_score']}, "
                f"algorithms={len(self._crypto_usage)}, "
                f"migrations={self.migrations_completed})")
