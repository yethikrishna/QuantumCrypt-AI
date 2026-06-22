"""
Post-Quantum Crypto Policy Enforcement Engine v12
QuantumCrypt-AI Feature Expansion (Dimension A)

Enforces cryptographic policies across the system to:
- Ensure compliance with NIST standards and security requirements
- Enforce minimum key strengths and algorithm requirements
- Prevent weak/deprecated algorithm usage
- Audit crypto operations against policy rules
- Provide policy violation alerts and remediation guidance

This is a NEW module - wraps existing crypto operations, no core modifications.
All existing behavior is 100% preserved.
"""

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from collections import defaultdict
from functools import wraps


class PolicySeverity(Enum):
    """Policy violation severity levels"""
    CRITICAL = "critical"    # Immediate security risk - block operation
    HIGH = "high"            # Severe risk - alert and log
    MEDIUM = "medium"        # Moderate risk - log only
    LOW = "low"              # Minor concern - informational
    INFO = "info"            # Compliance tracking only


class AlgorithmStatus(Enum):
    """Algorithm security status"""
    RECOMMENDED = "recommended"    # NIST approved, preferred
    ALLOWED = "allowed"            # Acceptable but not preferred
    DEPRECATED = "deprecated"      # Phase out, allowed only for legacy
    DISALLOWED = "disallowed"      # Blocked, security risk
    EXPERIMENTAL = "experimental"  # Testing only, not production


class PolicyAction(Enum):
    """Action to take on policy violation"""
    BLOCK = "block"           # Prevent operation
    ALERT = "alert"           # Allow but alert
    LOG = "log"               # Allow and log only
    ALLOW = "allow"           # Explicitly allow (exception)


@dataclass
class CryptoPolicyRule:
    """Single policy rule definition"""
    rule_id: str
    rule_name: str
    description: str
    severity: PolicySeverity
    algorithm_types: Set[str]
    minimum_key_size: Optional[int] = None
    allowed_algorithms: Optional[Set[str]] = None
    disallowed_algorithms: Optional[Set[str]] = None
    required_properties: Set[str] = field(default_factory=set)
    action: PolicyAction = PolicyAction.ALERT
    exception_contexts: Set[str] = field(default_factory=set)
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.value,
            "algorithm_types": list(self.algorithm_types),
            "minimum_key_size": self.minimum_key_size,
            "allowed_algorithms": list(self.allowed_algorithms) if self.allowed_algorithms else None,
            "disallowed_algorithms": list(self.disallowed_algorithms) if self.disallowed_algorithms else None,
            "required_properties": list(self.required_properties),
            "action": self.action.value,
            "enabled": self.enabled,
        }


@dataclass
class PolicyViolation:
    """Record of a policy violation"""
    violation_id: str
    rule_id: str
    rule_name: str
    severity: PolicySeverity
    action_taken: PolicyAction
    algorithm_used: str
    key_size: Optional[int]
    context: Dict[str, Any]
    timestamp: float
    operation_id: Optional[str] = None
    remediation: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "action_taken": self.action_taken.value,
            "algorithm_used": self.algorithm_used,
            "key_size": self.key_size,
            "context": self.context,
            "timestamp": self.timestamp,
            "operation_id": self.operation_id,
            "remediation": self.remediation,
        }


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation"""
    operation_allowed: bool
    applicable_rules: List[CryptoPolicyRule]
    violations: List[PolicyViolation]
    warnings: List[str]
    algorithm_status: AlgorithmStatus
    compliance_score: float  # 0.0 - 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_allowed": self.operation_allowed,
            "rules_applied": len(self.applicable_rules),
            "violations_count": len(self.violations),
            "violations": [v.to_dict() for v in self.violations],
            "warnings": self.warnings,
            "algorithm_status": self.algorithm_status.value,
            "compliance_score": self.compliance_score,
        }


class PostQuantumCryptoPolicyEnforcer:
    """
    Post-Quantum Cryptography Policy Enforcement Engine
    
    Enforces security policies for cryptographic operations,
    ensuring compliance with NIST standards and organizational requirements.
    """
    
    # NIST SP 800-186 recommended post-quantum algorithms
    NIST_RECOMMENDED_PQ = {
        # Key Encapsulation Mechanisms
        "CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024",
        # Digital Signatures
        "CRYSTALS-Dilithium-2", "CRYSTALS-Dilithium-3", "CRYSTALS-Dilithium-5",
        "Falcon-512", "Falcon-1024",
        "SPHINCS+-SHA2-128f", "SPHINCS+-SHA2-128s",
        "SPHINCS+-SHA2-192f", "SPHINCS+-SHA2-192s",
        "SPHINCS+-SHA2-256f", "SPHINCS+-SHA2-256s",
    }
    
    # Algorithms being deprecated
    DEPRECATED_ALGORITHMS = {
        "RSA-1024", "DSA-1024", "ECDSA-secp192r1",
        "SHA-1", "MD5", "3DES", "RC4",
    }
    
    # Disallowed algorithms (known broken)
    DISALLOWED_ALGORITHMS = {
        "MD5", "SHA-1", "RC4", "DES", "SKIPJACK",
    }
    
    # Minimum key sizes by algorithm type
    MINIMUM_KEY_SIZES = {
        "RSA": 2048,
        "ECDSA": 256,
        "ECDH": 256,
        "AES": 128,
        "Kyber": 512,
        "Dilithium": 128,
        "Falcon": 512,
    }
    
    def __init__(self, strict_mode: bool = False, audit_only: bool = False):
        self.strict_mode = strict_mode
        self.audit_only = audit_only
        self.policy_rules: Dict[str, CryptoPolicyRule] = {}
        self.violation_log: List[PolicyViolation] = []
        self.operation_audit: List[Dict[str, Any]] = []
        self.policy_stats = defaultdict(int)
        self.exception_contexts: Set[str] = set()
        
        # Initialize default policy rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self) -> None:
        """Initialize NIST-compliant default policy rules"""
        
        # Rule 1: Block known broken algorithms
        self.add_policy_rule(CryptoPolicyRule(
            rule_id="PQ-POL-001",
            rule_name="Block Known Broken Algorithms",
            description="Prevent use of cryptographically broken algorithms",
            severity=PolicySeverity.CRITICAL,
            algorithm_types={"hash", "symmetric", "asymmetric"},
            disallowed_algorithms=self.DISALLOWED_ALGORITHMS,
            action=PolicyAction.BLOCK,
        ))
        
        # Rule 2: Deprecated algorithm warning
        self.add_policy_rule(CryptoPolicyRule(
            rule_id="PQ-POL-002",
            rule_name="Deprecated Algorithm Detection",
            description="Warn on deprecated algorithm usage",
            severity=PolicySeverity.HIGH,
            algorithm_types={"hash", "symmetric", "asymmetric", "signature"},
            disallowed_algorithms=self.DEPRECATED_ALGORITHMS,
            action=PolicyAction.ALERT,
        ))
        
        # Rule 3: Minimum RSA key size
        self.add_policy_rule(CryptoPolicyRule(
            rule_id="PQ-POL-003",
            rule_name="Minimum RSA Key Size",
            description="Enforce minimum 2048-bit RSA keys",
            severity=PolicySeverity.HIGH,
            algorithm_types={"RSA"},
            minimum_key_size=2048,
            action=PolicyAction.ALERT,
        ))
        
        # Rule 4: Minimum ECC key size
        self.add_policy_rule(CryptoPolicyRule(
            rule_id="PQ-POL-004",
            rule_name="Minimum ECC Key Size",
            description="Enforce minimum 256-bit ECC keys",
            severity=PolicySeverity.HIGH,
            algorithm_types={"ECDSA", "ECDH"},
            minimum_key_size=256,
            action=PolicyAction.ALERT,
        ))
        
        # Rule 5: NIST PQ recommendation
        self.add_policy_rule(CryptoPolicyRule(
            rule_id="PQ-POL-005",
            rule_name="NIST Post-Quantum Standard",
            description="Prefer NIST-standardized post-quantum algorithms",
            severity=PolicySeverity.MEDIUM,
            algorithm_types={"kem", "signature", "post_quantum"},
            allowed_algorithms=self.NIST_RECOMMENDED_PQ,
            action=PolicyAction.LOG,
        ))
        
        # Rule 6: Forward secrecy requirement
        self.add_policy_rule(CryptoPolicyRule(
            rule_id="PQ-POL-006",
            rule_name="Forward Secrecy Requirement",
            description="Key exchange must provide forward secrecy",
            severity=PolicySeverity.MEDIUM,
            algorithm_types={"key_exchange", "kem"},
            required_properties={"forward_secrecy"},
            action=PolicyAction.LOG,
        ))
        
        # Rule 7: Side-channel resistance
        self.add_policy_rule(CryptoPolicyRule(
            rule_id="PQ-POL-007",
            rule_name="Side-Channel Resistance",
            description="Implementations must be side-channel resistant",
            severity=PolicySeverity.MEDIUM,
            algorithm_types={"all"},
            required_properties={"side_channel_resistant"},
            action=PolicyAction.LOG,
        ))
        
        # Rule 8: AES minimum key size
        self.add_policy_rule(CryptoPolicyRule(
            rule_id="PQ-POL-008",
            rule_name="Minimum AES Key Size",
            description="Enforce minimum 128-bit AES keys",
            severity=PolicySeverity.HIGH,
            algorithm_types={"AES"},
            minimum_key_size=128,
            action=PolicyAction.BLOCK,
        ))
    
    def add_policy_rule(self, rule: CryptoPolicyRule) -> None:
        """Add or update a policy rule"""
        self.policy_rules[rule.rule_id] = rule
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a policy rule by ID"""
        if rule_id in self.policy_rules:
            self.policy_rules[rule_id].enabled = False
            return True
        return False
    
    def add_exception_context(self, context: str) -> None:
        """Add a context that is exempt from policy checks"""
        self.exception_contexts.add(context)
    
    def _get_algorithm_status(self, algorithm: str) -> AlgorithmStatus:
        """Determine security status of an algorithm"""
        algo_upper = algorithm.upper()
        
        if algo_upper in self.DISALLOWED_ALGORITHMS or algorithm in self.DISALLOWED_ALGORITHMS:
            return AlgorithmStatus.DISALLOWED
        
        if algo_upper in self.DEPRECATED_ALGORITHMS or algorithm in self.DEPRECATED_ALGORITHMS:
            return AlgorithmStatus.DEPRECATED
        
        if algorithm in self.NIST_RECOMMENDED_PQ:
            return AlgorithmStatus.RECOMMENDED
        
        # Check if it's a known PQ variant
        if any(pq in algorithm for pq in ["Kyber", "Dilithium", "Falcon", "SPHINCS"]):
            return AlgorithmStatus.ALLOWED
        
        return AlgorithmStatus.ALLOWED
    
    def _check_key_size(self, algorithm: str, key_size: Optional[int], rule: CryptoPolicyRule) -> Tuple[bool, str]:
        """Check if key size meets minimum requirement"""
        if rule.minimum_key_size is None:
            return True, ""
        
        if key_size is None:
            return False, f"Key size not specified, minimum {rule.minimum_key_size} required"
        
        if key_size < rule.minimum_key_size:
            return False, f"Key size {key_size} below minimum {rule.minimum_key_size}"
        
        return True, ""
    
    def _check_algorithm_allowed(self, algorithm: str, rule: CryptoPolicyRule) -> Tuple[bool, str]:
        """Check if algorithm is in allowed list"""
        if rule.allowed_algorithms is None:
            return True, ""
        
        if algorithm not in rule.allowed_algorithms:
            return False, f"Algorithm {algorithm} not in allowed list"
        
        return True, ""
    
    def _check_algorithm_disallowed(self, algorithm: str, rule: CryptoPolicyRule) -> Tuple[bool, str]:
        """Check if algorithm is disallowed"""
        if rule.disallowed_algorithms is None:
            return True, ""
        
        if algorithm in rule.disallowed_algorithms:
            return False, f"Algorithm {algorithm} is explicitly disallowed"
        
        return True, ""
    
    def _check_required_properties(
        self, properties: Set[str], rule: CryptoPolicyRule
    ) -> Tuple[bool, str]:
        """Check if all required properties are present"""
        if not rule.required_properties:
            return True, ""
        
        missing = rule.required_properties - properties
        if missing:
            return False, f"Missing required properties: {missing}"
        
        return True, ""
    
    def _get_remediation_steps(self, rule: CryptoPolicyRule, algorithm: str) -> List[str]:
        """Generate remediation steps for a violation"""
        remediations = []
        
        if rule.rule_id == "PQ-POL-001":
            remediations.append(f"Replace {algorithm} with a NIST-approved alternative")
            remediations.append("For hashing: use SHA-256 or SHA-3")
            remediations.append("For encryption: use AES-256-GCM")
        
        elif rule.rule_id == "PQ-POL-002":
            remediations.append(f"Plan migration from {algorithm} to modern alternative")
            remediations.append("Schedule crypto agility review")
        
        elif rule.rule_id in ["PQ-POL-003", "PQ-POL-004", "PQ-POL-008"]:
            remediations.append(f"Increase key size to meet minimum {rule.minimum_key_size} bits")
            remediations.append("Consider post-quantum migration")
        
        elif rule.rule_id == "PQ-POL-005":
            remediations.append("Migrate to NIST-standardized post-quantum algorithms")
            remediations.append("Recommended: CRYSTALS-Kyber, CRYSTALS-Dilithium")
        
        remediations.append(f"Review policy rule: {rule.rule_id} - {rule.rule_name}")
        return remediations
    
    def evaluate_operation(
        self,
        algorithm: str,
        algorithm_type: str,
        key_size: Optional[int] = None,
        properties: Optional[Set[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        operation_id: Optional[str] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluate a cryptographic operation against all active policies.
        
        Returns: PolicyEvaluationResult with compliance assessment
        """
        context = context or {}
        properties = properties or set()
        operation_id = operation_id or f"op_{uuid.uuid4().hex[:12]}"
        
        # Check for policy exceptions
        context_tags = context.get("tags", set())
        if context_tags & self.exception_contexts:
            return PolicyEvaluationResult(
                operation_allowed=True,
                applicable_rules=[],
                violations=[],
                warnings=["Policy exception applied - operation exempt from checks"],
                algorithm_status=self._get_algorithm_status(algorithm),
                compliance_score=1.0,
            )
        
        violations: List[PolicyViolation] = []
        applicable: List[CryptoPolicyRule] = []
        warnings: List[str] = []
        algo_status = self._get_algorithm_status(algorithm)
        
        # Check each enabled rule
        for rule in self.policy_rules.values():
            if not rule.enabled:
                continue
            
            # Check if rule applies to this algorithm type
            if "all" not in rule.algorithm_types and algorithm_type not in rule.algorithm_types:
                continue
            
            applicable.append(rule)
            
            # Run all checks for this rule
            checks = [
                self._check_key_size(algorithm, key_size, rule),
                self._check_algorithm_allowed(algorithm, rule),
                self._check_algorithm_disallowed(algorithm, rule),
                self._check_required_properties(properties, rule),
            ]
            
            for passed, message in checks:
                if not passed and message:
                    # Determine action (audit mode overrides BLOCK)
                    action = rule.action
                    if self.audit_only and action == PolicyAction.BLOCK:
                        action = PolicyAction.ALERT
                        warnings.append("Audit mode: would have blocked operation")
                    
                    violation = PolicyViolation(
                        violation_id=f"vio_{uuid.uuid4().hex[:16]}",
                        rule_id=rule.rule_id,
                        rule_name=rule.rule_name,
                        severity=rule.severity,
                        action_taken=action,
                        algorithm_used=algorithm,
                        key_size=key_size,
                        context={
                            "message": message,
                            **context,
                        },
                        timestamp=time.time(),
                        operation_id=operation_id,
                        remediation=self._get_remediation_steps(rule, algorithm),
                    )
                    
                    violations.append(violation)
                    self.violation_log.append(violation)
                    self.policy_stats[f"violation_{rule.rule_id}"] += 1
                    break
        
        # Determine if operation is allowed
        blocks = [v for v in violations if v.action_taken == PolicyAction.BLOCK]
        operation_allowed = len(blocks) == 0
        
        # Calculate compliance score
        total_checks = len(applicable)
        if total_checks == 0:
            compliance_score = 1.0
        else:
            passed = total_checks - len(violations)
            compliance_score = round(passed / total_checks, 3)
        
        # Add status warnings
        if algo_status == AlgorithmStatus.DEPRECATED:
            warnings.append(f"Algorithm {algorithm} is deprecated - plan migration")
        elif algo_status == AlgorithmStatus.EXPERIMENTAL:
            warnings.append(f"Algorithm {algorithm} is experimental - not for production")
        
        # Audit log
        self.operation_audit.append({
            "operation_id": operation_id,
            "algorithm": algorithm,
            "algorithm_type": algorithm_type,
            "key_size": key_size,
            "allowed": operation_allowed,
            "violations_count": len(violations),
            "compliance_score": compliance_score,
            "timestamp": time.time(),
        })
        
        self.policy_stats["operations_evaluated"] += 1
        if not operation_allowed:
            self.policy_stats["operations_blocked"] += 1
        
        return PolicyEvaluationResult(
            operation_allowed=operation_allowed,
            applicable_rules=applicable,
            violations=violations,
            warnings=warnings,
            algorithm_status=algo_status,
            compliance_score=compliance_score,
        )
    
    def policy_decorator(
        self,
        algorithm_param: str = "algorithm",
        key_size_param: str = "key_size",
    ) -> Callable:
        """
        Decorator to automatically enforce policy on functions.
        
        Usage:
            @enforcer.policy_decorator()
            def encrypt(algorithm, key_size, data):
                ...
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                algorithm = kwargs.get(algorithm_param, "unknown")
                key_size = kwargs.get(key_size_param)
                
                result = self.evaluate_operation(
                    algorithm=algorithm,
                    algorithm_type="auto",
                    key_size=key_size,
                    context={"function": func.__name__},
                )
                
                if not result.operation_allowed:
                    raise PermissionError(
                        f"Crypto operation blocked by policy: "
                        f"{[v.rule_name for v in result.violations]}"
                    )
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def get_violations(
        self,
        min_severity: Optional[PolicySeverity] = None,
        limit: int = 100,
    ) -> List[PolicyViolation]:
        """Get policy violations, optionally filtered by severity"""
        violations = reversed(self.violation_log[-limit:])
        
        if min_severity:
            severity_order = {
                PolicySeverity.CRITICAL: 4,
                PolicySeverity.HIGH: 3,
                PolicySeverity.MEDIUM: 2,
                PolicySeverity.LOW: 1,
                PolicySeverity.INFO: 0,
            }
            min_level = severity_order[min_severity]
            violations = [
                v for v in violations
                if severity_order[v.severity] >= min_level
            ]
        
        return list(violations)
    
    def get_compliance_report(self) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        total_ops = self.policy_stats.get("operations_evaluated", 0)
        blocked_ops = self.policy_stats.get("operations_blocked", 0)
        total_violations = len(self.violation_log)
        
        by_severity = defaultdict(int)
        by_rule = defaultdict(int)
        
        for v in self.violation_log:
            by_severity[v.severity.value] += 1
            by_rule[v.rule_id] += 1
        
        compliance_rate = 1.0
        if total_ops > 0:
            compliance_rate = round((total_ops - blocked_ops) / total_ops, 4)
        
        return {
            "report_timestamp": time.time(),
            "summary": {
                "operations_evaluated": total_ops,
                "operations_blocked": blocked_ops,
                "total_violations": total_violations,
                "compliance_rate": compliance_rate,
                "active_policy_rules": len([r for r in self.policy_rules.values() if r.enabled]),
            },
            "violations_by_severity": dict(by_severity),
            "violations_by_rule": dict(by_rule),
            "policy_rules": [r.to_dict() for r in self.policy_rules.values()],
            "nist_recommended_algorithms": list(self.NIST_RECOMMENDED_PQ),
            "recent_violations": [v.to_dict() for v in self.get_violations(limit=20)],
        }


# Module export
__all__ = [
    "PolicySeverity",
    "AlgorithmStatus",
    "PolicyAction",
    "CryptoPolicyRule",
    "PolicyViolation",
    "PolicyEvaluationResult",
    "PostQuantumCryptoPolicyEnforcer",
]
