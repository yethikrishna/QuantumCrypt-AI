"""
Post-Quantum Cryptographic Inventory & Compliance Scanner
QuantumCrypt-AI - June 2026

Production-grade scanner that:
1. Discovers and inventories all cryptographic usage in code/configs
2. Identifies non-quantum-safe algorithms at risk
3. Assesses compliance with NIST/NSA post-quantum standards
4. Provides prioritized migration recommendations
5. Generates compliance audit reports
"""

import os
import re
import json
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import Enum
from datetime import datetime
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CryptoAlgorithmStatus(Enum):
    QUANTUM_SAFE = "QUANTUM_SAFE"      # NIST-standardized PQ algorithms
    AT_RISK = "AT_RISK"                # Classical algorithms vulnerable to quantum
    DEPRECATED = "DEPRECATED"          # Already broken/deprecated
    UNKNOWN = "UNKNOWN"                # Not categorized


class MigrationPriority(Enum):
    IMMEDIATE = "IMMEDIATE"    # Must migrate within 30 days
    HIGH = "HIGH"              # Migrate within 90 days
    MEDIUM = "MEDIUM"          # Migrate within 6 months
    LOW = "LOW"                # Migrate within 12 months
    NONE = "NONE"              # Already quantum-safe


class ComplianceStandard(Enum):
    NIST_SP_800_186 = "NIST SP 800-186"
    NIST_SP_800_56C = "NIST SP 800-56C"
    NSA_CNSA_20 = "NSA CNSA 2.0"
    ETSI_TS_103_740 = "ETSI TS 103 740"
    CISA_BOD_25_01 = "CISA BOD 25-01"


@dataclass
class CryptoUsageFinding:
    file_path: str
    line_number: int
    algorithm: str
    algorithm_type: str  # cipher, hash, signature, kem, key-exchange
    status: CryptoAlgorithmStatus
    priority: MigrationPriority
    context: str
    recommended_replacement: Optional[str] = None
    compliance_issues: List[str] = field(default_factory=list)
    code_snippet: Optional[str] = None


@dataclass
class ScanSummary:
    scan_id: str
    timestamp: str
    total_files_scanned: int
    total_crypto_findings: int
    quantum_safe_count: int
    at_risk_count: int
    deprecated_count: int
    compliance_score: float
    findings: List[CryptoUsageFinding]
    scan_duration_seconds: float


class PostQuantumCryptoInventoryScanner:
    """
    Production-grade post-quantum cryptographic inventory and compliance scanner.
    Scans code and configuration files for cryptographic usage,
    identifies vulnerable algorithms, and provides migration guidance.
    """

    def __init__(self):
        self.findings: List[CryptoUsageFinding] = []
        self.scan_start_time: Optional[datetime] = None
        self._initialize_crypto_database()

    def _initialize_crypto_database(self):
        """Initialize the cryptographic algorithm classification database."""
        
        # Quantum-safe algorithms (NIST standardized)
        self.quantum_safe = {
            # Key Encapsulation Mechanisms
            "CRYSTALS-Kyber": {"type": "kem", "nist_level": 5},
            "Kyber": {"type": "kem", "nist_level": 5},
            "ML-KEM": {"type": "kem", "nist_level": 5},
            
            # Digital Signatures
            "CRYSTALS-Dilithium": {"type": "signature", "nist_level": 5},
            "Dilithium": {"type": "signature", "nist_level": 5},
            "ML-DSA": {"type": "signature", "nist_level": 5},
            "FALCON": {"type": "signature", "nist_level": 5},
            "SPHINCS+": {"type": "signature", "nist_level": 5},
            "SLH-DSA": {"type": "signature", "nist_level": 5},
            
            # Hash functions (quantum-resistant)
            "SHA-256": {"type": "hash", "note": "Grover-resistant with sufficient output"},
            "SHA-384": {"type": "hash", "note": "Grover-resistant"},
            "SHA-512": {"type": "hash", "note": "Grover-resistant"},
            "SHA3-256": {"type": "hash", "note": "NIST standard"},
            "SHA3-384": {"type": "hash", "note": "NIST standard"},
            "SHA3-512": {"type": "hash", "note": "NIST standard"},
        }
        
        # At-risk algorithms (vulnerable to Shor's algorithm)
        self.at_risk_algorithms = {
            # Public-key encryption / Key exchange
            "RSA": {"type": "asymmetric", "bits_required": 2048, "risk": "Shor's algorithm"},
            "RSA-1024": {"type": "asymmetric", "risk": "Already breakable"},
            "RSA-2048": {"type": "asymmetric", "risk": "Vulnerable to large quantum"},
            "RSA-3072": {"type": "asymmetric", "risk": "Vulnerable long-term"},
            "RSA-4096": {"type": "asymmetric", "risk": "Vulnerable long-term"},
            "ECDH": {"type": "key-exchange", "risk": "Shor's algorithm"},
            "ECDHE": {"type": "key-exchange", "risk": "Shor's algorithm"},
            "ECDSA": {"type": "signature", "risk": "Shor's algorithm"},
            "secp256r1": {"type": "ecc-curve", "risk": "Shor's algorithm"},
            "secp384r1": {"type": "ecc-curve", "risk": "Shor's algorithm"},
            "secp521r1": {"type": "ecc-curve", "risk": "Shor's algorithm"},
            "prime256v1": {"type": "ecc-curve", "risk": "Shor's algorithm"},
            "X25519": {"type": "key-exchange", "risk": "Shor's algorithm"},
            "X448": {"type": "key-exchange", "risk": "Shor's algorithm"},
            "Ed25519": {"type": "signature", "risk": "Shor's algorithm"},
            "Ed448": {"type": "signature", "risk": "Shor's algorithm"},
            "Diffie-Hellman": {"type": "key-exchange", "risk": "Shor's algorithm"},
            "DHE": {"type": "key-exchange", "risk": "Shor's algorithm"},
            "DSA": {"type": "signature", "risk": "Shor's algorithm"},
            
            # Symmetric (at risk from Grover's - need double key size)
            "AES-128": {"type": "cipher", "risk": "Grover reduces to 64-bit", "recommended": "AES-256"},
            "3DES": {"type": "cipher", "risk": "Deprecated + Grover"},
            "DES": {"type": "cipher", "risk": "Already broken"},
            "Blowfish": {"type": "cipher", "risk": "64-bit block too small"},
            "RC4": {"type": "cipher", "risk": "Cryptographically broken"},
        }
        
        # Deprecated/broken algorithms
        self.deprecated_algorithms = {
            "MD5": {"type": "hash", "reason": "Cryptographically broken"},
            "SHA-1": {"type": "hash", "reason": "Collisions demonstrated"},
            "RC2": {"type": "cipher", "reason": "Weak and deprecated"},
            "RC5": {"type": "cipher", "reason": "Not recommended"},
            "DESede": {"type": "cipher", "reason": "Deprecated by NIST"},
        }
        
        # Pattern matching for code scanning
        self.crypto_patterns = [
            # Hash functions
            (r'(?i)md5|sha-?1|sha-?256|sha-?384|sha-?512|sha3-?256|sha3-?384|sha3-?512', 'hash'),
            
            # Ciphers
            (r'(?i)aes-?128|aes-?256|aes-?gcm|aes-?cbc|3des|des|rc4|blowfish', 'cipher'),
            
            # Asymmetric / Key exchange
            (r'(?i)rsa|ecdh|ecdhe|ecdsa|ed25519|ed448|x25519|x448|dsa|diffie-hellman|dhe', 'asymmetric'),
            
            # ECC curves
            (r'(?i)secp256r1|secp384r1|secp521r1|prime256v1', 'ecc-curve'),
            
            # Post-quantum algorithms
            (r'(?i)kyber|crystals-kyber|ml-kem|dilithium|crystals-dilithium|ml-dsa|falcon|sphincs|slh-dsa', 'post-quantum'),
            
            # Library usage
            (r'(?i)cryptography|openssl|pycryptodome|bcrypt|hashlib|hmac', 'library'),
        ]
        
        # Migration recommendations
        self.migration_map = {
            "RSA": "ML-KEM (Kyber) for key exchange, ML-DSA (Dilithium) for signatures",
            "ECDSA": "ML-DSA (Dilithium)",
            "ECDH": "ML-KEM (Kyber)",
            "X25519": "ML-KEM-768",
            "Ed25519": "ML-DSA-65",
            "secp256r1": "ML-KEM / ML-DSA",
            "secp384r1": "ML-KEM-1024 / ML-DSA-87",
            "AES-128": "AES-256 (Grover-resistant)",
            "SHA-256": "SHA-384 or SHA3-256",
        }

    def scan_directory(self, directory: str, file_patterns: List[str] = None) -> ScanSummary:
        """
        Scan a directory for cryptographic usage.
        
        Args:
            directory: Directory path to scan
            file_patterns: List of file extensions to include (default: common code files)
            
        Returns:
            ScanSummary with all findings
        """
        self.scan_start_time = datetime.utcnow()
        self.findings = []
        
        if file_patterns is None:
            file_patterns = ['.py', '.js', '.java', '.cpp', '.c', '.h', '.go', '.rs', 
                           '.xml', '.json', '.yaml', '.yml', '.conf', '.cfg', '.ini']
        
        logger.info(f"Starting post-quantum crypto scan of: {directory}")
        
        files_scanned = 0
        path = Path(directory)
        
        for file_path in path.rglob('*'):
            if file_path.is_file() and any(file_path.name.endswith(p) for p in file_patterns):
                try:
                    self._scan_file(str(file_path))
                    files_scanned += 1
                except Exception as e:
                    logger.warning(f"Could not scan {file_path}: {e}")
        
        scan_end_time = datetime.utcnow()
        duration = (scan_end_time - self.scan_start_time).total_seconds()
        
        # Calculate statistics
        quantum_safe = sum(1 for f in self.findings if f.status == CryptoAlgorithmStatus.QUANTUM_SAFE)
        at_risk = sum(1 for f in self.findings if f.status == CryptoAlgorithmStatus.AT_RISK)
        deprecated = sum(1 for f in self.findings if f.status == CryptoAlgorithmStatus.DEPRECATED)
        
        total = len(self.findings)
        compliance_score = (quantum_safe / total * 100) if total > 0 else 0.0
        
        summary = ScanSummary(
            scan_id=self._generate_scan_id(),
            timestamp=scan_end_time.isoformat(),
            total_files_scanned=files_scanned,
            total_crypto_findings=total,
            quantum_safe_count=quantum_safe,
            at_risk_count=at_risk,
            deprecated_count=deprecated,
            compliance_score=round(compliance_score, 2),
            findings=self.findings,
            scan_duration_seconds=round(duration, 3)
        )
        
        logger.info(f"Scan complete. Files: {files_scanned}, Findings: {total}")
        logger.info(f"Quantum-Safe: {quantum_safe}, At-Risk: {at_risk}, Deprecated: {deprecated}")
        logger.info(f"PQ Compliance Score: {compliance_score:.1f}%")
        
        return summary

    def _scan_file(self, file_path: str):
        """Scan an individual file for cryptographic patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                self._scan_line(file_path, line_num, line.strip())
                
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")

    def _scan_line(self, file_path: str, line_num: int, line_content: str):
        """Scan a single line of code for cryptographic patterns."""
        for pattern, algo_type in self.crypto_patterns:
            matches = re.finditer(pattern, line_content, re.IGNORECASE)
            for match in matches:
                algorithm = match.group(0).upper()
                self._classify_and_record(file_path, line_num, algorithm, algo_type, line_content)

    def _classify_and_record(self, file_path: str, line_num: int, algorithm: str, 
                            algo_type: str, context: str):
        """Classify algorithm and record finding."""
        # Normalize algorithm name
        algo_normalized = self._normalize_algorithm_name(algorithm)
        
        # Determine status
        status = CryptoAlgorithmStatus.UNKNOWN
        priority = MigrationPriority.NONE
        recommended = None
        compliance_issues = []
        
        if algo_normalized in self.quantum_safe:
            status = CryptoAlgorithmStatus.QUANTUM_SAFE
            priority = MigrationPriority.NONE
        elif algo_normalized in self.deprecated_algorithms:
            status = CryptoAlgorithmStatus.DEPRECATED
            priority = MigrationPriority.IMMEDIATE
            compliance_issues.append(f"Deprecated: {self.deprecated_algorithms[algo_normalized]['reason']}")
            compliance_issues.append("Violates NIST SP 800-131A")
            recommended = self.migration_map.get(algo_normalized, "Use NIST-approved post-quantum algorithm")
        elif algo_normalized in self.at_risk_algorithms:
            status = CryptoAlgorithmStatus.AT_RISK
            risk_info = self.at_risk_algorithms[algo_normalized]
            
            # Set priority based on algorithm
            if algo_normalized in ["RSA-1024", "DES", "RC4", "3DES"]:
                priority = MigrationPriority.IMMEDIATE
            elif algo_normalized in ["RSA-2048", "AES-128", "SHA-1"]:
                priority = MigrationPriority.HIGH
            elif algo_normalized in ["RSA-3072", "ECDSA", "ECDH", "X25519", "Ed25519"]:
                priority = MigrationPriority.MEDIUM
            else:
                priority = MigrationPriority.LOW
            
            compliance_issues.append(f"Vulnerable to: {risk_info.get('risk', 'Quantum attack')}")
            compliance_issues.append("Requires migration per CISA BOD 25-01")
            compliance_issues.append("Not compliant with NSA CNSA 2.0")
            
            recommended = self.migration_map.get(algo_normalized, "Migrate to NIST PQ standard")
        
        # Only record if we found something meaningful
        if status != CryptoAlgorithmStatus.UNKNOWN:
            finding = CryptoUsageFinding(
                file_path=file_path,
                line_number=line_num,
                algorithm=algo_normalized,
                algorithm_type=algo_type,
                status=status,
                priority=priority,
                context=context[:100],
                recommended_replacement=recommended,
                compliance_issues=compliance_issues,
                code_snippet=context[:200]
            )
            self.findings.append(finding)

    def _normalize_algorithm_name(self, algo: str) -> str:
        """Normalize algorithm name for lookup."""
        algo = algo.upper().strip()
        # Common normalizations
        mappings = {
            "AES128": "AES-128",
            "AES256": "AES-256",
            "SHA256": "SHA-256",
            "SHA384": "SHA-384",
            "SHA512": "SHA-512",
            "SHA3256": "SHA3-256",
            "NISTP256": "secp256r1",
            "PRIME256V1": "secp256r1",
        }
        return mappings.get(algo, algo)

    def generate_compliance_report(self, summary: ScanSummary, format: str = "json") -> str:
        """Generate compliance report."""
        if format == "json":
            return json.dumps({
                "scan_id": summary.scan_id,
                "timestamp": summary.timestamp,
                "summary": {
                    "files_scanned": summary.total_files_scanned,
                    "total_findings": summary.total_crypto_findings,
                    "quantum_safe": summary.quantum_safe_count,
                    "at_risk": summary.at_risk_count,
                    "deprecated": summary.deprecated_count,
                    "compliance_score": summary.compliance_score
                },
                "findings": [
                    {
                        "file": f.file_path,
                        "line": f.line_number,
                        "algorithm": f.algorithm,
                        "type": f.algorithm_type,
                        "status": f.status.value,
                        "priority": f.priority.value,
                        "recommended_replacement": f.recommended_replacement,
                        "compliance_issues": f.compliance_issues
                    }
                    for f in summary.findings
                ],
                "compliance_standards": [s.value for s in ComplianceStandard]
            }, indent=2)
        elif format == "markdown":
            md = f"# Post-Quantum Cryptographic Compliance Report\n\n"
            md += f"**Scan ID:** {summary.scan_id}  \n"
            md += f"**Timestamp:** {summary.timestamp}  \n"
            md += f"**PQ Compliance Score:** {summary.compliance_score}%  \n\n"
            
            md += f"## Executive Summary\n\n"
            md += f"- **Files Scanned:** {summary.total_files_scanned}\n"
            md += f"- **Cryptographic Findings:** {summary.total_crypto_findings}\n"
            md += f"- ✅ **Quantum-Safe:** {summary.quantum_safe_count}\n"
            md += f"- ⚠️ **At Risk:** {summary.at_risk_count}\n"
            md += f"- ❌ **Deprecated:** {summary.deprecated_count}\n\n"
            
            md += f"## Risk Assessment\n\n"
            
            # Immediate action required
            immediate = [f for f in summary.findings if f.priority == MigrationPriority.IMMEDIATE]
            if immediate:
                md += f"### 🔴 IMMEDIATE ACTION REQUIRED ({len(immediate)})\n\n"
                for f in immediate[:10]:
                    md += f"- **{f.algorithm}** in `{f.file_path}:{f.line_number}`\n"
                    md += f"  - Issue: {', '.join(f.compliance_issues)}\n"
                    md += f"  - Fix: {f.recommended_replacement}\n\n"
            
            # High priority
            high = [f for f in summary.findings if f.priority == MigrationPriority.HIGH]
            if high:
                md += f"### 🟠 HIGH PRIORITY ({len(high)})\n\n"
                for f in high[:10]:
                    md += f"- **{f.algorithm}** in `{f.file_path}:{f.line_number}`\n"
                    md += f"  - Fix: {f.recommended_replacement}\n\n"
            
            md += f"## Compliance Standards\n\n"
            md += f"- NIST SP 800-186 (Post-Quantum Cryptography Standards)\n"
            md += f"- NSA CNSA 2.0 (Commercial National Security Algorithm Suite)\n"
            md += f"- CISA BOD 25-01 (Quantum-Resistant Cryptography Mandate)\n"
            md += f"- ETSI TS 103 740 (Quantum-Safe Cryptography)\n\n"
            
            return md
        else:
            raise ValueError(f"Unsupported format: {format}")

    def get_migration_plan(self, summary: ScanSummary) -> Dict[str, Any]:
        """Generate prioritized migration plan."""
        migration_items = []
        
        for finding in summary.findings:
            if finding.status != CryptoAlgorithmStatus.QUANTUM_SAFE:
                migration_items.append({
                    "priority": finding.priority.value,
                    "algorithm": finding.algorithm,
                    "location": f"{finding.file_path}:{finding.line_number}",
                    "current_type": finding.algorithm_type,
                    "recommended": finding.recommended_replacement,
                    "deadline": self._get_migration_deadline(finding.priority)
                })
        
        # Sort by priority
        priority_order = {
            MigrationPriority.IMMEDIATE: 0,
            MigrationPriority.HIGH: 1,
            MigrationPriority.MEDIUM: 2,
            MigrationPriority.LOW: 3,
        }
        migration_items.sort(key=lambda x: priority_order.get(x["priority"], 99))
        
        return {
            "total_items_needing_migration": len(migration_items),
            "migration_timeline": {
                "30_days": sum(1 for i in migration_items if i["priority"] == "IMMEDIATE"),
                "90_days": sum(1 for i in migration_items if i["priority"] == "HIGH"),
                "6_months": sum(1 for i in migration_items if i["priority"] == "MEDIUM"),
                "12_months": sum(1 for i in migration_items if i["priority"] == "LOW"),
            },
            "prioritized_actions": migration_items
        }

    def _get_migration_deadline(self, priority: MigrationPriority) -> str:
        """Get recommended migration deadline."""
        deadlines = {
            MigrationPriority.IMMEDIATE: "Within 30 days",
            MigrationPriority.HIGH: "Within 90 days",
            MigrationPriority.MEDIUM: "Within 6 months",
            MigrationPriority.LOW: "Within 12 months",
            MigrationPriority.NONE: "No action required",
        }
        return deadlines.get(priority, "Unknown")

    def _generate_scan_id(self) -> str:
        """Generate unique scan ID."""
        timestamp = datetime.utcnow().isoformat()
        return hashlib.sha256(f"pq_scan_{timestamp}".encode()).hexdigest()[:16]
