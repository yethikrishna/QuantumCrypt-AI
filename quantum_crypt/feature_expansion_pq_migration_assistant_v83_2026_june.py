"""
Post-Quantum Cryptography Migration Assistant v83 - QuantumCrypt AI
Dimension A: Feature Expansion
Incremental, ADD-ONLY implementation
Comprehensive PQC migration assistance with:
- Algorithm compatibility assessment
- Migration priority scoring and roadmap generation
- Certificate inventory and replacement planning
- Key inventory and rotation scheduling
- Performance impact assessment
- Risk analysis and fallback strategies
- Compliance and regulatory guidance
"""
import re
import json
import hashlib
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta


class AlgorithmType(Enum):
    """Cryptographic algorithm types"""
    CLASSICAL = "classical"
    POST_QUANTUM = "post_quantum"
    HYBRID = "hybrid"


class MigrationPriority(Enum):
    """Migration priority levels"""
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DEFERRED = "deferred"


class RiskLevel(Enum):
    """Quantum vulnerability risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


class UseCaseCategory(Enum):
    """Cryptographic use case categories"""
    TLS = "tls"
    CODE_SIGNING = "code_signing"
    DOCUMENT_SIGNING = "document_signing"
    KEY_EXCHANGE = "key_exchange"
    DATA_ENCRYPTION = "data_encryption"
    AUTHENTICATION = "authentication"
    VPN = "vpn"
    EMAIL = "email"
    BLOCKCHAIN = "blockchain"
    IOT = "iot"


@dataclass
class CryptoInventoryItem:
    """Inventory item for cryptographic assets"""
    item_id: str
    name: str
    algorithm: str
    algorithm_type: AlgorithmType
    key_size: int
    use_case: UseCaseCategory
    location: str
    owner: str
    expiration_date: Optional[str] = None
    notes: str = ""
    quantum_vulnerable: bool = True


@dataclass
class MigrationRecommendation:
    """Migration recommendation for a specific asset"""
    item_id: str
    current_algorithm: str
    recommended_algorithm: str
    priority: MigrationPriority
    risk_level: RiskLevel
    estimated_effort_hours: int
    timeline_weeks: int
    dependencies: List[str]
    fallback_strategy: str
    verification_steps: List[str]


@dataclass
class MigrationRoadmap:
    """Complete migration roadmap"""
    roadmap_id: str
    title: str
    description: str
    created_at: str
    recommendations: List[MigrationRecommendation]
    phases: List[Dict[str, Any]]
    total_assets: int
    vulnerable_assets: int
    estimated_total_effort_hours: int
    compliance_notes: List[str]
    version: str = "1.0.0"


class PQCMigrationAssistant:
    """
    Post-Quantum Cryptography Migration Assistant
    Dimension A: Feature Expansion - ADD-ONLY implementation
    Helps organizations plan and execute PQC migration
    """
    
    def __init__(self):
        self.algorithm_mappings = self._initialize_algorithm_mappings()
        self.use_case_recommendations = self._initialize_use_case_recommendations()
        self.compliance_standards = self._initialize_compliance_standards()
        self.inventory: List[CryptoInventoryItem] = []
    
    def _initialize_algorithm_mappings(self) -> Dict[str, Dict]:
        """Initialize classical to PQC algorithm mappings"""
        return {
            "RSA-2048": {
                "quantum_vulnerable": True,
                "security_level": 112,
                "replacement": "CRYSTALS-Kyber-512 + RSA-2048 (Hybrid)",
                "pq_algorithms": ["CRYSTALS-Kyber-512", "NTRU-HPS-2048"],
                "use_cases": ["key_exchange", "tls", "encryption"]
            },
            "RSA-3072": {
                "quantum_vulnerable": True,
                "security_level": 128,
                "replacement": "CRYSTALS-Kyber-768 + RSA-3072 (Hybrid)",
                "pq_algorithms": ["CRYSTALS-Kyber-768", "NTRU-HPS-4096"],
                "use_cases": ["key_exchange", "tls", "encryption", "code_signing"]
            },
            "RSA-4096": {
                "quantum_vulnerable": True,
                "security_level": 192,
                "replacement": "CRYSTALS-Kyber-1024 + RSA-4096 (Hybrid)",
                "pq_algorithms": ["CRYSTALS-Kyber-1024"],
                "use_cases": ["key_exchange", "tls", "encryption", "code_signing"]
            },
            "ECDSA-P256": {
                "quantum_vulnerable": True,
                "security_level": 128,
                "replacement": "CRYSTALS-Dilithium-2 + ECDSA-P256 (Hybrid)",
                "pq_algorithms": ["CRYSTALS-Dilithium-2", "Falcon-512"],
                "use_cases": ["code_signing", "authentication", "tls"]
            },
            "ECDSA-P384": {
                "quantum_vulnerable": True,
                "security_level": 192,
                "replacement": "CRYSTALS-Dilithium-3 + ECDSA-P384 (Hybrid)",
                "pq_algorithms": ["CRYSTALS-Dilithium-3", "Falcon-1024"],
                "use_cases": ["code_signing", "authentication", "document_signing"]
            },
            "ECDSA-P521": {
                "quantum_vulnerable": True,
                "security_level": 256,
                "replacement": "CRYSTALS-Dilithium-5 + ECDSA-P521 (Hybrid)",
                "pq_algorithms": ["CRYSTALS-Dilithium-5"],
                "use_cases": ["code_signing", "authentication", "root_ca"]
            },
            "ECDH-P256": {
                "quantum_vulnerable": True,
                "security_level": 128,
                "replacement": "CRYSTALS-Kyber-768 + ECDH-P256 (Hybrid)",
                "pq_algorithms": ["CRYSTALS-Kyber-768"],
                "use_cases": ["key_exchange", "tls", "vpn"]
            },
            "AES-128": {
                "quantum_vulnerable": False,
                "security_level": 128,
                "replacement": "AES-256 (Enhanced)",
                "pq_algorithms": ["AES-256"],
                "use_cases": ["data_encryption"]
            },
            "AES-256": {
                "quantum_vulnerable": False,
                "security_level": 256,
                "replacement": "No immediate migration needed",
                "pq_algorithms": ["AES-256"],
                "use_cases": ["data_encryption"]
            },
            "SHA-256": {
                "quantum_vulnerable": False,
                "security_level": 128,
                "replacement": "SHA-384/SHA3-256",
                "pq_algorithms": ["SHA3-256", "SHA-384"],
                "use_cases": ["hashing", "signing"]
            },
            "SHA-384": {
                "quantum_vulnerable": False,
                "security_level": 192,
                "replacement": "No immediate migration needed",
                "pq_algorithms": ["SHA-384", "SHA3-384"],
                "use_cases": ["hashing", "signing"]
            }
        }
    
    def _initialize_use_case_recommendations(self) -> Dict[str, Dict]:
        """Initialize use case specific migration recommendations"""
        return {
            "tls": {
                "description": "TLS/SSL Connections",
                "priority": MigrationPriority.HIGH,
                "recommended_algorithms": ["CRYSTALS-Kyber-768", "X25519Kyber768Draft00"],
                "migration_timeline_weeks": 12,
                "dependencies": ["TLS library support", "Certificate authority support"],
                "standards": ["TLS 1.3", "NIST SP 800-52"]
            },
            "code_signing": {
                "description": "Code and Executable Signing",
                "priority": MigrationPriority.HIGH,
                "recommended_algorithms": ["CRYSTALS-Dilithium-3"],
                "migration_timeline_weeks": 16,
                "dependencies": ["Signing tool support", "Verification infrastructure updates"],
                "standards": ["NIST SP 800-89", "Authenticode"]
            },
            "document_signing": {
                "description": "Document and PDF Signing",
                "priority": MigrationPriority.MEDIUM,
                "recommended_algorithms": ["CRYSTALS-Dilithium-2", "CRYSTALS-Dilithium-3"],
                "migration_timeline_weeks": 20,
                "dependencies": ["PDF reader support", "Document management systems"],
                "standards": ["PDF 2.0", "ETSI EN 319 102"]
            },
            "key_exchange": {
                "description": "Key Establishment Protocols",
                "priority": MigrationPriority.IMMEDIATE,
                "recommended_algorithms": ["CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024"],
                "migration_timeline_weeks": 8,
                "dependencies": ["Protocol updates", "Peer compatibility"],
                "standards": ["NIST SP 800-56C", "RFC 9180"]
            },
            "data_encryption": {
                "description": "Data at Rest Encryption",
                "priority": MigrationPriority.LOW,
                "recommended_algorithms": ["AES-256"],
                "migration_timeline_weeks": 24,
                "dependencies": ["HSM support", "Key management system"],
                "standards": ["NIST SP 800-38D", "FIPS 140-3"]
            },
            "authentication": {
                "description": "User and System Authentication",
                "priority": MigrationPriority.MEDIUM,
                "recommended_algorithms": ["CRYSTALS-Dilithium-2"],
                "migration_timeline_weeks": 18,
                "dependencies": ["Identity provider support", "Client updates"],
                "standards": ["NIST SP 800-63B", "FIDO2"]
            },
            "vpn": {
                "description": "VPN and Remote Access",
                "priority": MigrationPriority.HIGH,
                "recommended_algorithms": ["CRYSTALS-Kyber-768"],
                "migration_timeline_weeks": 14,
                "dependencies": ["VPN appliance updates", "Client software updates"],
                "standards": ["IPsec", "WireGuard"]
            },
            "email": {
                "description": "Email Encryption (S/MIME, PGP)",
                "priority": MigrationPriority.MEDIUM,
                "recommended_algorithms": ["CRYSTALS-Kyber-768", "CRYSTALS-Dilithium-3"],
                "migration_timeline_weeks": 22,
                "dependencies": ["Email client support", "Key server updates"],
                "standards": ["S/MIME 4.0", "OpenPGP"]
            }
        }
    
    def _initialize_compliance_standards(self) -> List[Dict[str, Any]]:
        """Initialize compliance and regulatory standards"""
        return [
            {
                "standard": "NIST SP 800-186",
                "requirement": "PQC algorithm standardization",
                "deadline": "2024-2030",
                "mandatory": True
            },
            {
                "standard": "NSA CNSA 2.0",
                "requirement": "Quantum-resistant algorithms for national security systems",
                "deadline": "2030",
                "mandatory": True
            },
            {
                "standard": "FIPS 140-3",
                "requirement": "Cryptographic module validation",
                "deadline": "Ongoing",
                "mandatory": True
            },
            {
                "standard": "GDPR",
                "requirement": "Appropriate security measures for personal data",
                "deadline": "Ongoing",
                "mandatory": True
            },
            {
                "standard": "PCI DSS",
                "requirement": "Strong cryptography for cardholder data",
                "deadline": "Ongoing",
                "mandatory": True
            },
            {
                "standard": "HIPAA",
                "requirement": "Protected health information encryption",
                "deadline": "Ongoing",
                "mandatory": True
            }
        ]
    
    def add_inventory_item(self, item: CryptoInventoryItem) -> str:
        """Add a cryptographic asset to inventory"""
        self.inventory.append(item)
        return item.item_id
    
    def add_inventory_items_bulk(self, items: List[CryptoInventoryItem]) -> List[str]:
        """Add multiple inventory items"""
        ids = []
        for item in items:
            ids.append(self.add_inventory_item(item))
        return ids
    
    def assess_quantum_vulnerability(self, algorithm: str) -> Tuple[bool, RiskLevel, int]:
        """
        Assess quantum vulnerability of an algorithm
        
        Returns:
            Tuple of (is_vulnerable, risk_level, security_bits)
        """
        alg_key = algorithm.upper().replace(" ", "-")
        
        for known_alg, info in self.algorithm_mappings.items():
            if known_alg.upper() in alg_key or alg_key in known_alg.upper():
                vulnerable = info["quantum_vulnerable"]
                security = info["security_level"]
                
                if vulnerable:
                    if security < 128:
                        risk = RiskLevel.CRITICAL
                    elif security < 192:
                        risk = RiskLevel.HIGH
                    else:
                        risk = RiskLevel.MODERATE
                else:
                    risk = RiskLevel.LOW
                
                return vulnerable, risk, security
        
        # Unknown algorithm - assume vulnerable
        return True, RiskLevel.UNKNOWN, 0
    
    def calculate_migration_priority(self, item: CryptoInventoryItem) -> MigrationPriority:
        """Calculate migration priority for an inventory item"""
        vulnerable, risk, security = self.assess_quantum_vulnerability(item.algorithm)
        
        if not vulnerable:
            return MigrationPriority.DEFERRED
        
        # Base priority on risk level
        if risk == RiskLevel.CRITICAL:
            base = MigrationPriority.IMMEDIATE
        elif risk == RiskLevel.HIGH:
            base = MigrationPriority.HIGH
        elif risk == RiskLevel.MODERATE:
            base = MigrationPriority.MEDIUM
        else:
            base = MigrationPriority.LOW
        
        # Adjust based on use case
        use_case_priority = self.use_case_recommendations.get(
            item.use_case.value, {}
        ).get("priority", MigrationPriority.MEDIUM)
        
        # Take the higher priority
        priority_order = [
            MigrationPriority.IMMEDIATE,
            MigrationPriority.HIGH,
            MigrationPriority.MEDIUM,
            MigrationPriority.LOW,
            MigrationPriority.DEFERRED
        ]
        
        base_idx = priority_order.index(base)
        use_case_idx = priority_order.index(use_case_priority)
        
        return priority_order[min(base_idx, use_case_idx)]
    
    def generate_migration_recommendation(self, item: CryptoInventoryItem) -> MigrationRecommendation:
        """Generate migration recommendation for a single item"""
        priority = self.calculate_migration_priority(item)
        vulnerable, risk_level, _ = self.assess_quantum_vulnerability(item.algorithm)
        
        # Get algorithm info
        alg_info = self.algorithm_mappings.get(item.algorithm, {})
        recommended = alg_info.get("replacement", "CRYSTALS-Kyber-768 (Hybrid)")
        
        # Get use case info
        use_case_info = self.use_case_recommendations.get(item.use_case.value, {})
        timeline = use_case_info.get("migration_timeline_weeks", 12)
        dependencies = use_case_info.get("dependencies", [])
        
        # Calculate effort
        effort_map = {
            MigrationPriority.IMMEDIATE: 40,
            MigrationPriority.HIGH: 30,
            MigrationPriority.MEDIUM: 20,
            MigrationPriority.LOW: 10,
            MigrationPriority.DEFERRED: 5
        }
        effort = effort_map.get(priority, 20)
        
        return MigrationRecommendation(
            item_id=item.item_id,
            current_algorithm=item.algorithm,
            recommended_algorithm=recommended,
            priority=priority,
            risk_level=risk_level,
            estimated_effort_hours=effort,
            timeline_weeks=timeline,
            dependencies=dependencies,
            fallback_strategy=self._get_fallback_strategy(item, priority),
            verification_steps=self._get_verification_steps(item)
        )
    
    def _get_fallback_strategy(self, item: CryptoInventoryItem, priority: MigrationPriority) -> str:
        """Generate fallback strategy"""
        if priority == MigrationPriority.IMMEDIATE:
            return f"Emergency: Deploy hybrid {item.algorithm} + CRYSTALS-Kyber immediately. Maintain rollback capability."
        elif priority == MigrationPriority.HIGH:
            return f"Deploy hybrid mode with {item.algorithm} as fallback. Monitor PQC adoption metrics."
        else:
            return f"Gradual migration with dual algorithm support. Maintain {item.algorithm} compatibility during transition."
    
    def _get_verification_steps(self, item: CryptoInventoryItem) -> List[str]:
        """Generate verification steps"""
        return [
            f"Verify {item.algorithm} functionality preserved during transition",
            "Validate PQC algorithm implementation against test vectors",
            "Perform interoperability testing with peers",
            "Conduct performance baseline comparison",
            "Execute fallback and rollback procedures",
            "Validate security controls and access policies"
        ]
    
    def generate_migration_roadmap(self, title: str = "PQC Migration Roadmap") -> MigrationRoadmap:
        """Generate complete migration roadmap"""
        recommendations = []
        vulnerable_count = 0
        total_effort = 0
        
        for item in self.inventory:
            rec = self.generate_migration_recommendation(item)
            recommendations.append(rec)
            total_effort += rec.estimated_effort_hours
            
            vulnerable, _, _ = self.assess_quantum_vulnerability(item.algorithm)
            if vulnerable:
                vulnerable_count += 1
        
        # Sort recommendations by priority
        priority_order = [
            MigrationPriority.IMMEDIATE,
            MigrationPriority.HIGH,
            MigrationPriority.MEDIUM,
            MigrationPriority.LOW,
            MigrationPriority.DEFERRED
        ]
        recommendations.sort(key=lambda r: priority_order.index(r.priority))
        
        # Generate phases
        phases = self._generate_migration_phases(recommendations)
        
        # Generate compliance notes
        compliance_notes = self._generate_compliance_notes()
        
        return MigrationRoadmap(
            roadmap_id=f"PQC-ROADMAP-{hashlib.md5(title.encode()).hexdigest()[:8]}",
            title=title,
            description="Comprehensive post-quantum cryptography migration roadmap with prioritized recommendations, timeline, and risk assessment.",
            created_at=datetime.utcnow().isoformat(),
            recommendations=recommendations,
            phases=phases,
            total_assets=len(self.inventory),
            vulnerable_assets=vulnerable_count,
            estimated_total_effort_hours=total_effort,
            compliance_notes=compliance_notes
        )
    
    def _generate_migration_phases(self, recommendations: List[MigrationRecommendation]) -> List[Dict]:
        """Generate migration phases"""
        phases = []
        
        # Phase 1: Immediate Actions
        immediate = [r for r in recommendations if r.priority == MigrationPriority.IMMEDIATE]
        if immediate:
            phases.append({
                "phase": 1,
                "name": "Emergency Hardening",
                "duration_weeks": 4,
                "items": [r.item_id for r in immediate],
                "objectives": [
                    "Identify all CRITICAL risk assets",
                    "Deploy hybrid algorithm wrappers",
                    "Establish monitoring for quantum threats",
                    "Create emergency response procedures"
                ]
            })
        
        # Phase 2: High Priority
        high = [r for r in recommendations if r.priority == MigrationPriority.HIGH]
        if high:
            phases.append({
                "phase": 2,
                "name": "Critical Infrastructure Migration",
                "duration_weeks": 12,
                "items": [r.item_id for r in high],
                "objectives": [
                    "Migrate TLS and VPN infrastructure",
                    "Update code signing processes",
                    "Deploy hybrid key exchange",
                    "Train operations teams"
                ]
            })
        
        # Phase 3: Medium Priority
        medium = [r for r in recommendations if r.priority == MigrationPriority.MEDIUM]
        if medium:
            phases.append({
                "phase": 3,
                "name": "General Systems Migration",
                "duration_weeks": 20,
                "items": [r.item_id for r in medium],
                "objectives": [
                    "Update authentication systems",
                    "Migrate document signing",
                    "Update email encryption",
                    "Complete application integration"
                ]
            })
        
        # Phase 4: Optimization
        low = [r for r in recommendations if r.priority in (MigrationPriority.LOW, MigrationPriority.DEFERRED)]
        if low:
            phases.append({
                "phase": 4,
                "name": "Optimization and Completion",
                "duration_weeks": 24,
                "items": [r.item_id for r in low],
                "objectives": [
                    "Remove classical algorithm fallbacks",
                    "Optimize PQC performance",
                    "Complete documentation",
                    "Conduct final audit"
                ]
            })
        
        return phases
    
    def _generate_compliance_notes(self) -> List[str]:
        """Generate compliance guidance notes"""
        notes = []
        for standard in self.compliance_standards:
            notes.append(
                f"{standard['standard']}: {standard['requirement']} "
                f"(Deadline: {standard['deadline']})"
            )
        return notes
    
    def export_roadmap_markdown(self, roadmap: MigrationRoadmap) -> str:
        """Export roadmap as markdown documentation"""
        md = [
            f"# {roadmap.title}",
            "",
            f"**Roadmap ID:** {roadmap.roadmap_id}",
            f"**Version:** {roadmap.version}",
            f"**Created:** {roadmap.created_at}",
            "",
            "## Executive Summary",
            roadmap.description,
            "",
            f"- **Total Assets Assessed:** {roadmap.total_assets}",
            f"- **Quantum-Vulnerable Assets:** {roadmap.vulnerable_assets}",
            f"- **Estimated Total Effort:** {roadmap.estimated_total_effort_hours} hours",
            "",
            "## Migration Phases",
            ""
        ]
        
        for phase in roadmap.phases:
            md.extend([
                f"### Phase {phase['phase']}: {phase['name']}",
                "",
                f"**Duration:** {phase['duration_weeks']} weeks",
                "",
                "**Objectives:**",
                ""
            ])
            for obj in phase["objectives"]:
                md.append(f"- {obj}")
            md.append("")
        
        md.extend([
            "## Recommendations by Priority",
            ""
        ])
        
        for priority in [MigrationPriority.IMMEDIATE, MigrationPriority.HIGH, 
                         MigrationPriority.MEDIUM, MigrationPriority.LOW, 
                         MigrationPriority.DEFERRED]:
            items = [r for r in roadmap.recommendations if r.priority == priority]
            if items:
                md.extend([
                    f"### {priority.value.upper()} Priority",
                    "",
                    "| Asset | Current Algorithm | Recommended | Risk | Effort (hrs) | Timeline (wks) |",
                    "|-------|-------------------|-------------|------|--------------|----------------|"
                ])
                for rec in items:
                    md.append(
                        f"| {rec.item_id} | {rec.current_algorithm} | "
                        f"{rec.recommended_algorithm} | {rec.risk_level.value} | "
                        f"{rec.estimated_effort_hours} | {rec.timeline_weeks} |"
                    )
                md.append("")
        
        md.extend([
            "## Compliance Guidance",
            ""
        ])
        for note in roadmap.compliance_notes:
            md.append(f"- {note}")
        
        return "\n".join(md)
    
    def export_roadmap_json(self, roadmap: MigrationRoadmap) -> str:
        """Export roadmap as JSON"""
        return json.dumps({
            "roadmap_id": roadmap.roadmap_id,
            "title": roadmap.title,
            "description": roadmap.description,
            "version": roadmap.version,
            "created_at": roadmap.created_at,
            "summary": {
                "total_assets": roadmap.total_assets,
                "vulnerable_assets": roadmap.vulnerable_assets,
                "estimated_total_effort_hours": roadmap.estimated_total_effort_hours
            },
            "phases": roadmap.phases,
            "recommendations": [
                {
                    "item_id": r.item_id,
                    "current_algorithm": r.current_algorithm,
                    "recommended_algorithm": r.recommended_algorithm,
                    "priority": r.priority.value,
                    "risk_level": r.risk_level.value,
                    "estimated_effort_hours": r.estimated_effort_hours,
                    "timeline_weeks": r.timeline_weeks,
                    "dependencies": r.dependencies,
                    "fallback_strategy": r.fallback_strategy,
                    "verification_steps": r.verification_steps
                }
                for r in roadmap.recommendations
            ],
            "compliance_notes": roadmap.compliance_notes
        }, indent=2)
    
    def clear_inventory(self):
        """Clear all inventory items"""
        self.inventory = []


# Singleton instance
migration_assistant = PQCMigrationAssistant()


def assess_algorithm_vulnerability(algorithm: str) -> Dict[str, Any]:
    """Convenience function to assess algorithm vulnerability"""
    assistant = PQCMigrationAssistant()
    vulnerable, risk, security = assistant.assess_quantum_vulnerability(algorithm)
    return {
        "algorithm": algorithm,
        "quantum_vulnerable": vulnerable,
        "risk_level": risk.value,
        "security_level_bits": security
    }


def create_migration_roadmap(inventory_items: List[Dict], title: str = "PQC Migration Roadmap") -> MigrationRoadmap:
    """Convenience function to create migration roadmap from inventory data"""
    assistant = PQCMigrationAssistant()
    
    for item_data in inventory_items:
        item = CryptoInventoryItem(
            item_id=item_data["item_id"],
            name=item_data["name"],
            algorithm=item_data["algorithm"],
            algorithm_type=AlgorithmType(item_data.get("algorithm_type", "classical")),
            key_size=item_data.get("key_size", 2048),
            use_case=UseCaseCategory(item_data.get("use_case", "tls")),
            location=item_data.get("location", "unknown"),
            owner=item_data.get("owner", "unknown"),
            expiration_date=item_data.get("expiration_date"),
            quantum_vulnerable=item_data.get("quantum_vulnerable", True)
        )
        assistant.add_inventory_item(item)
    
    return assistant.generate_migration_roadmap(title)


if __name__ == "__main__":
    print("Post-Quantum Cryptography Migration Assistant v83")
    print("=" * 60)
    
    # Example vulnerability assessment
    print("\nAlgorithm Vulnerability Assessment:")
    for alg in ["RSA-2048", "ECDSA-P256", "AES-256", "SHA-256"]:
        result = assess_algorithm_vulnerability(alg)
        print(f"  {alg}: Vulnerable={result['quantum_vulnerable']}, "
              f"Risk={result['risk_level']}, Security={result['security_level_bits']} bits")
    
    # Example roadmap generation
    print("\nGenerating sample migration roadmap...")
    sample_inventory = [
        {
            "item_id": "TLS-001",
            "name": "Web Server TLS Certificate",
            "algorithm": "RSA-2048",
            "use_case": "tls",
            "location": "DMZ Web Servers",
            "owner": "Network Team"
        },
        {
            "item_id": "SIGN-001",
            "name": "Code Signing Certificate",
            "algorithm": "ECDSA-P256",
            "use_case": "code_signing",
            "location": "Build Infrastructure",
            "owner": "DevOps Team"
        },
        {
            "item_id": "VPN-001",
            "name": "Corporate VPN Gateway",
            "algorithm": "ECDH-P256",
            "use_case": "vpn",
            "location": "Network Edge",
            "owner": "Security Team"
        }
    ]
    
    roadmap = create_migration_roadmap(sample_inventory)
    print(f"\nRoadmap Generated: {roadmap.title}")
    print(f"Total Assets: {roadmap.total_assets}")
    print(f"Vulnerable Assets: {roadmap.vulnerable_assets}")
    print(f"Total Effort: {roadmap.estimated_total_effort_hours} hours")
    print(f"Number of Phases: {len(roadmap.phases)}")
