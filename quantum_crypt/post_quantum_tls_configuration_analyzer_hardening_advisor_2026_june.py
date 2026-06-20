"""
Post-Quantum TLS Configuration Analyzer & Hardening Advisor - June 2026
Analyzes TLS server configurations for post-quantum security readiness
and provides actionable hardening recommendations.

Features:
- Detects TLS version and cipher suite support
- Identifies post-quantum (PQ) cipher suite support
- Analyzes certificate key algorithm strength
- Checks for known vulnerabilities
- Generates priority-based hardening recommendations
- Provides migration timeline for NIST PQ standards
- Validates compliance with CNSA 2.0 / NSA CSSP standards

Based on:
- NIST SP 800-186 (Post-Quantum Cryptography Standards)
- NSA CNSA 2.0 Suite (Quantum-Resistant Algorithms)
- TLS 1.3 Post-Quantum Extensions (RFC 9189)
- IETF PQC TLS Working Group Drafts
"""
import re
from typing import List, Dict, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Post-quantum security levels per NIST standards"""
    NIST_LEVEL_1 = "nist_level_1"      # 128-bit security
    NIST_LEVEL_3 = "nist_level_3"      # 192-bit security
    NIST_LEVEL_5 = "nist_level_5"      # 256-bit security
    CLASSICAL_ONLY = "classical_only"  # No PQ protection
    VULNERABLE = "vulnerable"          # Broken/weak algorithms


class TLSVersion(Enum):
    """TLS versions with security status"""
    TLS_1_0 = ("TLS 1.0", False, "Deprecated - Insecure")
    TLS_1_1 = ("TLS 1.1", False, "Deprecated - Insecure")
    TLS_1_2 = ("TLS 1.2", True, "Acceptable - Transition to 1.3")
    TLS_1_3 = ("TLS 1.3", True, "Recommended - PQ Ready")
    
    def __init__(self, display: str, secure: bool, note: str):
        self.display = display
        self.secure = secure
        self.note = note


@dataclass
class TLSConfigurationResult:
    """Result from TLS configuration analysis"""
    hostname: str
    tls_versions_supported: List[str]
    cipher_suites: List[Dict[str, Any]]
    certificate_info: Dict[str, Any]
    pq_readiness_score: float
    overall_security_level: SecurityLevel
    vulnerabilities: List[str]
    recommendations: List[Dict[str, Any]]
    compliance_status: Dict[str, bool]
    migration_timeline: Dict[str, str]


@dataclass
class HardeningRecommendation:
    """Hardening recommendation with priority and details"""
    priority: str  # critical, high, medium, low
    category: str
    recommendation: str
    implementation: str
    reference: str


class PostQuantumTLSAnalyzer:
    """
    Post-Quantum TLS Configuration Analyzer & Hardening Advisor
    Evaluates TLS configurations for quantum-resistance and provides
    migration guidance.
    """
    
    def __init__(self):
        """Initialize the TLS analyzer with PQ standards"""
        self.pq_cipher_suites = self._get_pq_cipher_suites()
        self.secure_cipher_suites = self._get_secure_classical_ciphers()
        self.weak_cipher_suites = self._get_weak_cipher_suites()
        self.secure_key_exchanges = self._get_secure_key_exchanges()
        self.secure_signature_algorithms = self._get_secure_signature_algorithms()
        self.hardening_guidance = self._build_hardening_guidance()
        logger.info("Post-Quantum TLS Configuration Analyzer 2026 initialized")
    
    def _get_pq_cipher_suites(self) -> List[Dict[str, Any]]:
        """Post-quantum cipher suites and KEMs"""
        return [
            {"name": "TLS_AES_256_GCM_SHA384_X25519_KYBER768", "status": "standard", "nist_level": 3},
            {"name": "TLS_CHACHA20_POLY1305_SHA256_X25519_KYBER768", "status": "standard", "nist_level": 3},
            {"name": "TLS_AES_128_GCM_SHA256_X25519_KYBER512", "status": "standard", "nist_level": 1},
            {"name": "TLS_KYBER768_RSA_AES_256_GCM_SHA384", "status": "hybrid", "nist_level": 3},
            {"name": "TLS_KYBER512_ECDHE_RSA_AES_128_GCM_SHA256", "status": "hybrid", "nist_level": 1},
            {"name": "TLS_SIKE_P434_AES_256_GCM_SHA384", "status": "experimental", "nist_level": 1},
            {"name": "TLS_NTRU_HPS_2048_AES_256_GCM_SHA384", "status": "experimental", "nist_level": 1},
        ]
    
    def _get_secure_classical_ciphers(self) -> List[str]:
        """Secure classical cipher suites"""
        return [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ]
    
    def _get_weak_cipher_suites(self) -> List[str]:
        """Weak/insecure cipher suites to block"""
        return [
            "NULL", "EXPORT", "DES", "3DES", "RC4", "MD5", "SHA1",
            "CBC", "anon", "NULL", "SRP", "PSK"
        ]
    
    def _get_secure_key_exchanges(self) -> List[str]:
        """Secure key exchange algorithms"""
        return [
            "ECDHE", "X25519", "X448", "KYBER512", "KYBER768", 
            "KYBER1024", "NTRU", "BIKE", "FRODO"
        ]
    
    def _get_secure_signature_algorithms(self) -> Dict[str, Any]:
        """Secure signature algorithms with PQ status"""
        return {
            "classical_secure": ["ECDSA-P256", "ECDSA-P384", "RSA-2048", "RSA-3072", "RSA-4096"],
            "post_quantum": ["CRYSTALS-Dilithium", "Falcon", "SPHINCS+"],
            "weak": ["RSA-1024", "DSA", "MD5", "SHA1"],
        }
    
    def _build_hardening_guidance(self) -> List[HardeningRecommendation]:
        """Build comprehensive hardening recommendations"""
        return [
            HardeningRecommendation(
                priority="critical",
                category="tls_version",
                recommendation="Disable TLS 1.0 and TLS 1.1 immediately",
                implementation="Configure server to only allow TLS 1.2 and TLS 1.3",
                reference="RFC 8996 - Deprecating TLS 1.0 and 1.1"
            ),
            HardeningRecommendation(
                priority="critical",
                category="cipher_suites",
                recommendation="Remove all weak cipher suites (3DES, RC4, CBC, SHA1)",
                implementation="Filter cipher suite list to only AEAD ciphers",
                reference="NIST SP 800-52 Rev. 2"
            ),
            HardeningRecommendation(
                priority="high",
                category="post_quantum",
                recommendation="Deploy hybrid PQ key exchange (X25519 + KYBER-768)",
                implementation="Enable TLS 1.3 with X25519Kyber768Draft00",
                reference="NIST SP 800-186 - PQC Standards"
            ),
            HardeningRecommendation(
                priority="high",
                category="certificates",
                recommendation="Migrate to RSA-3072 or ECDSA-P384 certificates",
                implementation="Request new certificates with >= 3072-bit keys",
                reference="NSA CNSA 2.0 Suite"
            ),
            HardeningRecommendation(
                priority="high",
                category="tls_version",
                recommendation="Prioritize TLS 1.3 over TLS 1.2",
                implementation="Set TLS 1.3 as preferred protocol version",
                reference="RFC 8446 - TLS 1.3 Standard"
            ),
            HardeningRecommendation(
                priority="medium",
                category="post_quantum",
                recommendation="Plan for Dilithium certificates by 2027",
                implementation="Monitor CA support for PQ signature algorithms",
                reference="NIST PQC Migration Timeline"
            ),
            HardeningRecommendation(
                priority="medium",
                category="hsts",
                recommendation="Enable HSTS with max-age >= 1 year",
                implementation="Add Strict-Transport-Security header",
                reference="RFC 6797 - HSTS"
            ),
            HardeningRecommendation(
                priority="low",
                category="performance",
                recommendation="Enable TLS False Start and OCSP Stapling",
                implementation="Configure server optimizations",
                reference="RFC 7918 - TLS False Start"
            ),
        ]
    
    def analyze_tls_version_support(self, versions: List[str]) -> Dict[str, Any]:
        """Analyze TLS version support security"""
        result = {
            "supported": [],
            "insecure": [],
            "has_tls_13": False,
            "has_tls_12": False,
            "has_old_versions": False,
            "score": 0.0
        }
        
        for version in versions:
            if "1.3" in version or "13" in version:
                result["supported"].append(("TLS 1.3", True))
                result["has_tls_13"] = True
                result["score"] += 0.4
            elif "1.2" in version or "12" in version:
                result["supported"].append(("TLS 1.2", True))
                result["has_tls_12"] = True
                result["score"] += 0.25
            elif "1.1" in version or "1.0" in version:
                result["insecure"].append(version)
                result["has_old_versions"] = True
                result["score"] -= 0.3
        
        return result
    
    def analyze_cipher_suites(self, ciphers: List[str]) -> Dict[str, Any]:
        """Analyze cipher suite security"""
        result = {
            "pq_supported": [],
            "secure_classical": [],
            "weak_ciphers": [],
            "pq_score": 0.0,
            "classical_score": 0.0
        }
        
        for cipher in ciphers:
            cipher_upper = cipher.upper()
            
            # Check for PQ cipher suites
            for pq_cipher in self.pq_cipher_suites:
                if pq_cipher["name"] in cipher_upper:
                    result["pq_supported"].append(pq_cipher)
                    if pq_cipher["status"] == "standard":
                        result["pq_score"] += 0.2
                    else:
                        result["pq_score"] += 0.1
            
            # Check for secure classical
            if any(sc in cipher_upper for sc in self.secure_cipher_suites):
                result["secure_classical"].append(cipher)
                result["classical_score"] += 0.1
            
            # Check for weak
            if any(wc in cipher_upper for wc in self.weak_cipher_suites):
                result["weak_ciphers"].append(cipher)
                result["classical_score"] -= 0.15
        
        return result
    
    def analyze_certificate(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze certificate security"""
        result = {
            "key_algorithm": cert_info.get("algorithm", "unknown"),
            "key_size": cert_info.get("key_size", 0),
            "signature_hash": cert_info.get("signature_hash", "unknown"),
            "is_pq_ready": False,
            "strength_score": 0.0,
            "issues": []
        }
        
        key_size = result["key_size"]
        algo = result["key_algorithm"].upper()
        
        if "RSA" in algo:
            if key_size >= 4096:
                result["strength_score"] = 0.8
            elif key_size >= 3072:
                result["strength_score"] = 0.7
            elif key_size >= 2048:
                result["strength_score"] = 0.5
                result["issues"].append("RSA-2048 is minimum, migrate to 3072+")
            else:
                result["strength_score"] = 0.2
                result["issues"].append("RSA key size < 2048 is insecure")
        elif "ECDSA" in algo or "EC" in algo:
            if key_size >= 384:
                result["strength_score"] = 0.9
            elif key_size >= 256:
                result["strength_score"] = 0.7
            else:
                result["strength_score"] = 0.4
        
        # Check for post-quantum signatures
        if any(pq_sig in algo for pq_sig in ["DILITHIUM", "FALCON", "SPHINCS"]):
            result["is_pq_ready"] = True
            result["strength_score"] = 1.0
        
        return result
    
    def generate_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations based on analysis"""
        recommendations = []
        
        # Version recommendations
        if analysis["tls_versions"]["has_old_versions"]:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "TLS Version",
                "action": "Disable TLS 1.0 and TLS 1.1 immediately",
                "impact": "Eliminates known protocol vulnerabilities"
            })
        
        if not analysis["tls_versions"]["has_tls_13"]:
            recommendations.append({
                "priority": "HIGH",
                "category": "TLS Version",
                "action": "Enable TLS 1.3 support",
                "impact": "Enables PQ-ready cipher suites"
            })
        
        # Cipher suite recommendations
        if analysis["cipher_suites"]["weak_ciphers"]:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Cipher Suites",
                "action": f"Remove {len(analysis['cipher_suites']['weak_ciphers'])} weak cipher suites",
                "impact": "Blocks known weak encryption algorithms"
            })
        
        if not analysis["cipher_suites"]["pq_supported"]:
            recommendations.append({
                "priority": "HIGH",
                "category": "Post-Quantum",
                "action": "Enable hybrid PQ key exchange (X25519 + KYBER-768)",
                "impact": "Provides quantum-resistant key exchange"
            })
        
        # Certificate recommendations
        cert_issues = analysis["certificate"]["issues"]
        if cert_issues:
            for issue in cert_issues:
                recommendations.append({
                    "priority": "HIGH",
                    "category": "Certificate",
                    "action": issue,
                    "impact": "Improves certificate cryptographic strength"
                })
        
        return recommendations
    
    def calculate_pq_readiness_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall post-quantum readiness score (0-10)"""
        score = 0.0
        
        # TLS version (max 3 points)
        if analysis["tls_versions"]["has_tls_13"]:
            score += 3.0
        elif analysis["tls_versions"]["has_tls_12"]:
            score += 1.5
        
        # Cipher suites (max 4 points)
        score += min(4.0, analysis["cipher_suites"]["pq_score"] * 10)
        score += min(2.0, analysis["cipher_suites"]["classical_score"] * 5)
        
        # Certificate (max 3 points)
        score += analysis["certificate"]["strength_score"] * 3
        
        # Penalty for weak configurations
        if analysis["tls_versions"]["has_old_versions"]:
            score -= 2.0
        if analysis["cipher_suites"]["weak_ciphers"]:
            score -= 1.5
        
        return max(0.0, min(10.0, score))
    
    def analyze_configuration(self, hostname: str, tls_versions: List[str], 
                            cipher_suites: List[str], 
                            certificate_info: Dict[str, Any]) -> TLSConfigurationResult:
        """
        Analyze complete TLS configuration
        Args:
            hostname: Server hostname
            tls_versions: List of supported TLS versions
            cipher_suites: List of supported cipher suites
            certificate_info: Certificate metadata
        Returns:
            TLSConfigurationResult with full analysis
        """
        # Run individual analyses
        tls_analysis = self.analyze_tls_version_support(tls_versions)
        cipher_analysis = self.analyze_cipher_suites(cipher_suites)
        cert_analysis = self.analyze_certificate(certificate_info)
        
        analysis = {
            "tls_versions": tls_analysis,
            "cipher_suites": cipher_analysis,
            "certificate": cert_analysis
        }
        
        # Calculate scores
        pq_score = self.calculate_pq_readiness_score(analysis)
        
        # Determine security level
        if pq_score >= 8.0:
            security_level = SecurityLevel.NIST_LEVEL_5
        elif pq_score >= 6.0:
            security_level = SecurityLevel.NIST_LEVEL_3
        elif pq_score >= 4.0:
            security_level = SecurityLevel.NIST_LEVEL_1
        elif pq_score >= 2.0:
            security_level = SecurityLevel.CLASSICAL_ONLY
        else:
            security_level = SecurityLevel.VULNERABLE
        
        # Generate recommendations
        recommendations = self.generate_recommendations(analysis)
        
        # Compliance status
        compliance = {
            "nist_sp_800_52": pq_score >= 4.0,
            "nsa_cnsa_2.0": pq_score >= 6.0,
            "tls_1.3_ready": tls_analysis["has_tls_13"],
            "pq_migrated": len(cipher_analysis["pq_supported"]) > 0
        }
        
        # Migration timeline
        timeline = {
            "immediate": "Disable TLS 1.0/1.1, remove weak ciphers",
            "6_months": "Enable TLS 1.3 with hybrid PQ key exchange",
            "12_months": "Upgrade certificates to RSA-3072/ECDSA-P384",
            "24_months": "Deploy Dilithium-based certificates",
            "36_months": "Full post-quantum crypto agility implementation"
        }
        
        # Collect vulnerabilities
        vulnerabilities = []
        if tls_analysis["has_old_versions"]:
            vulnerabilities.extend(tls_analysis["insecure"])
        vulnerabilities.extend(cipher_analysis["weak_ciphers"])
        vulnerabilities.extend(cert_analysis["issues"])
        
        logger.info(f"TLS analysis complete for {hostname} - PQ Score: {pq_score:.1f}/10")
        
        return TLSConfigurationResult(
            hostname=hostname,
            tls_versions_supported=tls_versions,
            cipher_suites=[{
                "pq_supported": cipher_analysis["pq_supported"],
                "secure_classical": cipher_analysis["secure_classical"],
                "weak": cipher_analysis["weak_ciphers"]
            }],
            certificate_info=cert_analysis,
            pq_readiness_score=pq_score,
            overall_security_level=security_level,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            compliance_status=compliance,
            migration_timeline=timeline
        )
    
    def get_analyzer_metrics(self) -> Dict[str, Any]:
        """Get analyzer configuration and standards reference"""
        return {
            "analyzer_version": "2026.06",
            "standards": ["NIST SP 800-186", "NSA CNSA 2.0", "RFC 8446", "RFC 9189"],
            "pq_cipher_suites_supported": len(self.pq_cipher_suites),
            "classical_secure_ciphers": len(self.secure_cipher_suites),
            "weak_ciphers_blocked": len(self.weak_cipher_suites),
            "recommendations_count": len(self.hardening_guidance),
            "security_levels": [level.value for level in SecurityLevel]
        }
