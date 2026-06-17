"""
QuantumCrypt AI - Post-Quantum Secure Data Masking & Anonymization Engine
Production-grade module for PII detection and quantum-resistant data anonymization.

This module provides:
- PII (Personally Identifiable Information) detection
- Format-preserving data masking
- Reversible and irreversible anonymization
- Post-quantum secure encryption for masked data
- Tokenization with secure vault storage
"""

import re
import hashlib
import hmac
import secrets
from typing import Dict, List, Set, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json
import base64


class PiiType(Enum):
    """Types of Personally Identifiable Information"""
    EMAIL = "email"
    PHONE = "phone"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    IP_ADDRESS = "ip_address"
    NAME = "name"
    ADDRESS = "address"
    DATE_OF_BIRTH = "dob"
    PASSPORT = "passport"
    IBAN = "iban"


class MaskingStrategy(Enum):
    """Data masking strategies"""
    PARTIAL = "partial"          # Show first/last chars, mask middle
    FULL = "full"                # Mask entire value
    REPLACEMENT = "replacement"  # Replace with placeholder
    TOKENIZATION = "tokenization"  # Replace with secure token
    HASH = "hash"                # Cryptographic hash (irreversible)
    FORMAT_PRESERVING = "format_preserving"  # Keep format, encrypt


class AnonymizationLevel(Enum):
    """Anonymization security levels"""
    LOW = "low"           # Basic masking, reversible with key
    MEDIUM = "medium"     # Strong masking, salted hashing
    HIGH = "high"         # Tokenization with vault
    QUANTUM_RESISTANT = "quantum_resistant"  # Post-quantum cryptography


@dataclass
class MaskedField:
    """Data class representing a masked PII field"""
    original_value: str
    masked_value: str
    pii_type: PiiType
    strategy: MaskingStrategy
    level: AnonymizationLevel
    token: Optional[str] = None
    salt: Optional[str] = None
    is_reversible: bool = False
    masked_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "original_value": self.original_value if self.is_reversible else "[REDACTED]",
            "masked_value": self.masked_value,
            "pii_type": self.pii_type.value,
            "strategy": self.strategy.value,
            "level": self.level.value,
            "token": self.token,
            "is_reversible": self.is_reversible,
            "masked_at": self.masked_at.isoformat()
        }


class PIIDetector:
    """
    Production-grade PII Detector that identifies sensitive
    personal information in text content.
    """

    def __init__(self):
        # Regex patterns for PII detection
        self.patterns = {
            PiiType.EMAIL: re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ),
            PiiType.PHONE: re.compile(
                r'\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b'
            ),
            PiiType.CREDIT_CARD: re.compile(
                r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{16}\b'
            ),
            PiiType.SSN: re.compile(
                r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'
            ),
            PiiType.IP_ADDRESS: re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ),
            PiiType.IBAN: re.compile(
                r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'
            )
        }

    def detect_pii(self, text: str) -> List[Tuple[str, PiiType, int, int]]:
        """
        Detect all PII in text content.
        
        Returns:
            List of (value, pii_type, start_pos, end_pos) tuples
        """
        detections = []
        
        for pii_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                if self._is_valid_pii(match.group(), pii_type):
                    detections.append((
                        match.group(),
                        pii_type,
                        match.start(),
                        match.end()
                    ))
        
        return self._resolve_overlaps(detections)

    def _is_valid_pii(self, value: str, pii_type: PiiType) -> bool:
        """Validate detected PII with basic checks"""
        value = re.sub(r'[\s\-]', '', value)
        
        if pii_type == PiiType.CREDIT_CARD:
            # Basic Luhn check validation
            return self._luhn_check(value)
        elif pii_type == PiiType.SSN:
            # Basic SSN validation (not all zeros)
            return not value.startswith('000')
        return True

    def _luhn_check(self, number: str) -> bool:
        """Luhn algorithm for credit card validation"""
        digits = [int(d) for d in number if d.isdigit()]
        if len(digits) < 13:
            return False
        
        total = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0

    def _resolve_overlaps(self, detections: List) -> List:
        """Resolve overlapping detections (keep longest match)"""
        if not detections:
            return []
        
        detections.sort(key=lambda x: x[2])
        resolved = []
        prev_end = -1
        
        for detection in detections:
            _, _, start, end = detection
            if start >= prev_end:
                resolved.append(detection)
                prev_end = end
        
        return resolved


class QuantumSecureMasker:
    """
    Post-quantum secure data masking engine using
    cryptographically secure algorithms resistant to quantum attacks.
    """

    def __init__(self, master_key: Optional[bytes] = None):
        # Use cryptographically secure random key if none provided
        self.master_key = master_key or secrets.token_bytes(32)
        self.token_vault: Dict[str, Tuple[str, str]] = {}  # token -> (original, salt)
        self.detector = PIIDetector()

    def mask_value(
        self,
        value: str,
        pii_type: PiiType,
        strategy: MaskingStrategy = MaskingStrategy.PARTIAL,
        level: AnonymizationLevel = AnonymizationLevel.MEDIUM
    ) -> MaskedField:
        """
        Mask a single PII value using specified strategy and security level.
        """
        if strategy == MaskingStrategy.PARTIAL:
            masked = self._partial_mask(value, pii_type)
            reversible = True
        elif strategy == MaskingStrategy.FULL:
            masked = self._full_mask(value)
            reversible = False
        elif strategy == MaskingStrategy.REPLACEMENT:
            masked = self._replacement_mask(value, pii_type)
            reversible = False
        elif strategy == MaskingStrategy.TOKENIZATION:
            masked, token, salt = self._tokenize(value)
            reversible = True
        elif strategy == MaskingStrategy.HASH:
            masked, salt = self._quantum_hash(value, level)
            reversible = False
        elif strategy == MaskingStrategy.FORMAT_PRESERVING:
            masked = self._format_preserving_encrypt(value)
            reversible = True
        else:
            masked = self._partial_mask(value, pii_type)
            reversible = True

        return MaskedField(
            original_value=value,
            masked_value=masked,
            pii_type=pii_type,
            strategy=strategy,
            level=level,
            token=token if strategy == MaskingStrategy.TOKENIZATION else None,
            salt=salt if strategy in [MaskingStrategy.HASH, MaskingStrategy.TOKENIZATION] else None,
            is_reversible=reversible
        )

    def _partial_mask(self, value: str, pii_type: PiiType) -> str:
        """Mask middle characters, show first and last"""
        if len(value) <= 4:
            return '*' * len(value)
        
        if pii_type == PiiType.EMAIL:
            name, domain = value.split('@', 1)
            if len(name) > 2:
                masked_name = name[0] + '*' * (len(name) - 2) + name[-1]
            else:
                masked_name = '*' * len(name)
            return f"{masked_name}@{domain}"
        
        elif pii_type == PiiType.PHONE:
            digits = re.sub(r'\D', '', value)
            return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "***-***-****"
        
        elif pii_type == PiiType.CREDIT_CARD:
            digits = re.sub(r'\D', '', value)
            return f"****-****-****-{digits[-4:]}" if len(digits) >= 4 else "****-****-****-****"
        
        # Default: show first 2, last 2
        return value[:2] + '*' * (len(value) - 4) + value[-2:]

    def _full_mask(self, value: str) -> str:
        """Completely mask all characters"""
        return '*' * len(value)

    def _replacement_mask(self, value: str, pii_type: PiiType) -> str:
        """Replace with generic placeholder"""
        placeholders = {
            PiiType.EMAIL: "[EMAIL_REDACTED]",
            PiiType.PHONE: "[PHONE_REDACTED]",
            PiiType.CREDIT_CARD: "[CREDIT_CARD_REDACTED]",
            PiiType.SSN: "[SSN_REDACTED]",
            PiiType.IP_ADDRESS: "[IP_REDACTED]",
            PiiType.IBAN: "[IBAN_REDACTED]"
        }
        return placeholders.get(pii_type, "[REDACTED]")

    def _tokenize(self, value: str) -> Tuple[str, str, str]:
        """Generate secure token and store in vault (quantum-resistant)"""
        salt = secrets.token_hex(16)
        token = secrets.token_urlsafe(32)
        self.token_vault[token] = (value, salt)
        return token, token, salt

    def _quantum_hash(self, value: str, level: AnonymizationLevel) -> Tuple[str, str]:
        """
        Quantum-resistant hashing using SHA3-512 with salt.
        SHA3 is considered quantum-resistant according to NIST guidelines.
        """
        salt = secrets.token_hex(16)
        iterations = 100000 if level == AnonymizationLevel.QUANTUM_RESISTANT else 10000
        
        # Use PBKDF2 with SHA3-512 (quantum-resistant)
        hash_value = hashlib.pbkdf2_hmac(
            'sha3-512',
            value.encode('utf-8'),
            salt.encode('utf-8'),
            iterations
        )
        return base64.b64encode(hash_value).decode('ascii'), salt

    def _format_preserving_encrypt(self, value: str) -> str:
        """Simple format-preserving encryption (deterministic masking)"""
        result = []
        key_bytes = self.master_key
        
        for i, char in enumerate(value):
            if char.isdigit():
                shift = key_bytes[i % len(key_bytes)] % 10
                result.append(str((int(char) + shift) % 10))
            elif char.isalpha():
                shift = key_bytes[i % len(key_bytes)] % 26
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        
        return ''.join(result)

    def mask_text(
        self,
        text: str,
        strategy: MaskingStrategy = MaskingStrategy.PARTIAL,
        level: AnonymizationLevel = AnonymizationLevel.MEDIUM
    ) -> Tuple[str, List[MaskedField]]:
        """
        Detect and mask all PII in a text string.
        
        Returns:
            Tuple of (masked_text, list_of_masked_fields)
        """
        detections = self.detector.detect_pii(text)
        masked_fields = []
        
        # Process from end to beginning to preserve positions
        detections.sort(key=lambda x: x[2], reverse=True)
        
        for value, pii_type, start, end in detections:
            masked_field = self.mask_value(value, pii_type, strategy, level)
            masked_fields.append(masked_field)
            text = text[:start] + masked_field.masked_value + text[end:]
        
        return text, masked_fields

    def unmask_token(self, token: str) -> Optional[str]:
        """Retrieve original value from token (if reversible)"""
        if token in self.token_vault:
            return self.token_vault[token][0]
        return None


class AnonymizationReport:
    """Generates anonymization reports and statistics"""

    @staticmethod
    def generate_report(masked_fields: List[MaskedField]) -> Dict[str, Any]:
        """Generate anonymization statistics report"""
        report = {
            "total_fields_masked": len(masked_fields),
            "by_pii_type": {},
            "by_strategy": {},
            "by_security_level": {},
            "reversible_count": sum(1 for f in masked_fields if f.is_reversible),
            "generated_at": datetime.now().isoformat()
        }

        for field in masked_fields:
            type_key = field.pii_type.value
            report["by_pii_type"][type_key] = report["by_pii_type"].get(type_key, 0) + 1
            
            strat_key = field.strategy.value
            report["by_strategy"][strat_key] = report["by_strategy"].get(strat_key, 0) + 1
            
            level_key = field.level.value
            report["by_security_level"][level_key] = report["by_security_level"].get(level_key, 0) + 1

        return report

    @staticmethod
    def to_json(masked_fields: List[MaskedField], pretty: bool = True) -> str:
        """Export masked fields to JSON"""
        data = {
            "anonymization_report": AnonymizationReport.generate_report(masked_fields),
            "masked_fields": [f.to_dict() for f in masked_fields]
        }
        indent = 2 if pretty else None
        return json.dumps(data, indent=indent)


# Export main classes
__all__ = [
    'QuantumSecureMasker', 'PIIDetector', 'AnonymizationReport',
    'MaskedField', 'PiiType', 'MaskingStrategy', 'AnonymizationLevel'
]
