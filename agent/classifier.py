"""Machine Learning & Heuristic Classifier for Domain Generation Algorithms (DGA).

Provides feature extraction, statistical entropy computation, anomaly detection,
and risk classification for suspected malicious and algorithmically generated domains.
Designed for high throughput and zero external heavy dependencies, with native
explainability signals for SOC and Incident Response analysts.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# Known high-risk TLDs commonly abused by malware campaigns and DGAs
HIGH_RISK_TLDS = {
    "xyz", "top", "online", "ru", "cc", "click", "live", "fit", "surf",
    "work", "vip", "loan", "stream", "gq", "cf", "ml", "ga", "tk", "bid",
    "win", "monster", "icu", "bar", "kim", "pw", "support", "rest", "cam"
}

LOW_RISK_TLDS = {
    "gov", "edu", "org", "mil", "int", "gov.pt", "edu.pt", "ac.uk"
}

# Vowels set (Latin alphabet)
VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


@dataclass
class DomainFeatures:
    """Numerical and categorical features extracted from a domain name."""
    domain: str
    main_label: str
    length: int
    entropy: float
    vowel_ratio: float
    consonant_ratio: float
    max_consecutive_consonants: int
    max_consecutive_digits: int
    digit_ratio: float
    hex_ratio: float
    subdomain_count: int
    hyphen_count: int
    tld: str
    is_high_risk_tld: bool
    is_low_risk_tld: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert features to dictionary representation."""
        return asdict(self)


@dataclass
class PredictionResult:
    """Classification outcome including risk score, verdict, and explainable signals."""
    domain: str
    risk_score: float  # Normalized 0.0 to 1.0
    verdict: str       # BENIGN, SUSPICIOUS, HIGH_RISK_DGA
    confidence: float  # Estimated prediction confidence (0.0 to 1.0)
    signals: List[str] = field(default_factory=list)
    features: Optional[DomainFeatures] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert prediction result to dictionary."""
        data = asdict(self)
        if self.features:
            data["features"] = self.features.to_dict()
        return data


class DomainClassifier:
    """DGA and Anomaly Detection Classifier for Network Domains.

    Combines:
    1. Shannon Information Entropy of the main domain label.
    2. Character distribution analytics (vowel/consonant ratios, consecutive clusters).
    3. Hexadecimal and digit dispersion analysis.
    4. Top-Level Domain (TLD) reputation heuristics.
    5. Structural subdomain depth evaluation.
    """

    def __init__(self, risk_threshold_suspicious: float = 0.40, risk_threshold_high: float = 0.70) -> None:
        self.threshold_suspicious = risk_threshold_suspicious
        self.threshold_high = risk_threshold_high

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculates Shannon entropy in bits for a given text string.

        H(X) = - sum(p(x) * log2(p(x)))
        Higher values (> 3.5 bits for typical words) indicate pseudo-random characters.
        """
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def _split_domain_parts(domain: str) -> Tuple[str, str, int]:
        """Splits domain into (main_label, tld, subdomain_count).

        Example:
            'evil-c2.malware.example.com' -> ('example', 'com', 2)
            'xzkfplwq987123.top' -> ('xzkfplwq987123', 'top', 0)
        """
        clean = domain.strip().lower().rstrip(".")
        parts = clean.split(".")
        if len(parts) <= 1:
            return clean, "", 0

        # Heuristic for multi-part TLDs (e.g. .co.uk, .gov.pt, .com.br)
        if len(parts) >= 3 and parts[-2] in {"co", "com", "gov", "edu", "org", "net"} and len(parts[-1]) == 2:
            tld = f"{parts[-2]}.{parts[-1]}"
            main_label = parts[-3]
            subdomain_count = len(parts) - 3
        else:
            tld = parts[-1]
            main_label = parts[-2]
            subdomain_count = len(parts) - 2

        return main_label, tld, max(0, subdomain_count)

    def extract_features(self, domain: str) -> DomainFeatures:
        """Extracts statistical, lexical, and structural features from a domain."""
        clean_domain = domain.strip().lower().rstrip(".")
        main_label, tld, subdomain_count = self._split_domain_parts(clean_domain)

        # Label length (focusing on the SLD / algorithmically generated part)
        label_len = max(len(main_label), 1)

        # Entropy of the primary label
        entropy = self.calculate_shannon_entropy(main_label)

        # Character counts
        vowels_count = sum(1 for c in main_label if c in VOWELS)
        consonants_count = sum(1 for c in main_label if c in CONSONANTS)
        digits_count = sum(1 for c in main_label if c.isdigit())
        hex_count = sum(1 for c in main_label if c in "0123456789abcdef")
        hyphen_count = main_label.count("-")

        vowel_ratio = round(vowels_count / label_len, 4)
        consonant_ratio = round(consonants_count / label_len, 4)
        digit_ratio = round(digits_count / label_len, 4)
        hex_ratio = round(hex_count / label_len, 4)

        # Maximum consecutive consonants streak
        max_cons = 0
        current_cons = 0
        for c in main_label:
            if c in CONSONANTS:
                current_cons += 1
                if current_cons > max_cons:
                    max_cons = current_cons
            else:
                current_cons = 0

        # Maximum consecutive digits streak
        max_digits = 0
        current_digits = 0
        for c in main_label:
            if c.isdigit():
                current_digits += 1
                if current_digits > max_digits:
                    max_digits = current_digits
            else:
                current_digits = 0

        is_high_risk_tld = tld in HIGH_RISK_TLDS
        is_low_risk_tld = tld in LOW_RISK_TLDS

        return DomainFeatures(
            domain=clean_domain,
            main_label=main_label,
            length=len(main_label),
            entropy=entropy,
            vowel_ratio=vowel_ratio,
            consonant_ratio=consonant_ratio,
            max_consecutive_consonants=max_cons,
            max_consecutive_digits=max_digits,
            digit_ratio=digit_ratio,
            hex_ratio=hex_ratio,
            subdomain_count=subdomain_count,
            hyphen_count=hyphen_count,
            tld=tld,
            is_high_risk_tld=is_high_risk_tld,
            is_low_risk_tld=is_low_risk_tld,
        )

    def predict(self, domain: str) -> PredictionResult:
        """Classifies a domain and calculates its threat / DGA risk score."""
        features = self.extract_features(domain)
        signals: List[str] = []
        score = 0.0

        label = features.main_label
        length = features.length
        entropy = features.entropy

        # 1. Entropy Evaluation (Normal English/Portuguese is ~2.0 - 3.2 bits for typical words)
        if length >= 8:
            if entropy >= 4.0:
                score += 0.35
                signals.append(f"Entropia muito elevada ({entropy:.2f} bits) - forte indicador de DGA")
            elif entropy >= 3.5:
                score += 0.25
                signals.append(f"Entropia elevada ({entropy:.2f} bits)")
            elif entropy <= 1.5 and length > 10:
                score += 0.15
                signals.append(f"Entropia anormalmente baixa com repetições ({entropy:.2f} bits)")
        elif length >= 5 and entropy >= 3.2:
            score += 0.15
            signals.append(f"Entropia considerável para o tamanho ({entropy:.2f} bits)")

        # 2. Consecutive Consonants Streak (Classic DGA hallmark)
        if features.max_consecutive_consonants >= 6:
            score += 0.35
            signals.append(f"{features.max_consecutive_consonants} consoantes consecutivas (padrao aleatorio)")
        elif features.max_consecutive_consonants == 5:
            score += 0.25
            signals.append("5 consoantes consecutivas detetadas")
        elif features.max_consecutive_consonants == 4 and length > 7:
            score += 0.12
            signals.append("4 consoantes consecutivas detetadas")

        # 3. Vowel / Consonant Imbalance
        if length >= 7:
            if features.vowel_ratio == 0.0:
                score += 0.30
                signals.append("Ausência total de vogais no rótulo principal")
            elif features.vowel_ratio < 0.12:
                score += 0.20
                signals.append(f"Rácio de vogais muito baixo ({features.vowel_ratio * 100:.1f}%)")
            elif features.vowel_ratio > 0.70 and length >= 8:
                score += 0.15
                signals.append(f"Rácio de vogais anormalmente elevado ({features.vowel_ratio * 100:.1f}%)")

        # 4. Digit and Hexadecimal Patterns
        if features.max_consecutive_digits >= 6:
            score += 0.20
            signals.append(f"{features.max_consecutive_digits} dígitos consecutivos no nome")
        elif features.digit_ratio > 0.50 and length >= 6:
            score += 0.18
            signals.append(f"Elevada percentagem de números ({features.digit_ratio * 100:.1f}%)")

        # Hexadecimal hash string pattern (e.g. md5/sha hash subdomain/domain)
        if length >= 12 and features.hex_ratio == 1.0 and any(c.isdigit() for c in label) and any(c.isalpha() for c in label):
            score += 0.25
            signals.append("Rótulo com padrão de hash hexadecimal puro (MD5/SHA)")

        # 5. Length Analysis
        if length >= 25:
            score += 0.20
            signals.append(f"Extensão incomum do domínio ({length} caracteres)")
        elif length >= 16:
            score += 0.10
            signals.append(f"Domínio longo ({length} caracteres)")

        # 6. TLD Risk Adjustment
        if features.is_high_risk_tld:
            score += 0.18
            signals.append(f"TLD com histórico de abuso / alto risco (.{features.tld})")
        elif features.is_low_risk_tld:
            score = max(0.0, score - 0.25)

        # 7. Multiple Subdomain Depth (Tunneling / DGA CDN indicators)
        if features.subdomain_count >= 3:
            score += 0.15
            signals.append(f"Múltiplos níveis de subdomínios ({features.subdomain_count} níveis)")

        # Normalization (clamp to [0.0, 1.0])
        final_score = round(min(max(score, 0.0), 1.0), 3)

        # Verdict assignment
        if final_score >= self.threshold_high:
            verdict = "HIGH_RISK_DGA"
        elif final_score >= self.threshold_suspicious:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"
            if not signals:
                signals.append("Distribuição léxica e entropia compatíveis com domínio legítimo")

        # Confidence estimate based on score separation from boundaries
        if verdict == "HIGH_RISK_DGA":
            confidence = round(0.70 + (final_score - self.threshold_high) * 0.9, 2)
        elif verdict == "BENIGN":
            confidence = round(0.75 + (self.threshold_suspicious - final_score) * 0.6, 2)
        else:
            confidence = round(0.60 + abs(final_score - 0.55) * 0.4, 2)
        confidence = min(max(confidence, 0.50), 0.99)

        return PredictionResult(
            domain=features.domain,
            risk_score=final_score,
            verdict=verdict,
            confidence=confidence,
            signals=signals,
            features=features,
        )

    def predict_batch(self, domains: List[str]) -> List[PredictionResult]:
        """Classifies a list of domain names."""
        return [self.predict(d) for d in domains if d and d.strip()]
