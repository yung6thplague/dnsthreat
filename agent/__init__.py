"""Agent package initialization.

Exports extraction, normalisation, allowlisting and ML classification utilities.
"""

from agent.classifier import DomainClassifier, DomainFeatures, PredictionResult
from agent.extractor import (
    AllowlistFilter,
    DomainExtractor,
    ExtractionResult,
    FilteredDomain,
    defang_text,
    is_valid_fqdn,
    normalize_domain_candidate,
)

__all__ = [
    "DomainClassifier",
    "DomainFeatures",
    "PredictionResult",
    "DomainExtractor",
    "ExtractionResult",
    "FilteredDomain",
    "AllowlistFilter",
    "defang_text",
    "is_valid_fqdn",
    "normalize_domain_candidate",
]
