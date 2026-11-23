"""Unit tests for the Machine Learning and Heuristic DGA Domain Classifier."""

import pytest
from agent.classifier import DomainClassifier, DomainFeatures, PredictionResult


@pytest.fixture
def classifier() -> DomainClassifier:
    """Fixture providing a DomainClassifier instance."""
    return DomainClassifier()


def test_shannon_entropy_calculation(classifier: DomainClassifier) -> None:
    """Verifies that Shannon entropy is calculated accurately."""
    # Zero or empty
    assert classifier.calculate_shannon_entropy("") == 0.0

    # Single repeated character: entropy is zero
    assert classifier.calculate_shannon_entropy("aaaaaaa") == 0.0

    # Two equally likely characters: log2(2) = 1.0 bit
    assert classifier.calculate_shannon_entropy("abababab") == 1.0

    # High entropy string (diverse non-repeating characters)
    high_ent = classifier.calculate_shannon_entropy("abcdefghijklmnop")
    assert high_ent >= 3.8


def test_benign_domain_classification(classifier: DomainClassifier) -> None:
    """Legitimate everyday domains must receive BENIGN verdict and low risk score."""
    benign_samples = [
        "google.com",
        "wikipedia.org",
        "portugal.gov.pt",
        "github.com",
        "apple.com",
        "noticias-hoje.com"
    ]
    for d in benign_samples:
        result = classifier.predict(d)
        assert result.verdict == "BENIGN", f"Domain {d} incorrectly flagged as {result.verdict} (score: {result.risk_score})"
        assert result.risk_score < 0.40
        assert result.features is not None


def test_dga_domain_classification(classifier: DomainClassifier) -> None:
    """Classical DGA algorithmic strings must be flagged as HIGH_RISK_DGA."""
    dga_samples = [
        "xzkfplwq987123jfk.xyz",
        "b3a8c7d9e1f2495b.top",
        "qwrtpsdfghjklzxcvb.online",
        "m8n9b0v7c6x5z4.cc",
        "ajkdlqwpeojfa12984.click"
    ]
    for d in dga_samples:
        result = classifier.predict(d)
        assert result.verdict in {"HIGH_RISK_DGA", "SUSPICIOUS"}, (
            f"DGA domain {d} was not caught! Score: {result.risk_score}, Signals: {result.signals}"
        )
        assert result.risk_score >= 0.40
        assert len(result.signals) > 0


def test_consecutive_consonants_signal(classifier: DomainClassifier) -> None:
    """Domains with extreme consonant streaks should trigger appropriate explanation signals."""
    result = classifier.predict("bcdfghjklmn.com")
    features = result.features
    assert features is not None
    assert features.max_consecutive_consonants >= 10
    assert any("consoantes consecutivas" in sig.lower() for sig in result.signals)


def test_high_risk_tld_influence(classifier: DomainClassifier) -> None:
    """Verifies that high-risk TLDs (.xyz, .top, .online) elevate risk scoring."""
    base_res = classifier.predict("normalname.com")
    risky_res = classifier.predict("normalname.xyz")
    assert risky_res.risk_score > base_res.risk_score
    assert any("tld com histórico de abuso" in sig.lower() for sig in risky_res.signals)


def test_predict_batch(classifier: DomainClassifier) -> None:
    """Batch prediction should classify multiple domains consistently."""
    domains = ["google.com", "xzkfplwq987123jfk.xyz", "gov.pt"]
    results = classifier.predict_batch(domains)
    assert len(results) == 3
    assert results[0].domain == "google.com"
    assert results[0].verdict == "BENIGN"
    assert results[1].domain == "xzkfplwq987123jfk.xyz"
    assert results[1].verdict in {"HIGH_RISK_DGA", "SUSPICIOUS"}


def test_prediction_result_to_dict(classifier: DomainClassifier) -> None:
    """Verifies dictionary conversion for JSON API serialization."""
    result = classifier.predict("test-domain.org")
    d = result.to_dict()
    assert "domain" in d
    assert "risk_score" in d
    assert "verdict" in d
    assert "signals" in d
    assert "features" in d
    assert isinstance(d["features"], dict)
