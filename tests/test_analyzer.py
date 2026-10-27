import pytest

from analyzer import analyze_message, extract_urls


def test_empty_message():
    result = analyze_message("")

    assert result["risk_level"] == "Indeterminado"
    assert result["indicators"] == []


def test_urgent_message():
    result = analyze_message(
        "URGENTE! Sua conta será bloqueada."
    )

    assert result["score"] == 2
    assert result["risk_level"] == "Potencialmente seguro"
    assert result["indicators"][0]["type"] == "urgency"


def test_sensitive_information():
    result = analyze_message(
        "Confirme sua senha e seus dados bancários."
    )

    assert result["score"] >= 3
    assert result["risk_level"] == "Suspeito"


def test_suspicious_url():
    result = analyze_message(
        "Acesse http://example.com imediatamente."
    )

    assert result["urls"] == ["http://example.com"]
    assert any(
        item["type"] == "suspicious_url"
        for item in result["indicators"]
    )


def test_extract_multiple_urls():
    urls = extract_urls(
        "Acesse https://example.com ou www.example.org"
    )

    assert len(urls) == 2


def test_regular_message():
    result = analyze_message(
        "Olá, gostaria de confirmar nossa reunião de amanhã."
    )

    assert result["score"] == 0
    assert result["indicators"] == []


def test_non_string_input():
    with pytest.raises(TypeError):
        analyze_message(None)
