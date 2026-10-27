import re
from urllib.parse import urlparse


URGENT_WORDS = [
    "urgente",
    "imediatamente",
    "ação necessária",
    "acao necessaria",
    "conta será bloqueada",
    "conta sera bloqueada",
    "última chance",
    "ultima chance",
    "expira hoje",
    "acesso suspenso",
]

SENSITIVE_WORDS = [
    "senha",
    "dados bancários",
    "dados bancarios",
    "número do cartão",
    "numero do cartao",
    "código de verificação",
    "codigo de verificacao",
    "confirme seus dados",
    "confirmar identidade",
]

SUSPICIOUS_PHRASES = [
    "clique aqui",
    "clique no link",
    "verifique sua conta",
    "atualize seus dados",
    "confirme sua conta",
    "desbloqueie sua conta",
]

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.IGNORECASE,
)


def extract_urls(text: str) -> list[str]:
    """Extrai URLs sem acessá-las."""
    return URL_PATTERN.findall(text)


def analyze_message(text: str) -> dict:
    """Identifica indicadores suspeitos usando regras locais."""

    if not isinstance(text, str):
        raise TypeError("A mensagem precisa ser um texto.")

    if not text.strip():
        return {
            "risk_level": "Indeterminado",
            "score": 0,
            "indicators": [],
            "urls": [],
            "recommendations": [
                "Insira uma mensagem para iniciar a análise."
            ],
        }

    normalized = text.casefold()
    indicators = []
    score = 0

    def add_indicator(kind, description, evidence, points):
        nonlocal score

        if evidence:
            indicators.append({
                "type": kind,
                "description": description,
                "evidence": evidence,
                "points": points,
            })
            score += points

    urgency_matches = [
        word for word in URGENT_WORDS if word in normalized
    ]

    add_indicator(
        "urgency",
        "A mensagem utiliza linguagem de urgência ou pressão.",
        urgency_matches,
        2,
    )

    sensitive_matches = [
        word for word in SENSITIVE_WORDS if word in normalized
    ]

    add_indicator(
        "sensitive_information",
        "A mensagem menciona credenciais ou informações sensíveis.",
        sensitive_matches,
        3,
    )

    phrase_matches = [
        phrase for phrase in SUSPICIOUS_PHRASES
        if phrase in normalized
    ]

    add_indicator(
        "suspicious_phrase",
        "A mensagem contém frases frequentemente usadas em golpes.",
        phrase_matches,
        2,
    )

    urls = extract_urls(text)
    suspicious_urls = []

    for url in urls:
        candidate = (
            url if url.lower().startswith(("http://", "https://"))
            else f"http://{url}"
        )

        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").lower()
        reasons = []

        if parsed.scheme == "http":
            reasons.append("Usa HTTP em vez de HTTPS.")

        if hostname.startswith("xn--") or ".xn--" in hostname:
            reasons.append(
                "Contém um domínio internacionalizado que merece inspeção."
            )

        if re.search(r"\d{5,}", hostname):
            reasons.append(
                "O hostname contém uma sequência longa de números."
            )

        if "@" in parsed.netloc:
            reasons.append("Contém o caractere @ na autoridade da URL.")

        if reasons:
            suspicious_urls.append({
                "url": url,
                "reasons": reasons,
            })

    add_indicator(
        "suspicious_url",
        "Foram encontradas características suspeitas em URLs.",
        suspicious_urls,
        3,
    )

    if score >= 6:
        risk_level = "Alto risco"
    elif score >= 3:
        risk_level = "Suspeito"
    else:
        risk_level = "Potencialmente seguro"

    recommendations = []

    if indicators:
        recommendations.append(
            "Não clique nos links nem forneça dados antes de verificar "
            "a legitimidade da mensagem."
        )

    if suspicious_urls:
        recommendations.append(
            "Confira o domínio por um canal oficial independente. "
            "Nenhum link foi acessado durante esta análise."
        )

    if sensitive_matches:
        recommendations.append(
            "Nunca compartilhe senhas ou códigos de autenticação "
            "em resposta a mensagens inesperadas."
        )

    if not indicators:
        recommendations.append(
            "Nenhum indicador configurado foi encontrado. "
            "Isso não garante que a mensagem seja legítima."
        )

    return {
        "risk_level": risk_level,
        "score": score,
        "indicators": indicators,
        "urls": urls,
        "recommendations": recommendations,
    }
