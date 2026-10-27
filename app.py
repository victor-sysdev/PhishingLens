import streamlit as st

from analyzer import analyze_message


st.set_page_config(
    page_title="PhishingLens",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
        .stApp {
            background-color: #101214;
            color: #F1F3F5;
        }

        [data-testid="stHeader"] {
            background-color: #101214;
        }

        .main-title {
            font-size: 2.8rem;
            font-weight: 800;
            letter-spacing: -1px;
            color: #F1F3F5;
            margin-bottom: 0;
        }

        .accent {
            color: #FF5A36;
        }

        .subtitle {
            color: #A0A7B0;
            font-size: 1.05rem;
            margin-top: 0.4rem;
            margin-bottom: 2rem;
        }

        .panel {
            background: #191C20;
            border: 1px solid #30353B;
            border-radius: 12px;
            padding: 1.2rem;
            margin-bottom: 1rem;
        }

        .panel-title {
            font-size: 1.15rem;
            font-weight: 700;
            margin-bottom: 0.8rem;
        }

        .disclaimer {
            color: #9299A2;
            font-size: 0.85rem;
            border-top: 1px solid #30353B;
            padding-top: 1rem;
            margin-top: 2rem;
        }

        div.stButton > button[kind="primary"] {
            background-color: #FF5A36;
            border: 1px solid #FF5A36;
            color: white;
            font-weight: 700;
            min-height: 3rem;
        }

        div.stButton > button[kind="primary"]:hover {
            background-color: #E84725;
            border-color: #E84725;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="main-title">Phishing<span class="accent">Lens</span></div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">'
    "Análise de mensagens suspeitas para identificar possíveis tentativas de phishing."
    "</div>",
    unsafe_allow_html=True,
)

left, right = st.columns([1.15, 0.85], gap="large")

with left:
    st.subheader("Analisar mensagem")

    message = st.text_area(
        "Cole o conteúdo do e-mail ou da mensagem:",
        height=280,
        placeholder=(
            "Exemplo:\n\n"
            "URGENTE: sua conta será bloqueada!\n"
            "Confirme seus dados acessando http://example.com"
        ),
    )

    analyze_button = st.button(
        "🛡️ Analisar mensagem",
        type="primary",
        use_container_width=True,
    )

    st.caption(
        "A análise é feita localmente pelas regras do projeto. "
        "Os links encontrados não são acessados."
    )

with right:
    st.subheader("Como funciona")

    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">01 · Detecção de indicadores</div>
            Identifica sinais como urgência, solicitações de dados sensíveis
            e características suspeitas em URLs.
        </div>
        <div class="panel">
            <div class="panel-title">02 · Avaliação de risco</div>
            Reúne os indicadores encontrados para classificar o nível de risco.
        </div>
        <div class="panel">
            <div class="panel-title">03 · Recomendações</div>
            Apresenta orientações para ajudar você a lidar com a mensagem.
        </div>
        """,
        unsafe_allow_html=True,
    )

if analyze_button:
    if not message.strip():
        st.warning("Cole uma mensagem antes de iniciar a análise.")
    else:
        try:
            result = analyze_message(message)

            st.divider()
            st.header("Resultado da análise")

            risk = result.get("risk", "Indeterminado")
            score = result.get("score", 0)

            if risk == "Alto risco":
                st.error(f"🚨 Classificação: {risk}")
            elif risk == "Suspeito":
                st.warning(f"⚠️ Classificação: {risk}")
            elif risk == "Potencialmente seguro":
                st.success(f"Classificação: {risk}")
            else:
                st.info(f"Classificação: {risk}")

            st.metric("Pontuação de risco", score)

            indicators = result.get("indicators", [])

            st.subheader("Indicadores encontrados")

            if indicators:
                for indicator in indicators:
                    st.markdown(f"- {indicator}")
            else:
                st.info(
                    "Nenhum indicador configurado foi identificado. "
                    "Isso não garante que a mensagem seja segura."
                )

            urls = result.get("urls", [])

            st.subheader("URLs identificadas")

            if urls:
                for url in urls:
                    st.code(url, language=None)
            else:
                st.write("Nenhuma URL identificada.")

            recommendations = result.get("recommendations", [])

            st.subheader("Recomendações")

            if recommendations:
                for recommendation in recommendations:
                    st.markdown(f"- {recommendation}")
            else:
                st.write(
                    "Verifique o remetente e confirme solicitações "
                    "por um canal oficial independente."
                )

        except Exception as error:
            st.error("Não foi possível concluir a análise.")
            st.exception(error)

st.markdown(
    """
    <div class="disclaimer">
        PhishingLens é uma ferramenta experimental de apoio à análise.
        A classificação é baseada em regras e não garante a identificação
        de todas as ameaças. Não compartilhe senhas, tokens ou outros
        dados confidenciais durante os testes.
    </div>
    """,
    unsafe_allow_html=True,
)

