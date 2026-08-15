import streamlit as st

import forge_ai
import forge_compiler

st.set_page_config(page_title="Heraclitus Visual Web Forge", layout="wide", page_icon="🔨")

# Header
st.title("🔨 Heraclitus Visual Web Forge")
st.markdown(
    "Interface de Manufatura de Segurança (Design-Time) para criação autônoma de conectores."
)

# Estado da Sessão
if "derived_profile" not in st.session_state:
    st.session_state["derived_profile"] = None
if "artifact_id" not in st.session_state:
    st.session_state["artifact_id"] = None

# Layout em 3 colunas
col1, col2, col3 = st.columns([1, 1, 1])

# --- Coluna Esquerda: Entrada de Dados ---
with col1:
    st.subheader("1. Ingestão Bruta")
    st.markdown("Cole amostras reais de log para a IA analisar.")

    vendor = st.text_input(
        "Fornecedor / Sistema", value="Cisco ASA", help="Ex: Fortinet, AWS CloudTrail, etc."
    )
    artifact_id_input = st.text_input(
        "ID do Artefato (Fingerprint)", value="cisco_asa", help="Um identificador curto e limpo."
    )

    sample_logs = st.text_area(
        "Amostras de Log (uma por linha)",
        value="May 11 2026 10:11:12 10.0.0.1 %ASA-4-106023: Deny tcp src outside:192.168.1.5/1234 dst inside:10.0.0.5/80\n"
        "May 11 2026 10:11:13 10.0.0.1 %ASA-6-302013: Built inbound TCP connection 12345 for outside:192.168.1.6/5432 (192.168.1.6/5432) to inside:10.0.0.5/443 (10.0.0.5/443)",
        height=300,
    )

    if st.button("🧠 Analisar Formato com IA (Claude)", use_container_width=True):
        if not forge_ai.available():
            st.error(
                "Erro: A IA não está disponível. Defina a variável ANTHROPIC_API_KEY no seu ambiente."
            )
        elif not sample_logs.strip():
            st.warning("Insira pelo menos uma amostra de log.")
        else:
            with st.spinner("Derivando conector via IA..."):
                samples = [s.strip() for s in sample_logs.split("\n") if s.strip()]
                try:
                    profile = forge_ai.derive_profile(artifact_id_input, vendor, samples)
                    st.session_state["derived_profile"] = profile
                    st.session_state["artifact_id"] = artifact_id_input
                    st.success("Perfil derivado com sucesso!")
                except Exception as e:
                    st.error(f"Falha na IA: {e}")

# --- Coluna Central: Mapeamento Visual ---
with col2:
    st.subheader("2. Mapeamento Canônico (IA)")
    if st.session_state["derived_profile"]:
        st.markdown(
            "Valide o perfil semântico gerado pelo LLM. Você pode editar os parâmetros críticos antes do deploy."
        )

        prof = st.session_state["derived_profile"]

        # Toggles Visuais
        st.write("**Engine de Parse:**")
        engine = st.radio(
            "Selecione a engine",
            ["regex", "keyvalue"],
            index=0 if prof["parse"]["engine"] == "regex" else 1,
            horizontal=True,
        )
        prof["parse"]["engine"] = engine

        if engine == "regex":
            pattern = st.text_input(
                "Regex (Grupos Nomeados)", value=prof["parse"].get("pattern", "")
            )
            prof["parse"]["pattern"] = pattern

        st.write("**Taxonomia (Primeira Regra)**")
        if prof.get("reasoning") and len(prof["reasoning"]) > 0:
            first_rule = prof["reasoning"][0]
            col_a, col_b = st.columns(2)
            action = col_a.text_input("Ação Canônica", value=first_rule["set"]["action"])
            risk = col_b.selectbox(
                "Risco",
                ["Low", "Medium", "High", "Critical"],
                index=["Low", "Medium", "High", "Critical"].index(first_rule["set"]["risk"]),
            )

            first_rule["set"]["action"] = action
            first_rule["set"]["risk"] = risk

        with st.expander("Ver JSON Completo do Perfil", expanded=False):
            st.json(prof)

    else:
        st.info("Aguardando análise da IA na Coluna 1.")

# --- Coluna Direita: Validação e Deploy ---
with col3:
    st.subheader("3. Qualidade & Deploy")
    if st.session_state["derived_profile"]:
        prof = st.session_state["derived_profile"]

        st.write("### Matrix de Testes")
        st.dataframe(prof.get("test_matrix", []), use_container_width=True)

        st.write("### Desempenho Estimado")
        col_c, col_d = st.columns(2)
        col_c.metric("EPS", f"{prof['benchmark']['estimated_eps']:,}")
        col_d.metric("Latência Média", f"{prof['benchmark']['avg_latency_ms']} ms")

        st.markdown("---")
        if st.button(
            "🚀 Compilar & Assinar Deploy (Registry)", type="primary", use_container_width=True
        ):
            with st.spinner("Compilando .hcx seguro..."):
                try:
                    # Injeta o profile alterado para o forge_compiler enxergar
                    forge_compiler.CONNECTOR_PROFILES[st.session_state["artifact_id"]] = prof

                    compiler = forge_compiler.HeraclitusForgeCompiler()
                    first_sample = prof.get("test_matrix", [{"input": ""}])[0]["input"]

                    path = compiler.compile_knowledge(
                        artifact_id=st.session_state["artifact_id"],
                        vendor=prof.get("vendor", vendor),
                        sample_log=first_sample,
                    )

                    st.success(f"Artefato assinado e compilado em: `{path}`")
                    st.balloons()
                except Exception as e:
                    st.error(f"Erro no deploy: {e}")
    else:
        st.info("Aguardando perfil canônico.")
