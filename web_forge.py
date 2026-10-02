"""
Heraclitus Visual Web Forge — Interface Unificada da Suíte Heraclitus.

Contém:
  1. 🔥 A Forja Dialética: Pipeline completo de dados com Entrada Caótica, Ciclo Tese/Antítese/Síntese,
     Validação LLM-as-a-Judge, Filtros Heurísticos e Geração de Datasets SFT, DPO/ORPO e HeraclitusDB.
  2. 🔨 Manufatura de Conectores (.hcx): Interface design-time para derivação e deploy de conectores.
"""

from __future__ import annotations

import json

import streamlit as st

import forge_ai
import forge_compiler
from forge_chaotic import ChaoticIngestion
from forge_datasets import DatasetExporter, HeraclitusDBIndexer
from forge_dialectic import HeraclitusDialecticForge
from forge_validator import ForgeValidator

st.set_page_config(page_title="Heraclitus Visual Forge Suite", layout="wide", page_icon="🔥")

# Cabeçalho Principal
st.title("🔥 Heraclitus Visual Forge Suite")
st.markdown(
    "Plataforma Integrada de Evidência Digital, Forja Dialética e Manufatura de Conectores."
)

# Abas de Navegação Principal
tab_dialectic, tab_connector = st.tabs(
    [
        "🔥 Forja Dialética (Pipeline de Processamento de Dados)",
        "🔨 Manufatura de Conectores de Segurança (.hcx)",
    ]
)


# ==============================================================================
# ABA 1: A FORJA DIALÉTICA (PIPELINE DE PROCESSAMENTO DE DADOS)
# ==============================================================================
with tab_dialectic:
    st.subheader(
        "Pipeline Dialético de Dados: Tese ➔ Antítese ➔ Síntese ➔ LLM-as-a-Judge ➔ Datasets"
    )

    # 1. ENTRADA CAÓTICA
    st.markdown("### 1. Entrada Caótica")
    col_in_type, col_in_rounds = st.columns([2, 1])

    with col_in_type:
        tipo_entrada = st.radio(
            "Selecione o Canal de Entrada Caótica:",
            [
                "Logs Brutos (JSON/TXT/Syslog)",
                "Sementes de Prompt (Templates)",
                "Dump de Interações (Diálogos/Chats)",
            ],
            horizontal=True,
        )
    with col_in_rounds:
        rodadas = st.number_input(
            "Rodadas Dialéticas de Refinamento:", min_value=1, max_value=3, value=1
        )

    # Textos padrão conforme o tipo
    if "Logs Brutos" in tipo_entrada:
        default_input = (
            "2026-10-01 22:15:30 UTC [19202] FATAL: password authentication failed for user 'admin_db' from 187.65.12.99\n"
            "2026-10-01 22:16:01 SecurityEvent EventID=4625 Computer=SRV-SEC-01 TargetUserName=carlos.mgi LogonType=3 IpAddress=10.2.4.15 Status=0xC000006D\n"
            '2026-10-01 22:17:10 192.168.1.10 - ana.secretaria [01/Oct/2026:22:17:10 -0300] "GET /api/v1/folha/exportar HTTP/1.1" 403 412'
        )
        input_label = "Cole as linhas de log bruto (uma por linha):"
    elif "Sementes de Prompt" in tipo_entrada:
        default_input = (
            "Instrução: Audite a integridade da cadeia de custódia e determine se o acesso ao endpoint /folha/exportar "
            "constitui violação de privilégio funcional conforme a LGPD e as normas do órgão público."
        )
        input_label = "Insira o template de instrução / semente de prompt:"
    else:
        default_input = (
            "Usuário: Alerta detectado: 5 tentativas de logon falhadas seguidas de uma bem-sucedida para o usuário svc-backup.\n"
            "Assistente: Investigue se o IP de origem pertence à rede interna autorizada e se o horário é compatível com a janela de backup."
        )
        input_label = "Insira o dump de diálogo / transcrição de interação:"

    conteudo_entrada = st.text_area(input_label, value=default_input, height=140)

    btn_forjar = st.button(
        "⚡ Executar a Forja Dialética", type="primary", use_container_width=True
    )

    if btn_forjar:
        with st.spinner("Executando o ciclo dialético: Tese ➔ Antítese ➔ Síntese ➔ LLM Judge..."):
            # Normaliza entrada caótica
            if "Logs Brutos" in tipo_entrada:
                linhas = [ln.strip() for ln in conteudo_entrada.splitlines() if ln.strip()]
                items = ChaoticIngestion.from_raw_logs(linhas, source_name="web_logs")
            elif "Sementes de Prompt" in tipo_entrada:
                items = ChaoticIngestion.from_prompt_seeds(
                    [conteudo_entrada], template_name="web_prompt"
                )
            else:
                items = ChaoticIngestion.from_interaction_dump(
                    [conteudo_entrada], session_prefix="web_chat"
                )

            forge = HeraclitusDialecticForge(max_rounds=rodadas)
            validator = ForgeValidator()
            packages = []

            for it in items:
                dial_res = forge.forge(it)
                pkg = validator.process(dial_res)
                packages.append(pkg)

            st.session_state["dialectic_packages"] = packages
            st.success(
                f"✓ Forja Dialética concluída! {len(packages)} item(ns) processado(s) e validado(s)."
            )

    # Exibição dos Resultados da Forja
    if st.session_state.get("dialectic_packages"):
        pkgs = st.session_state["dialectic_packages"]
        st.markdown("---")
        st.subheader("2. A Forja Dialética & Resultados")

        for idx, pkg in enumerate(pkgs, start=1):
            with st.expander(
                f"📌 Item {idx}: [{pkg.dialectic_result.item.input_type.value.upper()}] {pkg.dialectic_result.item.id}",
                expanded=(idx == 1),
            ):
                # Painel de Validação e LLM-as-a-Judge
                score = pkg.judge_score
                heur = pkg.heuristic_filter

                st.markdown("#### ⚖️ Validação e Formatação (LLM-as-a-Judge & Heurísticas)")
                col_sc1, col_sc2, col_sc3, col_sc4, col_sc5 = st.columns(5)
                col_sc1.metric(
                    "Judge Overall Score", f"{score.overall_score:.2f}", delta=score.verdict.value
                )
                col_sc2.metric("Acurácia Factual", f"{score.factual_accuracy:.2f}")
                col_sc3.metric("Coerência CoT", f"{score.logical_coherence:.2f}")
                col_sc4.metric("Anti-Alucinação", f"{score.anti_hallucination:.2f}")
                col_sc5.metric("Filtros Heurísticos", "APROVADO" if heur.passed else "REPROVADO")

                st.caption(f"**Parecer do Juiz:** {score.rubric_feedback}")
                st.markdown("---")

                # As 3 Etapas Dialéticas
                col_tese, col_antitese, col_sintese = st.columns(3)

                turn = pkg.dialectic_result.turns[-1]
                with col_tese:
                    st.info("### 1. Tese (Modelo Gerador)")
                    st.markdown("**Chain-of-Thought Inicial:**")
                    st.caption(turn.thesis_thought)
                    st.markdown(turn.thesis)

                with col_antitese:
                    st.warning("### 2. Antítese (Modelo Crítico)")
                    st.markdown("**Crítica e Desafio:**")
                    st.caption(turn.antithesis_critique)
                    st.markdown(turn.antithesis)

                with col_sintese:
                    st.success("### 3. Síntese (Refinamento)")
                    st.markdown("**Chain-of-Thought Superior:**")
                    st.caption(turn.synthesis_thought)
                    st.markdown(turn.synthesis)

                # Fatos Estruturados
                if pkg.dialectic_result.structured_facts:
                    st.markdown("#### 🗄️ Fatos Estruturados Prontos para HeraclitusDB")
                    st.json(pkg.dialectic_result.structured_facts)

        # 3. Exportações Prontas para Heraclitus
        st.markdown("---")
        st.subheader("3. Saída Pronta para o Heraclitus")
        col_exp1, col_exp2, col_exp3 = st.columns(3)

        # Prepara dados para download
        sft_records = [DatasetExporter.build_sft_record(p) for p in pkgs if p.is_valid]
        dpo_records = [DatasetExporter.build_dpo_record(p) for p in pkgs if p.is_valid]
        facts_records = HeraclitusDBIndexer.extract_operational_facts(pkgs)

        sft_jsonl = "\n".join(json.dumps(r, ensure_ascii=False) for r in sft_records)
        dpo_jsonl = "\n".join(json.dumps(r, ensure_ascii=False) for r in dpo_records)
        facts_jsonl = "\n".join(json.dumps(r, ensure_ascii=False) for r in facts_records)

        with col_exp1:
            st.download_button(
                "📥 Baixar Dataset SFT (Fine-Tuning)",
                data=sft_jsonl,
                file_name="heraclitus_sft_dataset.jsonl",
                mime="application/jsonl",
                use_container_width=True,
            )
            st.caption(f"{len(sft_records)} registro(s) prontos para treino supervisionado.")

        with col_exp2:
            st.download_button(
                "📥 Baixar Dataset DPO / ORPO (Preferência)",
                data=dpo_jsonl,
                file_name="heraclitus_dpo_orpo_dataset.jsonl",
                mime="application/jsonl",
                use_container_width=True,
            )
            st.caption(f"{len(dpo_records)} pares contrastivos {{prompt, chosen, rejected}}.")

        with col_exp3:
            st.download_button(
                "📥 Baixar Fatos Estruturados (HeraclitusDB)",
                data=facts_jsonl,
                file_name="operational_facts_heraclitusdb.jsonl",
                mime="application/jsonl",
                use_container_width=True,
            )
            st.caption(f"{len(facts_records)} fato(s) operacionais para carga central.")


# ==============================================================================
# ABA 2: MANUFATURA DE CONECTORES (.HCX) - DESIGN TIME ORIGINAL
# ==============================================================================
with tab_connector:
    st.subheader("🔨 Manufatura de Conectores de Segurança (Design-Time)")
    st.markdown("Crie, ajuste e compile conectores declarativos `.hcx` assinados com Ed25519.")

    if "derived_profile" not in st.session_state:
        st.session_state["derived_profile"] = None
    if "artifact_id" not in st.session_state:
        st.session_state["artifact_id"] = None

    col1, col2, col3 = st.columns([1, 1, 1])

    # Coluna 1: Ingestão de Amostras
    with col1:
        st.subheader("1. Ingestão Bruta")
        st.markdown("Cole amostras reais de log para a IA analisar.")

        vendor = st.text_input(
            "Fornecedor / Sistema",
            value="Cisco ASA",
            help="Ex: Fortinet, AWS CloudTrail, etc.",
            key="conn_vendor",
        )
        artifact_id_input = st.text_input(
            "ID do Artefato (Fingerprint)",
            value="cisco_asa",
            help="Um identificador curto e limpo.",
            key="conn_art_id",
        )

        sample_logs = st.text_area(
            "Amostras de Log (uma por linha)",
            value="May 11 2026 10:11:12 10.0.0.1 %ASA-4-106023: Deny tcp src outside:192.168.1.5/1234 dst inside:10.0.0.5/80\n"
            "May 11 2026 10:11:13 10.0.0.1 %ASA-6-302013: Built inbound TCP connection 12345 for outside:192.168.1.6/5432 (192.168.1.6/5432) to inside:10.0.0.5/443 (10.0.0.5/443)",
            height=260,
            key="conn_samples",
        )

        if st.button(
            "🧠 Analisar Formato com IA (Claude)", use_container_width=True, key="btn_conn_ai"
        ):
            if not forge_ai.available():
                st.error(
                    "Erro: A IA não está disponível. Defina ANTHROPIC_API_KEY e FORGE_AI_MODEL no seu ambiente."
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

    # Coluna 2: Mapeamento Semântico
    with col2:
        st.subheader("2. Mapeamento Canônico")
        if st.session_state["derived_profile"]:
            st.markdown("Valide o perfil gerado antes do deploy.")
            prof = st.session_state["derived_profile"]

            engine = st.radio(
                "Selecione a engine",
                ["regex", "keyvalue"],
                index=0 if prof["parse"]["engine"] == "regex" else 1,
                horizontal=True,
                key="conn_engine_radio",
            )
            prof["parse"]["engine"] = engine

            if engine == "regex":
                pattern = st.text_input(
                    "Regex (Grupos Nomeados)",
                    value=prof["parse"].get("pattern", ""),
                    key="conn_pattern_input",
                )
                prof["parse"]["pattern"] = pattern

            if prof.get("reasoning") and len(prof["reasoning"]) > 0:
                first_rule = prof["reasoning"][0]
                col_a, col_b = st.columns(2)
                action = col_a.text_input(
                    "Ação Canônica", value=first_rule["set"]["action"], key="conn_action_input"
                )
                risk = col_b.selectbox(
                    "Risco",
                    ["Low", "Medium", "High", "Critical"],
                    index=["Low", "Medium", "High", "Critical"].index(first_rule["set"]["risk"]),
                    key="conn_risk_input",
                )
                first_rule["set"]["action"] = action
                first_rule["set"]["risk"] = risk

            with st.expander("Ver JSON Completo do Perfil", expanded=False):
                st.json(prof)
        else:
            st.info("Aguardando análise da IA na Coluna 1.")

    # Coluna 3: Deploy do Conector .hcx
    with col3:
        st.subheader("3. Qualidade & Deploy")
        if st.session_state["derived_profile"]:
            prof = st.session_state["derived_profile"]
            st.write("### Matriz de Testes")
            st.dataframe(prof.get("test_matrix", []), use_container_width=True)

            col_c, col_d = st.columns(2)
            col_c.metric("EPS", f"{prof['benchmark']['estimated_eps']:,}")
            col_d.metric("Latência Média", f"{prof['benchmark']['avg_latency_ms']} ms")

            st.markdown("---")
            if st.button(
                "🚀 Compilar & Assinar Deploy (Registry)",
                type="primary",
                use_container_width=True,
                key="btn_conn_deploy",
            ):
                with st.spinner("Compilando .hcx seguro..."):
                    try:
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
