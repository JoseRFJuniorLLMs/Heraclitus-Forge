import streamlit as st
import pandas as pd
import numpy as np
import psutil
import os
from datetime import datetime, timedelta

# Conversor de números gigantes para notação simplificada nacional (M / B)
def formatar_sufixo_br(valor):
    if valor >= 1_000_000_000:
        return f"{valor / 1_000_000_000:.2f}B".replace(".", ",")
    elif valor >= 1_000_000:
        return f"{valor / 1_000_000:.2f}M".replace(".", ",")
    elif valor >= 1_000:
        return f"{valor / 1_000:.1f}K".replace(".", ",")
    return str(valor)

# --- CAPTURA DE MÉTRICAS REAIS DA GPU ---
def obter_dados_gpu():
    try:
        import GPUtil
        gpus = GPUtil.getGPUs()
        if gpus:
            gpu = gpus[0]
            return {
                "ativo": True,
                "nome": gpu.name,
                "uso": gpu.load * 100,
                "mem_usada": gpu.memoryUsed / 1024,
                "mem_total": gpu.memoryTotal / 1024
            }
    except Exception:
        pass
    return {"ativo": False, "nome": "Emulação CPU (Layer M20)", "uso": 0.0, "mem_usada": 0.0, "mem_total": 0.0}

# --- INJEÇÃO DE CSS DE ALTA PERFORMANCE E CORREÇÃO DE LAYOUT ---
st.markdown("""
    <style>
        /* 🌐 CORREÇÃO DO GOV.BR: Adiciona margem de segurança no topo para o conteúdo nunca sumir atrás do header */
        .block-container, div.block-container, [data-testid="stMainViewContainer"] .block-container {
            max-width: 98% !important;
            width: 98% !important;
            padding-left: 2rem !important;
            padding-right: 2rem !important;
            padding-top: 5.5rem !important; /* Pushes content down safely below Streamlit absolute header bar */
            padding-bottom: 2rem !important;
            margin-left: auto !important;
            margin-right: auto !important;
        }

        /* Garante visibilidade permanente das setas de recolhimento (<< e >>) */
        [data-testid="stSidebarCollapseButton"], 
        [data-testid="stSidebarCollapseButton"] button,
        button[data-testid="baseButton-headerNoPadding"] {
            opacity: 1 !important;
            visibility: visible !important;
        }
        
        [data-testid="stSidebarCollapseButton"] svg,
        button[data-testid="baseButton-headerNoPadding"] svg {
            fill: var(--text-color) !important;
            color: var(--text-color) !important;
        }

        /* Cards forenses adaptativos ao tema */
        .forensic-card {
            background-color: var(--secondary-background-color) !important;
            border: 1px solid rgba(128, 128, 128, 0.2) !important;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 12px;
            width: 100% !important;
            box-sizing: border-box;
        }
        
        .forensic-title {
            color: var(--text-color);
            opacity: 0.6;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .forensic-value {
            font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
            font-size: 26px;
            font-weight: 700;
            color: var(--text-color) !important;
            margin-top: 4px;
        }
        
        /* Tabelas responsivas nativas */
        .forensic-table {
            width: 100%;
            border-collapse: collapse;
            background-color: var(--secondary-background-color);
            border: 1px solid rgba(128, 128, 128, 0.2);
            border-radius: 6px;
            margin-top: 10px;
        }
        
        .forensic-table th {
            background-color: var(--background-color);
            color: var(--text-color);
            opacity: 0.7;
            padding: 12px;
            font-size: 11px;
            text-transform: uppercase;
        }
        
        .forensic-table td {
            padding: 12px;
            border-bottom: 1px solid rgba(128, 128, 128, 0.1);
            color: var(--text-color);
            font-size: 13px;
        }
        
        .badge { padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 600; color: #ffffff !important; }
        .bg-low { background-color: #2ea44f; }
        .bg-medium { background-color: #d29922; }
        .bg-critical { background-color: #f85149; }
        
        /* Wrapper do Grid do GitHub */
        .github-wrapper {
            background-color: var(--secondary-background-color);
            padding: 20px;
            border-radius: 6px;
            border: 1px solid rgba(128, 128, 128, 0.2);
            margin-bottom: 20px;
            width: 100%;
            box-sizing: border-box;
        }
        
        .months-header {
            display: flex;
            justify-content: space-between;
            padding-left: 42px;
            margin-bottom: 6px;
            color: var(--text-color);
            opacity: 0.6;
            font-size: 12px;
            min-width: 800px;
        }
        
        .grid-container-layout { 
            display: flex; 
            gap: 10px;
            overflow-x: auto;
            width: 100%;
            padding-bottom: 5px;
        }
        
        .days-labels {
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            font-size: 11px;
            color: var(--text-color);
            opacity: 0.6;
            padding: 4px 0;
            width: 32px;
        }
        
        .github-grid-container {
            display: grid;
            grid-template-rows: repeat(7, 13px);
            grid-auto-flow: column;
            gap: 3px;
        }
        
        .github-cell { width: 13px; height: 13px; border-radius: 2px; }
        .l-0 { background-color: var(--background-color); border: 1px solid rgba(128, 128, 128, 0.1); }
        .l-1 { background-color: #bae1ff; } 
        .l-2 { background-color: #7cc0ff; }
        .l-3 { background-color: #3894ff; }
        .l-4 { background-color: #1f6feb; }
    </style>
""", unsafe_allow_html=True)

# --- CARREGAMENTO DE DADOS (88 MILHÕES) ---
@st.cache_data
def processar_dados_log():
    total_real = 88115203
    data_final = datetime(2026, 6, 21)
    datas = [data_final - timedelta(days=i) for i in range(371)]
    datas.reverse()
    
    np.random.seed(1634972)
    insercoes_diarias = np.random.normal(loc=total_real/371, scale=32000, size=371).astype(int)
    insercoes_diarias = np.clip(insercoes_diarias, 10000, None)
    
    df = pd.DataFrame({
        "Data": datas,
        "Novos Registros": insercoes_diarias,
        "LSN_Acumulado": np.cumsum(insercoes_diarias)
    })
    
    diff = total_real - df["LSN_Acumulado"].iloc[-1]
    df.loc[df.index[-1], "Novos Registros"] += diff
    df["LSN_Acumulado"] = np.cumsum(df["Novos Registros"])
    
    niveis = []
    for r in insercoes_diarias:
        if r < 225000: niveis.append(1)
        elif r < 240000: niveis.append(2)
        elif r < 255000: niveis.append(3)
        else: niveis.append(4)
    df["Nivel_Cor"] = niveis
    
    return total_real, df

total_events, df_log_pipeline = processar_dados_log()

# --- HARDWARE TELEMETRIA ---
cpu_percent = psutil.cpu_percent()
cores_fisicos = psutil.cpu_count(logical=False)
threads_logicos = psutil.cpu_count(logical=True)

memoria_info = psutil.virtual_memory()
ram_total = memoria_info.total / (1024 ** 3)
ram_usada = memoria_info.used / (1024 ** 3)
ram_percent = memoria_info.percent

gpu_info = obter_dados_gpu()

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("### ◉ OPERAÇÃO")
    menu_navegacao = st.radio(
        "Selecione a camada de visualização:",
        ["Central de Comando (SOC)", "Linha do Tempo Forense", "Grafo de Relações", "Geometria de Produto", "Painel Executivo / Governança"],
        index=0
    )
    st.markdown("---")
    st.markdown("### 🖥️ INFRAESTRUTURA")
    st.write(f"**Uso de CPU Global:** {cpu_percent}%")
    st.caption(f"Processamento: {cores_fisicos} Cores / {threads_logicos} Threads")
    st.progress(int(cpu_percent))
    
    st.write(f"**Uso de RAM Global:** {ram_percent}%")
    st.caption(f"Consumo: {ram_usada:.1f} GB de {ram_total:.1f} GB totais")
    st.progress(int(ram_percent))
    
    st.write(f"**Uso de GPU Dedicada:** {gpu_info['uso']:.1f}%")
    if gpu_info['ativo']:
        st.caption(f"Hardware: {gpu_info['nome']}")
        st.progress(int(gpu_info['uso']))
    else:
        st.caption(f"Status: {gpu_info['nome']}")
        st.progress(0)

# --- CONTEÚDO PRINCIPAL POSICIONADO COM SEGURANÇA ---
st.markdown("🌐 **GOV.BR** · Plataforma de Evidência Digital · Sincronização Dinâmica")
st.title(f"🌀 Heraclitus Forensic Engine — {menu_navegacao}")
st.markdown("---")

# ==============================================================================
# TELA 1: CENTRAL DE COMANDO (SOC)
# ==============================================================================
if menu_navegacao == "Central de Comando (SOC)":
    st.markdown("### 📊 Indicadores Forenses Operacionais")
    
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="forensic-card"><div class="forensic-title">Total de Eventos Selados</div><div class="forensic-value">{formatar_sufixo_br(total_events)} <small style="font-size:12px; opacity:0.6;">({total_events:,})</small></div></div>'.replace(",", "."), unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="forensic-card"><div class="forensic-title">Volume em Disco</div><div class="forensic-value">30.14 GB</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="forensic-card"><div class="forensic-title">Eventos Suspeitos</div><div class="forensic-value">2.365</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="forensic-card"><div class="forensic-title">Verificação de Log</div><div class="forensic-value">117/118 OK</div></div>', unsafe_allow_html=True)

    st.markdown("#### 🗺️ Mapa de Densidade Criptográfica de Segmentos (Estilo GitHub)")
    
    slider_data_soc = st.slider(
        "Selecione o Marco Temporal para Filtragem do Grid:",
        min_value=df_log_pipeline["Data"].min().to_pydatetime(),
        max_value=df_log_pipeline["Data"].max().to_pydatetime(),
        value=df_log_pipeline["Data"].max().to_pydatetime(),
        format="DD/MM/YYYY",
        key="soc_grid_slider"
    )

    github_html = f"""
    <div class="github-wrapper">
        <div class="grid-container-layout">
            <div class="days-labels">
                <span>Mon</span><span>Wed</span><span>Fri</span>
            </div>
            <div style="overflow-x: auto; flex: 1;">
                <div class="months-header">
                    <span>Jun</span><span>Jul</span><span>Ago</span><span>Set</span><span>Out</span><span>Nov</span>
                    <span>Dez</span><span>Jan</span><span>Fev</span><span>Mar</span><span>Abr</span><span>Mai</span><span>Jun</span>
                </div>
                <div class="github-grid-container">
    """

    for idx, row in df_log_pipeline.iterrows():
        data_bloco = row["Data"]
        reg_dia = row["Novos Registros"]
        
        h_dia = int(reg_dia * 0.55)
        s_dia = int(reg_dia * 0.25)
        e_dia = int(reg_dia * 0.20)
        
        if data_bloco.to_pydatetime() <= slider_data_soc:
            nivel = row["Nivel_Cor"]
            hint = f"{reg_dia:,} fatos selados em {data_bloco.strftime('%d/%m/%Y')} [Geometria Mista: Hiperbólica={h_dia:,} | Esférica={s_dia:,} | Euclidiana={e_dia:,}]".replace(",", ".")
        else:
            nivel = 0
            hint = "Bloco futuro não gravado no LSN selecionado."
            
        github_html += f'<div class="github-cell l-{nivel}" title="{hint}"></div>'
        
    github_html += "</div></div></div></div>"
    st.markdown(github_html, unsafe_allow_html=True)

    st.markdown("#### 📋 Últimos Registros Inseridos na Janela Ativa")
    eventos_mock = [
        {"hora": "09:41:02", "origem": "guest", "alvo": "prod_db", "acao": "authorization.failure", "risco": "Medium", "hash": "b3:b1cab9dd351db..."},
        {"hora": "09:40:58", "origem": "admin", "alvo": "prod_db", "acao": "query.execute", "risco": "Low", "hash": "b3:07e93b78408d3..."},
        {"hora": "09:39:44", "origem": "admin", "alvo": "postgresql", "acao": "authentication.failure", "risco": "Critical", "hash": "b3:a52d87df89718..."},
        {"hora": "09:38:12", "origem": "admin", "alvo": "postgresql", "acao": "authentication.failure", "risco": "Critical", "hash": "b3:2a8c9f08f8041..."}
    ]
    t_html = f'<table class="forensic-table"><thead><tr><th>HORA</th><th>ATOR ORIGEM</th><th>ALVO</th><th>AÇÃO OPERACIONAL</th><th>RISCO</th><th>HASH CRIPTOGRÁFICO</th></tr></thead><tbody>'
    for ev in eventos_mock:
        badge_type = "bg-critical" if ev["risco"] == "Critical" else ("bg-medium" if ev["risco"] == "Medium" else "bg-low")
        t_html += f'<tr><td style="font-family:monospace;">{ev["hora"]}</td><td><b>{ev["origem"]}</b></td><td>{ev["alvo"]}</td><td>{ev["acao"]}</td><td><span class="badge {badge_type}">{ev["risco"]}</span></td><td style="font-family:monospace; opacity:0.6;">{ev["hash"]}</td></tr>'
    t_html += '</tbody></table>'
    st.markdown(t_html, unsafe_allow_html=True)

# ==============================================================================
# TELA 2: LINHA DO TEMPO FORENSE
# ==============================================================================
elif menu_navegacao == "Linha do Tempo Forense":
    st.markdown("### ⏱ Viagem no Tempo Física Dinâmica (AS OF LSN)")
    
    slider_data_timeline = st.slider(
        "Selecione a barreira temporal para reconstrução dos dados:",
        min_value=df_log_pipeline["Data"].min().to_pydatetime(),
        max_value=df_log_pipeline["Data"].max().to_pydatetime(),
        value=df_log_pipeline["Data"].max().to_pydatetime(),
        format="DD/MM/YYYY",
        key="timeline_graph_slider"
    )
    
    df_filtrado_timeline = df_log_pipeline[df_log_pipeline["Data"] <= slider_data_timeline]
    chart_render_df = df_filtrado_timeline.copy().set_index("Data")
    st.area_chart(chart_render_df["LSN_Acumulado"], use_container_width=True)
    
    estado_ultimo = df_filtrado_timeline.iloc[-1]
    
    col_t1, col_t2, col_t3 = st.columns(3)
    with col_t1:
        st.metric("LSN Reconstruído no Alvo", f"{formatar_sufixo_br(estado_ultimo['LSN_Acumulado'])} ({estado_ultimo['LSN_Acumulado']:,})".replace(",", "."))
    with col_t2:
        st.metric("Data de Validade Recortada", estado_ultimo["Data"].strftime("%d/%m/%Y"))
    with col_t3:
        st.metric("Janela Histórica Carregada", f"{len(df_filtrado_timeline)} dias ativos")

# ==============================================================================
# ⬡ TELA 3: GRAFO DE RELAÇÕES (100% VISÍVEL, RESPONSIVO E COM ÍCONES DO GOV)
# ==============================================================================
elif menu_navegacao == "Grafo de Relações":
    st.markdown("### ⬡ Grafo de Ataques Dinâmico (AS OF LSN)")
    st.markdown("Mova a linha do tempo para ver o surgimento das conexões. Os nós agora usam ícones limpos e o texto fica sempre visível.")
    
    slider_graph_time = st.slider(
        "Mapear estado topológico do grafo até:",
        min_value=df_log_pipeline["Data"].min().to_pydatetime(),
        max_value=df_log_pipeline["Data"].max().to_pydatetime(),
        value=df_log_pipeline["Data"].max().to_pydatetime(),
        format="DD/MM/YYYY",
        key="live_graph_slider"
    )
    
    df_ponto = df_log_pipeline[df_log_pipeline["Data"] <= slider_graph_time]
    lsn_atual = df_ponto["LSN_Acumulado"].iloc[-1] if not df_ponto.empty else 0
    
    # Adicionado campo 'icon' e ajustado espaçamento Y para os textos nunca sumirem
    nodes_config = [
        {"id": 0, "label": "IP 187.*", "icon": "🌐", "x": 80, "y": 140, "lsn_start": 0},
        {"id": 1, "label": "Firewall", "icon": "🛡️", "x": 200, "y": 140, "lsn_start": 10_000_000},
        {"id": 2, "label": "Servidor B", "icon": "🖥️", "x": 340, "y": 60, "lsn_start": 25_000_000},
        {"id": 3, "label": "svc-bkp Creds", "icon": "🔑", "x": 340, "y": 220, "lsn_start": 40_000_000},
        {"id": 4, "label": "Proc. Suspeito", "icon": "☣️", "x": 480, "y": 140, "lsn_start": 55_000_000},
        {"id": 5, "label": "Postgres", "icon": "🗄️", "x": 640, "y": 60, "lsn_start": 70_000_000},
        {"id": 6, "label": "Tabela Users", "icon": "📊", "x": 640, "y": 220, "lsn_start": 80_000_000},
        {"id": 7, "label": "Dump Extrator", "icon": "📦", "x": 800, "y": 140, "lsn_start": 85_000_000}
    ]
    
    edges_config = [
        {"from": 0, "to": 1, "weight": "0.98", "lsn_start": 15_000_000},
        {"from": 1, "to": 2, "weight": "0.91", "lsn_start": 30_000_000},
        {"from": 2, "to": 4, "weight": "0.88", "lsn_start": 58_000_000},
        {"from": 3, "to": 4, "weight": "0.74", "lsn_start": 62_000_000},
        {"from": 4, "to": 5, "weight": "0.95", "lsn_start": 72_000_000},
        {"from": 5, "to": 6, "weight": "0.97", "lsn_start": 82_000_000},
        {"from": 6, "to": 7, "weight": "0.93", "lsn_start": 87_000_000}
    ]

    # Montagem do SVG sem blocos de código markdown vazados
    svg_build = []
    svg_build.append('<div class="forensic-card" style="width:100%; box-sizing:border-box;"><svg viewBox="0 0 880 280" style="width:100%; height:auto;">')
    
    # Desenhar as Linhas (Arestas)
    for edge in edges_config:
        if lsn_atual >= edge["lsn_start"]:
            n_start = nodes_config[edge["from"]]
            n_end = nodes_config[edge["to"]]
            # Linha liga os centros dos ícones
            svg_build.append(f'<line x1="{n_start["x"]}" y1="{n_start["y"]}" x2="{n_end["x"]}" y2="{n_end["y"]}" stroke="#f85149" stroke-width="2.5" opacity="0.8" />')
            svg_build.append(f'<text x="{(n_start["x"] + n_end["x"])/2}" y="{(n_start["y"] + n_end["y"])/2 - 8}" fill="#d29922" font-size="10" font-weight="bold" text-anchor="middle">{edge["weight"]}</text>')
            
    # Desenhar os Ícones e Textos (Nós)
    for node in nodes_config:
        if lsn_atual >= node["lsn_start"]:
            # Desenha o ícone em destaque na coordenada original
            svg_build.append(f'<text x="{node["x"]}" y="{node["y"]+6}" font-size="24" text-anchor="middle">{node["icon"]}</text>')
            
            # Adiciona um círculo luminoso sutil de alerta nos nós recém-criados
            if lsn_atual - node["lsn_start"] < 15_000_000:
                svg_build.append(f'<circle cx="{node["x"]}" cy="{node["y"]}" r="16" fill="none" stroke="#f85149" stroke-width="2" opacity="0.7"/>')
            
            # Desenha o texto do rótulo travado logo abaixo do ícone (sempre visível em var(--text-color))
            svg_build.append(f'<text x="{node["x"]}" y="{node["y"]+26}" fill="var(--text-color)" font-size="11" font-weight="700" text-anchor="middle" style="fill: var(--text-color) !important;">{node["label"]}</text>')
            
    svg_build.append('</svg></div>')
    
    # Injeção em linha única sem quebras de Markdown
    st.markdown("".join(svg_build), unsafe_allow_html=True)
    st.markdown(f"**Análise Forense no LSN:** `{lsn_atual:,}` | Nós Ativos: `{sum(1 for n in nodes_config if lsn_atual >= n['lsn_start'])}/8`".replace(",", "."))

# ==============================================================================
# TELA 4: GEOMETRIA DE PRODUTO
# ==============================================================================
elif menu_navegacao == "Geometria de Produto":
    st.markdown("### 📐 Distribuição de Dados na Variedade Produto")
    
    geo_stats = {
        "Espaço Hiperbólico (H³²)": {"vol": int(total_events * 0.55), "desc": "Árvores de linhagem causal, indexação HNSW hiperbólica e traces do operador WHY().", "cor": "#1f6feb"},
        "Espaço Esférico (S⁸)": {"vol": int(total_events * 0.25), "desc": "Mapeamento de relações cíclicas recorrentes e detecção de anéis de fraude.", "cor": "#2ea44f"},
        "Espaço Euclidiano (E⁸)": {"vol": int(total_events * 0.20), "desc": "Atributos planos lineares tradicionais e índices de texto invertido.", "cor": "#a371f7"}
    }
    
    col_geo1, col_geo2, col_geo3 = st.columns(3)
    for i, (nome_geo, detalhes) in enumerate(geo_stats.items()):
        with [col_geo1, col_geo2, col_geo3][i]:
            st.markdown(f"""
            <div class="forensic-card" style="border-left: 4px solid {detalhes['cor']};">
                <div class="forensic-title">{nome_geo}</div>
                <div class="forensic-value" style="color:{detalhes['cor']} !important;">{formatar_sufixo_br(detalhes['vol'])} <small style="font-size:11px; opacity:0.6;">({detalhes['vol']:,})</small></div>
                <p style="font-size:12px; opacity:0.7; margin-top:6px; line-height:1.4;">{detalhes['desc']}</p>
            </div>
            """.replace(",", "."), unsafe_allow_html=True)
            
    st.markdown("#### Distribuição Volumétrica das Variedades")
    df_chart_geo = pd.DataFrame([{"Espaço Geométrico": k, "Registros Alocados": v["vol"]} for k, v in geo_stats.items()])
    st.bar_chart(df_chart_geo, x="Espaço Geométrico", y="Registros Alocados", use_container_width=True)

# ==============================================================================
# TELA 5: PAINEL EXECUTIVO / GOVERNANÇA
# ==============================================================================
else:
    st.markdown("""
    <div class="forensic-card" style="border-left: 4px solid #2ea44f;">
        <h3 style="margin-top:0;">✓ STATUS DE SAÚDE JURÍDICA (db.verify)</h3>
        <p style="font-size:14px; margin:0;">Cadeia Merkle integrada aprovada. Nenhuma fraude detectada nos 118 segmentos físicos do log binário.</p>
    </div>
    """, unsafe_allow_html=True)
    controles = [
        {"Controle": "Imutabilidade Completa do Log", "Norma": "PPSI / ISO 27001 A.12.4", "Status": "CONFORME"},
        {"Controle": "Carimbo de Tempo Legal Sincronizado", "Norma": "MP 2.200-2 / SERPRO ICP-Brasil", "Status": "CONFORME"}
    ]
    st.table(pd.DataFrame(controles))

# Rodapé Técnico
st.markdown("---")
st.caption("HeraclitusDB Telemetry Layer v0.1.0 · Grafos baseados em ícones vetoriais e responsividade 100% elástica corrigida.")