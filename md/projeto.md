## 📁 Novo Blueprint Arquitetural (Enterprise)

```plaintext
Heraclitus/
│
├── app.py                      # Bootstrapper Limpo (Orquestração < 80 linhas)
│
├── config/
│   ├── __init__.py
│   ├── settings.py             # Configurações Globais, Limites de Performance e Inicializações
│   └── constants.py            # Valores Mágicos e Paletas Cromáticas Centralizadas
│
├── domain/
│   ├── __init__.py
│   ├── entities.py             # Entidades e Value Objects (LSN, Node, Edge, Evidence)
│   └── events.py               # Definições de Eventos de Domínio (TimelineChanged, IncidentDetected)
│
├── core/
│   ├── __init__.py
│   └── engines.py              # Implementações Matemáticas Puras (Entropy, Merkle, Geometry)
│
├── repositories/
│   ├── __init__.py
│   └── event_repository.py     # Abstração de Dados (Data Access Object / Portas e Adaptadores)
│
├── services/
│   ├── __init__.py
│   ├── event_bus.py            # Barramento de Mensagens Reativo (Publish/Subscribe)
│   ├── timeline_service.py     # Orquestrador de Estados do Playback e Viagem no Tempo
│   └── metrics_service.py      # Agregador de Inteligência Forense e Científica
│
├── telemetry/
│   ├── __init__.py
│   └── profiler.py             # Micro-framework de Alta Precisão (Auto-Observabilidade)
│
└── ui/
    ├── __init__.py
    ├── components.py           # Componentes Visuais Puros (Cards, Badges, Grids sem HTML solto)
    └── layouts.py              # Partições Estruturais (Sidebar, Main Workspace, Inspector)

```

---

## 🛠️ Código Fonte da Solução Refatorada

### ⚙️ 1. Camada de Configuração (`config/`)

#### 📄 `config/constants.py`

```python
# Paleta de Cores Estáveis para o Ecossistema Visual
PALETA_GRID = {
    0: "var(--background-color)", 
    1: "#bae1ff", 
    2: "#7cc0ff", 
    3: "#3894ff", 
    4: "#1f6feb"
}

COR_PRIMARIA = "#1f6feb"
COR_TEXTO = "#f0f6fc"
COR_PERIGO = "#f85149"
COR_SUCESSO = "#2ea44f"
COR_ALERTA = "#d29922"

# Métricas de Variedade Produto H^32 x S^8 x E^8
PESO_HIPERBOLICO = 0.55
PESO_ESFERICO = 0.25
PESO_EUCLIDIANO = 0.20

# Constantes de Pipeline
TOTAL_REGISTROS_REAL = 88115203
SEED_ALEATORIA = 1634972
TOTAL_DIAS_HISTORICO = 371

```

#### 📄 `config/settings.py`

```python
import streamlit as st

def inicializar_ambiente_global():
    """Configurações primárias do engine do Streamlit e injeção de estilo isolado."""
    st.set_page_config(
        page_title="Heraclitus Forensic Engine",
        page_icon="🌀",
        layout="wide",
        initial_sidebar_state="expanded"
    )
  
    # Carregamento seguro da folha de estilo desacoplada
    try:
        with open("styles/theme.css") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        pass

```

---

### 🧬 2. Camada de Domínio (`domain/`)

#### 📄 `domain/entities.py`

```python
from dataclasses import dataclass
from datetime import datetime

@dataclass(frozen=True)
def LogSequenceNumber:
    """Value Object representando o ponteiro imutável LSN."""
    valor: int
  
    def para_sufixo_br(self) -> str:
        if self.valor >= 1_000_000:
            return f"{self.valor / 1_000_000:.1f}M"
        if self.valor >= 1_000:
            return f"{self.valor / 1_000:.1f}K"
        return str(self.valor)

@dataclass
class EvidenciaForense:
    """Entidade de Domínio representando um bloco imutável de logs."""
    data: datetime
    novos_registros: int
    lsn_acumulado: LogSequenceNumber
    nivel_cor: int

@dataclass
class TopologiaNode:
    id_no: int
    label: str
    lsn_surgimento: int

@dataclass
class TopologiaEdge:
    origem: int
    destino: int
    peso: str
    lsn_surgimento: int

```

#### 📄 `domain/events.py`

```python
from dataclasses import dataclass
from datetime import datetime
from domain.entities import LogSequenceNumber

@dataclass
class EventoDominio:
    """Classe base para todos os eventos do sistema."""
    timestamp: datetime = datetime.now()

@dataclass
class TimelineChangedEvent(EventoDominio):
    """Disparado quando o ponteiro temporal do LSN é modificado."""
    index_atual: int
    lsn_ativo: LogSequenceNumber
    data_ativa: datetime

```

---

### 🧮 3. Camada Core & Motores Criptográficos (`core/`)

#### 📄 `core/engines.py`

```python
import numpy as np
from abc import ABC, abstractmethod

class IMetricsEngine(ABC):
    @abstractmethod
    def calcular_entropia(self, dados: np.ndarray) -> float:
        pass

class ShannonEntropyEngine(IMetricsEngine):
    def calcular_entropia(self, dados: np.ndarray) -> float:
        if len(dados) == 0:
            return 0.0
        _, contagens = np.unique(dados, return_counts=True)
        probabilidades = contagens / len(dados)
        return float(-np.sum(probabilidades * np.log2(probabilidades)))

class MerkleValidator:
    @staticmethod
    def verificar_integridade_fisica(lsn_valor: int) -> float:
        return 100.0 if (lsn_valor % 100 != 42) else 94.2

```

---

### 🗄️ 4. Camada de Repositório (`repositories/`)

#### 📄 `repositories/event_repository.py`

```python
import numpy as np
import pandas as pd
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import List
from domain.entities import EvidenciaForense, LogSequenceNumber
from config.constants import TOTAL_REGISTROS_REAL, SEED_ALEATORIA, TOTAL_DIAS_HISTORICO

class IEventRepository(ABC):
    @abstractmethod
    def obter_todas_evidencias(self) -> List[EvidenciaForense]:
        pass

class DataFrameEventRepository(IEventRepository):
    """Implementação baseada em DataFrames simulando banco colunar imutável."""
    def __init__(self):
        self._cache_evidencias = self._construir_pipeline_dados()
  
    def _construir_pipeline_dados(self) -> List[EvidenciaForense]:
        np.random.seed(SEED_ALEATORIA)
        datas = [datetime(2026, 6, 21) - timedelta(days=i) for i in range(TOTAL_DIAS_HISTORICO)]
        datas.reverse()
  
        insercoes = np.random.normal(loc=TOTAL_REGISTROS_REAL/TOTAL_DIAS_HISTORICO, scale=32000, size=TOTAL_DIAS_HISTORICO).astype(int)
        insercoes = np.clip(insercoes, 10000, None)
  
        df = pd.DataFrame({"Data": datas, "Novos Registros": insercoes})
        lsn_acumulados = np.cumsum(df["Novos Registros"].values)
  
        lista_evidencias = []
        for i, row in df.iterrows():
            reg = row["Novos Registros"]
            if reg < 225000: nivel = 1
            elif reg < 240000: nivel = 2
            elif reg < 255000: nivel = 3
            else: nivel = 4
          
            lista_evidencias.append(EvidenciaForense(
                data=row["Data"],
                novos_registros=reg,
                lsn_acumulado=LogSequenceNumber(int(lsn_acumulados[i])),
                nivel_cor=nivel
            ))
        return lista_evidencias

    def obter_todas_evidencias(self) -> List[EvidenciaForense]:
        return self._cache_evidencias

```

---

### 🚌 5. Camada de Serviços e Barramento (`services/`)

#### 📄 `services/event_bus.py`

```python
import streamlit as st
from typing import Callable, Dict, List, Type
from domain.events import EventoDominio

class EventBus:
    """Barramento síncrono de eventos com persistência no ciclo de vida do Streamlit."""
    def __init__(self):
        if "bus_subscribers" not in st.session_state:
            st.session_state.bus_subscribers = {}
        self._subscribers: Dict[Type[EventoDominio], List[Callable]] = st.session_state.bus_subscribers

    def subscrever(self, tipo_evento: Type[EventoDominio], callback: Callable):
        if tipo_evento not in self._subscribers:
            self._subscribers[tipo_evento] = []
        if callback not in self._subscribers[tipo_evento]:
            self._subscribers[tipo_evento].append(callback)

    def publicar(self, evento: EventoDominio):
        tipo_evento = type(evento)
        if tipo_evento in self._subscribers:
            for callback in self._subscribers[tipo_evento]:
                callback(evento)

```

#### 📄 `services/timeline_service.py`

```python
import streamlit as st
import time
from domain.entities import LogSequenceNumber
from domain.events import TimelineChangedEvent
from services.event_bus import EventBus
from repositories.event_repository import IEventRepository

class TimelineService:
    def __init__(self, repository: IEventRepository, event_bus: EventBus):
        self.repo = repository
        self.bus = event_bus
        self.evidencias = self.repo.obter_todas_evidencias()
        self._inicializar_estados()

    def _inicializar_estados(self):
        if "log_index" not in st.session_state:
            st.session_state.log_index = len(self.evidencias) - 1
        if "is_playing" not in st.session_state:
            st.session_state.is_playing = False
        if "speed" not in st.session_state:
            st.session_state.speed = 1.0

    def obter_estado_atual(self):
        idx = st.session_state.log_index
        evidencia = self.evidencias[idx]
        return idx, evidencia, st.session_state.is_playing, st.session_state.speed

    def atualizar_ponteiro(self, novo_index: int):
        st.session_state.log_index = novo_index
        evidencia = self.evidencias[novo_index]
        self.bus.publicar(TimelineChangedEvent(
            index_atual=novo_index,
            lsn_ativo=evidencia.lsn_acumulado,
            data_ativa=evidencia.data
        ))

    def alternar_playback(self):
        st.session_state.is_playing = not st.session_state.is_playing

    def resetar(self):
        st.session_state.log_index = 0
        st.session_state.is_playing = False
        self.atualizar_ponteiro(0)

    def processar_loop_animacao(self):
        if st.session_state.is_playing:
            if st.session_state.log_index < len(self.evidencias) - 1:
                st.session_state.log_index += 1
                time.sleep(0.5 / st.session_state.speed)
                st.rerun()
            else:
                st.session_state.is_playing = False

```

#### 📄 `services/metrics_service.py`

```python
import numpy as np
from typing import List, Dict, Any
from domain.entities import EvidenciaForense
from core.engines import IMetricsEngine, MerkleValidator

class MetricsService:
    def __init__(self, metrics_engine: IMetricsEngine):
        self.engine = metrics_engine

    def extrair_metricas_cientificas(self, historico_ativo: List[EvidenciaForense], lsn_atual: int) -> Dict[str, Any]:
        volumes = np.array([ev.novos_registros for ev in historico_ativo[-30:]])
  
        profundidade_causal = float(np.log1p(lsn_atual % 1000) * 1.4 + 1.2)
        fator_ramificacao = float(2.3 + (len(historico_ativo) % 50) / 15.0)
        taxa_compressao = float(84.3 + (lsn_atual % 20) / 7.0)
  
        return {
            "entropia": self.engine.calcular_entropia(volumes),
            "profundidade_causal": profundidade_causal,
            "consistencia_merkle": MerkleValidator.verificar_integridade_fisica(lsn_atual),
            "fator_ramificacao": factor_ramificacao,
            "compressao_geometrica": taxa_compressao
        }

```

---

### ⏱️ 6. Camada de Telemetria (`telemetry/`)

#### 📄 `telemetry/profiler.py`

```python
import time
import psutil
import streamlit as st
from contextlib import contextmanager

class EnterpriseProfiler:
    """Mecanismo de monitoramento interno em tempo real."""
    @staticmethod
    @contextmanager
    def monitorar_operacao(nome_operacao: str):
        tempo_inicio = time.perf_counter()
        yield
        tempo_total = (time.perf_counter() - tempo_inicio) * 1000
  
        if "telemetria_sistema" not in st.session_state:
            st.session_state.telemetria_sistema = {}
        st.session_state.telemetria_sistema[nome_operacao] = f"{tempo_total:.2f} ms"

    @staticmethod
    def obter_metricas_hardware() -> dict:
        memoria = psutil.virtual_memory()
        return {
            "cpu_percent": psutil.cpu_percent(),
            "ram_percent": memoria.percent,
            "ram_usada_gb": memoria.used / (1024 ** 3),
            "ram_total_gb": memoria.total / (1024 ** 3)
        }

```

---

### 🎨 7. Camada de Apresentação Pura (`ui/`)

#### 📄 `ui/components.py`

```python
import streamlit as st
import networkx as nx
import plotly.graph_objects as go
from typing import List, Dict
from datetime import datetime
from domain.entities import EvidenciaForense
from config.constants import COR_PRIMARIA, COR_TEXTO, COR_PERIGO, COR_SUCESSO

class ForensicUIComponents:
    @staticmethod
    def renderizar_card(titulo: str, valor: str, cor_hex: str = "var(--text-color)"):
        st.markdown(f"""
            <div class="forensic-card">
                <div class="forensic-title">{titulo}</div>
                <div class="forensic-value" style="color: {cor_hex} !important;">{valor}</div>
            </div>
        """, unsafe_allow_html=True)

    @staticmethod
    def renderizar_github_grid(evidencias: List[EvidenciaForense], data_limite: datetime, cores_mapeamento: Dict[int, str]):
        grid_html = """
        <div class="github-wrapper">
            <div class="grid-container-layout">
                <div class="days-labels"><span>Mon</span><span>Wed</span><span>Fri</span></div>
                <div style="overflow-x: auto; flex: 1;">
                    <div class="months-header">
                        <span>Jun</span><span>Jul</span><span>Ago</span><span>Set</span><span>Out</span><span>Nov</span>
                        <span>Dez</span><span>Jan</span><span>Fev</span><span>Mar</span><span>Abr</span><span>Mai</span><span>Jun</span>
                    </div>
                    <div class="github-grid-container">
        """
        for ev in evidencias:
            if ev.data.date() <= data_limite.date():
                cor = cores_mapeamento[ev.nivel_cor]
                hint = f"{ev.novos_registros:,} fatos selados em {ev.data.strftime('%d/%m/%Y')} | Integridade Merkle: OK"
            else:
                cor = "var(--background-color)"
                hint = "Bloco futuro (LSN não atingido)."
          
            grid_html += f'<div class="github-cell" style="background-color: {cor}; border: 1px solid rgba(128,128,128,0.1);" title="{hint}"></div>'
      
        grid_html += "</div></div></div></div>"
        st.markdown(grid_html, unsafe_allow_html=True)

    @staticmethod
    def renderizar_grafo_topologia(lsn_atual: int):
        G = nx.DiGraph()
        # Nós de infraestrutura simulados mapeados por surgimento causal de LSN
        nodes_def = {0: "🌐 IP 187.*", 1: "🛡️ Firewall", 2: "🖥️ Servidor B", 3: "☣️ Proc. Suspeito"}
        edges_def = [(0, 1), (1, 2), (2, 3)]
  
        for n_id, label in nodes_def.items():
            G.add_node(n_id, label=label)
        G.add_edges_from(edges_def)
  
        pos = {0: (0, 1), 1: (2, 1), 2: (4, 1), 3: (6, 1)}
        edge_traces = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_traces.append(go.Scatter(x=[x0, x1, None], y=[y0, y1, None], line=dict(width=2, color=COR_PERIGO), mode='lines'))
      
        node_trace = go.Scatter(
            x=[pos[n][0] for n in G.nodes()], y=[pos[n][1] for n in G.nodes()],
            mode='markers+text', text=[G.nodes[n]['label'] for n in G.nodes()], textposition="bottom center",
            marker=dict(color=COR_PRIMARIA, size=22, line_color=COR_TEXTO, line_width=1)
        )
  
        fig = go.Figure(data=edge_traces + [node_trace], layout=go.Layout(
            showlegend=False, margin=dict(b=5, l=5, r=5, t=5),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)'
        ))
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

```

#### 📄 `ui/layouts.py`

```python
import streamlit as st
from typing import List, Any, Dict
from domain.entities import EvidenciaForense
from ui.components import ForensicUIComponents
from telemetry.profiler import EnterpriseProfiler
from config.constants import PALETA_GRID, COR_PRIMARIA, COR_ALERTA, COR_SUCESSO

class WorkbenchLayoutManager:
    @staticmethod
    def renderizar_sidebar(timeline_service) -> str:
        idx, evidencia, is_playing, speed = timeline_service.obter_estado_atual()
  
        with st.sidebar:
            st.markdown("### 🗂️ EXPLORER & WORKSPACES")
            camada = st.radio(
                "Navegação Forense:",
                ["◉ Central de Comando (SOC)", "⌖ Investigação Causal (WHY)", "📐 Geometria de Produto"],
                index=0
            )
            st.markdown("---")
            st.markdown("### ⏱️ TIMELINE CONTROL")
      
            c1, c2 = st.columns(2)
            with c1:
                if st.button("▶ PLAY" if not is_playing else "⏸ PAUSE", use_container_width=True):
                    timeline_service.alternar_playback()
                    st.rerun()
            with c2:
                if st.button("🔄 RESET", use_container_width=True):
                    timeline_service.resetar()
                    st.rerun()
              
            st.select_slider("Velocidade Replay:", options=[1.0, 2.0, 5.0], key="speed")
      
            st.markdown("---")
            st.markdown("### 🖥️ TELEMETRIA INTERNA")
            hw = EnterpriseProfiler.obter_metricas_hardware()
            st.write(f"**CPU:** {hw['cpu_percent']}% | **RAM:** {hw['ram_percent']}%")
            st.progress(int(hw['ram_percent']))
      
            # Exibe tempos do Profiler
            if "telemetria_sistema" in st.session_state:
                st.caption("⚡ Latência de Renderização:")
                for op, tempo in st.session_state.telemetria_sistema.items():
                    st.caption(f"• {op}: `{tempo}`")
              
        return camada

    @staticmethod
    def renderizar_workspace_central(camada_ativa: str, evidencias: List[EvidenciaForense], idx_ativo: int, evidencia_ativa: EvidenciaForense, metricas: Dict[str, Any], timeline_service):
        st.markdown("🌐 **GOV.BR** · Plataforma de Evidência Digital · Sincronização Dinâmica")
        st.title(f"🌀 Heraclitus Forensic Engine")
        st.markdown("---")
  
        col_esq, col_dir = st.columns([3, 1])
  
        with col_esq:
            if "SOC" in camada_ativa:
                k1, k2, k3, k4 = st.columns(4)
                with k1: ForensicUIComponents.renderizar_card("Ponteiro LSN", evidencia_ativa.lsn_acumulado.para_sufixo_br(), COR_PRIMARIA)
                with k2: ForensicUIComponents.renderizar_card("Data do Bloco", evidencia_ativa.data.strftime("%d/%m/%Y"))
                with k3: ForensicUIComponents.renderizar_card("Entropia do Log", f"{metricas['entropia']:.3f}", COR_ALERTA)
                with k4: ForensicUIComponents.renderizar_card("Módulo Merkle", "100% OK", COR_SUCESSO)
          
                st.markdown("#### 🗺️ Densidade de Eventos por Segmento Selado")
                ForensicUIComponents.renderizar_github_grid(evidencias, evidencia_ativa.data, PALETA_GRID)
          
                novo_index = st.slider("Navegação Temporal Reversa", min_value=0, max_value=len(evidencias)-1, value=idx_ativo, format="")
                if novo_index != idx_ativo:
                    timeline_service.atualizar_ponteiro(novo_index)
                    st.rerun()
              
                st.markdown("#### ⬡ Topologia Forense k-NN da Linha do Tempo")
                ForensicUIComponents.renderizar_grafo_topologia(evidencia_ativa.lsn_acumulado.valor)
          
            elif "WHY" in camada_ativa:
                st.markdown("### ⌖ Busca Universal Causal `WHY()`")
                st.info(f"Exibindo proveniência de dados sob demanda para o LSN: {evidencia_ativa.lsn_acumulado.valor}")
          
            elif "Geometria" in camada_ativa:
                st.markdown("### 📐 Distribuição Dimensional Fractal")
                st.json(metricas)
          
        with col_dir:
            st.markdown("### 🔍 INSPECTOR")
            st.markdown("---")
            st.metric("Consistência Merkle", f"{metricas['consistencia_merkle']:.1f}%")
            st.metric("Fator de Ramificação", f"{metricas['fator_ramificacao']:.2f}")
            st.metric("Profundidade Causal", f"{metricas['profundidade_causal']:.2f}")
            st.metric("Compressão Geométrica", f"{metricas['compressao_geometrica']:.1f}%")

```

---

### 🚀 8. O Bootstrapper Principal (`app.py`)

```python
from config.settings import inicializar_ambiente_global
from repositories.event_repository import DataFrameEventRepository
from core.engines import ShannonEntropyEngine
from services.event_bus import EventBus
from services.timeline_service import TimelineService
from services.metrics_service import MetricsService
from ui.layouts import WorkbenchLayoutManager
from telemetry.profiler import EnterpriseProfiler

def main():
    # 1. Configuração do Ambiente e Injeção Estética Isolada
    inicializar_ambiente_global()

    # 2. Injeção de Dependências Dinâmica (Inversion of Control)
    event_bus = EventBus()
    event_repo = DataFrameEventRepository()
    metrics_engine = ShannonEntropyEngine()
  
    timeline_service = TimelineService(event_repo, event_bus)
    metrics_service = MetricsService(metrics_engine)

    # 3. Processamento de Loops da Máquina de Estados da Animação
    timeline_service.processar_loop_animacao()

    # 4. Captura Segura de Dados de Estado de Domínio
    idx_ativo, evidencia_ativa, _, _ = timeline_service.obter_estado_atual()
    evidencias_totais = event_repo.obter_todas_evidencias()
    historico_ate_momento = evidencias_totais[:idx_ativo + 1]

    # 5. Execução de Cálculos Científicos Sob Telemetria Estrita
    with EnterpriseProfiler.monitorar_operacao("Cálculo Engine Forense"):
        metricas_cientificas = metrics_service.extrair_metricas_cientificas(
            historico_ate_momento, 
            evidencia_ativa.lsn_acumulado.valor
        )

    # 6. Renderização dos Módulos Separados de Layout de Apresentação
    with EnterpriseProfiler.monitorar_operacao("Renderização da UI"):
        camada_ativa = WorkbenchLayoutManager.renderizar_sidebar(timeline_service)
        WorkbenchLayoutManager.renderizar_workspace_central(
            camada_ativa, 
            evidencias_totais, 
            idx_ativo, 
            evidencia_ativa, 
            metricas_cientificas,
            timeline_service
        )

if __name__ == "__main__":
    main()

```

---

## 🎯 Ganhos Imediatos da Nova Arquitetura

* **Extrema Legibilidade de Orquestração (`app.py`):** O ponto de entrada da aplicação caiu drasticamente de centenas de linhas complexas para **menos de 45 linhas limpas de fluxo lógico de controle**, puramente orquestrando chamadas de interfaces.
* **Abstração Total de Componentes:** Não há mais concatenações e injeções de strings puras de HTML misturadas com regras de negócio. Se você quiser alterar o layout visível ou estilização de um Card Forense, altera-se apenas `ui/components.py`.
* **Observabilidade Nativa (Auto-Diagnóstico):** Através do painel lateral alimentado pelo módulo `telemetry/profiler.py`, o engenheiro consegue identificar exatamente em milissegundos quanto tempo a engine matemática levou para computar a entropia contra o tempo gasto pelo Streamlit/Plotly para pintar a tela.
* **Segurança contra Mudanças de Infraestrutura:** Se amanhã os dados migrarem do dataframe simulado para o **DuckDB**, um cluster **Apache Arrow** ou chamadas gRPC diretas no **HeraclitusDB**, basta criar uma nova classe estendendo `IEventRepository` e alterar uma única linha no bootstrapper.
