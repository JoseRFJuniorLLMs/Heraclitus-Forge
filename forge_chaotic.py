"""
Heraclitus Forge — Módulo de Entrada Caótica (Chaotic Ingestion).

Conforme o Diagrama do Pipeline de Processamento de Dados:
Ingere e normaliza os três canais fundamentais de entrada:
  1. Logs Brutos: linhas de logs de sistemas, servidores, firewalls (JSON, TXT, Syslog).
  2. Sementes de Prompt: templates de instrução, diretrizes e prompts de tarefas.
  3. Dump de Interações: transcrições de diálogos, conversas multi-turno e histórico de agentes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class InputType(str, Enum):
    RAW_LOG = "raw_log"
    PROMPT_SEED = "prompt_seed"
    INTERACTION_DUMP = "interaction_dump"


@dataclass
class ChaoticItem:
    """Representa um elemento de entrada caótica normalizado para a Forja Dialética."""

    id: str
    input_type: InputType
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    context: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "input_type": self.input_type.value,
            "content": self.content,
            "metadata": self.metadata,
            "context": self.context,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChaoticItem:
        return cls(
            id=data["id"],
            input_type=InputType(data["input_type"]),
            content=data["content"],
            metadata=data.get("metadata", {}),
            context=data.get("context"),
        )


class ChaoticIngestion:
    """Carregador e normalizador de entradas caóticas."""

    @staticmethod
    def from_raw_logs(logs: list[str], source_name: str = "raw_stream") -> list[ChaoticItem]:
        """Ingere uma lista de linhas de log brutas."""
        items = []
        for idx, line in enumerate(logs):
            cleaned = line.strip()
            if not cleaned:
                continue
            item_id = f"log_{source_name}_{idx:05d}"
            # Tenta verificar se o log é um JSON serializado
            meta = {"source": source_name, "raw_format": "text"}
            if (cleaned.startswith("{") and cleaned.endswith("}")) or (
                cleaned.startswith("[") and cleaned.endswith("]")
            ):
                try:
                    parsed = json.loads(cleaned)
                    meta["raw_format"] = "json"
                    meta["parsed_keys"] = list(parsed.keys()) if isinstance(parsed, dict) else []
                except (json.JSONDecodeError, ValueError):
                    pass

            items.append(
                ChaoticItem(
                    id=item_id,
                    input_type=InputType.RAW_LOG,
                    content=cleaned,
                    metadata=meta,
                )
            )
        return items

    @staticmethod
    def from_prompt_seeds(
        seeds: list[str | dict[str, Any]], template_name: str = "seed"
    ) -> list[ChaoticItem]:
        """Ingere sementes de prompt (templates ou tarefas instrutivas)."""
        items = []
        for idx, seed in enumerate(seeds):
            item_id = f"seed_{template_name}_{idx:05d}"
            if isinstance(seed, str):
                content = seed.strip()
                meta = {"template": template_name}
                context = None
            else:
                content = seed.get("instruction") or seed.get("prompt") or str(seed)
                meta = {
                    k: v for k, v in seed.items() if k not in ("instruction", "prompt", "context")
                }
                context = seed.get("context")

            if content:
                items.append(
                    ChaoticItem(
                        id=item_id,
                        input_type=InputType.PROMPT_SEED,
                        content=content,
                        metadata=meta,
                        context=context,
                    )
                )
        return items

    @staticmethod
    def from_interaction_dump(
        interactions: list[str | dict[str, Any] | list[dict[str, str]]],
        session_prefix: str = "chat",
    ) -> list[ChaoticItem]:
        """Ingere dumps de diálogos, transcrições de chat ou conversas multi-turno."""
        items = []
        for idx, interaction in enumerate(interactions):
            item_id = f"interaction_{session_prefix}_{idx:05d}"
            if isinstance(interaction, str):
                content = interaction.strip()
                meta = {"format": "text_dialogue"}
            elif isinstance(interaction, list):
                # Formato padrão de mensagens [{'role': 'user', 'content': '...'}, ...]
                content = json.dumps(interaction, ensure_ascii=False)
                meta = {"format": "messages_array", "turn_count": len(interaction)}
            else:
                # Dicionário com histórico
                content = interaction.get("conversation") or json.dumps(
                    interaction, ensure_ascii=False
                )
                meta = {k: v for k, v in interaction.items() if k != "conversation"}

            if content:
                items.append(
                    ChaoticItem(
                        id=item_id,
                        input_type=InputType.INTERACTION_DUMP,
                        content=content,
                        metadata=meta,
                    )
                )
        return items

    @classmethod
    def load_from_file(cls, file_path: str | Path) -> list[ChaoticItem]:
        """Carrega dados de arquivo detectando automaticamente a extensão e o tipo."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Arquivo não encontrado: {path}")

        ext = path.suffix.lower()
        text = path.read_text(encoding="utf-8")

        if ext == ".jsonl":
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            parsed_entries = []
            for ln in lines:
                try:
                    parsed_entries.append(json.loads(ln))
                except (json.JSONDecodeError, ValueError):
                    parsed_entries.append(ln)

            # Heurística de classificação de tipo
            if parsed_entries and isinstance(parsed_entries[0], dict):
                first = parsed_entries[0]
                if "instruction" in first or "prompt" in first:
                    return cls.from_prompt_seeds(parsed_entries, template_name=path.stem)
                elif "messages" in first or "conversation" in first:
                    return cls.from_interaction_dump(parsed_entries, session_prefix=path.stem)
                elif "input_type" in first:
                    return [ChaoticItem.from_dict(d) for d in parsed_entries]

            return cls.from_raw_logs(lines, source_name=path.stem)

        elif ext == ".json":
            data = json.loads(text)
            if isinstance(data, list):
                if (
                    data
                    and isinstance(data[0], dict)
                    and ("instruction" in data[0] or "prompt" in data[0])
                ):
                    return cls.from_prompt_seeds(data, template_name=path.stem)
                elif (
                    data
                    and isinstance(data[0], dict)
                    and ("messages" in data[0] or "conversation" in data[0])
                ):
                    return cls.from_interaction_dump(data, session_prefix=path.stem)
                elif data and isinstance(data[0], dict) and "input_type" in data[0]:
                    return [ChaoticItem.from_dict(d) for d in data]
                return cls.from_raw_logs([json.dumps(d) for d in data], source_name=path.stem)
            elif isinstance(data, dict):
                return cls.from_prompt_seeds([data], template_name=path.stem)

        # Fallback para TXT / LOG
        lines = [ln for ln in text.splitlines() if ln.strip()]
        return cls.from_raw_logs(lines, source_name=path.stem)
