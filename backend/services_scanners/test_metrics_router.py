"""
Router para receber métricas de teste do atacante (attack_runner.py).

Permite que o script no Linux atacante envie attack_start e access_lost
para correlação com dados do IDS e da API.
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/test", tags=["Teste - Métricas"])

# Diretório para armazenar métricas recebidas (fallback se não houver banco)
METRICS_DIR = Path(__file__).parent.parent.parent / "data" / "attack_metrics"


@router.post("/attack-metrics", summary="Receber métricas de ataque do atacante")
async def receive_attack_metrics(
    payload: dict,
    x_api_key: Optional[str] = Header(None, description="Chave API (opcional)"),
):
    """
    Recebe registro de ataque do script attack_runner.py.

    Payload esperado:
    - attack_id: ID do tipo de ataque
    - attack_name: Nome do ataque
    - attack_start: ISO timestamp do início
    - access_lost: ISO timestamp da perda de acesso (ou null)
    - target: URL alvo
    - attacker_ip: IP do atacante
    """
    try:
        record = {
            "attack_id": payload.get("attack_id"),
            "attack_name": payload.get("attack_name"),
            "attack_start": payload.get("attack_start"),
            "access_lost": payload.get("access_lost"),
            "target": payload.get("target"),
            "attacker_ip": payload.get("attacker_ip"),
            "received_at": datetime.now().isoformat(),
        }

        # Salvar em arquivo para coleta posterior
        METRICS_DIR.mkdir(parents=True, exist_ok=True)
        filename = f"attack_{record['attacker_ip'] or 'unknown'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = METRICS_DIR / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)

        logger.info("Métrica de ataque recebida: %s", record.get("attack_name"))
        return {"success": True, "saved": str(filepath)}
    except Exception as e:
        logger.error("Erro ao salvar métrica de ataque: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-metrics", summary="Listar métricas de ataque recebidas")
async def list_attack_metrics(attacker_ip: Optional[str] = None, limit: int = 100):
    """Lista métricas de ataque salvas (para coleta)."""
    if not METRICS_DIR.exists():
        return {"attacks": []}
    files = sorted(METRICS_DIR.glob("attack_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    attacks = []
    for f in files[:limit]:
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            if attacker_ip and data.get("attacker_ip") != attacker_ip:
                continue
            attacks.append(data)
        except Exception:
            pass
    return {"attacks": attacks}


@router.get("/blocking-metrics", summary="Coletar métricas de detecção e bloqueio")
async def get_blocking_metrics(
    src_ip: Optional[str] = Query(None, description="Filtrar por IP do atacante"),
    ids: str = Query("snort,suricata", description="IDS a consultar: snort,suricata,zeek"),
    since: Optional[str] = Query(None, description="Data/hora inicial YYYY-MM-DD HH:MM"),
    log_path: str = Query("log_test.txt", description="Caminho do log_test.txt"),
):
    """
    Executa a coleta de métricas: correlaciona log_test.txt com raw_log_data dos IDS.
    Retorna T_ids_to_block (detecção IDS → bloqueio) e tempos granulares.
    """
    try:
        from pathlib import Path
        from datetime import datetime

        backend_dir = Path(__file__).parent.parent
        import sys
        if str(backend_dir) not in sys.path:
            sys.path.insert(0, str(backend_dir))

        from scripts.collect_test_metrics import (
            parse_log_test,
            get_alerts_from_ids,
            correlate,
        )

        log_file = Path(log_path)
        if not log_file.is_absolute():
            for base in [Path(__file__).parent.parent, Path.cwd()]:
                candidate = base / log_path
                if candidate.exists():
                    log_file = candidate
                    break
            else:
                log_file = Path(__file__).parent.parent / log_path
        if not log_file.exists():
            raise HTTPException(status_code=404, detail=f"Arquivo não encontrado: {log_path}")

        since_dt = None
        if since:
            try:
                since_dt = datetime.strptime(since, "%Y-%m-%d %H:%M")
            except ValueError:
                since_dt = datetime.strptime(since, "%Y-%m-%d")

        blocking_starts, syncs, blockings = parse_log_test(str(log_file))
        ids_list = [x.strip().lower() for x in ids.split(",") if x.strip() in ("snort", "suricata", "zeek")]
        if not ids_list:
            ids_list = ["snort", "suricata"]
        alerts = get_alerts_from_ids(ids_list, src_ip=src_ip, since=since_dt)
        results = correlate(blocking_starts, syncs, blockings, alerts, src_ip)

        return {
            "results": results,
            "summary": {
                "total": len(results),
                "blocking_starts": len(blocking_starts),
                "syncs": len(syncs),
                "blockings": len(blockings),
                "alerts": len(alerts),
            },
            "collected_at": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Erro ao coletar métricas: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
