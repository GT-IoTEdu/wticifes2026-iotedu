"""
Router para integração com Snort IDS/IPS
Fornece endpoint SSE para receber alertas em tempo real, persiste no banco
e aplica bloqueio automático para alertas de severidade alta.
Bloqueio é serializado em uma fila; eventos duplicados (mesmo tipo de ataque, IP e horário) não são enfileirados.
"""
import json
import logging
import queue
import threading
import time
from datetime import datetime
from typing import Optional

import requests
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from auth.dependencies import get_authenticated_user
from db.enums import IncidentSeverity
from db.models import SnortAlert
from db.session import SessionLocal
from services_firewalls.institution_config_service import InstitutionConfigService
from services_scanners.ids_sse_tls import sse_requests_verify
from services_scanners.sse_hmac import verify_and_strip_hmac
from services_scanners.snort_service import SnortService

logger = logging.getLogger(__name__)

# Fila de bloqueio Snort: um único worker processa um bloqueio por vez (evita esgotar pool)
_snort_block_queue = queue.Queue()
_snort_block_lock = threading.Lock()
# IPs já enfileirados ou bloqueados nesta sessão - evita múltiplos bloqueios do mesmo IP em sequência
_snort_ips_queued_or_blocked: set = set()
# Chaves já enfileiradas: (attack_type, src_ip, time_key) — evita duplicatas por mesmo evento (tipo + IP + horário)
_snort_block_dedup_keys: set = set()


def _snort_block_worker() -> None:
    """Worker único: processa bloqueios Snort um a um para não esgotar o pool de conexões."""
    while True:
        try:
            item = _snort_block_queue.get()
            if item is None:
                break
            alert_id, institution_id, src_ip = item
            _trigger_snort_auto_block(alert_id, institution_id, src_ip)
        except Exception as e:
            logger.error("Erro no worker de bloqueio Snort: %s", e, exc_info=True)
        finally:
            try:
                _snort_block_queue.task_done()
            except Exception:
                pass


# Inicia o worker em background (daemon)
_snort_block_worker_thread = threading.Thread(target=_snort_block_worker, daemon=True, name="snort-block-worker")
_snort_block_worker_thread.start()


def _snort_dedup_key(attack_type: str, src_ip: str, event_time: str) -> tuple:
    """Gera chave de desduplicação: (tipo de ataque, IP, horário ao minuto)."""
    at = (attack_type or "").strip()[:200]
    time_key = (event_time or "")[:16]  # "YYYY-MM-DDTHH:MM"
    return (at, (src_ip or "").strip(), time_key)


def clear_snort_blocked_ip(ip: str) -> None:
    """
    Remove um IP do conjunto de bloqueados. Chamado quando o administrador libera o IP manualmente.
    Permite que novos ataques desse IP sejam enfileirados e bloqueados novamente.
    """
    ip = (ip or "").strip()
    if not ip:
        return
    with _snort_block_lock:
        removed = ip in _snort_ips_queued_or_blocked
        _snort_ips_queued_or_blocked.discard(ip)
        _snort_block_dedup_keys.difference_update({k for k in _snort_block_dedup_keys if k[1] == ip})
        if removed:
            logger.info("IP %s removido da lista de bloqueados Snort (admin liberou) - novos ataques serão bloqueados", ip)


def _is_ip_in_bloqueados(ip: str, institution_id: int) -> bool:
    """Verifica se o IP está no alias Bloqueados da instituição (banco de dados)."""
    try:
        from services_firewalls.alias_service import AliasService
        with AliasService(institution_id=institution_id) as alias_service:
            blocked = alias_service.get_alias_by_name("Bloqueados")
            if not blocked or not blocked.get("addresses"):
                return False
            addresses = [a.get("address", "").strip() for a in blocked["addresses"] if a.get("address")]
            return ip in addresses
    except Exception as e:
        logger.warning("Erro ao verificar se IP %s está em Bloqueados: %s", ip, e)
        return True  # Em caso de erro, assumir que está bloqueado (não enfileirar de novo)


def _enqueue_snort_auto_block(
    alert_id: int,
    institution_id: int,
    src_ip: str,
    attack_type: Optional[str] = None,
    event_time: Optional[str] = None,
) -> None:
    """Enfileira bloqueio evitando duplicatas por (tipo de ataque, IP, horário).
    Se já existir evento com os mesmos parâmetros, não enfileira. Também evita múltiplos bloqueios
    do mesmo IP em sequência; se o admin liberou o IP, permite novo bloqueio."""
    src_ip = (src_ip or "").strip()
    if not src_ip or src_ip.upper() == "N/A":
        return
    with _snort_block_lock:
        if attack_type is not None and event_time is not None:
            dedup_key = _snort_dedup_key(attack_type, src_ip, event_time)
            if dedup_key in _snort_block_dedup_keys:
                logger.debug(
                    "Evento duplicado ignorado (tipo=%s, IP=%s, tempo=%s), alerta %s não enfileirado",
                    (attack_type or "")[:50], src_ip, (event_time or "")[:16], alert_id,
                )
                return
            _snort_block_dedup_keys.add(dedup_key)
        if src_ip in _snort_ips_queued_or_blocked:
            if _is_ip_in_bloqueados(src_ip, institution_id):
                logger.debug("IP %s já enfileirado/bloqueado, ignorando alerta %s (evita bloqueios repetidos)", src_ip, alert_id)
                return
            _snort_ips_queued_or_blocked.discard(src_ip)
            logger.info("IP %s liberado pelo admin (não está em Bloqueados) - enfileirando novo bloqueio", src_ip)
        _snort_ips_queued_or_blocked.add(src_ip)
    try:
        _snort_block_queue.put((alert_id, institution_id, src_ip), block=False)
    except queue.Full:
        with _snort_block_lock:
            _snort_ips_queued_or_blocked.discard(src_ip)
            if attack_type is not None and event_time is not None:
                _snort_block_dedup_keys.discard(_snort_dedup_key(attack_type, src_ip, event_time))
        logger.warning("Fila de bloqueio Snort cheia, ignorando alerta %s", alert_id)


def _save_snort_alert(institution_id: int, normalized_alert: dict) -> Optional[int]:
    """Persiste um alerta normalizado do Snort na tabela snort_alerts. Retorna o id do registro ou None."""
    try:
        ts = normalized_alert.get("timestamp") or ""
        try:
            detected_at = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            detected_at = datetime.utcnow()

        severity_str = (normalized_alert.get("severity") or "medium").lower()
        severity_enum = (
            IncidentSeverity(severity_str)
            if severity_str in ("low", "medium", "high", "critical")
            else IncidentSeverity.MEDIUM
        )

        raw = normalized_alert.get("raw")
        raw_log_data = json.dumps(raw, ensure_ascii=False) if raw else None

        record = SnortAlert(
            institution_id=institution_id,
            detected_at=detected_at,
            signature=(normalized_alert.get("signature") or "")[:500],
            signature_id=(str(normalized_alert.get("signature_id") or ""))[:50],
            severity=severity_enum,
            src_ip=(normalized_alert.get("src_ip") or "")[:45],
            dest_ip=(normalized_alert.get("dest_ip") or "")[:45],
            src_port=(str(normalized_alert.get("src_port") or ""))[:20],
            dest_port=(str(normalized_alert.get("dest_port") or ""))[:20],
            protocol=(normalized_alert.get("protocol") or "")[:20],
            category=(normalized_alert.get("category") or "")[:255],
            raw_log_data=raw_log_data,
        )
        db = SessionLocal()
        try:
            db.add(record)
            db.commit()
            db.refresh(record)
            logger.debug("Alerta Snort persistido: id=%s", record.id)
            return record.id
        finally:
            db.close()
    except Exception as e:
        logger.warning("Falha ao salvar alerta Snort no banco: %s", e, exc_info=True)
        return None


def _trigger_snort_auto_block(alert_id: int, institution_id: int, src_ip: str) -> None:
    """Executado em thread: aplica bloqueio automático para alerta Snort de severidade alta."""
    queued_ip = (src_ip or "").strip()
    try:
        time.sleep(0.5)
        from services_scanners.incident_service import IncidentService

        # Ler alerta e liberar conexão antes do I/O ao pfSense (evita esgotar pool)
        signature = None
        detected_at = None
        db = SessionLocal()
        try:
            alert = db.query(SnortAlert).filter(SnortAlert.id == alert_id).first()
            if not alert:
                logger.warning("Alerta Snort %s não encontrado para bloqueio automático", alert_id)
                with _snort_block_lock:
                    _snort_ips_queued_or_blocked.discard(queued_ip)
                return
            if alert.processed_at is not None:
                return
            if alert.severity not in (IncidentSeverity.HIGH, IncidentSeverity.CRITICAL):
                logger.debug("Alerta Snort %s não é HIGH/CRITICAL (severity=%s), bloqueio apenas para HIGH/CRITICAL", alert_id, alert.severity)
                with _snort_block_lock:
                    _snort_ips_queued_or_blocked.discard(queued_ip)
                return
            src_ip = (alert.src_ip or "").strip()
            if not src_ip:
                logger.warning("Alerta Snort %s sem src_ip, bloqueio ignorado", alert_id)
                with _snort_block_lock:
                    _snort_ips_queued_or_blocked.discard(queued_ip)
                return
            signature = (alert.signature or "")[:200]
            detected_at = alert.detected_at
        finally:
            db.close()

        if not src_ip:
            return
        incident_service = IncidentService()
        success = incident_service.apply_auto_block_for_device(
            device_ip=src_ip,
            institution_id=institution_id,
            source_type="snort",
            source_id=alert_id,
            description=signature or "",
            detected_at=detected_at,
        )
        if success:
            db2 = SessionLocal()
            try:
                alert = db2.query(SnortAlert).filter(SnortAlert.id == alert_id).first()
                if alert:
                    alert.processed_at = datetime.utcnow()
                    db2.commit()
                logger.info("Bloqueio automático Snort aplicado para IP %s (alerta %s)", src_ip, alert_id)
            finally:
                db2.close()
        else:
            logger.warning("Falha ao aplicar bloqueio automático Snort para alerta %s (IP %s)", alert_id, src_ip)
            with _snort_block_lock:
                _snort_ips_queued_or_blocked.discard(queued_ip)
    except Exception as e:
        logger.error("Erro ao processar bloqueio automático Snort para alerta %s: %s", alert_id, e, exc_info=True)
        with _snort_block_lock:
            _snort_ips_queued_or_blocked.discard(queued_ip)


router = APIRouter(prefix="/scanners/snort", tags=["Snort"])


def _resolve_institution_id(user_id: Optional[int], institution_id: Optional[int]) -> Optional[int]:
    if institution_id:
        return institution_id
    if user_id:
        try:
            config = InstitutionConfigService.get_user_institution_config(user_id=user_id)
            if config:
                return config.get("institution_id")
        except Exception as e:
            logger.warning("Erro ao buscar instituição do usuário %s: %s", user_id, e)
    return None


@router.get("/alerts", summary="Listar alertas do Snort salvos no banco (paginado)")
async def list_snort_alerts(
    user_id: Optional[int] = Query(None, description="ID do usuário"),
    institution_id: Optional[int] = Query(None, description="ID da instituição"),
    limit: int = Query(10, ge=1, le=100, description="Itens por página"),
    offset: int = Query(0, ge=0, description="Offset para paginação"),
    authenticated_user: dict = Depends(get_authenticated_user),
):
    """Retorna alertas da tabela snort_alerts (mais recentes primeiro), com total para paginação."""
    if user_id is not None and int(user_id) != int(authenticated_user["id"]):
        raise HTTPException(status_code=403, detail="user_id não corresponde ao usuário autenticado.")
    user_id = int(authenticated_user["id"])
    inst_id = _resolve_institution_id(user_id, institution_id)
    if not inst_id:
        raise HTTPException(
            status_code=400,
            detail="É necessário fornecer institution_id ou user_id para identificar a instituição.",
        )
    db = SessionLocal()
    try:
        base_q = db.query(SnortAlert).filter(SnortAlert.institution_id == inst_id)
        total = base_q.count()
        rows = (
            base_q.order_by(SnortAlert.detected_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        items = [
            {
                "id": r.id,
                "timestamp": r.detected_at.isoformat() if r.detected_at else None,
                "signature": r.signature,
                "signature_id": r.signature_id,
                "severity": r.severity.value if r.severity else None,
                "src_ip": r.src_ip,
                "dest_ip": r.dest_ip,
                "src_port": r.src_port,
                "dest_port": r.dest_port,
                "protocol": r.protocol,
                "category": r.category,
            }
            for r in rows
        ]
        return {"items": items, "total": total}
    finally:
        db.close()


@router.get("/health", summary="Verificar saúde da integração com Snort")
async def snort_health(
    user_id: Optional[int] = Query(None, description="ID do usuário para buscar configurações"),
    institution_id: Optional[int] = Query(None, description="ID da instituição"),
    authenticated_user: dict = Depends(get_authenticated_user),
):
    """Verifica se a integração com Snort está funcionando."""
    try:
        if user_id is not None and int(user_id) != int(authenticated_user["id"]):
            raise HTTPException(status_code=403, detail="user_id não corresponde ao usuário autenticado.")
        user_id = int(authenticated_user["id"])
        service = SnortService(user_id=user_id, institution_id=institution_id)
        result = service.test_connection()
        return result
    except Exception as e:
        logger.error("Erro ao verificar saúde do Snort: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erro ao verificar saúde do Snort: {str(e)}")


@router.get("/sse/alerts", summary="Stream de alertas do Snort (SSE)")
async def stream_snort_alerts(
    request: Request,
    user_id: Optional[int] = Query(None, description="ID do usuário para buscar configurações"),
    institution_id: Optional[int] = Query(None, description="ID da instituição"),
    authenticated_user: dict = Depends(get_authenticated_user),
):
    """Endpoint SSE para receber alertas do Snort em tempo real (proxy do servidor Snort)."""
    try:
        if user_id is not None and int(user_id) != int(authenticated_user["id"]):
            raise HTTPException(status_code=403, detail="user_id não corresponde ao usuário autenticado.")
        user_id = int(authenticated_user["id"])
        if not institution_id and user_id:
            try:
                user_config = InstitutionConfigService.get_user_institution_config(user_id=user_id)
                if user_config:
                    institution_id = user_config.get("institution_id")
            except Exception as e:
                logger.warning("Erro ao buscar configuração do usuário %s: %s", user_id, e)

        if not institution_id:
            raise HTTPException(
                status_code=400,
                detail="É necessário fornecer institution_id ou user_id para identificar a instituição.",
            )

        service = SnortService(user_id=user_id, institution_id=institution_id)
        if not service.base_url or not service.api_key:
            raise HTTPException(
                status_code=404,
                detail="Snort não configurado para esta instituição. Configure snort_base_url e snort_key no cadastro da instituição.",
            )

        sse_url = service.get_sse_url()
        if not sse_url:
            raise HTTPException(status_code=500, detail="Erro ao construir URL do SSE do Snort")

        masked_url = sse_url.replace(service.api_key, "***") if service.api_key else sse_url
        logger.info("Conectando ao Snort SSE: %s", masked_url)

        def event_generator():
            try:
                yield f"data: {json.dumps({'type': 'connected', 'message': 'Conectando ao stream de alertas do Snort'})}\n\n"
                response = requests.get(
                    sse_url,
                    stream=True,
                    timeout=None,
                    verify=sse_requests_verify(),
                    headers={"Accept": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive"},
                )
                response.raise_for_status()
                yield f"data: {json.dumps({'type': 'connected', 'message': 'Conectado ao stream de alertas do Snort'})}\n\n"

                buffer = ""
                for raw_line in response.iter_lines(decode_unicode=False):
                    try:
                        if raw_line is None or (isinstance(raw_line, bytes) and len(raw_line) == 0):
                            if buffer:
                                buffer += "\n"
                            if buffer and buffer.endswith("\n\n"):
                                event_data = buffer.strip()
                                buffer = ""
                                if event_data and event_data.startswith("data: "):
                                    json_str = event_data[6:].strip()
                                    try:
                                        alert_dict = json.loads(json_str)
                                        alert_dict = verify_and_strip_hmac(alert_dict, service.api_key or "")
                                        if alert_dict is None:
                                            continue
                                        alert = service._normalize_alert(alert_dict)
                                        alert_id = _save_snort_alert(institution_id, alert)
                                        if alert_id and (alert.get("severity") or "").lower() in ("high", "critical") and (alert.get("src_ip") or "").strip():
                                            _enqueue_snort_auto_block(
                                                alert_id,
                                                institution_id,
                                                (alert.get("src_ip") or "").strip(),
                                                attack_type=str(alert.get("signature_id") or "") or (alert.get("signature") or "")[:200],
                                                event_time=alert.get("timestamp") or "",
                                            )
                                        normalized_event = {"type": "alert", "alert": alert, "timestamp": alert.get("timestamp", ""), "source": "snort"}
                                        yield f"data: {json.dumps(normalized_event)}\n\n"
                                    except json.JSONDecodeError as e:
                                        logger.warning("Erro ao parsear JSON: %s", e)
                                        yield f"{event_data}\n\n"
                            continue
                        line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
                        if line:
                            buffer += line + "\n"
                            if buffer.endswith("\n\n"):
                                event_data = buffer.strip()
                                buffer = ""
                                if event_data and event_data.startswith("data: "):
                                    json_str = event_data[6:].strip()
                                    try:
                                        alert_dict = json.loads(json_str)
                                        alert_dict = verify_and_strip_hmac(alert_dict, service.api_key or "")
                                        if alert_dict is None:
                                            continue
                                        alert = service._normalize_alert(alert_dict)
                                        alert_id = _save_snort_alert(institution_id, alert)
                                        if alert_id and (alert.get("severity") or "").lower() in ("high", "critical") and (alert.get("src_ip") or "").strip():
                                            _enqueue_snort_auto_block(
                                                alert_id,
                                                institution_id,
                                                (alert.get("src_ip") or "").strip(),
                                                attack_type=str(alert.get("signature_id") or "") or (alert.get("signature") or "")[:200],
                                                event_time=alert.get("timestamp") or "",
                                            )
                                        normalized_event = {"type": "alert", "alert": alert, "timestamp": alert.get("timestamp", ""), "source": "snort"}
                                        yield f"data: {json.dumps(normalized_event)}\n\n"
                                    except json.JSONDecodeError as e:
                                        logger.warning("Erro ao parsear JSON: %s", e)
                                        yield f"{event_data}\n\n"
                    except (UnicodeDecodeError, AttributeError):
                        continue
            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if hasattr(e, "response") and e.response else "Desconhecido"
                yield f"data: {json.dumps({'type': 'error', 'message': f'Erro HTTP {status_code} ao conectar ao Snort'})}\n\n"
            except requests.exceptions.ConnectionError as e:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(sse_url)
                    host = parsed.hostname or "servidor"
                    port = parsed.port or ""
                    host_port = f"{host}:{port}" if port else host
                except Exception:
                    host_port = sse_url
                error_msg = (
                    f"Erro de conexão com Snort em {sse_url}. Verifique:\n"
                    f"1. Se o servidor IDS (Suricata/Snort) está rodando na máquina {host_port}\n"
                    f"2. Se o servidor foi iniciado com --host 0.0.0.0 (ex: uvicorn ... --host 0.0.0.0 --port 8001)\n"
                    f"3. Se há firewall bloqueando a conexão entre o backend e {host_port}\n"
                    f"4. Se o backend consegue acessar o IP/host configurado"
                )
                logger.error("Erro de conexão Snort: %s", e)
                yield f"data: {json.dumps({'type': 'error', 'message': error_msg})}\n\n"
            except requests.exceptions.Timeout:
                yield f"data: {json.dumps({'type': 'error', 'message': f'Timeout ao conectar com Snort'})}\n\n"
            except Exception as e:
                logger.error("Erro ao processar stream do Snort: %s", e, exc_info=True)
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Erro ao criar stream SSE do Snort: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erro ao criar stream SSE: {str(e)}")
