#!/usr/bin/env python3
"""
Script para coletar apenas timestamps e dados originais (sem cálculos).

Lê:
- log_test.txt: extrai TIMESTAMP original de cada linha (BLOCKING_START, SYNC, BLOCKING)
- Banco (snort_alerts, suricata_alerts, zeek_alerts): raw_log_data tal como está (timestamp, sid, message, protocol, src, dst)

Não calcula métricas; apenas apresenta os valores originais do ficheiro e do JSON do banco.

Uso:
    python collect_test_metrics.py --log log_test.txt
    python collect_test_metrics.py --log log_test.txt --src-ip 192.168.59.5
    python collect_test_metrics.py --log log_test.txt --ids snort suricata --since "2026-02-26 12:00"
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))


def parse_log_test(log_path: str) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Parseia log_test.txt. Retorna (blocking_starts, syncs, blockings).
    Guarda TIMESTAMP original como string (timestamp_original); sem calcular nada.
    """
    blocking_starts = []
    syncs = []
    blockings = []

    with open(log_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Separador: linha de 50+ sinais de igual (compatível com \r\n)
    blocks = re.split(r"\r?\n={50,}\r?\n", content)

    for block in blocks:
        event = {}
        for line in block.split("\n"):
            line = line.strip("\r")
            if line.startswith("TIMESTAMP:"):
                event["timestamp_original"] = line.replace("TIMESTAMP:", "").strip()
            elif line.startswith("TIPO:"):
                event["tipo"] = line.replace("TIPO:", "").strip()
            elif line.startswith("IP DO DISPOSITIVO:"):
                event["device_ip"] = line.replace("IP DO DISPOSITIVO:", "").strip()
            elif line.startswith("DESCRIÇÃO:"):
                desc = line.replace("DESCRIÇÃO:", "").strip()
                event["descricao"] = desc
                match = re.search(r"\((\w+)\s+(\d+)\)", desc)
                if match:
                    event["source_type"] = match.group(1).lower()
                    event["source_id"] = int(match.group(2))
            elif re.search(r"INCIDENTE\s+ID:\s*\d+", line, re.I):
                match = re.search(r"INCIDENTE\s+ID:\s*(\d+)", line, re.I)
                if match:
                    event["source_id"] = int(match.group(1))
            elif "source_id:" in line.lower():
                match = re.search(r"source_id:\s*(\d+)", line, re.I)
                if match:
                    event["source_id"] = int(match.group(1))
            elif "source_type:" in line.lower():
                match = re.search(r"source_type:\s*(\w+)", line, re.I)
                if match:
                    event["source_type"] = match.group(1).lower()
            elif "blocked_at:" in line:
                match = re.search(r"blocked_at:\s*(.+)", line)
                if match:
                    event["blocked_at_original"] = match.group(1).strip()
            elif "DURAÇÃO:" in line:
                event["duration_original"] = line.replace("DURAÇÃO:", "").strip()
            elif "alias_name:" in line.lower():
                match = re.search(r"alias_name:\s*(\w+)", line, re.I)
                if match:
                    event["alias_name"] = match.group(1)

        if not event.get("tipo") or not event.get("timestamp_original"):
            continue

        if event["tipo"] == "BLOCKING_START":
            blocking_starts.append(event)
        elif event["tipo"] == "SYNC":
            syncs.append(event)
        elif event["tipo"] == "BLOCKING":
            blockings.append(event)

    return blocking_starts, syncs, blockings


def parse_attack_logs(attack_logs_dir: Optional[str]) -> list[dict]:
    """
    Lê arquivos acesso_log_*.txt (logs do atacante) e extrai apenas os campos de interesse:
      - attack_start: linha "=== INICIO MONITORAMENTO: ... ==="
      - first_block_detected: linha "PRIMEIRO BLOQUEIO DETECTADO: ..."
    Mantém os valores exatamente como aparecem no ficheiro (strings).
    """
    if not attack_logs_dir:
        return []

    base = Path(attack_logs_dir)
    if not base.exists() or not base.is_dir():
        return []

    events: list[dict] = []
    for log_file in sorted(base.glob("acesso_log_*.txt")):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError:
            continue

        attack_start = None
        first_block = None
        monitoring_end = None  # não usado na saída, mas lido se precisar no futuro
        url = None  # idem

        for line in lines:
            if line.startswith("=== INICIO MONITORAMENTO:"):
                # Mantém o timestamp exatamente como está na linha
                parts = line.split("INICIO MONITORAMENTO:", 1)
                if len(parts) == 2:
                    attack_start = parts[1].strip(" =")
            elif line.startswith("URL:"):
                url = line.split("URL:", 1)[1].strip()
            elif line.startswith("PRIMEIRO BLOQUEIO DETECTADO:"):
                first_block = line.split("PRIMEIRO BLOQUEIO DETECTADO:", 1)[1].strip()
            elif line.startswith("MONITORAMENTO ENCERRADO:"):
                monitoring_end = line.split("MONITORAMENTO ENCERRADO:", 1)[1].strip()

        events.append(
            {
                "file_name": log_file.name,
                "attack_start": attack_start,
                "first_block_detected": first_block,
            }
        )

    # Não faz ordenação por data; mantém na ordem natural dos ficheiros
    return events


def get_alerts_from_ids(
    ids_types: list[str],
    src_ip: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = 500,
) -> list[dict]:
    """
    Busca alertas de snort_alerts, suricata_alerts, zeek_alerts.
    Retorna apenas source_type, alert_id, src_ip e raw_log_data original (timestamp, sid, message, protocol, src, dst, etc.).
    """
    from db.session import SessionLocal
    from db.enums import IncidentSeverity
    from sqlalchemy import desc

    alerts = []
    db = SessionLocal()

    try:
        if "snort" in ids_types:
            from db.models import SnortAlert
            q = db.query(SnortAlert).filter(
                SnortAlert.severity.in_([IncidentSeverity.HIGH, IncidentSeverity.CRITICAL])
            )
            if src_ip:
                q = q.filter(SnortAlert.src_ip == src_ip)
            if since:
                q = q.filter(SnortAlert.detected_at >= since)
            for r in q.order_by(desc(SnortAlert.detected_at)).limit(limit).all():
                raw = json.loads(r.raw_log_data) if r.raw_log_data else {}
                alerts.append({
                    "source_type": "snort",
                    "alert_id": r.id,
                    "src_ip": r.src_ip,
                    "raw_log_data": raw,
                })

        if "suricata" in ids_types:
            from db.models import SuricataAlert
            q = db.query(SuricataAlert).filter(
                SuricataAlert.severity.in_([IncidentSeverity.HIGH, IncidentSeverity.CRITICAL])
            )
            if src_ip:
                q = q.filter(SuricataAlert.src_ip == src_ip)
            if since:
                q = q.filter(SuricataAlert.detected_at >= since)
            for r in q.order_by(desc(SuricataAlert.detected_at)).limit(limit).all():
                raw = json.loads(r.raw_log_data) if r.raw_log_data else {}
                alerts.append({
                    "source_type": "suricata",
                    "alert_id": r.id,
                    "src_ip": r.src_ip,
                    "raw_log_data": raw,
                })

        if "zeek" in ids_types:
            from db.models import ZeekAlert
            q = db.query(ZeekAlert).filter(
                ZeekAlert.severity.in_([IncidentSeverity.HIGH, IncidentSeverity.CRITICAL])
            )
            if src_ip:
                q = q.filter(ZeekAlert.src_ip == src_ip)
            if since:
                q = q.filter(ZeekAlert.detected_at >= since)
            for r in q.order_by(desc(ZeekAlert.detected_at)).limit(limit).all():
                raw = json.loads(r.raw_log_data) if r.raw_log_data else {}
                alerts.append({
                    "source_type": "zeek",
                    "alert_id": r.id,
                    "src_ip": r.src_ip,
                    "raw_log_data": raw,
                })

        return alerts
    finally:
        db.close()


def timestamp_to_second_key(ts: str) -> str:
    """Reduz timestamp ao segundo para agrupar (ex: 02/26-15:21:32.765369 -> 02/26-15:21:32)."""
    if not ts:
        return ""
    # Snort: MM/DD-HH:MM:SS.ffffff
    m = re.match(r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2})", ts)
    if m:
        return m.group(1)
    # Suricata: MM/DD/YYYY-HH:MM:SS.ffffff
    m = re.match(r"(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2})", ts)
    if m:
        return m.group(1)
    return ts


def deduplicate_alerts_first_per_second(alerts: list[dict]) -> list[dict]:
    """
    Mantém apenas o primeiro (mais antigo) alerta por (source_type, sid, message, segundo).
    Alertas já devem estar ordenados por timestamp crescente.
    """
    seen = set()
    result = []
    for a in alerts:
        raw = a.get("raw_log_data") or {}
        ts = raw.get("timestamp", "")
        key = (a.get("source_type"), str(raw.get("sid", "")), raw.get("message", ""), timestamp_to_second_key(ts))
        if key in seen:
            continue
        seen.add(key)
        result.append(a)
    return result


def build_log_events_originals(
    blocking_starts: list, syncs: list, blockings: list, alerts: list[dict]
) -> list[dict]:
    """
    Junta eventos do log_test.txt com campos originais e enriquece com tipo de ataque (message do IDS)
    para cruzar com os alertas: (source_type, source_id) -> raw_log_data.message.
    """
    alert_message_by_key = {}
    for a in alerts:
        raw = a.get("raw_log_data") or {}
        key = (a.get("source_type"), a.get("alert_id"))
        if key not in alert_message_by_key:
            alert_message_by_key[key] = raw.get("message", "")
    out = []
    for e in blocking_starts + syncs + blockings:
        stype, sid = e.get("source_type"), e.get("source_id")
        attack_type = alert_message_by_key.get((stype, sid), "") if (stype is not None and sid is not None) else ""
        out.append({
            "tipo": e.get("tipo"),
            "timestamp_original": e.get("timestamp_original"),
            "device_ip": e.get("device_ip"),
            "source_type": stype,
            "source_id": sid,
            "attack_type": attack_type or None,
            "descricao": e.get("descricao"),
            "blocked_at_original": e.get("blocked_at_original"),
            "duration_original": e.get("duration_original"),
            "alias_name": e.get("alias_name"),
        })
    return out


def main():
    parser = argparse.ArgumentParser(description="Coleta métricas de detecção e bloqueio (log_test + banco)")
    parser.add_argument("--log", default="log_test.txt", help="Caminho do log_test.txt")
    parser.add_argument("--src-ip", help="Filtrar por IP do atacante")
    parser.add_argument(
        "--ids",
        nargs="+",
        default=["snort", "suricata", "zeek"],
        choices=["snort", "suricata", "zeek"],
        help="Tabelas IDS a consultar (snort, suricata, zeek)",
    )
    parser.add_argument("--since", help="Data/hora inicial (YYYY-MM-DD HH:MM)")
    parser.add_argument(
        "--attack-logs-dir",
        help="Diretório com acesso_log_*.txt (inicio do ataque). Se omitido, usa ATTACK_LOGS_DIR do .env ou backend/acesso_logs",
    )
    parser.add_argument("--output", help="Salvar relatório em JSON")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table")
    args = parser.parse_args()

    # Carregar .env do backend para ATTACK_LOGS_DIR
    _backend = Path(__file__).resolve().parent.parent
    try:
        from dotenv import load_dotenv
        load_dotenv(_backend / ".env")
    except ImportError:
        pass

    # Resolver log em relação ao backend quando for só o nome do ficheiro (ex: log_test.txt)
    log_path = Path(args.log)
    if not log_path.is_absolute() and len(log_path.parts) <= 1:
        in_backend = _backend / log_path.name
        if in_backend.exists():
            log_path = in_backend
        elif not log_path.exists():
            # tentar também no cwd (path relativo ao diretório atual)
            pass
    if not log_path.exists():
        print(f"Arquivo não encontrado: {log_path}")
        return 1

    since_dt = None
    if args.since:
        try:
            since_dt = datetime.strptime(args.since, "%Y-%m-%d %H:%M")
        except ValueError:
            since_dt = datetime.strptime(args.since, "%Y-%m-%d")

    print("Parseando log_test.txt...")
    blocking_starts, syncs, blockings = parse_log_test(str(log_path))
    print(f"  BLOCKING_START: {len(blocking_starts)}, SYNC: {len(syncs)}, BLOCKING: {len(blockings)}")

    print(f"Buscando alertas no banco ({', '.join(args.ids)})...")
    alerts = get_alerts_from_ids(args.ids, src_ip=args.src_ip, since=since_dt)
    print(f"  {len(alerts)} alertas encontrados")

    # Diretório dos acesso_log_*.txt: argumento, env ATTACK_LOGS_DIR, backend/acesso_logs ou OneDrive/POC2/SSH
    attack_logs_dir = args.attack_logs_dir or os.environ.get("ATTACK_LOGS_DIR")
    if not attack_logs_dir:
        if (_backend / "acesso_logs").is_dir():
            attack_logs_dir = str(_backend / "acesso_logs")
        else:
            for candidate in [
                Path.home() / "OneDrive" / "Documentos" / "POC2" / "SSH",
                Path.home() / "Documentos" / "POC2" / "SSH",
            ]:
                if candidate.is_dir() and list(candidate.glob("acesso_log_*.txt")):
                    attack_logs_dir = str(candidate)
                    break

    attack_logs = parse_attack_logs(attack_logs_dir)
    if attack_logs:
        print(f"  {len(attack_logs)} arquivos de ataque (acesso_log_*.txt) em {attack_logs_dir}")
    elif attack_logs_dir:
        print(f"  Nenhum acesso_log_*.txt em {attack_logs_dir}")

    alerts.sort(key=lambda a: (a.get("raw_log_data") or {}).get("timestamp") or "")
    log_events = build_log_events_originals(blocking_starts, syncs, blockings, alerts)
    log_events.sort(key=lambda e: e.get("timestamp_original") or "")
    log_events = [e for e in log_events if e.get("tipo") != "SYNC"]
    alerts = deduplicate_alerts_first_per_second(alerts)
    output_data = {
        "attack_logs": attack_logs,
        "alerts_originals": alerts,
        "log_test_originals": log_events,
    }

    if args.format == "table":
        print("\n" + "=" * 80)
        print("INICIO DO ATAQUE - LOGS DO HOST (acesso_log_*.txt)")
        print("=" * 80)
        for ev in attack_logs:
            print(
                f"{ev.get('file_name'):<32} "
                f"attack_start={ev.get('attack_start') or ''}  "
                f"first_block={ev.get('first_block_detected') or ''}"
            )
        print("\n" + "=" * 80)
        print("ALERTAS IDS (BANCO) - raw_log_data ORIGINAIS (timestamp, sid, message, protocol, src, dst)")
        print("=" * 80)
        for a in alerts:
            raw = a.get("raw_log_data") or {}
            ts = raw.get("timestamp", "")
            sid = raw.get("sid", "")
            msg = (raw.get("message") or "")[:40]
            proto = raw.get("protocol", "")
            src = raw.get("src", "")
            dst = raw.get("dst", "")
            print(f"{a.get('source_type'):<10} id={a.get('alert_id')}  timestamp={ts}  sid={sid}  message={msg}  protocol={proto}  src={src}  dst={dst}")
        print("\n" + "=" * 120)
        print("LOG_TEST.TXT - TIMESTAMPS ORIGINAIS (+ tipo de ataque para cruzar com IDS)")
        print("=" * 120)
        print(f"{'TIPO':<18} {'timestamp_original':<26} {'device_ip':<16} {'source_type':<10} {'source_id':<10} {'attack_type':<45}")
        print("-" * 120)
        for e in log_events:
            atk = (e.get("attack_type") or "")[:43]
            print(f"{e.get('tipo') or '':<18} {e.get('timestamp_original') or '':<26} {e.get('device_ip') or '':<16} {e.get('source_type') or '':<10} {e.get('source_id') or '':<10} {atk:<45}")
        print("=" * 120)
    elif args.format == "json":
        print(json.dumps(output_data, indent=2, default=str))
    elif args.format == "csv":
        import csv
        print("attack_logs")
        if attack_logs:
            w = csv.DictWriter(sys.stdout, fieldnames=attack_logs[0].keys())
            w.writeheader()
            w.writerows(attack_logs)
        print("\nalerts_originals")
        if alerts:
            rows = []
            for a in alerts:
                row = {"source_type": a.get("source_type"), "alert_id": a.get("alert_id"), "src_ip": a.get("src_ip")}
                row.update((k, v) for k, v in (a.get("raw_log_data") or {}).items())
                rows.append(row)
            if rows:
                w = csv.DictWriter(sys.stdout, fieldnames=rows[0].keys(), extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
        print("\nlog_test_originals")
        if log_events:
            w = csv.DictWriter(sys.stdout, fieldnames=log_events[0].keys())
            w.writeheader()
            w.writerows(log_events)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "attack_logs": attack_logs,
                    "alerts_originals": alerts,
                    "log_test_originals": log_events,
                    "collected_at": datetime.now().isoformat(),
                },
                f,
                indent=2,
                default=str,
            )
        print(f"\nRelatório salvo em {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
