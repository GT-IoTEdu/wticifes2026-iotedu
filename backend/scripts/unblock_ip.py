#!/usr/bin/env python3
"""
Remove o bloqueio de um IP comunicando-se diretamente com o pfSense:
- Remove o IP do alias "Bloqueados"
- Adiciona o IP ao alias "Autorizados"
- Aplica as mudanças no firewall

Não utiliza a API IoT-EDU; usa apenas o cliente pfSense (config via .env ou argumentos).

Uso:
    cd backend && python scripts/unblock_ip.py 192.168.59.5
    python scripts/unblock_ip.py 192.168.59.5 --pfsense-url https://pfsense.local/ --pfsense-key "CHAVE"
"""
import argparse
import sys
from pathlib import Path

# Permitir importar módulos do backend
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))


def main():
    parser = argparse.ArgumentParser(
        description="Remove o bloqueio de um IP no pfSense (alias Bloqueados). Comunicação direta com pfSense."
    )
    parser.add_argument("ip", help="Endereço IP a liberar (ex: 192.168.59.5)")
    parser.add_argument(
        "--pfsense-url",
        default=None,
        help="URL base do pfSense (ex: https://192.168.1.1/). Se omitido, usa PFSENSE_API_URL do .env",
    )
    parser.add_argument(
        "--pfsense-key",
        default=None,
        help="Chave API do pfSense. Se omitido, usa PFSENSE_API_KEY do .env",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Menos saída")
    args = parser.parse_args()

    ip = args.ip.strip()

    # Importar após adicionar backend ao path (e após carregar .env via config)
    import config
    from services_firewalls.pfsense_client import (
        obter_alias_pfsense,
        atualizar_alias_pfsense,
        aplicar_mudancas_firewall_pfsense,
    )

    pfsense_url = args.pfsense_url or config.PFSENSE_API_URL
    pfsense_key = args.pfsense_key or config.PFSENSE_API_KEY

    if not pfsense_url or not pfsense_key:
        print("Configure PFSENSE_API_URL e PFSENSE_API_KEY no .env ou use --pfsense-url e --pfsense-key")
        return 1

    # pfSense Plus REST API v2 usa o path /api/v2/; normalizar se o utilizador passou só o host
    base = pfsense_url.rstrip("/")
    if "/api/v2" not in base and "/api/v1" not in base:
        base = base + "/api/v2"
    pfsense_url = base + "/"

    if not args.quiet:
        print(f"Obtendo alias 'Bloqueados' no pfSense...")

    try:
        alias = obter_alias_pfsense(
            "Bloqueados",
            pfsense_url=pfsense_url,
            pfsense_key=pfsense_key,
        )
    except Exception as e:
        print(f"Erro ao obter alias do pfSense: {e}")
        return 1

    if not alias:
        print("Alias 'Bloqueados' não encontrado no pfSense.")
        return 1

    alias_id = alias.get("id")
    if alias_id is None:
        print("Alias retornado sem ID.")
        return 1

    addresses = list(alias.get("address") or [])
    details = list(alias.get("detail") or [])
    if len(details) < len(addresses):
        details.extend([""] * (len(addresses) - len(details)))

    if ip not in addresses:
        if not args.quiet:
            print(f"IP {ip} não está no alias Bloqueados. Nada a fazer.")
        return 0

    idx = addresses.index(ip)
    new_addresses = [a for i, a in enumerate(addresses) if i != idx]
    new_details = [d for i, d in enumerate(details) if i != idx]

    if not args.quiet:
        print(f"Removendo {ip} do alias Bloqueados...")

    try:
        atualizar_alias_pfsense(
            alias_id=alias_id,
            name="Bloqueados",
            address=new_addresses,
            detail=new_details,
            pfsense_url=pfsense_url,
            pfsense_key=pfsense_key,
        )
    except Exception as e:
        print(f"Erro ao atualizar alias Bloqueados no pfSense: {e}")
        return 1

    # Adicionar o IP ao alias "Autorizados"
    try:
        auth_alias = obter_alias_pfsense(
            "Autorizados",
            pfsense_url=pfsense_url,
            pfsense_key=pfsense_key,
        )
    except Exception as e:
        print(f"Erro ao obter alias Autorizados: {e}")
        return 1

    if auth_alias:
        auth_id = auth_alias.get("id")
        auth_addresses = list(auth_alias.get("address") or [])
        auth_details = list(auth_alias.get("detail") or [])
        if len(auth_details) < len(auth_addresses):
            auth_details.extend([""] * (len(auth_addresses) - len(auth_details)))

        if ip not in auth_addresses:
            if not args.quiet:
                print(f"Adicionando {ip} ao alias Autorizados...")
            auth_addresses.append(ip)
            auth_details.append("")
            try:
                atualizar_alias_pfsense(
                    alias_id=auth_id,
                    name="Autorizados",
                    address=auth_addresses,
                    detail=auth_details,
                    pfsense_url=pfsense_url,
                    pfsense_key=pfsense_key,
                )
            except Exception as e:
                print(f"Erro ao atualizar alias Autorizados no pfSense: {e}")
                return 1
        elif not args.quiet:
            print(f"IP {ip} já está no alias Autorizados.")
    elif not args.quiet:
        print("Alias 'Autorizados' não encontrado no pfSense; apenas Bloqueados foi atualizado.")

    try:
        aplicar_mudancas_firewall_pfsense(
            pfsense_url=pfsense_url,
            pfsense_key=pfsense_key,
        )
    except Exception as e:
        print(f"Erro ao aplicar mudanças no firewall: {e}")
        return 1

    if not args.quiet:
        print(f"OK: IP {ip} removido de Bloqueados, adicionado a Autorizados e mudanças aplicadas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
