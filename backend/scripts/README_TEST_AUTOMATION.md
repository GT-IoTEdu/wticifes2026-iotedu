# Automação de Coleta de Métricas - Detecção e Bloqueio

Coleta e correlaciona dados do **log_test.txt** (API) com **raw_log_data** dos IDS no banco (snort_alerts, suricata_alerts, zeek_alerts).

## Métricas Calculadas

| Métrica | Descrição |
|---------|-----------|
| **T_ids→block** | Detecção pelo IDS (raw_log_data.timestamp) → Bloqueio completo (BLOCKING) |
| **T_start→sync** | BLOCKING_START → SYNC (atualização do alias Bloqueados no pfSense) |
| **sync_dur** | Duração da sincronização com pfSense |

## Fontes de Dados

- **log_test.txt**: Eventos BLOCKING_START, SYNC, BLOCKING gerados pela API
- **Banco**: Coluna `raw_log_data` (todos os IDS usam o mesmo nome)
  - Snort: `{"timestamp": "02/26-12:31:46.865507", "sid": "1100003", "message": "ATAQUE -> SQL Comment Injection", "src": "192.168.59.5:56054", "dst": "192.168.59.103:80"}`
  - Suricata: formato similar com timestamp em MM/DD/YYYY-HH:MM:SS

## Uso do Script

```bash
cd backend

# Coleta padrão (Snort + Suricata)
python scripts/collect_test_metrics.py --log log_test.txt

# Filtrar por IP do atacante
python scripts/collect_test_metrics.py --log log_test.txt --src-ip 192.168.59.5

# Apenas Snort
python scripts/collect_test_metrics.py --log log_test.txt --ids snort

# Filtrar por período
python scripts/collect_test_metrics.py --log log_test.txt --since "2026-02-26 12:00"

# Salvar em JSON
python scripts/collect_test_metrics.py --log log_test.txt --output relatorio.json --format json
```

## Endpoint API

```
GET /api/test/blocking-metrics?src_ip=192.168.59.5&ids=snort,suricata
```

Permite coletar métricas remotamente (útil para automação após executar ataques via Docker).

**Parâmetros:**
- `src_ip`: Filtrar por IP do atacante
- `ids`: snort,suricata,zeek (default: snort,suricata)
- `since`: YYYY-MM-DD HH:MM
- `log_path`: Caminho do log_test.txt (default: log_test.txt)

## Fluxo com Ataques em Docker

1. Execute os ataques remotamente nos containers Docker
2. O IDS detecta e envia para a API (SSE)
3. A API processa, bloqueia e grava em log_test.txt
4. Execute a coleta:
   - **Script**: `python scripts/collect_test_metrics.py --log log_test.txt --src-ip <IP_ATACANTE>`
   - **API**: `GET /api/test/blocking-metrics?src_ip=<IP_ATACANTE>`
