# Diagrama de classes do sistema IoT-EDU

Este documento descreve o diagrama UML em PlantUML disponível em [`classes-sistema.puml`](./classes-sistema.puml). O foco é o **modelo de domínio persistido** (SQLAlchemy em `backend/db/models.py`) e os **enumerados** (`backend/db/enums.py`), que sustentam a API FastAPI, o dashboard e as integrações com pfSense e IDS.

## Como visualizar

- **VS Code / Cursor:** extensão “PlantUML” (renderiza pré-visualização).
- **CLI:** [PlantUML](https://plantuml.com/) com Java, ou serviço online que aceite ficheiros `.puml`.
- **Gradle/Maven:** integração opcional em pipelines para exportar PNG/SVG.

Comando típico (se tiver `plantuml.jar`):

```bash
java -jar plantuml.jar docs/diagramas/classes-sistema.puml
```

## Visão geral da arquitetura de dados

O sistema segue uma linha **multi-institutional**: cada **Institution** concentra configuração de rede (pfSense, Zeek, Suricata, Snort, intervalo de IPs). **User** associa-se opcionalmente a uma instituição e possui **permissão** (`UserPermission`) que restringe operações na API e no frontend.

Camadas **não** aparecem como classes neste diagrama (routers, serviços, `ids-log-monitor`), mas o modelo de dados reflecte o que essas camadas leem e gravam.

## Pacote de enums

| Enum | Papel |
|------|--------|
| `UserPermission` | Valores em `db.enums`: **USER**, **ADMIN**, **SUPERUSER** (o frontend pode referir “MANAGER” noutros fluxos; alinhar com o enum ao persistir). |
| `IncidentSeverity` | Severidade unificada para incidentes e alertas IDS persistidos. |
| `IncidentStatus` | Ciclo de vida de registos na entidade `Incident` (workflow de análise). |
| `ZeekLogType` | Origem semântica do incidente quando ligado a logs Zeek. |
| `FeedbackStatus` | Estado do feedback de bloqueio em `BlockingFeedbackHistory`. |

## Entidades principais

### Institution

Representa um campus ou rede gerida. Guarda URLs e chaves para **pfSense**, **Zeek**, **Suricata** e **Snort**, além do range de IPs. É o pivô de isolamento lógico: aliases, regras, mapeamentos DHCP e alertas IDS referenciam `institution_id` quando aplicável.

### User

Utilizador autenticado (OAuth/Google, CAFe, etc., tratado fora deste diagrama). Campos como `email`, `permission`, `institution_id` e `is_active` suportam autorização no backend (`get_authenticated_user`, `get_effective_user_id`) e políticas como `AUTH_STRICT_SESSION`.

### DHCP e dispositivos

- **DhcpServer:** servidores DHCP espelhados a partir do pfSense.
- **DhcpStaticMapping:** mapeamento MAC/IP (dispositivo na rede), com `institution_id` e flags de bloqueio.
- **UserDeviceAssignment:** tabela de junção **utilizador ↔ dispositivo** (N:N), com `assigned_by` opcional para auditoria.

### pfSense (aliases e regras)

- **PfSenseAlias** + **PfSenseAliasAddress:** cópia local de aliases (ex.: Autorizados / Bloqueados) e respectivos endereços.
- **PfSenseFirewallRule:** regras sincronizadas por instituição.

### Segurança e IDS

- **Incident** (alias legado `ZeekIncident`): incidentes de segurança com `severity`, `status`, `zeek_log_type` e atribuição opcional a um utilizador (`assigned_to`).
- **SuricataAlert**, **SnortAlert**, **ZeekAlert:** estruturas paralelas — alertas normalizados por `institution_id`, com `processed_at` para bloqueio automático e deduplicação no serviço.

### Feedback

- **BlockingFeedbackHistory:** feedback sobre bloqueios ligado a `dhcp_mapping_id`, com `FeedbackStatus` e revisão administrativa.

## Relações resumidas

| Relação | Cardinalidade | Notas |
|---------|----------------|-------|
| Institution → User | 1 : N | Utilizador pode pertencer a uma instituição. |
| Institution → DhcpStaticMapping / PfSense* / Alertas IDS | 1 : N | Dados segregados por instituição. |
| DhcpServer → DhcpStaticMapping | 1 : N | Mapeamentos por servidor DHCP. |
| User ↔ DhcpStaticMapping | N : M via `UserDeviceAssignment` | Atribuição de dispositivos a utilizadores. |
| PfSenseAlias → PfSenseAliasAddress | 1 : N | Endereços por alias. |
| User → Incident | 1 : N (opcional) | Campo `assigned_to`. |
| DhcpStaticMapping → BlockingFeedbackHistory | 1 : N | Histórico de feedback por dispositivo. |

## O que o diagrama não cobre

- **Frontend (Next.js):** componentes React e estado local não são classes de domínio.
- **Routers FastAPI:** expõem REST/SSE; dependem destas entidades mas não são modeladas aqui.
- **ids-log-monitor:** processo à parte que produz streams SSE; o backend consome e persiste em `*Alert`.
- **Sessão HTTP / JWT / OAuth:** mecanismos de autenticação, não entidades ORM.

Para alterações ao modelo, editar `backend/db/models.py` e, em seguida, actualizar este ficheiro `.puml` e o presente `.md` para manter a documentação alinhada.
