
# Testes de segurança (IoT-EDU)

  

Este diretório contém testes automatizados focados em comportamentos de segurança introduzidos ou reforçados no backend e na integração IDS:

  

-  **HMAC** nos payloads SSE (`ids-log-monitor` → API)
-  **TLS `verify`** para `requests` ao consumir SSE dos IDS (`IDS_SSE_TLS_VERIFY` / `IDS_SSE_TLS_CAFILE`)
-  **Política de sessão** (`AUTH_STRICT_SESSION` vs `current_user_id` legado)

-  **CORS** (lista explícita de origens, sem `*` com credenciais)



  

## Requisitos

  

- Python 3.9+ (alinhado ao backend)

- Pacotes: `pytest` (ver `testes/requirements-test.txt`)

  

```bash

cd  testes

pip  install  -r  requirements-test.txt

```

  

O ficheiro `backend/config.py` é carregado (via `backend/.env` se existir). Não é obrigatório MySQL a correr para a maior parte dos testes; o ficheiro `test_auth_session_policy.py` usa *stubs* da BD para evitar ligar ao MySQL.

  

## Como executar

  

Na raiz do repositório ou dentro de `testes/`:

  

```bash

cd  testes

python  -m  pytest  .  -v

```

  

Com filtro por ficheiro:

  

```bash

python  -m  pytest  test_sse_hmac_security.py  -v

python  -m  pytest  test_auth_session_policy.py  -v

python  -m  pytest  test_config_cors_security.py  -v

python  -m  pytest  test_ids_sse_tls_security.py  -v

```

  

## Mapa dos ficheiros

  


| Ficheiro                          | O que valida                                                                                                                                                      |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `test_sse_hmac_security.py`       | `verify_and_strip_hmac`: assinatura válida, inválida, chave errada, payload sem `signature` (compatibilidade), API key vazia.                                    |
| `test_auth_session_policy.py`     | `get_effective_user_id`: modo estrito ignora query; modo legado aceita `current_user_id`; sessão com email devolve id; mismatch query vs sessão → 403.          |
| `test_config_cors_security.py`    | `CORS_ALLOWED_ORIGINS` não contém `*`; tipo de `AUTH_STRICT_SESSION`.                                                                                              |
| `test_ids_sse_tls_security.py`    | `sse_requests_verify()` com `IDS_SSE_TLS_VERIFY` simulado True/False.                                                                                              |
  

## Testes manuais sugeridos (API em execução)

  

Estes cenários complementam os testes unitários quando o Uvicorn está no ar.

  

### 1. Sessão estrita e aliases

  

- Com `AUTH_STRICT_SESSION=true`, um `GET` a `/api/devices/aliases-db`  **sem** cookie de sessão deve responder **401**, mesmo com `?current_user_id=1` na query.

- Com cookie válido (mesma origem que o front, ex. via proxy Next em `/api`), deve responder **200**.

  

### 2. HMAC no SSE (integração)

  

- Com o `ids-log-monitor` a assinar eventos: o backend deve aceitar apenas assinaturas calculadas com a mesma API key configurada na instituição.

- Alterar um byte na `signature` no payload deve fazer o backend **descartar** o evento (ver logs de aviso SSE HMAC).

  

### 3. CORS e credenciais

  

- O browser não envia credenciais para respostas com `Access-Control-Allow-Origin: *`.

- Com `allow_credentials=True`, o FastAPI deve devolver uma **origem explícita** listada em `CORS_ALLOWED_ORIGINS` (não `*`).

  

## Notas de desenho

  

-  `test_sse_hmac_security.py` carrega `sse_hmac.py` via `importlib` para **não** importar `services_scanners/__init__.py` (que arrasta routers e ligação à BD).

-  `test_auth_session_policy.py` regista `sys.modules` mínimos para `db` antes de importar `auth.dependencies`, evitando criar o engine SQLAlchemy/MySQL durante a coleção de testes.

  

## Integração contínua (opcional)

  

Exemplo mínimo para GitHub Actions ou similar:

  

```yaml

- run: pip install -r testes/requirements-test.txt

- run: cd testes && python -m pytest . -v

```

  

Última execução aqui:  15 passaram, 1 skipped  (lista CORS personalizada no  `.env`) e 1 aviso do Starlette/`multipart`  sem relação com estes testes.

Nota:  Os testes de HMAC e TLS carregam só os  `.py`  necessários com  `importlib`, para não importar  `services_scanners`  a partir do  `__init__`  (evita routers e MySQL). Os testes de auth usam  _stubs_  de  `db`  para o mesmo efeito.

## Execução dos testes

PS C:\xampp\htdocs\API-IoT-EDU\testes> python -m pytest . -v
================================================= test session starts =================================================
platform win32 -- Python 3.9.7, pytest-8.4.2, pluggy-1.6.0 -- C:\Users\joner\AppData\Local\Programs\Python\Python39\python.exe
cachedir: .pytest_cache
rootdir: C:\xampp\htdocs\API-IoT-EDU\testes
configfile: pytest.ini
plugins: anyio-3.7.1
collected 16 items

test_auth_session_policy.py::TestEffectiveUserIdStrictSession::test_sem_sessao_strict_true_bloqueia_mesmo_com_query PASSED [  6%]
test_auth_session_policy.py::TestEffectiveUserIdStrictSession::test_sem_sessao_strict_false_aceita_query PASSED  [ 12%]
test_auth_session_policy.py::TestEffectiveUserIdStrictSession::test_sem_sessao_sem_query_401 PASSED              [ 18%]
test_auth_session_policy.py::TestEffectiveUserIdStrictSession::test_com_sessao_retorna_id PASSED                 [ 25%]
test_auth_session_policy.py::TestEffectiveUserIdStrictSession::test_com_sessao_user_id_query_diferente_403 PASSED [ 31%]
test_config_cors_security.py::TestCorsOrigins::test_allow_origins_nao_e_curinga_com_credenciais PASSED           [ 37%]
test_config_cors_security.py::TestCorsOrigins::test_origem_localhost_presente_se_usar_padrao SKIPPED             [ 43%]
test_config_cors_security.py::TestAuthFlags::test_strict_session_e_booleano_legivel PASSED                       [ 50%]
test_ids_sse_tls_security.py::TestSseRequestsVerify::test_verify_false_retorna_false PASSED                      [ 56%]
test_ids_sse_tls_security.py::TestSseRequestsVerify::test_verify_true_sem_cafile_retorna_true PASSED             [ 62%]
test_sse_hmac_security.py::TestSseHmacVerification::test_payload_sem_assinatura_aceite_compatibilidade PASSED    [ 68%]
test_sse_hmac_security.py::TestSseHmacVerification::test_assinatura_valida_remove_campo PASSED                   [ 75%]
test_sse_hmac_security.py::TestSseHmacVerification::test_assinatura_invalida_rejeitada PASSED                    [ 81%]
test_sse_hmac_security.py::TestSseHmacVerification::test_chave_errada_rejeitada PASSED                           [ 87%]
test_sse_hmac_security.py::TestSseHmacVerification::test_payload_assinado_com_api_key_vazia_rejeitado PASSED     [ 93%]
test_sse_hmac_security.py::TestSseHmacVerification::test_payload_nao_e_dict PASSED                               [100%]

================================================== warnings summary ===================================================
..\..\..\..\Users\joner\AppData\Local\Programs\Python\Python39\lib\site-packages\starlette\formparsers.py:10
  C:\Users\joner\AppData\Local\Programs\Python\Python39\lib\site-packages\starlette\formparsers.py:10: PendingDeprecationWarning: Please use `import python_multipart` instead.
    import multipart

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
====================================== 15 passed, 1 skipped, 1 warning in 0.56s =======================================