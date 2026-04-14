import os
from typing import Optional

from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
# Especifica o caminho para garantir que o arquivo seja encontrado
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Configurações de autenticação CAFe (OAuth2/OpenID Connect)
# As configurações são carregadas do arquivo .env para maior segurança
CAFE_CLIENT_ID = os.getenv("CAFE_CLIENT_ID")
CAFE_CLIENT_SECRET = os.getenv("CAFE_CLIENT_SECRET")
CAFE_AUTH_URL = os.getenv("CAFE_AUTH_URL", "https://sso.cafe.unipampa.edu.br/auth/realms/CAFe/protocol/openid-connect/auth")
CAFE_TOKEN_URL = os.getenv("CAFE_TOKEN_URL", "https://sso.cafe.unipampa.edu.br/auth/realms/CAFe/protocol/openid-connect/token")
CAFE_USERINFO_URL = os.getenv("CAFE_USERINFO_URL", "https://sso.cafe.unipampa.edu.br/auth/realms/CAFe/protocol/openid-connect/userinfo")
CAFE_REDIRECT_URI = os.getenv("CAFE_REDIRECT_URI", "http://localhost:8000/auth/callback")

# Configurações de autenticação Google OAuth2
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/auth/callback")

# Configurações JWT
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "sua_chave_secreta_jwt_muito_segura_aqui")

# Configurações do banco de dados MySQL
MYSQL_USER = os.getenv("MYSQL_USER", "IoT_EDU")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_DB = os.getenv("MYSQL_DB", "iot_edu")

# Configurações da API do pfSense
PFSENSE_API_URL = os.getenv("PFSENSE_API_URL")
PFSENSE_API_KEY = os.getenv("PFSENSE_API_KEY")
PFSENSE_API_SECRET = os.getenv("PFSENSE_API_SECRET")

# Configurações do Zeek Network Security Monitor
ZEEK_API_URL = os.getenv("ZEEK_API_URL", "http://192.168.100.1/zeek-api")
ZEEK_API_TOKEN = os.getenv("ZEEK_API_TOKEN")

# Configurações de atribuição automática de IP
IP_RANGE_START = os.getenv("IP_RANGE_START", "192.168.100.1")
IP_RANGE_END = os.getenv("IP_RANGE_END", "192.168.100.254")
IP_RANGE_EXCLUDED = os.getenv("IP_RANGE_EXCLUDED", "192.168.100.1,192.168.100.100,192.168.100.200")

# Configurações de acesso administrativo
# IMPORTANTE: O login administrativo é feito via Google OAuth.
# Configure apenas o email do superusuário em SUPERUSER_ACCESS.
# O sistema verificará automaticamente se o email autenticado via Google corresponde ao SUPERUSER_ACCESS.
SUPERUSER_ACCESS = os.getenv("SUPERUSER_ACCESS", "admin@iotedu.local")
# ADMIN_PASSWORD não é mais necessário - removido para usar apenas Google OAuth



# Conexões HTTPS para SSE dos IDS (Suricata/Snort/Zeek em ids-log-monitor).
# IDS_SSE_TLS_VERIFY=false desativa verificação (só em ambiente confiável).
# Para manter verify=true com certificado autoassinado: copie o server.crt do IDS para esta máquina e defina:
#   IDS_SSE_TLS_CAFILE=C:\caminho\server.crt
_IDS_SSE_CA_RAW = os.getenv("IDS_SSE_TLS_CAFILE", "").strip()
IDS_SSE_TLS_CAFILE: Optional[str] = _IDS_SSE_CA_RAW if _IDS_SSE_CA_RAW else None
IDS_SSE_TLS_VERIFY = os.getenv("IDS_SSE_TLS_VERIFY", "true").lower() not in (
    "0",
    "false",
    "no",
    "off",
)

# Autenticação de API:
# - False (padrão): compatível com fluxo legado usando current_user_id em query.
# - True: exige sessão backend válida para endpoints protegidos.
AUTH_STRICT_SESSION = os.getenv("AUTH_STRICT_SESSION", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# CORS: com allow_credentials=True o navegador não aceita allow_origins="*".
# Defina CORS_ALLOWED_ORIGINS como URLs separadas por vírgula (ex.: https://app.exemplo.com,http://localhost:3000).
_cors_raw = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
if _cors_raw:
    CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_raw.split(",") if o.strip()]
else:
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

# Observação:
# Para usar este sistema, crie um arquivo .env na pasta backend/ com as configurações necessárias.
# Exemplo de arquivo .env:
# HTTPS IDS (SSE): IDS_SSE_TLS_VERIFY=true + copie server.crt do IDS e:
#   IDS_SSE_TLS_CAFILE=C:\caminho\server.crt
# Ou sem verificação (só testes): IDS_SSE_TLS_VERIFY=false
# CAFE_CLIENT_ID=seu_client_id_aqui
# CAFE_CLIENT_SECRET=seu_client_secret_aqui
# MYSQL_PASSWORD=sua_senha_aqui
# PFSENSE_API_KEY=sua_api_key_aqui
# ZEEK_API_TOKEN=seu_token_zeek_aqui
# 
# O arquivo .env deve ser adicionado ao .gitignore para não ser commitado no repositório. 