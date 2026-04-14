"""
Parâmetros TLS para requests ao proxy SSE dos IDS (ids-log-monitor em HTTPS).

- IDS_SSE_TLS_VERIFY=false → sem verificação (só rede confiável).
- IDS_SSE_TLS_VERIFY=true (padrão) + IDS_SSE_TLS_CAFILE=caminho/server.crt → verifica usando o PEM
  (ideal para certificado autoassinado: copie o mesmo server.crt do IDS para o backend).
- IDS_SSE_TLS_VERIFY=true sem CAFILE → usa o store de CAs do sistema (cert. público ou CA instalada).
"""
import logging
import os
from typing import Union

logger = logging.getLogger(__name__)
_warned_insecure = False
_patched_urllib3 = False
_warned_ca_missing = False


def sse_requests_verify() -> Union[bool, str]:
    """
    Valor de verify para requests:
    False, True, ou caminho para ficheiro PEM (CA ou cert. autoassinado do servidor).
    """
    global _warned_insecure, _patched_urllib3, _warned_ca_missing
    try:
        from config import IDS_SSE_TLS_VERIFY, IDS_SSE_TLS_CAFILE
        tls_verify = bool(IDS_SSE_TLS_VERIFY)
        cafile = IDS_SSE_TLS_CAFILE
    except Exception:
        tls_verify = True
        cafile = None

    if not tls_verify:
        if not _warned_insecure:
            _warned_insecure = True
            logger.warning(
                "IDS SSE: verificação TLS desativada (IDS_SSE_TLS_VERIFY=false). "
                "Use apenas em ambiente confiável."
            )
            if not _patched_urllib3:
                try:
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                except Exception:
                    pass
                _patched_urllib3 = True
        return False

    if cafile:
        path = os.path.normpath(cafile)
        if os.path.isfile(path):
            logger.info("IDS SSE: TLS com verify via ficheiro: %s", path)
            return path
        if not _warned_ca_missing:
            _warned_ca_missing = True
            logger.error(
                "IDS SSE: IDS_SSE_TLS_CAFILE não encontrado (%s); a usar CAs do sistema.",
                path,
            )

    return True
