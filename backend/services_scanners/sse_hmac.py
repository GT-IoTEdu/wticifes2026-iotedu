"""
Verificação HMAC-SHA256 para payloads SSE recebidos do ids-log-monitor.
O servidor SSE assina cada evento com a API key; aqui validamos e removemos a assinatura.
Compatível com Python 3.9 (usa typing.Optional em vez de |).
"""
import hmac
import hashlib
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


def verify_and_strip_hmac(payload: Dict[str, Any], api_key: str) -> Optional[Dict[str, Any]]:
    """
    Se o payload contiver o campo 'signature', verifica HMAC-SHA256 usando api_key
    e retorna o payload sem o campo. Se a assinatura for inválida, retorna None.
    Se não houver 'signature', retorna o payload inalterado (compatibilidade com servidor sem HMAC).
    """
    if not isinstance(payload, dict):
        return None
    signature = payload.get("signature")
    if signature is None:
        return payload
    payload_without_sig: Dict[str, Any] = {k: v for k, v in payload.items() if k != "signature"}
    if not api_key:
        logger.warning("SSE HMAC: payload assinado recebido mas api_key vazia; evento rejeitado")
        return None
    try:
        body = json.dumps(payload_without_sig, sort_keys=True, ensure_ascii=False)
        expected = hmac.new(
            api_key.encode("utf-8"),
            body.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(expected, signature):
            return payload_without_sig
        logger.warning("SSE HMAC: assinatura inválida; evento rejeitado")
        return None
    except Exception as e:
        logger.warning("SSE HMAC: erro ao verificar assinatura: %s", e)
        return None
