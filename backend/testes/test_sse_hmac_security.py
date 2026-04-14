"""
Testes de segurança: verificação HMAC dos payloads SSE (ids-log-monitor → backend).

Carrega apenas o ficheiro sse_hmac.py para não importar services_scanners/__init__.py
(que puxa routers e MySQL).
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent / "backend"


def _load_sse_hmac():
    path = BACKEND / "services_scanners" / "sse_hmac.py"
    spec = importlib.util.spec_from_file_location("sse_hmac_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sse_hmac_mod():
    return _load_sse_hmac()


def _sign(payload: dict, secret: str) -> dict:
    """Mesma lógica que ids-log-monitor/sse_server.py sign_payload (canónico)."""
    body = json.dumps({k: v for k, v in payload.items() if k != "signature"}, sort_keys=True, ensure_ascii=False)
    sig = hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return {**{k: v for k, v in payload.items() if k != "signature"}, "signature": sig}


class TestSseHmacVerification:
    API_KEY = "chave-secreta-de-teste-uuid-exemplo"

    def test_payload_sem_assinatura_aceite_compatibilidade(self, sse_hmac_mod):
        """Servidor legado sem HMAC: backend não rejeita por falta de signature."""
        verify = sse_hmac_mod.verify_and_strip_hmac
        p = {"type": "alert", "data": {"x": 1}}
        out = verify(p, self.API_KEY)
        assert out == p

    def test_assinatura_valida_remove_campo(self, sse_hmac_mod):
        verify = sse_hmac_mod.verify_and_strip_hmac
        inner = {"type": "alert", "message": "teste"}
        signed = _sign(inner, self.API_KEY)
        out = verify(signed, self.API_KEY)
        assert out is not None
        assert "signature" not in out
        assert out["type"] == "alert"

    def test_assinatura_invalida_rejeitada(self, sse_hmac_mod):
        verify = sse_hmac_mod.verify_and_strip_hmac
        inner = {"type": "alert"}
        tampered = {**inner, "signature": "0" * 64}
        assert verify(tampered, self.API_KEY) is None

    def test_chave_errada_rejeitada(self, sse_hmac_mod):
        verify = sse_hmac_mod.verify_and_strip_hmac
        inner = {"type": "alert"}
        signed = _sign(inner, self.API_KEY)
        assert verify(signed, "outra-chave") is None

    def test_payload_assinado_com_api_key_vazia_rejeitado(self, sse_hmac_mod):
        verify = sse_hmac_mod.verify_and_strip_hmac
        signed = _sign({"a": 1}, self.API_KEY)
        assert verify(signed, "") is None

    def test_payload_nao_e_dict(self, sse_hmac_mod):
        assert sse_hmac_mod.verify_and_strip_hmac("not-a-dict", self.API_KEY) is None
