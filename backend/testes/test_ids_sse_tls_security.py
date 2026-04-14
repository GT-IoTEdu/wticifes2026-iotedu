"""
Comportamento de verify TLS para requests ao ids-log-monitor (sem rede).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest import mock

import pytest

BACKEND = Path(__file__).resolve().parent.parent / "backend"


@pytest.fixture
def fresh_tls_mod():
    """Recarrega o módulo para repor globais de aviso (testes isolados)."""
    import importlib
    import sys

    name = "ids_sse_tls_under_test_reload"
    path = BACKEND / "services_scanners" / "ids_sse_tls.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    yield mod
    if name in sys.modules:
        del sys.modules[name]


class TestSseRequestsVerify:
    def test_verify_false_retorna_false(self, fresh_tls_mod):
        import config

        with mock.patch.object(config, "IDS_SSE_TLS_VERIFY", False):
            with mock.patch.object(config, "IDS_SSE_TLS_CAFILE", None):
                assert fresh_tls_mod.sse_requests_verify() is False

    def test_verify_true_sem_cafile_retorna_true(self, fresh_tls_mod):
        import config

        with mock.patch.object(config, "IDS_SSE_TLS_VERIFY", True):
            with mock.patch.object(config, "IDS_SSE_TLS_CAFILE", None):
                assert fresh_tls_mod.sse_requests_verify() is True
