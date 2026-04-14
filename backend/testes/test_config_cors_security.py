"""
Testes de configuração relacionados com segurança (CORS + flags).
Requer backend/.env ou variáveis por defeito em config.py.
"""
from __future__ import annotations

import os

import pytest

import config


class TestCorsOrigins:
    def test_allow_origins_nao_e_curinga_com_credenciais(self):
        """Com allow_credentials=True no FastAPI, origins não pode ser ['*']."""
        assert isinstance(config.CORS_ALLOWED_ORIGINS, list)
        assert len(config.CORS_ALLOWED_ORIGINS) > 0
        assert "*" not in config.CORS_ALLOWED_ORIGINS

    def test_origem_localhost_presente_se_usar_padrao(self):
        """Lista por defeito inclui origens de desenvolvimento explícitas."""
        if os.getenv("CORS_ALLOWED_ORIGINS", "").strip():
            pytest.skip("CORS_ALLOWED_ORIGINS definido no ambiente — validação manual")
        assert "http://localhost:3000" in config.CORS_ALLOWED_ORIGINS


class TestAuthFlags:
    def test_strict_session_e_booleano_legivel(self):
        assert isinstance(config.AUTH_STRICT_SESSION, bool)
