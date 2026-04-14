"""
Política get_effective_user_id: modo estrito vs legado, sem ligar ao MySQL.

Injeta stubs em sys.modules antes de importar auth.dependencies (evita db.session
a criar engine MySQL na importação).
"""
from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

BACKEND = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _install_db_stubs():
    """Regista pacotes db mínimos para auth.dependencies importar."""
    db = types.ModuleType("db")
    db.session = types.ModuleType("db.session")
    db.models = types.ModuleType("db.models")

    def SessionLocal():
        raise RuntimeError("SessionLocal deve ser mockado no teste")

    db.session.SessionLocal = SessionLocal

    class User:
        # SQLAlchemy usa User.email na expressão filter(User.email == email)
        email = MagicMock(name="User_email_column")

    db.models.User = User
    sys.modules["db"] = db
    sys.modules["db.session"] = db.session
    sys.modules["db.models"] = db.models


_install_db_stubs()

import auth.dependencies as auth_dep  # noqa: E402
import config as app_config  # noqa: E402


def _mock_db_with_user(user: Optional[MagicMock]):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = user
    return db


class TestEffectiveUserIdStrictSession:
    def test_sem_sessao_strict_true_bloqueia_mesmo_com_query(self):
        """AUTH_STRICT_SESSION=true: current_user_id na URL não substitui cookie."""
        request = MagicMock()
        request.session = {}
        with patch.object(app_config, "AUTH_STRICT_SESSION", True):
            with pytest.raises(HTTPException) as exc:
                auth_dep.get_effective_user_id(request=request, current_user_id=99)
        assert exc.value.status_code == 401

    def test_sem_sessao_strict_false_aceita_query(self):
        request = MagicMock()
        request.session = {}
        with patch.object(app_config, "AUTH_STRICT_SESSION", False):
            uid = auth_dep.get_effective_user_id(request=request, current_user_id=7)
        assert uid == 7

    def test_sem_sessao_sem_query_401(self):
        request = MagicMock()
        request.session = {}
        with patch.object(app_config, "AUTH_STRICT_SESSION", False):
            with pytest.raises(HTTPException) as exc:
                auth_dep.get_effective_user_id(request=request, current_user_id=None)
        assert exc.value.status_code == 401

    def test_com_sessao_retorna_id(self):
        user = MagicMock()
        user.id = 42
        user.is_active = True
        request = MagicMock()
        request.session = {"email": "user@test.local"}
        db = _mock_db_with_user(user)
        with patch.object(auth_dep, "SessionLocal", return_value=db):
            uid = auth_dep.get_effective_user_id(request=request, current_user_id=None)
        assert uid == 42

    def test_com_sessao_user_id_query_diferente_403(self):
        user = MagicMock()
        user.id = 42
        user.is_active = True
        request = MagicMock()
        request.session = {"email": "user@test.local"}
        db = _mock_db_with_user(user)
        with patch.object(auth_dep, "SessionLocal", return_value=db):
            with pytest.raises(HTTPException) as exc:
                auth_dep.get_effective_user_id(request=request, current_user_id=999)
        assert exc.value.status_code == 403
