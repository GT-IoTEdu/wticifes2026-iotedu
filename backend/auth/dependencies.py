"""
Dependências de autenticação/autorização para FastAPI.

Objetivo:
- Validar sessão no backend (request.session), sem confiar no frontend.
- Resolver user_id efetivo para endpoints legados que ainda recebem current_user_id via query.
- Manter compatibilidade opcional com legado via config.AUTH_STRICT_SESSION.
"""
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Query, Request, status

from db.models import User
from db.session import SessionLocal


def get_authenticated_user(request: Request) -> Dict[str, Any]:
    """Obtém usuário autenticado pela sessão e valida status ativo."""
    email = None
    try:
        email = request.session.get("email")
    except Exception:
        email = None

    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Não autenticado. Faça login novamente.",
        )

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sessão inválida. Usuário não encontrado.",
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Sua conta está desativada.",
            )
        return {
            "id": user.id,
            "email": user.email,
            "permission": user.permission.value if getattr(user, "permission", None) else "USER",
            "institution_id": user.institution_id,
        }
    finally:
        db.close()


def get_effective_user_id(
    request: Request,
    current_user_id: Optional[int] = Query(None, description="(Legado) ID do usuário"),
) -> int:
    """
    Resolve o user_id efetivo no backend:
    - Se sessão válida existir: usa sessão; current_user_id (se enviado) deve coincidir.
    - Sem sessão:
      - AUTH_STRICT_SESSION=true  -> bloqueia (401).
      - AUTH_STRICT_SESSION=false -> aceita current_user_id legado.
    """
    # 1) Tentar validar sessão
    email = None
    try:
        email = request.session.get("email")
    except Exception:
        email = None

    if email:
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == email).first()
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Sessão inválida.",
                )
            session_user_id = int(user.id)
            if current_user_id is not None and int(current_user_id) != session_user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="current_user_id não corresponde ao usuário autenticado.",
                )
            return session_user_id
        finally:
            db.close()

    # 2) Sem sessão: seguir política de compatibilidade
    try:
        import config
        strict = bool(getattr(config, "AUTH_STRICT_SESSION", False))
    except Exception:
        strict = False

    if strict:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Não autenticado. Faça login novamente.",
        )

    if current_user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão ausente e current_user_id não informado.",
        )
    return int(current_user_id)
