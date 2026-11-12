"""Funções de segurança do Core Box (autenticação, hash, JWT)."""
import datetime
import functools

import jwt
from flask import current_app, g, request, jsonify, redirect

from app.db import get_db

from werkzeug.security import generate_password_hash, check_password_hash

def hash_senha(senha):
    # TM-12 CORRIGIDO:
    # password hashing lento e com salt aleatório.
    return generate_password_hash(
        senha,
        method="pbkdf2:sha256",
        salt_length=16,
    )


def verificar_senha(senha, senha_hash):
    try:
        return check_password_hash(senha_hash, senha)
    except (ValueError, TypeError):
        return False


def emitir_token(usuario):
    agora = datetime.datetime.utcnow()
    payload = {
        "sub": str(usuario["id"]),
        "cpf": usuario["cpf"],
        "nome": usuario["nome"],
        "perfil": usuario["perfil"],
        "iat": agora,
        "exp": agora + datetime.timedelta(hours=current_app.config["JWT_EXPIRACAO_HORAS"]),
    }
    token = jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")
    if isinstance(token, bytes):  # compatibilidade PyJWT 1.x
        token = token.decode()
    return token


def _token_da_requisicao():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("box_token")


def usuario_atual():
    token = _token_da_requisicao()
    if not token:
        return None
    try:
        dados = jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return get_db().execute("SELECT * FROM usuarios WHERE id = ?", (int(dados["sub"]),)).fetchone()


def login_obrigatorio(perfil=None, api=False):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            usuario = usuario_atual()
            if usuario is None or (perfil and usuario["perfil"] != perfil):
                if api or request.path.startswith("/api/"):
                    return jsonify({"erro": "não autenticado"}), 401
                destino = "/backoffice/login" if request.path.startswith("/backoffice") else "/login"
                return redirect(destino)
            g.usuario = usuario
            return fn(*args, **kwargs)
        return wrapper
    return deco
