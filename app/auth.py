
"""Login, recuperação de senha e troca de celular."""
import datetime
import secrets
import time

from flask import (
    Blueprint,
    current_app,
    render_template,
    request,
    make_response,
    jsonify,
    redirect,
)

from app import auditoria
from app.db import get_db
from app.seguranca import verificar_senha, emitir_token, hash_senha

bp = Blueprint("auth", __name__)

# Controle temporário de tentativas de login.
MAX_TENTATIVAS = 5
TEMPO_BLOQUEIO = 300  # 5 minutos

# OTP válido por 10 minutos.
TEMPO_VALIDADE_OTP = 10


def _tentativas_login():
    if "TENTATIVAS_LOGIN" not in current_app.config:
        current_app.config["TENTATIVAS_LOGIN"] = {}

    return current_app.config["TENTATIVAS_LOGIN"]


def _autenticar(cpf, senha):
    """Retorna (usuario, erro, status_http)."""
    db = get_db()
    agora = time.time()
    tentativas_login = _tentativas_login()

    tentativa = tentativas_login.get(cpf)

    if tentativa and tentativa.get("bloqueado_ate", 0) > agora:
        return None, "Muitas tentativas. Tente novamente mais tarde.", 429

    usuario = db.execute(
        "SELECT * FROM usuarios WHERE cpf = ?",
        (cpf,),
    ).fetchone()

    credenciais_invalidas = (
        usuario is None
        or not verificar_senha(senha, usuario["senha_hash"])
    )

    if credenciais_invalidas:
        dados = tentativas_login.setdefault(
            cpf,
            {"falhas": 0, "bloqueado_ate": 0},
        )

        dados["falhas"] += 1

        if dados["falhas"] >= MAX_TENTATIVAS:
            dados["bloqueado_ate"] = agora + TEMPO_BLOQUEIO

        return None, "CPF ou senha inválidos.", 401

    tentativas_login.pop(cpf, None)

    return usuario, None, 200


def _vincular_dispositivo(usuario):
    db = get_db()

    db.execute(
        """
        INSERT INTO dispositivos
        (usuario_id, descricao, vinculado_em)
        VALUES (?, ?, ?)
        """,
        (
            usuario["id"],
            request.headers.get("User-Agent", "desconhecido")[:80],
            datetime.datetime.now().isoformat(timespec="seconds"),
        ),
    )

    db.commit()


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    cpf = request.form.get("cpf", "").strip()
    senha = request.form.get("senha", "")

    usuario, erro, status = _autenticar(cpf, senha)

    if erro:
        return render_template(
            "login.html",
            erro=erro,
            cpf=cpf,
        ), status

    token = emitir_token(usuario)

    _vincular_dispositivo(usuario)

    # Não registrar token, senha ou outros segredos na auditoria.
    auditoria.registrar(
        cpf,
        "LOGIN_OK",
        {
            "ip": request.remote_addr,
        },
    )

    resp = make_response(redirect("/home"))

    # COOKIE_SECURE deve permanecer True em produção.
    cookie_secure = current_app.config.get("COOKIE_SECURE", True)

    resp.set_cookie(
        "box_token",
        token,
        max_age=60 * 60 * 24 * 7,
        httponly=True,
        secure=cookie_secure,
        samesite="Lax",
    )

    return resp


@bp.route("/api/v1/auth/login", methods=["POST"])
def api_login():
    dados = request.get_json(silent=True)

    if not isinstance(dados, dict):
        return jsonify({"erro": "Dados inválidos."}), 400

    cpf = str(dados.get("cpf", "")).strip()
    senha = dados.get("senha", "")

    if not isinstance(senha, str):
        return jsonify({"erro": "Dados inválidos."}), 400

    usuario, erro, status = _autenticar(cpf, senha)

    if erro:
        return jsonify({"erro": erro}), status

    token = emitir_token(usuario)

    auditoria.registrar(
        usuario["cpf"],
        "LOGIN_API_OK",
    )

    return jsonify({
        "token": token,
        "tipo": "Bearer",
        "expira_em_horas": 168,
    })


@bp.route("/logout")
def logout():
    resp = make_response(redirect("/login"))

    cookie_secure = current_app.config.get("COOKIE_SECURE", True)

    resp.delete_cookie(
        "box_token",
        path="/",
        secure=cookie_secure,
        httponly=True,
        samesite="Lax",
    )

    return resp


@bp.route("/recuperar", methods=["GET", "POST"])
def recuperar():
    if request.method == "GET":
        return render_template("recuperar.html", etapa="dados")

    db = get_db()

    cpf = request.form.get("cpf", "").strip()
    nascimento = request.form.get("nascimento", "").strip()

    usuario = db.execute(
        """
        SELECT * FROM usuarios
        WHERE cpf = ? AND nascimento = ?
        """,
        (cpf, nascimento),
    ).fetchone()

    if not usuario:
        return render_template(
            "recuperar.html",
            etapa="dados",
            erro="Dados não conferem.",
        ), 400

    # Gerador criptograficamente seguro.
    codigo = f"{secrets.randbelow(10000):04d}"

    expira = (
        datetime.datetime.now()
        + datetime.timedelta(minutes=TEMPO_VALIDADE_OTP)
    ).isoformat()

    db.execute(
        """
        INSERT OR REPLACE INTO otp (cpf, codigo, expira_em)
        VALUES (?, ?, ?)
        """,
        (cpf, codigo, expira),
    )

    db.commit()

    # Nunca registrar o código OTP na auditoria.
    auditoria.registrar(
        cpf,
        "OTP_ENVIADO",
    )

    return render_template(
        "recuperar.html",
        etapa="codigo",
        cpf=cpf,
        celular=usuario["celular"],
    )


@bp.route("/recuperar/confirmar", methods=["POST"])
def recuperar_confirmar():
    db = get_db()

    cpf = request.form.get("cpf", "").strip()
    codigo = request.form.get("codigo", "").strip()
    nova_senha = request.form.get("nova_senha", "")

    otp = db.execute(
        """
        SELECT * FROM otp
        WHERE cpf = ? AND codigo = ?
        """,
        (cpf, codigo),
    ).fetchone()

    if not otp:
        return render_template(
            "recuperar.html",
            etapa="codigo",
            cpf=cpf,
            erro="Código inválido.",
        ), 400

    # Verifica se o código expirou.
    try:
        expira_em = datetime.datetime.fromisoformat(otp["expira_em"])
    except (ValueError, TypeError):
        return render_template(
            "recuperar.html",
            etapa="codigo",
            cpf=cpf,
            erro="Código inválido ou expirado.",
        ), 400

    if datetime.datetime.now() > expira_em:
        db.execute("DELETE FROM otp WHERE cpf = ?", (cpf,))
        db.commit()

        return render_template(
            "recuperar.html",
            etapa="codigo",
            cpf=cpf,
            erro="Código expirado. Solicite um novo.",
        ), 400

    # Atualiza a senha e invalida o OTP após o uso.
    db.execute(
        "UPDATE usuarios SET senha_hash = ? WHERE cpf = ?",
        (hash_senha(nova_senha), cpf),
    )

    db.execute(
        "DELETE FROM otp WHERE cpf = ?",
        (cpf,),
    )

    db.commit()

    auditoria.registrar(cpf, "SENHA_RECUPERADA")

    return render_template("recuperar.html", etapa="ok")


@bp.route("/recuperar/trocar-celular", methods=["POST"])
def trocar_celular():
    db = get_db()

    cpf = request.form.get("cpf", "").strip()
    nome_mae = request.form.get("nome_mae", "").strip()
    novo = request.form.get("novo_celular", "").strip()

    # ATENÇÃO:
    # CPF + nome da mãe não são suficientes para autorizar
    # uma alteração de telefone com segurança.
    # O ideal é exigir sessão autenticada e confirmação adicional.

    usuario = db.execute(
        """
        SELECT id FROM usuarios
        WHERE cpf = ? AND nome_mae = ?
        """,
        (cpf, nome_mae),
    ).fetchone()

    if not usuario:
        return render_template(
            "recuperar.html",
            etapa="dados",
            erro="Dados não conferem.",
        ), 400

    # Esta atualização deve ser protegida por uma etapa
    # adicional de verificação de identidade.
    db.execute(
        "UPDATE usuarios SET celular = ? WHERE id = ?",
        (novo, usuario["id"]),
    )

    db.commit()

    return render_template(
        "recuperar.html",
        etapa="dados",
        info="Celular atualizado com sucesso!",
    )
