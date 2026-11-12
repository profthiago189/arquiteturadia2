"""Abertura de conta digital / KYC."""
from werkzeug.utils import secure_filename
import uuid
import os

from flask import (
    Blueprint,
    render_template,
    request,
    current_app,
    Response,
    url_for
)

from app import auditoria

nome_original = secure_filename(arq.filename)

if not nome_original:
    return "Nome de arquivo inválido.", 400

extensao = os.path.splitext(nome_original)[1].lower()

extensoes_permitidas = {".pdf", ".jpg", ".jpeg", ".png"}

if extensao not in extensoes_permitidas:
    return "Tipo de arquivo não permitido.", 400

nome_seguro = f"{uuid.uuid4().hex}{extensao}"
bp = Blueprint("onboarding", __name__)


@bp.route("/abrir-conta", methods=["GET", "POST"])
def abrir_conta():
    if request.method == "GET":
        return render_template("abrir_conta.html")
    cpf = request.form.get("cpf", "")
    salvos = []
    os.makedirs(current_app.config["UPLOAD_DIR"], exist_ok=True)
    for campo in ("documento", "selfie"):
        arq = request.files.get(campo)
        if arq is None or arq.filename == "":
            continue
        nome_original = secure_filename(arq.filename)

        if not nome_original:
            return "Nome de arquivo inválido.", 400

        extensao = os.path.splitext(nome_original)[1].lower()

        extensoes_permitidas = {".pdf", ".jpg", ".jpeg", ".png"}

        if extensao not in extensoes_permitidas:
            return "Tipo de arquivo não permitido.", 400

        nome_seguro = f"{uuid.uuid4().hex}{extensao}"
        # TM-28 (CWE-434 / CWE-22): nome original, sem validar tipo, tamanho ou caminho
        destino = os.path.join(
            current_app.config["UPLOAD_DIR"],
            nome_seguro
        )
        arq.save(destino)
        salvos.append(nome_seguro)
    auditoria.registrar(cpf, "KYC_UPLOAD", {"cpf": cpf, "arquivos": salvos})
    return render_template("abrir_conta.html", enviados=salvos)


@bp.route("/uploads/<path:nome>")
def ver_upload(nome):
    # TM-09: documentos e selfies públicos, sem autenticação; leitura com caminho controlado pelo usuário
    caminho = os.path.join(current_app.config["UPLOAD_DIR"], nome)
    with open(caminho, "rb") as f:
        return Response(f.read(), mimetype="application/octet-stream")
