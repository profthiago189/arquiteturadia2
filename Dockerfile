# Core Box — imagem de produção endurecida
FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BOX_AMBIENTE=producao

WORKDIR /app

# Atualiza pacotes do SO para corrigir CVEs do Debian e instala dependências mínimas
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends iputils-ping && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Atualiza ferramentas base do Python (corrige CVEs de pip/setuptools/wheel)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Instala dependências da aplicação
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip uninstall -y setuptools wheel && \
    rm -rf /usr/local/lib/python*/ensurepip

# Cria usuário sem privilégios de root
RUN useradd --create-home --shell /bin/bash appuser
COPY --chown=appuser:appuser . .
USER appuser

EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "wsgi:app"]
