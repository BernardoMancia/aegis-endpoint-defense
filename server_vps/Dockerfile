# ---- Build Stage ----
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- Runtime Stage ----
FROM python:3.11-slim

LABEL maintainer="Aegis SOC Team"
LABEL description="Aegis SIEM & EDR C2 Server"
LABEL version="1.0.0"

# Instala curl para o healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Cria usuário não-root para segurança
RUN groupadd -r aegis && useradd -r -g aegis aegis

WORKDIR /app

# Copia dependências do build stage
COPY --from=builder /install /usr/local

# Copia o código da aplicação
COPY . .

# Cria diretório de dados e ajusta permissões
RUN mkdir -p /app/data && chown -R aegis:aegis /app

USER aegis

EXPOSE 5000

# Saúde da aplicação
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Usa gunicorn em produção, com suporte a threads para o SQLite WAL
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", \
    "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", \
    "app:app"]
