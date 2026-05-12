# Dockerfile multi-stage seguro
#
# Estágio 1 (builder): instala dependências, compila se necessário
# Estágio 2 (runtime): imagem mínima com apenas o necessário para rodar
#
# Segurança implementada:
#   - Usuário não-root (uid 10001)
#   - Sem SUID binaries
#   - Imagem base mínima (python:slim — ~50MB vs ~300MB do full)
#   - Labels OCI para rastreabilidade
#   - Healthcheck definido
#
# Para verificar: docker build -t app:test . && docker run --rm app:test python -c "import app"
# Para scan: trivy image app:test

# ── Stage 1: Build / instalação de dependências ────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Instala dependências de sistema para compilar pacotes Python que têm extensões C
# --no-install-recommends evita instalar pacotes opcionais não necessários
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copia requirements primeiro para aproveitar cache do Docker
# (se requirements.txt não mudar, essa layer é reutilizada)
COPY requirements.txt .

# Instala dependências em diretório separado para copiar para o runtime
RUN pip install --no-cache-dir --target=/app-deps -r requirements.txt

# ── Stage 2: Runtime ────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Labels OCI — rastreabilidade do artefato
# Permite saber de qual commit e repositório veio essa imagem
LABEL org.opencontainers.image.title="Zero Trust App"
LABEL org.opencontainers.image.description="API de demonstração — Zero Trust DevSecOps"
LABEL org.opencontainers.image.authors="Leandro Oliveira Moraes"
LABEL org.opencontainers.image.source="https://github.com/leandroninja/zero-trust-devsecops-supply-chain"
LABEL org.opencontainers.image.licenses="MIT"
# ARG passados no build --build-arg para ter valores reais na imagem de produção
ARG BUILD_VERSION="dev"
ARG BUILD_COMMIT="unknown"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT}"

# Cria grupo e usuário não-root antes de qualquer outra coisa
# UID 10001 — fora da faixa de sistema (1-999) e de usuário normal (<10000)
# Sem shell (-s /sbin/nologin) e sem home (-M) — menos superfície de ataque
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid 10001 \
    --no-create-home \
    --shell /sbin/nologin \
    --comment "App service account" \
    appuser

# Cria diretório da aplicação e atribui ao usuário da app
# /app: código da aplicação (read-only em runtime)
# /tmp/app: arquivos temporários se necessário
WORKDIR /app
RUN mkdir -p /tmp/app && \
    chown -R appuser:appgroup /app /tmp/app

# Copia dependências instaladas no stage de build
COPY --from=builder /app-deps /usr/local/lib/python3.11/site-packages/

# Copia código da aplicação
# --chown garante que os arquivos pertencem ao usuário da app
COPY --chown=appuser:appgroup main.py ./

# Remove SUID e SGID bits de binários do sistema
# SUID permite executar binários com privilégios do dono — risco em caso de exploit
RUN find / -perm /6000 -type f 2>/dev/null | xargs chmod a-s 2>/dev/null || true

# Remove pacotes desnecessários que vieram na imagem base
# gcc, binutils, etc. não são necessários em runtime
RUN apt-get update && \
    apt-get remove -y --purge \
        gcc \
        binutils \
        bsdutils \
    2>/dev/null; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Troca para usuário não-root
# A partir daqui, todos os comandos rodam como appuser (uid 10001)
USER appuser

# Variáveis de ambiente da aplicação
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PORT=8080 \
    HOST=0.0.0.0 \
    LOG_LEVEL=info \
    # Diretório temporário no volume montado (filesystem root é read-only)
    TMPDIR=/tmp/app

# Porta da aplicação
EXPOSE 8080

# Healthcheck — Kubernetes usa para liveness e readiness
# Mas a definição aqui também funciona para docker run sem k8s
HEALTHCHECK --interval=30s \
            --timeout=5s \
            --start-period=10s \
            --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Comando de inicialização
# uvicorn com workers — sem reload (reload usa watchfiles que adiciona dependência)
CMD ["python3", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "2", \
     "--no-access-log", \
     "--log-level", "info"]
