"""
API de demonstração — Zero Trust DevSecOps
Leandro Oliveira Moraes

API FastAPI simples para demonstrar os scans da pipeline DevSecOps.
Autenticação via JWT Bearer token.

Endpoints:
  GET  /health     — health check (sem auth)
  GET  /api/v1/info — informações básicas da aplicação (auth necessária)
  POST /api/v1/echo — ecoa o payload recebido (auth + scope api:write)

Para testar localmente:
  uvicorn main:app --reload --port 8080
  curl http://localhost:8080/health
"""

import os
import logging
import time
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Importa jose para validação de JWT
# python-jose é a biblioteca recomendada para FastAPI
from jose import jwt, JWTError, ExpiredSignatureError

# Configuração de logging estruturado
# Em produção, os logs vão para stdout e são coletados pelo Fluentd/Loki
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "info").upper(),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ─── Configurações da aplicação ────────────────────────────────────────────────

APP_VERSION = "1.0.0"
APP_NAME = "zero-trust-api"

# Configurações JWT — em produção vêm de variáveis de ambiente / Vault
# Nunca hardcoded em produção
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE-ME-IN-PRODUCTION-USE-VAULT")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")  # TODO: mudar para RS256 em prod
JWT_ISSUER = os.getenv("JWT_ISSUER", "https://auth.zero-trust-app.example.com")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "zero-trust-api")

# ─── Inicialização do app ──────────────────────────────────────────────────────

app = FastAPI(
    title="Zero Trust API",
    description="API de demonstração para o projeto zero-trust-devsecops-supply-chain",
    version=APP_VERSION,
    # Desabilita docs em produção — evita exposição desnecessária
    docs_url="/docs" if os.getenv("ENV", "production") != "production" else None,
    redoc_url="/redoc" if os.getenv("ENV", "production") != "production" else None,
    openapi_url="/openapi.json" if os.getenv("ENV", "production") != "production" else None,
)

# CORS restrito — apenas origins autorizados
# Em produção, substituir pelo domínio real
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://app.zero-trust.example.com").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # só os métodos que a API usa
    allow_headers=["Authorization", "Content-Type"],
)

# Esquema de autenticação Bearer (JWT)
bearer_scheme = HTTPBearer()

# ─── Modelos Pydantic ──────────────────────────────────────────────────────────

class EchoRequest(BaseModel):
    """Payload para o endpoint de echo."""
    message: str
    metadata: dict[str, Any] | None = None


class TokenData(BaseModel):
    """Dados extraídos do JWT após validação."""
    sub: str           # subject — ID do usuário ou service account
    scopes: list[str]  # escopos autorizados
    exp: int           # expiration timestamp

# ─── Autenticação e Autorização ────────────────────────────────────────────────

def validate_jwt(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> TokenData:
    """
    Valida o JWT Bearer token e retorna os dados do token.

    Verifica:
    - Assinatura válida
    - Token não expirado
    - Issuer correto
    - Audience correto

    Raises:
        HTTPException 401 se o token for inválido ou expirado.
    """
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido ou expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["sub", "exp", "iat"],  # campos obrigatórios
            }
        )

        sub = payload.get("sub")
        if not sub:
            logger.warning("Token sem campo 'sub'")
            raise credentials_exception

        # Extrai escopos — pode vir como string "api:read api:write" ou lista
        scope_field = payload.get("scope", "")
        if isinstance(scope_field, str):
            scopes = scope_field.split() if scope_field else []
        elif isinstance(scope_field, list):
            scopes = scope_field
        else:
            scopes = []

        return TokenData(
            sub=sub,
            scopes=scopes,
            exp=payload.get("exp", 0)
        )

    except ExpiredSignatureError:
        logger.warning("Token expirado")
        raise credentials_exception
    except JWTError as e:
        logger.warning("Erro de validação JWT: %s", str(e))
        raise credentials_exception


def require_scope(required_scope: str):
    """
    Dependency factory — cria uma dependência que verifica um scope específico.

    Uso:
        @app.get("/rota")
        def handler(token: TokenData = Depends(require_scope("api:read"))):
            ...
    """
    def check_scope(token_data: TokenData = Depends(validate_jwt)) -> TokenData:
        if required_scope not in token_data.scopes:
            logger.warning(
                "Acesso negado: usuário '%s' não tem scope '%s'. Scopes do token: %s",
                token_data.sub,
                required_scope,
                token_data.scopes
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope '{required_scope}' necessário para acessar este recurso"
            )
        return token_data

    return check_scope

# ─── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", include_in_schema=False)
def health_check():
    """
    Health check para liveness probe do Kubernetes.
    Sem autenticação — o kubelet precisa chamar sem token.
    """
    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": int(time.time())
    }


@app.get("/api/v1/info")
def get_info(
    token_data: Annotated[TokenData, Depends(require_scope("api:read"))]
):
    """
    Retorna informações básicas da aplicação.
    Requer autenticação com scope 'api:read'.
    """
    logger.info("Info solicitado por: %s", token_data.sub)

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "environment": os.getenv("ENV", "production"),
        "requested_by": token_data.sub,
        "timestamp": int(time.time()),
        "features": {
            "zero_trust": True,
            "mtls": True,
            "sbom": True,
            "slsa_level": 2
        }
    }


@app.post("/api/v1/echo", status_code=status.HTTP_200_OK)
def echo(
    request: EchoRequest,
    token_data: Annotated[TokenData, Depends(require_scope("api:write"))]
):
    """
    Ecoa o payload recebido.
    Requer autenticação com scope 'api:write'.

    Sanitiza a mensagem antes de retornar — previne reflected injection.
    """
    logger.info("Echo solicitado por: %s", token_data.sub)

    # Sanitização básica — remove caracteres de controle
    # Em uma API real, validação seria mais completa
    sanitized_message = "".join(
        c for c in request.message
        if c.isprintable() and c != "<" and c != ">"
    )

    if len(sanitized_message) != len(request.message):
        logger.warning("Mensagem sanitizada — caracteres removidos. Usuário: %s", token_data.sub)

    return {
        "echo": sanitized_message,
        "metadata": request.metadata,
        "processed_by": APP_NAME,
        "timestamp": int(time.time())
    }


# ─── Error handlers ────────────────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found_handler(request, exc):
    """Resposta padronizada para 404."""
    return JSONResponse(
        status_code=404,
        content={"error": "not_found", "detail": "Recurso não encontrado"}
    )


@app.exception_handler(405)
async def method_not_allowed_handler(request, exc):
    """Resposta padronizada para método não permitido."""
    return JSONResponse(
        status_code=405,
        content={"error": "method_not_allowed", "detail": "Método HTTP não permitido"}
    )


# ─── Inicialização para execução local ────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    host = os.getenv("HOST", "0.0.0.0")

    logger.info("Iniciando %s v%s em %s:%d", APP_NAME, APP_VERSION, host, port)

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=False,  # reload apenas em dev — usar variável de ambiente se necessário
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
        workers=1  # múltiplos workers via --workers no CMD do Dockerfile
    )
