#!/bin/bash
# generate-sbom.sh
#
# Gera Software Bill of Materials (SBOM) completo para um diretório ou imagem.
# Suporta múltiplos formatos: SPDX-JSON, CycloneDX-JSON, CycloneDX-XML.
# Após gerar, faz análise de vulnerabilidades e verifica licenças.
#
# Uso:
#   ./generate-sbom.sh [caminho-do-projeto-ou-imagem] [--image]
#
# Exemplos:
#   ./generate-sbom.sh ../../app                  # analisa diretório
#   ./generate-sbom.sh myapp:latest --image        # analisa imagem Docker
#   ./generate-sbom.sh . --image myapp:latest      # projeto atual + imagem
#
# Pré-requisitos:
#   - syft (https://github.com/anchore/syft)
#   - grype (https://github.com/anchore/grype)
#   - cosign (https://github.com/sigstore/cosign)
#   - pip-licenses (pip install pip-licenses)
#   - jq
#
# Referência: LFEL1007 — Automating Supply Chain Security

set -euo pipefail

# ─── Configurações ─────────────────────────────────────────────────────────────

TARGET="${1:-.}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="sbom-output/${TIMESTAMP}"
LOG_FILE="${OUTPUT_DIR}/generate-sbom.log"

# Cores para output no terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# ─── Funções auxiliares ────────────────────────────────────────────────────────

log() {
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $1" | tee -a "${LOG_FILE}"
}

success() {
    echo -e "${GREEN}✓${NC} $1" | tee -a "${LOG_FILE}"
}

warn() {
    echo -e "${YELLOW}⚠${NC} $1" | tee -a "${LOG_FILE}"
}

error() {
    echo -e "${RED}✗${NC} $1" | tee -a "${LOG_FILE}"
    exit 1
}

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        error "Ferramenta '$1' não encontrada. Instale antes de continuar."
    fi
    success "Ferramenta '$1' encontrada: $(command -v "$1")"
}

# ─── Início ────────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SBOM Generator — Zero Trust DevSecOps"
echo "  Alvo: ${TARGET}"
echo "  Output: ${OUTPUT_DIR}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Cria diretório de output
mkdir -p "${OUTPUT_DIR}"

# ─── Verifica ferramentas necessárias ─────────────────────────────────────────

log "Verificando ferramentas..."
check_tool syft
check_tool grype
check_tool jq

# cosign e pip-licenses são opcionais mas recomendados
if command -v cosign &> /dev/null; then
    COSIGN_AVAILABLE=true
    success "cosign disponível — SBOM será assinado"
else
    COSIGN_AVAILABLE=false
    warn "cosign não encontrado — SBOM não será assinado (recomendado instalar)"
fi

if command -v pip-licenses &> /dev/null; then
    PIP_LICENSES_AVAILABLE=true
else
    PIP_LICENSES_AVAILABLE=false
    warn "pip-licenses não encontrado — análise de licenças Python será pulada"
fi

echo ""

# ─── Geração do SBOM — Formato SPDX-JSON ──────────────────────────────────────
# SPDX é o formato padrão ISO/IEC 5962:2021 — mais adotado em compliance

log "Gerando SBOM em formato SPDX-JSON..."

syft "${TARGET}" \
    --output "spdx-json=${OUTPUT_DIR}/sbom.spdx.json" \
    --source-name "zero-trust-app" \
    --source-version "$(git describe --tags --always 2>/dev/null || echo 'unknown')"

# Conta quantos componentes foram encontrados
COMPONENT_COUNT=$(jq '.packages | length' "${OUTPUT_DIR}/sbom.spdx.json" 2>/dev/null || echo "0")
success "SPDX-JSON gerado: ${COMPONENT_COUNT} pacotes identificados"

# ─── Geração do SBOM — Formato CycloneDX-JSON ─────────────────────────────────
# CycloneDX é preferido para análise de vulnerabilidades com grype

log "Gerando SBOM em formato CycloneDX-JSON..."

syft "${TARGET}" \
    --output "cyclonedx-json=${OUTPUT_DIR}/sbom.cyclonedx.json" \
    --source-name "zero-trust-app"

success "CycloneDX-JSON gerado"

# ─── Geração do SBOM — Formato CycloneDX-XML ──────────────────────────────────
# XML para compatibilidade com ferramentas legadas e algumas ferramentas de compliance

log "Gerando SBOM em formato CycloneDX-XML..."

syft "${TARGET}" \
    --output "cyclonedx-xml=${OUTPUT_DIR}/sbom.cyclonedx.xml" \
    --source-name "zero-trust-app"

success "CycloneDX-XML gerado"

echo ""

# ─── Análise de vulnerabilidades com Grype ────────────────────────────────────
# Grype analisa o SBOM (não precisa reescanear o alvo)

log "Analisando vulnerabilidades com Grype..."

grype "sbom:${OUTPUT_DIR}/sbom.cyclonedx.json" \
    --output json \
    --file "${OUTPUT_DIR}/vulnerabilities.json" \
    --fail-on critical 2>&1 | tee -a "${LOG_FILE}" || {

    # grype retorna código != 0 se encontrou vulnerabilidades críticas
    # mas queremos continuar o script e gerar o relatório
    warn "Grype encontrou vulnerabilidades CRITICAL — verifique ${OUTPUT_DIR}/vulnerabilities.json"
}

# Gera relatório resumido de vulnerabilidades
log "Gerando resumo de vulnerabilidades..."
python3 << EOF | tee -a "${LOG_FILE}"
import json

try:
    with open("${OUTPUT_DIR}/vulnerabilities.json") as f:
        data = json.load(f)

    matches = data.get("matches", [])
    by_severity = {}
    for m in matches:
        sev = m.get("vulnerability", {}).get("severity", "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    print("\n  Resumo de vulnerabilidades:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]:
        count = by_severity.get(sev, 0)
        symbol = "✗" if sev in ["CRITICAL", "HIGH"] and count > 0 else "•"
        print(f"    {symbol} {sev}: {count}")
    print()
except Exception as e:
    print(f"  Erro ao processar vulnerabilidades: {e}")
EOF

# ─── Análise de licenças ───────────────────────────────────────────────────────

log "Analisando licenças das dependências..."

# Extrai licenças do SBOM (funciona para qualquer linguagem)
python3 << 'EOF' > "${OUTPUT_DIR}/licenses-summary.json"
import json, sys

with open("${OUTPUT_DIR}/sbom.spdx.json") as f:
    sbom = json.load(f)

licenses = []
for pkg in sbom.get("packages", []):
    pkg_name = pkg.get("name", "unknown")
    pkg_version = pkg.get("versionInfo", "unknown")
    pkg_licenses = pkg.get("licenseDeclared", "NOASSERTION")
    pkg_source = pkg.get("externalRefs", [{}])[0].get("referenceLocator", "") if pkg.get("externalRefs") else ""

    licenses.append({
        "name": pkg_name,
        "version": pkg_version,
        "license": pkg_licenses,
        "source": pkg_source
    })

print(json.dumps({"packages": licenses, "total": len(licenses)}, indent=2))
EOF

success "Análise de licenças concluída — ver ${OUTPUT_DIR}/licenses-summary.json"

# Verifica licenças bloqueadas
log "Verificando política de licenças..."
python3 << 'EOF' | tee -a "${LOG_FILE}"
import json

BLOCKED_LICENSES = [
    "GPL-2.0", "GPL-3.0", "AGPL-3.0",
    "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0"
]

with open("${OUTPUT_DIR}/licenses-summary.json") as f:
    data = json.load(f)

blocked_found = []
for pkg in data["packages"]:
    lic = pkg.get("license", "")
    for b in BLOCKED_LICENSES:
        if b in lic:
            blocked_found.append(f"{pkg['name']}@{pkg['version']}: {lic}")

if blocked_found:
    print(f"  ✗ Licenças BLOQUEADAS encontradas:")
    for b in blocked_found:
        print(f"    - {b}")
else:
    print("  ✓ Nenhuma licença bloqueada encontrada")
EOF

# pip-licenses para Python (se disponível)
if [ "${PIP_LICENSES_AVAILABLE}" = "true" ] && [ -f "${TARGET}/requirements.txt" ]; then
    log "Gerando relatório de licenças Python com pip-licenses..."
    pip-licenses \
        --format=json \
        --output-file="${OUTPUT_DIR}/licenses-python.json" \
        2>/dev/null || warn "pip-licenses falhou — verifique se as dependências estão instaladas"
fi

echo ""

# ─── Hash e integridade ────────────────────────────────────────────────────────

log "Calculando hashes dos SBOMs..."

sha256sum \
    "${OUTPUT_DIR}/sbom.spdx.json" \
    "${OUTPUT_DIR}/sbom.cyclonedx.json" \
    "${OUTPUT_DIR}/sbom.cyclonedx.xml" \
    > "${OUTPUT_DIR}/sbom-checksums.sha256"

success "Checksums salvos em ${OUTPUT_DIR}/sbom-checksums.sha256"

# ─── Assinatura com Cosign ────────────────────────────────────────────────────

if [ "${COSIGN_AVAILABLE}" = "true" ]; then
    log "Assinando SBOMs com Cosign (keyless via OIDC)..."

    # Em ambiente local, cosign usa uma chave temporária de desenvolvimento
    # Em CI/CD, usa OIDC token do GitHub Actions (keyless signing)
    if [ -n "${COSIGN_KEY:-}" ]; then
        # Assinatura com chave (se COSIGN_KEY estiver definido)
        cosign sign-blob \
            --key "${COSIGN_KEY}" \
            --output-signature "${OUTPUT_DIR}/sbom.spdx.json.sig" \
            "${OUTPUT_DIR}/sbom.spdx.json"
        success "SBOM assinado com chave: ${OUTPUT_DIR}/sbom.spdx.json.sig"
    else
        warn "COSIGN_KEY não definido — assinatura keyless requer ambiente CI/CD com OIDC"
        warn "Para assinar localmente: export COSIGN_KEY=cosign.key && ./generate-sbom.sh"
    fi
fi

# ─── Resumo final ─────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SBOM gerado com sucesso!"
echo ""
echo "  Arquivos em: ${OUTPUT_DIR}/"
echo "  ├── sbom.spdx.json         (SPDX-JSON — ISO/IEC 5962)"
echo "  ├── sbom.cyclonedx.json    (CycloneDX-JSON)"
echo "  ├── sbom.cyclonedx.xml     (CycloneDX-XML)"
echo "  ├── vulnerabilities.json   (resultado Grype)"
echo "  ├── licenses-summary.json  (análise de licenças)"
echo "  ├── sbom-checksums.sha256  (integridade)"
echo "  └── generate-sbom.log      (log completo)"
echo ""
echo "  Para verificar: ./verify-sbom.sh ${OUTPUT_DIR}/sbom.spdx.json"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
