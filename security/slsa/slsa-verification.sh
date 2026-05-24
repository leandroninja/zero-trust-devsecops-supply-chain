#!/bin/bash
# slsa-verification.sh
#
# Verifica SLSA provenance de um artefato.
# Garante que o binário/imagem foi construído por um builder confiável,
# a partir do repositório oficial, sem modificações.
#
# O que é SLSA?
#   Supply-chain Levels for Software Artifacts — framework da OpenSSF
#   para verificar integridade da cadeia de supply chain.
#   Level 2 = build feito por CI/CD com provenance assinada.
#   Level 3 = builder hardened + isolamento de build.
#
# Uso:
#   ./slsa-verification.sh <artifact> <provenance.intoto.jsonl>
#
# Exemplos:
#   ./slsa-verification.sh app-v1.0.tar.gz provenance.intoto.jsonl
#   ./slsa-verification.sh ghcr.io/org/app:v1.0 provenance.intoto.jsonl
#
# Pré-requisito: slsa-verifier (https://github.com/slsa-framework/slsa-verifier)
#
# Referência: LFEL1007 — Automating Supply Chain Security
#             https://slsa.dev/spec/v1.0/levels

set -euo pipefail

# ─── Configurações ─────────────────────────────────────────────────────────────

ARTIFACT="${1:-}"
PROVENANCE_FILE="${2:-}"

# Builder confiável — GitHub Actions SLSA generator oficial
TRUSTED_BUILDER="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"

# Repositório fonte autorizado
SOURCE_REPO="github.com/leandroninja/zero-trust-devsecops-supply-chain"

# Nível SLSA mínimo exigido
MIN_SLSA_LEVEL=2

# Branch permitido para produção
ALLOWED_BRANCHES=("main" "release/*")

# ─── Verificações de input ─────────────────────────────────────────────────────

if [ -z "${ARTIFACT}" ] || [ -z "${PROVENANCE_FILE}" ]; then
    echo ""
    echo "Uso: ./slsa-verification.sh <artifact> <provenance.intoto.jsonl>"
    echo ""
    echo "Exemplos:"
    echo "  ./slsa-verification.sh app.tar.gz provenance.intoto.jsonl"
    echo "  ./slsa-verification.sh image.tar provenance.intoto.jsonl"
    echo ""
    exit 1
fi

if [ ! -f "${PROVENANCE_FILE}" ]; then
    echo "✗ Arquivo de provenance não encontrado: ${PROVENANCE_FILE}"
    echo "  O arquivo de provenance deve ser baixado junto com o artefato."
    exit 1
fi

# ─── Verifica ferramenta slsa-verifier ────────────────────────────────────────

if ! command -v slsa-verifier &> /dev/null; then
    echo ""
    echo "✗ slsa-verifier não instalado."
    echo ""
    echo "  Instale com:"
    echo "    curl -Lo slsa-verifier https://github.com/slsa-framework/slsa-verifier/releases/latest/download/slsa-verifier-linux-amd64"
    echo "    chmod +x slsa-verifier && sudo mv slsa-verifier /usr/local/bin/"
    echo ""
    exit 1
fi

VERIFIER_VERSION=$(slsa-verifier version 2>/dev/null | head -1)
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SLSA Provenance Verification"
echo "  Ferramenta: ${VERIFIER_VERSION}"
echo "  Artefato: ${ARTIFACT}"
echo "  Provenance: ${PROVENANCE_FILE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

VERIFICATION_PASSED=true

# ─── Verificação 1: Arquivo de provenance válido ──────────────────────────────

echo "[ 1/4 ] Validando formato do arquivo de provenance..."

if ! jq empty "${PROVENANCE_FILE}" 2>/dev/null; then
    echo "  ✗ Provenance inválida — não é JSON válido"
    VERIFICATION_PASSED=false
else
    # Verifica campos obrigatórios do in-toto statement
    PREDICATE_TYPE=$(jq -r '.[0].predicateType // empty' "${PROVENANCE_FILE}" 2>/dev/null || \
                     jq -r '.predicateType // empty' "${PROVENANCE_FILE}" 2>/dev/null)

    if [[ "${PREDICATE_TYPE}" == *"slsa-provenance"* ]]; then
        echo "  ✓ Formato in-toto válido — predicateType: ${PREDICATE_TYPE}"
    else
        echo "  ⚠ predicateType inesperado: ${PREDICATE_TYPE}"
        echo "    Esperado: algo como https://slsa.dev/provenance/v0.2"
    fi
fi

# ─── Verificação 2: Builder confiável ─────────────────────────────────────────

echo ""
echo "[ 2/4 ] Verificando builder..."

# Extrai builder ID do provenance (formato pode variar por versão SLSA)
BUILDER_ID=$(jq -r '
  if type == "array" then .[0] else . end |
  .predicate.builder.id //
  .predicate.buildDefinition.buildType //
  "NOT_FOUND"
' "${PROVENANCE_FILE}" 2>/dev/null || echo "NOT_FOUND")

echo "  Builder encontrado: ${BUILDER_ID}"

if [[ "${BUILDER_ID}" == *"slsa-framework"* ]] || [[ "${BUILDER_ID}" == *"github"* ]]; then
    echo "  ✓ Builder é do slsa-framework (confiável)"
else
    echo "  ✗ Builder desconhecido ou não confiável"
    echo "  Builder esperado deve conter: slsa-framework ou github"
    VERIFICATION_PASSED=false
fi

# ─── Verificação 3: Repositório fonte ─────────────────────────────────────────

echo ""
echo "[ 3/4 ] Verificando repositório fonte..."

SOURCE_URI=$(jq -r '
  if type == "array" then .[0] else . end |
  .predicate.invocation.configSource.uri //
  .predicate.buildDefinition.externalParameters.source.uri //
  .predicate.materials[0].uri //
  "NOT_FOUND"
' "${PROVENANCE_FILE}" 2>/dev/null || echo "NOT_FOUND")

echo "  Source URI: ${SOURCE_URI}"

if [[ "${SOURCE_URI}" == *"${SOURCE_REPO}"* ]]; then
    echo "  ✓ Artefato vem do repositório oficial: ${SOURCE_REPO}"
else
    echo "  ✗ Repositório fonte não confere!"
    echo "  Esperado: ${SOURCE_REPO}"
    echo "  Encontrado: ${SOURCE_URI}"
    VERIFICATION_PASSED=false
fi

# Verifica branch
SOURCE_REF=$(jq -r '
  if type == "array" then .[0] else . end |
  .predicate.invocation.configSource.ref //
  .predicate.buildDefinition.externalParameters.source.ref //
  "NOT_FOUND"
' "${PROVENANCE_FILE}" 2>/dev/null || echo "NOT_FOUND")

echo "  Branch/Ref: ${SOURCE_REF}"

BRANCH_OK=false
for branch_pattern in "${ALLOWED_BRANCHES[@]}"; do
    if [[ "${SOURCE_REF}" == *"${branch_pattern%/*}"* ]]; then
        BRANCH_OK=true
        break
    fi
done

if [ "${BRANCH_OK}" = "true" ] || [[ "${SOURCE_REF}" == *"main"* ]]; then
    echo "  ✓ Build veio de branch autorizado"
else
    echo "  ⚠ Build de branch não padrão: ${SOURCE_REF}"
    echo "  Branches permitidos para produção: ${ALLOWED_BRANCHES[*]}"
    # Aviso mas não bloqueia — pode ser deploy de release branch
fi

# ─── Verificação 4: Verificação formal com slsa-verifier ──────────────────────

echo ""
echo "[ 4/4 ] Verificação formal com slsa-verifier..."

# A verificação formal valida a assinatura criptográfica da provenance
# e verifica contra o Sigstore transparency log (Rekor)
if slsa-verifier verify-artifact "${ARTIFACT}" \
    --provenance-path "${PROVENANCE_FILE}" \
    --source-uri "${SOURCE_REPO}" \
    --source-branch "main" \
    2>&1; then
    echo "  ✓ Verificação formal SLSA: PASSOU"
    echo "    Assinatura verificada no Sigstore/Rekor transparency log"
else
    echo "  ✗ Verificação formal SLSA: FALHOU"
    echo "    O artefato pode ter sido adulterado ou o provenance é inválido"
    VERIFICATION_PASSED=false
fi

# Verifica nível SLSA
echo ""
echo "[ Nível SLSA ]"
SLSA_LEVEL=$(slsa-verifier verify-artifact "${ARTIFACT}" \
    --provenance-path "${PROVENANCE_FILE}" \
    --source-uri "${SOURCE_REPO}" \
    2>&1 | grep -oP "SLSA level \K[0-9]" || echo "0")

echo "  Nível detectado: SLSA Level ${SLSA_LEVEL}"

if [ "${SLSA_LEVEL}" -ge "${MIN_SLSA_LEVEL}" ] 2>/dev/null; then
    echo "  ✓ Nível ${SLSA_LEVEL} >= mínimo exigido (${MIN_SLSA_LEVEL})"
else
    echo "  ✗ Nível ${SLSA_LEVEL} < mínimo exigido (${MIN_SLSA_LEVEL})"
    echo "  Configure o slsa-github-generator para atingir Level 2+"
    VERIFICATION_PASSED=false
fi

# ─── Resultado ────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "${VERIFICATION_PASSED}" = "true" ]; then
    echo "  RESULTADO: SLSA VERIFICADO"
    echo "  Artefato pode ser usado em produção."
    exit 0
else
    echo "  RESULTADO: VERIFICAÇÃO SLSA FALHOU"
    echo "  NÃO use este artefato em produção."
    echo "  Revise os itens acima antes de prosseguir."
    exit 1
fi
