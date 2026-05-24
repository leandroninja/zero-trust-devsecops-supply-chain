#!/bin/bash
# verify-sbom.sh
#
# Verifica a integridade e autenticidade de um SBOM gerado pelo generate-sbom.sh.
# Checks realizados:
#   1. Hash SHA256 — arquivo não foi modificado
#   2. Assinatura Cosign — veio de um pipeline autorizado
#   3. Formato SPDX válido — estrutura correta
#   4. Componentes presentes — não está vazio
#
# Uso:
#   ./verify-sbom.sh <caminho-do-sbom.spdx.json> [--signature <sig-file>] [--cert <cert-file>]
#
# Exemplos:
#   ./verify-sbom.sh sbom-output/20240101_120000/sbom.spdx.json
#   ./verify-sbom.sh sbom.spdx.json --signature sbom.spdx.json.sig --cert sbom.spdx.json.crt
#
# Referência: LFEL1007 — Automating Supply Chain Security

set -euo pipefail

# ─── Argumentos ────────────────────────────────────────────────────────────────

SBOM_FILE="${1:-}"
SIGNATURE_FILE="${2:-}"
CERT_FILE="${3:-}"

if [ -z "${SBOM_FILE}" ]; then
    echo "Uso: ./verify-sbom.sh <sbom.spdx.json> [signature] [cert]"
    exit 1
fi

if [ ! -f "${SBOM_FILE}" ]; then
    echo "✗ Arquivo não encontrado: ${SBOM_FILE}"
    exit 1
fi

# Detecta automaticamente arquivos de assinatura/cert se não fornecidos
if [ -z "${SIGNATURE_FILE}" ] && [ -f "${SBOM_FILE}.sig" ]; then
    SIGNATURE_FILE="${SBOM_FILE}.sig"
fi

if [ -z "${CERT_FILE}" ] && [ -f "${SBOM_FILE}.crt" ]; then
    CERT_FILE="${SBOM_FILE}.crt"
fi

# ─── Resultado acumulado ───────────────────────────────────────────────────────

CHECKS_PASSED=0
CHECKS_FAILED=0
WARNINGS=0

pass_check() {
    echo "  ✓ $1"
    ((CHECKS_PASSED++))
}

fail_check() {
    echo "  ✗ $1"
    ((CHECKS_FAILED++))
}

warn_check() {
    echo "  ⚠ $1"
    ((WARNINGS++))
}

# ─── Verificação 1: Arquivo existe e tem conteúdo ─────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SBOM Verification"
echo "  Arquivo: ${SBOM_FILE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "[ Check 1: Integridade do arquivo ]"

FILE_SIZE=$(wc -c < "${SBOM_FILE}")
if [ "${FILE_SIZE}" -gt 100 ]; then
    pass_check "Arquivo presente e não vazio (${FILE_SIZE} bytes)"
else
    fail_check "Arquivo muito pequeno (${FILE_SIZE} bytes) — suspeito de estar corrompido ou vazio"
fi

# ─── Verificação 2: JSON válido ────────────────────────────────────────────────

echo ""
echo "[ Check 2: Formato JSON ]"

if jq empty "${SBOM_FILE}" 2>/dev/null; then
    pass_check "JSON válido"
else
    fail_check "Arquivo não é um JSON válido — corrompido ou formato incorreto"
    echo ""
    echo "FALHA: SBOM inválido — abortando verificação"
    exit 1
fi

# ─── Verificação 3: Estrutura SPDX ────────────────────────────────────────────

echo ""
echo "[ Check 3: Estrutura SPDX ]"

SPDX_VERSION=$(jq -r '.spdxVersion // empty' "${SBOM_FILE}")
DOC_NAMESPACE=$(jq -r '.documentNamespace // empty' "${SBOM_FILE}")
CREATION_INFO=$(jq -r '.creationInfo // empty' "${SBOM_FILE}")

if [ -n "${SPDX_VERSION}" ]; then
    pass_check "Versão SPDX encontrada: ${SPDX_VERSION}"
else
    fail_check "Campo spdxVersion ausente — não parece ser um SBOM SPDX válido"
fi

if [ -n "${DOC_NAMESPACE}" ]; then
    pass_check "documentNamespace presente: ${DOC_NAMESPACE}"
else
    warn_check "documentNamespace ausente — SPDX spec exige este campo"
fi

if [ -n "${CREATION_INFO}" ]; then
    CREATOR=$(jq -r '.creationInfo.creators[0] // "desconhecido"' "${SBOM_FILE}")
    CREATED=$(jq -r '.creationInfo.created // "desconhecido"' "${SBOM_FILE}")
    pass_check "creationInfo presente — criado por: ${CREATOR} em ${CREATED}"
else
    fail_check "creationInfo ausente — não é possível verificar origem do SBOM"
fi

# ─── Verificação 4: Componentes/Pacotes ───────────────────────────────────────

echo ""
echo "[ Check 4: Conteúdo do SBOM ]"

PACKAGE_COUNT=$(jq '.packages | length' "${SBOM_FILE}" 2>/dev/null || echo "0")

if [ "${PACKAGE_COUNT}" -gt 0 ]; then
    pass_check "SBOM contém ${PACKAGE_COUNT} pacotes"

    # Verifica se os pacotes têm informações mínimas
    PACKAGES_WITH_LICENSE=$(jq '[.packages[] | select(.licenseDeclared != "NOASSERTION" and .licenseDeclared != null)] | length' "${SBOM_FILE}")
    PACKAGES_WITHOUT_LICENSE=$((PACKAGE_COUNT - PACKAGES_WITH_LICENSE))

    if [ "${PACKAGES_WITHOUT_LICENSE}" -gt 0 ]; then
        warn_check "${PACKAGES_WITHOUT_LICENSE} pacote(s) sem licença declarada (NOASSERTION)"
    else
        pass_check "Todos os pacotes têm licença declarada"
    fi

    # Lista os 5 primeiros pacotes como amostra
    echo ""
    echo "  Amostra de pacotes (primeiros 5):"
    jq -r '.packages[:5] | .[] | "    \(.name) \(.versionInfo // "?") — \(.licenseDeclared // "sem licença")"' "${SBOM_FILE}"

else
    fail_check "SBOM sem pacotes — provavelmente erro na geração"
fi

# ─── Verificação 5: Checksum (se existir) ─────────────────────────────────────

echo ""
echo "[ Check 5: Checksum SHA256 ]"

CHECKSUM_FILE="$(dirname "${SBOM_FILE}")/sbom-checksums.sha256"
if [ -f "${CHECKSUM_FILE}" ]; then
    if sha256sum --check --quiet <(grep "$(basename "${SBOM_FILE}")" "${CHECKSUM_FILE}") 2>/dev/null; then
        pass_check "Hash SHA256 verificado — arquivo íntegro"
    else
        fail_check "Hash SHA256 não confere — arquivo pode ter sido modificado após geração!"
    fi
else
    warn_check "Arquivo de checksums não encontrado em ${CHECKSUM_FILE} — pulando verificação de hash"
fi

# ─── Verificação 6: Assinatura Cosign ─────────────────────────────────────────

echo ""
echo "[ Check 6: Assinatura Digital (Cosign) ]"

if [ -n "${SIGNATURE_FILE}" ] && [ -f "${SIGNATURE_FILE}" ]; then
    if command -v cosign &> /dev/null; then
        if [ -n "${CERT_FILE}" ] && [ -f "${CERT_FILE}" ]; then
            # Verifica com certificado (keyless flow)
            if cosign verify-blob \
                --signature "${SIGNATURE_FILE}" \
                --certificate "${CERT_FILE}" \
                --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                --certificate-identity-regexp "https://github.com/leandroninja/zero-trust-devsecops-supply-chain" \
                "${SBOM_FILE}" 2>/dev/null; then
                pass_check "Assinatura Cosign verificada — SBOM veio do pipeline oficial"
            else
                fail_check "Assinatura Cosign INVÁLIDA — SBOM pode ter sido adulterado ou vem de pipeline não autorizado!"
            fi
        else
            warn_check "Certificado não fornecido — verificação de assinatura incompleta"
        fi
    else
        warn_check "cosign não instalado — não foi possível verificar assinatura"
    fi
else
    warn_check "Arquivo de assinatura não encontrado — SBOM não assinado ou assinatura separada"
    warn_check "Para assinar: cosign sign-blob --yes ${SBOM_FILE} --output-signature ${SBOM_FILE}.sig"
fi

# ─── Resultado final ───────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Resultado da Verificação"
echo "  ✓ Checks passaram: ${CHECKS_PASSED}"
echo "  ✗ Checks falharam: ${CHECKS_FAILED}"
echo "  ⚠ Avisos: ${WARNINGS}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "${CHECKS_FAILED}" -gt 0 ]; then
    echo ""
    echo "  RESULTADO: FALHOU — SBOM não passou na verificação"
    echo "  Não use este SBOM para decisões de deploy."
    exit 1
else
    echo ""
    echo "  RESULTADO: OK — SBOM verificado com sucesso"
    exit 0
fi
