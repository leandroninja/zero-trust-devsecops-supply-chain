package pipeline.gates

# Pipeline Gates — OPA
#
# Verifica pré-condições antes de autorizar o deploy.
# Cada gate é uma condição binária: passou ou não passou.
# Se qualquer gate falhar, o deploy é bloqueado no zero-trust-gate job.
#
# Input esperado: JSON com resultado dos scans (trivy, sbom, licenças, slsa)
# Formato de input: ver security/sbom/generate-sbom.sh para estrutura

import future.keywords.in
import future.keywords.if

# ─── Gate 1: SBOM deve estar presente ────────────────────────────────────────

deny[msg] {
	# Verifica se o campo sbom_generated existe e é true
	not input.sbom.generated == true

	msg := "GATE BLOQUEADO: SBOM não foi gerado para este artefato. Execute a geração de SBOM antes do deploy."
}

deny[msg] {
	# SBOM gerado mas sem componentes listados
	input.sbom.generated == true
	count(input.sbom.components) == 0

	msg := "GATE BLOQUEADO: SBOM foi gerado mas não contém componentes. SBOM vazio é suspeito — verifique a geração."
}

deny[msg] {
	# SBOM não tem assinatura digital
	input.sbom.generated == true
	not input.sbom.signed == true

	msg := "GATE BLOQUEADO: SBOM presente mas sem assinatura digital. Assine com cosign antes do deploy para garantir integridade."
}

# ─── Gate 2: Sem CRITICAL não mitigado (Trivy) ───────────────────────────────

deny[msg] {
	vuln := input.trivy.vulnerabilities[_]
	vuln.severity == "CRITICAL"
	not vuln.mitigated == true
	not vuln.accepted_risk == true

	msg := sprintf(
		"GATE BLOQUEADO: Vulnerabilidade CRITICAL não mitigada — %s em %s@%s. Corrija ou documente a aceitação de risco antes do deploy.",
		[vuln.id, vuln.package, vuln.version]
	)
}

# Gate específico para contagem de criticals (sumário)
deny[msg] {
	criticals := [v | v := input.trivy.vulnerabilities[_]; v.severity == "CRITICAL"; not v.mitigated]
	count(criticals) > 0

	msg := sprintf(
		"GATE BLOQUEADO: %d vulnerabilidade(s) CRITICAL sem mitigação documentada.",
		[count(criticals)]
	)
}

# Aviso (não bloqueia) para HIGH vulnerabilities
warn[msg] {
	highs := [v | v := input.trivy.vulnerabilities[_]; v.severity == "HIGH"; not v.mitigated]
	count(highs) > 0

	msg := sprintf(
		"AVISO: %d vulnerabilidade(s) HIGH encontradas. Não bloqueiam o deploy mas devem ser corrigidas em breve.",
		[count(highs)]
	)
}

# ─── Gate 3: Licenças incompatíveis bloqueam o deploy ─────────────────────────

# Lista de licenças explicitamente bloqueadas
blocked_licenses := {
	"GPL-2.0",
	"GPL-3.0",
	"AGPL-3.0",
	"AGPL-3.0-only",
	"AGPL-3.0-or-later",
	"GPL-2.0-only",
	"GPL-2.0-or-later",
	"GPL-3.0-only",
	"GPL-3.0-or-later",
	"SSPL-1.0",
}

deny[msg] {
	dep := input.licenses.dependencies[_]
	dep.license in blocked_licenses

	msg := sprintf(
		"GATE BLOQUEADO: Dependência '%s@%s' usa licença '%s' que é incompatível com a política de licenças do projeto.",
		[dep.name, dep.version, dep.license]
	)
}

# Dependências sem licença identificada — potencialmente problemáticas
deny[msg] {
	dep := input.licenses.dependencies[_]
	dep.license == "UNKNOWN"
	not dep.license_reviewed == true

	msg := sprintf(
		"GATE BLOQUEADO: Dependência '%s@%s' tem licença desconhecida e não foi revisada. Identifique a licença antes do deploy.",
		[dep.name, dep.version]
	)
}

# Aviso para licenças que precisam de revisão (não bloqueiam)
warn[msg] {
	review_licenses := {"LGPL-2.1", "LGPL-3.0", "MPL-2.0", "CDDL-1.0", "EPL-1.0", "EPL-2.0"}
	dep := input.licenses.dependencies[_]
	dep.license in review_licenses
	not dep.approved == true

	msg := sprintf(
		"AVISO: Dependência '%s@%s' usa licença '%s' que requer revisão jurídica antes de uso em produção.",
		[dep.name, dep.version, dep.license]
	)
}

# ─── Gate 4: SLSA Attestation deve estar presente ────────────────────────────

deny[msg] {
	not input.slsa.attestation_present == true

	msg := "GATE BLOQUEADO: SLSA provenance não encontrada para este artefato. Gere a attestation antes do deploy."
}

deny[msg] {
	input.slsa.attestation_present == true
	input.slsa.level < 2

	msg := sprintf(
		"GATE BLOQUEADO: SLSA level %d encontrado mas o mínimo exigido é level 2. Verifique o processo de build.",
		[input.slsa.level]
	)
}

deny[msg] {
	input.slsa.attestation_present == true
	# Verifica se o builder é o GitHub Actions (builder confiável)
	not startswith(input.slsa.builder_id, "https://github.com/slsa-framework/slsa-github-generator")

	msg := sprintf(
		"GATE BLOQUEADO: Builder '%s' não é um builder confiável para SLSA. Use o slsa-github-generator oficial.",
		[input.slsa.builder_id]
	)
}

# ─── Gate 5: Source repo deve ser o oficial ──────────────────────────────────

deny[msg] {
	# Verifica que o build veio do repositório correto (não de um fork não autorizado)
	input.slsa.attestation_present == true
	not startswith(input.slsa.source_uri, "git+https://github.com/leandroninja/zero-trust-devsecops-supply-chain")

	msg := sprintf(
		"GATE BLOQUEADO: Artefato veio do repositório '%s' que não é o repositório oficial do projeto.",
		[input.slsa.source_uri]
	)
}

# ─── Resumo ───────────────────────────────────────────────────────────────────

# Retorna true se todos os gates passaram
all_gates_passed {
	count(deny) == 0
}

# Mensagem de resumo
summary := msg {
	all_gates_passed
	msg := "TODOS OS GATES PASSARAM — Deploy autorizado"
} else := msg {
	msg := sprintf("DEPLOY BLOQUEADO — %d gate(s) falharam", [count(deny)])
}
