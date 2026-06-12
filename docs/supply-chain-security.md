# Supply Chain Security

Guia de segurança da cadeia de suprimentos de software implementada neste projeto.

## O que é supply chain security?

Nos últimos anos, ataques à cadeia de suprimentos de software se tornaram um dos vetores mais eficazes para comprometer sistemas em larga escala. Em vez de atacar diretamente o alvo, os atacantes comprometem uma dependência ou ferramenta que o alvo usa — e ganham acesso a todos os usuários daquela dependência.

Exemplos reais:
- **SolarWinds (2020):** build pipeline comprometido, malware inserido nas atualizações
- **event-stream (2018):** pacote npm populár com maintainer malicioso
- **XZ Utils (2024):** backdoor inserido por contribuidor que ganhou confiança ao longo de 2 anos
- **Log4Shell (2021):** vulnerabilidade crítica em biblioteca usada em milhares de projetos

A pergunta que a supply chain security responde: **"Como você sabe que o software que está rodando é exatamente o que foi escrito pelos desenvolvedores?"**

## SBOMs — Software Bill of Materials

### O que é?

SBOM é um inventário completo de todos os componentes de software — bibliotecas, dependências, versões — que fazem parte de um aplicativo. É o equivalente à lista de ingredientes de um produto alimentício.

### Por que usar?

1. **Visibilidade:** saber exatamente o que está rodando
2. **Resposta a incidentes:** quando uma vulnerabilidade é descoberta (ex: Log4Shell), identifica em minutos se seu software está afetado
3. **Compliance:** EU Cyber Resilience Act (CRA) e Executive Order 14028 dos EUA exigem SBOMs para software governamental
4. **Auditoria:** evidência de que o inventário foi verificado

### Formatos suportados

Este projeto gera SBOMs em 3 formatos:

| Formato | Padrão | Uso principal |
|---|---|---|
| SPDX-JSON | ISO/IEC 5962:2021 | Compliance e auditoria formal |
| CycloneDX-JSON | OWASP | Análise de vulnerabilidades (Grype) |
| CycloneDX-XML | OWASP | Integração com ferramentas legadas |

### Como gerar

```bash
cd security/sbom/
chmod +x generate-sbom.sh
./generate-sbom.sh ../../app

# Output em sbom-output/<timestamp>/
# - sbom.spdx.json
# - sbom.cyclonedx.json
# - sbom.cyclonedx.xml
# - vulnerabilities.json (análise Grype)
# - licenses-summary.json
```

### Como verificar

```bash
./verify-sbom.sh sbom-output/<timestamp>/sbom.spdx.json
```

O script verifica:
1. JSON válido e não corrompido
2. Estrutura SPDX correta
3. Componentes presentes (SBOM não vazio)
4. Hash SHA256 confere com o gerado
5. Assinatura Cosign válida (se presente)

### Assinatura com Cosign

O SBOM é assinado digitalmente com Cosign usando keyless signing via OIDC:

```bash
# Em CI/CD (GitHub Actions) — sem chave privada para guardar
cosign sign-blob --yes sbom.spdx.json \
  --output-signature sbom.spdx.json.sig \
  --output-certificate sbom.spdx.json.crt

# Verificação — qualquer pessoa pode verificar sem ter a chave
cosign verify-blob sbom.spdx.json \
  --signature sbom.spdx.json.sig \
  --certificate sbom.spdx.json.crt \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/leandroninja/.*"
```

A verificação pode ser feita por qualquer pessoa com o SBOM + signature + certificate — sem precisar da chave privada. A validade é verificada contra o Sigstore/Rekor transparency log.

## SLSA — Supply chain Levels for Software Artifacts

### O que é?

SLSA (pronuncia-se "salsa") é um framework da OpenSSF que define níveis de garantia para a integridade de artefatos de software — do processo de build ao artefato final.

### Níveis SLSA

| Nível | Requisitos |
|---|---|
| SLSA 1 | Provenance gerada (mas não verificada) |
| SLSA 2 | Provenance gerada por CI/CD, assinada pelo builder |
| SLSA 3 | Builder hardened, isolamento de build, provenance verificável end-to-end |
| SLSA 4 | (descontinuado no SLSA v1.0 — fundido com L3) |

**Este projeto implementa SLSA Level 2** — o mínimo para uso em produção.

### Como funciona a provenance

```
1. GitHub Actions executa o build
          │
          ▼
2. slsa-github-generator gera o provenance:
   {
     "builder": "https://github.com/slsa-framework/slsa-github-generator/...",
     "source": "git+https://github.com/leandroninja/zero-trust-devsecops-supply-chain",
     "branch": "refs/heads/main",
     "commit": "abc123...",
     "artifact_hash": "sha256:def456..."
   }
          │
          ▼
3. Provenance é assinada pelo builder (não pelo desenvolvedor)
   e publicada no Rekor transparency log
          │
          ▼
4. Verificação:
   slsa-verifier verify-artifact app.tar.gz \
     --provenance-path provenance.intoto.jsonl \
     --source-uri github.com/leandroninja/zero-trust-...
```

### O que a provenance garante?

- O artefato foi construído pelo GitHub Actions (não em máquina local)
- O build veio do repositório oficial, do branch correto
- O código-fonte corresponde ao commit declarado (hash verificável)
- O build não foi adulterado após a publicação (Rekor log imutável)

### Verificação

```bash
chmod +x security/slsa/slsa-verification.sh
./security/slsa/slsa-verification.sh app.tar.gz provenance.intoto.jsonl
```

## Como verificar a integridade de dependências

Além do SBOM do projeto, é importante verificar a integridade das próprias dependências.

### Python (pip)

```bash
# Gera hash das dependências instaladas
pip hash requirements.txt

# Instala verificando hashes (pip vai recusar pacotes com hash diferente)
pip install --require-hashes -r requirements.txt
```

Para usar `--require-hashes`, o `requirements.txt` precisa ter os hashes:

```
fastapi==0.110.0 \
    --hash=sha256:abc123... \
    --hash=sha256:def456...
```

Gerar com: `pip-compile --generate-hashes requirements.in`

### Verificação com Grype

```bash
# Verifica vulnerabilidades no SBOM gerado
grype sbom:sbom.cyclonedx.json

# Verifica uma imagem Docker
grype docker:zero-trust-app:1.0.0

# Verifica um diretório
grype dir:./app
```

### Scorecard OpenSSF

O OpenSSF Scorecard avalia práticas de segurança de projetos open source:

```bash
# Verifica score de uma dependência antes de usar
scorecard --repo github.com/fastapi/fastapi

# Campos importantes:
# - Branch-Protection: branch principal protegida?
# - CI-Tests: tem testes automatizados?
# - Maintained: projeto ativo?
# - Vulnerabilities: vulnerabilidades abertas?
# - Signed-Releases: releases assinadas?
```

Score < 3: cuidado extra antes de usar. Score < 2: evitar se possível.

## Compliance com EU Cyber Resilience Act (CRA)

O Cyber Resilience Act europeu (CRA), aprovado em 2024, exige que produtos com elementos digitais incluam SBOMs e atendam a requisitos mínimos de segurança.

**O que o CRA exige (artigo 13):**

1. SBOM disponível para autoridades de mercado
2. Vulnerabilidades conhecidas devem ser reportadas em 24h
3. Patches de segurança devem ser distribuídos sem custo
4. Documentação de segurança deve acompanhar o produto

**O que este projeto implementa:**

- SBOM gerado em formato SPDX (padrão aceito pelo CRA)
- Pipeline automatizada de scan de vulnerabilidades (Trivy + Grype)
- Processo de license compliance (LFC191)
- SLSA provenance para rastreabilidade de origem

## Pipeline completa de supply chain security

```
git push
     │
     ▼
1. Secret scan (Gitleaks)
     │
     ▼
2. SAST (Semgrep)
     │
     ▼
3. Dependency review (actions/dependency-review-action)
     │   └── bloqueia nova dependência com CVE alto ou licença proibida
     │
     ▼
4. SBOM gerado (Syft — SPDX + CycloneDX)
     │   └── assinado com Cosign
     │
     ▼
5. License compliance (pip-licenses)
     │   └── bloqueia GPL/AGPL/SSPL
     │
     ▼
6. Container build + scan (Trivy)
     │   └── bloqueia se CRITICAL não mitigado
     │
     ▼
7. SLSA provenance gerada
     │
     ▼
8. OPA policy check
     │
     ▼
9. DAST (OWASP ZAP)
     │
     ▼
10. Zero Trust Gate — verifica todos os checks
     │
     ▼
11. Deploy (somente se gate passou)
```

## Referências

- [LFEL1007 — Automating Supply Chain Security](https://training.linuxfoundation.org/training/automating-supply-chain-security-sboms-and-signatures-lfel1007/)
- [LFC191 — Open Source Licensing Basics](https://training.linuxfoundation.org/training/open-source-licensing-basics-for-software-developers-lfc191/)
- [SLSA Framework](https://slsa.dev/)
- [SPDX Specification](https://spdx.github.io/spdx-spec/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [Sigstore / Cosign](https://www.sigstore.dev/)
- [EU Cyber Resilience Act](https://www.europarl.europa.eu/news/en/press-room/20231218IPR20138)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
