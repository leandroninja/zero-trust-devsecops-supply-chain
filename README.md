# zero-trust-devsecops-supply-chain

Pipeline DevSecOps completa com arquitetura Zero Trust e supply chain security — do código ao deploy com cada camada de segurança verificada e auditada.

> Projeto de portfólio demonstrando conceitos práticos de: Zero Trust (LFS183), Supply Chain Security / SBOMs (LFEL1007), Open Source Licensing (LFC191), Security for SDMs (LFD125), Cybersecurity Essentials (LFC108), Fortinet NSE Associate + Fundamentals, Authentication & Authorization (LFEL1004) e Security Self-Assessments (LFEL1005).

---

## Visão Geral

Este repositório implementa uma pipeline de segurança ponta a ponta. Cada artefato gerado — código, imagem, dependências — passa por múltiplas camadas de verificação antes de chegar ao ambiente de produção. O princípio base é simples: **nada é confiável por padrão**.

A ideia veio da necessidade real de times DevOps que precisam mostrar compliance sem travar o deploy. Aqui cada job da pipeline tem um motivo, não é segurança por segurança.

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PIPELINE DEVSECOPS                                  │
│                                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────────────────┐  │
│  │  Código  │───▶│   SAST   │───▶│   SBOM   │───▶│  License Compliance  │  │
│  │  (Git)   │    │ Semgrep  │    │  Syft    │    │  pip-licenses / FOSS │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────────────────┘  │
│                       │               │                      │              │
│                       ▼               ▼                      ▼              │
│                  ┌─────────┐   ┌──────────┐         ┌───────────────┐      │
│                  │  SARIF  │   │ CycloneDX│         │  Bloqueia GPL │      │
│                  │ GitHub  │   │ SPDX-JSON│         │  não aprovada │      │
│                  │Security │   └──────────┘         └───────────────┘      │
│                  └─────────┘         │                                      │
│                                      ▼                                      │
│              ┌───────────────────────────────────────────┐                  │
│              │           Container Security               │                  │
│              │  docker build → Trivy scan → SBOM imagem  │                  │
│              └───────────────────────────────────────────┘                  │
│                                      │                                      │
│                       ┌──────────────┼──────────────┐                       │
│                       ▼              ▼               ▼                      │
│                ┌────────────┐ ┌──────────┐  ┌──────────────┐               │
│                │    SLSA    │ │   OPA    │  │     DAST     │               │
│                │ Provenance │ │ Policies │  │  OWASP ZAP   │               │
│                │  Level 2   │ │ conftest │  │   staging    │               │
│                └────────────┘ └──────────┘  └──────────────┘               │
│                       │              │               │                      │
│                       └──────────────┴───────────────┘                     │
│                                      │                                      │
│                                      ▼                                      │
│                        ┌─────────────────────────┐                          │
│                        │    Zero Trust Gate       │                          │
│                        │  Todos os checks OK?     │                          │
│                        │  SBOM presente?          │                          │
│                        │  SLSA attestation?       │                          │
│                        │  Sem CRITICAL aberto?    │                          │
│                        └─────────────────────────┘                          │
│                                      │                                      │
│                          ┌───────────┴──────────┐                           │
│                          │ SIM                  │ NÃO → ❌ Bloqueado         │
│                          ▼                                                   │
│                   ┌─────────────┐                                            │
│                   │   Deploy    │                                            │
│                   │ Kubernetes  │                                            │
│                   │ Zero Trust  │                                            │
│                   │  Network    │                                            │
│                   └─────────────┘                                            │
│                          │                                                   │
│           ┌──────────────┼──────────────────────┐                           │
│           ▼              ▼                       ▼                          │
│    ┌─────────────┐ ┌──────────────┐    ┌────────────────┐                  │
│    │NetworkPolicy│ │ Istio mTLS   │    │  SPIFFE/SPIRE  │                  │
│    │ default deny│ │ STRICT mode  │    │  Workload ID   │                  │
│    └─────────────┘ └──────────────┘    └────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Componentes

### Zero Trust Network

Implementado em três camadas independentes que se complementam:

| Componente | Tecnologia | O que faz |
|---|---|---|
| Network Policies | Kubernetes | Default deny-all, libera só o necessário |
| mTLS | Istio STRICT | Toda comunicação pod-a-pod precisa de certificado |
| Identity | SPIFFE/SPIRE | Identidade criptográfica para cada workload |
| RBAC | Kubernetes | Permissão mínima por service account |

Arquivos em `zero-trust/`.

### Supply Chain Security (SBOMs)

```
Código → Syft → SBOM (SPDX + CycloneDX) → Grype → Vulnerabilidades
                                         → License Checker → Compliance
                                         → Cosign → Assinatura digital
```

- **SBOM gerado em 3 formatos**: SPDX-JSON, CycloneDX-JSON, CycloneDX-XML
- **Assinado com Cosign** — verificável sem acesso ao repositório original
- **SLSA Level 2** — provenance gerada pelo GitHub Actions com builder verificável

Scripts em `security/sbom/`, workflow em `.github/workflows/devsecops-pipeline.yml`.

### OPA Policies (Open Policy Agent)

10+ regras Rego cobrindo:
- Containers privilegiados bloqueados
- Root user bloqueado (runAsNonRoot obrigatório)
- Tags `:latest` bloqueadas em produção
- Resource limits obrigatórios
- hostNetwork e hostPID bloqueados
- allowPrivilegeEscalation: false obrigatório
- readOnlyRootFilesystem obrigatório

Políticas em `security/opa-policies/`.

### Fortinet Policies

Baseadas nos conceitos do Fortinet NSE:
- Zonas de segurança: DMZ / Internal / External
- Inspeção SSL/TLS com certificate pinning
- IPS policies mapeadas para OWASP Top 10
- Web filtering e application control

Configurações em `security/fortinet/`.

### Análise de Licenças

Política definida em `security/supply-chain/license-policy.yaml`:
- **Aprovadas**: MIT, Apache-2.0, BSD-2/3-Clause, ISC
- **Requer revisão manual**: LGPL-2.1, LGPL-3.0, MPL-2.0
- **Bloqueadas automaticamente**: GPL-2.0, GPL-3.0, AGPL-3.0, SSPL

### Infraestrutura (Terraform)

AKS privado no Azure com:
- Key Vault para secrets
- Microsoft Defender for Cloud ativado
- Policies de compliance (CIS AKS Benchmark)
- Private Link para acesso ao cluster

---

## Como usar

### Pré-requisitos

```bash
# Ferramentas necessárias
syft --version       # >= 0.90
grype --version      # >= 0.70
cosign version       # >= 2.0
conftest --version   # >= 0.45
slsa-verifier version
```

### Gerar SBOM localmente

```bash
cd security/sbom/
chmod +x generate-sbom.sh
./generate-sbom.sh ./../../app
# Output em sbom-output/<timestamp>/
```

### Verificar SBOM

```bash
./verify-sbom.sh sbom-output/<timestamp>/app-sbom.spdx.json
```

### Verificar SLSA provenance

```bash
chmod +x security/slsa/slsa-verification.sh
./security/slsa/slsa-verification.sh <artifact> <provenance-file>
```

### Testar OPA policies localmente

```bash
# Instalar conftest
conftest test k8s/deployment.yaml --policy security/opa-policies/
```

### Aplicar Zero Trust no cluster

```bash
# Ordem importa: primeiro deny-all, depois libera seletivo
kubectl apply -f zero-trust/network-policies/default-deny.yaml
kubectl apply -f zero-trust/network-policies/allow-dns.yaml
kubectl apply -f zero-trust/network-policies/app-policies.yaml

# mTLS
kubectl apply -f zero-trust/mtls/peer-authentication.yaml
kubectl apply -f zero-trust/mtls/authorization-policy.yaml

# RBAC
kubectl apply -f zero-trust/rbac/rbac-policies.yaml
```

---

## Documentação

- [Arquitetura Zero Trust](docs/zero-trust-architecture.md) — princípios e implementação por camada
- [Supply Chain Security](docs/supply-chain-security.md) — SBOMs, SLSA, verificação de integridade
- [Checklist de Compliance](docs/compliance-checklist.md) — CIS Benchmark, NIST CSF, OWASP Top 10

---

## Certificações e cursos que embasam este projeto

| Certificação / Curso | Área aplicada |
|---|---|
| LFS183 — Zero Trust | `zero-trust/` — network policies, mTLS, SPIFFE |
| LFEL1007 — Supply Chain Security | `security/sbom/`, SBOMs, SLSA provenance |
| LFC191 — Open Source Licensing | `security/supply-chain/license-policy.yaml` |
| LFD125 — Security for SDMs | pipeline gates, compliance docs |
| LFC108 — Cybersecurity Essentials | threat model, Fortinet policies |
| Fortinet NSE Associate + Fundamentals | `security/fortinet/` |
| LFEL1004 — Auth & AuthZ Web/API | `security/auth/`, JWT/OAuth2, mTLS |
| LFEL1005 — Security Self-Assessments | `docs/compliance-checklist.md` |

---

## Autor

**Leandro Oliveira Moraes**
Arquiteto Sênior DevOps & Multi-Cloud

GitHub: [leandroninja](https://github.com/leandroninja)

---

_Projeto de portfólio. Feedback e sugestões são bem-vindos via issues._
