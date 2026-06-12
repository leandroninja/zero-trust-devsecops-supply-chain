# Checklist de Compliance

Mapeamento de controles implementados neste projeto contra frameworks de segurança reconhecidos.

**Legenda:**
- Implementado: controle presente e ativo no projeto
- Parcial: controle implementado mas não cobrindo 100% dos casos
- Não se aplica: fora do escopo deste projeto de demonstração

---

## CIS Kubernetes Benchmark v1.8

### 1. Control Plane Components
Não se aplica — gerenciado pelo AKS (Azure gerencia o control plane).

### 2. Etcd
Não se aplica — gerenciado pelo AKS com criptografia em repouso por padrão.

### 3. Control Plane Configuration
Não se aplica — gerenciado pelo AKS.

### 4. Worker Nodes

| ID | Controle | Status | Onde |
|---|---|---|---|
| 4.1.1 | ServiceAccount tokens sem montagem automática | Implementado | `zero-trust/rbac/rbac-policies.yaml` — `automountServiceAccountToken: false` |
| 4.1.2 | ServiceAccount não deve ter permissões desnecessárias | Implementado | Roles com least-privilege |
| 4.1.3 | Cluster roles não devem ter wildcards | Implementado | Roles especificam recursos e verbos |
| 4.2.1 | PodSecurity Admission configurado | Parcial | NetworkPolicies + OPA em vez de PSA |
| 4.2.2 | Sem containers privilegiados | Implementado | OPA policy `deny_privileged_containers` |
| 4.2.3 | Sem containers como root | Implementado | OPA policy `deny_root_user` + Deployment securityContext |
| 4.2.4 | Sem hostNetwork | Implementado | OPA policy `deny_host_network` + Deployment `hostNetwork: false` |
| 4.2.5 | Sem hostPID | Implementado | OPA policy `deny_host_pid` + Deployment `hostPID: false` |
| 4.2.6 | allowPrivilegeEscalation: false | Implementado | OPA policy + Deployment securityContext |
| 4.2.7 | readOnlyRootFilesystem | Implementado | OPA policy + Deployment securityContext |

### 5. Policies

| ID | Controle | Status | Onde |
|---|---|---|---|
| 5.1.1 | RBAC ativo | Implementado | AKS habilita por padrão |
| 5.1.2 | Minimize uso de secrets no Kubernetes | Implementado | External Secrets via Key Vault |
| 5.1.3 | Minimize wildcards em roles | Implementado | Roles com resourceNames específicos |
| 5.1.5 | Default service accounts sem permissões | Implementado | Sem roles ligadas ao default SA |
| 5.2.2 | Minimize containers privilegiados | Implementado | OPA deny |
| 5.2.3 | Minimize containers como root | Implementado | OPA deny |
| 5.2.4 | Minimize HostPID | Implementado | OPA deny |
| 5.2.5 | Minimize HostNetwork | Implementado | OPA deny |
| 5.2.7 | Minimize allowPrivilegeEscalation | Implementado | OPA deny |
| 5.2.8 | Minimize containers com capabilities adicionais | Implementado | `capabilities.drop: ALL` |
| 5.3.1 | NetworkPolicies implementadas | Implementado | `zero-trust/network-policies/` |
| 5.3.2 | NetworkPolicies restringem ingress e egress | Implementado | default-deny + policies específicas |
| 5.4.1 | Secrets não em variáveis de ambiente simples | Implementado | secretKeyRef via Key Vault |
| 5.4.2 | Considerar external secret store | Implementado | Azure Key Vault via External Secrets Operator |
| 5.7.1 | Namespaces para isolar workloads | Implementado | namespaces production, staging, monitoring |
| 5.7.4 | Namespace default não usado | Implementado | Todos os workloads em namespaces específicos |

---

## NIST Cybersecurity Framework 2.0

### GOVERN (GV)

| Subcategoria | Controle | Status |
|---|---|---|
| GV.OC-01 | Missão e objetivos de segurança definidos | Implementado | docs/ com arquitetura e políticas |
| GV.OC-05 | Dependências identificadas | Implementado | SBOMs gerados automaticamente |
| GV.RM-01 | Riscos identificados e documentados | Parcial | `docs/compliance-checklist.md` |
| GV.SC-01 | Gestão de riscos da cadeia de suprimentos | Implementado | supply chain security pipeline completa |

### IDENTIFY (ID)

| Subcategoria | Controle | Status |
|---|---|---|
| ID.AM-01 | Inventário de hardware | Não se aplica | IaC Terraform — inventário via Azure |
| ID.AM-02 | Inventário de software | Implementado | SBOM com Syft |
| ID.AM-05 | Recursos protegidos por criticidade | Implementado | Namespaces, RBAC, NetworkPolicies |
| ID.RA-01 | Vulnerabilidades identificadas | Implementado | Trivy + Grype automatizados |
| ID.RA-05 | Ameaças, vulnerabilidades e probabilidade avaliadas | Implementado | CVSS scores no relatório Trivy |
| ID.SC-02 | Fornecedores avaliados | Implementado | Dependency review + OpenSSF Scorecard |

### PROTECT (PR)

| Subcategoria | Controle | Status |
|---|---|---|
| PR.AA-01 | Identidades gerenciadas | Implementado | SPIFFE/SPIRE + Azure AD |
| PR.AA-02 | Autenticação forte | Implementado | mTLS + JWT com RS/ES256 |
| PR.AA-03 | Usuários, serviços, hardware autenticados | Implementado | RBAC + mTLS + SPIFFE |
| PR.AA-05 | Princípio do menor privilégio | Implementado | RBAC, NetworkPolicies, securityContext |
| PR.AA-06 | Autenticação baseada em identidade | Implementado | SPIFFE SVID para workloads |
| PR.DS-01 | Dados em repouso protegidos | Implementado | Azure Key Vault, etcd criptografado |
| PR.DS-02 | Dados em trânsito protegidos | Implementado | mTLS STRICT, TLS 1.2/1.3 |
| PR.DS-10 | Integridade de dados verificada | Implementado | SBOMs + assinaturas Cosign |
| PR.IP-01 | Baseline de configuração | Implementado | OPA policies como baseline |
| PR.IP-03 | Gestão de configuração | Implementado | GitOps — tudo em código, revisado via PR |
| PR.PS-01 | Software autorizado e seguro | Implementado | SBOM + SLSA provenance |
| PR.PS-02 | Software checado por vulnerabilidades | Implementado | Trivy + Grype + Semgrep |

### DETECT (DE)

| Subcategoria | Controle | Status |
|---|---|---|
| DE.AE-01 | Baseline de atividade de rede | Implementado | NetworkPolicies definem o esperado |
| DE.AE-02 | Eventos analisados | Implementado | Log Analytics + Fortinet logs |
| DE.CM-01 | Redes monitoradas | Implementado | Istio access logs + Azure Monitor |
| DE.CM-06 | Personnel ativities monitoradas | Implementado | Kubernetes audit logs |
| DE.CM-09 | Testes de segurança realizados | Implementado | SAST + DAST na pipeline |

### RESPOND (RS)

| Subcategoria | Controle | Status |
|---|---|---|
| RS.MA-01 | Plano de resposta a incidentes | Parcial | Não criado neste projeto |
| RS.AN-03 | Análise forense suportada | Implementado | Logs imutáveis no Log Analytics |
| RS.MI-01 | Incidentes contidos | Implementado | Isolamento por NetworkPolicy e mTLS |

### RECOVER (RC)

| Subcategoria | Controle | Status |
|---|---|---|
| RC.RP-01 | Plano de recuperação | Parcial | IaC permite recriação — plano formal não criado |

---

## OWASP Top 10 — Mitigações

### A01: Broken Access Control

**Risco:** usuário acessa recursos além da sua autorização.

**Mitigações implementadas:**
- Istio AuthorizationPolicy — deny-all por padrão, allow seletivo
- JWT com scopes obrigatórios — endpoint verifica scope antes de processar
- Kubernetes RBAC — service accounts com menor privilégio
- NetworkPolicy — isolamento de rede entre tiers

### A02: Cryptographic Failures

**Risco:** dados expostos por criptografia fraca ou ausente.

**Mitigações implementadas:**
- mTLS STRICT — toda comunicação interna criptografada com TLS 1.3
- Key Vault HSM — chaves armazenadas em hardware
- JWT — apenas RS256/ES256 (rejeita HS256 e "none")
- TLS mínimo 1.2 — sem protocolos legados
- readOnlyRootFilesystem — sem escrita de dados sensíveis em disco local

### A03: Injection

**Risco:** dados não confiáveis enviados como parte de um comando ou query.

**Mitigações implementadas:**
- Semgrep SAST — detecta padrões de injection no código
- Input validation com Pydantic — tipos e formatos verificados
- Fortinet IPS — SQL injection, XSS, command injection detectados na camada de rede
- Sem uso de eval(), exec(), subprocess com input não validado na app

### A04: Insecure Design

**Risco:** ausência de controles de segurança no design.

**Mitigações implementadas:**
- Zero Trust by design — segurança em todas as camadas
- Checkov — valida IaC para problemas de design
- OPA policies — enforça padrões de segurança nos workloads

### A05: Security Misconfiguration

**Risco:** configurações padrão inseguras, portas abertas, permissões excessivas.

**Mitigações implementadas:**
- OPA policies bloqueiam configurações inseguras (privileged, root, latest tag)
- Hadolint valida Dockerfile contra boas práticas
- Checkov valida Terraform e Kubernetes
- seccompProfile RuntimeDefault — restringe syscalls

### A06: Vulnerable and Outdated Components

**Risco:** uso de componentes com vulnerabilidades conhecidas.

**Mitigações implementadas:**
- Trivy scan em cada build — bloqueia CRITICAL
- Grype via SBOM — análise de vulnerabilidades das dependências
- Dependency Review em PRs — detecta novas dependências vulneráveis
- Versões fixadas em requirements.txt — builds reproducíveis

### A07: Identification and Authentication Failures

**Risco:** falhas na autenticação permitem acesso não autorizado.

**Mitigações implementadas:**
- JWT com validação completa (exp, iss, aud, scope)
- mTLS para serviço-a-serviço — sem tokens de longa duração
- SPIFFE SVIDs — identidade de workload com rotação automática a cada hora
- Rate limiting — proteção contra brute force
- Sem senhas hardcoded — tudo via Key Vault

### A08: Software and Data Integrity Failures

**Risco:** código ou dados sem verificação de integridade.

**Mitigações implementadas:**
- SBOM assinado com Cosign — verificável por qualquer pessoa
- SLSA Level 2 — provenance do build
- Dependency Review — detecta dependências comprometidas
- Container image assinada — verificável via cosign verify

### A09: Security Logging and Monitoring Failures

**Risco:** ataques não detectados por ausência de logs ou alertas.

**Mitigações implementadas:**
- Istio access logs para todo tráfego entre serviços
- Kubernetes audit logs para acesso à API
- Fortinet logs para tráfego de rede
- JWT audit — toda tentativa de autenticação logada
- OPA decision logs — toda decisão de política logada
- Log Analytics — centralização e retenção de 90 dias

### A10: Server-Side Request Forgery (SSRF)

**Risco:** servidor faz requisições para destinos controlados pelo atacante.

**Mitigações implementadas:**
- NetworkPolicy egress restrito — pods só se comunicam com destinos aprovados
- Fortinet IPS — detecta padrões de SSRF
- Allowlist de URLs externas — serviços internos só acessam APIs aprovadas

---

## LFEL1005 — Security Self-Assessment Checklist

Baseado nos conceitos do LFEL1005 — Security Self-Assessments for Open Source Projects.

### Processo de desenvolvimento

- Revisão de código obrigatória (PRs com checks automatizados)
- SAST em toda PR e push para main
- Dependências monitoradas (Dependabot + Dependency Review)
- Secrets nunca em código (Gitleaks)

### Gerenciamento de vulnerabilidades

- SBOMs gerados para cada release
- CVEs verificadas na pipeline
- Processo de disclosure documentado (SECURITY.md — a criar)
- Patch process: PRs com fix + novo release

### Gestão de dependências

- Versões fixadas (pinned) em requirements.txt
- Licenças verificadas automaticamente
- Score OpenSSF verificado para novas dependências
- Sem dependências com maintainer único sem backup

### Build e release

- Builds reproducíveis (imagem base fixada, versões pinadas)
- SLSA Level 2 — provenance verificável
- Releases assinadas com Cosign
- Changelog mantido para cada versão
