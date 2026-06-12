# Arquitetura Zero Trust

Documento explicando os princípios e a implementação da arquitetura Zero Trust deste projeto.

## O que é Zero Trust?

Zero Trust é um modelo de segurança baseado no princípio "never trust, always verify" — nunca confiar, sempre verificar. Diferente do modelo perimetral tradicional (onde tudo dentro da rede é confiável), o Zero Trust assume que:

1. A rede interna já pode estar comprometida
2. Toda requisição deve ser autenticada, independente de onde vem
3. O acesso deve ser concedido com o menor privilégio possível
4. Todo tráfego deve ser monitorado e auditado

**Por que isso importa?** Violações de dados modernos frequentemente começam de dentro — um endpoint comprometido, credenciais vazadas, um insider malicioso. O modelo perimetral não protege contra essas ameaças.

## Implementação por Camada

Este projeto implementa Zero Trust em 4 camadas independentes:

### Camada 1 — Rede

Implementada via **Kubernetes NetworkPolicy** (arquivo: `zero-trust/network-policies/`).

**Princípio:** nenhum tráfego de rede é permitido por padrão.

```
┌─────────────────────────────────────────────┐
│ Namespace: production                        │
│                                             │
│  [Pod A] ──X──> [Pod B]   ← bloqueado      │
│  [Pod A] ──X──> [Ext]     ← bloqueado      │
│                                             │
│  Somente permite o que está na NetworkPolicy │
└─────────────────────────────────────────────┘
```

**Como funciona:**
1. `default-deny.yaml` — bloqueia TODO ingress e egress em todos os namespaces de app
2. `allow-dns.yaml` — libera apenas DNS (porta 53) — mínimo para pods funcionarem
3. `app-policies.yaml` — libera somente o necessário: ingress→api, api→db, api→cache

**Resultado:** Um pod comprometido não consegue se comunicar com outros serviços além do que a policy permite. Mesmo que o atacante tenha acesso shell ao pod, as chamadas de rede falham.

### Camada 2 — Workload (mTLS)

Implementada via **Istio** (arquivos: `zero-trust/mtls/`).

**Princípio:** toda comunicação pod-a-pod é autenticada e criptografada.

```
[Pod API] ──── mTLS handshake ────> [Pod Database]
    │                                     │
    │  certificado emitido pelo          │  certificado emitido pelo
    │  Istio CA (SPIFFE SVID)            │  Istio CA (SPIFFE SVID)
    └─────────────────────────────────────┘
         Ambos verificam o certificado do outro
```

**Como funciona:**
- `peer-authentication.yaml` com `mode: STRICT` — rejeita qualquer conexão sem certificado mTLS válido
- `authorization-policy.yaml` — mesmo com mTLS (autenticação), define quem pode acessar o quê (autorização)
- O Istio sidecar (Envoy) intercepta o tráfego transparentemente — a aplicação não precisa implementar mTLS

**Diferença importante:** autenticação (mTLS) ≠ autorização. Ter certificado válido não significa poder acessar qualquer serviço.

### Camada 3 — Identidade (SPIFFE/SPIRE)

Implementada via **SPIRE** (arquivos: `zero-trust/spiffe/`).

**Princípio:** toda entidade (pod, serviço, nó) tem uma identidade criptográfica verificável.

```
 SPIRE Server
      │
      │  emite SVID (certificado X.509 ou JWT)
      │
      ▼
 SPIRE Agent (roda em cada nó)
      │
      │  entrega SVID para o workload
      │
      ▼
 Pod (workload) ← identidade: spiffe://zero-trust-app.example.com/production/api
```

**SPIFFE ID:** cada workload tem um ID único no formato `spiffe://trust-domain/namespace/service`. Esse ID é emitido baseado em atributos verificáveis do pod (namespace, service account) — não é auto-declarado.

**Por que não usar apenas tokens/secrets?** Tokens são estáticos e podem ser roubados. SVIDs do SPIRE são rotacionados automaticamente a cada hora e são ligados à identidade do workload — não podem ser usados por outro processo.

### Camada 4 — RBAC (Controle de Acesso)

Implementada via **Kubernetes RBAC** (arquivos: `zero-trust/rbac/`).

**Princípio:** cada service account só tem acesso ao mínimo necessário.

```
api-service-account → Role(api-role)
    ├── get ConfigMap "app-config"
    ├── get ConfigMap "feature-flags"
    ├── get Secret "app-db-credentials"
    └── get Secret "app-jwt-secret"
    
    NÃO TEM: list secrets, create pods, delete namespaces, ...
```

**O que está implementado:**
- Service accounts sem `automountServiceAccountToken` — token montado apenas quando necessário
- Roles com `resourceNames` específicos — não pode listar nem acessar outros secrets
- ClusterRoles mínimos para CI/CD — só pode atualizar deployments, sem acesso a secrets

## Como o tráfego é verificado

Exemplo de uma requisição chegando do exterior até o banco de dados:

```
1. Internet ──HTTPS──> Ingress Controller
   - TLS terminado no ingress
   - Certificado verificado pelo cliente
   - Fortinet IPS/WAF analisa o tráfego (OWASP Top 10)

2. Ingress ──────────> Pod API
   - NetworkPolicy: ingress só aceita de ingress-nginx
   - Istio mTLS: ingress precisa ter certificado válido
   - Istio AuthorizationPolicy: verifica principal SPIFFE do ingress
   - JWT validation: header Authorization verificado pelo Envoy
   - Scope check: aplicação verifica se o scope autoriza a operação

3. Pod API ──────────> Pod Database
   - NetworkPolicy: api→db na porta 5432 (somente)
   - Istio mTLS: api precisa ter certificado da identidade api-service-account
   - Istio AuthorizationPolicy: database só aceita do principal da API
   
4. Response volta pelo mesmo caminho (mTLS bidirecional)
```

## O que acontece se um pod for comprometido?

**Cenário:** atacante explora uma vulnerabilidade na API e tem shell no pod.

**O que o atacante PODE fazer:**
- Ler arquivos dentro do container (limitado por readOnlyRootFilesystem)
- Fazer chamadas dentro dos limites das NetworkPolicies (api→db, api→cache)
- Usar o SVID do pod (válido por 1 hora, depois expira)

**O que o atacante NÃO PODE fazer:**
- Escalar para root (runAsNonRoot, allowPrivilegeEscalation: false)
- Acessar outros pods fora do escopo (NetworkPolicy)
- Persistir no filesystem (readOnlyRootFilesystem)
- Acessar a API do Kubernetes (serviceAccountToken não montado)
- Comunicar com C&C externo (egress bloqueado por NetworkPolicy)
- Usar o SVID para acessar serviços não autorizados (AuthorizationPolicy)

## Monitoramento e Auditoria

Zero Trust sem visibilidade não funciona. Todo acesso é logado:

- **Istio access logs:** cada chamada entre serviços com principal SPIFFE, resposta, latência
- **Kubernetes audit logs:** todo acesso à API do k8s (quem fez o quê e quando)
- **Fortinet logs:** tráfego de entrada com detalhes de inspeção
- **JWT audit:** toda tentativa de autenticação (sucesso e falha)
- **OPA decision logs:** cada decisão de política (allow/deny)

Tudo centralizado no Log Analytics Workspace para análise e alertas.

## Referências

- [NIST SP 800-207 — Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
- [LFS183 — Introduction to Zero Trust](https://training.linuxfoundation.org/training/introduction-to-zero-trust-lfs183/)
- [SPIFFE/SPIRE Documentation](https://spiffe.io/docs/)
- [Istio Security](https://istio.io/latest/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
