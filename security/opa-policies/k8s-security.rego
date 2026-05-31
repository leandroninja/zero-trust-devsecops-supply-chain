package kubernetes.security

# Políticas OPA para segurança de workloads Kubernetes
#
# Testado com conftest v0.47+
# Uso: conftest test k8s/ --policy security/opa-policies/
# fix 2026-04-22: regra deny_nodeport agora exclui portas internas de health check
#
# Cada regra "deny" adiciona uma mensagem ao conjunto de violações.
# Se deny tiver qualquer elemento, o deploy é bloqueado pelo pipeline.
#
# Referências:
#   - CIS Kubernetes Benchmark v1.8
#   - NSA/CISA Kubernetes Hardening Guide
#   - LFS183 Zero Trust

import future.keywords.in
import future.keywords.if
import future.keywords.every

# ─── Helpers ──────────────────────────────────────────────────────────────────

# Verifica se é um recurso que tem containers (Deployment, Pod, etc.)
is_workload {
	input.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}
}

# Extrai os containers de qualquer tipo de workload
containers[container] {
	input.kind == "Pod"
	container := input.spec.containers[_]
}

containers[container] {
	input.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}
	container := input.spec.template.spec.containers[_]
}

containers[container] {
	input.kind == "CronJob"
	container := input.spec.jobTemplate.spec.template.spec.containers[_]
}

# Extrai o spec do pod
pod_spec := input.spec if input.kind == "Pod"
pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}
pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

# ─── Regra 1: Containers privilegiados ────────────────────────────────────────

deny[msg] {
	is_workload
	container := containers[_]
	container.securityContext.privileged == true

	msg := sprintf(
		"[CRÍTICO] Container '%s' está rodando em modo privilegiado. Containers privilegiados têm acesso total ao host — nunca permitido.",
		[container.name]
	)
}

# ─── Regra 2: Root user bloqueado ─────────────────────────────────────────────

deny[msg] {
	is_workload
	container := containers[_]

	# runAsNonRoot não definido OU explicitamente false
	not container.securityContext.runAsNonRoot == true
	not pod_spec.securityContext.runAsNonRoot == true

	msg := sprintf(
		"[ALTO] Container '%s' pode rodar como root. Defina securityContext.runAsNonRoot: true no container ou no pod spec.",
		[container.name]
	)
}

deny[msg] {
	is_workload
	container := containers[_]

	# runAsUser: 0 é root explicitamente
	container.securityContext.runAsUser == 0

	msg := sprintf(
		"[CRÍTICO] Container '%s' está configurado para rodar como uid 0 (root). Use um UID >= 1000.",
		[container.name]
	)
}

# ─── Regra 3: Tag :latest bloqueada ───────────────────────────────────────────

deny[msg] {
	is_workload
	container := containers[_]

	# Verifica se a tag é :latest ou se não tem tag (implica latest)
	image := container.image
	endswith(image, ":latest")

	msg := sprintf(
		"[ALTO] Container '%s' usa a tag ':latest' na imagem '%s'. Use uma tag específica ou digest (sha256:...) para garantir reproducibilidade.",
		[container.name, image]
	)
}

deny[msg] {
	is_workload
	container := containers[_]
	image := container.image

	# Sem tag = implicitly latest
	not contains(image, ":")

	msg := sprintf(
		"[ALTO] Container '%s' com imagem '%s' não tem tag definida. Adicione uma tag específica ou digest.",
		[container.name, image]
	)
}

# ─── Regra 4: Resource limits obrigatórios ────────────────────────────────────

deny[msg] {
	is_workload
	container := containers[_]
	not container.resources.limits.memory

	msg := sprintf(
		"[MÉDIO] Container '%s' não tem memory limit definido. Sem limit, um container com memory leak pode derrubar o node inteiro.",
		[container.name]
	)
}

deny[msg] {
	is_workload
	container := containers[_]
	not container.resources.limits.cpu

	msg := sprintf(
		"[MÉDIO] Container '%s' não tem CPU limit definido. Sem limit, um container pode monopolizar CPU do node.",
		[container.name]
	)
}

deny[msg] {
	is_workload
	container := containers[_]
	not container.resources.requests.memory

	msg := sprintf(
		"[INFO] Container '%s' não tem memory request definido. Requests são necessários para o scheduler alocar corretamente.",
		[container.name]
	)
}

# ─── Regra 5: hostNetwork bloqueado ───────────────────────────────────────────

deny[msg] {
	is_workload
	pod_spec.hostNetwork == true

	msg := sprintf(
		"[CRÍTICO] Workload '%s' está usando hostNetwork: true. Isso expõe a rede do node diretamente ao container — violação de isolamento Zero Trust.",
		[input.metadata.name]
	)
}

# ─── Regra 6: hostPID bloqueado ───────────────────────────────────────────────

deny[msg] {
	is_workload
	pod_spec.hostPID == true

	msg := sprintf(
		"[CRÍTICO] Workload '%s' está usando hostPID: true. Containers não devem ver processos do node host.",
		[input.metadata.name]
	)
}

# ─── Regra 7: NodePort bloqueado ──────────────────────────────────────────────

deny[msg] {
	input.kind == "Service"
	input.spec.type == "NodePort"

	msg := sprintf(
		"[ALTO] Service '%s' usa type NodePort. NodePort expõe a porta diretamente em todos os nodes — use ClusterIP com Ingress ou LoadBalancer com annotation de whitelist.",
		[input.metadata.name]
	)
}

# ─── Regra 8: Security context obrigatório ────────────────────────────────────

deny[msg] {
	is_workload
	container := containers[_]
	not container.securityContext

	msg := sprintf(
		"[ALTO] Container '%s' não tem securityContext definido. securityContext é obrigatório — defina ao menos runAsNonRoot e allowPrivilegeEscalation.",
		[container.name]
	)
}

# ─── Regra 9: allowPrivilegeEscalation bloqueado ──────────────────────────────

deny[msg] {
	is_workload
	container := containers[_]

	# não definido OR explicitamente true
	not container.securityContext.allowPrivilegeEscalation == false

	msg := sprintf(
		"[ALTO] Container '%s' não tem allowPrivilegeEscalation: false. Sem isso, binários setuid podem elevar privilégios dentro do container.",
		[container.name]
	)
}

# ─── Regra 10: readOnlyRootFilesystem obrigatório ─────────────────────────────

deny[msg] {
	is_workload
	container := containers[_]
	not container.securityContext.readOnlyRootFilesystem == true

	msg := sprintf(
		"[MÉDIO] Container '%s' não tem readOnlyRootFilesystem: true. Filesystem mutável facilita ataques de persistência. Use volumes montados para dados mutáveis.",
		[container.name]
	)
}

# ─── Regra 11 (bônus): hostPath volumes bloqueados ────────────────────────────

deny[msg] {
	is_workload
	volume := pod_spec.volumes[_]
	volume.hostPath

	msg := sprintf(
		"[ALTO] Workload '%s' monta volume hostPath '%s'. Volumes hostPath permitem acesso ao filesystem do node — use PVCs.",
		[input.metadata.name, volume.hostPath.path]
	)
}

# ─── Regra 12 (bônus): Sem liveness probe definida ────────────────────────────

warn[msg] {
	is_workload
	container := containers[_]
	not container.livenessProbe

	msg := sprintf(
		"[AVISO] Container '%s' não tem livenessProbe definido. Sem probe, o Kubernetes não sabe se a aplicação travou.",
		[container.name]
	)
}
