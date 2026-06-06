###############################################################################
# Outputs — Zero Trust DevSecOps Platform
#
# Valores exportados para uso em outros módulos Terraform ou
# para configuração manual pós-deploy (ex: kubectl, Helm).
###############################################################################

# ─── AKS ──────────────────────────────────────────────────────────────────────

output "aks_cluster_name" {
  description = "Nome do cluster AKS"
  value       = azurerm_kubernetes_cluster.main.name
}

output "aks_resource_group" {
  description = "Resource group do cluster AKS"
  value       = azurerm_resource_group.main.name
}

output "aks_cluster_id" {
  description = "ID do recurso AKS"
  value       = azurerm_kubernetes_cluster.main.id
}

output "aks_fqdn" {
  description = "FQDN privado do API server do AKS"
  value       = azurerm_kubernetes_cluster.main.private_fqdn
  # Apenas acessível de dentro da VNet ou via VPN/ExpressRoute
}

output "aks_kubernetes_version" {
  description = "Versão do Kubernetes em uso"
  value       = azurerm_kubernetes_cluster.main.kubernetes_version
}

output "aks_node_resource_group" {
  description = "Resource group dos nodes do AKS (gerenciado pelo Azure)"
  value       = azurerm_kubernetes_cluster.main.node_resource_group
}

# Comando para obter credenciais do kubectl (só funciona de dentro da VNet)
output "kubectl_command" {
  description = "Comando para configurar kubectl"
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${azurerm_kubernetes_cluster.main.name} --admin"
}

# ─── ACR ──────────────────────────────────────────────────────────────────────

output "acr_name" {
  description = "Nome do Azure Container Registry"
  value       = azurerm_container_registry.main.name
}

output "acr_login_server" {
  description = "Login server do ACR (usado no docker push/pull)"
  value       = azurerm_container_registry.main.login_server
}

output "acr_id" {
  description = "ID do recurso ACR"
  value       = azurerm_container_registry.main.id
}

# ─── Key Vault ────────────────────────────────────────────────────────────────

output "key_vault_name" {
  description = "Nome do Key Vault"
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "URI do Key Vault (para referências em aplicações)"
  value       = azurerm_key_vault.main.vault_uri
}

output "key_vault_id" {
  description = "ID do recurso Key Vault"
  value       = azurerm_key_vault.main.id
}

# ─── Log Analytics ────────────────────────────────────────────────────────────

output "log_analytics_workspace_id" {
  description = "ID do Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.main.id
}

output "log_analytics_workspace_name" {
  description = "Nome do Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.main.name
}

# ─── Identidades ──────────────────────────────────────────────────────────────

output "kubelet_identity_client_id" {
  description = "Client ID da identidade gerenciada do kubelet"
  value       = azurerm_user_assigned_identity.kubelet.client_id
}

output "kubelet_identity_object_id" {
  description = "Object ID da identidade gerenciada do kubelet"
  value       = azurerm_user_assigned_identity.kubelet.principal_id
}

# ─── Região e Resource Group ──────────────────────────────────────────────────

output "resource_group_name" {
  description = "Nome do resource group principal"
  value       = azurerm_resource_group.main.name
}

output "azure_region" {
  description = "Região Azure onde os recursos foram criados"
  value       = azurerm_resource_group.main.location
}

# ─── Resumo do ambiente ────────────────────────────────────────────────────────

output "environment_summary" {
  description = "Resumo do ambiente provisionado"
  value = {
    project     = var.project_name
    environment = var.environment
    region      = var.azure_region
    aks_cluster = azurerm_kubernetes_cluster.main.name
    acr         = azurerm_container_registry.main.login_server
    key_vault   = azurerm_key_vault.main.name
  }
}
