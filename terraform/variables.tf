###############################################################################
# Variables — Zero Trust DevSecOps Platform
###############################################################################

variable "project_name" {
  type        = string
  description = "Nome do projeto — usado como prefixo em todos os recursos"
  default     = "zero-trust-app"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_name))
    error_message = "project_name deve ter entre 3 e 21 caracteres, começar com letra, e conter apenas letras minúsculas, números e hífen."
  }
}

variable "environment" {
  type        = string
  description = "Ambiente de deploy"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment deve ser: dev, staging ou prod."
  }
}

variable "azure_region" {
  type        = string
  description = "Região Azure para os recursos"
  default     = "brazilsouth"  # Brasil — latência menor para usuários BR

  # Regiões onde o AKS privado é suportado com todos os add-ons
  validation {
    condition = contains([
      "brazilsouth",
      "eastus",
      "eastus2",
      "westus2",
      "westus3",
      "westeurope",
      "northeurope",
    ], var.azure_region)
    error_message = "azure_region inválida. Consulte a documentação para regiões suportadas."
  }
}

variable "kubernetes_version" {
  type        = string
  description = "Versão do Kubernetes para o AKS"
  default     = "1.28"
  # Manter atualizado — versões antigas perdem suporte e patches de segurança
}

variable "system_node_vm_size" {
  type        = string
  description = "Tamanho das VMs do node pool de sistema"
  default     = "Standard_D2s_v3"  # 2 vCPU, 8GB RAM — suficiente para control plane workloads
}

variable "app_node_vm_size" {
  type        = string
  description = "Tamanho das VMs do node pool de aplicação"
  default     = "Standard_D4s_v3"  # 4 vCPU, 16GB RAM — para workloads de aplicação
}

variable "aks_admin_group_ids" {
  type        = list(string)
  description = "IDs dos grupos Azure AD que terão acesso admin ao AKS"
  default     = []
  # Em produção: preencher com o Object ID do grupo de admins do AKS no Azure AD
  # Obtido via: az ad group show --group "AKS-Admins" --query id -o tsv
}

variable "use_oidc_auth" {
  type        = bool
  description = "Usar OIDC para autenticação (true em CI/CD, false em local)"
  default     = false
  # Em GitHub Actions: true + permissão id-token: write no workflow
}

variable "vnet_address_space" {
  type        = list(string)
  description = "Address space da VNet principal"
  default     = ["10.0.0.0/8"]
  # Espaço grande para acomodar subnets de nodes, pods, serviços
}

variable "aks_nodes_subnet_cidr" {
  type        = string
  description = "CIDR da subnet dos nodes AKS"
  default     = "10.10.0.0/16"
}

variable "aks_pods_subnet_cidr" {
  type        = string
  description = "CIDR da subnet dos pods (Azure CNI)"
  default     = "10.20.0.0/16"
}

variable "private_endpoints_subnet_cidr" {
  type        = string
  description = "CIDR da subnet para Private Endpoints"
  default     = "10.30.0.0/24"
}

variable "log_retention_days" {
  type        = number
  description = "Retenção de logs no Log Analytics Workspace (dias)"
  default     = 90

  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 730
    error_message = "log_retention_days deve ser entre 30 e 730 dias."
  }
}

variable "tags" {
  type        = map(string)
  description = "Tags adicionais para todos os recursos"
  default     = {}
  # Exemplo: { "CostCenter" = "engineering", "Team" = "platform" }
}
