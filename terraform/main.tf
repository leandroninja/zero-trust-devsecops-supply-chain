###############################################################################
# Terraform — Zero Trust DevSecOps Platform (Azure)
#
# Provisiona:
#   - AKS privado (sem endpoint público)
#   - Azure Key Vault (secrets e certificados)
#   - Microsoft Defender for Cloud
#   - Log Analytics Workspace
#   - Azure Container Registry (ACR) privado
#
# Referência: LFS183 Zero Trust — Infrastructure Layer
#
# Pré-requisitos:
#   - Azure CLI autenticado: az login
#   - Service Principal com permissões Contributor no resource group
#   - terraform init com backend configurado (ver backend.tf)
#
# Uso:
#   terraform init
#   terraform plan -var-file="environments/prod.tfvars"
#   terraform apply -var-file="environments/prod.tfvars"
###############################################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Backend remoto — necessário para trabalho em equipe e CI/CD
  # Substituir pelos valores reais antes de usar
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "stterraformstate"  # precisa ser globalmente único
    container_name       = "tfstate"
    key                  = "zero-trust-devsecops/terraform.tfstate"
    # Autenticação via OIDC (GitHub Actions) — sem client_secret em código
    use_oidc = true
  }
}

provider "azurerm" {
  features {
    # Purge protection no Key Vault — evita exclusão acidental de segredos
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }

    # Soft delete no Resource Group — 90 dias de recovery window
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
  }

  # Autenticação via Workload Identity (OIDC) no GitHub Actions
  # Em local: usa az login
  use_oidc = var.use_oidc_auth
}

# ─── Data sources ─────────────────────────────────────────────────────────────

data "azurerm_client_config" "current" {}

data "azuread_client_config" "current" {}

# ─── Resource Group ────────────────────────────────────────────────────────────

resource "azurerm_resource_group" "main" {
  name     = "rg-${var.project_name}-${var.environment}"
  location = var.azure_region

  tags = local.common_tags
}

# ─── Log Analytics Workspace ───────────────────────────────────────────────────
# Centraliza logs do AKS, Defender e outros serviços

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${var.project_name}-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 90  # compliance — 90 dias de retenção mínima

  tags = local.common_tags
}

# ─── Azure Container Registry ──────────────────────────────────────────────────
# Registro privado de containers — sem acesso público

resource "azurerm_container_registry" "main" {
  name                = "acr${replace(var.project_name, "-", "")}${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Premium"  # Premium: geo-replication, private endpoint, content trust

  # Desabilita acesso público — somente via Private Endpoint
  public_network_access_enabled = false

  # Habilita content trust (assinatura de imagens com Notary)
  trust_policy {
    enabled = true
  }

  # Habilita scanning automático de vulnerabilidades com Defender
  quarantine_policy_enabled = true

  # Zone redundancy para HA
  zone_redundancy_enabled = true

  # Retenção de imagens sem tag (cleanup automático)
  retention_policy {
    days    = 7
    enabled = true
  }

  tags = local.common_tags
}

# ─── Key Vault ─────────────────────────────────────────────────────────────────
# Armazenamento seguro de secrets, certificados e chaves

resource "random_string" "kv_suffix" {
  length  = 4
  upper   = false
  special = false
  numeric = true
}

resource "azurerm_key_vault" "main" {
  name                = "kv-${var.project_name}-${random_string.kv_suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "premium"  # premium: HSM-backed keys

  # Habilita soft delete — segredos ficam 90 dias após exclusão antes de sumir
  soft_delete_retention_days = 90

  # Purge protection — impede exclusão definitiva mesmo com acesso admin
  # Protege contra ataques de ransomware que deletam backups e segredos
  purge_protection_enabled = true

  # Desabilita acesso público — somente via Private Endpoint
  public_network_access_enabled = false

  # Modelo de permissão: RBAC (mais granular que Access Policies)
  enable_rbac_authorization = true

  # Log de auditoria de acesso a segredos
  # (configurado via Diagnostic Settings abaixo)

  tags = local.common_tags
}

# Diagnostic settings para Key Vault — logs de auditoria
resource "azurerm_monitor_diagnostic_setting" "kv" {
  name                       = "kv-diagnostics"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "AuditEvent"
  }

  metric {
    category = "AllMetrics"
  }
}

# ─── AKS Cluster ──────────────────────────────────────────────────────────────
# Cluster privado — sem endpoint público do API server

resource "azurerm_kubernetes_cluster" "main" {
  name                = "aks-${var.project_name}-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = "${var.project_name}-${var.environment}"

  # Kubernetes version — manter atualizado
  kubernetes_version = var.kubernetes_version

  # Cluster privado — API server sem IP público
  private_cluster_enabled             = true
  private_dns_zone_id                 = "System"  # usa DNS zone gerenciada pelo Azure
  private_cluster_public_fqdn_enabled = false

  # SKU Uptime SLA — 99.95% de disponibilidade garantida
  sku_tier = "Standard"

  # Node pool de sistema (control plane workloads do k8s)
  default_node_pool {
    name                = "system"
    node_count          = 2
    vm_size             = var.system_node_vm_size
    os_disk_size_gb     = 50
    os_disk_type        = "Ephemeral"  # disco efêmero — mais rápido e sem dados residuais
    vnet_subnet_id      = azurerm_subnet.aks_nodes.id

    # Habilita autoscaling
    enable_auto_scaling = true
    min_count           = 2
    max_count           = 5
    max_pods            = 50

    # Apenas pods de sistema — app pods vão para user node pools
    only_critical_addons_enabled = true

    # Upgrade de nodes — usa surge para zero downtime
    upgrade_settings {
      max_surge = "1"
    }

    node_labels = {
      "zero-trust/node-type" = "system"
    }
  }

  # Identidade gerenciada para o cluster (sem service principal manual)
  identity {
    type = "SystemAssigned"
  }

  # Kubelet identity — usada pelos nodes para acessar ACR
  kubelet_identity {
    client_id                 = azurerm_user_assigned_identity.kubelet.client_id
    object_id                 = azurerm_user_assigned_identity.kubelet.principal_id
    user_assigned_identity_id = azurerm_user_assigned_identity.kubelet.id
  }

  # Networking
  network_profile {
    network_plugin    = "azure"  # Azure CNI — pods têm IPs da VNet (necessário para private cluster)
    network_policy    = "calico"  # Calico para NetworkPolicies
    load_balancer_sku = "standard"
    # Sem IP público nos nodes — tráfego de saída via NAT Gateway
    outbound_type = "userAssignedNATGateway"
  }

  # Azure Active Directory integration — RBAC via Azure AD
  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
    admin_group_object_ids = var.aks_admin_group_ids
  }

  # Add-ons do cluster
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  azure_policy_enabled = true  # Azure Policy para Kubernetes (Gatekeeper)

  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }

  # Microsoft Defender for Containers
  microsoft_defender {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  # Maintenance window — updates apenas em horários programados
  maintenance_window {
    allowed {
      day   = "Sunday"
      hours = [2, 3, 4]  # 2h às 4h da manhã de domingo
    }
  }

  tags = local.common_tags

  lifecycle {
    # Ignora mudanças de kubernetes_version feitas manualmente (upgrades via portal)
    ignore_changes = [kubernetes_version]
  }
}

# Node pool para aplicações (separado do sistema)
resource "azurerm_kubernetes_cluster_node_pool" "app" {
  name                  = "app"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = var.app_node_vm_size
  vnet_subnet_id        = azurerm_subnet.aks_nodes.id

  enable_auto_scaling = true
  min_count           = 2
  max_count           = 10
  max_pods            = 30
  os_disk_type        = "Ephemeral"

  node_labels = {
    "zero-trust/node-type" = "application"
  }

  node_taints = []  # sem taints — todos os pods de app podem usar esse pool

  upgrade_settings {
    max_surge = "1"
  }

  tags = local.common_tags
}

# ─── Microsoft Defender for Cloud ─────────────────────────────────────────────

resource "azurerm_security_center_subscription_pricing" "containers" {
  tier          = "Standard"
  resource_type = "Containers"
}

resource "azurerm_security_center_subscription_pricing" "key_vaults" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# ─── Identidades ──────────────────────────────────────────────────────────────

resource "azurerm_user_assigned_identity" "kubelet" {
  name                = "id-${var.project_name}-kubelet-${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = local.common_tags
}

# Permissão para o kubelet fazer pull de imagens do ACR
resource "azurerm_role_assignment" "kubelet_acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.kubelet.principal_id
}

# ─── Locals ───────────────────────────────────────────────────────────────────

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    Owner       = "leandro-moraes"
    ManagedBy   = "terraform"
    CostCenter  = "platform"
  }
}
