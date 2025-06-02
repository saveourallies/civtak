terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      version = "~>4.31"
    }
  }
}
provider "azurerm" {
  features {}
}

locals {
  net_env = "${var.infra_name}-${var.env_name}_net"
  tags   = {
    network = var.infra_name
    environment = var.env_name
    infra_group = var.component
    owner       = var.owner
  }
}
