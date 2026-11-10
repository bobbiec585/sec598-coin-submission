variable "deployment_suffix" {
  description = "Optional suffix for disposable pipeline deployments"
  type        = string
  default     = ""

  validation {
    condition = (
      length(var.deployment_suffix) <= 32 &&
      length(regexall("[^a-z0-9-]", var.deployment_suffix)) == 0
    )
    error_message = "Use up to 32 lowercase letters, numbers or hyphens."
  }
}

locals {
  name_suffix = var.deployment_suffix == "" ? "" : "-${var.deployment_suffix}"
}
