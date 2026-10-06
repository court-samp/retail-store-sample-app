variable "environment_name" {
  description = "Name of the environment"
  type        = string
  default     = "retail-store"
}

variable "istio_enabled" {
  description = "Boolean value that enables istio."
  type        = bool
  default     = false
}

variable "api_access_cidrs" {
  description = "List of CIDR blocks allowed to reach the EKS public Kubernetes API server endpoint. Set this to the IP(s) you will run kubectl from. You can change it later in the AWS Console (EKS > cluster > Networking > Manage endpoint access) or by re-applying with a new value."
  type        = list(string)
  default     = ["98.122.162.118/32"]
}

variable "opentelemetry_enabled" {
  description = "Boolean value that enables OpenTelemetry."
  type        = bool
  default     = false
}

variable "container_image_overrides" {
  type = object({
    default_repository = optional(string)
    default_tag        = optional(string)

    ui       = optional(string)
    catalog  = optional(string)
    cart     = optional(string)
    checkout = optional(string)
    orders   = optional(string)
  })
  default     = {}
  description = "Object that encapsulates any overrides to default values"
}
