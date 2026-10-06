variable "environment_name" {
  description = "Name of the environment"
  type        = string
}

variable "cluster_version" {
  description = "EKS cluster version."
  type        = string
  default     = "1.31"
}

variable "tags" {
  description = "List of tags to be associated with resources."
  default     = {}
  type        = map(string)
}

variable "vpc_id" {
  description = "VPC ID used to create EKS cluster."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC ID used to create EKS cluster."
  type        = string
}

variable "subnet_ids" {
  description = "List of private subnet IDs used by EKS cluster nodes."
  type        = list(string)
}

variable "istio_enabled" {
  description = "Boolean value that enables istio."
  type        = bool
  default     = false
}

variable "opentelemetry_enabled" {
  description = "Boolean value that enables OpenTelemetry."
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "List of CIDR blocks allowed to access the public EKS Kubernetes API server endpoint. Defaults to open (0.0.0.0/0); override to restrict to specific IPs."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
