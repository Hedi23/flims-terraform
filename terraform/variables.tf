# ---------------------------------------------------------------------------------------------------------------------
# Global Variables
# ---------------------------------------------------------------------------------------------------------------------
variable "cloud_region" {
  type        = string
  description = "define the location which tf should use."
  default     = "eu-central-1"
}

# -------------------------------------------------------------------------------------------------------

variable "public_vpc_id" {
  description = "ID of the public VPC"
  type        = string
}

variable "private_vpc_id" {
  description = "ID of the private VPC"
  type        = string
}

variable "public_subnet_ids" {
  description = "A list of subnet IDs to launch resources in. Subnets automatically determine which availability zones the group will reside. Conflicts with `availability_zones`"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "A list of subnet IDs to launch resources in. Subnets automatically determine which availability zones the group will reside. Conflicts with `availability_zones`"
  type        = list(string)
}

variable "intranet_subnet_ids" {
  description = "A list of subnet IDs to launch resources in. Subnets automatically determine which availability zones the group will reside. Conflicts with `availability_zones`"
  type        = list(string)
}
