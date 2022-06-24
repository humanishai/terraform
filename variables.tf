terraform {
  backend "remote" {
    organization = "simtooreal"

    workspaces {
      name = "simtooreal"
    }
  }
}

# This is to avoid terraform complaining about no region specified
provider "aws" {
  region = "us-east-1"
}

# The major region is us-east-1
variable "aws_region" {
  description = "The AWS region"
  default     = "us-east-1"
}

# The number of AZs to cover for AZ fault tolerance
variable "az_count" {
  description = "Number of AZs to cover in a given AWS region"
  default     = "2"
}

# The number of app containers to normally run
variable "app_count" {
  description = "Number of app containers to run"
  default     = 1
}

# The database password should be passed in at terraform runtime by using -var
variable "db_password" {
  description = "Database password"
  default     = "$$${db_password}"
  sensitive   = true
}

# The aws secret should be passed in at terraform runtime by using -var
variable "aws_secret_access_key" {
  description = "AWS access key"
  default     = "$$${aws_secret_access_key}"
  sensitive   = true
}

# The database password should be passed in at terraform runtime by using -var
variable "aws_access_key_id" {
  description = "AWS key ID"
  default     = "$$${aws_access_key_id}"
  sensitive   = true
}

# OpenAI API key for using any models from OpenAI
variable "openai_api_key" {
  description = "OpenAI API Key"
  default     = "$$${openai_api_key}"
  sensitive   = true
}

# The api token for replicate used for running model inference
variable "replicate_api_token" {
  description = "Replicate API Token"
  default     = "$$${replicate_api_token}"
  sensitive   = true
}

# The api token for flask praetorian
variable "secret_key" {
  description = "flask_praetorian secret key"
  default     = "$$${secret_key}"
  sensitive   = true
}

# The api token for flask praetorian
variable "stripe_secret_key" {
  description = "Stripe secret key"
  default     = "$$${stripe_secret_key}"
  sensitive   = true
}

# The minimum number of containers that should be running
variable "ecs_autoscale_min_instances" {
  default = "2"
}

# The maximum number of containers that should be running
variable "ecs_autoscale_max_instances" {
  default = "5"
}

# The number of instances to reserve
variable "reserved_instances_count" {
  description = "Number of reserved instances to run"
  default     = 1
}