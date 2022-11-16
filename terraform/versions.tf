terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    local = {
      source = "hashicorp/local"
    }
  }
  required_version = ">= 1"
  backend "s3" {
    region         = "eu-central-1"
    bucket         = "tst-eu-central-1-auto-tfstates-123"
    dynamodb_table = "tst-eu-central-1-auto-tfstates-123"
    key            = "atc-cgbp-aws-github-runner/atc-cgbp-aws-runner.tfstate"
    encrypt        = true
  }
}
