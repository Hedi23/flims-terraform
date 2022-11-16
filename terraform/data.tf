data "aws_vpc" "private_vpc" {
  id = var.private_vpc_id
}

data "aws_vpc" "public_vpc" {
  id = var.public_vpc_id
}

data "aws_subnet" "public_subnet_ids" {
  id = var.public_subnet_ids
}

data "aws_subnet" "private_subnet_ids" {
  id = var.private_subnet_ids
}

data "aws_subnet" "intranet_subnet_ids" {
  id = var.intranet_subnet_ids
}

data "aws_caller_identity" "current" {}