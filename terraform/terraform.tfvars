# ---------------------------------------------------------------------------------------------------------------------
# Global Variables
# ---------------------------------------------------------------------------------------------------------------------

cloud_region = "eu-central-1"
global_config = {
  customer_prefix = "CNA"
  env             = "DEV"
  product_id      = "SWP-3397"
  application     = "APPD"
  app_name        = "20adv"
  costcenter      = "0815"
}

# ---------------------------------------------------------------------------------------------------------------------
# Custom Variables
# ---------------------------------------------------------------------------------------------------------------------

vpc_id         = "vpc-098f9c56af805adec"
vpc_subnet_ids = ["subnet-0b1a758f87a25bea7", "subnet-0743fca648311e619"]

public_vpc_id         = "vpc-07d5f52932ea6851d"
public_vpc_subnet_ids = ["subnet-0868ebba6997a7def", "subnet-0b86c4e9d13ed07e3"]
public_dns_zone_name  = "cgpb-test.aws.bmw.cloud"

waf_web_acl_arn = "arn:aws:wafv2:eu-central-1:069882449779:regional/webacl/FMManagedWebACLV2-BMW-WAFPolicy-Standard-ALB-1650445046482/84a81c93-e462-45eb-8105-9ffc4f428f3a"