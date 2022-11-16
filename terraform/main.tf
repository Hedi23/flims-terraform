module "common" {
  source               = "git::https://atc-github.azure.cloud.bmw/cgbp/terraform-bmw-cloud-commons.git?ref=1.1.2"
  module_name          = basename(abspath(path.module))
  cloud_region         = var.cloud_region
  global_config        = var.global_config
  custom_tags          = var.custom_tags
  custom_name          = var.custom_name
  commons_file_json    = var.commons_file_json
  local_file_json_tpl  = var.local_file_json_tpl
  naming_file_json_tpl = var.naming_file_json_tpl
}

# ---------------------------------------------------------------------------- #
#                                Security Group                                #
# ---------------------------------------------------------------------------- #

module "sg" {
  source = "git::https://atc-github.azure.cloud.bmw/cgbp/terraform-aws-bmw-sg.git?ref=1.3.0"

  cloud_region         = var.cloud_region
  global_config        = var.global_config
  custom_tags          = var.custom_tags
  custom_name          = var.custom_name
  commons_file_json    = var.commons_file_json
  local_file_json_tpl  = var.local_file_json_tpl
  naming_file_json_tpl = var.naming_file_json_tpl

  vpc_id    = var.public_vpc_id
  create_sg = true

  ingress_rules = {
    https = {
      from_port        = var.lb_listener_port
      to_port          = var.lb_listener_port
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = null
    }
  }

  egress_rules = {
    https = {
      from_port        = var.lb_backend_port
      to_port          = var.lb_backend_port
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = null
    }
  }

}

# ---------------------------------------------------------------------------- #
#                                  PUBLIC DNS                                  #
# ---------------------------------------------------------------------------- #

data "aws_route53_zone" "route_53_public_hosted_zone" {
  name         = var.public_dns_zone_name
  private_zone = false
}
resource "aws_route53_record" "route_53_record_public_ingress" {
  zone_id = data.aws_route53_zone.route_53_public_hosted_zone.zone_id
  name    = var.public_dns_zone_record
  type    = "A"
  alias {
    name                   = module.alb.lb_dns_name
    zone_id                = module.alb.lb_zone_id
    evaluate_target_health = true
  }

}


# ============================================================================ #
#                                 Certificates                                 #
# ============================================================================ #

# ============================== AWS Certificate ============================= #

resource "aws_acm_certificate" "cert" {
  count             = var.use_aws_certificate ? 1 : 0
  domain_name       = "${var.public_dns_zone_record}.${var.public_dns_zone_name}"
  validation_method = "DNS"
  options {
    certificate_transparency_logging_preference = "ENABLED"
  }
  lifecycle {
    create_before_destroy = true
  }
  tags = module.common.tags
}


resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in var.use_aws_certificate ? aws_acm_certificate.cert[0].domain_validation_options : [] : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.route_53_public_hosted_zone.zone_id
}


resource "aws_acm_certificate_validation" "cert" {
  count                   = var.use_aws_certificate ? 1 : 0
  certificate_arn         = aws_acm_certificate.cert[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# ---------------------------------------------------------------------------- #
#                                      ALB                                     #
# ---------------------------------------------------------------------------- #

module "alb" {
  source = "git::https://atc-github.azure.cloud.bmw/cgbp/terraform-aws-bmw-elb.git?ref=2.6.0"

  cloud_region         = var.cloud_region
  global_config        = var.global_config
  custom_tags          = var.custom_tags
  custom_name          = var.custom_name
  commons_file_json    = var.commons_file_json
  local_file_json_tpl  = var.local_file_json_tpl
  naming_file_json_tpl = var.naming_file_json_tpl


  load_balancer_type         = "application"
  enable_deletion_protection = false
  internal                   = false

  security_groups = [module.sg.sg_id]
  vpc_id          = var.public_vpc_id
  subnets         = var.public_vpc_subnet_ids

  access_logs = {
    bucket  = module.lb_logs.s3_bucket_id
    prefix  = var.lb_logs_access_logs_prefix
    enabled = true
  }

  http_tcp_listeners = [
    {
      port        = 80
      protocol    = "HTTP"
      action_type = "redirect"
      redirect = {
        port        = "${var.lb_listener_port}"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    },
  ]

  https_listeners = [{
    port            = var.lb_listener_port
    protocol        = "HTTPS"
    action_type     = var.authenticate_oidc == {} ? "forward" : "authenticate-oidc"
    certificate_arn = var.certificate_arn == null ? aws_acm_certificate.cert[0].arn : var.certificate_arn
    authenticate_oidc = try(var.authenticate_oidc == {} ? tomap(false) : {
      authentication_request_extra_params = lookup(var.authenticate_oidc, "authentication_request_extra_params", {})
      authorization_endpoint              = var.authenticate_oidc.authorization_endpoint
      client_id                           = var.authenticate_oidc.client_id
      client_secret                       = var.authenticate_oidc.client_secret
      issuer                              = var.authenticate_oidc.issuer
      on_unauthenticated_request          = lookup(var.authenticate_oidc, "on_unauthenticated_request", null)
      scope                               = lookup(var.authenticate_oidc, "scope", null)
      session_cookie_name                 = lookup(var.authenticate_oidc, "session_cookie_name", null)
      session_timeout                     = lookup(var.authenticate_oidc, "session_timeout", null)
      token_endpoint                      = var.authenticate_oidc.token_endpoint
      user_info_endpoint                  = var.authenticate_oidc.user_info_endpoint
    }, {})
  }]

  target_groups = [
    {
      name             = "${module.common.names.resource_type["aws_lb_target_group"].name}-vpce"
      backend_port     = var.lb_backend_port
      target_type      = "ip"
      backend_protocol = "HTTPS"
      targets          = local.targets
    }
  ]

  web_acl_arn = var.web_acl_arn
}


# ---------------------------------------------------------------------------- #
#                                   Endpoints                                  #
# ---------------------------------------------------------------------------- #

module "vpc_endpoint" {
  source = "git::https://atc-github.azure.cloud.bmw/cgbp/terraform-aws-bmw-vpc-endpoints.git?ref=1.1.0"

  cloud_region         = var.cloud_region
  global_config        = var.global_config
  custom_tags          = var.custom_tags
  custom_name          = var.custom_name
  commons_file_json    = var.commons_file_json
  local_file_json_tpl  = var.local_file_json_tpl
  naming_file_json_tpl = var.naming_file_json_tpl

  vpc_id                      = var.public_vpc_id
  create_vpc_endpoint         = true
  create_vpc_endpoint_service = true
  vpc_subnet_ids              = var.public_vpc_subnet_ids

  network_load_balancer_arns = [var.nlb_arn]
  security_group_ids         = [module.sg.sg_id]
}

data "aws_network_interface" "vpce" {
  count = length(var.public_vpc_subnet_ids)
  id    = tolist(module.vpc_endpoint.aws_vpc_endpoint_network_interface_ids)[count.index]
}


# --------------------------------------------------------------------------------------------------



module "sg_nlb" {
  source        = "git::https://atc-github.azure.cloud.bmw/cgbp/terraform-aws-bmw-sg.git?ref=1.3.0"
  cloud_region  = var.cloud_region
  global_config = var.global_config
  custom_name   = "20adv"
  vpc_id        = var.vpc_id

  # Allow LB Traffic from VPC
  ingress_rules = {
    https = {
      service          = "https"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = null
    }
  }
  egress_rules = {
    dns = {
      service          = "dns"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
    },
    https = {
      service          = "https"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
    }
  }
}

# Local variables to set BMW Proxy settings, so machines able to connect to internet etc.
data "template_file" "user_data" {
  template = file("./common/user_data.tpl")
  vars = {
    config     = file("./common/nginx_https.conf")
    index      = file("./common/index.html")
    server_key = file("./common/privateKey.key")
    server_crt = file("./common/certificate.crt")
  }
}
#################################
# SSM Instance profile
# https://www.terraform.io/docs/providers/aws/r/iam_instance_profile.html
resource "aws_iam_instance_profile" "asg" {
  name = module.common.names.resource_type["aws_iam_instance_profile"].name
  role = aws_iam_role.default.name
  path = "/"
  tags = module.common.tags
}

# https://www.terraform.io/docs/providers/aws/r/iam_role.html
resource "aws_iam_role" "default" {
  name               = module.common.names.resource_type["aws_iam_role"].name
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
  path               = "/"
  description        = "IAM role for ${module.common.names.resource_type["aws_iam_role"].name} EC2 session-manager"
  tags               = merge({ "Name" = "${module.common.names.resource_type["aws_iam_role"].name}" }, module.common.tags)
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# https://www.terraform.io/docs/providers/aws/r/iam_policy.html
resource "aws_iam_policy" "default" {
  name        = module.common.names.resource_type["aws_iam_policy_document"].name
  policy      = data.aws_iam_policy.default.policy
  path        = "/"
  description = "IAM policy for ${module.common.names.resource_type["aws_iam_policy_document"].name} EC2 session-manager"
}

# https://www.terraform.io/docs/providers/aws/r/iam_role_policy_attachment.html
resource "aws_iam_role_policy_attachment" "default" {
  role       = aws_iam_role.default.name
  policy_arn = aws_iam_policy.default.arn
}

data "aws_iam_policy" "default" {
  arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
#################################

module "asg" {
  source        = "git::https://atc-github.azure.cloud.bmw/cgbp/terraform-aws-bmw-autoscaling.git?ref=2.2.14"
  cloud_region  = var.cloud_region
  global_config = var.global_config
  custom_name   = "asg20"

  vpc_subnet_ids    = var.vpc_subnet_ids
  instance_type     = "t2.micro"
  security_groups   = [module.sg_nlb.sg_id]
  health_check_type = "ELB"
  min_size          = 2
  max_size          = 4
  #The Base64-encoded user data to provide when launching the instance. You should use this for Launch Templates instead user_data
  user_data                = data.template_file.user_data.rendered
  iam_instance_profile_arn = resource.aws_iam_instance_profile.asg.arn
}

module "nlb" {
  source = "git::https://atc-github.azure.cloud.bmw/cgbp/terraform-aws-bmw-elb.git?ref=2.6.0"
  cloud_region                     = var.cloud_region
  global_config                    = var.global_config
  custom_name                      = "pr20"
  load_balancer_type               = "network"
  enable_deletion_protection       = false
  enable_cross_zone_load_balancing = true
  vpc_id                           = var.vpc_id
  subnets                          = var.vpc_subnet_ids

  target_groups = [
    {
      name             = "target-to-autoscaling-group-ex20"
      backend_protocol = "TCP"
      backend_port     = 443
      target_type      = "instance"
    }
  ]

  http_tcp_listeners = [
    {
      port               = 443
      protocol           = "TCP"
      target_group_index = 0
    }
  ]
}

resource "aws_autoscaling_attachment" "asg" {
  autoscaling_group_name = module.asg.autoscaling_group_name
  lb_target_group_arn    = module.nlb.target_group_arns[0]
}


################################################################################
# WAF
################################################################################

#Contains zero or more IP addresses or blocks of IP addresses specified in
#Classless Inter-Domain Routing (CIDR) notation.
resource "aws_wafv2_ip_set" "this" {
  name               = "20-mucproxy"
  description        = "All"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = ["160.46.252.0/25"]
}

#Define a collection of rules to use to inspect and control web requests.
resource "aws_wafv2_web_acl" "this" {
  #checkov:skip=CKV2_AWS_31:Logging Configuration done using Public Ingress module.
  name        = "20-bmw-proxy-muc-ip-public-ingress"
  description = "Allows access from BMW Proxy.muc IPs"
  scope       = "REGIONAL"

  default_action {
    block {}
  }

  rule {
    name     = "bmw-proxy-muc-ip-rule"
    priority = 2

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.this.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "bmw-proxy-muc-ip-rule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "log4j-rule"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "bmw-proxy-muc-ip"
    sampled_requests_enabled   = true
  }
}

# ============================================================================ #
#                                  Certificate                                 #
# ============================================================================ #

# Creates a private key in PEM format
resource "tls_private_key" "private_key" {
  algorithm = "RSA"
}

# Generates a TLS self-signed certificate using the private key
resource "tls_self_signed_cert" "self_signed_cert" {
  private_key_pem = tls_private_key.private_key.private_key_pem

  validity_period_hours = 48

  subject {
    # The subject CN field here contains the hostname to secure
    common_name = "*.${var.public_dns_zone_name}"
  }

  allowed_uses = ["key_encipherment", "digital_signature", "server_auth"]
}
resource "aws_acm_certificate" "this" {
  private_key      = tls_private_key.private_key.private_key_pem
  certificate_body = tls_self_signed_cert.self_signed_cert.cert_pem

  tags = merge({ "Name" = "CNA-DEMO-CERT-SELF" })
  lifecycle {
    create_before_destroy = true
  }
}

module "public_ingress" {
  source = "../.."

  cloud_region  = var.cloud_region
  global_config = var.global_config
  custom_name   = "pb20"

  nlb_arn = module.nlb.lb_arn

  public_vpc_id          = var.public_vpc_id
  public_vpc_subnet_ids  = var.public_vpc_subnet_ids
  public_dns_zone_name   = var.public_dns_zone_name
  public_dns_zone_record = "ingress-ex20.dev"

  certificate_arn = aws_acm_certificate.this.arn
  web_acl_arn     = [aws_wafv2_web_acl.this.arn]

  waf_logs_identifier_name   = lower("${var.global_config.customer_prefix}-${var.global_config.env}-${var.cloud_region}-${var.global_config.product_id}-${var.global_config.app_name}")
  waf_logs_logging_account   = "104485279185"
  lb_logs_access_logs_prefix = "pbl"
}
