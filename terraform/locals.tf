locals {
  targets = {
    for index, network_interface in data.aws_network_interface.vpce[*].private_ip : join(".", [index, "vpce"]) => { target_id = network_interface }
  }

  central_s3_waf_logs = "arn:aws:s3:::aws-waf-logs-${var.waf_logs_logging_account}-${var.cloud_region}"
}

