resource "aws_security_group" "alb_dev" {
  vpc_id      = local.public_vpc_id
  name        = "alb_dev"
  description = "Allow from outside to ALB and to DEV inbound traffic"


  ingress {
    description      = "allow_from_outside"
    from_port        = 8080
    to_port          = 8080
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }


  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_from_outside"
  }
}