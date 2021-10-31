provider "aws" {
  region = local.region
  # Make it faster by skipping something
  skip_get_ec2_platforms      = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_requesting_account_id  = true
}

locals {
  name   = "example-ec2-complete"
  region = "us-east-1"

  user_data = <<-EOT
  #!/bin/bash
  echo "Hello Terraform!"
  EOT

  asg_user_data = <<-EOT
  #!/bin/bash
  # get admin privileges
  sudo su
  # install httpd (Linux 2 version)
  yum update -y
  yum install -y httpd.x86_64
  systemctl start httpd.service
  systemctl enable httpd.service
  echo "Hello World from $(hostname -f)" > /var/www/html/index.html
  EOT

  asgtags = [
    {
      key                 = "Project"
      value               = "megasecret"
      propagate_at_launch = true
    },
    {
      key                 = "foo"
      value               = ""
      propagate_at_launch = true
    },
  ]

  tags = {
    Owner       = "user"
    Environment = "dev"
  }
    tags_as_map = {
    Owner       = "user"
    Environment = "dev"
  }
  bucket_name = "s3-bucket-${random_pet.this.id}"
}

################################################################################
# Supporting Resources
################################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 3.0"

  #name = local.name
  name = "my-vpc"  
  #cidr = "10.99.0.0/18"
  cidr = "10.1.0.0/16"


  #azs              = ["${local.region}a", "${local.region}b", "${local.region}c"]
  azs              = ["${local.region}a", "${local.region}b"]
  #public_subnets   = ["10.99.0.0/24", "10.99.1.0/24", "10.99.2.0/24"]
  public_subnets  = ["10.1.0.0/24", "10.1.1.0/24"]
  #private_subnets  = ["10.99.3.0/24", "10.99.4.0/24", "10.99.5.0/24"]
  private_subnets = ["10.1.2.0/24", "10.1.3.0/24"]
  #database_subnets = ["10.99.7.0/24", "10.99.8.0/24", "10.99.9.0/24"]

  manage_default_route_table = true
  default_route_table_tags   = { DefaultRouteTable = true }

  enable_dns_hostnames = true
  enable_dns_support   = true
  enable_nat_gateway = true
  single_nat_gateway = true

  tags = local.tags

}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ami-hvm-*-x86_64-gp2"]
  }
}

module "security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 4.0"

  name        = local.name
  description = "Security group for example usage with EC2 instance"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp", "all-icmp"]
  egress_rules        = ["all-all"]

  tags = local.tags
}
/*
resource "aws_placement_group" "web" {
  name     = local.name
  strategy = "cluster"
}
*/
#resource "aws_kms_key" "this" {}

resource "aws_network_interface" "this" {
  subnet_id = element(module.vpc.private_subnets, 0)
}

module "ec2_complete" {
  source = "terraform-aws-modules/ec2-instance/aws"

  name = local.name

  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t2.micro"
  key_name                    = "user1"
  availability_zone           = element(module.vpc.azs, 1)
  subnet_id                   = element(module.vpc.public_subnets, 1)
  vpc_security_group_ids      = [module.security_group.security_group_id]
  #placement_group             = aws_placement_group.web.id
  associate_public_ip_address = true

# only one of these can be enabled at a time
  #hibernation = true
  # enclave_options_enabled = true

  user_data_base64 = base64encode(local.user_data)

  #cpu_core_count       = 2 # default 4
  #cpu_threads_per_core = 1 # default 2

  capacity_reservation_specification = {
    capacity_reservation_preference = "open"
  }

  enable_volume_tags = false
  root_block_device = [
    {
      #encrypted   = true
      volume_type = "gp3"
      throughput  = 200
      volume_size = 20
      tags = {
        Name = "my-root-block"
      }
    },
  ]

  ebs_block_device = [
    {
      device_name = "/dev/sdf"
      volume_type = "gp3"
      volume_size = 20
      throughput  = 200
      #encrypted   = true
      #kms_key_id  = aws_kms_key.this.arn
    }
  ]

  tags = local.tags
}

module "asg_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 4.0"

  name        = local.name
  description = "A security group"
  vpc_id      = module.vpc.vpc_id

  computed_ingress_with_source_security_group_id = [
    {
      rule                     = "http-80-tcp"
      source_security_group_id = module.alb_http_sg.security_group_id
    }
  ]
  number_of_computed_ingress_with_source_security_group_id = 1

  egress_rules = ["all-all"]

  tags = local.tags_as_map
}

resource "aws_iam_service_linked_role" "autoscaling" {
  aws_service_name = "autoscaling.amazonaws.com"
  description      = "A service linked role for autoscaling"
  custom_suffix    = local.name

  # Sometimes good sleep is required to have some IAM resources created before they can be used
  provisioner "local-exec" {
    command = "sleep 10"
  }
}

resource "aws_iam_instance_profile" "ssm" {
  name = "complete-${local.name}"
  role = aws_iam_role.ssm.name
  tags = local.tags_as_map
}

resource "aws_iam_role" "ssm" {
  name = "complete-${local.name}"
  tags = local.tags_as_map

  assume_role_policy = <<-EOT
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  }
  EOT
}

module "alb_http_sg" {
  source  = "terraform-aws-modules/security-group/aws//modules/http-80"
  version = "~> 4.0"

  name        = "${local.name}-alb-http"
  vpc_id      = module.vpc.vpc_id
  description = "Security group for ${local.name}"

  ingress_cidr_blocks = ["0.0.0.0/0"]

  tags = local.tags_as_map
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 6.0"

  name = local.name

  vpc_id          = module.vpc.vpc_id
  #subnets        = module.vpc.public_subnets
  subnets        = module.vpc.private_subnets
  #subnets         = [element(module.vpc.private_subnets, 1)]
  security_groups = [module.alb_http_sg.security_group_id]

  http_tcp_listeners = [
    {
      port               = 80
      protocol           = "HTTP"
      target_group_index = 0
    }
  ]

  target_groups = [
    {
      name             = local.name
      backend_protocol = "HTTP"
      backend_port     = 80
      target_type      = "instance"
    },
  ]

  tags = local.tags_as_map
}

module "default_lt" {
  source = "HDE/autoscaling/aws"

  # Autoscaling group
  name = "default-lt-${local.name}"

  #vpc_zone_identifier = module.vpc.public_subnets
  vpc_zone_identifier = module.vpc.private_subnets
  #vpc_zone_identifier = [element(module.vpc.private_subnets, 1)]
  min_size            = 2
  max_size            = 6
  desired_capacity    = 2

  # Launch template
  use_lt    = true
  create_lt = true

  image_id      = data.aws_ami.amazon_linux.id
  instance_type = "t2.micro"
  key_name      = "user1"
  user_data_base64  = base64encode(local.asg_user_data)

  target_group_arns = module.alb.target_group_arns

  block_device_mappings = [
    {
      # Root volume
      device_name = "/dev/xvda"
      no_device   = 0
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 20
        volume_type           = "gp2"
      }
      }, {
      device_name = "/dev/sda1"
      no_device   = 1
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 20
        volume_type           = "gp2"
      }
    }
  ]


  tags        = local.asgtags
  tags_as_map = local.tags_as_map
}

resource "random_pet" "this" {
  length = 2
}

resource "aws_iam_role" "this" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

data "aws_iam_policy_document" "bucket_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.this.arn]
    }

    actions = [
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::${local.bucket_name}",
    ]
  }
}

module "s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"

  bucket        = local.bucket_name
  acl           = "private"
  force_destroy = true

  attach_policy = true
  policy        = data.aws_iam_policy_document.bucket_policy.json

  attach_deny_insecure_transport_policy = true

  tags = {
    Owner = "s3test"
  }

  versioning = {
    enabled = true
  }

  lifecycle_rule = [
    {
      id      = "log"
      enabled = true
      prefix  = "log/"

      tags = {
        rule      = "log"
        autoclean = "true"
      }

      expiration = {
        days = 90
      }

      noncurrent_version_expiration = {
        days = 90
      }
    },
    {
      id                                     = "images"
      enabled                                = true
      prefix                                 = "images/"
      abort_incomplete_multipart_upload_days = 7

      noncurrent_version_transition = [
        {
          days          = 90
          storage_class = "GLACIER"
        },
      ]

      noncurrent_version_expiration = {
        days = 91
      }
    },
  ]


  # S3 bucket-level Public Access Block configuration
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  # S3 Bucket Ownership Controls
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"
}