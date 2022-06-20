# route53 zone for simtooreal
resource "aws_route53_zone" "zone_deus_live" {
  name = "deus.live"
}

# route53 record for database so that no long database endpoints need to be remembered
resource "aws_route53_record" "record_database_deus_live" {
  name    = "database.deus.live"
  zone_id = aws_route53_zone.zone_deus_live.id
  type    = "CNAME"
  ttl     = 30

  records = [aws_rds_cluster.simtooreal.endpoint]
}

# route53 record for private EC2 instance so that no long ip addresses need to be remembered
resource "aws_route53_record" "record_private_deus_live" {
  name    = "private.deus.live"
  zone_id = aws_route53_zone.zone_deus_live.id
  type    = "A"
  ttl     = 30

  records = [aws_instance.simtooreal_private.private_ip]
}

# route53 record for public EC2 instance so that no long ip addresses need to be remembered
resource "aws_route53_record" "record_public_deus_live" {
  name    = "public.deus.live"
  zone_id = aws_route53_zone.zone_deus_live.id
  type    = "A"
  ttl     = 30

  records = [aws_instance.simtooreal_public.public_ip]
}

# route53 record for short url
resource "aws_route53_record" "short_deus_live" {
  name    = "deus.live"
  zone_id = aws_route53_zone.zone_deus_live.id
  type    = "A"

  alias {
    name                   = aws_lb.simtooreal.dns_name
    zone_id                = aws_lb.simtooreal.zone_id
    evaluate_target_health = true
  }
}

# route53 record for full url
resource "aws_route53_record" "deus_live" {
  name    = "www.deus.live"
  zone_id = aws_route53_zone.zone_deus_live.id
  type    = "A"

  alias {
    name                   = aws_lb.simtooreal.dns_name
    zone_id                = aws_lb.simtooreal.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "deus_live_mx" {
  zone_id = aws_route53_zone.zone_deus_live.id
  name    = "deus.live"
  type    = "MX"

  records = [
    "1 ASPMX.L.GOOGLE.COM",
    "5 ALT1.ASPMX.L.GOOGLE.COM",
    "5 ALT2.ASPMX.L.GOOGLE.COM",
    "10 ALT3.ASPMX.L.GOOGLE.COM",
    "10 ALT4.ASPMX.L.GOOGLE.COM",
  ]

  ttl = 60
}

resource "aws_route53_record" "deus_txt_txt" {
  zone_id = aws_route53_zone.zone_deus_live.id
  name    = "deus.live"
  type    = "TXT"

  records = [
    "google-site-verification=61Exwgsm5YaTH7UBODn-rnEC-ussrNrrLE69yzQqrJ8",
    "google-site-verification=oHevX9OzCBICu005GizU61VVYMby2BH1KfsmoOHob-Q"
  ]

  ttl = 60
}

# deus_live certificate managed by Terraform
resource "aws_acm_certificate" "deus_live" {
  domain_name               = "*.deus.live"
  validation_method         = "DNS"
  subject_alternative_names = ["deus.live"]

  tags = {
    Description = "deus_live certificate managed by Terraform"
    Name        = "deus_live"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# the listener needs a cert as well
resource "aws_lb_listener_certificate" "deus_live" {
  listener_arn    = aws_lb_listener.deus_live.arn
  certificate_arn = aws_acm_certificate.deus_live.arn
}

# validation record for simtooreal cert
resource "aws_route53_record" "deus_live_validation" {
  name    = sort(aws_acm_certificate.deus_live.domain_validation_options[*].resource_record_name)[0]
  type    = sort(aws_acm_certificate.deus_live.domain_validation_options[*].resource_record_type)[0]
  records = [sort(aws_acm_certificate.deus_live.domain_validation_options[*].resource_record_value)[0]]
  zone_id = aws_route53_zone.zone_deus_live.id
  ttl     = "300"
}

# cert for deus_live
resource "aws_acm_certificate_validation" "deus_live" {
  certificate_arn         = aws_acm_certificate.deus_live.arn
  validation_record_fqdns = [aws_route53_record.deus_live_validation.fqdn]
}

### IAM/ECR

# ecr for holding all images
resource "aws_ecr_repository" "simtooreal" {
  name                 = "simtooreal"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# ecr admin role for simtooreal
resource "aws_iam_user" "simtooreal_ecr_admin" {
  name = "simtooreal_ecr_admin"

  tags = {
    tag-key = "simtooreal"
  }
}

# ecr admin policy for simtooreal
resource "aws_iam_user_policy" "simtooreal_ecr_admin" {
  name = "simtooreal_ecr_admin"
  user = aws_iam_user.simtooreal_ecr_admin.name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "ecr:*",
            "Resource": "*"
        }
    ]
}
EOF
}

# instance profile for reading s3 from an EC2 instance
# which could be useful for a bastion or prepoluating instances with files
resource "aws_iam_instance_profile" "simtooreal_s3_public_read" {
  name = "simtooreal_s3_public_read"
}

resource "aws_iam_instance_profile" "simtooreal_s3_private_read" {
  name = "simtooreal_s3_private_read"
}

# instance profile for ecs
resource "aws_iam_instance_profile" "simtooreal_ecs" {
  name = "simtooreal_ecs"
}

# task execution ecs role for simtooreal
resource "aws_iam_role" "simtooreal_ecs_task_execution" {
  name = "simtooreal_ecs_task_execution"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ecs-tasks.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF

  # this is necessary for hosting database passwords and hosts in AWS Systems Manager
  # for convenience and so passwords are less likely to be stored on local machines
  inline_policy {
    name = "my_inline_policy"

    policy = jsonencode({
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "ssm:GetParameters"
          ],
          "Resource" : [
            "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/POSTGRESQL_HOST",
            "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/POSTGRESQL_PASSWORD",
            "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/OPENAI_API_KEY",
            "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/REPLICATE_API_TOKEN",
            "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/REACT_APP_URL_BACKEND",
            "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/REACT_APP_URL_FRONTEND",
            "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/POSTGRESQL_USER_NAME",
            "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/POSTGRESQL_DB",
            "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/LISTEN_ON_FRONTEND",
            "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/LISTEN_ON"
          ]
        }
      ]
    })
  }
}

# s3 reading role for ECS tasks
resource "aws_iam_role" "simtooreal_s3_read" {
  name = "simtooreal_s3_read"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ecs-tasks.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

# ECS task role
resource "aws_iam_role" "simtooreal_ecs" {
  name = "simtooreal_ecs"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ecs-tasks.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

# ECS task execution role policy attachment
resource "aws_iam_role_policy_attachment" "simtooreal_ecs_task_execution" {
  role       = aws_iam_role.simtooreal_ecs_task_execution.name
  policy_arn = aws_iam_policy.simtooreal_ecs_task_execution.arn
}

# ECS task  role policy attachment
resource "aws_iam_role_policy_attachment" "simtooreal_ecs" {
  role       = aws_iam_role.simtooreal_ecs.name
  policy_arn = aws_iam_policy.simtooreal_ecs.arn
}

# role policy attachment for reading s3
resource "aws_iam_role_policy_attachment" "simtooreal_s3_public_read" {
  role       = aws_iam_role.simtooreal_s3_read.name
  policy_arn = aws_iam_policy.simtooreal_s3_public_read.arn
}

# role policy attachment for reading s3
resource "aws_iam_role_policy_attachment" "simtooreal_s3_private_read" {
  role       = aws_iam_role.simtooreal_s3_read.name
  policy_arn = aws_iam_policy.simtooreal_s3_private_read.arn
}

# IAM policy for task execution
resource "aws_iam_policy" "simtooreal_ecs_task_execution" {
  name        = "simtooreal_ecs_task_execution"
  description = "Policy to allow ECS to execute tasks"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:CreateLogGroup",
                "logs:DescribeLogGroups"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

# IAM policy for reading s3 in simtooreal
resource "aws_iam_policy" "simtooreal_s3_public_read" {
  name        = "simtooreal_s3_public_read"
  description = "Policy to allow S3 reading of bucket simtooreal-public"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "ssm:GetParametersByPath",
                "ssm:GetParameters",
                "ssm:GetParameter"
            ],
            "Resource": [
                "arn:aws:s3:::simtooreal-public/*"
            ]
        }
    ]
}
EOF
}

# IAM policy for reading s3 in simtooreal
resource "aws_iam_policy" "simtooreal_s3_private_read" {
  name        = "simtooreal_s3_private_read"
  description = "Policy to allow S3 reading of bucket simtooreal-private and ssm"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "ssm:GetParametersByPath",
                "ssm:GetParameters",
                "ssm:GetParameter"
            ],
            "Resource": [
                "arn:aws:s3:::simtooreal-private/*",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/AWS_ACCESS_KEY_ID",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/AWS_SECRET_ACCESS_KEY",
                "arn:aws:ssm:${var.aws_region}:*:parameter/parameter/production/OPENAI_API_KEY"
            ]
        }
    ]
}
EOF
}

# IAM policy for ECS
resource "aws_iam_policy" "simtooreal_ecs" {
  name        = "simtooreal_ecs"
  description = "Policy to allow ECS access"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeTags",
                "ecs:CreateCluster",
                "ecs:DeregisterContainerInstance",
                "ecs:DiscoverPollEndpoint",
                "ecs:Poll",
                "ecs:RegisterContainerInstance",
                "ecs:StartTelemetrySession",
                "ecs:UpdateContainerInstancesState",
                "ecs:Submit*",
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:CreateLogGroup",
                "logs:DescribeLogGroups"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

### Networking and subnets

# AWS VPC for simtooreal
resource "aws_vpc" "simtooreal" {
  cidr_block           = "172.17.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Description = "Scalable AI platform"
    Environment = "production"
    Name        = "simtooreal"
  }
}

# Fetch Availability Zones in the current region
data "aws_availability_zones" "simtooreal" {
}

# Create var.az_count private subnets, each in a different AZ
resource "aws_subnet" "simtooreal_private" {
  count             = var.az_count
  cidr_block        = cidrsubnet(aws_vpc.simtooreal.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.simtooreal.names[count.index]
  vpc_id            = aws_vpc.simtooreal.id

  tags = {
    Description = "Scalable AI platform"
    Environment = "production"
  }
}

# Create var.az_count public subnets, each in a different AZ
resource "aws_subnet" "simtooreal_public" {
  count = var.az_count
  cidr_block = cidrsubnet(
    aws_vpc.simtooreal.cidr_block,
    8,
    var.az_count + count.index,
  )
  availability_zone       = data.aws_availability_zones.simtooreal.names[count.index]
  vpc_id                  = aws_vpc.simtooreal.id
  map_public_ip_on_launch = true

  tags = {
    Description = "simtooreal public subnet managed by Terraform"
    Environment = "production"
  }
}

# Create var.az_count rds subnets, each in a different AZ
resource "aws_subnet" "simtooreal_rds" {
  count = var.az_count
  cidr_block = cidrsubnet(
    aws_vpc.simtooreal.cidr_block,
    8,
    2 * var.az_count + 1 + count.index,
  )
  availability_zone = data.aws_availability_zones.simtooreal.names[count.index]
  vpc_id            = aws_vpc.simtooreal.id

  tags = {
    Description = "simtooreal RDS subnet managed by Terraform"
    Environment = "production"
  }
}

# IGW for the public subnet
resource "aws_internet_gateway" "simtooreal" {
  vpc_id = aws_vpc.simtooreal.id
}

# Route the public subnet traffic through the IGW
resource "aws_route" "simtooreal_internet_access" {
  route_table_id         = aws_vpc.simtooreal.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.simtooreal.id
}

# Create a NAT gateway with an EIP for each private subnet to get internet connectivity
resource "aws_eip" "simtooreal" {
  count      = var.az_count
  vpc        = true
  depends_on = [aws_internet_gateway.simtooreal]

  tags = {
    Description = "simtooreal gateway EIP managed by Terraform"
    Environment = "production"
  }
}

# NAT gateway for internet access
resource "aws_nat_gateway" "simtooreal" {
  count         = var.az_count
  subnet_id     = element(aws_subnet.simtooreal_public.*.id, count.index)
  allocation_id = element(aws_eip.simtooreal.*.id, count.index)

  tags = {
    Description = "simtooreal gateway NAT managed by Terraform"
    Environment = "production"
  }
}

# Create a new route table for the private subnets
# And make it route non-local traffic through the NAT gateway to the internet
resource "aws_route_table" "simtooreal_private" {
  count  = var.az_count
  vpc_id = aws_vpc.simtooreal.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = element(aws_nat_gateway.simtooreal.*.id, count.index)
  }

  tags = {
    Description = "simtooreal gateway NAT managed by Terraform"
    Environment = "production"
  }
}

# RDS route table for simtooreal
resource "aws_route_table" "simtooreal_rds" {
  count  = var.az_count
  vpc_id = aws_vpc.simtooreal.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = element(aws_nat_gateway.simtooreal.*.id, count.index)
  }

  tags = {
    Description = "simtooreal RDS route table managed by Terraform"
    Environment = "production"
  }
}

# Explicitely associate the newly created route tables to the private subnets (so they don't default to the main route table)
resource "aws_route_table_association" "simtooreal_private" {
  count          = var.az_count
  subnet_id      = element(aws_subnet.simtooreal_private.*.id, count.index)
  route_table_id = element(aws_route_table.simtooreal_private.*.id, count.index)
}

resource "aws_route_table_association" "rsimtooreal_rds" {
  count          = var.az_count
  subnet_id      = element(aws_subnet.simtooreal_rds.*.id, count.index)
  route_table_id = element(aws_route_table.simtooreal_rds.*.id, count.index)
}

### RDS

# subnet used by rds
resource "aws_db_subnet_group" "simtooreal" {
  name        = "simtooreal"
  description = "simtooreal RDS Subnet Group managed by Terraform"
  subnet_ids  = aws_subnet.simtooreal_rds.*.id
}

# Security Group for resources that want to access the database
resource "aws_security_group" "simtooreal_db_access" {
  vpc_id      = aws_vpc.simtooreal.id
  name        = "simtooreal_db_access"
  description = "simtooreal allow access to RDS, managed by Terraform"

  ingress {
    # TLS (change to whatever ports you need)
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.simtooreal.cidr_block]
  }
}

# database security group
resource "aws_security_group" "simtooreal_rds" {
  name        = "simtooreal_rds"
  description = "simtooreal RDS security group, managed by Terraform"
  vpc_id      = aws_vpc.simtooreal.id

  //allow traffic for TCP 5432
  ingress {
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = aws_security_group.simtooreal_ecs.*.id
  }

  // outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# database cluster instances for simtooreal
resource "aws_rds_cluster_instance" "simtooreal" {
  # WARNING: Setting count to anything less than 2 reduces
  # the reliability of your system, many times an instance
  # failure has occured requiring a hot switch to a
  # secondary instance, if there is nothing to switch to
  # you may regret setting count to 1, consider reliability
  # and weigh it against infrastructure cost
  count                = 1
  cluster_identifier   = aws_rds_cluster.simtooreal.id
  instance_class       = "db.r4.large"
  db_subnet_group_name = aws_db_subnet_group.simtooreal.name
  engine               = "aurora-postgresql"
  engine_version       = "12.8"
}

# database cluster for simtooreal
resource "aws_rds_cluster" "simtooreal" {
  cluster_identifier = "simtooreal"
  #availability_zones        = ["us-east-1a", "us-east-1b", "us-east-1c"]
  database_name             = "simtooreal"
  master_username           = "postgres"
  master_password           = var.db_password
  db_subnet_group_name      = aws_db_subnet_group.simtooreal.name
  engine                    = "aurora-postgresql"
  engine_version            = "12.8"
  vpc_security_group_ids    = [aws_security_group.simtooreal_rds.id]
  skip_final_snapshot       = "true"
  final_snapshot_identifier = "foo"
  storage_encrypted         = "true"
  #snapshot_identifier      = "simtooreal"
}

### Elasticache

# Security Group for resources that want to access redis
resource "aws_security_group" "simtooreal_redis_access" {
  vpc_id      = aws_vpc.simtooreal.id
  name        = "simtooreal_redis_access"
  description = "simtooreal redis access security group managed by Terraform"

  ingress {
    # TLS (change to whatever ports you need)
    from_port = 6379
    to_port   = 6379
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.simtooreal.cidr_block]
  }
}

resource "aws_security_group" "simtooreal_redis" {
  name        = "simtooreal_redis"
  vpc_id      = aws_vpc.simtooreal.id
  description = "simtooreal Redis Security Group managed by Terraform"

  //allow traffic for TCP 6379
  ingress {
    from_port = 6379
    to_port   = 6379
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = aws_security_group.simtooreal_ecs.*.id
  }

  // outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# public security group for load balancers and bastions
resource "aws_security_group" "simtooreal_public" {
  name        = "simtooreal_public"
  description = "simtooreal public security group managed by Terraform"
  vpc_id      = aws_vpc.simtooreal.id

  # allows ssh attempts from my IP address
  # you should change this to your IP address
  # or your corporate network
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["76.231.26.199/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

### Elasticache

# # elasticache for simtooreal
# resource "aws_elasticache_subnet_group" "simtooreal" {
#   name       = "simtooreal"
#   subnet_ids = aws_subnet.simtooreal_private.*.id
# }

# # elasticache cluster for simtooreal
# resource "aws_elasticache_cluster" "simtooreal" {
#   cluster_id           = "simtooreal"
#   engine               = "redis"
#   node_type            = "cache.m5.large"
#   port                 = 6379
#   num_cache_nodes      = 1
#   security_group_ids   = [aws_security_group.simtooreal_redis.id]
#   subnet_group_name    = aws_elasticache_subnet_group.simtooreal.name
#   parameter_group_name = aws_elasticache_parameter_group.simtooreal.name
# }

# # elasticache parameter group for simtooreal
# resource "aws_elasticache_parameter_group" "simtooreal" {
#   name   = "redis-28-simtooreal"
#   family = "redis6.x"

#   parameter {
#     name  = "timeout"
#     value = "500"
#   }
# }

### AWS instances

resource "aws_key_pair" "simtooreal" {
  key_name   = "simtooreal"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC60teZFO7BuQVwHSUewqOFGo7Iko16pF/vpio8p0K4PR29KG4oaKd4lRHx0WwX5NlLTxEI5xXQWAN9sRQMz60UDnURKnGbjiy+QI/mL3Ivkt4YV6gEfGYdVChJE6bYpnmUbPn8e27JcIJkBcDEATTEZEvSWi8xNhXWOr3I4m/Jc7OOOZAk7R9roqFlsNQrOCizc543PxCLLKafwFcDNUg+h8EOO3+PVZJziAllRTx53WxYbOUZ1tSXwaiJkXSLhVmSZQU6gXuzjlUe2ZAYwW9XzQj8xvPjFJIgizJthnbFxiAn6BygM+/4YdT+SjdpG1Y3NamXgBPQPKWFX8vBkwxVIGywDqpMVlI8L1DgbU4ISVmkHj+kG8t7iX9NF73fG9M414SBpIZSO7lsXz5rHqoz7VZe5DDl5piVV/thXwaAMMm1kerF1GlWcvUxsABv4yD2DnuqMVPz77dP1abOVpRTr7NcSvQCFv4vcMO+0CAGO/RIn3vYawjLvBFEeICsd35mnWF+PDg4QiSycJpUX9wFnZKsbI+pOEfexHqseuiS+PTOgROVonC7PUzYjFbxT3SRKRsiJxNxmRtbaEjWXZpsEFjDb/ifs9K06mqTF6MqFYXVs4AhTxDuhqQ9EOBg/LG+JUIj76o4cl7VkUJxhYyP9MNO1Ze6AVl7/xmzigsEFQ== chase.brignac@example.com"
}

# public facing instance through which maintenance work is done
# t3a.micro has enough memory to run a Duo bastion but t3a.nano will save money
resource "aws_instance" "simtooreal_public" {
  ami                         = "ami-0fa37863afb290840"
  instance_type               = "t3a.micro"
  subnet_id                   = aws_subnet.simtooreal_public[0].id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.simtooreal_s3_public_read.name
  vpc_security_group_ids      = [aws_security_group.simtooreal_public.id]
  key_name                    = aws_key_pair.simtooreal.key_name
  depends_on                  = [aws_s3_object.simtooreal_public]
  user_data                   = "#!/bin/bash\necho $USER\ncd /home/ubuntu\npwd\necho beginscript\nexport AWS_ACCESS_KEY_ID=${aws_ssm_parameter.simtooreal_aws_access_key_id.value}\nexport AWS_SECRET_ACCESS_KEY=${aws_ssm_parameter.simtooreal_secret_access_key.value}\necho $AWS_SECRET_ACCESS_KEY\necho $AWS_ACCESS_KEY_ID\nexport AWS_DEFAULT_REGION=us-east-1\nsudo apt-get update -y\nsudo apt-get install awscli -y\nsudo apt-get install awscli -y\naws s3 cp s3://simtooreal-public/bastion.tar.gz ./\napt-get remove docker docker-engine docker-ce docker.io\napt-get install -y apt-transport-https ca-certificates curl software-properties-common\ncurl -fsSL https://download.docker.com/linux/ubuntu/gpg  | apt-key add -\nadd-apt-repository 'deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable'\napt-get -y install docker-ce\nsystemctl start docker\napt-get install -y docker-compose\nsystemctl enable docker\ntar -zxvf bastion.tar.gz\ncd bastion/examples/compose\ndocker-compose up --build"
  # to troubleshoot your user_data logon to the instance and run this
  #cat /var/log/cloud-init-output.log

  root_block_device {
    volume_size = "20"
    volume_type = "standard"
  }

  # lifecycle {
  #   ignore_changes = [user_data]
  # }

  tags = {
    Name = "simtooreal_public"
  }
}

# private instance inside the private subnet
# reaching RDS is done through this instance
resource "aws_instance" "simtooreal_private" {
  # These can be ecs optimized AMI if Amazon Linux OS is your thing
  # or you can even add an ECS compatible AMI, update instance type to t2.2xlarge
  # add to the user_data "ECS_CLUSTER= simtooreal >> /etc/ecs/ecs.config"
  # and add the iam_instance_profile of aws_iam_instance_profile.simtooreal_ecs.name
  # and you would then be able to use this instance in ECS
  ami           = "ami-0fa37863afb290840"
  instance_type = "t2.nano"
  subnet_id     = aws_subnet.simtooreal_private[0].id

  vpc_security_group_ids = [aws_security_group.simtooreal_ecs.id]
  key_name               = aws_key_pair.simtooreal.key_name
  iam_instance_profile   = aws_iam_instance_profile.simtooreal_s3_private_read.name
  depends_on             = [aws_s3_bucket.simtooreal_private]
  user_data              = "#!/bin/bash\necho $USER\ncd /home/ubuntu\npwd\necho beginscript\nsudo apt-get update -y\nsudo apt-get install awscli -y\necho $USER\necho ECS_CLUSTER=simtooreal > /etc/ecs/ecs.config\napt-add-repository --yes --update ppa:ansible/ansible\napt -y install ansible\napt install postgresql-client-common\napt-get -y install postgresql\napt-get remove docker docker-engine docker-ce docker.io\napt-get install -y apt-transport-https ca-certificates curl software-properties-common\nexport AWS_ACCESS_KEY_ID=${aws_ssm_parameter.simtooreal_aws_access_key_id.value}\nexport AWS_SECRET_ACCESS_KEY=${aws_ssm_parameter.simtooreal_secret_access_key.value}\nexport AWS_DEFAULT_REGION=us-east-1\naws s3 cp s3://simtooreal-private/deus.tar.gz ./\ntar -zxvf deus.tar.gz\nmv simtooreal data\napt install python3-pip -y\napt-get install tmux"
  # to troubleshoot your user_data logon to the instance and run this
  #cat /var/log/cloud-init-output.log

  # lifecycle {
  #   ignore_changes = [user_data]
  # }

  root_block_device {
    volume_size = "100"
    volume_type = "standard"
  }

  tags = {
    Name = "simtooreal_private"
  }
}

### ECS

# ECS service for the backend
resource "aws_ecs_service" "simtooreal_backend" {
  name                 = "simtooreal_backend"
  cluster              = aws_ecs_cluster.simtooreal.id
  task_definition      = aws_ecs_task_definition.simtooreal_backend.family
  desired_count        = var.app_count
  launch_type          = "FARGATE"
  force_new_deployment = true

  network_configuration {
    security_groups = [aws_security_group.simtooreal_ecs.id]
    subnets         = aws_subnet.simtooreal_private.*.id
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.simtooreal_frontend.id
    container_name   = "simtooreal-frontend"
    container_port   = "3000"
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.simtooreal_backend.id
    container_name   = "simtooreal-backend"
    container_port   = "8080"
  }

  depends_on = [aws_lb_listener.deus_live]

  tags = {
    Description = "simtooreal Elastic Container Service managed by Terraform"
    Environment = "production"
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# in case we ever want to start using reserved instances to try and save money
# resource "aws_ecs_service" "simtooreal_backend_reserved" {
#   name            = "simtooreal_backend_reserved"
#   cluster         = aws_ecs_cluster.simtooreal.id
#   task_definition = aws_ecs_task_definition.simtooreal_backend.arn
#   desired_count   = var.app_count
#   launch_type     = "EC2"
#
#   network_configuration {
#     security_groups = [aws_security_group.simtooreal_ecs.id]
#     subnets         = aws_subnet.simtooreal_private.*.id
#   }
#
#   load_balancer {
#     target_group_arn = aws_lb_target_group.simtooreal_backend.id
#     container_name   = "simtooreal_backend"
#     container_port   = "8080"
#   }
#
#   depends_on = [aws_lb_listener.deus_live]
#
#   tags = {
#     Description = "simtooreal reserved Elastic Container Service managed by Terraform"
#     Environment = "production"
#   }
#
#   lifecycle {
#     ignore_changes = [desired_count]
#   }
# }

### Autoscaling

# autoscaling target for simtooreal
resource "aws_appautoscaling_target" "simtooreal_backend" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.simtooreal.name}/${aws_ecs_service.simtooreal_backend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  max_capacity       = var.ecs_autoscale_max_instances
  min_capacity       = 1
}

resource "aws_cloudwatch_metric_alarm" "simtooreal_backend_memory_utilization_high" {
  alarm_name          = "simtooreal_backend_memory_utilization_high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = 30

  dimensions = {
    ClusterName = aws_ecs_cluster.simtooreal.name
    ServiceName = aws_ecs_service.simtooreal_backend.name
  }

  alarm_actions = [aws_appautoscaling_policy.simtooreal_backend_memory_utilization_high.arn]
}

# memory metric alarm
resource "aws_cloudwatch_metric_alarm" "simtooreal_backend_memory_utilization_low" {
  alarm_name          = "simtooreal_backend_memory_utilization_low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = 30

  dimensions = {
    ClusterName = aws_ecs_cluster.simtooreal.name
    ServiceName = aws_ecs_service.simtooreal_backend.name
  }

  alarm_actions = [aws_appautoscaling_policy.simtooreal_backend_memory_utilization_low.arn]
}

# memory metric alarm
resource "aws_appautoscaling_policy" "simtooreal_backend_memory_utilization_high" {
  name               = "simtooreal_backend_memory_utilization_high"
  service_namespace  = aws_appautoscaling_target.simtooreal_backend.service_namespace
  resource_id        = aws_appautoscaling_target.simtooreal_backend.resource_id
  scalable_dimension = aws_appautoscaling_target.simtooreal_backend.scalable_dimension

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 60
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_lower_bound = 0
      scaling_adjustment          = 1
    }
  }
}

# memory metric alarm policy
resource "aws_appautoscaling_policy" "simtooreal_backend_memory_utilization_low" {
  name               = "simtooreal_backend_memory_utilization_low"
  service_namespace  = aws_appautoscaling_target.simtooreal_backend.service_namespace
  resource_id        = aws_appautoscaling_target.simtooreal_backend.resource_id
  scalable_dimension = aws_appautoscaling_target.simtooreal_backend.scalable_dimension

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 300
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_upper_bound = 0
      scaling_adjustment          = -1
    }
  }
}

# backend task definition
resource "aws_ecs_task_definition" "simtooreal_backend" {
  depends_on = [
    aws_lb.simtooreal,
    #aws_elasticache_cluster.simtooreal,
    aws_rds_cluster.simtooreal,
  ]
  family                   = "simtooreal"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 1024
  memory                   = 4096
  execution_role_arn       = aws_iam_role.simtooreal_ecs_task_execution.arn

  container_definitions = jsonencode([
    {
      name      = "simtooreal-backend"
      image     = "923082272114.dkr.ecr.us-east-1.amazonaws.com/simtooreal:backend"
      cpu       = 256
      memory    = 512
      essential = true
      command   = ["app.py"]
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ],
      secrets = [
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/POSTGRESQL_USER_NAME",
          name      = "POSTGRESQL_USER_NAME"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/POSTGRESQL_DB",
          name      = "POSTGRESQL_DB"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/LISTEN_ON",
          name      = "LISTEN_ON"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/POSTGRESQL_HOST",
          name      = "POSTGRESQL_HOST"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/POSTGRESQL_PASSWORD",
          name      = "POSTGRESQL_PASSWORD"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/OPENAI_API_KEY",
          name      = "OPENAI_API_KEY"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/REPLICATE_API_TOKEN",
          name      = "REPLICATE_API_TOKEN"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/REACT_APP_URL_BACKEND",
          name      = "REACT_APP_URL_BACKEND"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/REACT_APP_URL_FRONTEND",
          name      = "REACT_APP_URL_FRONTEND"
        }
      ],
      mountPoints = [],
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = "/ecs/simtooreal-backend",
          awslogs-region        = "us-east-1",
          awslogs-stream-prefix = "ecs",
          awslogs-create-group  = "true"
        }
      },
      volumesFrom = [],
      environment = []
    },
    {
      name      = "simtooreal-frontend"
      image     = "923082272114.dkr.ecr.us-east-1.amazonaws.com/simtooreal:frontend"
      cpu       = 256
      memory    = 2048
      essential = true
      command   = ["npm", "start"]
      portMappings = [
        {
          containerPort = 3000
          hostPort      = 3000
        }
      ],
      secrets = [
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/POSTGRESQL_USER_NAME",
          name      = "POSTGRESQL_USER_NAME"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/POSTGRESQL_DB",
          name      = "POSTGRESQL_DB"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/LISTEN_ON_FRONTEND",
          name      = "LISTEN_ON"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/POSTGRESQL_HOST",
          name      = "POSTGRESQL_HOST"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/POSTGRESQL_PASSWORD",
          name      = "POSTGRESQL_PASSWORD"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/OPENAI_API_KEY",
          name      = "OPENAI_API_KEY"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/REPLICATE_API_TOKEN",
          name      = "REPLICATE_API_TOKEN"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/REACT_APP_URL_BACKEND",
          name      = "REACT_APP_URL_BACKEND"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/parameter/production/REACT_APP_URL_FRONTEND",
          name      = "REACT_APP_URL_FRONTEND"
        }
      ],
      mountPoints = [],
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = "/ecs/simtooreal-frontend",
          awslogs-region        = "us-east-1",
          awslogs-stream-prefix = "ecs",
          awslogs-create-group  = "true"
        }
      },
      volumesFrom = [],
      environment = []
    }
  ])
}

# cloudwatch log group
resource "aws_cloudwatch_log_group" "simtooreal_backend" {
  name              = "/ecs/simtooreal-backend"
  retention_in_days = 30

  tags = {
    Environment = "production"
    Application = "simtooreal"
  }
}

# cloudwatch log group
resource "aws_cloudwatch_log_group" "simtooreal_frontend" {
  name              = "/ecs/simtooreal-frontend"
  retention_in_days = 30

  tags = {
    Environment = "production"
    Application = "simtooreal"
  }
}

# This needs to be integrated completely into our container_definitions of our aws_ecs_task_definition
resource "aws_cloudwatch_log_stream" "simtooreal_backend" {
  name           = "simtooreal"
  log_group_name = aws_cloudwatch_log_group.simtooreal_backend.name
}

# This needs to be integrated completely into our container_definitions of our aws_ecs_task_definition
resource "aws_cloudwatch_log_stream" "simtooreal_frontend" {
  name           = "simtooreal"
  log_group_name = aws_cloudwatch_log_group.simtooreal_frontend.name
}

# ECS cluster for simtooreal
resource "aws_ecs_cluster" "simtooreal" {
  name = "simtooreal"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Traffic to the ECS Cluster should only come from the ALB, DB, or elasticache
resource "aws_security_group" "simtooreal_ecs" {
  name        = "simtooreal_ecs"
  description = "simtooreal Elastic Container Service (ECS) security group managed by Terraform"
  vpc_id      = aws_vpc.simtooreal.id

  ingress {
    protocol  = "tcp"
    from_port = "80"
    to_port   = "80"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = [aws_security_group.simtooreal_lb.id]
  }

  ingress {
    protocol  = "tcp"
    from_port = 3000
    to_port   = 3000

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = [aws_security_group.simtooreal_lb.id]
  }

  ingress {
    protocol  = "tcp"
    from_port = 8080
    to_port   = 8080

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = [aws_security_group.simtooreal_lb.id]
  }

  egress {
    protocol        = "tcp"
    from_port       = "5432"
    to_port         = "5432"
    security_groups = [aws_security_group.simtooreal_db_access.id]
  }

  egress {
    protocol        = "tcp"
    from_port       = "6379"
    to_port         = "6379"
    security_groups = [aws_security_group.simtooreal_redis_access.id]
  }

  ingress {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.simtooreal.cidr_block]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

### ALB

# load balancer for simtooreal
resource "aws_lb" "simtooreal" {
  name            = "simtooreal"
  subnets         = aws_subnet.simtooreal_public.*.id
  security_groups = [aws_security_group.simtooreal_lb.id]
  idle_timeout    = 1800

  tags = {
    Description = "simtooreal Application Load Balancer managed by Terraform"
    Environment = "production"
  }
}

# redirecting https://deus.live/generate* or any other backend url to backend target group
resource "aws_lb_listener_rule" "simtooreal_backend" {
  listener_arn = aws_lb_listener.deus_live.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.simtooreal_backend.arn
  }

  condition {
    path_pattern {
      values = ["/generate*", "/feedback*"]
    }
  }
}

# target group for simtooreal backend
resource "aws_lb_target_group" "simtooreal_backend" {
  name        = "simtooreal-backend"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.simtooreal.id
  target_type = "ip"
  slow_start  = 60

  health_check {
    interval = 60
    timeout  = 10
    path     = "/"
    matcher  = "200"
  }

  tags = {
    Description = "simtooreal Application Load Balancer target group managed by Terraform"
    Environment = "production"
  }
}

# target group for simtooreal frontend
resource "aws_lb_target_group" "simtooreal_frontend" {
  name        = "simtooreal-frontend"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.simtooreal.id
  target_type = "ip"
  slow_start  = 60

  health_check {
    interval = 60
    timeout  = 10
    path     = "/"
    matcher  = "200"
  }

  tags = {
    Description = "simtooreal Application Load Balancer target group managed by Terraform"
    Environment = "production"
  }
}

# security group for simtooreal load balancer
resource "aws_security_group" "simtooreal_lb" {
  name        = "simtooreal_lb"
  description = "simtooreal load balancer security group managed by Terraform"
  vpc_id      = aws_vpc.simtooreal.id

  ingress {
    protocol  = "tcp"
    from_port = 443
    to_port   = 443

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol  = "tcp"
    from_port = 80
    to_port   = 80

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol  = "tcp"
    from_port = 3000
    to_port   = 3000

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol  = "tcp"
    from_port = 8080
    to_port   = 8080

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Redirect all traffic from the ALB to the target group
resource "aws_lb_listener" "deus_live" {
  load_balancer_arn = aws_lb.simtooreal.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.deus_live.arn

  default_action {
    target_group_arn = aws_lb_target_group.simtooreal_frontend.id
    type             = "forward"
  }
}

# listener for http to be redirected to https
resource "aws_lb_listener" "deus_live_http" {
  load_balancer_arn = aws_lb.simtooreal.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

### S3

resource "aws_s3_bucket_acl" "simtooreal_private_acl" {
  bucket = aws_s3_bucket.simtooreal_private.id
  acl    = "private"
}

resource "aws_s3_bucket_acl" "simtooreal_public_acl" {
  bucket = aws_s3_bucket.simtooreal_public.id
  acl    = "private"
}

# simtooreal s3 bucket
resource "aws_s3_bucket" "simtooreal_public" {
  bucket = "simtooreal-public"

  tags = {
    Name        = "simtooreal"
    Environment = "production"
  }
}

# simtooreal s3 bucket
resource "aws_s3_bucket" "simtooreal_private" {
  bucket = "simtooreal-private"

  tags = {
    Name        = "simtooreal"
    Environment = "production"
  }
}

# bastion
resource "aws_s3_object" "simtooreal_public" {
  bucket = aws_s3_bucket.simtooreal_public.bucket
  key    = "bastion.tar.gz"
  source = "bastion.tar.gz"

  # The filemd5() function is available in Terraform 0.11.12 and later
  etag = filemd5("bastion.tar.gz")
}

# tar-ed up simtooreal directory without terraform files
resource "aws_s3_object" "simtooreal_private" {
  bucket = aws_s3_bucket.simtooreal_private.bucket
  key    = "deus.tar.gz"
  source = "deus.tar.gz"

  # The filemd5() function is available in Terraform 0.11.12 and later
  etag = filemd5("deus.tar.gz")
}

### Systems Manager

# ssm parameter group for database name in the schema
resource "aws_ssm_parameter" "postgresql_db" {
  name        = "/parameter/production/POSTGRESQL_DB"
  description = "The database name inside the aurora database schema"
  type        = "SecureString"
  value       = "simtooreal"
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for listen on port
resource "aws_ssm_parameter" "listen_on" {
  name        = "/parameter/production/LISTEN_ON"
  description = "The port to listen on"
  type        = "SecureString"
  value       = "8080"
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for listen on port
resource "aws_ssm_parameter" "listen_on_frontend" {
  name        = "/parameter/production/LISTEN_ON_FRONTEND"
  description = "The port to listen on for the frontend"
  type        = "SecureString"
  value       = "3000"
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}


# ssm parameter group for database username
resource "aws_ssm_parameter" "postgresql_user_name" {
  name        = "/parameter/production/POSTGRESQL_USER_NAME"
  description = "The database username"
  type        = "SecureString"
  value       = "postgres"
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for database password
resource "aws_ssm_parameter" "db_password" {
  name        = "/parameter/production/POSTGRESQL_PASSWORD"
  description = "The database password"
  type        = "SecureString"
  value       = var.db_password
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "db_endpoint" {
  name        = "/parameter/production/POSTGRESQL_HOST"
  description = "The database endpoint"
  type        = "SecureString"
  value       = aws_rds_cluster.simtooreal.endpoint
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "openai_api_key" {
  name        = "/parameter/production/OPENAI_API_KEY"
  description = "Your OpenAI API Key"
  type        = "SecureString"
  value       = var.openai_api_key
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for replicate api token
resource "aws_ssm_parameter" "replicate_api_token" {
  name        = "/parameter/production/REPLICATE_API_TOKEN"
  description = "Your Replicate API Token"
  type        = "SecureString"
  value       = var.replicate_api_token
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "react_app_url_backend" {
  name        = "/parameter/production/REACT_APP_URL_BACKEND"
  description = "Your url to use in production for the backend"
  type        = "SecureString"
  value       = "https://deus.live"
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "react_app_url_frontend" {
  name        = "/parameter/production/REACT_APP_URL_FRONTEND"
  description = "Your url to use in production for the frontend"
  type        = "SecureString"
  value       = "https://deus.live"
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for user id password
resource "aws_ssm_parameter" "simtooreal_aws_access_key_id" {
  name        = "/parameter/production/AWS_ACCESS_KEY_ID"
  description = "The database password"
  type        = "SecureString"
  value       = var.aws_access_key_id
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}

# ssm parameter group for user secret endpoint
resource "aws_ssm_parameter" "simtooreal_secret_access_key" {
  name        = "/parameter/production/AWS_SECRET_ACCESS_KEY"
  description = "The database endpoint"
  type        = "SecureString"
  value       = var.aws_secret_access_key
  overwrite   = "true"

  tags = {
    Name        = "simtooreal"
    environment = "production"
  }
}















































































































# route53 zone for deus
resource "aws_route53_zone" "zone_deus" {
  name = "deus.live"
}

# route53 record for database so that no long database endpoints need to be remembered
resource "aws_route53_record" "record_database_deus" {
  name    = "database.deus-new.live"
  zone_id = aws_route53_zone.zone_deus.id
  type    = "CNAME"
  ttl     = 30

  records = [aws_rds_cluster.deus.endpoint]
}

# route53 record for private EC2 instance so that no long ip addresses need to be remembered
resource "aws_route53_record" "record_private_deus" {
  name    = "private.deus.live"
  zone_id = aws_route53_zone.zone_deus.id
  type    = "A"
  ttl     = 30

  records = [aws_instance.deus_private.private_ip]
}

# route53 record for public EC2 instance so that no long ip addresses need to be remembered
resource "aws_route53_record" "record_public_deus" {
  name    = "public.deus.live"
  zone_id = aws_route53_zone.zone_deus.id
  type    = "A"
  ttl     = 30

  records = [aws_instance.deus_public.public_ip]
}

# route53 record for short url
resource "aws_route53_record" "short_deus" {
  name    = "dev.deus.live" # used to be deus.live
  zone_id = aws_route53_zone.zone_deus.id
  type    = "A"

  alias {
    name                   = aws_lb.deus.dns_name
    zone_id                = aws_lb.deus.zone_id
    evaluate_target_health = true
  }
}

# route53 record for short url
resource "aws_route53_record" "short_backend_deus" {
  name    = "api.deus.live"
  zone_id = aws_route53_zone.zone_deus.id
  type    = "A"

  alias {
    name                   = aws_lb.deus.dns_name
    zone_id                = aws_lb.deus.zone_id
    evaluate_target_health = true
  }
}

# route53 record for full url
resource "aws_route53_record" "deus" {
  name    = "staging.deus.live" # used to be www.deus.live
  zone_id = aws_route53_zone.zone_deus.id
  type    = "A"

  alias {
    name                   = aws_lb.deus.dns_name
    zone_id                = aws_lb.deus.zone_id
    evaluate_target_health = true
  }
}

# resource "aws_route53_record" "deus_mx" {
#   zone_id = aws_route53_zone.zone_deus.id
#   name    = "deus.live"
#   type    = "MX"

#   records = [
#     "1 ASPMX.L.GOOGLE.COM",
#     "5 ALT1.ASPMX.L.GOOGLE.COM",
#     "5 ALT2.ASPMX.L.GOOGLE.COM",
#     "10 ALT3.ASPMX.L.GOOGLE.COM",
#     "10 ALT4.ASPMX.L.GOOGLE.COM",
#   ]

#   ttl = 60
# }

# resource "aws_route53_record" "deus_txt_txt" {
#   zone_id = aws_route53_zone.zone_deus.id
#   name    = "deus.live"
#   type    = "TXT"

#   records = [
#     "google-site-verification=61Exwgsm5YaTH7UBODn-rnEC-ussrNrrLE69yzQqrJ8",
#     "google-site-verification=oHevX9OzCBICu005GizU61VVYMby2BH1KfsmoOHob-Q"
#   ]

#   ttl = 60
# }

# deus certificate managed by Terraform
resource "aws_acm_certificate" "deus" {
  domain_name               = "*.deus.live"
  validation_method         = "DNS"
  subject_alternative_names = ["deus.live"]

  tags = {
    Description = "deus certificate managed by Terraform"
    Name        = "deus"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# the listener needs a cert as well
resource "aws_lb_listener_certificate" "deus" {
  listener_arn    = aws_lb_listener.deus.arn
  certificate_arn = aws_acm_certificate.deus.arn
}

# validation record for deus cert
resource "aws_route53_record" "deus_validation" {
  name    = sort(aws_acm_certificate.deus.domain_validation_options[*].resource_record_name)[0]
  type    = sort(aws_acm_certificate.deus.domain_validation_options[*].resource_record_type)[0]
  records = [sort(aws_acm_certificate.deus.domain_validation_options[*].resource_record_value)[0]]
  zone_id = aws_route53_zone.zone_deus.id
  ttl     = "300"
}

# cert for deus
resource "aws_acm_certificate_validation" "deus" {
  certificate_arn         = aws_acm_certificate.deus.arn
  validation_record_fqdns = [aws_route53_record.deus_validation.fqdn]
}

### IAM/ECR

# ecr for holding all images
resource "aws_ecr_repository" "deus" {
  name                 = "deus"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# ecr admin role for deus
resource "aws_iam_user" "deus_ecr_admin" {
  name = "deus_ecr_admin"

  tags = {
    tag-key = "deus"
  }
}

# ecr admin policy for deus
resource "aws_iam_user_policy" "deus_ecr_admin" {
  name = "deus_ecr_admin"
  user = aws_iam_user.deus_ecr_admin.name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "ecr:*",
            "Resource": "*"
        }
    ]
}
EOF
}

# instance profile for reading s3 from an EC2 instance
# which could be useful for a bastion or prepoluating instances with files
resource "aws_iam_instance_profile" "deus_s3_public_read" {
  name = "deus_s3_public_read"
}

resource "aws_iam_instance_profile" "deus_s3_private_read" {
  name = "deus_s3_private_read"
  role = "deus_private_instance"
}

# instance profile for ecs
resource "aws_iam_instance_profile" "deus_ecs" {
  name = "deus_ecs"
}

# task execution ecs role for deus
resource "aws_iam_role" "deus_ecs_task_execution" {
  name = "deus_ecs_task_execution"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ecs-tasks.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF

  # this is necessary for hosting database passwords and hosts in AWS Systems Manager
  # for convenience and so passwords are less likely to be stored on local machines
  inline_policy {
    name = "my_inline_policy"

    policy = jsonencode({
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "ssm:GetParameters"
          ],
          "Resource" : [
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/POSTGRESQL_HOST",
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/POSTGRESQL_PASSWORD",
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/OPENAI_API_KEY",
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/REPLICATE_API_TOKEN",
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/REACT_APP_URL_BACKEND",
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/REACT_APP_URL_FRONTEND",
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/POSTGRESQL_USER_NAME",
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/POSTGRESQL_DB",
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/LISTEN_ON_FRONTEND",
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/LISTEN_ON",
            "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/SECRET_KEY"
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel"
          ],
          "Resource" : "*"
        }
      ]
    })
  }
}

# s3 reading role for ECS tasks
resource "aws_iam_role" "deus_s3_read" {
  name = "deus_s3_read"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ecs-tasks.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

# TODO: fix
# # s3 reading role for ECS tasks
# resource "aws_iam_role" "deus_private_instance" {
#   name = "deus_private_instance"

#   assume_role_policy = <<EOF
# {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Action": [
#                 "ssm:DescribeAssociation",
#                 "ssm:GetDeployablePatchSnapshotForInstance",
#                 "ssm:GetDocument",
#                 "ssm:DescribeDocument",
#                 "ssm:GetManifest",
#                 "ssm:GetParameter",
#                 "ssm:GetParameters",
#                 "ssm:ListAssociations",
#                 "ssm:ListInstanceAssociations",
#                 "ssm:PutInventory",
#                 "ssm:PutComplianceItems",
#                 "ssm:PutConfigurePackageResult",
#                 "ssm:UpdateAssociationStatus",
#                 "ssm:UpdateInstanceAssociationStatus",
#                 "ssm:UpdateInstanceInformation"
#             ],
#             "Effect": "Allow",
#             "Resource": "*"
#         },
#         {
#             "Action": [
#                 "ssmmessages:CreateControlChannel",
#                 "ssmmessages:CreateDataChannel",
#                 "ssmmessages:OpenControlChannel",
#                 "ssmmessages:OpenDataChannel"
#             ],
#             "Effect": "Allow",
#             "Resource": "*"
#         },
#         {
#             "Action": [
#                 "ec2messages:AcknowledgeMessage",
#                 "ec2messages:DeleteMessage",
#                 "ec2messages:FailMessage",
#                 "ec2messages:GetEndpoint",
#                 "ec2messages:GetMessages",
#                 "ec2messages:SendReply"
#             ],
#             "Effect": "Allow",
#             "Resource": "*"
#         }
#     ]
# }
# EOF
# }

# ECS task role
resource "aws_iam_role" "deus_ecs" {
  name = "deus_ecs"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ecs-tasks.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

# ECS task execution role policy attachment
resource "aws_iam_role_policy_attachment" "deus_ecs_task_execution" {
  role       = aws_iam_role.deus_ecs_task_execution.name
  policy_arn = aws_iam_policy.deus_ecs_task_execution.arn
}

# ECS task  role policy attachment
resource "aws_iam_role_policy_attachment" "deus_ecs" {
  role       = aws_iam_role.deus_ecs.name
  policy_arn = aws_iam_policy.deus_ecs.arn
}

# role policy attachment for reading s3
resource "aws_iam_role_policy_attachment" "deus_s3_public_read" {
  role       = aws_iam_role.deus_s3_read.name
  policy_arn = aws_iam_policy.deus_s3_public_read.arn
}

# role policy attachment for reading s3
resource "aws_iam_role_policy_attachment" "deus_s3_private_read" {
  role       = aws_iam_role.deus_s3_read.name
  policy_arn = aws_iam_policy.deus_s3_private_read.arn
}

# IAM policy for task execution
resource "aws_iam_policy" "deus_ecs_task_execution" {
  name        = "deus_ecs_task_execution"
  description = "Policy to allow ECS to execute tasks"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:CreateLogGroup",
                "logs:DescribeLogGroups"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

# IAM policy for reading s3 in deus
resource "aws_iam_policy" "deus_s3_public_read" {
  name        = "deus_s3_public_read"
  description = "Policy to allow S3 reading of bucket deus-public"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "ssm:GetParametersByPath",
                "ssm:GetParameters",
                "ssm:GetParameter"
            ],
            "Resource": [
                "arn:aws:s3:::deus-public/*"
            ]
        }
    ]
}
EOF
}

# IAM policy for reading s3 in deus
resource "aws_iam_policy" "deus_s3_private_read" {
  name        = "deus_s3_private_read"
  description = "Policy to allow S3 reading of bucket deus-private and ssm"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "ssm:GetParametersByPath",
                "ssm:GetParameters",
                "ssm:GetParameter"
            ],
            "Resource": [
                "arn:aws:s3:::deus-private/*",
                "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/AWS_ACCESS_KEY_ID",
                "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/AWS_SECRET_ACCESS_KEY",
                "arn:aws:ssm:${var.aws_region}:*:parameter/deus/production/OPENAI_API_KEY"
            ]
        }
    ]
}
EOF
}

# IAM policy for ECS
resource "aws_iam_policy" "deus_ecs" {
  name        = "deus_ecs"
  description = "Policy to allow ECS access"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeTags",
                "ecs:CreateCluster",
                "ecs:DeregisterContainerInstance",
                "ecs:DiscoverPollEndpoint",
                "ecs:Poll",
                "ecs:RegisterContainerInstance",
                "ecs:StartTelemetrySession",
                "ecs:UpdateContainerInstancesState",
                "ecs:Submit*",
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:CreateLogGroup",
                "logs:DescribeLogGroups"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

### Networking and subnets

# AWS VPC for deus
resource "aws_vpc" "deus" {
  cidr_block           = "172.17.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Description = "Scalable AI platform"
    Environment = "production"
    Name        = "deus"
  }
}

# Fetch Availability Zones in the current region
data "aws_availability_zones" "deus" {
}

# Create var.az_count private subnets, each in a different AZ
resource "aws_subnet" "deus_private" {
  count             = var.az_count
  cidr_block        = cidrsubnet(aws_vpc.deus.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.deus.names[count.index]
  vpc_id            = aws_vpc.deus.id

  tags = {
    Description = "Scalable AI platform"
    Environment = "production"
  }
}

# Create var.az_count public subnets, each in a different AZ
resource "aws_subnet" "deus_public" {
  count = var.az_count
  cidr_block = cidrsubnet(
    aws_vpc.deus.cidr_block,
    8,
    var.az_count + count.index,
  )
  availability_zone       = data.aws_availability_zones.deus.names[count.index]
  vpc_id                  = aws_vpc.deus.id
  map_public_ip_on_launch = true

  tags = {
    Description = "deus public subnet managed by Terraform"
    Environment = "production"
  }
}

# Create var.az_count rds subnets, each in a different AZ
resource "aws_subnet" "deus_rds" {
  count = var.az_count
  cidr_block = cidrsubnet(
    aws_vpc.deus.cidr_block,
    8,
    2 * var.az_count + 1 + count.index,
  )
  availability_zone = data.aws_availability_zones.deus.names[count.index]
  vpc_id            = aws_vpc.deus.id

  tags = {
    Description = "deus RDS subnet managed by Terraform"
    Environment = "production"
  }
}

# IGW for the public subnet
resource "aws_internet_gateway" "deus" {
  vpc_id = aws_vpc.deus.id
}

# Route the public subnet traffic through the IGW
resource "aws_route" "deus_internet_access" {
  route_table_id         = aws_vpc.deus.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.deus.id
}

# Create a NAT gateway with an EIP for each private subnet to get internet connectivity
resource "aws_eip" "deus" {
  count      = var.az_count
  vpc        = true
  depends_on = [aws_internet_gateway.deus]

  tags = {
    Description = "deus gateway EIP managed by Terraform"
    Environment = "production"
  }
}

# NAT gateway for internet access
resource "aws_nat_gateway" "deus" {
  count         = var.az_count
  subnet_id     = element(aws_subnet.deus_public.*.id, count.index)
  allocation_id = element(aws_eip.deus.*.id, count.index)

  tags = {
    Description = "deus gateway NAT managed by Terraform"
    Environment = "production"
  }
}

# Create a new route table for the private subnets
# And make it route non-local traffic through the NAT gateway to the internet
resource "aws_route_table" "deus_private" {
  count  = var.az_count
  vpc_id = aws_vpc.deus.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = element(aws_nat_gateway.deus.*.id, count.index)
  }

  tags = {
    Description = "deus gateway NAT managed by Terraform"
    Environment = "production"
  }
}

# RDS route table for deus
resource "aws_route_table" "deus_rds" {
  count  = var.az_count
  vpc_id = aws_vpc.deus.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = element(aws_nat_gateway.deus.*.id, count.index)
  }

  tags = {
    Description = "deus RDS route table managed by Terraform"
    Environment = "production"
  }
}

# Explicitely associate the newly created route tables to the private subnets (so they don't default to the main route table)
resource "aws_route_table_association" "deus_private" {
  count          = var.az_count
  subnet_id      = element(aws_subnet.deus_private.*.id, count.index)
  route_table_id = element(aws_route_table.deus_private.*.id, count.index)
}

resource "aws_route_table_association" "rdeus_rds" {
  count          = var.az_count
  subnet_id      = element(aws_subnet.deus_rds.*.id, count.index)
  route_table_id = element(aws_route_table.deus_rds.*.id, count.index)
}

### RDS

# subnet used by rds
resource "aws_db_subnet_group" "deus" {
  name        = "deus"
  description = "deus RDS Subnet Group managed by Terraform"
  subnet_ids  = aws_subnet.deus_rds.*.id
}

# Security Group for resources that want to access the database
resource "aws_security_group" "deus_db_access" {
  vpc_id      = aws_vpc.deus.id
  name        = "deus_db_access"
  description = "deus allow access to RDS, managed by Terraform"

  ingress {
    # TLS (change to whatever ports you need)
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.deus.cidr_block]
  }
}

# database security group
resource "aws_security_group" "deus_rds" {
  name        = "deus_rds"
  description = "deus RDS security group, managed by Terraform"
  vpc_id      = aws_vpc.deus.id

  //allow traffic for TCP 5432
  ingress {
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = aws_security_group.deus_ecs.*.id
  }

  // outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# database cluster instances for deus
resource "aws_rds_cluster_instance" "deus" {
  # WARNING: Setting count to anything less than 2 reduces
  # the reliability of your system, many times an instance
  # failure has occured requiring a hot switch to a
  # secondary instance, if there is nothing to switch to
  # you may regret setting count to 1, consider reliability
  # and weigh it against infrastructure cost
  count                = 1
  cluster_identifier   = aws_rds_cluster.deus.id
  instance_class       = "db.r4.large"
  db_subnet_group_name = aws_db_subnet_group.deus.name
  engine               = "aurora-postgresql"
  engine_version       = "12.8"
}

# database cluster for deus
resource "aws_rds_cluster" "deus" {
  cluster_identifier = "deus"
  #availability_zones        = ["us-east-1a", "us-east-1b", "us-east-1c"]
  database_name             = "deus"
  master_username           = "postgres"
  master_password           = var.db_password
  db_subnet_group_name      = aws_db_subnet_group.deus.name
  engine                    = "aurora-postgresql"
  engine_version            = "12.8"
  vpc_security_group_ids    = [aws_security_group.deus_rds.id]
  skip_final_snapshot       = "true"
  final_snapshot_identifier = "foo"
  storage_encrypted         = "true"
  #snapshot_identifier      = "deus"
}

### Elasticache

# Security Group for resources that want to access redis
resource "aws_security_group" "deus_redis_access" {
  vpc_id      = aws_vpc.deus.id
  name        = "deus_redis_access"
  description = "deus redis access security group managed by Terraform"

  ingress {
    # TLS (change to whatever ports you need)
    from_port = 6379
    to_port   = 6379
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.deus.cidr_block]
  }
}

resource "aws_security_group" "deus_redis" {
  name        = "deus_redis"
  vpc_id      = aws_vpc.deus.id
  description = "deus Redis Security Group managed by Terraform"

  //allow traffic for TCP 6379
  ingress {
    from_port = 6379
    to_port   = 6379
    protocol  = "tcp"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = aws_security_group.deus_ecs.*.id
  }

  // outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# public security group for load balancers and bastions
resource "aws_security_group" "deus_public" {
  name        = "deus_public"
  description = "deus public security group managed by Terraform"
  vpc_id      = aws_vpc.deus.id

  # allows ssh attempts from my IP address
  # you should change this to your IP address
  # or your corporate network
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["76.231.26.199/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

### Elasticache

# # elasticache for deus
# resource "aws_elasticache_subnet_group" "deus" {
#   name       = "deus"
#   subnet_ids = aws_subnet.deus_private.*.id
# }

# # elasticache cluster for deus
# resource "aws_elasticache_cluster" "deus" {
#   cluster_id           = "deus"
#   engine               = "redis"
#   node_type            = "cache.m5.large"
#   port                 = 6379
#   num_cache_nodes      = 1
#   security_group_ids   = [aws_security_group.deus_redis.id]
#   subnet_group_name    = aws_elasticache_subnet_group.deus.name
#   parameter_group_name = aws_elasticache_parameter_group.deus.name
# }

# # elasticache parameter group for deus
# resource "aws_elasticache_parameter_group" "deus" {
#   name   = "redis-28-deus"
#   family = "redis6.x"

#   parameter {
#     name  = "timeout"
#     value = "500"
#   }
# }

### AWS instances

resource "aws_key_pair" "deus" {
  key_name   = "deus"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC60teZFO7BuQVwHSUewqOFGo7Iko16pF/vpio8p0K4PR29KG4oaKd4lRHx0WwX5NlLTxEI5xXQWAN9sRQMz60UDnURKnGbjiy+QI/mL3Ivkt4YV6gEfGYdVChJE6bYpnmUbPn8e27JcIJkBcDEATTEZEvSWi8xNhXWOr3I4m/Jc7OOOZAk7R9roqFlsNQrOCizc543PxCLLKafwFcDNUg+h8EOO3+PVZJziAllRTx53WxYbOUZ1tSXwaiJkXSLhVmSZQU6gXuzjlUe2ZAYwW9XzQj8xvPjFJIgizJthnbFxiAn6BygM+/4YdT+SjdpG1Y3NamXgBPQPKWFX8vBkwxVIGywDqpMVlI8L1DgbU4ISVmkHj+kG8t7iX9NF73fG9M414SBpIZSO7lsXz5rHqoz7VZe5DDl5piVV/thXwaAMMm1kerF1GlWcvUxsABv4yD2DnuqMVPz77dP1abOVpRTr7NcSvQCFv4vcMO+0CAGO/RIn3vYawjLvBFEeICsd35mnWF+PDg4QiSycJpUX9wFnZKsbI+pOEfexHqseuiS+PTOgROVonC7PUzYjFbxT3SRKRsiJxNxmRtbaEjWXZpsEFjDb/ifs9K06mqTF6MqFYXVs4AhTxDuhqQ9EOBg/LG+JUIj76o4cl7VkUJxhYyP9MNO1Ze6AVl7/xmzigsEFQ== chase.brignac@example.com"
}

# public facing instance through which maintenance work is done
# t3a.micro has enough memory to run a Duo bastion but t3a.nano will save money
resource "aws_instance" "deus_public" {
  ami                         = "ami-0fa37863afb290840"
  instance_type               = "t3a.micro"
  subnet_id                   = aws_subnet.deus_public[0].id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.deus_s3_public_read.name
  vpc_security_group_ids      = [aws_security_group.deus_public.id]
  key_name                    = aws_key_pair.deus.key_name
  depends_on                  = [aws_s3_object.deus_public]
  user_data                   = "#!/bin/bash\necho $USER\ncd /home/ubuntu\npwd\necho beginscript\nexport AWS_ACCESS_KEY_ID=${aws_ssm_parameter.deus_aws_access_key_id.value}\nexport AWS_SECRET_ACCESS_KEY=${aws_ssm_parameter.deus_secret_access_key.value}\necho $AWS_SECRET_ACCESS_KEY\necho $AWS_ACCESS_KEY_ID\nexport AWS_DEFAULT_REGION=us-east-1\nsudo apt-get update -y\nsudo apt-get install awscli -y\nsudo apt-get install awscli -y\naws s3 cp s3://deus-public/bastion.tar.gz ./\napt-get remove docker docker-engine docker-ce docker.io\napt-get install -y apt-transport-https ca-certificates curl software-properties-common\ncurl -fsSL https://download.docker.com/linux/ubuntu/gpg  | apt-key add -\nadd-apt-repository 'deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable'\napt-get -y install docker-ce\nsystemctl start docker\napt-get install -y docker-compose\nsystemctl enable docker\ntar -zxvf bastion.tar.gz\ncd bastion/examples/compose\ndocker-compose up --build"
  # to troubleshoot your user_data logon to the instance and run this
  #cat /var/log/cloud-init-output.log

  root_block_device {
    volume_size = "20"
    volume_type = "standard"
  }

  # lifecycle {
  #   ignore_changes = [user_data]
  # }

  tags = {
    Name = "deus_public"
  }
}

# private instance inside the private subnet
# reaching RDS is done through this instance
resource "aws_instance" "deus_private" {
  # These can be ecs optimized AMI if Amazon Linux OS is your thing
  # or you can even add an ECS compatible AMI, update instance type to t2.2xlarge
  # add to the user_data "ECS_CLUSTER= deus >> /etc/ecs/ecs.config"
  # and add the iam_instance_profile of aws_iam_instance_profile.deus_ecs.name
  # and you would then be able to use this instance in ECS
  ami           = "ami-0fa37863afb290840"
  instance_type = "t2.nano"
  subnet_id     = aws_subnet.deus_private[0].id

  vpc_security_group_ids = [aws_security_group.deus_ecs.id]
  key_name               = aws_key_pair.deus.key_name
  iam_instance_profile   = aws_iam_instance_profile.deus_s3_private_read.name
  depends_on             = [aws_s3_bucket.deus_private]
  user_data              = "#!/bin/bash\necho $USER\ncd /home/ubuntu\npwd\necho beginscript\nsudo apt-get update -y\nsudo apt-get install awscli -y\necho $USER\necho ECS_CLUSTER=deus > /etc/ecs/ecs.config\napt-add-repository --yes --update ppa:ansible/ansible\napt -y install ansible\napt install postgresql-client-common\napt-get -y install postgresql\napt-get remove docker docker-engine docker-ce docker.io\napt-get install -y apt-transport-https ca-certificates curl software-properties-common\nexport AWS_ACCESS_KEY_ID=${aws_ssm_parameter.deus_aws_access_key_id.value}\nexport AWS_SECRET_ACCESS_KEY=${aws_ssm_parameter.deus_secret_access_key.value}\nexport AWS_DEFAULT_REGION=us-east-1\naws s3 cp s3://deus-private/deus.tar.gz ./\ntar -zxvf deus.tar.gz\nmv deus data\napt install python3-pip -y\napt-get install tmux"
  # to troubleshoot your user_data logon to the instance and run this
  #cat /var/log/cloud-init-output.log

  # lifecycle {
  #   ignore_changes = [user_data]
  # }

  root_block_device {
    volume_size = "100"
    volume_type = "standard"
  }

  tags = {
    Name = "deus_private"
  }
}

### ECS

# ECS service for the backend
resource "aws_ecs_service" "deus_backend" {
  name                   = "deus_backend"
  cluster                = aws_ecs_cluster.deus.id
  task_definition        = aws_ecs_task_definition.deus_backend.family
  desired_count          = var.app_count
  launch_type            = "FARGATE"
  force_new_deployment   = true
  enable_execute_command = true

  network_configuration {
    security_groups = [aws_security_group.deus_ecs.id]
    subnets         = aws_subnet.deus_private.*.id
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.deus_backend.id
    container_name   = "deus-backend"
    container_port   = "8080"
  }

  depends_on = [aws_lb_listener.deus]

  tags = {
    Description = "deus Elastic Container Service managed by Terraform"
    Environment = "production"
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# ECS service for the frontend
resource "aws_ecs_service" "deus_frontend" {
  name                   = "deus_frontend"
  cluster                = aws_ecs_cluster.deus.id
  task_definition        = aws_ecs_task_definition.deus_frontend.family
  desired_count          = var.app_count
  launch_type            = "FARGATE"
  force_new_deployment   = true
  enable_execute_command = true

  network_configuration {
    security_groups = [aws_security_group.deus_ecs.id]
    subnets         = aws_subnet.deus_private.*.id
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.deus_frontend.id
    container_name   = "deus-frontend"
    container_port   = "3000"
  }

  depends_on = [aws_lb_listener.deus]

  tags = {
    Description = "deus Elastic Container Service managed by Terraform"
    Environment = "production"
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# in case we ever want to start using reserved instances to try and save money
# resource "aws_ecs_service" "deus_backend_reserved" {
#   name            = "deus_backend_reserved"
#   cluster         = aws_ecs_cluster.deus.id
#   task_definition = aws_ecs_task_definition.deus_backend.arn
#   desired_count   = var.app_count
#   launch_type     = "EC2"
#
#   network_configuration {
#     security_groups = [aws_security_group.deus_ecs.id]
#     subnets         = aws_subnet.deus_private.*.id
#   }
#
#   load_balancer {
#     target_group_arn = aws_lb_target_group.deus_backend.id
#     container_name   = "deus_backend"
#     container_port   = "8080"
#   }
#
#   depends_on = [aws_lb_listener.deus]
#
#   tags = {
#     Description = "deus reserved Elastic Container Service managed by Terraform"
#     Environment = "production"
#   }
#
#   lifecycle {
#     ignore_changes = [desired_count]
#   }
# }

# in case we ever want to start using reserved instances to try and save money
# resource "aws_ecs_service" "deus_frontend_reserved" {
#   name            = "deus_frontend_reserved"
#   cluster         = aws_ecs_cluster.deus.id
#   task_definition = aws_ecs_task_definition.deus_frontend.arn
#   desired_count   = var.app_count
#   launch_type     = "EC2"
#
#   network_configuration {
#     security_groups = [aws_security_group.deus_ecs.id]
#     subnets         = aws_subnet.deus_private.*.id
#   }
#
#   load_balancer {
#     target_group_arn = aws_lb_target_group.deus_frontend.id
#     container_name   = "deus_frontend"
#     container_port   = "8080"
#   }
#
#   depends_on = [aws_lb_listener.deus]
#
#   tags = {
#     Description = "deus reserved Elastic Container Service managed by Terraform"
#     Environment = "production"
#   }
#
#   lifecycle {
#     ignore_changes = [desired_count]
#   }
# }

### Autoscaling

# autoscaling target for deus
resource "aws_appautoscaling_target" "deus_backend" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.deus.name}/${aws_ecs_service.deus_backend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  max_capacity       = var.ecs_autoscale_max_instances
  min_capacity       = 1
}

# autoscaling target for deus
resource "aws_appautoscaling_target" "deus_frontend" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.deus.name}/${aws_ecs_service.deus_frontend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  max_capacity       = var.ecs_autoscale_max_instances
  min_capacity       = 1
}

resource "aws_cloudwatch_metric_alarm" "deus_backend_memory_utilization_high" {
  alarm_name          = "deus_backend_memory_utilization_high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = 30

  dimensions = {
    ClusterName = aws_ecs_cluster.deus.name
    ServiceName = aws_ecs_service.deus_backend.name
  }

  alarm_actions = [aws_appautoscaling_policy.deus_backend_memory_utilization_high.arn]
}

resource "aws_cloudwatch_metric_alarm" "deus_frontend_memory_utilization_high" {
  alarm_name          = "deus_frontend_memory_utilization_high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = 30

  dimensions = {
    ClusterName = aws_ecs_cluster.deus.name
    ServiceName = aws_ecs_service.deus_frontend.name
  }

  alarm_actions = [aws_appautoscaling_policy.deus_frontend_memory_utilization_high.arn]
}

# memory metric alarm
resource "aws_cloudwatch_metric_alarm" "deus_backend_memory_utilization_low" {
  alarm_name          = "deus_backend_memory_utilization_low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = 30

  dimensions = {
    ClusterName = aws_ecs_cluster.deus.name
    ServiceName = aws_ecs_service.deus_backend.name
  }

  alarm_actions = [aws_appautoscaling_policy.deus_backend_memory_utilization_low.arn]
}

# memory metric alarm
resource "aws_cloudwatch_metric_alarm" "deus_frontend_memory_utilization_low" {
  alarm_name          = "deus_frontend_memory_utilization_low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "60"
  statistic           = "Average"
  threshold           = 30

  dimensions = {
    ClusterName = aws_ecs_cluster.deus.name
    ServiceName = aws_ecs_service.deus_frontend.name
  }

  alarm_actions = [aws_appautoscaling_policy.deus_frontend_memory_utilization_low.arn]
}

# memory metric alarm
resource "aws_appautoscaling_policy" "deus_backend_memory_utilization_high" {
  name               = "deus_backend_memory_utilization_high"
  service_namespace  = aws_appautoscaling_target.deus_backend.service_namespace
  resource_id        = aws_appautoscaling_target.deus_backend.resource_id
  scalable_dimension = aws_appautoscaling_target.deus_backend.scalable_dimension

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 60
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_lower_bound = 0
      scaling_adjustment          = 1
    }
  }
}

# memory metric alarm
resource "aws_appautoscaling_policy" "deus_frontend_memory_utilization_high" {
  name               = "deus_frontend_memory_utilization_high"
  service_namespace  = aws_appautoscaling_target.deus_frontend.service_namespace
  resource_id        = aws_appautoscaling_target.deus_frontend.resource_id
  scalable_dimension = aws_appautoscaling_target.deus_frontend.scalable_dimension

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 60
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_lower_bound = 0
      scaling_adjustment          = 1
    }
  }
}

# memory metric alarm policy
resource "aws_appautoscaling_policy" "deus_backend_memory_utilization_low" {
  name               = "deus_backend_memory_utilization_low"
  service_namespace  = aws_appautoscaling_target.deus_backend.service_namespace
  resource_id        = aws_appautoscaling_target.deus_backend.resource_id
  scalable_dimension = aws_appautoscaling_target.deus_backend.scalable_dimension

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 300
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_upper_bound = 0
      scaling_adjustment          = -1
    }
  }
}

# memory metric alarm policy
resource "aws_appautoscaling_policy" "deus_frontend_memory_utilization_low" {
  name               = "deus_frontend_memory_utilization_low"
  service_namespace  = aws_appautoscaling_target.deus_frontend.service_namespace
  resource_id        = aws_appautoscaling_target.deus_frontend.resource_id
  scalable_dimension = aws_appautoscaling_target.deus_frontend.scalable_dimension

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 300
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_upper_bound = 0
      scaling_adjustment          = -1
    }
  }
}

# backend task definition
resource "aws_ecs_task_definition" "deus_backend" {
  depends_on = [
    aws_lb.deus,
    #aws_elasticache_cluster.deus,
    aws_rds_cluster.deus,
  ]
  family                   = "deus-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 1024
  memory                   = 4096
  execution_role_arn       = aws_iam_role.deus_ecs_task_execution.arn
  task_role_arn            = aws_iam_role.deus_ecs_task_execution.arn

  container_definitions = jsonencode([
    {
      name      = "deus-backend"
      image     = "923082272114.dkr.ecr.us-east-1.amazonaws.com/deus:backend"
      cpu       = 256
      memory    = 512
      essential = true
      command   = ["app.py"]
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ],
      secrets = [
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/POSTGRESQL_USER_NAME",
          name      = "POSTGRESQL_USER_NAME"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/POSTGRESQL_DB",
          name      = "POSTGRESQL_DB"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/LISTEN_ON",
          name      = "LISTEN_ON"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/POSTGRESQL_HOST",
          name      = "POSTGRESQL_HOST"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/POSTGRESQL_PASSWORD",
          name      = "POSTGRESQL_PASSWORD"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/OPENAI_API_KEY",
          name      = "OPENAI_API_KEY"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/REPLICATE_API_TOKEN",
          name      = "REPLICATE_API_TOKEN"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/REACT_APP_URL_BACKEND",
          name      = "REACT_APP_URL_BACKEND"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/REACT_APP_URL_FRONTEND",
          name      = "REACT_APP_URL_FRONTEND"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/SECRET_KEY",
          name      = "SECRET_KEY"
        }
      ],
      mountPoints = [],
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = "/ecs/deus-backend",
          awslogs-region        = "us-east-1",
          awslogs-stream-prefix = "ecs",
          awslogs-create-group  = "true"
        }
      },
      volumesFrom = [],
      environment = []
    }
  ])
}

# backend task definition
resource "aws_ecs_task_definition" "deus_frontend" {
  depends_on = [
    aws_lb.deus,
    #aws_elasticache_cluster.deus,
    aws_rds_cluster.deus,
  ]
  family                   = "deus-frontend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 1024
  memory                   = 4096
  execution_role_arn       = aws_iam_role.deus_ecs_task_execution.arn
  task_role_arn            = aws_iam_role.deus_ecs_task_execution.arn

  container_definitions = jsonencode([
    {
      name      = "deus-frontend"
      image     = "923082272114.dkr.ecr.us-east-1.amazonaws.com/deus:frontend"
      cpu       = 512
      memory    = 2048
      essential = true
      command   = ["npm", "start"]
      portMappings = [
        {
          containerPort = 3000
          hostPort      = 3000
        }
      ],
      secrets = [
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/POSTGRESQL_USER_NAME",
          name      = "POSTGRESQL_USER_NAME"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/POSTGRESQL_DB",
          name      = "POSTGRESQL_DB"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/LISTEN_ON_FRONTEND",
          name      = "LISTEN_ON"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/POSTGRESQL_HOST",
          name      = "POSTGRESQL_HOST"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/POSTGRESQL_PASSWORD",
          name      = "POSTGRESQL_PASSWORD"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/OPENAI_API_KEY",
          name      = "OPENAI_API_KEY"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/REPLICATE_API_TOKEN",
          name      = "REPLICATE_API_TOKEN"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/REACT_APP_URL_BACKEND",
          name      = "REACT_APP_URL_BACKEND"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/REACT_APP_URL_FRONTEND",
          name      = "REACT_APP_URL_FRONTEND"
        },
        {
          valueFrom = "arn:aws:ssm:${var.aws_region}:923082272114:parameter/deus/production/SECRET_KEY",
          name      = "SECRET_KEY"
        }
      ],
      mountPoints = [],
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = "/ecs/deus-frontend",
          awslogs-region        = "us-east-1",
          awslogs-stream-prefix = "ecs",
          awslogs-create-group  = "true"
        }
      },
      volumesFrom = [],
      environment = []
    }
  ])
}

# cloudwatch log group
resource "aws_cloudwatch_log_group" "deus_backend" {
  name              = "/ecs/deus-backend"
  retention_in_days = 30

  tags = {
    Environment = "production"
    Application = "deus"
  }
}

# cloudwatch log group
resource "aws_cloudwatch_log_group" "deus_frontend" {
  name              = "/ecs/deus-frontend"
  retention_in_days = 30

  tags = {
    Environment = "production"
    Application = "deus"
  }
}

# This needs to be integrated completely into our container_definitions of our aws_ecs_task_definition
resource "aws_cloudwatch_log_stream" "deus_backend" {
  name           = "deus"
  log_group_name = aws_cloudwatch_log_group.deus_backend.name
}

# This needs to be integrated completely into our container_definitions of our aws_ecs_task_definition
resource "aws_cloudwatch_log_stream" "deus_frontend" {
  name           = "deus"
  log_group_name = aws_cloudwatch_log_group.deus_frontend.name
}

# ECS cluster for deus
resource "aws_ecs_cluster" "deus" {
  name = "deus"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Traffic to the ECS Cluster should only come from the ALB, DB, or elasticache
resource "aws_security_group" "deus_ecs" {
  name        = "deus_ecs"
  description = "deus Elastic Container Service (ECS) security group managed by Terraform"
  vpc_id      = aws_vpc.deus.id

  ingress {
    protocol  = "tcp"
    from_port = "80"
    to_port   = "80"

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = [aws_security_group.deus_lb.id]
  }

  ingress {
    protocol  = "tcp"
    from_port = 3000
    to_port   = 3000

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = [aws_security_group.deus_lb.id]
  }

  ingress {
    protocol  = "tcp"
    from_port = 8080
    to_port   = 8080

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    security_groups = [aws_security_group.deus_lb.id]
  }

  egress {
    protocol        = "tcp"
    from_port       = "5432"
    to_port         = "5432"
    security_groups = [aws_security_group.deus_db_access.id]
  }

  egress {
    protocol        = "tcp"
    from_port       = "6379"
    to_port         = "6379"
    security_groups = [aws_security_group.deus_redis_access.id]
  }

  ingress {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = [aws_vpc.deus.cidr_block]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

### ALB

# load balancer for deus
resource "aws_lb" "deus" {
  name            = "deus"
  subnets         = aws_subnet.deus_public.*.id
  security_groups = [aws_security_group.deus_lb.id]
  idle_timeout    = 1800

  tags = {
    Description = "deus Application Load Balancer managed by Terraform"
    Environment = "production"
  }
}

# redirecting api*.deus.live which is an indication of a backend URL to backend target group
resource "aws_lb_listener_rule" "deus_backend" {
  listener_arn = aws_lb_listener.deus.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.deus_backend.arn
  }

  condition {
    host_header {
      values = ["api.*"]
    }
  }
}

# redirecting api*.deus.live which is an indication of a backend URL to backend target group
resource "aws_lb_listener_rule" "deus_frontend" {
  listener_arn = aws_lb_listener.deus.arn
  priority     = 90

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.deus_frontend.arn
  }

  condition {
    host_header {
      values = ["www.deus.live"]
    }
  }
}

# target group for deus backend
resource "aws_lb_target_group" "deus_backend" {
  name        = "deus-backend"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.deus.id
  target_type = "ip"
  slow_start  = 60

  health_check {
    interval = 60
    timeout  = 10
    path     = "/"
    matcher  = "200"
  }

  tags = {
    Description = "deus Application Load Balancer target group managed by Terraform"
    Environment = "production"
  }
}

# target group for deus frontend
resource "aws_lb_target_group" "deus_frontend" {
  name        = "deus-frontend"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.deus.id
  target_type = "ip"
  slow_start  = 60

  health_check {
    interval = 60
    timeout  = 10
    path     = "/"
    matcher  = "200"
  }

  tags = {
    Description = "deus Application Load Balancer target group managed by Terraform"
    Environment = "production"
  }
}

# security group for deus load balancer
resource "aws_security_group" "deus_lb" {
  name        = "deus_lb"
  description = "deus load balancer security group managed by Terraform"
  vpc_id      = aws_vpc.deus.id

  ingress {
    protocol  = "tcp"
    from_port = 443
    to_port   = 443

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol  = "tcp"
    from_port = 80
    to_port   = 80

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol  = "tcp"
    from_port = 3000
    to_port   = 3000

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol  = "tcp"
    from_port = 8080
    to_port   = 8080

    # Please restrict your ingress to only necessary IPs and ports.
    # Opening to 0.0.0.0/0 can lead to security vulnerabilities.
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Redirect all traffic from the ALB to the target group
resource "aws_lb_listener" "deus" {
  load_balancer_arn = aws_lb.deus.id
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.deus.arn

  default_action {
    target_group_arn = aws_lb_target_group.deus_frontend.id
    type             = "forward"
  }
}

# listener for http to be redirected to https
resource "aws_lb_listener" "deus_http" {
  load_balancer_arn = aws_lb.deus.id
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

### S3

resource "aws_s3_bucket_acl" "deus_private_acl" {
  bucket = aws_s3_bucket.deus_private.id
  acl    = "private"
}

resource "aws_s3_bucket_acl" "deus_public_acl" {
  bucket = aws_s3_bucket.deus_public.id
  acl    = "private"
}

# deus s3 bucket
resource "aws_s3_bucket" "deus_public" {
  bucket = "deus-public"

  tags = {
    Name        = "deus"
    Environment = "production"
  }
}

# deus s3 bucket
resource "aws_s3_bucket" "deus_private" {
  bucket = "deus-private"

  tags = {
    Name        = "deus"
    Environment = "production"
  }
}

# bastion
resource "aws_s3_object" "deus_public" {
  bucket = aws_s3_bucket.deus_public.bucket
  key    = "bastion.tar.gz"
  source = "bastion.tar.gz"

  # The filemd5() function is available in Terraform 0.11.12 and later
  etag = filemd5("bastion.tar.gz")
}

# tar-ed up deus directory without terraform files
resource "aws_s3_object" "deus_private" {
  bucket = aws_s3_bucket.deus_private.bucket
  key    = "deus.tar.gz"
  source = "deus.tar.gz"

  # The filemd5() function is available in Terraform 0.11.12 and later
  etag = filemd5("deus.tar.gz")
}

### Systems Manager

# ssm parameter group for database name in the schema
resource "aws_ssm_parameter" "deus_postgresql_db" {
  name        = "/deus/production/POSTGRESQL_DB"
  description = "The database name inside the aurora database schema"
  type        = "SecureString"
  value       = "deus"
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for listen on port
resource "aws_ssm_parameter" "deus_listen_on" {
  name        = "/deus/production/LISTEN_ON"
  description = "The port to listen on"
  type        = "SecureString"
  value       = "8080"
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for listen on port
resource "aws_ssm_parameter" "deus_listen_on_frontend" {
  name        = "/deus/production/LISTEN_ON_FRONTEND"
  description = "The port to listen on for the frontend"
  type        = "SecureString"
  value       = "3000"
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}


# ssm parameter group for database username
resource "aws_ssm_parameter" "deus_postgresql_user_name" {
  name        = "/deus/production/POSTGRESQL_USER_NAME"
  description = "The database username"
  type        = "SecureString"
  value       = "postgres"
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for database password
resource "aws_ssm_parameter" "deus_db_password" {
  name        = "/deus/production/POSTGRESQL_PASSWORD"
  description = "The database password"
  type        = "SecureString"
  value       = var.db_password
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "deus_db_endpoint" {
  name        = "/deus/production/POSTGRESQL_HOST"
  description = "The database endpoint"
  type        = "SecureString"
  value       = aws_rds_cluster.deus.endpoint
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "deus_openai_api_key" {
  name        = "/deus/production/OPENAI_API_KEY"
  description = "Your OpenAI API Key"
  type        = "SecureString"
  value       = var.openai_api_key
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for replicate api token
resource "aws_ssm_parameter" "deus_replicate_api_token" {
  name        = "/deus/production/REPLICATE_API_TOKEN"
  description = "Your Replicate API Token"
  type        = "SecureString"
  value       = var.replicate_api_token
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "deus_react_app_url_backend" {
  name        = "/deus/production/REACT_APP_URL_BACKEND"
  description = "Your url to use in production for the backend"
  type        = "SecureString"
  value       = "https://api.deus.live"
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "deus_react_app_url_frontend" {
  name        = "/deus/production/REACT_APP_URL_FRONTEND"
  description = "Your url to use in production for the frontend"
  type        = "SecureString"
  value       = "https://deus.live"
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for database endpoint
resource "aws_ssm_parameter" "deus_secret_key" {
  name        = "/deus/production/SECRET_KEY"
  description = "Secret key for flask_praetorian"
  type        = "SecureString"
  value       = var.secret_key
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for user id password
resource "aws_ssm_parameter" "deus_aws_access_key_id" {
  name        = "/deus/production/AWS_ACCESS_KEY_ID"
  description = "The database password"
  type        = "SecureString"
  value       = var.aws_access_key_id
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}

# ssm parameter group for user secret endpoint
resource "aws_ssm_parameter" "deus_secret_access_key" {
  name        = "/deus/production/AWS_SECRET_ACCESS_KEY"
  description = "The database endpoint"
  type        = "SecureString"
  value       = var.aws_secret_access_key
  overwrite   = "true"

  tags = {
    Name        = "deus"
    environment = "production"
  }
}