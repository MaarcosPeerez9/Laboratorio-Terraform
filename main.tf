#LAB 03
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=3.0"
    }
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.15.0"


  name = "vpc-lab04"
  cidr = var.vpc_cidr
  azs  = ["us-east-1a", "us-east-1b"]

  public_subnets     = var.public_subnets
  private_subnets    = var.private_subnets
  enable_nat_gateway = true
  single_nat_gateway = true

  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

// Definir el Rol de IAM y la Política para SSM
resource "aws_iam_role" "ec2_ssm_role" {
  name = "ec2-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "ssm_policy_attachment" {
  name       = "ssm-policy-attachment"
  roles      = [aws_iam_role.ec2_ssm_role.name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_ssm_instance_profile" {
  name = "ec2-ssm-instance-profile"
  role = aws_iam_role.ec2_ssm_role.name
}

//Security group http
resource "aws_security_group" "Web_SG" {
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name        = "Web_SG"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Secuity grouo para la BBDD
resource "aws_security_group" "Database_SG" {
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.Web_SG.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name        = "Database_SG"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Security group para el EFS
resource "aws_security_group" "EFS_SG" {
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.Web_SG.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name        = "EFS_SG"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Security group para el Load Balancer
resource "aws_security_group" "LoadBalancer_SG" {
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name        = "LoadBalancer_SG"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

resource "aws_db_subnet_group" "Postgres_DB" {
  name       = "aws_db_subnet_group"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_db_instance" "db_instance_a" {
  identifier             = "web-db-a"
  allocated_storage      = 20
  storage_type           = "gp3"
  engine                 = "postgres"
  engine_version         = "16.3"
  instance_class         = "db.t3.micro"
  username               = var.db_username
  password               = aws_secretsmanager_secret_version.db_password.secret_string
  db_subnet_group_name   = aws_db_subnet_group.Postgres_DB.name
  vpc_security_group_ids = [module.vpc.default_security_group_id]
  multi_az               = true
  publicly_accessible    = false
  skip_final_snapshot    = true

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

resource "aws_secretsmanager_secret" "db_password" {
  name = "db-password"
  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = var.db_pasword
}


resource "aws_launch_template" "LT-lab04" {
  name_prefix   = "LT-lab04"
  image_id      = var.ami_id
  instance_type = var.instance_type

    tags = {
    Name        = "LT-lab04"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_ssm_instance_profile.name
  }

  network_interfaces {
    associate_public_ip_address = false
    subnet_id                   = module.vpc.private_subnets[0]
  }

  # Codificamos el user_data en Base64
  user_data = base64encode(<<EOF
    #!/bin/bash
    yum update -y
    yum install -y httpd php php-pgsql php-gd amazon-linux-extras
    yum install -y aws-cli
    wget https://wordpress.org/latest.tar.gz
    tar -xzf latest.tar.gz -C /var/www/html --strip-components=1
    chown -R apache:apache /var/www/html
    chmod -R 755 /var/www/html
    cd /var/www/html
    cp wp-config-sample.php wp-config.php
    sed -i "s/database_name_here/webdb/g" wp-config.php
    sed -i "s/username_here/${var.db_username}/g" wp-config.php
    DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.db_password.id} --query SecretString --output text)
    sed -i "s/password_here/$DB_PASSWORD/g" wp-config.php
    get https://github.com/kevinoid/postgresql-for-wordpress/archive/master.zip
    unzip master.zip
    mv postgresql-for-wordpress-master /var/www/html/wp-content/pg4wp
    cp /var/www/html/wp-content/pg4wp/db.php /var/www/html/wp-content/
    systemctl enable httpd
    systemctl start httpd
    EOF
  )

  lifecycle {
    create_before_destroy = true
  }
}