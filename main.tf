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

// Asignamos la política SSM al Rol
resource "aws_iam_role_policy_attachment" "ssm_policy_attachment" {
  role       = aws_iam_role.ec2_ssm_role.name
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
    cidr_blocks = [module.vpc.vpc_cidr_block]
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
resource "aws_security_group" "HTTPS-SG" {
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
    Name        = "HTTPS-SG"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

resource "aws_security_group" "instance_security_group" {
  name   = "instance-sg"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port       = 80 # Puerto del health check
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.Web_SG.id] # Solo permite tráfico del ALB
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "Postgres_DB" {
  name       = "aws_db_subnet_group"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_db_instance" "db_instance_a" {
  identifier             = "db-wp"
  allocated_storage      = 20
  storage_type           = "gp3"
  engine                 = "postgres"
  engine_version         = "16.3"
  instance_class         = "db.t3.micro"
  username               = var.db_username
  password               = aws_secretsmanager_secret_version.db_password.secret_string
  db_subnet_group_name   = aws_db_subnet_group.Postgres_DB.name
  vpc_security_group_ids = [aws_security_group.Database_SG.id]
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
  name = "password3"

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
    security_groups             = [aws_security_group.instance_security_group.id]
  }

  # Codificamos el user_data en Base64
  user_data = base64encode(<<-EOF
    #!/bin/bash
    yum update -y
    cd /var/www/html/wordpress
    sed -i "s/localhost/${aws_db_instance.db_instance_a.endpoint}/g" wp-config.php
    systemctl restart httpd
  EOF
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "ASG-Lab4" {
  desired_capacity    = var.min_size
  max_size            = var.max_size
  min_size            = var.min_size
  vpc_zone_identifier = module.vpc.private_subnets

  launch_template {
    id      = aws_launch_template.LT-lab04.id
    version = "$Latest"
  }

  target_group_arns = [aws_lb_target_group.TG-Lab4.arn]

  health_check_type         = "EC2"
  health_check_grace_period = 300

  lifecycle {
    create_before_destroy = true
  }
}

# Creación del Application Load Balancer
resource "aws_lb" "ALB-Lab4" {
  name               = "ALB-Lab4"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.Web_SG.id]
  subnets            = module.vpc.public_subnets

  idle_timeout = 60

  tags = {
    Name        = "ALB-Lab4"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

# Creación del Target Group para el ALB
resource "aws_lb_target_group" "TG-Lab4" {
  name     = "TG-Lab4"
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id

  health_check {
    path                = "/health" # Asegúrate de que este path esté disponible en tus instancias
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 2
    matcher             = "200" # Espera una respuesta 200 de tu aplicación
  }

  tags = {
    Name        = "TG-Lab4"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

# Creación del Listener para el ALB
resource "aws_lb_listener" "web_listener" {
  load_balancer_arn = aws_lb.ALB-Lab4.arn
  port              = 80
  protocol          = "HTTP"
  //ssl_policy        = "ELBSecurityPolicy-2016-08"
  //certificate_arn   = aws_acm_certificate.ssl_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.TG-Lab4.arn
  }
  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

/*----------------------------------------------------------------
resource "aws_acm_certificate" "ssl_cert" {
  domain_name       = "lab4.hackaboss.com"
  validation_method = "DNS"
  tags = {
    Name        = "Certificado SSL"
    Env         = "Hack-a-Boss"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

resource "aws_acm_certificate_validation" "ssl_cert_validation" {
  certificate_arn         = aws_acm_certificate.ssl_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.ssl_cert_validation : record.fqdn]

}


resource "aws_route53_zone" "internal" {
  name = "lab4.hackaboss.com" # Dominio interno gratuito
  vpc {
    vpc_id = module.vpc.vpc_id
  }
}

resource "aws_route53_record" "ssl_cert_validation" {
  for_each = { for dvo in aws_acm_certificate.ssl_cert.domain_validation_options : dvo.domain_name => dvo }

  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  records = [each.value.resource_record_value]
  zone_id = aws_route53_zone.internal.zone_id
  ttl     = 60
}

resource "aws_route53_record" "web_record" {
  zone_id = aws_route53_zone.internal.id
  name    = "lab4.hackaboss.com"
  type    = "A"

  alias {
    name                   = aws_lb.ALB-Lab4.name
    zone_id                = aws_lb.ALB-Lab4.zone_id
    evaluate_target_health = false
  }
}
*/