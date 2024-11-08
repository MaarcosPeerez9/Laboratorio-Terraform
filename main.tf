#LAB 03
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=3.0"
    }
  }
  backend "s3" {
    bucket         = "buckets3-lab4-mp"
    key            = "prod/lab4.tfstate" # Define la ruta dentro del bucket
    region         = "us-east-1"  # Cambia a la región de tu bucket
    dynamodb_table = "terraform-state-locks" # Tabla para el locking de estado
    encrypt        = true
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
resource "aws_security_group" "HTTP-SG" {
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
    Name        = "HTTP-SG"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Secuity grouo para la BBDD
resource "aws_security_group" "Database_SG" {
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "tcp"
    //security_groups = [aws_security_group.HTTP-SG.id]
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
resource "aws_security_group" "EFS-SG" {
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port = 2049
    to_port   = 2049
    protocol  = "tcp"
    //security_groups = [aws_security_group.HTTP-SG.id]
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

//Security group 443
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

resource "aws_security_group" "instance-SG" {
  name   = "instance-sg"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port       = 80 # Puerto del health check
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.HTTP-SG.id] # Solo permite tráfico del ALB
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

resource "aws_db_instance" "wordpressDB" {
  identifier             = "wordpressdb"
  db_name                = "wordpressdb"
  allocated_storage      = 20
  storage_type           = "gp3"
  engine                 = "postgres"
  engine_version         = "16.3"
  instance_class         = "db.t3.micro"
  username               = "dbuser"
  password               = "admin1234"
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

resource "aws_route53_zone" "internal" {
  name = "lab4.hackaboss.com" # Dominio interno gratuito
  vpc {
    vpc_id = module.vpc.vpc_id
  }
}

resource "aws_route53_record" "rds_record" {
  zone_id = aws_route53_zone.internal.zone_id
  name    = "rds.lab4.hackaboss.com"
  type    = "CNAME"
  ttl     = 300
  records = [aws_db_instance.wordpressDB.address]

}

resource "aws_route53_record" "web_record" {
  zone_id = aws_route53_zone.internal.zone_id
  name    = "web.lab4.hackaboss.com"
  type    = "A"

  alias {
    name                   = aws_lb.ALB-Lab4.dns_name
    zone_id                = aws_lb.ALB-Lab4.zone_id
    evaluate_target_health = true
  }
}

resource "aws_secretsmanager_secret" "db_password" {
  name = "password13"

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
    security_groups             = [aws_security_group.instance-SG.id]
  }

  # Codificamos el user_data en Base64
  user_data = base64encode(file("user-data.sh"))
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
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.HTTP-SG.id, aws_security_group.HTTPS-SG.id]
  subnets            = module.vpc.public_subnets

  tags = {
    Name        = "ALB-Lab4"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

# Creación del Target Group para el ALB
resource "aws_lb_target_group" "TG-Lab4" {
  name        = "TG-Lab4"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = module.vpc.vpc_id

  health_check {
    path                = "/health/healthcheck.html"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2 
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

# Define el bucket de S3
resource "aws_s3_bucket" "terraform_state" {
  bucket = "buckets3-lab4-mp"
  acl    = "private"

  versioning {
    enabled = true
  }

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state_block" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-state-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

