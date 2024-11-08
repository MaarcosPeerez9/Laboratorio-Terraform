#LAB 04
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=3.0"
    }
  }

  // Configuración del backend
  backend "s3" {
    bucket         = "buckets3-lab4-mp"
    key            = "prod/lab4.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }

}

// Definición de la VPC
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

// Asignamos el Rol al perfil de instancia
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
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"
    security_groups = [aws_security_group.instance-SG.id]
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
    cidr_blocks = ["0.0.0.0/0"]
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

//Security group para las instancias
resource "aws_security_group" "instance-SG" {
  name   = "instance-sg"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port       = 80 # Puerto del health check
    to_port         = 80
    protocol        = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

//Subnet group para la BBDD
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

// Zona de Route53 para el dominio interno
resource "aws_route53_zone" "internal" {
  name = "lab4.hackaboss.com" # Dominio interno gratuito
  vpc {
    vpc_id = module.vpc.vpc_id
  }
}

//Registro de la BBDD en Route53
resource "aws_route53_record" "rds_record" {
  zone_id = aws_route53_zone.internal.zone_id
  name    = "rds.lab4.hackaboss.com"
  type    = "CNAME"
  ttl     = 300
  records = [aws_db_instance.wordpressDB.address]

}

//Registro de la web en Route53
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

//Secret manager para la BBDD
resource "aws_secretsmanager_secret" "db_password" {
  name = "secreto-super-secreto"

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Versión del secret manager para la BBDD
resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = var.db_pasword
}

//Launch template para las instancias
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

  //Asignamos el perfil de instancia
  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_ssm_instance_profile.name
  }

  //Asignamos la red privada
  network_interfaces {
    associate_public_ip_address = false
    subnet_id                   = module.vpc.private_subnets[0]
    security_groups             = [aws_security_group.instance-SG.id]
  }

  //Codificamos el user_data en Base64
  user_data = base64encode(file("user-data.sh"))
}

//Autoscaling group para las instancias
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

# Define el bucket de S3
resource "aws_s3_bucket" "bucket_imagenes" {
  bucket = "buckets3-lab04-mp"
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

//Certificado SSL para el dominio
resource "aws_acm_certificate" "ssl_certificate" {
  domain_name       = "lab4.hackaboss.com"
  validation_method = "DNS"

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }

  lifecycle {
    create_before_destroy = true
  }
}

//Certificado SSL para el dominio
resource "aws_acm_certificate" "imported_certificate" {
  private_key       = file("private-key.pem")
  certificate_body  = file("certificate.pem")
  
  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Modificar el listener HTTPS
resource "aws_lb_listener" "web_listener_https" {
  load_balancer_arn = aws_lb.ALB-Lab4.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.imported_certificate.arn

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

//Agregar un listener HTTP que redirija a HTTPS
resource "aws_lb_listener" "http_redirect" {
  depends_on = [
    aws_lb_listener.web_listener_https,
    aws_lb.ALB-Lab4
  ]
  load_balancer_arn = aws_lb.ALB-Lab4.arn
  port              = 80
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

//Zona pública de Route53
resource "aws_route53_zone" "public" {
  name = "lab4.hackaboss.com"
  
  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Tabla DynamoDB para el state locking
resource "aws_dynamodb_table" "terraform_state_lock" {
  count          = var.create_dynamodb_table ? 1 : 0
  name           = "terraform-state-lock"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

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

//Dashboard de CloudWatch
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "LAB04-Dashboard"

  dashboard_body = jsonencode({
    widgets = [
      // Widget para CPU de EC2
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", aws_autoscaling_group.ASG-Lab4.name]
          ]
          period = 300
          stat   = "Average"
          title  = "CPU Utilización EC2"
          region = "us-east-1"
        }
      },
      // Widget para memoria de EC2
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/EC2", "MemoryUtilization", "AutoScalingGroupName", aws_autoscaling_group.ASG-Lab4.name]
          ]
          period = 300
          stat   = "Average"
          title  = "Memoria EC2"
          region = "us-east-1"
        }
      },
      // Widget para CPU de RDS
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.wordpressDB.id]
          ]
          period = 300
          stat   = "Average"
          title  = "CPU Utilización RDS"
          region = "us-east-1"
        }
      },
      // Widget para conexiones a RDS
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", aws_db_instance.wordpressDB.id]
          ]
          period = 300
          stat   = "Average"
          title  = "Conexiones RDS"
          region = "us-east-1"
        }
      }
    ]
  })
}

//Alarmas para EC2
resource "aws_cloudwatch_metric_alarm" "ec2_cpu_high" {
  alarm_name          = "ec2-cpu-utilization-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period             = "300"
  statistic          = "Average"
  threshold          = "80"
  alarm_description  = "La utilización de CPU es superior al 80%"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.ASG-Lab4.name
  }

  alarm_actions = [aws_sns_topic.monitoring_alerts.arn]
  ok_actions    = [aws_sns_topic.monitoring_alerts.arn]

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Alarmas para RDS
resource "aws_cloudwatch_metric_alarm" "rds_cpu_high" {
  alarm_name          = "rds-cpu-utilization-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period             = "300"
  statistic          = "Average"
  threshold          = "80"
  alarm_description  = "La utilización de CPU de RDS es superior al 80%"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.wordpressDB.id
  }

  alarm_actions = [aws_sns_topic.monitoring_alerts.arn]
  ok_actions    = [aws_sns_topic.monitoring_alerts.arn]

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Alarmas para RDS de espacio libre
resource "aws_cloudwatch_metric_alarm" "rds_storage_low" {
  alarm_name          = "rds-free-storage-space-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period             = "300"
  statistic          = "Average"
  threshold          = "5000000000" // 5GB en bytes
  alarm_description  = "El espacio libre en RDS es menor a 5GB"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.wordpressDB.id
  }

  alarm_actions = [aws_sns_topic.monitoring_alerts.arn]
  ok_actions    = [aws_sns_topic.monitoring_alerts.arn]

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Tema SNS para alertas
resource "aws_sns_topic" "monitoring_alerts" {
  name = "lab04-monitoring-alerts"

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//EFS para las instancias
resource "aws_efs_file_system" "wordpress_efs" {
  creation_token = "wordpress-efs"
  encrypted      = true

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = {
    Name        = "WordPressEFS"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Mount targets en las subredes privadas
resource "aws_efs_mount_target" "wordpress_efs_mount" {
  count           = length(module.vpc.private_subnets)
  file_system_id  = aws_efs_file_system.wordpress_efs.id
  subnet_id       = module.vpc.private_subnets[count.index]
  security_groups = [aws_security_group.EFS-SG.id]
}

//Actualizar el security group EFS-SG para permitir tráfico desde las instancias EC2
resource "aws_security_group_rule" "efs_ingress" {
  type                     = "ingress"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  security_group_id        = aws_security_group.EFS-SG.id
  source_security_group_id = aws_security_group.instance-SG.id
}

//Punto de acceso EFS para WordPress
resource "aws_efs_access_point" "wordpress_access_point" {
  file_system_id = aws_efs_file_system.wordpress_efs.id

  posix_user {
    gid = 33 # www-data group ID
    uid = 33 # www-data user ID
  }

  root_directory {
    path = "/wordpress"
    creation_info {
      owner_gid   = 33
      owner_uid   = 33
      permissions = "755"
    }
  }

  tags = {
    Name        = "WordPressAccessPoint"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

//Política de backup para EFS
resource "aws_backup_plan" "efs_backup" {
  name = "efs-backup-plan"

  rule {
    rule_name         = "efs-daily-backup"
    target_vault_name = aws_backup_vault.efs_backup_vault.name
    schedule          = "cron(0 1 * * ? *)" # Backup diario a la 1 AM UTC

    lifecycle {
      delete_after = 30 # Mantener backups por 30 días
    }
  }

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

resource "aws_backup_vault" "efs_backup_vault" {
  name = "efs-backup-vault"
  
  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

resource "aws_backup_selection" "efs_backup" {
  name         = "efs-backup-selection"
  plan_id      = aws_backup_plan.efs_backup.id
  iam_role_arn = aws_iam_role.backup_role.arn

  resources = [
    aws_efs_file_system.wordpress_efs.arn
  ]
}

//Rol IAM para AWS Backup
resource "aws_iam_role" "backup_role" {
  name = "aws-backup-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "backup_policy" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
  role       = aws_iam_role.backup_role.name
}

// Security Group para Redis
resource "aws_security_group" "redis_sg" {
  name        = "redis-sg"
  description = "Security group para Redis"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.instance-SG.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "Redis-SG"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

// Subnet Group para Redis
resource "aws_elasticache_subnet_group" "redis_subnet_group" {
  name       = "redis-subnet-group"
  subnet_ids = module.vpc.private_subnets

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

// Grupo de parámetros para Redis
resource "aws_elasticache_parameter_group" "redis_parameter_group" {
  family = "redis7"
  name   = "redis-params"

  parameter {
    name  = "maxmemory-policy"
    value = "volatile-lru"
  }

  parameter {
    name  = "maxmemory-samples"
    value = "10"
  }

  parameter {
    name  = "timeout"
    value = "300"
  }

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

// Grupo de replicación de Redis
resource "aws_elasticache_replication_group" "redis_cluster" {
  replication_group_id          = "lab04-redis"
  description                  = "Cluster Redis para LAB04"
  node_type                    = "cache.t3.micro"
  num_cache_clusters           = 2
  port                         = 6379
  parameter_group_name         = aws_elasticache_parameter_group.redis_parameter_group.name
  subnet_group_name            = aws_elasticache_subnet_group.redis_subnet_group.name
  security_group_ids           = [aws_security_group.redis_sg.id]
  automatic_failover_enabled   = true
  multi_az_enabled            = true
  
  engine                      = "redis"
  engine_version              = "7.0"
  
  maintenance_window          = "sun:05:00-sun:06:00"
  snapshot_window            = "04:00-05:00"
  snapshot_retention_limit   = 7

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  tags = {
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

// Registro DNS para Redis
resource "aws_route53_record" "redis_record" {
  zone_id = aws_route53_zone.internal.zone_id
  name    = "redis.lab4.hackaboss.com"
  type    = "CNAME"
  ttl     = 300
  records = [aws_elasticache_replication_group.redis_cluster.primary_endpoint_address]
}

// Segunda VPC para el peering
module "vpc_peer" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.15.0"

  name = "vpc-peer-lab04"
  cidr = "10.1.0.0/16"  // Diferente CIDR que la primera VPC
  azs  = ["us-east-1a", "us-east-1b"]

  private_subnets  = ["10.1.1.0/24", "10.1.2.0/24"]
  public_subnets   = ["10.1.101.0/24", "10.1.102.0/24"]

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

// Conexión VPC Peering
resource "aws_vpc_peering_connection" "peer" {
  peer_vpc_id   = module.vpc_peer.vpc_id     // ID de la VPC peer
  vpc_id        = module.vpc.vpc_id          // ID de nuestra VPC principal
  auto_accept   = true                 

  tags = {
    Name        = "VPC-Peering-Lab04"
    Environment = "Prod"
    Owner       = "Marcos"
    Project     = "LAB04"
  }
}

// Rutas en las tablas de enrutamiento de nuestra VPC principal
resource "aws_route" "route_to_peer_private" {
  count                     = length(module.vpc.private_route_table_ids)
  route_table_id            = module.vpc.private_route_table_ids[count.index]
  destination_cidr_block    = "10.1.0.0/16"  // CIDR de la VPC peer
  vpc_peering_connection_id = aws_vpc_peering_connection.peer.id
}

resource "aws_route" "route_to_peer_public" {
  count                     = length(module.vpc.public_route_table_ids)
  route_table_id            = module.vpc.public_route_table_ids[count.index]
  destination_cidr_block    = "10.1.0.0/16"  // CIDR de la VPC peer
  vpc_peering_connection_id = aws_vpc_peering_connection.peer.id
}

// Rutas en las tablas de enrutamiento de la VPC peer
resource "aws_route" "route_from_peer_private" {
  count                     = length(module.vpc_peer.private_route_table_ids)
  route_table_id            = module.vpc_peer.private_route_table_ids[count.index]
  destination_cidr_block    = var.vpc_cidr    // CIDR de la VPC principal
  vpc_peering_connection_id = aws_vpc_peering_connection.peer.id
}

resource "aws_route" "route_from_peer_public" {
  count                     = length(module.vpc_peer.public_route_table_ids)
  route_table_id            = module.vpc_peer.public_route_table_ids[count.index]
  destination_cidr_block    = var.vpc_cidr    // CIDR de la VPC principal
  vpc_peering_connection_id = aws_vpc_peering_connection.peer.id
}

