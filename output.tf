# Output de la VPC
output "vpc_id" {
  description = "ID de la VPC"
  value       = module.vpc.vpc_id
}

# Outputs de las Subnets Públicas
output "public_subnet_ids" {
  description = "IDs de las Subnets Públicas"
  value       = module.vpc.public_subnets
}

# Outputs de las Subnets Privadas
output "private_subnet_ids" {
  description = "IDs de las Subnets Privadas"
  value       = module.vpc.private_subnets
}

# Output del Internet Gateway
output "internet_gateway_id" {
  description = "ID del Internet Gateway"
  value       = module.vpc.public_internet_gateway_route_id
}

# Output del NAT Gateway
output "nat_gateway_id" {
  description = "ID del NAT Gateway"
  value       = module.vpc.private_nat_gateway_route_ids
}

# Output del Security Group para la Web
output "web_security_group_id" {
  description = "ID del Security Group para la Web"
  value       = aws_security_group.Web_SG.id
}

# Output del Security Group para la Base de Datos
output "db_security_group_id" {
  description = "ID del Security Group para la Base de Datos"
  value       = aws_security_group.Database_SG.id
}

# Output del Launch Template
output "launch_template_id" {
  description = "ID del Launch Template"
  value       = aws_launch_template.LT-lab04.id
}

# Outputs de la Base de Datos
output "db_instance_id" {
  description = "ID de la instancia de Base de Datos"
  value       = aws_db_instance.db_instance_a.id
}

# Output del Secrets Manager de la Contraseña de la BBDD
output "db_password_secret_id" {
  description = "ID del Secret en Secrets Manager para la contraseña de la base de datos"
  value       = aws_secretsmanager_secret.db_password.id
}

# Output del Secrets Manager con la Versión de la Contraseña
output "db_password_secret_version_id" {
  description = "ID de la versión del Secret en Secrets Manager para la contraseña de la base de datos"
  value       = aws_secretsmanager_secret_version.db_password.id
}

output "asg_id" {
  description = "ID del Auto Scaling Group"
  value       = aws_autoscaling_group.ASG-Lab4.id
}

output "endpoint_db" {
  description = "Endpoint de la base de datos"
  value       = aws_db_instance.db_instance_a.endpoint
}