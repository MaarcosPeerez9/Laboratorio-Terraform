output "vpc_id" {
  description = "ID de la VPC principal"
  value       = module.vpc.vpc_id
}

output "vpc_peer_id" {
  description = "ID de la VPC peer"
  value       = module.vpc_peer.vpc_id
}

output "alb_dns_name" {
  description = "DNS público del Application Load Balancer"
  value       = aws_lb.ALB-Lab4.dns_name
}

output "rds_endpoint" {
  description = "Endpoint de la base de datos RDS"
  value       = aws_db_instance.wordpressDB.endpoint
}

output "redis_endpoint" {
  description = "Endpoint del cluster Redis"
  value       = aws_elasticache_replication_group.redis_cluster.primary_endpoint_address
}

output "efs_id" {
  description = "ID del sistema de archivos EFS"
  value       = aws_efs_file_system.wordpress_efs.id
}

output "efs_dns_name" {
  description = "DNS del sistema de archivos EFS"
  value       = aws_efs_file_system.wordpress_efs.dns_name
}

output "private_subnets" {
  description = "IDs de las subredes privadas"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "IDs de las subredes públicas"
  value       = module.vpc.public_subnets
}

output "route53_zone_id" {
  description = "ID de la zona DNS interna"
  value       = aws_route53_zone.internal.zone_id
}

output "s3_bucket_name" {
  description = "Nombre del bucket S3"
  value       = aws_s3_bucket.bucket_imagenes.id
}