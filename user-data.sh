#!/bin/bash
sudo mkdir -p /var/www/html/health
echo "OK" | sudo tee /var/www/html/health/healthcheck.html
# Instalar el cliente NFS
yum install -y amazon-efs-utils

# Crear el directorio para montar EFS
mkdir -p /var/www/html

# Montar EFS usando el punto de acceso
mount -t efs -o tls,accesspoint=${aws_efs_access_point.wordpress_access_point.id} ${aws_efs_file_system.wordpress_efs.id}:/ /var/www/html

# Asegurarse de que el montaje persista después de reinicios
echo "${aws_efs_file_system.wordpress_efs.id}:/ /var/www/html efs _netdev,tls,accesspoint=${aws_efs_access_point.wordpress_access_point.id} 0 0" >> /etc/fstab
