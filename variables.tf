variable "aws_region" {
  description = "La region de AWS"
  default     = "us-east-1"

}

variable "vpc_cidr" {
  description = "Bloque CIDR para el VPC"
  default     = "10.0.0.0/16"

}

variable "public_subnets" {
  description = "Lista de bloques CIDR para las subredes publicas"
  default     = ["10.0.1.0/24", "10.0.2.0/24"]

}

variable "private_subnets" {
  description = "Lista de bloques CIDR para las subredes privadas"
  default     = ["10.0.3.0/24", "10.0.4.0/24"]

}

variable "availability_zones" {
  description = "Las zonas de disponibilidad para las subredes (publica y prvada)"
  default     = ["us-east-1"]
}

variable "enable_nat_gateway" {
  description = "Variable para habilitar el NAT GW"
  default     = true
}

variable "region" {
  description = "AWS region where resources are created"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "Tipo de instancia EC2"
  default     = "t2.micro"
}

variable "ami_id" {
  description = "ID de la AMI"
  default     = "ami-094af7c98bcdbc0b4"
}

variable "min_size" {
  description = "Numero minimo de instancias"
  default     = 2
}

variable "max_size" {
  description = "Numero maximo de instancias"
  default     = 3
}

variable "db_username" {
  description = "Username de la BBDD"
  default     = "dbuser"
}

variable "db_pasword" {
  description = "Pasword de la BBDD"
  default     = "admin1234"
}