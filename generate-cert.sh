#!/bin/bash

# Generar llave privada
openssl genrsa -out private-key.pem 2048

# Generar certificado autofirmado directamente
openssl req -x509 -new -nodes \
  -key private-key.pem \
  -sha256 \
  -days 365 \
  -out certificate.pem \
  -subj "//C=ES/ST=Madrid/L=Madrid/O=Hackaboss/CN=lab4.hackaboss.com"