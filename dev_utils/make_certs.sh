#!/bin/sh

mkdir -p "$(dirname "$0")"/certs

# create CA certificate
openssl req -config "$(dirname "$0")"/ssl.cnf -new -sha256 -nodes -extensions v3_ca -out "$(dirname "$0")"/certs/ca.csr -keyout "$(dirname "$0")"/certs/ca-key.pem
openssl req -config "$(dirname "$0")"/ssl.cnf -key "$(dirname "$0")"/certs/ca-key.pem -x509 -new -days 7300 -sha256 -nodes -extensions v3_ca -out "$(dirname "$0")"/certs/ca.crt

# Create certificate for MQ
openssl req -config "$(dirname "$0")"/ssl.cnf -new -nodes -newkey rsa:4096 -keyout "$(dirname "$0")"/certs/mq.key -out "$(dirname "$0")"/certs/mq.csr -extensions server_cert
openssl x509 -req -in "$(dirname "$0")"/certs/mq.csr -days 1200 -CA "$(dirname "$0")"/certs/ca.crt -CAkey "$(dirname "$0")"/certs/ca-key.pem -set_serial 01 -out "$(dirname "$0")"/certs/mq.crt -extensions server_cert -extfile "$(dirname "$0")"/ssl.cnf

# Create certificate for Proxy
openssl req -config "$(dirname "$0")"/ssl.cnf -new -nodes -newkey rsa:4096 -keyout "$(dirname "$0")"/certs/proxy.key -out "$(dirname "$0")"/certs/proxy.csr -extensions server_cert
openssl x509 -req -in "$(dirname "$0")"/certs/proxy.csr -days 1200 -CA "$(dirname "$0")"/certs/ca.crt -CAkey "$(dirname "$0")"/certs/ca-key.pem -set_serial 01 -out "$(dirname "$0")"/certs/proxy.crt -extensions server_cert -extfile "$(dirname "$0")"/ssl.cnf

# Create certificate for minio
openssl req -config "$(dirname "$0")"/ssl.cnf -new -nodes -newkey rsa:4096 -keyout "$(dirname "$0")"/certs/s3.key -out "$(dirname "$0")"/certs/s3.csr -extensions server_cert
openssl x509 -req -in "$(dirname "$0")"/certs/s3.csr -days 1200 -CA "$(dirname "$0")"/certs/ca.crt -CAkey "$(dirname "$0")"/certs/ca-key.pem -set_serial 01 -out "$(dirname "$0")"/certs/s3.crt -extensions server_cert -extfile "$(dirname "$0")"/ssl.cnf

# Create client certificate
openssl req -config "$(dirname "$0")"/ssl.cnf -new -nodes -newkey rsa:4096 -keyout "$(dirname "$0")"/certs/client.key -out "$(dirname "$0")"/certs/client.csr -extensions client_cert -subj "/CN=admin"
openssl x509 -req -in "$(dirname "$0")"/certs/client.csr -days 1200 -CA "$(dirname "$0")"/certs/ca.crt -CAkey "$(dirname "$0")"/certs/ca-key.pem -set_serial 01 -out "$(dirname "$0")"/certs/client.crt -extensions client_cert -extfile "$(dirname "$0")"/ssl.cnf

chmod 644 "$(dirname "$0")"/certs/*
