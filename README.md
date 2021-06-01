# NeIC SDA S3 Upload Proxy

[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-orange.svg)](https://www.gnu.org/licenses/agpl-3.0)
![](https://github.com/NBISweden/S3-Upload-Proxy/workflows/static%20check/badge.svg)
![](https://github.com/NBISweden/S3-Upload-Proxy/workflows/Go%20tests/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/NBISweden/S3-Upload-Proxy/badge.svg?branch=master)](https://coveralls.io/github/NBISweden/S3-Upload-Proxy?branch=master)

S3 Upload Proxy

## Introduction
The S3 Upload Proxy is a service used in the Sensitive Data Archive project. It is a proxy setup in front of the S3 backend and it is used for
- allowing the users to perform specific actions against the S3 backend and
- only to specific folders owned by the user performing the action
- hiding the actual bucket name from the user, who can use their username instead

In order to interact with the S3 proxy, and therefore the S3 backend, the [s3cmd](https://s3tools.org/s3cmd) tool can be used. This tool is using a configuration file, which can be downloading by logging in with the EGA or Elixir account [here](https://login.ega.nbis.se/). For example, to upload a file using the configuration file use

```bash
s3cmd -c <CONF_FILE> put <FILE_TO_UPLOAD> s3://<USERNAME>
```
where `CONF_FILE` is downloaded from the link above and the `USERNAME` can be found in the configuration file under `access_key`.

## Backend services

In the `dev_utils` folder ther is an docker compose file that will start the required backed services.  
Use the command below to start the servies in a detached state.

```sh
docker-compose -f dev_utils/docker-compose.yml up -d
```

## Building the image

To build the image there are two ways

Building the image directly

```sh
docker build -t nbisweden/s3inbox:latest .
```

Using the compose file

```sh
docker-compose -f dev_utils/docker-compose.yml build
```

## Configuration

The app can be confiugured via ENVs as seen in the docker-compose file. Or it can be configures via a yaml file, an example config file is located in the root of this repo.

## Certificates
To recrete the certificates for the different services, navigate to `dev_tools/scripts` and export the openssl configuration file using
```sh
export OPENSSL_CONF=$PWD/ssl.cnf
```
 execute the script using
```sh
./make_certs
```
Replace the `dev_utils/utils/certs` folder with the newly created `dev_utils/scripts/certs` folder.

To make sure the certificates are correctly created, verify the CA and the certificate using
```sh
openssl verify -CAfile <CA_FILE>.crt <CRT_FILE>.crt 
```
which should return `mq.crt: OK` for the RabbitMQ certificates. Also, using
```sh
openssl x509 -in <CRT_FILE>.crt -text -noout
```
make sure that the `X509v3 Subject Alternative Name:` includes the `mq`, `s3` and `proxy` DNS.