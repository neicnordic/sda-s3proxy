# NeIC SDA S3 Upload Proxy

[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-orange.svg)](https://www.gnu.org/licenses/agpl-3.0)
![](https://github.com/NBISweden/S3-Upload-Proxy/workflows/static%20check/badge.svg)
![](https://github.com/NBISweden/S3-Upload-Proxy/workflows/Go%20tests/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/NBISweden/S3-Upload-Proxy/badge.svg?branch=master)](https://coveralls.io/github/NBISweden/S3-Upload-Proxy?branch=master)

S3 Upload Proxy

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
