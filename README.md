# S3-Upload-Proxy

S3 Upload Proxy

## Backend services

In the `dummy` folder ther is an docker compose file that will start the required backed services.  
Use the command below to start the servies in a detached state.

```sh
docker-compose -f dummy/docker-compose.yml up -d
```

## Building the image

To build the image there are two ways

Building the image directly

```sh
docker build -t nbisweden/s3inbox:latest .
```

Using the compose file

```sh
docker-compose -f dummy/docker-compose.yml build
```

## Configuration

The app can be confiugured via ENVs as seen in the docker-compose file. Or it can be configures via a yaml file, an example config file is located in the root of this repo.