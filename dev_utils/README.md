# Dev environment setup recomendations

## minio s3 server

Run the minio local thing by starting it with

```bash
docker-compose up -d
```

Then it's possible to trace all the requests that come to minio by first
putting the following in the hosts array your `~/.mc/config.json` file:

```json
"proxydev": {
    "url": "http://localhost:9000",
    "accessKey": "ElexirID",
    "secretKey": "987654321",
    "api": "s3v4",
    "lookup": "auto"
}
```

and then in one terminal it's possible to see all requests comming to and all
responses from minio by running

```bash
mc admin trace -v proxydev
```

## Go proxy

Run the go proxy from the root directory

```bash
export GO111MODULE=on
export SERVER_CONFFILE=dev_utils/config.yaml
go build main.go
./main
```

## For example use s3tools to interact with the proxy

```bash
s3cmd -c dev_utils/directS3 ls s3 ## For access without using the proxy
s3cmd -c dev_utils/proxyS3 ls s3  ## For access with using the proxy
```

it's of course also possible to use the `mc` command from minio to access
through the proxy or directly but then you have to configure that in the
`~/.mc/config.json` file.
