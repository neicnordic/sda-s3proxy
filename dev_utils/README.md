# Dev environment setup recomendations

This guide uses the
[minio client](https://docs.min.io/minio/baremetal/reference/minio-cli/minio-mc.html)
(mc) for testing.

## minio s3 server

The S3Proxy development environment is run through docker compose, and can be
started from this directory using:

```bash
docker compose up
```
(use the `-d` flag if you wish to run docker in the background).

Then it's possible to trace all the requests that come to minio by first
putting the following in the hosts array your `~/.mc/config.json` file:

```json
"proxydev": {
    "url": "http://localhost:9000",
    "accessKey": "ElixirID",
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

## Test with s3 configuration file
To test the implementation locally use the `proxyS3` file located
in the `dev_utils` folder or a file downloaded from the login portal.

## For example use s3tools to interact with the proxy

```bash
s3cmd -c dev_utils/directS3 ls s3 ## For access without using the proxy
s3cmd -c dev_utils/proxyS3 ls s3  ## For access with using the proxy
```

it's of course also possible to use the `mc` command from minio to access
through the proxy or directly but then you have to configure that in the
`~/.mc/config.json` file.
