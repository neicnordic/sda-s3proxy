FROM golang:1.13.4-alpine3.10
RUN apk add --no-cache git
COPY . .
ENV GO111MODULE=on
RUN go build -o ./build/s3proxy main.go

FROM scratch
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=0 /go/build/s3proxy s3proxy
USER 65534
ENTRYPOINT [ "/s3proxy" ]
