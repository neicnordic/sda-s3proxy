package main

import (
    "fmt"
    "io"
    "net/http"
    "net/http/httputil"
    "os"
    "strconv"
    "github.com/minio/minio-go/v6/pkg/s3signer"

    "log"
    "github.com/NBISweden/S3-Upload-Proxy/mq"
)

var realUrl = "http://localhost:9000"

var logHandle *os.File


var (
    mqUri        = "amqp://test:test@localhost:5672/test" //"AMQP URI"
    exchangeName = "localega.v1" //"Durable AMQP exchange name"
    exchangeType = "topic" //"Exchange type - direct|fanout|topic|x-custom"
    routingKey   = "files.inbox" //"AMQP routing key"
    body         = "foobar" //"Body of message"
    reliable     = true //"Wait for the publisher confirmation before exiting"
)

func main() {
    logHandle, _ = os.Create("_requestLog.dump")
    http.HandleFunc("/", handler)
    if err := http.ListenAndServe(":8000", nil); err != nil {
        panic(err)
    }
}

func resignHeader(r *http.Request) *http.Request {
    r.Host = "localhost:9000"
    return s3signer.SignV4(*r, "ElexirID", "987654321", "", "us-east-1")
}

func handler(w http.ResponseWriter, r *http.Request) {
    // Log request
    dump, err := httputil.DumpRequest(r, true)
    if err != nil {
        fmt.Println(err)
    }
    fmt.Fprintln(logHandle, "FORWARDING REQUEST TO BACKEND")
    fmt.Fprintln(logHandle, string(dump))

    body = "FORWARDING REQUEST TO BACKEND\n" + string(dump)
    if err := mq.Publish(mqUri, exchangeName, exchangeType, routingKey, body, reliable); err != nil {
        log.Fatalf("%s", err)
    }

    resignHeader(r)

    // Redirect request
    nr, err := http.NewRequest(r.Method, realUrl+r.URL.String(), r.Body)
    if err != nil {
        fmt.Println(err)
    }
    nr.Header = r.Header
    i, err := strconv.ParseInt(r.Header.Get("content-length"), 10, 64)
    nr.ContentLength = i
    response, err := http.DefaultClient.Do(nr)
    if err != nil {
        fmt.Println(err)
    }

    // Log answer
    responseDump, err := httputil.DumpResponse(response, true)
    if err != nil {
        fmt.Println(err)
    }
    fmt.Fprintln(logHandle, "FORWARDING RESPONSE TO CLIENT")
    fmt.Fprintln(logHandle, string(responseDump))

    body = "FORWARDING RESPONSE TO CLIENT\n" + string(responseDump)
    if err := mq.Publish(mqUri, exchangeName, exchangeType, routingKey, body, reliable); err != nil {
        log.Fatalf("%s", err)
    }

    for header, values := range response.Header {
        for _, value := range values {
            w.Header().Add(header, value)
        }
    }

    // Redirect answer
    io.Copy(w, response.Body)
}
