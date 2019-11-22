package main

import (
    "fmt"
    "io"
    "net/http"
    "net/http/httputil"
    "os"
    "strconv"
    "github.com/minio/minio-go/v6/pkg/s3signer"
)

var realUrl = "http://localhost:9000"

var logHandle *os.File

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

    for header, values := range response.Header {
        for _, value := range values {
            w.Header().Add(header, value)
        }
    }

    // Redirect answer
    io.Copy(w, response.Body)
}
