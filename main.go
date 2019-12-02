package main

import (
    "fmt"
    "io"
    "net/http"
    "net/http/httputil"
    "os"
    "strconv"
    "github.com/minio/minio-go/v6/pkg/s3signer"
    "strings"
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

type S3RequestType int

const (
    MakeBucket S3RequestType = iota
    RemoveBucket
    List
    Put
    Get
    Delete
    // Fill in more if needed
    AbortMultipart
    Policy
    Other
)

func detectRequestType(r *http.Request) S3RequestType {
    switch r.Method {
    case http.MethodGet:
        if strings.HasSuffix(r.URL.String(), "/") {
            return Get
        } else if strings.Contains(r.URL.String(), "?acl"){
            return Policy
        } else {
            return List
        }
    case http.MethodDelete:
        if strings.HasSuffix(r.URL.String(), "/") {
            return RemoveBucket
        } else if strings.Contains(r.URL.String(), "uploadId") {
            return AbortMultipart
        }else {
            // Do we allow deletion of files?
            return Delete
        }
    case http.MethodPut:
        if strings.HasSuffix(r.URL.String(), "/") {
            return MakeBucket
        } else if strings.Contains(r.URL.String(), "?policy") {
            return Policy
        } else {
            // Should decide if we will handle copy here or through authentication
            return Put
        }
    }
    return Other
} 

// Don't know exactly how to do this yet
func authenticateUser(r *http.Request) error {
    return nil
}

func notAuthorized(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(401) // Actually correct!
}

func handler(w http.ResponseWriter, r *http.Request) {
    // Log request
    dump, err := httputil.DumpRequest(r, true)
    if err != nil {
        fmt.Println(err)
    }
    fmt.Fprintln(logHandle, "FORWARDING REQUEST TO BACKEND")
    fmt.Fprintln(logHandle, string(dump))

    if err := authenticateUser(r); err != nil {
        notAuthorized(w, r)
        return
    }
    switch t := detectRequestType(r); t {
    case MakeBucket, RemoveBucket, Delete, Policy, Get:
        // Not allowed
        notAllowedResponse(w, r)
    case Put, List, Other, AbortMultipart:
        // Allowed
        allowedResponse(w, r)
    default:
        fmt.Printf("Don't know how to handle %q\n", t)
        notAllowedResponse(w, r)
    }
}

func notAllowedResponse(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(403)
}

func allowedResponse(w http.ResponseWriter, r *http.Request) {
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
