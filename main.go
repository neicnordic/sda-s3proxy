package main

import (
    "fmt"
    "io"
    "io/ioutil"
    "net/http"
    "net/http/httputil"
)

var realUrl = "http://localhost:9000"

func main() {
    http.HandleFunc("/", handler)
    if err := http.ListenAndServe(":8000", nil); err != nil {
        panic(err)
    }
}

func handler(w http.ResponseWriter, r *http.Request) {
    // Log request
    dump, err := httputil.DumpRequest(r, true)
    if err != nil {
        fmt.Println(err)
    }
    if err := ioutil.WriteFile("_request.dump", dump, 0644); err != nil {
        fmt.Println(err)
    }

    // Redirect request
    nr, err := http.NewRequest(r.Method, realUrl+r.URL.String(), r.Body)
    if err != nil {
        fmt.Println(err)
    }
    nr.Header = r.Header
    response, err := http.DefaultClient.Do(nr)
    if err != nil {
        fmt.Println(err)
    }

    // Log answer
    responseDump, err := httputil.DumpResponse(response, true)
    if err != nil {
        fmt.Println(err)
    }
    if err := ioutil.WriteFile("_response.dump", responseDump, 0644); err != nil {
        fmt.Println(err)
    }

    // Redirect answer
    io.Copy(w, response.Body)
}