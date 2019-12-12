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

    "log"
    "github.com/NBISweden/S3-Upload-Proxy/mq"
    "encoding/json"
    "github.com/spf13/viper"
    "github.com/streadway/amqp"
    "crypto/tls"
    "crypto/x509"
    "io/ioutil"
    "regexp"
    "encoding/csv"
    "bufio"
)

var logHandle *os.File
var AmqpChannel *amqp.Channel
var err error
var (
    confVars         = []string{
                        "aws.url", "aws.accessKey", "aws.secretKey", "broker.host","broker.port", "broker.user",
                        "broker.password", "broker.vhost","broker.exchange", "broker.routingKey", "broker.ssl",
                        }
    backedS3Url      = ""
    backedAccessKey  = ""
    backedSecretKey  = ""
    brokerHost       = ""
    brokerPort       = ""
    brokerUsername   = ""
    brokerPassword   = ""
    brokerVhost      = ""
    brokerExchange   = ""
    brokerSsl        = ""
    brokerRoutingKey = ""
)


type Event struct {
    Operation string `json:"operation"`
    Username string `json:"username"`
    Filepath string `json:"filepath"`
    Filesize int64 `json:"filesize"`
    Checksum Checksum `json:"checksum"`
}

type Checksum struct {
    Type string `json:"type"`
    Value string `json:"value"`
}

var username string
var usersMap map[string]string

func main() {
    viper.SetConfigName("config")
    viper.AddConfigPath(".")
    viper.AutomaticEnv()
    viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
    viper.SetConfigType("yaml")
    if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            // Config file not found; ignore error if desired
            for _, s := range confVars {
                if viper.Get(s) == nil {
                    panic(fmt.Errorf("%s not set", s))
                }
            }
            if viper.Get("broker.ssl") == "true" {
                if viper.Get("broker.caCert") == nil {
                    panic(fmt.Errorf("broker.caCert not set"))
                }
            }
        } else {
            panic(fmt.Errorf("Fatal error config file: %s \n", err))
        }
    }

    backedS3Url      = viper.Get("aws.url").(string)
    backedAccessKey  = viper.Get("aws.accessKey").(string)
    backedSecretKey  = viper.Get("aws.secretKey").(string)
    brokerHost       = viper.Get("broker.host").(string)
    brokerPort       = viper.Get("broker.port").(string)
    brokerUsername   = viper.Get("broker.user").(string)
    brokerPassword   = viper.Get("broker.password").(string)
    brokerVhost      = viper.Get("broker.vhost").(string)
    brokerExchange   = viper.Get("broker.exchange").(string)
    brokerRoutingKey = viper.Get("broker.routingKey").(string)
    brokerSsl        = viper.Get("broker.ssl").(string)

    brokerUri := buildMqUri(brokerHost, brokerPort, brokerUsername, brokerPassword, brokerVhost, brokerSsl)

    var connection *amqp.Connection

    if brokerSsl == "true" {
        cfg := new(tls.Config)

        cfg.RootCAs = x509.NewCertPool()

        cacert := viper.Get("broker.caCert").(string)
        if ca, err := ioutil.ReadFile(cacert); err == nil {
            cfg.RootCAs.AppendCertsFromPEM(ca)
        }

        cert := viper.Get("broker.clientCert")
        key := viper.Get("broker.clientKey")
        if (cert != nil && key != nil) {
            if cert, err := tls.LoadX509KeyPair(cert.(string), key.(string)); err == nil {
                cfg.Certificates = append(cfg.Certificates, cert)
            }
        }
        connection, err = mq.DialTLS(brokerUri, cfg)
        if err != nil {
            panic(fmt.Errorf("BrokerErrMsg: %s", err))
        }
    } else {
        connection, err = mq.Dial(brokerUri)
        if err != nil {
            panic(fmt.Errorf("BrokerErrMsg: %s", err))
        }
    }

    AmqpChannel, err = mq.Channel(connection)
    if err != nil {
        panic(fmt.Errorf("BrokerErrMsg: %s", err))
    }

    err = mq.Exchange(AmqpChannel, brokerExchange)
    if err != nil {
        panic(fmt.Errorf("BrokerErrMsg: %s", err))
    }

    logHandle, _ = os.Create("_requestLog.dump")

    usersMap = readUsersFile()

    http.HandleFunc("/", handler)

    if (viper.Get("server.Cert") != nil && viper.Get("server.Key") != nil && viper.Get("server.Cert").(string) != "" && viper.Get("server.Key").(string) != ""){
        if err := http.ListenAndServeTLS(":8000", viper.Get("server.Cert").(string), viper.Get("server.Key").(string), nil); err != nil {
            panic(err)
        }
    } else {
        if err := http.ListenAndServe( ":8000", nil); err != nil {
            panic(err)
        }
    }

    defer AmqpChannel.Close()
    defer connection.Close()

}

func readUsersFile() map[string]string {
    users := make(map[string]string)
    f, err := os.Open("users.csv")
    if err!=nil {
        panic(fmt.Errorf("UsersFileErrMsg: %s", err))
    }

    r := csv.NewReader(bufio.NewReader(f))
    for {
        record, err := r.Read()
        if err == io.EOF {
            break
        }
        users[record[0]] = record[1]
    }
    return users
}

func buildMqUri(mqHost, mqPort, mqUser, mqPassword, mqVhost, ssl string) string {
    brokerUri := ""
    if ssl == "true" {
        brokerUri = "amqps://"+mqUser+":"+mqPassword+"@"+mqHost+":"+mqPort+mqVhost
    } else {
        brokerUri = "amqp://"+mqUser+":"+mqPassword+"@"+mqHost+":"+mqPort+mqVhost
    }
    return brokerUri
}

func resignHeader(r *http.Request, accessKey string, secretKey string, backendUrl string) *http.Request {
    if strings.Contains(backendUrl, "//") {
        host := strings.SplitN(backendUrl, "//", 2)
        r.Host = host[1]
    }
    
    return s3signer.SignV4(*r, accessKey, secretKey, "", "us-east-1")
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

// Extracts the signature from the authorization header
func extractSignature(r *http.Request) string {
    
    re := regexp.MustCompile("Signature=(.*)")
    signature := re.FindStringSubmatch(r.Header.Get("Authorization"))[1]

    return signature
}

// Authenticates the user against stored credentials
// 1) Extracts the username and retrieve the key from the map
// 2) Sign the request with the new credentials
// 3) Compare the signatures between the requests and return authentication status
func authenticateUser(r *http.Request) error {
    re := regexp.MustCompile("Credential=([^/]+)/")
    curAccessKey := re.FindStringSubmatch(r.Header.Get("Authorization"))[1]
    if curSecretKey, ok := usersMap[curAccessKey]; ok {

        if r.Method == http.MethodGet {
        
            signature := extractSignature(r)
            // Create signing request
            nr, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
            if err != nil {
                fmt.Println(err)
            }
            // Add required headers
            nr.Header.Set("X-Amz-Date", r.Header.Get("X-Amz-Date"))
            nr.Header.Set("X-Amz-Content-Sha256", r.Header.Get("X-Amz-Content-Sha256"))
            nr.Host = r.Host
            nr.URL.RawQuery = r.URL.RawQuery
            // Sing the new request
            resignHeader(nr, curAccessKey, curSecretKey, nr.Host)
            curSignature := extractSignature(nr)
            // Compare signatures
            if curSignature != signature {
                err = fmt.Errorf("User signature not authenticated")
                return err
            }
        } 
    } else {
        err = fmt.Errorf("User not existing")
        return err
    }
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
    bucket := "test"
    re := regexp.MustCompile("/([^/]+)/")
    username = re.FindStringSubmatch(r.URL.Path)[1]
    if r.Method == http.MethodGet && strings.Contains(r.URL.String(), "?delimiter") {
        r.URL.Path = "/"+bucket+"/"
        if strings.Contains(r.URL.RawQuery, "&prefix") {
            params := strings.Split(r.URL.RawQuery, "&prefix=")
            r.URL.RawQuery = params[0]+"&prefix="+username+"%2F"+params[1]
        } else {
            r.URL.RawQuery = r.URL.RawQuery+"&prefix="+username+"%2F"
        }
    } else if r.Method == http.MethodGet && strings.Contains(r.URL.String(), "?location") {
        r.URL.Path = "/"+bucket+"/"
    } else if r.Method == http.MethodPost || r.Method == http.MethodPut {
        r.URL.Path = "/"+bucket+r.URL.Path
    }
    resignHeader(r, backedAccessKey, backedSecretKey, backedS3Url)

    // Redirect request
    nr, err := http.NewRequest(r.Method, backedS3Url+r.URL.String(), r.Body)
    if err != nil {
        fmt.Println(err)
    }
    nr.Header = r.Header
    contentLength, err := strconv.ParseInt(r.Header.Get("content-length"), 10, 64)
    nr.ContentLength = contentLength
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

    // Send message to RabbitMQ if the upload is finished
    // TODO: Use the actual username in both cases and size, checksum for multipart upload
    if (nr.Method == http.MethodPut && response.StatusCode == 200 && !strings.Contains(nr.URL.String(), "partNumber")) ||
        (nr.Method == http.MethodPost && response.StatusCode == 200 && strings.Contains(nr.URL.String(), "uploadId")) {
        event := Event{}
        checksum := Checksum{}

        // Case for simple upload
        if nr.Method == http.MethodPut {
            event.Operation = "upload"
            event.Filepath = r.URL.Path
            event.Filesize = contentLength
        // Case for multi-part upload
        } else if nr.Method == http.MethodPost {
            event.Operation = "multipart-upload"
            event.Filepath = r.URL.Path
            event.Filesize = contentLength
        }
        event.Username = username
        checksum.Type = "sha256"
        checksum.Value = r.Header.Get("x-amz-content-sha256")
        event.Checksum = checksum
        
        body, err := json.Marshal(event)
        if err!=nil {
            log.Fatalf("%s", err)
        }
        if err := mq.Publish(brokerExchange, brokerRoutingKey, string(body), true, AmqpChannel); err != nil {
            log.Fatalf("%s", err)
        }        
    }

    // Redirect answer
    io.Copy(w, response.Body)
}
