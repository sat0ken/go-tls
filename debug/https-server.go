package main

import (
	"crypto/tls"
	"fmt"
	"gotls"
	"log"
	"net/http"
	"os"
)

// https://github.com/denji/golang-tls
func HelloServer(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("client from : %s\n", req.RemoteAddr)
	fmt.Fprintf(w, "hello\n")
	//w.Header().Set("Content-Type", "text/plain")
	//w.Write([]byte(`hello https server`))
	//w.Write([]byte("\n"))
}

func main() {
	http.HandleFunc("/", HelloServer)

	w := os.Stdout
	server := &http.Server{
		Addr: ":10443",
		TLSConfig: &tls.Config{
			Rand:       gotls.ZeroSource{}, // for example only; don't do this.
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			//CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
			KeyLogWriter: w,
		},
	}

	err := server.ListenAndServeTLS("./pems/my-tls.pem", "./pems/my-tls-key.pem")
	if err != nil {
		log.Fatal(err)
	}
}
