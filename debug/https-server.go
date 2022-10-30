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
			Rand:         gotls.ZeroSource{}, // for example only; don't do this.
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			KeyLogWriter: w,
		},
	}

	err := server.ListenAndServeTLS("./my-tls.pem", "./my-tls-key.pem")
	if err != nil {
		log.Fatal(err)
	}
}
