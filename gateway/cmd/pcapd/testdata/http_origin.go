package main

import (
	"io"
	"net/http"
)

func main() {
	server := &http.Server{Addr: "127.0.0.1:18082", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "container-real-pcap-response")
	})}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
