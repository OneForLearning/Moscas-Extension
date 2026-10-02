// Minimal Go crypto/tls server for the testbed.
// usage: go-server PORT CERT KEY MODE   (MODE: enforce | prefer | classical-first)
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
)

func main() {
	port, cert, key, mode := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	cfg := &tls.Config{}
	switch mode {
	case "enforce":
		cfg.MinVersion = tls.VersionTLS13
		cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	case "prefer":
		cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	case "classical-first":
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.X25519MLKEM768}
	}
	srv := &http.Server{Addr: "127.0.0.1:" + port, TLSConfig: cfg,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })}
	if err := srv.ListenAndServeTLS(cert, key); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
