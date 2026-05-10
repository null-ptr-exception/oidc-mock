package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"gopkg.in/yaml.v3"
)

func main() {
	configPath := flag.String("config", "", "path to config YAML file")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		log.Fatalf("failed to generate key pair: %v", err)
	}

	srv := &Server{
		Config:  cfg,
		KeyPair: kp,
		Store:   NewStore(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", srv.HandleDiscovery)
	mux.HandleFunc("GET /authorize", srv.HandleAuthorize)
	mux.HandleFunc("POST /authorize/callback", srv.HandleAuthorizeCallback)
	mux.HandleFunc("POST /token", srv.HandleToken)
	mux.HandleFunc("GET /jwks", srv.HandleJWKS)
	mux.HandleFunc("GET /userinfo", srv.HandleUserinfo)
	mux.HandleFunc("POST /revoke", srv.HandleRevoke)
	mux.HandleFunc("GET /end-session", srv.HandleEndSession)

	addr := fmt.Sprintf(":%d", cfg.Port)
	cfgYAML, _ := yaml.Marshal(cfg)
	log.Printf("Runtime OIDC_CONFIG:\n---\n%s---", cfgYAML)
	log.Printf("oidc-mock listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
