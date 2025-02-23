package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"
)

type config struct {
	internalPort int
	externalPort int
	authToken    string
	endpoint     string
	upstream     string
	mode         string
	skipVerify   bool
	certFile     string
	keyFile      string
	caFile       string
}

func (c config) makeTlsconfig() (*tls.Config, error) {
	if c.certFile == "" || c.keyFile == "" {
		return nil, fmt.Errorf("certificate and key files are required")
	}
	tlsConfig := tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
	tlsConfig.Certificates = make([]tls.Certificate, 1)
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificates: %v", err)
	}
	tlsConfig.Certificates[0] = cert

	return &tlsConfig, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := fmt.Sscanf(v, "%d"); err == nil {
			return i
		}
	}
	return fallback
}

func loadConfig() config {
	cfg := config{}

	// Define flags with env var fallbacks
	flag.IntVar(&cfg.internalPort, "internal-port",
		envInt("INTERNAL_PORT", 8080),
		"Internal HTTP server port")
	flag.IntVar(&cfg.externalPort, "external-port",
		envInt("EXTERNAL_PORT", 443),
		"External HTTPS server port")
	flag.StringVar(&cfg.mode, "mode", "server", "Mode to run: client or server")
	flag.StringVar(&cfg.endpoint, "endpoint", "", "WebSocket endpoint (client mode)")
	flag.StringVar(&cfg.upstream, "upstream", "", "Upstream server URL (client mode)")
	flag.BoolVar(&cfg.skipVerify, "skip-verify",
		os.Getenv("SKIP_VERIFY") == "true",
		"Skip TLS certificate verification")
	flag.StringVar(&cfg.certFile, "cert-file", os.Getenv("SSL_CERT"), "Path to SSL certificate file")
	flag.StringVar(&cfg.keyFile, "key-file", os.Getenv("SSL_KEY"), "Path to SSL key file")
	flag.StringVar(&cfg.caFile, "ca-file", os.Getenv("CA_FILE"), "Path to certificate authority file")
	flag.Parse()

	// Auth token is required
	cfg.authToken = os.Getenv("AUTH_TOKEN")
	if cfg.authToken == "" {
		log.Fatal("AUTH_TOKEN env variable not set")
	}

	if cfg.mode == "client" && (cfg.endpoint == "" || cfg.upstream == "") {
		log.Fatal("Both endpoint and upstream must be specified in client mode")
	}

	return cfg
}

func RunClient(cfg config) {
	// Build TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.skipVerify,
	}

	// Load CA file if specified
	if cfg.caFile != "" {
		caCert, err := os.ReadFile(cfg.caFile)
		if err != nil {
			log.Fatalf("Failed to read CA file: %v", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			log.Fatal("Failed to append CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if both cert and key are specified
	if cfg.certFile != "" && cfg.keyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.certFile, cfg.keyFile)
		if err != nil {
			log.Fatalf("Failed to load client certificate: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	client, err := NewWebSocketClient(cfg.endpoint, cfg.authToken, cfg.upstream, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start WebSocket client: %v", err)
	}
	log.Printf("WebSocket client connected to %s, proxying to %s", cfg.endpoint, cfg.upstream)
	client.AcceptMessages()
}

func main() {
	cfg := loadConfig()

	if cfg.mode == "client" {
		RunClient(cfg)
	} else {
		server := NewServer(cfg)
		server.Start()
	}
}
