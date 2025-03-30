package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// ShellTemplate holds an optional user and a command template.
type ShellTemplate struct {
	User     string
	Template string
}

// PathProxyRule defines a rule for proxying requests from a path to a local port
type PathProxyRule struct {
	Path         string // The path to match (e.g. "/jupyter")
	Port         int    // The local port to proxy to
	UpstreamPath string // The path to use on the upstream server (e.g. "/" or "/api")
}

type config struct {
	internalPort   int
	externalPort   int
	useHttp        bool
	authToken      string
	endpoint       string
	upstream       string
	mode           string
	skipVerify     bool
	certFile       string
	keyFile        string
	caFile         string
	shellFlags     []string
	ShellTemplates map[string]ShellTemplate
	Workspace      string
	PathProxies    []PathProxyRule // List of path-based proxy rules
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

func envInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return defaultVal
}

func setupServerFlags(fs *flag.FlagSet, cfg *config) {
	fs.IntVar(&cfg.internalPort, "internal-port", envInt("INTERNAL_PORT", 8080),
		"Internal HTTP server port (env: INTERNAL_PORT)")
	fs.IntVar(&cfg.externalPort, "external-port", envInt("EXTERNAL_PORT", 443),
		"External HTTPS server port (env: EXTERNAL_PORT)")
	fs.BoolVar(&cfg.skipVerify, "skip-verify", os.Getenv("SKIP_VERIFY") == "true",
		"Skip TLS certificate verification (env: SKIP_VERIFY)")
	fs.BoolVar(&cfg.useHttp, "use-http", false, "Don't use TLS on the external interface")
	fs.StringVar(&cfg.certFile, "cert-file", os.Getenv("SSL_CERT"),
		"Path to SSL certificate file (env: SSL_CERT)")
	fs.StringVar(&cfg.keyFile, "key-file", os.Getenv("SSL_KEY"),
		"Path to SSL key file (env: SSL_KEY)")
	fs.StringVar(&cfg.caFile, "ca-file", os.Getenv("CA_FILE"),
		"Path to certificate authority file (env: CA_FILE)")
	fs.StringVar(&cfg.authToken, "auth-token", os.Getenv("AUTH_TOKEN"),
		"Authorization token (env: AUTH_TOKEN)")
	fs.StringVar(&cfg.Workspace, "workspace", os.Getenv("WORKSPACE"),
		"Base workspace directory (env: WORKSPACE)")

	fs.Func("shell", "Define shell command template in format name[@user]:template", func(s string) error {
		cfg.shellFlags = append(cfg.shellFlags, s)
		return nil
	})

	fs.Func("proxy", "Define proxy rule in format path:port:upstream_path (e.g. /jupyter:8000:/)", func(s string) error {
		parts := strings.Split(s, ":")
		if len(parts) != 3 {
			return fmt.Errorf("invalid path proxy format. Use path:port:upstream_path")
		}

		path := parts[0]
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("invalid port number: %v", err)
		}

		upstreamPath := parts[2]
		if !strings.HasPrefix(upstreamPath, "/") {
			upstreamPath = "/" + upstreamPath
		}

		cfg.PathProxies = append(cfg.PathProxies, PathProxyRule{
			Path:         path,
			Port:         port,
			UpstreamPath: upstreamPath,
		})
		return nil
	})
}

// new helper to parse a shell flag of form "name[@user]:template"
func parseShellFlag(s string) (name, user, tmpl string, err error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid shell flag format")
	}
	left := parts[0]
	tmpl = parts[1]
	if at := strings.Index(left, "@"); at != -1 {
		name = left[:at]
		user = left[at+1:]
	} else {
		name = left
	}
	return name, user, tmpl, nil
}

// new helper to process env vars starting with BEACHHEAD_SHELL_
func processShellEnv() map[string]ShellTemplate {
	templates := make(map[string]ShellTemplate)
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "BEACHHEAD_SHELL_") {
			kv := strings.SplitN(env, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := kv[0]
			// command name is lower-case of suffix after BEACHHEAD_SHELL_
			name := strings.ToLower(strings.TrimPrefix(key, "BEACHHEAD_SHELL_"))
			val := kv[1]
			// For env var, if a colon is present, the portion before colon is user.
			if idx := strings.Index(val, ":"); idx != -1 {
				user := val[:idx]
				tmpl := val[idx+1:]
				templates[name] = ShellTemplate{User: user, Template: tmpl}
			} else {
				templates[name] = ShellTemplate{Template: val}
			}
		}
	}
	return templates
}

// new helper to process env vars starting with BEACHHEAD_PATH_PROXY_
func processPathProxyEnv() []PathProxyRule {
	var rules []PathProxyRule
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "BEACHHEAD_PROXY_") {
			kv := strings.SplitN(env, "=", 2)
			if len(kv) != 2 {
				continue
			}
			val := kv[1]
			// For env var, format is path:port:upstream_path
			parts := strings.Split(val, ":")
			if len(parts) != 3 {
				log.Printf("Invalid path proxy format in env var: %s", env)
				continue
			}

			path := parts[0]
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}

			port, err := strconv.Atoi(parts[1])
			if err != nil {
				log.Printf("Invalid port number in env var: %s", env)
				continue
			}

			upstreamPath := parts[2]
			if !strings.HasPrefix(upstreamPath, "/") {
				upstreamPath = "/" + upstreamPath
			}

			rules = append(rules, PathProxyRule{
				Path:         path,
				Port:         port,
				UpstreamPath: upstreamPath,
			})
		}
	}
	return rules
}

// Process shell flags and env vars after flag parsing.
func processShellTemplates(cfg *config) {
	cfg.ShellTemplates = make(map[string]ShellTemplate)
	// Process -shell flag entries.
	for _, s := range cfg.shellFlags {
		name, user, tmpl, err := parseShellFlag(s)
		if err != nil {
			log.Fatalf("Error parsing -shell flag: %v", err)
		}
		cfg.ShellTemplates[name] = ShellTemplate{User: user, Template: tmpl}
	}
	// Merge in env var definitions (env takes lower-case key).
	envTemplates := processShellEnv()
	for name, t := range envTemplates {
		cfg.ShellTemplates[name] = t
	}
}

func setupClientFlags(fs *flag.FlagSet, cfg *config) {
	fs.StringVar(&cfg.endpoint, "endpoint", os.Getenv("ENDPOINT"),
		"WebSocket endpoint (env: ENDPOINT)")
	fs.StringVar(&cfg.upstream, "upstream", os.Getenv("UPSTREAM"),
		"Upstream server URL (env: UPSTREAM)")
	fs.BoolVar(&cfg.skipVerify, "skip-verify", os.Getenv("SKIP_VERIFY") == "true",
		"Skip TLS certificate verification (env: SKIP_VERIFY)")
	fs.StringVar(&cfg.authToken, "auth-token", os.Getenv("AUTH_TOKEN"),
		"Authorization token (env: AUTH_TOKEN)")
}

func loadConfig() config {
	if len(os.Args) < 2 {
		printUsageAndExit()
	}

	cfg := config{}
	cfg.mode = os.Args[1]

	switch cfg.mode {
	case "server":
		serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
		setupServerFlags(serverCmd, &cfg)
		if err := serverCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("Error parsing server command: %v", err)
		}

		if cfg.authToken == "" {
			log.Fatal("Authorization token not set")
		}
		processShellTemplates(&cfg)
		// Process path proxy environment variables
		cfg.PathProxies = append(cfg.PathProxies, processPathProxyEnv()...)

	case "client":
		clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
		setupClientFlags(clientCmd, &cfg)
		if err := clientCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("Error parsing client command: %v", err)
		}

		if cfg.authToken == "" {
			log.Fatal("Authorization token not set")
		}
		if cfg.endpoint == "" || cfg.upstream == "" {
			log.Fatal("Both endpoint and upstream must be specified in client mode")
		}

	default:
		printUsageAndExit()
	}

	return cfg
}

func printUsageAndExit() {
	fmt.Printf(`Usage: %s <mode> [options]

Modes:
  server    Run in server mode
  client    Run in client mode

Run '%s <mode> -h' for mode-specific options
`, os.Args[0], os.Args[0])
	os.Exit(1)
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
		if cfg.Workspace != "" {
			if err := os.MkdirAll(cfg.Workspace, 0755); err != nil {
				log.Fatalf("Failed to create workspace directory: %v", err)
			}
		}

		server := NewServer(cfg)
		server.Start()
	}
}
