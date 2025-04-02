package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

type Server struct {
	internalListener    net.Listener
	internalServer      *http.Server
	externalListener    net.Listener
	externalTlsListener net.Listener
	externalServer      *http.Server
	proxy               *Proxy
	workspace           *WorkspaceHandler
	pathProxies         []PathProxyRule
	metrics             *MetricsCollector
}

func authenticate(authToken string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		const bearerPrefix = "Bearer "
		if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		token := authHeader[len(bearerPrefix):]
		if token != authToken {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func NewServer(cfg config) *Server {
	metricsCollector := NewMetricsCollector()

	result := Server{
		proxy:       NewProxy(),
		workspace:   NewWorkspaceHandler(cfg),
		pathProxies: cfg.PathProxies,
		metrics:     metricsCollector,
	}

	// Generate self-signed cert if not provided via env vars.
	generated, err := GetOrGenerateCert(&cfg)
	if err != nil {
		log.Fatalf("Error generating certificate: %v", err)
	}
	if generated {
		log.Printf("Using self-signed certificate @ %s", cfg.certFile)
	}

	// Setup external HTTPS server with listener first
	extListener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.externalPort))
	if err != nil {
		log.Fatalf("Failed to create external listener: %v", err)
	}
	result.externalListener = extListener

	if !cfg.useHttp {
		tlsConfig, err := cfg.makeTlsconfig()
		if err != nil {
			log.Fatalf("Failed to create TLS config: %v", err)
		}
		result.externalTlsListener = tls.NewListener(extListener, tlsConfig)
	}

	// Setup external HTTP server
	extMux := http.NewServeMux()
	extMux.HandleFunc("/health", HealthHandler)
	extMux.HandleFunc("/version", VersionHandler)
	extMux.Handle("/workspace", authenticate(cfg.authToken, result.workspace.CreateWorkspaceHandler()))
	extMux.Handle("/workspace/upload/", authenticate(cfg.authToken, result.workspace.MakeWorkspaceUploadHandler()))
	extMux.Handle("/workspace/download/", authenticate(cfg.authToken, result.workspace.MakeWorkspaceDownloadHandler()))
	extMux.Handle("/ws", authenticate(cfg.authToken, http.HandlerFunc(result.proxy.HandleConnection)))

	// Add metrics endpoints
	extMux.Handle("/metrics", metricsCollector.PrometheusHandler())
	extMux.Handle("/metrics/history", authenticate(cfg.authToken, http.HandlerFunc(metricsCollector.MetricsHandler)))

	// Process management endpoints
	extMux.Handle("/workspace/exec/", authenticate(cfg.authToken, result.workspace.MakeExecHandler()))
	extMux.Handle("/workspace/processes", authenticate(cfg.authToken, result.workspace.MakeProcessListHandler()))
	extMux.Handle("/workspace/process/", authenticate(cfg.authToken, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		processID := strings.TrimPrefix(r.URL.Path, "/workspace/process/")
		if processID == "" {
			http.Error(w, "Process ID is required", http.StatusBadRequest)
			return
		}

		isOutput := strings.HasSuffix(processID, "/output")
		if isOutput {
			processID = strings.TrimSuffix(processID, "/output")
		}

		// Call the ProcessRegistry to get the process
		process, exists := result.workspace.processRegistry.GetProcess(processID)
		if !exists {
			http.Error(w, fmt.Sprintf("Process with ID %s not found", processID), http.StatusNotFound)
			return
		}

		// Route based on HTTP method
		switch r.Method {
		case http.MethodGet:
			if isOutput {
				result.workspace.ProcessOutputHandler(w, r, process)
			} else {
				result.workspace.ProcessDetailsHandler(w, process)
			}
		case http.MethodDelete:
			// DELETE requests are handled by the terminate handler
			result.workspace.ProcessTerminateHandler(w, process)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	// Add path proxy handlers
	if len(cfg.PathProxies) > 0 {
		pathProxyHandler := NewPathProxyHandler(cfg.PathProxies)
		extMux.Handle("/", pathProxyHandler)
	}

	result.externalServer = &http.Server{
		Handler: extMux,
	}

	// Setup internal HTTP server
	intMux := http.NewServeMux()
	intMux.HandleFunc("/", result.proxy.HandleRequest)

	// Create the internal listener
	intListener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", cfg.internalPort))
	if err != nil {
		log.Fatalf("Failed to create internal listener: %v", err)
	}
	result.internalListener = intListener
	result.internalServer = &http.Server{
		Handler: intMux,
	}

	return &result
}

func (s *Server) Start() {
	s.metrics.Start()

	go func() {
		log.Printf("Starting internal HTTP server on %s", s.internalListener.Addr().String())
		if err := s.internalServer.Serve(s.internalListener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Internal server error: %v", err)
		}
	}()

	log.Printf("Starting external HTTPS server on %s", s.externalListener.Addr().String())

	extListener := s.externalListener
	if s.externalTlsListener != nil {
		extListener = s.externalTlsListener
	}
	if err := s.externalServer.Serve(extListener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("External server error: %v", err)
	}
}

func (s *Server) GetInternalPort() int {
	addr := s.internalListener.Addr().(*net.TCPAddr)
	return addr.Port
}

func (s *Server) GetExternalPort() int {
	addr := s.externalListener.Addr().(*net.TCPAddr)
	return addr.Port
}

func (s *Server) Shutdown() {
	s.metrics.Stop()

	if err := s.internalServer.Close(); err != nil {
		log.Printf("Error shutting down internal server: %v", err)
	}
	if err := s.externalServer.Close(); err != nil {
		log.Printf("Error shutting down external server: %v", err)
	}
}
