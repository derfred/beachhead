package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// PathProxyHandler handles proxying requests to local ports based on path rules
type PathProxyHandler struct {
	rules []PathProxyRule
}

func NewPathProxyHandler(rules []PathProxyRule) *PathProxyHandler {
	return &PathProxyHandler{
		rules: rules,
	}
}

func (h *PathProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Find matching rule
	var matchingRule *PathProxyRule
	for _, rule := range h.rules {
		if strings.HasPrefix(r.URL.Path, rule.Path) {
			matchingRule = &rule
			break
		}
	}

	if matchingRule == nil {
		http.Error(w, "No matching proxy rule found", http.StatusNotFound)
		return
	}

	// Check if this is a WebSocket upgrade request
	if isWebSocketRequest(r) {
		h.handleWebSocket(w, r, matchingRule)
		return
	} else {
		h.handleRequest(w, r, matchingRule)
	}
}

// isWebSocketRequest checks if the request is a WebSocket upgrade request
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func (h *PathProxyHandler) handleRequest(w http.ResponseWriter, r *http.Request, rule *PathProxyRule) {
	// Create new URL for the proxy target
	targetURL := *r.URL
	targetURL.Scheme = "http"
	targetURL.Host = fmt.Sprintf("localhost:%d", rule.Port)

	// Replace the matched path with the upstream path
	remainingPath := strings.TrimPrefix(r.URL.Path, rule.Path)
	if remainingPath == "" {
		remainingPath = "/"
	}
	// Ensure we don't get double slashes when joining paths
	upstreamPath := rule.UpstreamPath
	if strings.HasSuffix(upstreamPath, "/") && strings.HasPrefix(remainingPath, "/") {
		upstreamPath = strings.TrimSuffix(upstreamPath, "/")
	} else if !strings.HasSuffix(upstreamPath, "/") && !strings.HasPrefix(remainingPath, "/") {
		upstreamPath = upstreamPath + "/"
	}
	targetURL.Path = upstreamPath + remainingPath

	// Create new request
	proxyReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Error creating proxy request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Send request
	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Error forwarding request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("Error copying response body: %v", err)
	}
}

// handleWebSocket handles WebSocket proxy connections
func (h *PathProxyHandler) handleWebSocket(w http.ResponseWriter, r *http.Request, rule *PathProxyRule) {
	// Create the target URL for the WebSocket connection
	remainingPath := strings.TrimPrefix(r.URL.Path, rule.Path)
	if remainingPath == "" {
		remainingPath = "/"
	}

	// Ensure we don't get double slashes when joining paths
	upstreamPath := rule.UpstreamPath
	if strings.HasSuffix(upstreamPath, "/") && strings.HasPrefix(remainingPath, "/") {
		upstreamPath = strings.TrimSuffix(upstreamPath, "/")
	} else if !strings.HasSuffix(upstreamPath, "/") && !strings.HasPrefix(remainingPath, "/") {
		upstreamPath = upstreamPath + "/"
	}

	// For localhost connections, always use "ws" scheme for the backend
	// as internal connections should be unencrypted regardless of the client connection
	targetURL := url.URL{
		Scheme: "ws", // Local backend connections are always unencrypted
		Host:   fmt.Sprintf("localhost:%d", rule.Port),
		Path:   upstreamPath + remainingPath,
	}

	// Copy query parameters
	targetURL.RawQuery = r.URL.RawQuery

	// Create header for dialing the backend
	requestHeader := http.Header{}
	// Don't copy WebSocket-specific headers as they will be added by the Dial method
	for key, values := range r.Header {
		// Skip headers that are managed by the WebSocket library
		if strings.EqualFold(key, "Connection") ||
			strings.EqualFold(key, "Upgrade") ||
			strings.EqualFold(key, "Sec-Websocket-Key") ||
			strings.EqualFold(key, "Sec-Websocket-Version") ||
			strings.EqualFold(key, "Sec-Websocket-Extensions") ||
			strings.EqualFold(key, "Sec-Websocket-Protocol") {
			continue
		}
		for _, value := range values {
			requestHeader.Add(key, value)
		}
	}

	// Create WebSocket dialer
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
	}

	// Connect to the backend WebSocket server
	backendConn, resp, err := dialer.Dial(targetURL.String(), requestHeader)
	if err != nil {
		if resp != nil {
			// If we got a response, try to return its status
			statusCode := resp.StatusCode
			http.Error(w, fmt.Sprintf("Failed to connect to backend WebSocket: %v", err), statusCode)
		} else {
			http.Error(w, fmt.Sprintf("Failed to connect to backend WebSocket: %v", err), http.StatusBadGateway)
		}
		log.Printf("WebSocket dial error: %v", err)
		return
	}
	defer backendConn.Close()

	// Upgrade the client connection to WebSocket
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
	}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade client connection: %v", err)
		return
	}
	defer clientConn.Close()

	// Create channels to signal when connections are closed
	errChan := make(chan error, 2)

	// Copy messages from backend to client
	go func() {
		for {
			messageType, message, err := backendConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}

			if err := clientConn.WriteMessage(messageType, message); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// Copy messages from client to backend
	go func() {
		for {
			messageType, message, err := clientConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}

			if err := backendConn.WriteMessage(messageType, message); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// Wait for either connection to close
	<-errChan
}
