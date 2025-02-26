package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebsocketConnectionTerminationCleanup(t *testing.T) {
	// Create a new proxy
	proxy := NewProxy()

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/ws") {
			proxy.HandleConnection(w, r)
		}
	}))
	defer server.Close()

	// Convert http URL to ws URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	// First connection
	ws1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect first client: %v", err)
	}

	// Abruptly close the connection to simulate client termination
	ws1.Close()

	// Wait a brief moment for the connection to fully close
	time.Sleep(100 * time.Millisecond)

	// Try to establish a second connection - this should succeed
	ws2, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to establish second connection: %v", err)
	}
	defer ws2.Close()

	// Verify that we get a 101 Switching Protocols status (standard for successful WebSocket upgrade)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("Expected status code %d, got %d", http.StatusSwitchingProtocols, resp.StatusCode)
	}
}
