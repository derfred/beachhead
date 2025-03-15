package main

import (
	"bytes"
	"fmt"
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

type messageRecord struct {
	messageType int
	data        []byte
}

// mockProxy embeds Proxy and adds message recording capability
type mockProxy struct {
	*Proxy
	messages []messageRecord
}

func newMockProxy() *mockProxy {
	return &mockProxy{
		Proxy: &Proxy{
			activeRequests: make(map[byte]*Request),
		},
		messages: make([]messageRecord, 0),
	}
}

func (mp *mockProxy) WriteMessage(messageType int, data []byte) error {
	mp.messages = append(mp.messages, messageRecord{messageType: messageType, data: data})
	return nil
}

// TestParseMessage tests the parseMessage function for both text and binary messages.
func TestParseMessage(t *testing.T) {
	// Test for text message
	textMsg := "NewRequest 5"
	pm, err := parseMessage(websocket.TextMessage, []byte(textMsg))
	if err != nil {
		t.Fatalf("parseMessage failed for text message: %v", err)
	}
	if pm.RequestID != 5 {
		t.Errorf("Expected RequestID 5, got %d", pm.RequestID)
	}
	if string(pm.Message) != "NewRequest" {
		t.Errorf("Expected Message 'NewRequest', got '%s'", string(pm.Message))
	}

	// Test for binary message
	binaryMsg := append([]byte{7}, []byte("test")...)
	pm, err = parseMessage(websocket.BinaryMessage, binaryMsg)
	if err != nil {
		t.Fatalf("parseMessage failed for binary message: %v", err)
	}
	if pm.RequestID != 7 {
		t.Errorf("Expected RequestID 7, got %d", pm.RequestID)
	}
	if string(pm.Message) != "test" {
		t.Errorf("Expected Message 'test', got '%s'", string(pm.Message))
	}
}

// TestSendRequest tests the sendRequest method of Request.
func TestSendRequest(t *testing.T) {
	// Create a mock proxy to capture messages
	mp := newMockProxy()

	// Create a Request with a specific RequestID and the mock proxy
	req := &Request{
		RequestID: 5,
		proxy:     mp,
	}

	// Create an HTTP request with a body content
	bodyContent := "hello world"
	httpReq, err := http.NewRequest("GET", "http://example.com/test", bytes.NewBufferString(bodyContent))
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}
	httpReq.Proto = "HTTP/1.1"

	// Call sendRequest
	err = req.sendRequest(httpReq)
	if err != nil {
		t.Fatalf("sendRequest failed: %v", err)
	}

	// Now verify the messages captured
	expectedMessages := []messageRecord{}

	// First message: Binary message with headers (prepended with RequestID)
	// Expected content: RequestID byte + "GET http://example.com/test HTTP/1.1\n\n"
	headerStr := fmt.Sprintf("GET %s %s\n\n", httpReq.URL.String(), httpReq.Proto)
	expHeader := append([]byte{req.RequestID}, []byte(headerStr)...)
	expectedMessages = append(expectedMessages, messageRecord{messageType: websocket.BinaryMessage, data: expHeader})

	// If body exists, then a text message for RequestHeadersComplete
	if httpReq.Body != nil {
		expectedText := fmt.Sprintf("RequestHeadersComplete %d", req.RequestID)
		expectedMessages = append(expectedMessages, messageRecord{messageType: websocket.TextMessage, data: []byte(expectedText)})

		// Body message: might be sent in one chunk. Since our buffer is small, entire body sent as binary with prefix
		expBody := append([]byte{req.RequestID}, []byte(bodyContent)...)
		expectedMessages = append(expectedMessages, messageRecord{messageType: websocket.BinaryMessage, data: expBody})
	}

	// Finally, a text message for RequestComplete
	expComplete := fmt.Sprintf("RequestComplete %d", req.RequestID)
	expectedMessages = append(expectedMessages, messageRecord{messageType: websocket.TextMessage, data: []byte(expComplete)})

	if len(mp.messages) != len(expectedMessages) {
		t.Fatalf("Expected %d messages, got %d", len(expectedMessages), len(mp.messages))
	}

	for i, msg := range mp.messages {
		expMsg := expectedMessages[i]
		if msg.messageType != expMsg.messageType {
			t.Errorf("Message %d: expected type %d, got %d", i, expMsg.messageType, msg.messageType)
		}
		if !bytes.Equal(msg.data, expMsg.data) {
			t.Errorf("Message %d: expected data '%v', got '%v'", i, expMsg.data, msg.data)
		}
	}
}

// TestHandleRequestFailedStart tests that the handler exits early when startNewRequest fails
func TestHandleRequestFailedStart(t *testing.T) {
	// Create a proxy with no websocket connection
	proxy := NewProxy()

	// Create a test HTTP request
	req, err := http.NewRequest("GET", "http://example.com/test", nil)
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	// Create a response recorder to capture the response
	recorder := httptest.NewRecorder()

	// Call HandleRequest - this should not panic even though there's no websocket connection
	proxy.HandleRequest(recorder, req)

	// Verify that we got the expected error response
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status code %d, got %d", http.StatusServiceUnavailable, recorder.Code)
	}

	// Verify the error message
	expectedError := "no websocket connection available"
	if !strings.Contains(recorder.Body.String(), expectedError) {
		t.Errorf("Expected error message to contain '%s', got '%s'", expectedError, recorder.Body.String())
	}
}

// TestHandleRequestMaxConcurrentRequests tests that the handler exits early when maximum concurrent requests is reached
func TestHandleRequestMaxConcurrentRequests(t *testing.T) {
	// Create a proxy with an empty request ID queue to simulate maximum concurrent requests
	proxy := NewProxy()
	proxy.requestIDQueue = []byte{} // Empty the queue

	// Create a mock websocket connection
	proxy.ws = &websocket.Conn{}

	// Create a test HTTP request
	req, err := http.NewRequest("GET", "http://example.com/test", nil)
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	// Create a response recorder to capture the response
	recorder := httptest.NewRecorder()

	// Call HandleRequest - this should not panic even though there are no request IDs available
	proxy.HandleRequest(recorder, req)

	// Verify that we got the expected error response
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status code %d, got %d", http.StatusServiceUnavailable, recorder.Code)
	}

	// Verify the error message
	expectedError := "maximum number of concurrent requests reached (255)"
	if !strings.Contains(recorder.Body.String(), expectedError) {
		t.Errorf("Expected error message to contain '%s', got '%s'", expectedError, recorder.Body.String())
	}
}
