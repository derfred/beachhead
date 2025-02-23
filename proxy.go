package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Proxy struct {
	upgrader websocket.Upgrader
	ws       *websocket.Conn
	mutex    sync.Mutex
	// Add channels for message passing
	messages chan []byte
	done     chan struct{}
}

func NewProxy() *Proxy {
	return &Proxy{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		messages: make(chan []byte, 100), // Buffer size of 100 messages
		done:     make(chan struct{}),
	}
}

func (p *Proxy) HandleConnection(w http.ResponseWriter, r *http.Request) {
	// Upgrade the connection to a websocket
	ws, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}
	defer ws.Close()

	// Set the websocket connection
	p.mutex.Lock()
	// Check if a websocket client is already connected
	if p.ws != nil {
		p.mutex.Unlock()
		http.Error(w, "Websocket client already connected", http.StatusConflict)
		return
	}
	p.ws = ws
	p.mutex.Unlock()

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the read pump
	go func() {
		defer cancel() // Ensure context is canceled when we exit

		for {
			messageType, message, err := ws.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("WebSocket read error: %v", err)
				}
				return
			}

			// Only handle binary messages
			if messageType != websocket.BinaryMessage {
				continue
			}

			// Try to send the message, respect context cancellation
			select {
			case p.messages <- message:
				// Message sent successfully
			case <-ctx.Done():
				return
			default:
				// Channel is full, implement backpressure by waiting
				select {
				case p.messages <- message:
					// Message sent successfully after waiting
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
					// Timeout after 5 seconds of backpressure
					log.Printf("Message dropped due to backpressure")
				}
			}
		}
	}()

	// Wait for done signal or context cancellation
	<-ctx.Done()

	// Clean up
	p.mutex.Lock()
	p.ws = nil
	p.mutex.Unlock()

	// Drain any remaining messages
	for {
		select {
		case <-p.messages:
		default:
			return
		}
	}
}

func (p *Proxy) HandleRequest(w http.ResponseWriter, r *http.Request) {
	// Check if a websocket client is connected
	p.mutex.Lock()
	ws := p.ws
	p.mutex.Unlock()

	if ws == nil {
		http.Error(w, "No WebSocket client connected", http.StatusServiceUnavailable)
		return
	}

	// Proxy the request to the websocket client
	var reqBuilder strings.Builder
	reqBuilder.WriteString(fmt.Sprintf("%s %s %s\n", r.Method, r.URL.String(), r.Proto))
	for key, values := range r.Header {
		for _, value := range values {
			reqBuilder.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	reqBuilder.WriteString("\n")

	if err := ws.WriteMessage(websocket.BinaryMessage, []byte(reqBuilder.String())); err != nil {
		http.Error(w, "Failed to write to WebSocket: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Body != nil {
		io.Copy(ws.UnderlyingConn(), r.Body)
	}

	var headerBuf bytes.Buffer
	bodyStarted := false

	// Read from the message channel instead of directly from websocket
	messageTimeout := time.NewTimer(30 * time.Second)
	defer messageTimeout.Stop()

	for !bodyStarted {
		select {
		case message := <-p.messages:
			headerBuf.Write(message)
			if i := bytes.Index(headerBuf.Bytes(), []byte("\r\n\r\n")); i >= 0 {
				headerData := headerBuf.Bytes()[:i]
				remainingData := headerBuf.Bytes()[i+4:]

				if err := parseHeaders(string(headerData), w); err != nil {
					http.Error(w, "Invalid response headers: "+err.Error(), http.StatusInternalServerError)
					return
				}

				if len(remainingData) > 0 {
					w.Write(remainingData)
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
				}

				bodyStarted = true
			}
		case <-messageTimeout.C:
			http.Error(w, "Timeout waiting for response headers", http.StatusGatewayTimeout)
			return
		}
	}

	// Set a shorter timeout for body messages
	messageTimeout.Reset(5 * time.Second)

	for {
		select {
		case message := <-p.messages:
			w.Write(message)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			messageTimeout.Reset(5 * time.Second)
		case <-messageTimeout.C:
			// Consider this a normal EOF condition
			return
		}
	}
}

func parseHeaders(headerData string, w http.ResponseWriter) error {
	lines := strings.Split(headerData, "\r\n")
	if len(lines) == 0 {
		return fmt.Errorf("no headers found")
	}

	statusLine := lines[0]
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("invalid status line: %s", statusLine)
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid status code: %s", parts[1])
	}

	headers := make(http.Header)
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		headers.Add(key, value)
	}

	for k, v := range headers {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}

	w.WriteHeader(code)
	return nil
}
