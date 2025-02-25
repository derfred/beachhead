package main

import (
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

// Define RequestState enum
type RequestState int

const (
	StateHeaderSent RequestState = iota
	StateRequestSent
	StateResponseHeaderReceived
)

// Add a struct to hold metadata about the current request, using an enum for state, and including the response channel
type RequestMetadata struct {
	Path                  string
	Method                string
	State                 RequestState
	RequestContentLength  int64
	ResponseContentLength int64
	ResponseChan          chan []byte
	ErrorChan             chan error
}

// Update Proxy struct to include fields for the active request and its response channel
type Proxy struct {
	upgrader       websocket.Upgrader
	mutex          sync.Mutex
	ws             *websocket.Conn
	currentRequest *RequestMetadata
}

func NewProxy() *Proxy {
	return &Proxy{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		currentRequest: nil,
	}
}

func (p *Proxy) HandleConnection(w http.ResponseWriter, r *http.Request) {
	// Upgrade the connection to a websocket
	ws, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}

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

	go p.readPump(ws)
}

func (p *Proxy) readPump(ws *websocket.Conn) {
	defer ws.Close()
	for {
		_, message, err := ws.ReadMessage()
		if err != nil {
			p.mutex.Lock()
			if p.currentRequest != nil && p.currentRequest.ErrorChan != nil && !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				select {
				case p.currentRequest.ErrorChan <- err:
				default:
					log.Println("Error channel full, dropping error")
				}
			}
			p.mutex.Unlock()
			break
		}

		p.mutex.Lock()
		var respChan chan []byte
		if p.currentRequest != nil {
			respChan = p.currentRequest.ResponseChan
		}
		p.mutex.Unlock()

		if respChan != nil {
			// Non-blocking send to avoid deadlocks if channel buffer is full
			select {
			case respChan <- message:
			// message forwarded
			default:
				log.Println("Response channel full, dropping message")
			}
		}
	}
}

func sendRequest(r *http.Request, ws *websocket.Conn) error {
	// Proxy the request to the websocket client
	var reqBuilder strings.Builder
	reqBuilder.WriteString(fmt.Sprintf("%s %s %s\n", r.Method, r.URL.String(), r.Proto))
	for key, values := range r.Header {
		for _, value := range values {
			reqBuilder.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	reqBuilder.WriteString("\n")

	// Write headers first
	if err := ws.WriteMessage(websocket.BinaryMessage, []byte(reqBuilder.String())); err != nil {
		return fmt.Errorf("failed to write to WebSocket: %w", err)
	}

	// Stream the body in chunks if present
	if r.Body != nil {
		// Tell the client that the headers are complete
		if err := ws.WriteMessage(websocket.TextMessage, []byte("HeaderComplete")); err != nil {
			return fmt.Errorf("failed to write to WebSocket: %w", err)
		}

		buffer := make([]byte, 32*1024) // 32KB buffer
		for {
			n, err := r.Body.Read(buffer)
			if err != nil && err != io.EOF {
				return fmt.Errorf("failed to read request body: %w", err)
			}
			if n > 0 {
				// Send the chunk as a binary message
				if err := ws.WriteMessage(websocket.BinaryMessage, buffer[:n]); err != nil {
					return fmt.Errorf("failed to write to WebSocket: %w", err)
				}
			}
			if err == io.EOF {
				break
			}
		}
	}

	// Tell the client that the request is complete
	if err := ws.WriteMessage(websocket.TextMessage, []byte("RequestComplete")); err != nil {
		return fmt.Errorf("failed to write to WebSocket: %w", err)
	}

	return nil
}

func (p *Proxy) startNewRequest(r *http.Request) *websocket.Conn {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	ws := p.ws
	if ws == nil {
		return nil
	}

	requestContentLength := int64(-1)
	if clStr := r.Header.Get("Content-Length"); clStr != "" {
		if cl, err := strconv.ParseInt(clStr, 10, 64); err == nil {
			requestContentLength = cl
		}
	}
	p.currentRequest = &RequestMetadata{
		Path:                  r.URL.Path,
		Method:                r.Method,
		State:                 StateHeaderSent,
		RequestContentLength:  requestContentLength,
		ResponseContentLength: -1,
		ResponseChan:          make(chan []byte, 100),
		ErrorChan:             make(chan error, 1),
	}
	return ws
}

func (p *Proxy) cleanupCurrentRequest() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.currentRequest != nil {
		// Close channels if they exist
		if p.currentRequest.ResponseChan != nil {
			close(p.currentRequest.ResponseChan)
		}
		if p.currentRequest.ErrorChan != nil {
			close(p.currentRequest.ErrorChan)
		}
		p.currentRequest = nil
	}
}

func (p *Proxy) HandleRequest(w http.ResponseWriter, r *http.Request) {
	ws := p.startNewRequest(r)
	defer p.cleanupCurrentRequest()
	if ws == nil {
		http.Error(w, "No WebSocket client connected", http.StatusServiceUnavailable)
		return
	}

	// Send the request to the upstream client
	if err := sendRequest(r, ws); err != nil {
		http.Error(w, "Failed to proxy request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	p.mutex.Lock()
	// Optionally update state to StateRequestSent here if needed
	p.currentRequest.State = StateRequestSent
	p.mutex.Unlock()

	// Accumulate header data, which may be fragmented across multiple messages
	req := p.currentRequest
	var headerBuf strings.Builder

	var firstMsg []byte
	select {
	case firstMsg = <-req.ResponseChan:
	case <-time.After(30 * time.Second):
		http.Error(w, "Gateway Timeout: upstream did not respond", http.StatusGatewayTimeout)
		return
	}
	headerBuf.Write(firstMsg)
	headerStr := headerBuf.String()
	for !strings.Contains(headerStr, "\r\n\r\n") {
		msg, ok := <-req.ResponseChan
		if !ok {
			break
		}
		headerBuf.Write(msg)
		headerStr = headerBuf.String()
	}

	idx := strings.Index(headerStr, "\r\n\r\n")
	if idx < 0 {
		http.Error(w, "Invalid response header received", http.StatusInternalServerError)
		return
	}

	headerPart := headerStr[:idx+4]
	bodyRemainder := headerStr[idx+4:]

	p.mutex.Lock()
	req.State = StateResponseHeaderReceived
	p.mutex.Unlock()

	if err := returnResponseHeader(headerPart, w); err != nil {
		http.Error(w, "Failed to process response header: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if we should expect a response body
	contentLength := w.Header().Get("Content-Length")
	connectionClose := strings.ToLower(w.Header().Get("Connection")) == "close"

	// If Content-Length is 0 or not present and Connection isn't close, we're done
	if contentLength == "0" {
		return
	}

	if len(bodyRemainder) > 0 {
		if _, err := w.Write([]byte(bodyRemainder)); err != nil {
			log.Printf("Error writing initial response body: %v", err)
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		p.mutex.Lock()
		req.ResponseContentLength += int64(len(bodyRemainder))
		p.mutex.Unlock()
	}

	// Only continue reading the body if we have a non-zero Content-Length or Connection: close
	if contentLength != "0" || connectionClose {
		// Forward subsequent response messages without timeout
		for {
			msg, ok := <-req.ResponseChan
			if !ok {
				// Channel closed, end response
				break
			}
			if _, err := w.Write(msg); err != nil {
				log.Printf("Error writing response to client: %v", err)
				break
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			p.mutex.Lock()
			req.ResponseContentLength += int64(len(msg))
			p.mutex.Unlock()
		}
	}
}

func returnResponseHeader(headerData string, w http.ResponseWriter) error {
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
