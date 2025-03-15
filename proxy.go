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
	"golang.org/x/time/rate"
)

// Define RequestState enum
type RequestState int

const (
	StateHeaderSent RequestState = iota
	StateRequestSent
	StateResponseHeaderReceived
)

// ProxyWriter is an interface for types that can write websocket messages
type ProxyWriter interface {
	WriteMessage(messageType int, data []byte) error
}

type Request struct {
	RequestID             byte
	Path                  string
	Method                string
	State                 RequestState
	RequestContentLength  int64
	ResponseContentLength int64
	ResponseChan          chan websocketMessage
	proxy                 ProxyWriter
}

func (r *Request) WriteMessage(messageType int, data []byte) error {
	if messageType == websocket.TextMessage {
		text := fmt.Sprintf("%s %d", string(data), r.RequestID)
		data = []byte(text)
	} else if messageType == websocket.BinaryMessage {
		data = append([]byte{r.RequestID}, data...)
	}
	return r.proxy.WriteMessage(messageType, data)
}

type Proxy struct {
	upgrader             websocket.Upgrader
	requestsMutex        sync.Mutex
	writeMutex           sync.Mutex
	ws                   *websocket.Conn
	activeRequests       map[byte]*Request
	requestIDQueue       []byte
	unknownReqLogLimiter *rate.Limiter
}

type websocketMessage struct {
	RequestID byte
	Type      int
	Message   []byte
	Error     error
}

func parseMessage(messageType int, message []byte) (*websocketMessage, error) {
	result := &websocketMessage{
		Type: messageType,
	}
	if messageType == websocket.TextMessage {
		str := string(message)
		idx := strings.LastIndex(str, " ")
		if idx < 0 || idx == len(str)-1 {
			return nil, fmt.Errorf("invalid request ID: %s", str)
		}
		idStr := strings.TrimSpace(str[idx+1:])
		id, err := strconv.ParseUint(idStr, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid request ID: %s", idStr)
		}
		result.RequestID = byte(id)
		result.Message = []byte(strings.TrimSpace(str[:idx]))
	} else if messageType == websocket.BinaryMessage {
		if len(message) < 1 {
			return nil, fmt.Errorf("invalid binary message format: %s", message)
		}
		result.RequestID = message[0]
		result.Message = message[1:]
	}
	return result, nil
}

func NewProxy() *Proxy {
	// Initialize the queue with all available request IDs (0-254)
	idQueue := make([]byte, 255)
	for i := range 255 {
		idQueue[i] = byte(i)
	}

	return &Proxy{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		activeRequests:       make(map[byte]*Request),
		requestIDQueue:       idQueue,
		unknownReqLogLimiter: rate.NewLimiter(rate.Every(5*time.Second), 1), // Allow 1 log per 5 seconds
	}
}

func (p *Proxy) WriteMessage(messageType int, data []byte) error {
	p.writeMutex.Lock()
	defer p.writeMutex.Unlock()
	return p.ws.WriteMessage(messageType, data)
}

func (p *Proxy) HandleConnection(w http.ResponseWriter, r *http.Request) {
	p.requestsMutex.Lock()
	// Check if a websocket client is already connected
	if p.ws != nil {
		p.requestsMutex.Unlock()
		http.Error(w, "Websocket client already connected", http.StatusConflict)
		return
	}

	// Upgrade the connection to a websocket
	ws, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}

	// Set the websocket connection
	p.ws = ws
	p.requestsMutex.Unlock()

	go p.readPump(ws)
}

func (p *Proxy) readPump(ws *websocket.Conn) {
	defer func() {
		ws.Close()
		// Clear the websocket connection when it's terminated
		p.requestsMutex.Lock()
		if p.ws == ws { // Only clear if it's still the same connection
			p.ws = nil
		}
		for _, req := range p.activeRequests {
			if req.ResponseChan != nil {
				close(req.ResponseChan)
				req.ResponseChan = nil
			}
		}
		p.requestsMutex.Unlock()
	}()

	for {
		messageType, message, err := ws.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				p.requestsMutex.Lock()
				for _, req := range p.activeRequests {
					if req.ResponseChan != nil {
						select {
						case req.ResponseChan <- websocketMessage{Error: err}:
						default:
							log.Printf("Response channel full, dropping error")
							err := req.WriteMessage(websocket.TextMessage, []byte("Cancel"))
							if err != nil {
								log.Printf("Failed to send Cancel message: %v", err)
							}
							p.cleanupRequest(req)
						}
					}
				}
				p.requestsMutex.Unlock()
			}
			break
		}

		wsMessage, err := parseMessage(messageType, message)
		if err != nil {
			log.Printf("Error parsing message: %v", err)
			continue
		}

		req, exists := p.activeRequests[wsMessage.RequestID]
		if !exists {
			if p.unknownReqLogLimiter.Allow() {
				log.Printf("Received message for unknown request ID: %d", wsMessage.RequestID)
			}
			continue
		}

		if req.ResponseChan != nil {
			if len(req.ResponseChan) >= cap(req.ResponseChan)/2 {
				err := req.WriteMessage(websocket.TextMessage, []byte("SlowDown"))
				if err != nil {
					log.Printf("Failed to send SlowDown message: %v", err)
				}
			}

			select {
			case req.ResponseChan <- *wsMessage:
			default:
				log.Println("Response channel full, dropping request")
				err := req.WriteMessage(websocket.TextMessage, []byte("Cancel"))
				if err != nil {
					log.Printf("Failed to send Cancel message: %v", err)
				}
				p.cleanupRequest(req)
			}
		}
	}
}

func (req *Request) sendRequest(r *http.Request) error {
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
	if err := req.WriteMessage(websocket.BinaryMessage, []byte(reqBuilder.String())); err != nil {
		return fmt.Errorf("failed to write to WebSocket: %w", err)
	}

	// Stream the body in chunks if present
	if r.Body != nil {
		// Tell the client that the headers are complete
		if err := req.WriteMessage(websocket.TextMessage, []byte("RequestHeadersComplete")); err != nil {
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
				if err := req.WriteMessage(websocket.BinaryMessage, buffer[:n]); err != nil {
					return fmt.Errorf("failed to write to WebSocket: %w", err)
				}
			}
			if err == io.EOF {
				break
			}
		}
	}

	// Tell the client that the request is complete
	if err := req.WriteMessage(websocket.TextMessage, []byte("RequestComplete")); err != nil {
		return fmt.Errorf("failed to write to WebSocket: %w", err)
	}

	req.State = StateRequestSent

	return nil
}

func (p *Proxy) startNewRequest(r *http.Request) (*Request, error) {
	p.requestsMutex.Lock()
	defer p.requestsMutex.Unlock()

	ws := p.ws
	if ws == nil {
		return nil, fmt.Errorf("no websocket connection available")
	}

	// Get a request ID from the queue
	if len(p.requestIDQueue) == 0 {
		return nil, fmt.Errorf("maximum number of concurrent requests reached (255)")
	}

	// Dequeue a request ID from the front of the queue
	requestID := p.requestIDQueue[0]
	p.requestIDQueue = p.requestIDQueue[1:]

	requestContentLength := int64(-1)
	if clStr := r.Header.Get("Content-Length"); clStr != "" {
		if cl, err := strconv.ParseInt(clStr, 10, 64); err == nil {
			requestContentLength = cl
		}
	}

	req := &Request{
		RequestID:             requestID,
		Path:                  r.URL.Path,
		Method:                r.Method,
		State:                 StateHeaderSent,
		RequestContentLength:  requestContentLength,
		ResponseContentLength: 0,
		ResponseChan:          make(chan websocketMessage, 500),
		proxy:                 p,
	}

	p.activeRequests[requestID] = req
	err := req.WriteMessage(websocket.TextMessage, []byte("NewRequest"))
	if err != nil {
		return nil, fmt.Errorf("failed to write to WebSocket: %w", err)
	}

	return req, nil
}

func (p *Proxy) cleanupRequest(req *Request) {
	p.requestsMutex.Lock()
	defer p.requestsMutex.Unlock()

	if _, exists := p.activeRequests[req.RequestID]; exists {
		if req.ResponseChan != nil {
			close(req.ResponseChan)
			req.ResponseChan = nil
		}
		delete(p.activeRequests, req.RequestID)

		// Add the freed ID back to the end of the queue
		p.requestIDQueue = append(p.requestIDQueue, req.RequestID)
	}
}

func (p *Proxy) HandleRequest(w http.ResponseWriter, r *http.Request) {
	req, err := p.startNewRequest(r)
	if err != nil {
		if err.Error() == "maximum number of concurrent requests reached (255)" {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		} else if err.Error() == "no websocket connection available" {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	defer p.cleanupRequest(req)

	// Send the request to the upstream client
	err = req.sendRequest(r)
	if err != nil {
		http.Error(w, "Failed to proxy request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Accumulate header data, which may be fragmented across multiple messages
	var headerBuf strings.Builder

	var firstMsg websocketMessage
	select {
	case firstMsg = <-req.ResponseChan:
	case <-time.After(30 * time.Second):
		http.Error(w, "Gateway Timeout: upstream did not respond", http.StatusGatewayTimeout)
		return
	}
	if firstMsg.Error != nil {
		http.Error(w, "Failed to process response header: "+firstMsg.Error.Error(), http.StatusInternalServerError)
		return
	}
	headerBuf.Write(firstMsg.Message)

	headerStr := headerBuf.String()
	for !strings.Contains(headerStr, "\r\n\r\n") {
		msg, ok := <-req.ResponseChan
		if !ok {
			break
		}
		if msg.Error != nil {
			http.Error(w, "Failed to process response header: "+msg.Error.Error(), http.StatusInternalServerError)
			return
		}
		headerBuf.Write(msg.Message)
		headerStr = headerBuf.String()
	}

	idx := strings.Index(headerStr, "\r\n\r\n")
	if idx < 0 {
		http.Error(w, "Invalid response header received", http.StatusInternalServerError)
		return
	}

	headerPart := headerStr[:idx+4]
	bodyRemainder := headerStr[idx+4:]

	req.State = StateResponseHeaderReceived

	if err := returnResponseHeader(headerPart, w); err != nil {
		http.Error(w, "Failed to process response header: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if len(bodyRemainder) > 0 {
		if _, err := w.Write([]byte(bodyRemainder)); err != nil {
			http.Error(w, "Error writing initial response body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		req.ResponseContentLength += int64(len(bodyRemainder))
	}

	// Forward subsequent response messages without timeout
	for {
		msg, ok := <-req.ResponseChan
		if !ok {
			// Channel closed, end response
			break
		}
		if msg.Error != nil {
			http.Error(w, "Failed to process response body: "+msg.Error.Error(), http.StatusInternalServerError)
			return
		}
		if msg.Type == websocket.BinaryMessage {
			if _, err := w.Write(msg.Message); err != nil {
				log.Printf("Error writing response to client: %v", err)
				break
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			req.ResponseContentLength += int64(len(msg.Message))
		} else if string(msg.Message) == "ResponseComplete" {
			break
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
