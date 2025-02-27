package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"
)

// ClientRequestState represents the state of a single multiplexed request in the client.
type ClientRequestState struct {
	headerBuffer bytes.Buffer
	bodyBuffer   bytes.Buffer
	current      *bytes.Buffer
}

// WebSocketClient represents the client that connects to the WebSocket endpoint.
type WebSocketClient struct {
	conn          *websocket.Conn
	upstreamURL   *url.URL
	msgMutex      sync.Mutex
	requestStates map[byte]*ClientRequestState
	done          chan struct{}
}

// NewWebSocketClient initializes a new WebSocketClient.
func NewWebSocketClient(endpoint string, token string, upstream string, tlsClientConfig *tls.Config) (*WebSocketClient, error) {
	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}

	dialer := websocket.Dialer{
		TLSClientConfig: tlsClientConfig,
	}
	headers := http.Header{}
	headers.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	conn, _, err := dialer.Dial(endpoint, headers)
	if err != nil {
		return nil, fmt.Errorf("websocket connection failed: %v", err)
	}

	client := &WebSocketClient{
		conn:          conn,
		upstreamURL:   upstreamURL,
		requestStates: make(map[byte]*ClientRequestState),
		done:          make(chan struct{}),
	}

	return client, nil
}

// AcceptMessages accepts and handles incoming messages on the connection.
func (client *WebSocketClient) AcceptMessages() {
	for {
		select {
		case <-client.done:
			return
		default:
			messageType, message, err := client.conn.ReadMessage()
			if err != nil {
				var closeErr *websocket.CloseError
				if errors.As(err, &closeErr) && closeErr.Code == websocket.CloseNormalClosure {
					return
				}

				log.Printf("Error accepting message: %v", err)
				return
			}

			wsMessage, err := parseMessage(messageType, message)
			if err != nil {
				log.Printf("Error parsing message: %v", err)
				continue
			}

			if messageType == websocket.TextMessage {
				if string(wsMessage.Message) == "NewRequest" {
					client.initializeRequestState(wsMessage.RequestID)
				} else {
					state, exists := client.requestStates[wsMessage.RequestID]
					if !exists {
						log.Printf("Received message for unknown request ID: %d", wsMessage.RequestID)
						continue
					}

					switch string(wsMessage.Message) {
					case "RequestHeadersComplete":
						state.current = &state.bodyBuffer
					case "RequestComplete":
						client.handleRequest(wsMessage.RequestID, state)
						delete(client.requestStates, wsMessage.RequestID)
					}
				}
			} else if messageType == websocket.BinaryMessage {
				state, exists := client.requestStates[wsMessage.RequestID]
				if !exists {
					log.Printf("Received binary data for unknown request ID: %d", wsMessage.RequestID)
					continue
				}

				state.current.Write(wsMessage.Message)
			}
		}
	}
}

// initializeRequestState creates a new request state for a given ID.
func (client *WebSocketClient) initializeRequestState(requestID byte) {
	state := &ClientRequestState{
		headerBuffer: bytes.Buffer{},
		bodyBuffer:   bytes.Buffer{},
	}
	state.current = &state.headerBuffer

	client.requestStates[requestID] = state
}

// handleRequest processes a complete HTTP request and proxies it to the upstream server.
func (client *WebSocketClient) handleRequest(requestID byte, state *ClientRequestState) {
	req, err := http.ReadRequest(bufio.NewReader(&state.headerBuffer))
	if err != nil {
		log.Printf("Error reading request: %v", err)
		return
	}

	// Set the body if bodyBuffer is not empty
	if state.bodyBuffer.Len() > 0 {
		req.Body = io.NopCloser(bytes.NewReader(state.bodyBuffer.Bytes()))
		req.ContentLength = int64(state.bodyBuffer.Len())
	}

	req.URL.Scheme = client.upstreamURL.Scheme
	req.URL.Host = client.upstreamURL.Host
	req.RequestURI = ""

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error forwarding request: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("Forwarded request to %s %s -> %d", req.Method, req.URL.String(), resp.StatusCode)

	client.msgMutex.Lock()
	defer client.msgMutex.Unlock()

	var respBuf bytes.Buffer
	if err := resp.Write(&respBuf); err != nil {
		log.Printf("Error writing response to buffer: %v", err)
		return
	}

	// Prepend the request ID to the binary message
	responseBinaryMessage := append([]byte{requestID}, respBuf.Bytes()...)
	if err := client.conn.WriteMessage(websocket.BinaryMessage, responseBinaryMessage); err != nil {
		log.Printf("Error writing response to WebSocket: %v", err)
		return
	}

	// Append the request ID to the text message
	responseCompleteMessage := fmt.Sprintf("ResponseComplete %d", requestID)
	if err := client.conn.WriteMessage(websocket.TextMessage, []byte(responseCompleteMessage)); err != nil {
		log.Printf("Error writing response complete to WebSocket: %v", err)
		return
	}
}

// Shutdown gracefully closes the WebSocket connection.
func (client *WebSocketClient) Shutdown() error {
	// Signal AcceptMessages to stop
	close(client.done)

	client.msgMutex.Lock()
	defer client.msgMutex.Unlock()
	return client.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Shutdown"))
}
