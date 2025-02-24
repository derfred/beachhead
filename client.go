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

// WebSocketClient represents the client that connects to the WebSocket endpoint.
type WebSocketClient struct {
	conn        *websocket.Conn
	upstreamURL *url.URL
	msgMutex    sync.Mutex
	msgBuffer   bytes.Buffer
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
		conn:        conn,
		upstreamURL: upstreamURL,
		msgBuffer:   bytes.Buffer{},
	}

	return client, nil
}

// AcceptMessages accepts and handles incoming messages on the connection.
func (client *WebSocketClient) AcceptMessages() {
	headerBuffer := bytes.Buffer{}
	bodyBuffer := bytes.Buffer{}
	current := &headerBuffer

	for {
		messageType, message, err := client.conn.ReadMessage()
		if err != nil {
			var closeErr *websocket.CloseError
			if errors.As(err, &closeErr) && closeErr.Code == websocket.CloseNormalClosure {
				return
			}

			log.Printf("Error accepting message: %v", err)
			return
		}

		if messageType == websocket.BinaryMessage {
			current.Write(message)
		} else {
			log.Printf("Received text message: %s", message)
			if bytes.Equal(message, []byte("HeaderComplete")) {
				current = &bodyBuffer
			} else if bytes.Equal(message, []byte("RequestComplete")) {
				client.handleRequest(&headerBuffer, &bodyBuffer)

				// get ready for next request
				headerBuffer.Reset()
				bodyBuffer.Reset()
				current = &headerBuffer
			}
		}
	}
}

// handleRequest processes a complete HTTP request and proxies it to the upstream server.
func (client *WebSocketClient) handleRequest(headerBuffer *bytes.Buffer, bodyBuffer *bytes.Buffer) {
	req, err := http.ReadRequest(bufio.NewReader(headerBuffer))
	if err != nil {
		log.Printf("Error reading request: %v", err)
		return
	}

	// Set the body if bodyBuffer is not empty
	if bodyBuffer.Len() > 0 {
		req.Body = io.NopCloser(bytes.NewReader(bodyBuffer.Bytes()))
		req.ContentLength = int64(bodyBuffer.Len())
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

	if err := client.conn.WriteMessage(websocket.BinaryMessage, respBuf.Bytes()); err != nil {
		log.Printf("Error writing response to WebSocket: %v", err)
		return
	}
}

// Shutdown gracefully closes the WebSocket connection.
func (client *WebSocketClient) Shutdown() error {
	return client.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Shutdown"))
}
