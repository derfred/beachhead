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
		return nil, err
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
	for {
		_, message, err := client.conn.ReadMessage()
		if err != nil {
			var closeErr *websocket.CloseError
			if errors.As(err, &closeErr) && closeErr.Code == websocket.CloseNormalClosure {
				return
			}

			log.Printf("Error accepting message: %v", err)
			return
		}

		client.msgBuffer.Write(message)

		// Try to parse the accumulated buffer as an HTTP request
		bufReader := bufio.NewReader(&client.msgBuffer)
		req, err := http.ReadRequest(bufReader)

		if err != nil {
			// If we can't parse a complete request yet, wait for more data
			if err == bufio.ErrBufferFull || errors.Is(err, io.ErrUnexpectedEOF) {
				continue
			}

			// Other parsing error, reset buffer and log
			log.Printf("Error parsing request: %v", err)
			client.msgBuffer.Reset()
			continue
		}

		// Successfully parsed a complete request
		// Clear the buffer and process the request
		client.msgBuffer.Reset()

		// Handle the complete request synchronously
		client.handleRequest(req)
	}
}

// handleRequest processes a complete HTTP request and proxies it to the upstream server.
func (client *WebSocketClient) handleRequest(req *http.Request) {
	req.URL.Scheme = client.upstreamURL.Scheme
	req.URL.Host = client.upstreamURL.Host
	req.RequestURI = ""

	log.Printf("Forwarding request to %s", req.URL.String())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error forwarding request: %v", err)
		return
	}
	defer resp.Body.Close()

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
