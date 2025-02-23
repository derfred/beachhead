package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// GenerateTestCert creates a self-signed certificate for testing purposes.
// It returns the certificate, private key, and any error that occurred.
func GenerateTestCert(host string) (*x509.Certificate, any, error) {
	// Generate private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Prepare certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   host,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

func buildServer(t *testing.T) (*Server, *x509.CertPool, func()) {
	// Generate test certificates
	cert, privKey, err := GenerateTestCert("localhost")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	// Write cert and key to temp files
	certFile, err := os.CreateTemp("", "cert")
	if err != nil {
		t.Fatal(err)
	}

	keyFile, err := os.CreateTemp("", "key")
	if err != nil {
		t.Fatal(err)
	}

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}); err != nil {
		t.Fatal(err)
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	}); err != nil {
		t.Fatal(err)
	}

	// Start WebTransport server with certs
	cfg := config{
		internalPort: 0,
		externalPort: 0,
		authToken:    "test-token",
		mode:         "server",
		certFile:     certFile.Name(),
		keyFile:      keyFile.Name(),
	}
	server := NewServer(cfg)
	cleanup := func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
		server.Shutdown()
	}
	return server, certPool, cleanup
}

func TestIntegrationWithCertificates(t *testing.T) {
	// Start upstream server
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from secure upstream"))
	}))
	defer upstreamServer.Close()

	server, certPool, cleanup := buildServer(t)
	go server.Start()
	defer cleanup()

	// Start Websocket client with cert verification
	clientCfg := config{
		endpoint:  fmt.Sprintf("wss://localhost:%d/ws", server.GetExternalPort()),
		upstream:  upstreamServer.URL,
		authToken: "test-token",
	}

	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}

	client, err := NewWebSocketClient(clientCfg.endpoint, clientCfg.authToken, clientCfg.upstream, tlsConfig)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	go client.AcceptMessages()
	defer client.Shutdown()
	time.Sleep(1 * time.Second)

	// Test request
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/resource", server.GetInternalPort()))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	if string(body) != "Hello from secure upstream" {
		t.Fatalf("Unexpected response: %s", string(body))
	}
}

func TestUploadDownloadIntegration(t *testing.T) {
	server, certPool, cleanup := buildServer(t)
	go server.Start()
	defer cleanup()
	time.Sleep(1 * time.Second)

	// Create a file to upload
	fileContent := "This is a test file."
	fileBuffer := &bytes.Buffer{}
	writer := multipart.NewWriter(fileBuffer)
	part, err := writer.CreateFormFile("file", "testfile.txt")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	part.Write([]byte(fileContent))
	writer.Close()

	// Create custom HTTP client with cert verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	// Upload the file
	req, err := http.NewRequest("POST", fmt.Sprintf("https://localhost:%d/upload", server.GetExternalPort()), fileBuffer)
	if err != nil {
		t.Fatalf("Failed to create upload request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to upload file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected status code: %d", resp.StatusCode)
	}

	// Read the file ID from the response
	fileID, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Download the file
	downloadURL := fmt.Sprintf("https://localhost:%d/download?id=%s", server.GetExternalPort(), fileID)
	req, err = http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		t.Fatalf("Failed to create download request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to download file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected status code: %d", resp.StatusCode)
	}

	// Read the downloaded file content
	downloadedContent, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}

	// Verify the content
	if string(downloadedContent) != fileContent {
		t.Fatalf("File content mismatch: expected %s, got %s", fileContent, string(downloadedContent))
	}
}
