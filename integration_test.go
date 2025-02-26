package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func buildServer(t *testing.T, cmds map[string]ShellTemplate) (*Server, *x509.CertPool, func()) {
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
		internalPort:   0,
		externalPort:   0,
		authToken:      "test-token",
		mode:           "server",
		certFile:       certFile.Name(),
		keyFile:        keyFile.Name(),
		ShellTemplates: cmds,
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

	server, certPool, cleanup := buildServer(t, nil)
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
	defer func() {
		if err := client.Shutdown(); err != nil {
			t.Logf("Error during client shutdown: %v", err)
		}
	}()
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
	server, certPool, cleanup := buildServer(t, nil)
	go server.Start()
	defer cleanup()
	time.Sleep(1 * time.Second)

	// Create a test workspace first
	tempWorkspace, err := os.MkdirTemp("", "workspace_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(tempWorkspace)

	// Set the workspace
	server.workspaceCurrent = tempWorkspace

	// Create file content
	fileContent := []byte("This is a test file.")

	// Create custom HTTP client with cert verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	// Upload the file
	uploadURL := fmt.Sprintf("https://localhost:%d/workspace/upload/testfile.txt", server.GetExternalPort())
	req, err := http.NewRequest(http.MethodPut, uploadURL, bytes.NewReader(fileContent))
	if err != nil {
		t.Fatalf("Failed to create upload request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to upload file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Upload failed with status %d", resp.StatusCode)
	}

	// Download the file
	downloadURL := fmt.Sprintf("https://localhost:%d/workspace/download/testfile.txt", server.GetExternalPort())
	req, err = http.NewRequest(http.MethodGet, downloadURL, nil)
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
		t.Fatalf("Download failed with status %d", resp.StatusCode)
	}

	// Read the downloaded content
	downloadedContent, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}

	// Verify the content
	if !bytes.Equal(downloadedContent, fileContent) {
		t.Fatalf("File content mismatch: expected %s, got %s", fileContent, downloadedContent)
	}
}

func TestExecIntegration(t *testing.T) {
	server, certPool, cleanup := buildServer(t, map[string]ShellTemplate{
		"echo": {Template: "echo {{.args}}"},
	})
	go server.Start()
	defer server.Shutdown()
	defer cleanup()

	// Wait briefly for the server to start.
	time.Sleep(500 * time.Millisecond)

	// Prepare the exec request.
	reqBody, err := json.Marshal(map[string]string{
		"args": "Hello Exec",
	})
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	// Create an HTTP client with TLS config.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}

	execURL := fmt.Sprintf("https://localhost:%d/exec/echo", server.GetExternalPort())
	req, err := http.NewRequest(http.MethodPost, execURL, bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	// Perform the request.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to perform exec request: %v", err)
	}
	defer resp.Body.Close()

	// Read the output.
	output, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Validate output and exit code.
	if !bytes.Contains(output, []byte("Hello Exec")) {
		t.Fatalf("Expected output to contain 'Hello Exec', got: %s", output)
	}
	exitCode := resp.Trailer.Get("X-Exit-Code")
	if exitCode != "0" {
		t.Fatalf("Expected exit code '0', got: %s", exitCode)
	}
}

func TestExecWithFilesIntegration(t *testing.T) {
	// Generate test certificates and start server
	server, certPool, cleanup := buildServer(t, map[string]ShellTemplate{
		"cat": {Template: "cat {{.input}}"},
	})

	go server.Start()
	defer cleanup()
	time.Sleep(1 * time.Second)

	// Create a test file with content
	testContent := "Hello from test file"
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatalf("Failed to write test content: %v", err)
	}
	tmpFile.Close()

	// Prepare the multipart request
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// Add the file
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer file.Close()

	filePart, err := writer.CreateFormFile("input", "input.txt")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	if _, err := io.Copy(filePart, file); err != nil {
		t.Fatalf("Failed to copy file content: %v", err)
	}
	writer.Close()

	// Create HTTPS client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	// Make the request
	url := fmt.Sprintf("https://localhost:%d/exec/cat", server.GetExternalPort())
	req, err := http.NewRequest(http.MethodPost, url, &b)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Read and verify the response
	output, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	expectedOutput := testContent + " additional args"
	if !strings.Contains(string(output), testContent) {
		t.Errorf("Expected output to contain %q, got %q", expectedOutput, string(output))
	}

	exitCode := resp.Trailer.Get("X-Exit-Code")
	if exitCode != "0" {
		t.Errorf("Expected exit code 0, got %s", exitCode)
	}
}

func TestWorkspaceIntegration(t *testing.T) {
	server, certPool, cleanup := buildServer(t, nil)
	go server.Start()
	defer cleanup()
	time.Sleep(1 * time.Second)

	// Create a temporary zip file with test content
	zipBuffer := &bytes.Buffer{}
	zipWriter := zip.NewWriter(zipBuffer)

	// Add a few test files to the zip
	files := map[string]string{
		"test.txt":       "Hello World",
		"dir/nested.txt": "Nested content",
		"config.json":    `{"key": "value"}`,
	}

	for name, content := range files {
		f, err := zipWriter.Create(name)
		if err != nil {
			t.Fatalf("Failed to create zip entry: %v", err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("Failed to write zip content: %v", err)
		}
	}

	if err := zipWriter.Close(); err != nil {
		t.Fatalf("Failed to close zip writer: %v", err)
	}

	// Prepare the multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "workspace.zip")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	if _, err := io.Copy(part, zipBuffer); err != nil {
		t.Fatalf("Failed to copy zip content: %v", err)
	}
	writer.Close()

	// Create custom HTTP client with cert verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	// Make the workspace upload request
	req, err := http.NewRequest("PUT", fmt.Sprintf("https://localhost:%d/workspace", server.GetExternalPort()), body)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to upload workspace: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Read the response which contains the workspace path
	workspacePath, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Extract the actual path from the response message
	path := strings.TrimPrefix(string(workspacePath), "Workspace set to: ")

	// Verify the extracted files
	for name, expectedContent := range files {
		content, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			t.Errorf("Failed to read extracted file %s: %v", name, err)
			continue
		}

		if string(content) != expectedContent {
			t.Errorf("File %s content mismatch\nExpected: %s\nGot: %s",
				name, expectedContent, string(content))
		}
	}

	// Cleanup the workspace directory
	os.RemoveAll(path)
}
