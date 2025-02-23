# Beachhead

Beachhead is a Go program that exposes both an HTTPS external interface and an HTTP internal interface. Its features include:

- **External HTTPS Interface** (port 443)
  - **Authentication:** All endpoints require a token (set via the `AUTH_TOKEN` environment variable).
  - **WebSocket Endpoint:** `/ws` for proxying connections.
  - **Health Check Endpoint:** `/health`
  - **Version Endpoint:** `/version`
  - **Command Execution Endpoint:** `/exec?cmd=<shell_command>`  
    Streams stdout/stderr in chunked responses and returns the exit code as a trailer.
  - **File Upload Endpoint:** `/upload`  
    Designed for uploading files. Supports multipart/form-data submissions.
  - **File Download Endpoint:** `/download`  
    Retrieves previously uploaded files.

- **Internal HTTP Interface** (port 8080)
  - Forwards requests to the connected WebSocket client (only one allowed at a time). The client is expected to send back a response that is streamed back to the requester.

- **Certificate Generation:**  
  If no SSL certificate is provided via `SSL_CERT` and `SSL_KEY`, a self-signed certificate is generated.

## Building and Running

1. **Set Environment Variables:**

   - `AUTH_TOKEN`: The token used for authenticating requests to external endpoints.
   - *(Optional)* `SSL_CERT` and `SSL_KEY`: Paths to your SSL certificate and key. If not set, a self-signed certificate will be generated.

2. **Build:**

   ```bash
   go build -o beachhead .
   ```
