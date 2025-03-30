#!/bin/bash

# Configuration variables
TARGET_ARCH="amd64"  # Target architecture (arm64, amd64, etc.)
TARGET_OS="linux"    # Target OS
GO_PROJECT_DIR="$HOME/src/beachhead"  # Path to your Go project
BINARY_NAME="beachhead"  # The name of your application binary
REMOTE_USER="root"   # SSH username
REMOTE_HOST="135.181.63.212"  # SSH host
REMOTE_PORT="22"     # SSH port
REMOTE_DIR="/usr/local/bin"  # Remote directory where binary will be placed
SERVICE_NAME="beachhead"  # systemd service name

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored status messages
print_status() {
  echo -e "${GREEN}[+] $1${NC}"
}

print_error() {
  echo -e "${RED}[!] $1${NC}"
  exit 1
}

# Check if all required commands are available
check_requirements() {
  print_status "Checking requirements..."
  
  commands=("go" "ssh" "scp")
  for cmd in "${commands[@]}"; do
    if ! command -v $cmd &> /dev/null; then
      print_error "$cmd command not found. Please install it."
    fi
  done
}

# Build the binary
build_binary() {
  print_status "Building binary for $TARGET_OS/$TARGET_ARCH..."
  
  cd "$GO_PROJECT_DIR" || print_error "Could not change to project directory"
  
  # Clean any previous builds
  go clean
  
  # Set environment variables for cross-compilation
  GOOS=$TARGET_OS GOARCH=$TARGET_ARCH go build -o $BINARY_NAME
  
  if [ $? -ne 0 ]; then
    print_error "Build failed"
  fi
  
  print_status "Binary built successfully: $BINARY_NAME"
}

# Upload binary to remote server
upload_binary() {
  print_status "Uploading binary to $REMOTE_HOST..."

  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "sudo systemctl stop $SERVICE_NAME" || print_error "Failed to restart service"

  # Create remote directory if it doesn't exist
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "mkdir -p $REMOTE_DIR" || print_error "Failed to create remote directory"
  
  # Upload the binary
  # scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $REMOTE_PORT "$GO_PROJECT_DIR/$BINARY_NAME" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/" || print_error "Upload failed"
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$GO_PROJECT_DIR/$BINARY_NAME" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/" || print_error "Upload failed"
  
  # Make binary executable
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "chmod +x $REMOTE_DIR/$BINARY_NAME" || print_error "Failed to make binary executable"
  print_status "Binary uploaded successfully"
}

# Restart the systemd service
restart_service() {
  print_status "Restarting $SERVICE_NAME service..."
  
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "sudo systemctl restart $SERVICE_NAME" || print_error "Failed to restart service"
  
  # Check service status
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "sudo systemctl status $SERVICE_NAME" || print_error "Service failed to start properly"
  
  print_status "Service restarted successfully"
}

# Main function
main() {
  print_status "Starting deployment process..."
  
  check_requirements
  build_binary
  upload_binary
  restart_service
  
  print_status "Deployment completed successfully!"
}

# Run the script
main
