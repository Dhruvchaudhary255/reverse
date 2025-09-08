.PHONY: all build clean test install

# Build variables
BINARY_NAME := reverse
GO_MODULE := ./cmd/reverse
BUILD_DIR := .
INSTALL_DIR := $(HOME)/bin

# Default target
all: build

# Build the reverse tool
build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) $(GO_MODULE)
	@echo "✓ Built $(BINARY_NAME) successfully"

# Install to user bin directory
install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	@mkdir -p $(INSTALL_DIR)
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/
	@echo "✓ Installed to $(INSTALL_DIR)/$(BINARY_NAME)"

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

# Run regression tests
test-regression: build
	@echo "Running regression tests..."
	@cd samples && ./test_regression.sh

# Run regression tests on samples (alias)
test-samples: test-regression

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(BUILD_DIR)/$(BINARY_NAME)
	@echo "✓ Cleaned"

# Format code
fmt:
	@echo "Formatting code..."
	@gofmt -w .
	@echo "✓ Code formatted"

# Run linters
lint:
	@echo "Running linters..."
	@go vet ./...
	@echo "✓ Linting complete"

# Help
help:
	@echo "Available targets:"
	@echo "  make build          - Build the reverse tool"
	@echo "  make install        - Build and install to ~/bin"
	@echo "  make test           - Run unit tests"
	@echo "  make test-regression - Run regression tests on samples"
	@echo "  make test-samples    - Alias for test-regression"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make fmt            - Format Go code"
	@echo "  make lint           - Run linters"
	@echo "  make help           - Show this help message"