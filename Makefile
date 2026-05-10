# Binary names
BINARY_NAME=calibrute
BINARY_UNIX=$(BINARY_NAME)_unix

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test

all: build

build: 
	@echo "=> Building standard binary..."
	$(GOBUILD) -o $(BINARY_NAME) main.go
	@echo "=> Build complete."

build-static:
	@echo "=> Building statically linked Linux 64-bit binary..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -a -installsuffix cgo -ldflags="-extldflags '-static'" -o $(BINARY_NAME) main.go
	@echo "=> Static build complete. Run with ./$(BINARY_NAME)"

build-mac:
	@echo "=> Building for MacOS..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)_mac main.go

build-windows:
	@echo "=> Building for Windows..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME).exe main.go

clean: 
	@echo "=> Cleaning up..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).exe
	rm -f $(BINARY_NAME)_mac
	rm -f $(BINARY_UNIX)

run:
	$(GOBUILD) -o $(BINARY_NAME) main.go
	./$(BINARY_NAME)

.PHONY: all build build-static build-mac build-windows clean run
