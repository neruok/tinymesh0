BINARY     := tinymesh0d
BUILD_DIR  := .
CMD        := ./cmd/tinymesh0d

GOLANGCI   := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

.PHONY: all build lint test dev release

all: build

build:
	go build -o $(BUILD_DIR)/$(BINARY) $(CMD)

lint:
	$(GOLANGCI) run

test:
	go test ./...

dev:
	bash scripts/setup-dev.sh
	docker compose up --build

release: build test lint
	@echo "Release build complete: $(BUILD_DIR)/$(BINARY)"
