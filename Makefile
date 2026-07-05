BINARY  := sandtrap
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X github.com/sandtrap-sh/sandtrap/internal/cli.Version=$(VERSION)

.PHONY: build test lint clean install release-snapshot

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go test -race -cover ./...

lint:
	go vet ./...
	gofmt -l . | tee /dev/stderr | wc -l | grep -q '^0$$'

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/$(BINARY)

clean:
	rm -rf bin dist

# cross-compile a release matrix without external tooling
release-snapshot: clean
	@for os in linux darwin windows; do \
	  for arch in amd64 arm64; do \
	    ext=""; [ $$os = windows ] && ext=".exe"; \
	    out=dist/$(BINARY)_$${os}_$${arch}$${ext}; \
	    echo "building $$out"; \
	    GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/$(BINARY) || exit 1; \
	  done; \
	done
