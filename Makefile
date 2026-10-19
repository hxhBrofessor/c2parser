VERSION := $(shell grep -m1 "const version" main.go | cut -d\" -f2)
LDFLAGS := -s -w

.PHONY: build test release clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o c2parser .

test:
	go vet ./...
	go test ./...

release: clean
	mkdir -p dist
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/c2parser-v$(VERSION)-darwin-arm64 .
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/c2parser-v$(VERSION)-darwin-amd64 .
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/c2parser-v$(VERSION)-linux-amd64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/c2parser-v$(VERSION)-windows-amd64.exe .
	cd dist && (sha256sum c2parser-* 2>/dev/null || shasum -a 256 c2parser-*) > SHA256SUMS

clean:
	rm -rf dist c2parser c2parser.exe
