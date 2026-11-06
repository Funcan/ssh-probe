BINARY := ssh-probe

.PHONY: build test integration-test format lint clean

build:
	go build -o $(BINARY) .

test:
	go test ./...

# Requires Docker; starts a throwaway SSH server to probe against.
integration-test:
	go test -tags integration ./...

format:
	gofmt -w .

lint:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed on:"; gofmt -l .; exit 1; }
	go vet ./...

clean:
	rm -f $(BINARY)
	go clean
