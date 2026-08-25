# WordEye — build targets for Linux/macOS workstations.
# Windows users: use ./build.ps1

VERSION ?= 0.1.0+$(shell date -u +%Y%m%d.%H%M%S)
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST    := dist

.PHONY: all agent controller test vet clean fmt

all: agent controller

# CGO_ENABLED=0 produces a genuinely static binary: no libc dependency, so the
# same file runs on glibc and musl hosts alike. That is the whole "one scp, no
# deps" promise.
agent:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(DIST)/wordeye-agent-linux-amd64 ./cmd/wordeye-agent
	@echo "built $(DIST)/wordeye-agent-linux-amd64 ($(VERSION))"

controller:
	@mkdir -p $(DIST)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/wordeye ./cmd/wordeye
	@echo "built $(DIST)/wordeye ($(VERSION))"

test:
	go test ./...

vet:
	go vet ./...
	CGO_ENABLED=0 GOOS=linux go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -rf $(DIST)
