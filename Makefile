VERSION ?= 0.1.1-dev
LDFLAGS := -s -w -X main.version=$(VERSION)

test:
	go test ./...

dist:
	mkdir -p dist
	for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/wrangle-$$os-$$arch . ; \
	done
